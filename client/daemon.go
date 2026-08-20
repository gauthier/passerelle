package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gauthier/passerelle/internal/backoff"
	"github.com/gauthier/passerelle/internal/httppipe"
	"github.com/gauthier/passerelle/internal/logging"
	"github.com/gauthier/passerelle/internal/origin"
	"github.com/gauthier/passerelle/internal/tlsutil"
	"github.com/gauthier/passerelle/internal/tunnelconn"
	"github.com/gauthier/passerelle/internal/version"
	"github.com/gauthier/passerelle/protocol"
	controlv1 "github.com/gauthier/passerelle/protocol/controlv1"
	"github.com/quic-go/quic-go"
)

type Daemon struct {
	log    *slog.Logger
	socket string

	mu        sync.Mutex
	cfg       Config
	tunnels   map[string]*liveTunnel
	local     map[string]localOrigin // tunnelID -> loopback target
	pending   map[uint64]chan *controlv1.Envelope
	seq       uint64
	control   io.ReadWriteCloser
	ctrlMu    sync.Mutex
	connected bool
	transport string
	gateway   string
	latency   atomic.Int64 // ns
	bytesIn   atomic.Int64
	bytesOut  atomic.Int64
	lastErr   string
	cancel    context.CancelFunc
}

type liveTunnel struct {
	Tunnel
}

type localOrigin struct {
	Addr string
	TLS  bool
}

func NewDaemon(log *slog.Logger, socket string) *Daemon {
	if log == nil {
		log = logging.New("text", "info")
	}
	if socket == "" {
		socket = SocketPath()
	}
	cfg, _ := Load()
	return &Daemon{
		log:     log,
		socket:  socket,
		cfg:     cfg,
		tunnels: make(map[string]*liveTunnel),
		local:   make(map[string]localOrigin),
		pending: make(map[uint64]chan *controlv1.Envelope),
	}
}

func (d *Daemon) Run(ctx context.Context) error {
	ctx, d.cancel = context.WithCancel(ctx)
	ln, err := listenIPC(d.socket)
	if err != nil {
		return err
	}
	defer ln.Close()
	d.log.Info("daemon listening", "socket", d.socket)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", d.serveStatus)
	mux.HandleFunc("GET /v1/tunnels", d.serveList)
	mux.HandleFunc("POST /v1/tunnels", d.serveOpen)
	mux.HandleFunc("DELETE /v1/tunnels/{id}", d.serveClose)
	mux.HandleFunc("GET /v1/events", d.serveEvents)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	go d.loop(ctx)
	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
	return nil
}

func (d *Daemon) loop(ctx context.Context) {
	wait := time.Duration(0)
	for {
		if ctx.Err() != nil {
			return
		}
		d.mu.Lock()
		cfg := d.cfg
		d.mu.Unlock()
		if cfg.ClientID == "" || cfg.CertPEM == "" {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				cfg, _ = Load()
				d.mu.Lock()
				d.cfg = cfg
				d.mu.Unlock()
				continue
			}
		}
		start := time.Now()
		err := d.connect(ctx, cfg)
		d.mu.Lock()
		d.connected = false
		d.control = nil
		if err != nil {
			d.lastErr = err.Error()
		}
		d.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > 30*time.Second {
			wait = 0
		} else {
			wait = backoff.Next(wait)
		}
		d.log.Info("reconnecting", "after", wait.String(), "err", err)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (d *Daemon) connect(ctx context.Context, cfg Config) error {
	tlsConf, err := d.tlsConfig(cfg)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.gateway = cfg.TunnelQUIC
	d.mu.Unlock()

	// Prefer QUIC.
	if cfg.TunnelQUIC != "" {
		qctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		conn, err := tunnelconn.DialQUIC(qctx, cfg.TunnelQUIC, tlsConf)
		cancel()
		if err == nil {
			d.mu.Lock()
			d.transport = "quic"
			d.lastErr = ""
			d.mu.Unlock()
			return d.serveQUIC(ctx, conn)
		}
		d.log.Info("quic dial failed, trying http/2", "err", err)
	}
	addr := cfg.TunnelTLS
	if addr == "" {
		addr = cfg.TunnelQUIC
	}
	dialer := &tls.Dialer{Config: tlsConf, NetDialer: &net.Dialer{Timeout: 8 * time.Second}}
	c, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.transport = "http2"
	d.gateway = addr
	d.lastErr = ""
	d.mu.Unlock()
	return d.serveH2(ctx, c)
}

func (d *Daemon) tlsConfig(cfg Config) (*tls.Config, error) {
	keyPEM, err := LoadPrivateKey()
	if err != nil {
		return nil, err
	}
	cert, err := tlsutil.TLSCertFromPEM([]byte(cfg.CertPEM), keyPEM)
	if err != nil {
		return nil, err
	}
	pool, err := tlsutil.PoolFromPEM([]byte(cfg.CAPEM))
	if err != nil {
		return nil, err
	}
	serverName := hostOf(cfg.TunnelQUIC)
	if serverName == "" {
		serverName = hostOf(cfg.TunnelTLS)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
		RootCAs:            pool,
		ServerName:         serverName,
		NextProtos:         []string{protocol.ALPN},
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}, nil
}

func (d *Daemon) serveQUIC(ctx context.Context, conn *quic.Conn) error {
	defer conn.CloseWithError(0, "bye")
	ctrl, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		for {
			st, err := conn.AcceptStream(subCtx)
			if err != nil {
				cancel()
				return
			}
			go d.handleData(st)
		}
	}()
	return d.session(subCtx, ctrl)
}

func (d *Daemon) serveH2(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	errCh := make(chan error, 1)
	sessDone := make(chan error, 1)
	go func() {
		errCh <- tunnelconn.ServeH2Daemon(ctx, conn, tunnelconn.H2ClientHandlers{
			OnControl: func(st tunnelconn.Stream) {
				sessDone <- d.session(ctx, st)
			},
			OnData: func(st tunnelconn.Stream) {
				d.handleData(st)
			},
		})
	}()
	select {
	case err := <-sessDone:
		return err
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Daemon) session(ctx context.Context, ctrl io.ReadWriteCloser) error {
	defer ctrl.Close()
	d.mu.Lock()
	d.control = ctrl
	d.mu.Unlock()

	readErr := make(chan error, 1)
	go func() {
		for {
			env, err := tunnelconn.ReadEnvelope(ctrl)
			if err != nil {
				readErr <- err
				return
			}
			d.dispatch(env)
		}
	}()

	hello := &controlv1.Envelope{
		Payload: &controlv1.Envelope_Hello{Hello: &controlv1.Hello{
			ProtocolMin:   protocol.ProtocolMin,
			ProtocolMax:   protocol.ProtocolMax,
			ClientVersion: version.Version,
		}},
	}
	ch := d.expect(hello)
	if err := d.writeControl(ctrl, hello); err != nil {
		return err
	}
	select {
	case ack := <-ch:
		if ack.GetHelloAck() == nil {
			if e := ack.GetError(); e != nil {
				return fmt.Errorf("hello: %s", e.GetMessage())
			}
			return fmt.Errorf("unexpected hello reply")
		}
	case err := <-readErr:
		return err
	case <-time.After(8 * time.Second):
		return fmt.Errorf("timeout waiting for hello ack")
	case <-ctx.Done():
		return ctx.Err()
	}

	d.mu.Lock()
	d.connected = true
	d.lastErr = ""
	d.mu.Unlock()

	go d.keepalive(ctx, ctrl)
	go d.restoreTunnels(ctx)

	select {
	case err := <-readErr:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Daemon) restoreTunnels(ctx context.Context) {
	time.Sleep(50 * time.Millisecond)
	d.mu.Lock()
	type liveSpec struct {
		id, host, subdomain, local string
		port                       int
		persist, https             bool
	}
	live := make([]liveSpec, 0, len(d.tunnels))
	for _, t := range d.tunnels {
		h, p, err := origin.ParseHostPort(t.Local)
		if err != nil {
			continue
		}
		sub := t.Subdomain
		if sub == "" {
			sub, _, _ = strings.Cut(t.Hostname, ".")
		}
		live = append(live, liveSpec{t.ID, h, sub, t.Local, p, t.Persist, t.HTTPS})
	}
	persist := append([]TunnelSpec(nil), d.cfg.Persistent...)
	d.mu.Unlock()

	announced := make(map[string]bool, len(live))
	for _, sp := range live {
		if err := d.reopenTunnel(sp.id, sp.host, sp.port, sp.subdomain, sp.persist, sp.https); err != nil {
			d.log.Info("reannounce failed", "err", err, "hostname", sp.local, "id", sp.id)
			d.mu.Lock()
			if t, ok := d.tunnels[sp.id]; ok {
				t.Status = "stale"
			}
			d.mu.Unlock()
			continue
		}
		announced[sp.local] = true
	}
	for _, spec := range persist {
		addr := net.JoinHostPort(spec.Host, fmt.Sprintf("%d", spec.Port))
		if announced[addr] {
			continue
		}
		d.mu.Lock()
		already := false
		for _, t := range d.tunnels {
			if t.Local == addr && t.Persist {
				already = true
				break
			}
		}
		d.mu.Unlock()
		if already {
			continue
		}
		if _, err := d.openTunnel(spec.Host, spec.Port, spec.Subdomain, true, spec.HTTPS); err != nil {
			d.log.Info("restore tunnel failed", "err", err, "port", spec.Port)
		}
	}
	_ = ctx
}

func (d *Daemon) keepalive(ctx context.Context, ctrl io.ReadWriteCloser) {
	ping := func() bool {
		start := time.Now()
		env := &controlv1.Envelope{Payload: &controlv1.Envelope_KeepAlive{KeepAlive: &controlv1.KeepAlive{UnixMs: start.UnixMilli()}}}
		ch := d.expect(env)
		d.mu.Lock()
		c := d.control
		d.mu.Unlock()
		if c == nil {
			return false
		}
		if err := d.writeControl(c, env); err != nil {
			return false
		}
		select {
		case <-ch:
			d.latency.Store(time.Since(start).Nanoseconds())
			return true
		case <-time.After(5 * time.Second):
			d.mu.Lock()
			delete(d.pending, env.Seq)
			d.mu.Unlock()
			_ = c.Close()
			return false
		case <-ctx.Done():
			return false
		}
	}
	if !ping() {
		_ = ctrl.Close()
		return
	}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !ping() {
				return
			}
		}
	}
}

func (d *Daemon) writeControl(ctrl io.ReadWriteCloser, env *controlv1.Envelope) error {
	if env.Seq == 0 {
		env.Seq = atomic.AddUint64(&d.seq, 1)
	}
	d.ctrlMu.Lock()
	defer d.ctrlMu.Unlock()
	return tunnelconn.WriteEnvelope(ctrl, env)
}

func (d *Daemon) expect(env *controlv1.Envelope) chan *controlv1.Envelope {
	if env.Seq == 0 {
		env.Seq = atomic.AddUint64(&d.seq, 1)
	}
	ch := make(chan *controlv1.Envelope, 1)
	d.mu.Lock()
	d.pending[env.Seq] = ch
	d.mu.Unlock()
	return ch
}

func (d *Daemon) dispatch(env *controlv1.Envelope) {
	if env.Seq != 0 {
		d.mu.Lock()
		ch, ok := d.pending[env.Seq]
		if ok {
			delete(d.pending, env.Seq)
		}
		d.mu.Unlock()
		if ok {
			d.log.Debug("control reply", "seq", env.Seq, "type", fmt.Sprintf("%T", env.Payload))
			ch <- env
			return
		}
	}
	switch p := env.Payload.(type) {
	case *controlv1.Envelope_Error:
		d.log.Info("gateway error", "code", p.Error.GetCode(), "msg", p.Error.GetMessage())
		d.mu.Lock()
		d.lastErr = p.Error.GetMessage()
		d.mu.Unlock()
	case *controlv1.Envelope_KeepAlive:
		d.latency.Store(0)
	case *controlv1.Envelope_HelloAck:
		d.log.Info("connected", "gateway_version", p.HelloAck.GetGatewayVersion())
	}
}

func (d *Daemon) handleData(stream io.ReadWriteCloser) {
	id, err := tunnelconn.ReadPreamble(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	d.mu.Lock()
	orig := d.local[id]
	t := d.tunnels[id]
	d.mu.Unlock()
	if orig.Addr == "" {
		_ = stream.Close()
		return
	}
	if t != nil {
		atomic.AddInt64(&t.Conns, 1)
		atomic.AddInt64(&t.Requests, 1)
		defer atomic.AddInt64(&t.Conns, -1)
	}
	var tlsConf *tls.Config
	if orig.TLS {
		tlsConf = &tls.Config{
			InsecureSkipVerify: true, // loopback; Docker/Apache certs are not for 127.0.0.1
			MinVersion:         tls.VersionTLS12,
			ServerName:         "localhost",
		}
	}
	stats, _ := httppipe.ServeOrigin(stream, orig.Addr, 10*time.Second, tlsConf)
	d.bytesIn.Add(stats.ToOrigin)
	d.bytesOut.Add(stats.FromOrigin)
	if t != nil {
		atomic.AddInt64(&t.BytesIn, stats.ToOrigin)
		atomic.AddInt64(&t.BytesOut, stats.FromOrigin)
	}
}

func (d *Daemon) openTunnel(host string, port int, subdomain string, persist, https bool) (*Tunnel, error) {
	t, err := d.requestOpen(host, port, subdomain, persist, https)
	if err != nil {
		return nil, err
	}
	d.installTunnel(t, "")
	return t, nil
}

func (d *Daemon) reopenTunnel(oldID, host string, port int, subdomain string, persist, https bool) error {
	t, err := d.requestOpen(host, port, subdomain, persist, https)
	if err != nil {
		return err
	}
	d.installTunnel(t, oldID)
	return nil
}

func (d *Daemon) requestOpen(host string, port int, subdomain string, persist, https bool) (*Tunnel, error) {
	addr, err := origin.ResolveLoopback(host, port)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	ctrl := d.control
	connected := d.connected
	d.mu.Unlock()
	if !connected || ctrl == nil {
		return nil, errors.New("not connected to gateway")
	}
	env := &controlv1.Envelope{Payload: &controlv1.Envelope_OpenTunnel{OpenTunnel: &controlv1.OpenTunnel{
		Subdomain: subdomain,
		Persist:   persist,
	}}}
	ch := d.expect(env)
	d.log.Debug("open tunnel request", "seq", env.Seq, "port", port, "host", host)
	if err := d.writeControl(ctrl, env); err != nil {
		return nil, err
	}
	var reply *controlv1.Envelope
	select {
	case reply = <-ch:
	case <-time.After(10 * time.Second):
		return nil, errors.New("timeout opening tunnel")
	}
	switch p := reply.Payload.(type) {
	case *controlv1.Envelope_OpenTunnelAck:
		t := Tunnel{
			ID:        p.OpenTunnelAck.GetTunnelId(),
			PublicURL: p.OpenTunnelAck.GetPublicUrl(),
			Hostname:  p.OpenTunnelAck.GetHostname(),
			Local:     addr,
			HTTPS:     https,
			Subdomain: subdomain,
			Status:    "active",
			Persist:   persist,
		}
		return &t, nil
	case *controlv1.Envelope_Error:
		return nil, fmt.Errorf("%s", p.Error.GetMessage())
	default:
		return nil, errors.New("unexpected gateway reply")
	}
}

func (d *Daemon) installTunnel(t *Tunnel, replaceID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	live := &liveTunnel{Tunnel: *t}
	if replaceID != "" {
		if old, ok := d.tunnels[replaceID]; ok {
			live.Requests = atomic.LoadInt64(&old.Requests)
			live.BytesIn = atomic.LoadInt64(&old.BytesIn)
			live.BytesOut = atomic.LoadInt64(&old.BytesOut)
			live.Conns = atomic.LoadInt64(&old.Conns)
		}
		if replaceID != t.ID {
			delete(d.tunnels, replaceID)
			delete(d.local, replaceID)
		}
	}
	d.tunnels[t.ID] = live
	d.local[t.ID] = localOrigin{Addr: t.Local, TLS: t.HTTPS}
	if t.Persist {
		h, pth, _ := origin.ParseHostPort(t.Local)
		d.cfg.UpsertPersistent(TunnelSpec{Host: h, Port: pth, Subdomain: t.Subdomain, HTTPS: t.HTTPS})
		_ = d.cfg.Save()
	}
}

func (d *Daemon) closeTunnel(id string) error {
	d.mu.Lock()
	ctrl := d.control
	t, ok := d.tunnels[id]
	d.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown tunnel")
	}
	// Drop persist first so a reconnect cannot restore this tunnel.
	if t.Persist {
		d.mu.Lock()
		h, p, _ := origin.ParseHostPort(t.Local)
		d.cfg.RemovePersistent(h, p, t.Subdomain)
		_ = d.cfg.Save()
		d.mu.Unlock()
	}
	if ctrl != nil {
		env := &controlv1.Envelope{Payload: &controlv1.Envelope_CloseTunnel{CloseTunnel: &controlv1.CloseTunnel{TunnelId: id}}}
		ch := d.expect(env)
		if err := d.writeControl(ctrl, env); err != nil {
			d.mu.Lock()
			delete(d.pending, env.Seq)
			d.mu.Unlock()
			return fmt.Errorf("notify gateway: %w", err)
		}
		select {
		case reply := <-ch:
			if e := reply.GetError(); e != nil {
				return fmt.Errorf("%s", e.GetMessage())
			}
		case <-time.After(8 * time.Second):
			return fmt.Errorf("timeout waiting for gateway close")
		}
	}
	d.mu.Lock()
	delete(d.tunnels, id)
	delete(d.local, id)
	d.mu.Unlock()
	return nil
}

func (d *Daemon) serveStatus(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	st := Status{
		Connected: d.connected,
		Gateway:   d.gateway,
		Transport: d.transport,
		UserID:    d.cfg.UserID,
		ClientID:  d.cfg.ClientID,
		LatencyMS: float64(d.latency.Load()) / 1e6,
		BytesIn:   d.bytesIn.Load(),
		BytesOut:  d.bytesOut.Load(),
		LastError: d.lastErr,
	}
	d.mu.Unlock()
	writeJSON(w, st)
}

func (d *Daemon) serveList(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	out := make([]Tunnel, 0, len(d.tunnels))
	for _, t := range d.tunnels {
		out = append(out, snapshotTunnel(t))
	}
	d.mu.Unlock()
	writeJSON(w, out)
}

func (d *Daemon) serveOpen(w http.ResponseWriter, r *http.Request) {
	var req openReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if req.Host == "" {
		req.Host = "127.0.0.1"
	}
	t, err := d.openTunnel(req.Host, req.Port, req.Subdomain, req.Persist, req.HTTPS)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writeJSON(w, t)
}

func (d *Daemon) serveClose(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := d.closeTunnel(id); err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.WriteHeader(204)
}

func (d *Daemon) serveEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flush", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
			d.mu.Lock()
			st := Status{
				Connected: d.connected,
				Gateway:   d.gateway,
				Transport: d.transport,
				LatencyMS: float64(d.latency.Load()) / 1e6,
				BytesIn:   d.bytesIn.Load(),
				BytesOut:  d.bytesOut.Load(),
				LastError: d.lastErr,
			}
			tunnels := make([]Tunnel, 0, len(d.tunnels))
			for _, tn := range d.tunnels {
				tunnels = append(tunnels, snapshotTunnel(tn))
			}
			d.mu.Unlock()
			payload, _ := json.Marshal(map[string]any{"status": st, "tunnels": tunnels})
			fmt.Fprintf(w, "data: %s\n\n", payload)
			fl.Flush()
		}
	}
}

func snapshotTunnel(t *liveTunnel) Tunnel {
	tt := t.Tunnel
	tt.Conns = atomic.LoadInt64(&t.Conns)
	tt.Requests = atomic.LoadInt64(&t.Requests)
	tt.BytesIn = atomic.LoadInt64(&t.BytesIn)
	tt.BytesOut = atomic.LoadInt64(&t.BytesOut)
	return tt
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func WaitForDaemon(socket string, timeout time.Duration) error {
	api := NewAPI(socket)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := api.Ping(); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("daemon not running")
}
