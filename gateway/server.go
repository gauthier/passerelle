package gateway

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
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gauthier/passerelle/gateway/identity"
	"github.com/gauthier/passerelle/gateway/metrics"
	"github.com/gauthier/passerelle/gateway/router"
	"github.com/gauthier/passerelle/gateway/tunnel"
	"github.com/gauthier/passerelle/internal/httppipe"
	"github.com/gauthier/passerelle/internal/limits"
	"github.com/gauthier/passerelle/internal/logging"
	"github.com/gauthier/passerelle/internal/tlsutil"
	"github.com/gauthier/passerelle/internal/tunnelconn"
	"github.com/gauthier/passerelle/internal/version"
	"github.com/gauthier/passerelle/protocol"
	controlv1 "github.com/gauthier/passerelle/protocol/controlv1"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

type Server struct {
	cfg      Config
	log      *slog.Logger
	store    *identity.Store
	reg      *router.Registry
	metrics  *metrics.Metrics
	conns    *limits.Conns
	enrollRL *rate.Limiter

	publicTLS *tls.Config
	tunnelTLS *tls.Config

	httpsLn net.Listener
	httpLn  net.Listener
	httpCh  *chanListener
	quicLn  *quic.Listener
	udpConn net.PacketConn

	httpServer *http.Server
	plainMux   http.Handler

	mu       sync.Mutex
	sessions map[string]*tunnel.Session
}

func New(cfg Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = logging.New(cfg.LogFormat, cfg.LogLevel)
	}
	store, err := identity.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if cfg.Quotas.DefaultMaxDevices > 0 {
		// applied per-user at creation; defaults live on new users
	}
	reg := router.New(cfg.BaseDomain, cfg.Grace)
	m := metrics.New()
	s := &Server{
		cfg:      cfg,
		log:      log,
		store:    store,
		reg:      reg,
		metrics:  m,
		enrollRL: rate.NewLimiter(rate.Every(time.Second), 10),
		sessions: make(map[string]*tunnel.Session),
	}
	s.conns = limits.NewConns(func(userID string) int {
		u, err := store.User(userID)
		if err != nil {
			return cfg.Quotas.DefaultMaxConns
		}
		if u.Quotas.MaxConns > 0 {
			return u.Quotas.MaxConns
		}
		return cfg.Quotas.DefaultMaxConns
	})
	reg.SetOnChange(func(n int) {
		m.Tunnels.Set(float64(n))
	})
	if err := s.initTLS(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) Store() *identity.Store     { return s.store }
func (s *Server) Registry() *router.Registry { return s.reg }
func (s *Server) Config() Config             { return s.cfg }

func (s *Server) initTLS() error {
	dns := []string{s.cfg.BaseDomain, "*." + s.cfg.BaseDomain}
	var ips []net.IP
	if s.cfg.Dev {
		ips = []net.IP{net.ParseIP("127.0.0.1")}
	}
	gwCertPEM, gwKeyPEM, err := s.store.CA.IssueGateway(dns, ips)
	if err != nil {
		return err
	}
	gwCert, err := tlsutil.TLSCertFromPEM(gwCertPEM, gwKeyPEM)
	if err != nil {
		return err
	}
	pool, err := tlsutil.PoolFromPEM(s.store.CA.PEM)
	if err != nil {
		return err
	}
	s.tunnelTLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{gwCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{protocol.ALPN},
	}

	var pub tls.Certificate
	switch {
	case s.cfg.ACME.Enabled:
		return s.setupACME()
	case s.cfg.TLSCert != "" && s.cfg.TLSKey != "":
		pub, err = tlsutil.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return err
		}
	default:
		certPath := filepath.Join(s.cfg.DataDir, tlsutil.PubCertFile)
		keyPath := filepath.Join(s.cfg.DataDir, tlsutil.PubKeyFile)
		if _, err := os.Stat(certPath); err == nil {
			pub, err = tlsutil.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return err
			}
		} else {
			if !s.cfg.Dev {
				return fmt.Errorf("tls_cert/tls_key required (or enable acme, or --dev)")
			}
			pem, key, err := tlsutil.SelfSignedPublic(dns, []net.IP{net.ParseIP("127.0.0.1")})
			if err != nil {
				return err
			}
			if err := tlsutil.WritePair(s.cfg.DataDir, tlsutil.PubCertFile, tlsutil.PubKeyFile, pem, key); err != nil {
				return err
			}
			pub, err = tlsutil.TLSCertFromPEM(pem, key)
			if err != nil {
				return err
			}
		}
	}
	s.publicTLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pub},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	return nil
}

func (s *Server) muxTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{protocol.ALPN, "h2", "http/1.1"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			for _, p := range chi.SupportedProtos {
				if p == protocol.ALPN {
					return s.tunnelTLS, nil
				}
			}
			return s.publicTLS, nil
		},
	}
}

func (s *Server) Run(ctx context.Context) error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve(ctx)
}

func (s *Server) Listen() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", s.handleEnroll)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", s.handlePublic)
	s.plainMux = mux

	s.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    protocol.MaxHeaderBytes,
	}
	_ = http2.ConfigureServer(s.httpServer, &http2.Server{})

	ln, err := tls.Listen("tcp", s.cfg.ListenHTTPS, s.muxTLS())
	if err != nil {
		return fmt.Errorf("https listen: %w", err)
	}
	s.httpsLn = ln
	s.httpCh = newChanListener(ln.Addr())

	if s.cfg.ListenHTTP != "" {
		hl, err := net.Listen("tcp", s.cfg.ListenHTTP)
		if err != nil {
			return fmt.Errorf("http listen: %w", err)
		}
		s.httpLn = hl
	}

	quicAddr := s.cfg.ListenQUIC
	if quicAddr == "" {
		quicAddr = s.cfg.ListenHTTPS
	}
	udp, err := net.ListenPacket("udp", quicAddr)
	if err != nil {
		return fmt.Errorf("quic listen: %w", err)
	}
	s.udpConn = udp
	qln, err := tunnelconn.ListenQUIC(udp, s.tunnelTLS)
	if err != nil {
		return fmt.Errorf("quic: %w", err)
	}
	s.quicLn = qln
	s.log.Info("gateway listening",
		"https", s.ListenHTTPSAddr(),
		"http", s.ListenHTTPAddr(),
		"quic", s.ListenQUICAddr(),
		"domain", s.cfg.BaseDomain,
		"version", version.Version,
	)
	return nil
}

func (s *Server) Serve(ctx context.Context) error {
	if s.httpServer != nil {
		s.httpServer.BaseContext = func(net.Listener) context.Context { return ctx }
		go func() {
			if err := s.httpServer.Serve(s.httpCh); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.log.Error("https server", "err", err)
			}
		}()
	}
	if s.httpLn != nil {
		go func() {
			hs := &http.Server{
				Handler:           s.httpRedirectOrDev(s.plainMux),
				ReadHeaderTimeout: 10 * time.Second,
				BaseContext:       func(net.Listener) context.Context { return ctx },
			}
			if err := hs.Serve(s.httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.log.Error("http server", "err", err)
			}
		}()
	}
	if s.cfg.Metrics.Listen != "" {
		go s.serveMetrics(ctx)
	}
	go s.serveTCP(ctx)
	go s.serveQUIC(ctx)
	<-ctx.Done()
	return s.Shutdown()
}

func (s *Server) ListenHTTPSAddr() string {
	if s.httpsLn == nil {
		return s.cfg.ListenHTTPS
	}
	return s.httpsLn.Addr().String()
}

func (s *Server) ListenHTTPAddr() string {
	if s.httpLn == nil {
		return s.cfg.ListenHTTP
	}
	return s.httpLn.Addr().String()
}

func (s *Server) ListenQUICAddr() string {
	if s.udpConn == nil {
		return s.cfg.ListenQUIC
	}
	return s.udpConn.LocalAddr().String()
}

func (s *Server) httpRedirectOrDev(mux http.Handler) http.Handler {
	if s.cfg.Dev {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			mux.ServeHTTP(w, r)
			return
		}
		host := r.Host
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func (s *Server) serveTCP(ctx context.Context) {
	for {
		c, err := s.httpsLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Debug("accept", "err", err)
			continue
		}
		go s.handleTCP(ctx, c)
	}
}

func (s *Server) handleTCP(ctx context.Context, c net.Conn) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		c.Close()
		return
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		c.Close()
		return
	}
	alpn := tc.ConnectionState().NegotiatedProtocol
	if alpn == protocol.ALPN {
		s.handleTunnelTCP(ctx, tc)
		return
	}
	if s.httpCh != nil {
		s.httpCh.Enqueue(tc)
		return
	}
	_ = tc.Close()
}

func (s *Server) handleTunnelTCP(ctx context.Context, tc *tls.Conn) {
	userID, clientID, err := tunnel.IdentityFromTLS(tc.ConnectionState())
	if err != nil {
		s.log.Info("tunnel tcp rejected", "err", err)
		_ = tc.Close()
		return
	}
	if err := s.store.CheckDevice(userID, clientID, ""); err != nil {
		s.log.Info("tunnel device rejected", "user_id", userID, "client_id", clientID, "err", err)
		_ = tc.Close()
		return
	}
	gc, err := tunnelconn.NewH2Gateway(tc)
	if err != nil {
		s.log.Info("h2 gateway", "err", err)
		_ = tc.Close()
		return
	}
	sess, err := tunnel.FromH2(ctx, gc, userID, clientID)
	if err != nil {
		s.log.Info("h2 session", "err", err)
		_ = gc.Close()
		return
	}
	s.serveSession(ctx, sess)
}

func (s *Server) serveQUIC(ctx context.Context) {
	for {
		c, err := s.quicLn.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Debug("quic accept", "err", err)
			continue
		}
		go func(c *quic.Conn) {
			sess, err := tunnel.FromQUIC(ctx, c)
			if err != nil {
				s.log.Info("quic session", "err", err)
				return
			}
			if err := s.store.CheckDevice(sess.UserID(), sess.ClientID(), ""); err != nil {
				s.log.Info("quic device rejected", "user_id", sess.UserID(), "client_id", sess.ClientID(), "err", err)
				_ = sess.Close()
				return
			}
			s.serveSession(ctx, sess)
		}(c)
	}
}

func (s *Server) serveSession(ctx context.Context, sess *tunnel.Session) {
	s.mu.Lock()
	s.sessions[sess.ClientID()] = sess
	s.mu.Unlock()
	s.metrics.Clients.Inc()
	defer func() {
		s.metrics.Clients.Dec()
		s.reg.DisconnectClient(sess.ClientID())
		s.mu.Lock()
		if s.sessions[sess.ClientID()] == sess {
			delete(s.sessions, sess.ClientID())
		}
		s.mu.Unlock()
		_ = sess.Close()
	}()
	s.log.Info("client connected", "user_id", sess.UserID(), "client_id", sess.ClientID())
	ctrl := sess.Control()
	for {
		env, err := tunnelconn.ReadEnvelope(ctrl)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.log.Debug("control closed", "client_id", sess.ClientID(), "err", err)
			}
			return
		}
		s.log.Debug("control message", "client_id", sess.ClientID(), "seq", env.Seq, "type", fmt.Sprintf("%T", env.Payload))
		if err := s.handleControl(sess, env); err != nil {
			s.log.Info("control error", "client_id", sess.ClientID(), "err", err)
			_ = tunnelconn.WriteEnvelope(ctrl, &controlv1.Envelope{
				Payload: &controlv1.Envelope_Error{Error: &controlv1.Error{Code: "internal", Message: err.Error()}},
			})
		}
	}
}

func (s *Server) handleControl(sess *tunnel.Session, env *controlv1.Envelope) error {
	switch p := env.Payload.(type) {
	case *controlv1.Envelope_Hello:
		return tunnelconn.WriteEnvelope(sess.Control(), &controlv1.Envelope{
			Seq: env.Seq,
			Payload: &controlv1.Envelope_HelloAck{HelloAck: &controlv1.HelloAck{
				Protocol:       protocol.ProtocolMax,
				GatewayVersion: version.Version,
			}},
		})
	case *controlv1.Envelope_KeepAlive:
		return tunnelconn.WriteEnvelope(sess.Control(), env)
	case *controlv1.Envelope_OpenTunnel:
		return s.openTunnel(sess, env.Seq, p.OpenTunnel)
	case *controlv1.Envelope_CloseTunnel:
		id := p.CloseTunnel.GetTunnelId()
		if alloc, _, ok := s.reg.GetTunnel(id); ok {
			if alloc.UserID != sess.UserID() {
				return fmt.Errorf("tunnel not owned")
			}
			s.log.Info("tunnel close", "user_id", sess.UserID(), "hostname", alloc.Hostname, "tunnel_id", id)
		}
		s.reg.Release(id)
		return tunnelconn.WriteEnvelope(sess.Control(), &controlv1.Envelope{
			Seq: env.Seq,
			Payload: &controlv1.Envelope_CloseTunnelAck{CloseTunnelAck: &controlv1.CloseTunnelAck{
				TunnelId: id,
			}},
		})
	default:
		return fmt.Errorf("unexpected control message")
	}
}

func (s *Server) openTunnel(sess *tunnel.Session, seq uint64, req *controlv1.OpenTunnel) error {
	u, err := s.store.User(sess.UserID())
	if err != nil {
		return err
	}
	maxT := u.Quotas.MaxTunnels
	if maxT <= 0 {
		maxT = s.cfg.Quotas.DefaultMaxTunnels
	}
	if s.reg.CountForUser(sess.UserID()) >= maxT {
		return tunnelconn.WriteEnvelope(sess.Control(), &controlv1.Envelope{
			Seq:     seq,
			Payload: &controlv1.Envelope_Error{Error: &controlv1.Error{Code: "quota", Message: "tunnel quota exceeded"}},
		})
	}
	alloc, err := s.reg.Allocate(sess, req.GetSubdomain(), req.GetPersist())
	if err != nil {
		return tunnelconn.WriteEnvelope(sess.Control(), &controlv1.Envelope{
			Seq:     seq,
			Payload: &controlv1.Envelope_Error{Error: &controlv1.Error{Code: "allocate", Message: err.Error()}},
		})
	}
	port := s.cfg.PublicPort
	if port == 0 {
		if addr, ok := s.httpsLn.Addr().(*net.TCPAddr); ok {
			port = addr.Port
		}
	}
	url := router.PublicURL(s.cfg.PublicScheme, alloc.Hostname, port)
	s.log.Info("tunnel open", "user_id", sess.UserID(), "hostname", alloc.Hostname, "persist", alloc.Persist)
	return tunnelconn.WriteEnvelope(sess.Control(), &controlv1.Envelope{
		Seq: seq,
		Payload: &controlv1.Envelope_OpenTunnelAck{OpenTunnelAck: &controlv1.OpenTunnelAck{
			TunnelId:  alloc.TunnelID,
			Hostname:  alloc.Hostname,
			PublicUrl: url,
		}},
	})
}

func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/enroll" {
		s.handleEnroll(w, r)
		return
	}
	host := r.Host
	alloc, sess, ok := s.reg.Lookup(host)
	if !ok {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}
	release, err := s.conns.Acquire(alloc.UserID)
	if err != nil {
		http.Error(w, "too many connections", http.StatusTooManyRequests)
		return
	}
	defer release()
	s.metrics.Requests.Inc()
	stream, err := sess.OpenDataStream()
	if err != nil {
		http.Error(w, "tunnel unavailable", http.StatusBadGateway)
		return
	}
	if err := tunnelconn.WritePreamble(stream, alloc.TunnelID); err != nil {
		_ = stream.Close()
		http.Error(w, "tunnel unavailable", http.StatusBadGateway)
		return
	}
	if err := httppipe.ForwardRequest(w, r, stream); err != nil {
		s.log.Debug("proxy", "err", err, "host", host)
	}
}

type enrollRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

type enrollResponse struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
	UserID      string `json:"user_id"`
	ClientID    string `json:"client_id"`
	TunnelQUIC  string `json:"tunnel_quic"`
	TunnelTLS   string `json:"tunnel_tls"`
	BaseDomain  string `json:"base_domain"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	s.metrics.Enroll.Inc()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.enrollRL.Allow() {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	userID, err := s.store.ConsumeToken(req.Token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	certPEM, clientID, _, err := s.store.Enroll(userID, req.CSR)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	quicAddr := s.advertiseAddr(s.ListenQUICAddr(), r)
	tlsAddr := s.advertiseAddr(s.ListenHTTPSAddr(), r)
	resp := enrollResponse{
		Certificate: string(certPEM),
		CA:          string(s.store.CA.PEM),
		UserID:      userID,
		ClientID:    clientID,
		TunnelQUIC:  quicAddr,
		TunnelTLS:   tlsAddr,
		BaseDomain:  s.cfg.BaseDomain,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
	s.log.Info("enrolled", "user_id", userID, "client_id", clientID)
}

func (s *Server) advertiseAddr(listen string, r *http.Request) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		h, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			h = r.Host
		}
		if h == "" {
			h = "127.0.0.1"
		}
		return net.JoinHostPort(h, port)
	}
	if host == "127.0.0.1" || host == "::1" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return listen
}

func (s *Server) serveMetrics(ctx context.Context) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", s.metrics.Handler())
	srv := &http.Server{Addr: s.cfg.Metrics.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", s.cfg.Metrics.Listen)
	if err != nil {
		s.log.Warn("metrics listen", "err", err)
		return
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	s.log.Info("metrics", "listen", ln.Addr().String())
	_ = srv.Serve(ln)
}

func (s *Server) Shutdown() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = s.httpServer.Shutdown(ctx)
		cancel()
	}
	if s.httpCh != nil {
		_ = s.httpCh.Close()
	}
	if s.httpsLn != nil {
		_ = s.httpsLn.Close()
	}
	if s.httpLn != nil {
		_ = s.httpLn.Close()
	}
	if s.quicLn != nil {
		_ = s.quicLn.Close()
	}
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
	return nil
}

type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{addr: addr, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) Enqueue(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }
