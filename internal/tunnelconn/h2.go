package tunnelconn

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/gauthier/passerelle/protocol"
	"golang.org/x/net/http2"
)

type Stream = io.ReadWriteCloser

type H2ClientHandlers struct {
	OnControl func(Stream)
	OnData    func(Stream)
}

func ServeH2Daemon(ctx context.Context, conn net.Conn, h H2ClientHandlers) error {
	h2s := &http2.Server{IdleTimeout: 90 * time.Second}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		st := &flushStream{r: r.Body, w: w, f: flusherOf(w)}
		switch r.URL.Path {
		case protocol.H2ControlPath:
			if h.OnControl != nil {
				h.OnControl(st)
			}
		case protocol.H2DataPath:
			if h.OnData != nil {
				h.OnData(st)
			}
		default:
			http.NotFound(w, r)
		}
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		h2s.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: handler})
	}()
	select {
	case <-ctx.Done():
		_ = conn.Close()
		<-done
		return ctx.Err()
	case <-done:
		return nil
	}
}

type H2GatewayConn struct {
	cc   *http2.ClientConn
	conn net.Conn
}

func NewH2Gateway(conn net.Conn) (*H2GatewayConn, error) {
	tr := &http2.Transport{AllowHTTP: true}
	cc, err := tr.NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	return &H2GatewayConn{cc: cc, conn: conn}, nil
}

func (g *H2GatewayConn) OpenControl(ctx context.Context) (Stream, error) {
	return g.open(ctx, protocol.H2ControlPath)
}

func (g *H2GatewayConn) OpenData(ctx context.Context) (Stream, error) {
	return g.open(ctx, protocol.H2DataPath)
}

func (g *H2GatewayConn) Close() error {
	g.cc.Close()
	return g.conn.Close()
}

func (g *H2GatewayConn) open(ctx context.Context, path string) (Stream, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://passerelle"+path, pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := g.cc.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		return nil, err
	}
	return &halfConn{r: res.Body, w: pw, c: closerFunc(func() error {
		_ = pw.Close()
		return res.Body.Close()
	})}, nil
}

type halfConn struct {
	r io.Reader
	w io.Writer
	c io.Closer
}

func (h *halfConn) Read(p []byte) (int, error)  { return h.r.Read(p) }
func (h *halfConn) Write(p []byte) (int, error) { return h.w.Write(p) }
func (h *halfConn) Close() error {
	if h.c != nil {
		return h.c.Close()
	}
	return nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

type flushStream struct {
	r io.Reader
	w io.Writer
	f http.Flusher
}

func (s *flushStream) Read(p []byte) (int, error) { return s.r.Read(p) }
func (s *flushStream) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if s.f != nil {
		s.f.Flush()
	}
	return n, err
}
func (s *flushStream) Close() error {
	if c, ok := s.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func flusherOf(w http.ResponseWriter) http.Flusher {
	f, _ := w.(http.Flusher)
	return f
}
