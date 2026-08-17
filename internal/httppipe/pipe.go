package httppipe

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const bufSize = 32 * 1024

// ForwardRequest writes the visitor request to the tunnel stream then copies
// the origin response back, flushing as it goes. WebSocket/upgrades hijack.
func ForwardRequest(w http.ResponseWriter, r *http.Request, stream io.ReadWriteCloser) error {
	defer stream.Close()

	if err := r.Write(stream); err != nil {
		return err
	}

	br := bufio.NewReaderSize(stream, bufSize)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		return upgrade(w, resp, br, stream)
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	body := resp.Body
	defer body.Close()
	return copyFlush(w, body)
}

// ServeOrigin reads an HTTP/1.1 request from the stream, dials the loopback
// origin, and pipes until both sides close.
func ServeOrigin(stream io.ReadWriteCloser, addr string, timeout time.Duration) error {
	defer stream.Close()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	br := bufio.NewReaderSize(stream, bufSize)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	origin, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		writeErr(stream, err)
		return err
	}
	defer origin.Close()
	req.RequestURI = ""
	if err := req.Write(origin); err != nil {
		return err
	}
	rest := io.MultiReader(br, stream)
	return bidir(origin, rest, stream, origin)
}

func upgrade(w http.ResponseWriter, resp *http.Response, br *bufio.Reader, stream io.ReadWriteCloser) error {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return errors.New("hijack not supported")
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := resp.Write(bufrw); err != nil {
		return err
	}
	if err := bufrw.Flush(); err != nil {
		return err
	}
	rest := io.MultiReader(br, stream)
	return bidir(conn, rest, stream, conn)
}

func bidir(dstA io.Writer, srcA io.Reader, dstB io.Writer, srcB io.Reader) error {
	var wg sync.WaitGroup
	wg.Add(2)
	errc := make(chan error, 2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(dstA, srcA)
		errc <- err
		closeWrite(dstA)
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(dstB, srcB)
		errc <- err
		closeWrite(dstB)
	}()
	wg.Wait()
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	default:
	}
	return nil
}

func copyFlush(w io.Writer, src io.Reader) error {
	buf := make([]byte, bufSize)
	flusher, _ := w.(http.Flusher)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func closeWrite(w io.Writer) {
	type cw interface{ CloseWrite() error }
	if c, ok := w.(cw); ok {
		_ = c.CloseWrite()
	}
}

func writeErr(w io.Writer, err error) {
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	_ = resp.Write(w)
	_, _ = io.WriteString(w, "origin unreachable")
	_ = err
}
