package httppipe_test

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gauthier/passerelle/internal/httppipe"
)

func TestServeOriginTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "from-tls-origin")
	}))
	t.Cleanup(origin.Close)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	errc := make(chan error, 1)
	statsc := make(chan httppipe.OriginStats, 1)
	go func() {
		st, err := httppipe.ServeOrigin(server, origin.Listener.Addr().String(), 2*time.Second, &tls.Config{
			InsecureSkipVerify: true,
		})
		statsc <- st
		errc <- err
	}()

	req, err := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "from-tls-origin" {
		t.Fatalf("got %q", body)
	}
	_ = client.Close()
	select {
	case <-errc:
		st := <-statsc
		if st.ToOrigin == 0 || st.FromOrigin == 0 {
			t.Fatalf("stats %+v", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeOrigin did not return")
	}
}
