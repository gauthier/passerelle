package gateway_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gauthier/passerelle/client"
	"github.com/gauthier/passerelle/gateway"
	"github.com/gauthier/passerelle/gateway/identity"
	"github.com/gauthier/passerelle/internal/logging"
)

func TestLoopbackOpenHTTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			_, _ = io.WriteString(w, "hello-")
			f.Flush()
			_, _ = io.WriteString(w, "world")
			return
		}
		_, _ = io.WriteString(w, "hello-world")
	}))
	t.Cleanup(origin.Close)
	_, originPortStr, err := net.SplitHostPort(origin.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	originPort, err := strconv.Atoi(originPortStr)
	if err != nil {
		t.Fatal(err)
	}

	data := t.TempDir()
	cfg := gateway.Defaults()
	cfg.Dev = true
	cfg.DataDir = data
	cfg.BaseDomain = "passerelle.test"
	cfg.ListenHTTPS = "127.0.0.1:0"
	cfg.ListenHTTP = "127.0.0.1:0"
	cfg.ListenQUIC = "127.0.0.1:0"
	cfg.Metrics.Listen = "127.0.0.1:0"
	cfg.LogFormat = "text"
	cfg.PublicScheme = "https"

	gw, err := gateway.New(cfg, logging.New("text", "error"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Store().AddUser("alice", identity.DefaultQuotas()); err != nil {
		t.Fatal(err)
	}
	tok, err := gw.Store().CreateToken("alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := gw.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = gw.Serve(ctx) }()

	cliDir := t.TempDir()
	t.Setenv("PASSERELLE_CONFIG_DIR", cliDir)
	sock := filepath.Join(cliDir, "daemon.sock")
	t.Setenv("PASSERELLE_SOCK", sock)
	_ = os.MkdirAll(cliDir, 0o700)

	if _, err := client.Enroll(client.EnrollInput{
		GatewayURL: "http://" + gw.ListenHTTPAddr(),
		Token:      tok,
		Insecure:   true,
	}); err != nil {
		t.Fatal(err)
	}

	d := client.NewDaemon(logging.New("text", "error"), sock)
	go func() { _ = d.Run(ctx) }()
	if err := client.WaitForDaemon(sock, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	api := client.NewAPI(sock)
	deadline := time.Now().Add(8 * time.Second)
	var st *client.Status
	for time.Now().Before(deadline) {
		st, err = api.Status()
		if err == nil && st.Connected {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if st == nil || !st.Connected {
		t.Fatalf("client not connected: %+v err=%v", st, err)
	}

	tun, err := api.Open("127.0.0.1", originPort, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if tun.PublicURL == "" || tun.Hostname == "" {
		t.Fatalf("missing url: %+v", tun)
	}

	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			ServerName:         tun.Hostname,
		}},
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+gw.ListenHTTPSAddr()+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = tun.Hostname
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello-world" {
		t.Fatalf("body %q status %d", body, res.StatusCode)
	}

	list, err := api.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("tunnels: %+v", list)
	}
}
