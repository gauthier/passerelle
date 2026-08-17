package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type APIClient struct {
	http *http.Client
	base string
}

func NewAPI(socket string) *APIClient {
	if socket == "" {
		socket = SocketPath()
	}
	t := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return dialIPC(socket)
		},
	}
	return &APIClient{
		http: &http.Client{Transport: t, Timeout: 15 * time.Second},
		base: "http://daemon",
	}
}

func (c *APIClient) Status() (*Status, error) {
	var st Status
	if err := c.get("/v1/status", &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (c *APIClient) List() ([]Tunnel, error) {
	var out []Tunnel
	if err := c.get("/v1/tunnels", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *APIClient) Open(host string, port int, subdomain string, persist, https bool) (*Tunnel, error) {
	body, _ := json.Marshal(openReq{Host: host, Port: port, Subdomain: subdomain, Persist: persist, HTTPS: https})
	var t Tunnel
	if err := c.do(http.MethodPost, "/v1/tunnels", bytes.NewReader(body), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (c *APIClient) Close(id string) error {
	return c.do(http.MethodDelete, "/v1/tunnels/"+id, nil, nil)
}

func (c *APIClient) Events(ctx context.Context) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/events", nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func (c *APIClient) Ping() error {
	_, err := c.Status()
	return err
}

func (c *APIClient) get(path string, out any) error {
	return c.do(http.MethodGet, path, nil, out)
}

func (c *APIClient) do(method, path string, body io.Reader, out any) error {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return fmt.Errorf("daemon: %s", bytes.TrimSpace(b))
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, out)
}

type openReq struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Subdomain string `json:"subdomain"`
	Persist   bool   `json:"persist"`
	HTTPS     bool   `json:"https,omitempty"`
}

type Status struct {
	Connected bool    `json:"connected"`
	Gateway   string  `json:"gateway"`
	Transport string  `json:"transport"`
	UserID    string  `json:"user_id"`
	ClientID  string  `json:"client_id"`
	LatencyMS float64 `json:"latency_ms"`
	BytesIn   int64   `json:"bytes_in"`
	BytesOut  int64   `json:"bytes_out"`
	LastError string  `json:"last_error,omitempty"`
}

type Tunnel struct {
	ID        string `json:"id"`
	PublicURL string `json:"public_url"`
	Hostname  string `json:"hostname"`
	Local     string `json:"local"`
	HTTPS     bool   `json:"https,omitempty"`
	Status    string `json:"status"`
	Persist   bool   `json:"persist"`
	Conns     int64  `json:"connections"`
	BytesIn   int64  `json:"bytes_in"`
	BytesOut  int64  `json:"bytes_out"`
}
