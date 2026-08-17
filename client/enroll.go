package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gauthier/passerelle/internal/tlsutil"
)

const DefaultGatewayURL = "https://passerelle.gnthr.dev"

type EnrollInput struct {
	GatewayURL string
	Token      string
	Insecure   bool
}

func NormalizeGatewayURL(s string) string {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	if s == "" {
		return DefaultGatewayURL
	}
	if !strings.Contains(s, "://") {
		return "https://" + s
	}
	return s
}

func Enroll(in EnrollInput) (Config, error) {
	csr, key, err := tlsutil.CreateCSR()
	if err != nil {
		return Config{}, err
	}
	body, _ := json.Marshal(map[string]string{
		"token": in.Token,
		"csr":   string(csr),
	})
	in.GatewayURL = NormalizeGatewayURL(in.GatewayURL)
	url := in.GatewayURL + "/v1/enroll"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Config{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 20 * time.Second}
	if in.Insecure {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	res, err := hc.Do(req)
	if err != nil {
		return Config{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(res.Body)
		return Config{}, fmt.Errorf("enroll failed (%d): %s", res.StatusCode, strings.TrimSpace(buf.String()))
	}
	var out struct {
		Certificate string `json:"certificate"`
		CA          string `json:"ca"`
		UserID      string `json:"user_id"`
		ClientID    string `json:"client_id"`
		TunnelQUIC  string `json:"tunnel_quic"`
		TunnelTLS   string `json:"tunnel_tls"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return Config{}, err
	}
	if err := StorePrivateKey(key); err != nil {
		return Config{}, err
	}
	cfg := Config{
		EnrollURL:          in.GatewayURL,
		TunnelQUIC:         out.TunnelQUIC,
		TunnelTLS:          out.TunnelTLS,
		UserID:             out.UserID,
		ClientID:           out.ClientID,
		CAPEM:              out.CA,
		CertPEM:            out.Certificate,
		InsecureSkipVerify: in.Insecure,
	}
	if err := cfg.Save(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
