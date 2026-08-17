package client

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	EnrollURL          string       `json:"enroll_url"`
	TunnelQUIC         string       `json:"tunnel_quic"`
	TunnelTLS          string       `json:"tunnel_tls"`
	UserID             string       `json:"user_id"`
	ClientID           string       `json:"client_id"`
	CAPEM              string       `json:"ca_pem"`
	CertPEM            string       `json:"cert_pem"`
	InsecureSkipVerify bool         `json:"insecure_skip_verify,omitempty"`
	Persistent         []TunnelSpec `json:"persistent_tunnels,omitempty"`
}

type TunnelSpec struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Subdomain string `json:"subdomain,omitempty"`
	HTTPS     bool   `json:"https,omitempty"`
}

func Dir() string {
	if d := os.Getenv("PASSERELLE_CONFIG_DIR"); d != "" {
		return d
	}
	base, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "passerelle")
}

func Path() string { return filepath.Join(Dir(), "config.json") }

func SocketPath() string {
	if p := os.Getenv("PASSERELLE_SOCK"); p != "" {
		return p
	}
	return filepath.Join(Dir(), "daemon.sock")
}

func Load() (Config, error) {
	var c Config
	b, err := os.ReadFile(Path())
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

func (c Config) Save() error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := Path() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, Path())
}

func (c *Config) UpsertPersistent(spec TunnelSpec) {
	for i, p := range c.Persistent {
		if p.Host == spec.Host && p.Port == spec.Port && p.Subdomain == spec.Subdomain {
			c.Persistent[i] = spec
			return
		}
	}
	c.Persistent = append(c.Persistent, spec)
}

func (c *Config) RemovePersistent(host string, port int, subdomain string) {
	out := c.Persistent[:0]
	for _, p := range c.Persistent {
		same := p.Host == host && p.Port == port
		if same && (subdomain == "" || p.Subdomain == subdomain) {
			continue
		}
		out = append(out, p)
	}
	c.Persistent = out
}
