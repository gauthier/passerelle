package gateway

import (
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	BaseDomain   string        `toml:"base_domain"`
	ListenHTTPS  string        `toml:"listen_https"`
	ListenHTTP   string        `toml:"listen_http"`
	ListenQUIC   string        `toml:"listen_quic"`
	DataDir      string        `toml:"data_dir"`
	TLSCert      string        `toml:"tls_cert"`
	TLSKey       string        `toml:"tls_key"`
	LogFormat    string        `toml:"log_format"`
	LogLevel     string        `toml:"log_level"`
	PublicScheme string        `toml:"public_scheme"`
	PublicPort   int           `toml:"public_port"`
	Dev          bool          `toml:"dev"`
	Grace        time.Duration `toml:"grace"`
	ACME         ACMEConfig    `toml:"acme"`
	Metrics      MetricsConfig `toml:"metrics"`
	Quotas       QuotaConfig   `toml:"quotas"`
}

type ACMEConfig struct {
	Enabled         bool   `toml:"enabled"`
	Email           string `toml:"email"`
	DNSProvider     string `toml:"dns_provider"`
	CloudflareToken string `toml:"cloudflare_api_token"`
}

type MetricsConfig struct {
	Listen string `toml:"listen"`
}

type QuotaConfig struct {
	DefaultMaxDevices int `toml:"default_max_devices"`
	DefaultMaxTunnels int `toml:"default_max_tunnels"`
	DefaultMaxConns   int `toml:"default_max_conns"`
}

func Defaults() Config {
	return Config{
		BaseDomain:   "passerelle.local",
		ListenHTTPS:  ":8443",
		ListenHTTP:   "127.0.0.1:8080",
		ListenQUIC:   ":8443",
		DataDir:      "/var/lib/passerelle",
		LogFormat:    "json",
		LogLevel:     "info",
		PublicScheme: "https",
		Grace:        2 * time.Minute,
		Metrics:      MetricsConfig{Listen: "127.0.0.1:9091"},
		Quotas: QuotaConfig{
			DefaultMaxDevices: 5,
			DefaultMaxTunnels: 10,
			DefaultMaxConns:   100,
		},
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := toml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}
