package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

func (s *Server) setupACME() error {
	email := s.cfg.ACME.Email
	if email == "" {
		return fmt.Errorf("acme.email is required when acme.enabled is true")
	}
	token := s.cfg.ACME.CloudflareToken
	if token == "" {
		token = os.Getenv("CF_API_TOKEN")
	}
	issuer := &certmagic.ACMEIssuer{
		CA:     certmagic.LetsEncryptProductionCA,
		Email:  email,
		Agreed: true,
	}
	switch strings.ToLower(s.cfg.ACME.DNSProvider) {
	case "cloudflare":
		if token == "" {
			return fmt.Errorf("acme cloudflare token missing (acme.cloudflare_api_token or CF_API_TOKEN)")
		}
		issuer.DNS01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &cloudflare.Provider{APIToken: token},
			},
		}
	case "":
		return fmt.Errorf("acme.dns_provider is required for wildcard certificates (supported: cloudflare)")
	default:
		return fmt.Errorf("unsupported acme.dns_provider %q", s.cfg.ACME.DNSProvider)
	}
	magic := certmagic.NewDefault()
	magic.Issuers = []certmagic.Issuer{issuer}
	names := []string{s.cfg.BaseDomain, "*." + s.cfg.BaseDomain}
	if err := magic.ManageSync(context.Background(), names); err != nil {
		return fmt.Errorf("acme: %w", err)
	}
	cfg := magic.TLSConfig()
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{"h2", "http/1.1"}
	s.publicTLS = cfg
	return nil
}
