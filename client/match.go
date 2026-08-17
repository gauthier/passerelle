package client

import (
	"net"
	"strings"
)

func (t Tunnel) LocalDisplay() string {
	if t.HTTPS {
		return "https://" + t.Local
	}
	return t.Local
}

// MatchTunnels returns tunnels that match a user-facing ref: id, public URL,
// hostname, subdomain, local address, or local port.
func MatchTunnels(list []Tunnel, ref string) []Tunnel {
	raw := strings.TrimSpace(ref)
	if raw == "" {
		return nil
	}
	n := normalizeRef(raw)
	var out []Tunnel
	for _, t := range list {
		if tunnelMatches(t, raw, n) {
			out = append(out, t)
		}
	}
	return out
}

func tunnelMatches(t Tunnel, raw, n string) bool {
	if strings.EqualFold(t.ID, raw) {
		return true
	}
	if normalizeRef(t.PublicURL) == n {
		return true
	}
	if normalizeRef(t.Hostname) == n {
		return true
	}
	if host, _, ok := strings.Cut(t.Hostname, "."); ok && strings.EqualFold(host, raw) {
		return true
	}
	if t.Subdomain != "" && strings.EqualFold(t.Subdomain, raw) {
		return true
	}
	if normalizeRef(t.Local) == n || normalizeRef(t.LocalDisplay()) == n {
		return true
	}
	if _, port, err := net.SplitHostPort(t.Local); err == nil && port == raw {
		return true
	}
	return false
}

func normalizeRef(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "/")
	return strings.ToLower(s)
}
