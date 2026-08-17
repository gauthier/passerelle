package origin

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ResolveLoopback returns a loopback host:port to dial. Default host is 127.0.0.1.
// The hostname "localhost" is resolved and accepted only if it is loopback.
func ResolveLoopback(host string, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port %d", port)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.IsLoopback() {
			return "", fmt.Errorf("refusing to dial non-loopback address %s", host)
		}
		return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(nil, "ip", host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, a := range addrs {
		if a.IsLoopback() {
			return net.JoinHostPort(a.Unmap().String(), fmt.Sprintf("%d", port)), nil
		}
	}
	return "", fmt.Errorf("host %q does not resolve to loopback", host)
}

func ParseHostPort(spec string) (host string, port int, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", 0, fmt.Errorf("empty target")
	}
	if !strings.Contains(spec, ":") {
		var p int
		if _, err := fmt.Sscanf(spec, "%d", &p); err != nil {
			return "", 0, fmt.Errorf("invalid port %q", spec)
		}
		return "127.0.0.1", p, nil
	}
	h, p, err := net.SplitHostPort(spec)
	if err != nil {
		return "", 0, err
	}
	var portN int
	if _, err := fmt.Sscanf(p, "%d", &portN); err != nil {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	if h == "" {
		h = "127.0.0.1"
	}
	return h, portN, nil
}
