package client_test

import (
	"testing"

	"github.com/gauthier/passerelle/client"
)

func TestMatchTunnels(t *testing.T) {
	tun := client.Tunnel{
		ID:        "aabbccddeeff0011",
		PublicURL: "https://lbe.gnthr.dev",
		Hostname:  "lbe.gnthr.dev",
		Local:     "127.0.0.1:443",
		HTTPS:     true,
		Subdomain: "lbe",
	}
	cases := []string{
		"aabbccddeeff0011",
		"https://lbe.gnthr.dev",
		"https://lbe.gnthr.dev/",
		"lbe.gnthr.dev",
		"lbe",
		"127.0.0.1:443",
		"https://127.0.0.1:443",
		"443",
	}
	for _, ref := range cases {
		got := client.MatchTunnels([]client.Tunnel{tun}, ref)
		if len(got) != 1 {
			t.Fatalf("%q: got %d matches", ref, len(got))
		}
	}
	if got := client.MatchTunnels([]client.Tunnel{tun}, "nope"); len(got) != 0 {
		t.Fatalf("expected no match")
	}
}
