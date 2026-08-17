package origin_test

import (
	"strings"
	"testing"

	"github.com/gauthier/passerelle/internal/origin"
)

func TestParseHostPort(t *testing.T) {
	h, p, err := origin.ParseHostPort("8080")
	if err != nil || h != "127.0.0.1" || p != 8080 {
		t.Fatalf("%s %d %v", h, p, err)
	}
	h, p, err = origin.ParseHostPort("127.0.0.1:3000")
	if err != nil || h != "127.0.0.1" || p != 3000 {
		t.Fatalf("%s %d %v", h, p, err)
	}
}

func TestRejectNonLoopback(t *testing.T) {
	_, err := origin.ResolveLoopback("8.8.8.8", 80)
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("expected reject, got %v", err)
	}
}

func TestLoopbackOK(t *testing.T) {
	addr, err := origin.ResolveLoopback("127.0.0.1", 8080)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:8080" {
		t.Fatal(addr)
	}
}
