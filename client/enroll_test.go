package client

import "testing"

func TestNormalizeGatewayURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"  ", ""},
		{"passerelle.example.com", "https://passerelle.example.com"},
		{"https://passerelle.example.com/", "https://passerelle.example.com"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
	}
	for _, tt := range tests {
		if got := NormalizeGatewayURL(tt.in); got != tt.want {
			t.Errorf("NormalizeGatewayURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
