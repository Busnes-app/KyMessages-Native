package sso

import "testing"

// A loopback issuer may be plain http, by name or by address, as ky-primitives/suitedir allows.
func TestSuiteIssuerLoopback(t *testing.T) {
	for host, want := range map[string]bool{"localhost": true, "LOCALHOST": true, "127.0.0.1": true, "::1": true, "id.example": false, "10.0.0.1": false} {
		if got := isLoopback(host); got != want {
			t.Errorf("isLoopback(%q) = %v", host, got)
		}
	}
}
