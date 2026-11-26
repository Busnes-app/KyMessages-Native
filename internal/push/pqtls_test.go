package push

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"

	"github.com/Busnes-app/ky-primitives/pqtls"
)

// TestOutboundPQTLS verifies that the production outbound Web Push HTTP/TLS
// transport negotiates TLS 1.3 with the hybrid X25519MLKEM768 key exchange
// without classical fallback or overrides (both normally and under FIPS mode).
func TestOutboundPQTLS(t *testing.T) {
	vapid, err := GenerateVAPIDKey()
	if err != nil {
		t.Fatalf("GenerateVAPIDKey: %v", err)
	}
	uaPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate UA key: %v", err)
	}
	authSecret := make([]byte, 16)
	if _, err := rand.Read(authSecret); err != nil {
		t.Fatalf("generate auth secret: %v", err)
	}

	serverStates := make(chan tls.ConnectionState, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			serverStates <- *r.TLS
		}
		w.WriteHeader(http.StatusCreated)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	sender := NewSender(SenderOptions{
		VAPID:        vapid,
		Subject:      "mailto:ops@example.com",
		AllowPrivate: true,
		TLSConfig:    &tls.Config{RootCAs: roots},
	})

	clientStates := make(chan tls.ConnectionState, 1)
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil {
				select {
				case clientStates <- state:
				default:
				}
			}
		},
	})

	sub := Subscription{
		ID:         "ps_pqtls",
		Endpoint:   srv.URL + "/push",
		P256DH:     base64.RawURLEncoding.EncodeToString(uaPriv.PublicKey().Bytes()),
		AuthSecret: base64.RawURLEncoding.EncodeToString(authSecret),
	}
	res, err := sender.Send(ctx, sub, Payload{Kind: "message", Title: "pqtls"}, SendOptions{})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected status %d, want %d", res.StatusCode, http.StatusCreated)
	}

	select {
	case clientState := <-clientStates:
		pqtls.RequireHybrid(t, clientState)
	default:
		t.Fatal("client TLS handshake trace did not fire")
	}

	select {
	case serverState := <-serverStates:
		pqtls.RequireHybrid(t, serverState)
	default:
		t.Fatal("server did not observe TLS connection state")
	}
}
