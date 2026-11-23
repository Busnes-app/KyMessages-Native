package rtc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestJoinTokenFormatAndClaims(t *testing.T) {
	fixed := time.Unix(1700000000, 0)
	c := NewClient("https://rtc.example.com", "APIKey123", "SuperSecretKeyValueThatIsLongEnough123")
	c.now = func() time.Time { return fixed }

	if c.WSURL() != "wss://rtc.example.com" {
		t.Fatalf("expected wss URL, got %q", c.WSURL())
	}

	tok := c.JoinToken("room-abc", "peer-1", "Alice", `{"role":"member"}`, 10*time.Minute)
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// Verify HS256 signature.
	mac := hmac.New(sha256.New, []byte("SuperSecretKeyValueThatIsLongEnough123"))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if parts[2] != wantSig {
		t.Fatalf("signature mismatch: got %q want %q", parts[2], wantSig)
	}

	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims["iss"] != "APIKey123" || claims["sub"] != "peer-1" || claims["name"] != "Alice" {
		t.Fatalf("unexpected identity claims: %#v", claims)
	}
	if int64(claims["exp"].(float64)) != fixed.Unix()+600 {
		t.Fatalf("expected exp %d, got %v", fixed.Unix()+600, claims["exp"])
	}
	video := claims["video"].(map[string]any)
	if video["room"] != "room-abc" || video["roomJoin"] != true {
		t.Fatalf("unexpected video grant: %#v", video)
	}
}

func TestTwirpCreateAndRemove(t *testing.T) {
	var seenPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPaths = append(seenPaths, r.URL.Path)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/RemoveParticipant") || strings.HasSuffix(r.URL.Path, "/DeleteRoom") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"not_found"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "k", "s")
	if err := c.CreateRoom(context.Background(), "call-1", ""); err != nil {
		t.Fatalf("CreateRoom failed: %v", err)
	}
	// 404 on RemoveParticipant should be treated as already-removed (idempotent).
	if err := c.RemoveParticipant(context.Background(), "call-1", "peer-1"); err != nil {
		t.Fatalf("RemoveParticipant 404 should succeed idempotently: %v", err)
	}
	if err := c.DeleteRoom(context.Background(), "call-1"); err != nil {
		t.Fatalf("DeleteRoom404 must be idempotent: %v", err)
	}
	if len(seenPaths) != 3 {
		t.Fatalf("expected 3 requests, got %v", seenPaths)
	}
}
