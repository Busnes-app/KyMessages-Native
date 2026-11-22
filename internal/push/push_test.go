package push

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// decryptAES128GCM is a test helper implementing the UA (browser) side of RFC 8291 decryption.
func decryptAES128GCM(t *testing.T, uaPriv *ecdh.PrivateKey, authSecret, body []byte) []byte {
	t.Helper()
	if len(body) < aes128GCMHeaderSize+17 {
		t.Fatalf("ciphertext too short: %d", len(body))
	}
	salt := body[0:16]
	rs := binary.BigEndian.Uint32(body[16:20])
	if rs != aes128GCMRecordSize {
		t.Fatalf("unexpected record size %d", rs)
	}
	idLen := int(body[20])
	if idLen != 65 {
		t.Fatalf("unexpected key id len %d", idLen)
	}
	asPubBytes := body[21 : 21+idLen]
	ciphertext := body[21+idLen:]

	asPub, err := ecdh.P256().NewPublicKey(asPubBytes)
	if err != nil {
		t.Fatalf("parse asPub: %v", err)
	}
	ecdhSecret, err := uaPriv.ECDH(asPub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	cek, nonce, err := deriveAES128GCMKeys(ecdhSecret, authSecret, salt, uaPriv.PublicKey().Bytes(), asPubBytes)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	plainWithDelim, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("gcm open: %v", err)
	}
	if len(plainWithDelim) == 0 || plainWithDelim[len(plainWithDelim)-1] != 0x02 {
		t.Fatalf("missing 0x02 final-record delimiter: %x", plainWithDelim)
	}
	return plainWithDelim[:len(plainWithDelim)-1]
}

// TestEncryptPayloadRFC8291Vector verifies byte-for-byte conformance with RFC 8291 Section 5.
func TestEncryptPayloadRFC8291Vector(t *testing.T) {
	// RFC 8291 Section 5 official test vector.
	uaPrivRaw, _ := base64.RawURLEncoding.DecodeString("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")
	asPrivRaw, _ := base64.RawURLEncoding.DecodeString("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
	authSecret, _ := base64.RawURLEncoding.DecodeString("BTBZMqHH6r4Tts7J_aSIgg")
	salt, _ := base64.RawURLEncoding.DecodeString("DGv6ra1nlYgDCS1FRnbzlw")
	wantBody, _ := base64.RawURLEncoding.DecodeString(
		"DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml" +
			"mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT" +
			"pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
	)

	uaPriv, err := ecdh.P256().NewPrivateKey(uaPrivRaw)
	if err != nil {
		t.Fatalf("uaPriv: %v", err)
	}
	asPriv, err := ecdh.P256().NewPrivateKey(asPrivRaw)
	if err != nil {
		t.Fatalf("asPriv: %v", err)
	}

	got, err := encryptPayloadWithParams([]byte("When I grow up, I want to be a watermelon"), uaPriv.PublicKey(), authSecret, asPriv, salt)
	if err != nil {
		t.Fatalf("encryptPayloadWithParams: %v", err)
	}
	if !bytes.Equal(got, wantBody) {
		t.Fatalf("RFC 8291 Section 5 mismatch:\ngot:  %s\nwant: %s",
			base64.RawURLEncoding.EncodeToString(got),
			base64.RawURLEncoding.EncodeToString(wantBody))
	}
}

func TestEncryptPayloadRoundTrip(t *testing.T) {
	uaPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ua key: %v", err)
	}
	authSecret := make([]byte, 16)
	_, _ = rand.Read(authSecret)

	p256dh := base64.RawURLEncoding.EncodeToString(uaPriv.PublicKey().Bytes())
	auth := base64.RawURLEncoding.EncodeToString(authSecret)
	plain := []byte(`{"kind":"message","room_id":"rm_1","title":"General","body":"Hello world"}`)

	body, err := EncryptPayload(plain, p256dh, auth)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	got := decryptAES128GCM(t, uaPriv, authSecret, body)
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plain)
	}
}

func TestVAPIDKeyPersistenceAndSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vapid.key")

	k1, err := LoadOrCreateVAPIDKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateVAPIDKey create: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("expected 0600 perms, got %o", mode)
	}

	k2, err := LoadOrCreateVAPIDKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateVAPIDKey reload: %v", err)
	}
	if k1.PublicKeyBase64() != k2.PublicKeyBase64() || k1.PrivateKeyBase64() != k2.PrivateKeyBase64() {
		t.Fatalf("reloaded key did not match persisted key")
	}

	endpoint, _ := url.Parse("https://push.example.com/wpush/v2/abc")
	now := time.Unix(1700000000, 0).UTC()
	hdr, err := k1.AuthorizationHeader(endpoint, "mailto:admin@example.com", 2*time.Hour, now)
	if err != nil {
		t.Fatalf("AuthorizationHeader: %v", err)
	}
	if !strings.HasPrefix(hdr, "vapid t=") || !strings.Contains(hdr, ", k="+k1.PublicKeyBase64()) {
		t.Fatalf("unexpected header format: %s", hdr)
	}
	jwtPart := strings.TrimPrefix(strings.Split(hdr, ", k=")[0], "vapid t=")
	parts := strings.Split(jwtPart, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.Aud != "https://push.example.com" || claims.Sub != "mailto:admin@example.com" || claims.Exp != now.Add(2*time.Hour).Unix() {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("expected 64-byte ES256 sig, got %d (%v)", len(sig), err)
	}
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&k1.private.PublicKey, digest[:], r, s) {
		t.Fatalf("ES256 signature failed verification")
	}
}

func TestValidateEndpointSSRFDefenses(t *testing.T) {
	blocked := []string{
		"",
		"http://fcm.googleapis.com/fcm/send/abc",
		"https://user:pass@fcm.googleapis.com/fcm/send/abc",
		"https://localhost/push",
		"https://sub.localhost/push",
		"https://host.local/push",
		"https://metadata.google.internal/computeMetadata/v1/",
		"https://127.0.0.1/push",
		"https://[::1]/push",
		"https://10.0.0.5/push",
		"https://172.16.0.1/push",
		"https://192.168.1.10/push",
		"https://169.254.169.254/latest/meta-data/",
		"https://100.64.0.1/push",
		"https://[fc00::1]/push",
		"https://[fe80::1]/push",
		"https://[::ffff:127.0.0.1]/push",
		"https://[::ffff:169.254.169.254]/push",
		"https://fcm.googleapis.com:8443/fcm/send/abc",
		"https://fcm.googleapis.com/has space",
	}
	for _, raw := range blocked {
		if _, err := ValidateEndpoint(raw, false); err == nil {
			t.Errorf("expected endpoint %q to be blocked", raw)
		} else if !errors.Is(err, ErrEndpointBlocked) {
			t.Errorf("expected ErrEndpointBlocked for %q, got %v", raw, err)
		}
	}

	allowed := []string{
		"https://fcm.googleapis.com/fcm/send/abc123",
		"https://updates.push.services.mozilla.com/wpush/v2/token",
		"https://web.push.apple.com/QAbc123",
		"https://wns2-bl2p.notify.windows.com:443/w/?token=abc",
	}
	for _, raw := range allowed {
		if _, err := ValidateEndpoint(raw, false); err != nil {
			t.Errorf("expected endpoint %q to be allowed, got %v", raw, err)
		}
	}
}

func TestSenderEndToEndAndRedirectRefused(t *testing.T) {
	vapid, err := GenerateVAPIDKey()
	if err != nil {
		t.Fatalf("GenerateVAPIDKey: %v", err)
	}
	uaPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	authSecret := make([]byte, 16)
	_, _ = rand.Read(authSecret)
	sub := Subscription{
		ID:         "ps_1",
		P256DH:     base64.RawURLEncoding.EncodeToString(uaPriv.PublicKey().Bytes()),
		AuthSecret: base64.RawURLEncoding.EncodeToString(authSecret),
	}

	var gotAuth, gotEnc, gotTTL, gotUrgency string
	var gotBody []byte
	var redirectTargetHit atomic.Bool

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			gotAuth = r.Header.Get("Authorization")
			gotEnc = r.Header.Get("Content-Encoding")
			gotTTL = r.Header.Get("TTL")
			gotUrgency = r.Header.Get("Urgency")
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
		case "/gone":
			w.WriteHeader(http.StatusGone)
		case "/redirect":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			redirectTargetHit.Store(true)
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()

	sender := NewSender(SenderOptions{
		VAPID:        vapid,
		Subject:      "mailto:ops@example.com",
		AllowPrivate: true,
		TLSConfig:    srv.Client().Transport.(*http.Transport).TLSClientConfig,
	})

	// 1. Successful encrypted delivery.
	sub.Endpoint = srv.URL + "/ok"
	wantPayload := Payload{
		Kind:       "message",
		RoomID:     "rm_1",
		RoomName:   "General",
		SenderName: "Alice",
		Title:      "Alice in #General",
		Body:       "Hello from Web Push",
		URL:        "/#room=rm_1",
	}
	res, err := sender.Send(context.Background(), sub, wantPayload, SendOptions{TTL: 3600, Urgency: "high"})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if res.StatusCode != http.StatusCreated || res.Gone {
		t.Fatalf("unexpected result: %+v", res)
	}
	if gotEnc != "aes128gcm" || gotTTL != "3600" || gotUrgency != "high" || !strings.HasPrefix(gotAuth, "vapid t=") {
		t.Fatalf("unexpected headers: enc=%q ttl=%q urgency=%q auth=%q", gotEnc, gotTTL, gotUrgency, gotAuth)
	}
	plain := decryptAES128GCM(t, uaPriv, authSecret, gotBody)
	var gotPayload Payload
	if err := json.Unmarshal(plain, &gotPayload); err != nil {
		t.Fatalf("unmarshal decrypted payload: %v", err)
	}
	if gotPayload != wantPayload {
		t.Fatalf("payload mismatch: got %+v want %+v", gotPayload, wantPayload)
	}

	// 2. Redirects MUST NOT be followed.
	sub.Endpoint = srv.URL + "/redirect"
	res, err = sender.Send(context.Background(), sub, wantPayload, SendOptions{})
	if err == nil || res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 refusal, got status=%d err=%v", res.StatusCode, err)
	}
	if redirectTargetHit.Load() {
		t.Fatalf("sender followed redirect to /target!")
	}

	// 3. Dispatcher triggers onGone for HTTP 410.
	goneCh := make(chan string, 1)
	disp := NewDispatcher(sender, func(_ context.Context, subID string) {
		goneCh <- subID
	}, nil)
	defer disp.Close()

	sub.Endpoint = srv.URL + "/gone"
	if !disp.Enqueue(Job{Subscription: sub, Payload: wantPayload}) {
		t.Fatalf("Enqueue returned false")
	}
	select {
	case id := <-goneCh:
		if id != "ps_1" {
			t.Fatalf("unexpected gone sub id %q", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for onGone callback")
	}
}
