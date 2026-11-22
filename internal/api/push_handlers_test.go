package api_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/push"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func newTestPushKeys(t *testing.T) (p256dh, auth string) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate p256dh: %v", err)
	}
	authBytes := make([]byte, 16)
	_, _ = rand.Read(authBytes)
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(authBytes)
}

func newPushTestServer(t *testing.T, allowPrivate bool) (*api.Server, store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := &config.Config{
		Server: config.ServerConfig{
			AppName: "KyMessages",
			AppURL:  "https://chat.example.com",
		},
		Database: config.DatabaseConfig{
			DataDir: t.TempDir(),
		},
		Security: config.SecurityConfig{
			SessionTTL: 24 * time.Hour,
		},
		Push: config.PushConfig{
			AllowPrivate: allowPrivate,
		},
	}
	srv := api.NewServer(cfg, st)
	t.Cleanup(func() { srv.WaitDetached() })
	return srv, st
}

func TestPushBootstrapAndSSRFRejection(t *testing.T) {
	srv, st := newPushTestServer(t, false)
	_, aliceTok := createChatTestUser(t, st, "usr_p_alice", "alice", "user")

	// Bootstrap exposes VAPID public key.
	rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/bootstrap", aliceTok, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap status %d: %s", rec.Code, rec.Body.String())
	}
	var boot struct {
		Push struct {
			Available      bool   `json:"available"`
			VAPIDPublicKey string `json:"vapid_public_key"`
		} `json:"push"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &boot); err != nil {
		t.Fatalf("decode bootstrap: %v", err)
	}
	if !boot.Push.Available || len(boot.Push.VAPIDPublicKey) < 80 {
		t.Fatalf("expected valid VAPID key in bootstrap, got %+v", boot.Push)
	}

	p256dh, auth := newTestPushKeys(t)

	// SSRF / bad endpoints MUST be rejected with 400.
	badEndpoints := []string{
		"http://fcm.googleapis.com/fcm/send/abc",
		"https://127.0.0.1/push",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.1/push",
		"https://localhost/push",
		"https://fcm.googleapis.com:8443/fcm/send/abc",
	}
	for _, ep := range badEndpoints {
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/push/subscriptions", aliceTok, map[string]any{
			"endpoint": ep,
			"keys":     map[string]string{"p256dh": p256dh, "auth": auth},
		}, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("endpoint %q: expected 400, got %d (%s)", ep, rec.Code, rec.Body.String())
		}
	}

	// Bad keys MUST be rejected with 400.
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/push/subscriptions", aliceTok, map[string]any{
		"endpoint": "https://fcm.googleapis.com/fcm/send/valid-ep",
		"keys":     map[string]string{"p256dh": "not-a-key", "auth": auth},
	}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad p256dh: expected 400, got %d", rec.Code)
	}

	// Valid public push endpoint succeeds and hides secrets in JSON response.
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/push/subscriptions", aliceTok, map[string]any{
		"endpoint": "https://fcm.googleapis.com/fcm/send/valid-ep",
		"keys":     map[string]string{"p256dh": p256dh, "auth": auth},
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid register: expected 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), p256dh) || strings.Contains(rec.Body.String(), auth) {
		t.Fatalf("push response leaked p256dh or auth secret: %s", rec.Body.String())
	}
}

func TestPushMessageNotifyModesCallsAndGonePruning(t *testing.T) {
	srv, st := newPushTestServer(t, true)
	alice, aliceTok := createChatTestUser(t, st, "usr_pd_alice", "alice", "user")
	bob, bobTok := createChatTestUser(t, st, "usr_pd_bob", "bob", "user")

	// Start fake TLS Web Push endpoint.
	type receivedPush struct {
		Path    string
		Urgency string
		TTL     string
		Enc     string
		Auth    string
	}
	gotCh := make(chan receivedPush, 16)
	var returnGone atomic.Bool

	pushSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if returnGone.Load() {
			w.WriteHeader(http.StatusGone)
			return
		}
		gotCh <- receivedPush{
			Path:    r.URL.Path,
			Urgency: r.Header.Get("Urgency"),
			TTL:     r.Header.Get("TTL"),
			Enc:     r.Header.Get("Content-Encoding"),
			Auth:    r.Header.Get("Authorization"),
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer pushSrv.Close()

	vapidKey, err := push.GenerateVAPIDKey()
	if err != nil {
		t.Fatalf("GenerateVAPIDKey: %v", err)
	}
	sender := push.NewSender(push.SenderOptions{
		VAPID:        vapidKey,
		Subject:      "mailto:ops@example.com",
		AllowPrivate: true,
		TLSConfig:    pushSrv.Client().Transport.(*http.Transport).TLSClientConfig,
	})
	disp := push.NewDispatcher(sender, func(ctx context.Context, subID string) {
		_ = st.Chat().DeletePushSubscriptionInternal(ctx, subID)
	}, nil)
	srv.SetPushDispatcher(disp)

	// Create channel with Alice + Bob.
	rm := &store.Room{
		TenantID:  store.DefaultTenantID,
		Kind:      store.RoomKindChannel,
		Name:      "engineering",
		CreatedBy: alice.ID,
	}
	if err := st.Chat().CreateRoom(context.Background(), rm, []string{alice.ID, bob.ID}); err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}

	// Register push subscription for Bob.
	p256dh, auth := newTestPushKeys(t)
	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/push/subscriptions", bobTok, map[string]any{
		"endpoint": pushSrv.URL + "/bob",
		"keys":     map[string]string{"p256dh": p256dh, "auth": auth},
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register bob sub: %d %s", rec.Code, rec.Body.String())
	}

	// 1. Default notify_mode ("all"): Alice sends message -> Bob receives Web Push.
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+rm.ID+"/messages", aliceTok, map[string]any{
		"body": "Hello engineering!",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("send msg 1: %d %s", rec.Code, rec.Body.String())
	}
	select {
	case p := <-gotCh:
		if p.Path != "/bob" || p.Enc != "aes128gcm" || !strings.HasPrefix(p.Auth, "vapid t=") {
			t.Fatalf("unexpected push headers: %+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for message push")
	}

	// 2. Switch Bob to "mentions": plain message without @bob -> NO push.
	rec = doBearerJSON(t, srv, http.MethodPut, "/api/v1/rooms/"+rm.ID+"/notifications", bobTok, map[string]any{
		"notify_mode": "mentions",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("update notify_mode mentions: %d %s", rec.Code, rec.Body.String())
	}
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+rm.ID+"/messages", aliceTok, map[string]any{
		"body": "Just chatting without mentioning anyone",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("send msg 2: %d", rec.Code)
	}
	select {
	case p := <-gotCh:
		t.Fatalf("unexpected push when notify_mode=mentions and not mentioned: %+v", p)
	case <-time.After(200 * time.Millisecond):
	}

	// Mentioning @bob triggers push!
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+rm.ID+"/messages", aliceTok, map[string]any{
		"body": "Hey @Bob, can you check this?",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("send msg 3: %d", rec.Code)
	}
	select {
	case p := <-gotCh:
		if p.Path != "/bob" {
			t.Fatalf("unexpected mention push: %+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for @bob mention push")
	}

	// 3. Incoming call start -> high-urgency TTL=60 push!
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+rm.ID+"/calls/join", aliceTok, map[string]any{
		"audio": true,
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("call join: %d %s", rec.Code, rec.Body.String())
	}
	select {
	case p := <-gotCh:
		if p.Urgency != "high" || p.TTL != "60" {
			t.Fatalf("expected high urgency TTL=60 for call push, got %+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for call push")
	}

	// 4. Switch Bob to "mute" -> even @bob does NOT trigger push!
	rec = doBearerJSON(t, srv, http.MethodPut, "/api/v1/rooms/"+rm.ID+"/notifications", bobTok, map[string]any{
		"notify_mode": "mute",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("update notify_mode mute: %d", rec.Code)
	}
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+rm.ID+"/messages", aliceTok, map[string]any{
		"body": "Hey @bob are you there?",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("send msg 4: %d", rec.Code)
	}
	select {
	case p := <-gotCh:
		t.Fatalf("unexpected push when room is muted: %+v", p)
	case <-time.After(200 * time.Millisecond):
	}

	// 5. HTTP 410 Gone automatically prunes Bob's stale subscription from DB.
	_ = doBearerJSON(t, srv, http.MethodPut, "/api/v1/rooms/"+rm.ID+"/notifications", bobTok, map[string]any{
		"notify_mode": "all",
	}, nil)
	returnGone.Store(true)
	_ = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+rm.ID+"/messages", aliceTok, map[string]any{
		"body": "Trigger 410 cleanup",
	}, nil)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		subs, _ := st.Chat().ListPushSubscriptions(context.Background(), store.DefaultTenantID, bob.ID)
		if len(subs) == 0 {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("expected 410 Gone to prune Bob's push subscription")
}
