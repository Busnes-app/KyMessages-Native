package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func setupCallTestServer(t *testing.T, withLiveKit bool) (*Server, store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := &config.Config{
		Server: config.ServerConfig{
			AppName: "KyMessages Test",
			AppURL:  "https://chat.example.com",
		},
		Security: config.SecurityConfig{
			SessionSecret: "0123456789abcdef0123456789abcdef",
		},
		Captcha: config.CaptchaConfig{
			Provider: "none",
		},
		RTC: config.RTCConfig{
			STUNURLs: []string{"stun:stun.example.com:3478"},
		},
		SSO:        config.SSOConfig{Enabled: true, KyIdentityIssuer: testCalIssuer},
		KyCalendar: config.PairConfig{URL: "https://cal.example", Secret: []byte(testCalSecret)},
	}
	if withLiveKit {
		lk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}))
		t.Cleanup(lk.Close)
		cfg.RTC.LiveKitURL = lk.URL
		cfg.RTC.LiveKitAPIKey = "devkey"
		cfg.RTC.LiveKitAPISecret = "devsecret1234567890"
	}

	srv := NewServer(cfg, st)
	return srv, st
}

const (
	testCalIssuer = "https://id.example.com"
	testCalSecret = "kycalendar-pair-secret-key-32-bytes-minimum!!"
)

// signCal signs body as KyCalendar does: the pair secret, the route's event type.
func signCal(t *testing.T, req *http.Request, event, eventID string, body []byte) {
	t.Helper()
	h, err := syncauth.Sign([]byte(testCalSecret), time.Now(), event, eventID, body)
	if err != nil {
		t.Fatalf("syncauth.Sign: %v", err)
	}
	h.Apply(req)
}

func makeUserAndToken(t *testing.T, _ *Server, st store.Store, id, username, role string) string {
	t.Helper()
	u := &store.User{
		ID:          id,
		Username:    username,
		DisplayName: username,
		Role:        role,
		Status:      "active",
	}
	if err := st.Users().CreateUser(context.Background(), u); err != nil {
		t.Fatalf("CreateUser(%s): %v", username, err)
	}
	rawTok := "tok_" + crypto.RandomHex(24)
	sess := &store.Session{
		TokenHash: crypto.SHA256Hex([]byte(rawTok)),
		UserID:    u.ID,
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := st.Sessions().CreateSession(context.Background(), sess, ""); err != nil {
		t.Fatalf("CreateSession(%s): %v", username, err)
	}
	return rawTok
}

func doAuthedJSON(t *testing.T, srv *Server, method, path, bearer string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	if payload != nil {
		if err := json.NewEncoder(&body).Encode(payload); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &body)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestHybridCallEndpointsAndAdminMediaPolicy(t *testing.T) {
	srv, st := setupCallTestServer(t, true)
	t1 := makeUserAndToken(t, srv, st, "u1", "alice", "admin")
	t2 := makeUserAndToken(t, srv, st, "u2", "bob", "user")
	t3 := makeUserAndToken(t, srv, st, "u3", "carol", "user")

	// Create room with all 3 users.
	rec := doAuthedJSON(t, srv, http.MethodPost, "/api/v1/rooms", t1, map[string]any{
		"kind":       "channel",
		"name":       "standup",
		"member_ids": []string{"u2", "u3"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create room: %d %s", rec.Code, rec.Body.String())
	}
	// Verify CSP includes media-src 'self' blob: and the LiveKit host.
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "media-src 'self' blob:") || !strings.Contains(csp, "ws://") {
		t.Fatalf("expected RTC-aware CSP header, got: %s", csp)
	}
	var roomResp struct {
		Room struct {
			ID string `json:"id"`
		} `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &roomResp)
	roomID := roomResp.Room.ID

	// 1st and 2nd video peers stay in p2p_mesh.
	j1 := doAuthedJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/calls/join", t1, map[string]any{"audio": true, "video": true})
	if j1.Code != http.StatusOK {
		t.Fatalf("j1: %d %s", j1.Code, j1.Body.String())
	}
	j2 := doAuthedJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/calls/join", t2, map[string]any{"audio": true, "video": true})
	var jr2 map[string]any
	_ = json.Unmarshal(j2.Body.Bytes(), &jr2)
	if jr2["mode"] != "p2p_mesh" {
		t.Fatalf("expected p2p_mesh for 2 video peers, got %v", jr2)
	}

	// 3rd video peer auto-escalates to sfu_livekit and returns a LiveKit JWT!
	j3 := doAuthedJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/calls/join", t3, map[string]any{"audio": true, "video": true})
	var jr3 map[string]any
	_ = json.Unmarshal(j3.Body.Bytes(), &jr3)
	if jr3["mode"] != "sfu_livekit" || jr3["livekit_token"] == "" {
		t.Fatalf("expected sfu_livekit + token on 3rd video peer, got %v", jr3)
	}

	// Admin updates tenant media policy to sfu_only.
	mp := doAuthedJSON(t, srv, http.MethodPut, "/api/admin/media-policy", t1, map[string]any{
		"p2p_policy":      "sfu_only",
		"p2p_max_video":   2,
		"p2p_max_audio":   4,
		"guest_force_sfu": true,
	})
	if mp.Code != http.StatusOK {
		t.Fatalf("update media policy: %d %s", mp.Code, mp.Body.String())
	}
	// Non-admin must be rejected.
	mpUser := doAuthedJSON(t, srv, http.MethodGet, "/api/admin/media-policy", t2, nil)
	if mpUser.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin media-policy, got %d", mpUser.Code)
	}
}

func TestMeetingSyncAndConfinedGuestWaitingRoom(t *testing.T) {
	srv, st := setupCallTestServer(t, true)
	hostTok := makeUserAndToken(t, srv, st, "u_host", "host", "user")
	host, _ := st.Users().GetUserByID(context.Background(), "u_host")
	host.SSOProvider, host.SSOSubject = "kyidentity", "sub-host"
	if err := st.Users().UpdateUser(context.Background(), host); err != nil {
		t.Fatal(err)
	}

	// 1. KyCalendar upserts a meeting via syncauth-signed PUT /api/meetings/{id}.
	now := time.Now().UTC()
	payload, _ := json.Marshal(map[string]any{
		"id":          "cal-evt-42",
		"sub":         "sub-host",
		"issuer":      testCalIssuer,
		"title":       "Quarterly Review",
		"member_subs": []string{"sub-host"},
		"guests":      []map[string]string{{"key": "ext-client"}},
		"windows": []map[string]string{{
			"start": now.Add(-5 * time.Minute).Format(time.RFC3339),
			"end":   now.Add(45 * time.Minute).Format(time.RFC3339),
		}},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/meetings/cal-evt-42", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	signCal(t, req, "kycalendar.meeting.put", "evt-1", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/meetings: %d %s", rec.Code, rec.Body.String())
	}
	var syncResp struct {
		RoomID    string            `json:"room_id"`
		GuestURLs map[string]string `json:"guest_urls"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &syncResp)
	guestURL := syncResp.GuestURLs["ext-client"]
	if syncResp.RoomID == "" || !strings.Contains(guestURL, "/meet/") {
		t.Fatalf("unexpected meeting sync response: %+v", syncResp)
	}
	guestToken := guestURL[strings.LastIndex(guestURL, "/meet/")+len("/meet/"):]

	// 2. External guest inspects /api/meet/{token}.
	infoRec := doAuthedJSON(t, srv, http.MethodGet, "/api/meet/"+guestToken, "", nil)
	if infoRec.Code != http.StatusOK {
		t.Fatalf("GET /api/meet: %d %s", infoRec.Code, infoRec.Body.String())
	}

	// 3. External guest knocks.
	knockRec := doAuthedJSON(t, srv, http.MethodPost, "/api/meet/"+guestToken+"/knock", "", map[string]any{
		"display_name": "Jordan Client",
	})
	if knockRec.Code != http.StatusOK {
		t.Fatalf("POST knock: %d %s", knockRec.Code, knockRec.Body.String())
	}
	var knockResp struct {
		GuestID string `json:"guest_id"`
		Status  string `json:"status"`
	}
	_ = json.Unmarshal(knockRec.Body.Bytes(), &knockResp)
	if knockResp.Status != "waiting" || knockResp.GuestID == "" {
		t.Fatalf("unexpected knock response: %+v", knockResp)
	}
	var guestCookie *http.Cookie
	for _, c := range knockRec.Result().Cookies() {
		if c.Name == guestSessionCookieName {
			guestCookie = c
		}
	}
	if guestCookie == nil {
		t.Fatalf("expected ky_guest_session cookie")
	}

	// 4. Before admission, guest CANNOT read messages or join the call (403).
	preMsgReq := httptest.NewRequest(http.MethodGet, "/api/meet/"+guestToken+"/messages", nil)
	preMsgReq.AddCookie(guestCookie)
	preMsgRec := httptest.NewRecorder()
	srv.ServeHTTP(preMsgRec, preMsgReq)
	if preMsgRec.Code != http.StatusForbidden {
		t.Fatalf("unadmitted guest must receive 403 on messages, got %d", preMsgRec.Code)
	}

	// 5. Internal host admits guest via lobby endpoint.
	admitRec := doAuthedJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+syncResp.RoomID+"/lobby/"+knockResp.GuestID+"/admit", hostTok, nil)
	if admitRec.Code != http.StatusOK {
		t.Fatalf("admit guest: %d %s", admitRec.Code, admitRec.Body.String())
	}

	// 6. Admitted guest can post a chat message in the meeting room and join the call (forced SFU).
	msgReq := httptest.NewRequest(http.MethodPost, "/api/meet/"+guestToken+"/messages", strings.NewReader(`{"body":"Hello from waiting room!"}`))
	msgReq.Header.Set("Content-Type", "application/json")
	msgReq.AddCookie(guestCookie)
	msgRec := httptest.NewRecorder()
	srv.ServeHTTP(msgRec, msgReq)
	if msgRec.Code != http.StatusCreated {
		t.Fatalf("admitted guest post message: %d %s", msgRec.Code, msgRec.Body.String())
	}

	callReq := httptest.NewRequest(http.MethodPost, "/api/meet/"+guestToken+"/call/join", strings.NewReader(`{"audio":true,"video":true}`))
	callReq.Header.Set("Content-Type", "application/json")
	callReq.AddCookie(guestCookie)
	callRec := httptest.NewRecorder()
	srv.ServeHTTP(callRec, callReq)
	if callRec.Code != http.StatusOK {
		t.Fatalf("admitted guest join call: %d %s", callRec.Code, callRec.Body.String())
	}
	var guestCall map[string]any
	_ = json.Unmarshal(callRec.Body.Bytes(), &guestCall)
	if guestCall["mode"] != "sfu_livekit" || guestCall["livekit_token"] == "" {
		t.Fatalf("guest with guest_force_sfu=true must be forced to sfu_livekit, got %+v", guestCall)
	}

	// 7. KyCalendar deletes/closes the meeting -> guest is evicted and link returns 404.
	delBody := []byte(`{"id":"cal-evt-42","sub":"sub-host","issuer":"` + testCalIssuer + `"}`)
	delReq := httptest.NewRequest(http.MethodDelete, "/api/meetings/cal-evt-42", bytes.NewReader(delBody))
	signCal(t, delReq, "kycalendar.meeting.close", "evt-2", delBody)
	delRec := httptest.NewRecorder()
	srv.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/meetings: %d %s", delRec.Code, delRec.Body.String())
	}
	afterReq := httptest.NewRequest(http.MethodGet, "/api/meet/"+guestToken+"/messages", nil)
	afterReq.AddCookie(guestCookie)
	afterRec := httptest.NewRecorder()
	srv.ServeHTTP(afterRec, afterReq)
	if afterRec.Code != http.StatusNotFound {
		t.Fatalf("closed meeting must reject guest with 404, got %d", afterRec.Code)
	}
}
