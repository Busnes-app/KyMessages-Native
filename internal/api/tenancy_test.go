package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/chat"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
	"github.com/coder/websocket"
	"github.com/google/uuid"
)

const testStaffOrg = "00000000-0000-4000-8000-000000000001"

const testMultiTenantHMAC = "4f1c2a9e8b7d6c5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e"

func newMultiTenantTestServer(t *testing.T) (*api.Server, store.Store, *config.Config) {
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
		SSO: config.SSOConfig{
			KyIdentityHMACSecret: testMultiTenantHMAC,
		},
		RTC: config.RTCConfig{
			MeetingSyncSecret: testMultiTenantHMAC,
		},
		Tenancy: config.TenancyConfig{
			Mode:       config.TenancyMulti,
			StaffOrgID: testStaffOrg,
		},
		SCIM: config.SCIMConfig{
			// Even if left on in config, multi-tenant mode must never expose /scim/v2/*.
			Enabled:  true,
			TokenSet: true,
		},
	}
	if err := api.EnsureTenancyMode(context.Background(), st, cfg.Tenancy); err != nil {
		t.Fatalf("EnsureTenancyMode: %v", err)
	}
	srv := api.NewServer(cfg, st)
	t.Cleanup(func() { srv.WaitDetached() })
	return srv, st, cfg
}

func createOrgUser(t *testing.T, st store.Store, id, username, role, orgID string) (*store.User, string) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.Chat().EnsureTenant(ctx, orgID); err != nil {
		t.Fatalf("EnsureTenant(%s): %v", orgID, err)
	}
	u := &store.User{
		ID:          id,
		Username:    username,
		DisplayName: strings.ToUpper(username[:1]) + username[1:],
		Email:       username + "@" + orgID + ".example.com",
		Role:        role,
		Status:      "active",
		SSOProvider: "kyidentity",
		SSOSubject:  "sub-" + id,
		OrgID:       orgID,
	}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser(%s): %v", username, err)
	}
	rawTok := "tok_" + id + "_" + uuid.NewString()
	sess := &store.Session{
		UserID:    u.ID,
		TokenHash: crypto.SHA256Hex([]byte(rawTok)),
		IPAddress: "127.0.0.1",
		UserAgent: "test",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := st.Sessions().CreateSession(ctx, sess, ""); err != nil {
		t.Fatalf("CreateSession(%s): %v", username, err)
	}
	return u, rawTok
}

func TestEnsureTenancyModeLocksDatabase(t *testing.T) {
	ctx := context.Background()

	// Single-tenant DB refuses multi-tenant startup.
	stSingle, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = stSingle.Close() })

	if err := api.EnsureTenancyMode(ctx, stSingle, config.TenancyConfig{Mode: config.TenancySingle}); err != nil {
		t.Fatalf("first single boot: %v", err)
	}
	if err := api.EnsureTenancyMode(ctx, stSingle, config.TenancyConfig{Mode: config.TenancySingle}); err != nil {
		t.Fatalf("repeat single boot: %v", err)
	}
	if err := api.EnsureTenancyMode(ctx, stSingle, config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}); err == nil {
		t.Fatal("expected single-tenant DB to fail closed when booted in multi-tenant mode")
	}

	// Multi-tenant DB refuses single-tenant startup.
	stMulti, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = stMulti.Close() })

	if err := api.EnsureTenancyMode(ctx, stMulti, config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}); err != nil {
		t.Fatalf("first multi boot: %v", err)
	}
	if err := api.EnsureTenancyMode(ctx, stMulti, config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}); err != nil {
		t.Fatalf("repeat multi boot: %v", err)
	}
	if err := api.EnsureTenancyMode(ctx, stMulti, config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: "00000000-0000-4000-8000-0000000000ff"}); err == nil {
		t.Fatal("expected a multi-tenant DB to refuse a different KY_STAFF_ORG_ID")
	}
	if err := api.EnsureTenancyMode(ctx, stMulti, config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: "org-staff"}); err == nil {
		t.Fatal("expected a non-canonical KY_STAFF_ORG_ID to be refused")
	}
	if err := api.EnsureTenancyMode(ctx, stMulti, config.TenancyConfig{Mode: config.TenancySingle}); err == nil {
		t.Fatal("expected multi-tenant DB to fail closed when booted in single-tenant mode")
	}
	// A database from before canonical org IDs that binds an account to "org-alpha" refuses
	// to start: KyIdentity could never suspend or offboard that account.
	multi := config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}
	if err := stMulti.Users().CreateUser(ctx, &store.User{ID: "u_legacy", Username: "legacy", Role: "user", Status: "active", SSOProvider: "kyidentity", SSOSubject: "sub-legacy", OrgID: "org-alpha"}); err != nil {
		t.Fatal(err)
	}
	if err := api.EnsureTenancyMode(ctx, stMulti, multi); err == nil || !strings.Contains(err.Error(), "org-alpha") {
		t.Fatalf("legacy org ID boot: %v", err)
	}
	if err := stMulti.Users().DeleteUser(ctx, "u_legacy"); err != nil {
		t.Fatal(err)
	}
	if err := api.EnsureTenancyMode(ctx, stMulti, multi); err != nil {
		t.Fatalf("boot after the legacy account is gone: %v", err)
	}
	if _, err := stMulti.Chat().EnsureTenant(ctx, "org-beta"); err != nil {
		t.Fatal(err)
	}
	if err := api.EnsureTenancyMode(ctx, stMulti, multi); err == nil || !strings.Contains(err.Error(), "org-beta") {
		t.Fatalf("legacy tenant boot: %v", err)
	}
}

func TestMultiTenantSCIMDisabled(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	_, adminTok := createOrgUser(t, st, "usr_mt_admin", "mtadmin", "admin", testStaffOrg)

	// /scim/v2/* must return JSON 404, never SPA 200 or SCIM 401.
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer should-never-be-active")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /scim/v2/Users = %d (%s), want 404", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("GET /scim/v2/Users content-type = %q, want application/json", rec.Header().Get("Content-Type"))
	}

	// Admin SCIM view must report disabled with empty users.
	rec = doBearerJSON(t, srv, http.MethodGet, "/api/admin/scim/users", adminTok, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/admin/scim/users = %d: %s", rec.Code, rec.Body.String())
	}
	var scimResp struct {
		Enabled bool  `json:"enabled"`
		Users   []any `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &scimResp); err != nil {
		t.Fatalf("decode scim users: %v", err)
	}
	if scimResp.Enabled || len(scimResp.Users) != 0 {
		t.Fatalf("expected disabled empty SCIM response in multi-tenant mode, got %+v", scimResp)
	}
}

func TestMultiTenantCrossOrgIsolation(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)

	alice, aliceTok := createOrgUser(t, st, "usr_a_alice", "alice", "admin", "00000000-0000-4000-8000-00000000000a")
	bob, _ := createOrgUser(t, st, "usr_a_bob", "bob", "user", "00000000-0000-4000-8000-00000000000a")
	carol, carolTok := createOrgUser(t, st, "usr_b_carol", "carol", "admin", "00000000-0000-4000-8000-00000000000b")
	_, _ = createOrgUser(t, st, "usr_b_dave", "dave", "user", "00000000-0000-4000-8000-00000000000b")

	// 1. User directory must only list caller's org.
	rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/users", aliceTok, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice list users: %d %s", rec.Code, rec.Body.String())
	}
	var dirResp struct {
		Users []struct {
			ID string `json:"id"`
		} `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &dirResp); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	if len(dirResp.Users) != 2 {
		t.Fatalf("alice directory count = %d, want 2 (only org-alpha): %+v", len(dirResp.Users), dirResp.Users)
	}
	for _, u := range dirResp.Users {
		if u.ID == carol.ID {
			t.Fatalf("cross-org user %s leaked into org-alpha directory", carol.ID)
		}
	}

	// 2. Cross-org DM & channel member invite must fail.
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind":       "dm",
		"dm_user_id": carol.ID,
	}, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-org DM = %d, want 404: %s", rec.Code, rec.Body.String())
	}

	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind":       "channel",
		"name":       "alpha-secret",
		"member_ids": []string{carol.ID},
	}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cross-org channel create = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	// 3. Create valid org-alpha room, send message, verify org-beta cannot read/post/search/call/add.
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind":       "channel",
		"name":       "alpha-ops",
		"member_ids": []string{bob.ID},
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create alpha room = %d: %s", rec.Code, rec.Body.String())
	}
	var roomResp struct {
		Room struct {
			ID       string `json:"id"`
			TenantID string `json:"tenant_id"`
		} `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &roomResp)
	if roomResp.Room.TenantID != "00000000-0000-4000-8000-00000000000a" {
		t.Fatalf("room tenant_id = %q, want org-alpha", roomResp.Room.TenantID)
	}
	roomID := roomResp.Room.ID

	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/messages", aliceTok, map[string]any{
		"body":     testEnvelope("alpha-launch-code-9981"),
		"encoding": "e2ee_room_v1",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("send alpha message = %d: %s", rec.Code, rec.Body.String())
	}

	// Carol (admin in org-beta) must get 404 on org-alpha room operations.
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/rooms/" + roomID, nil},
		{http.MethodGet, "/api/v1/rooms/" + roomID + "/messages", nil},
		{http.MethodPost, "/api/v1/rooms/" + roomID + "/messages", sealed("hijack", nil)},
		{http.MethodPost, "/api/v1/rooms/" + roomID + "/members", map[string]any{"user_id": carol.ID}},
		{http.MethodPost, "/api/v1/rooms/" + roomID + "/calls/join", nil},
	} {
		rec = doBearerJSON(t, srv, tc.method, tc.path, carolTok, tc.body, nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("cross-org %s %s = %d, want 404: %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	// Server search is gone (search runs on the device), so there is nothing to search across orgs.
	if rec = doBearerJSON(t, srv, http.MethodGet, "/api/v1/search?q=alpha-launch-code-9981", carolTok, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("server search = %d, want 404 now that it is removed: %s", rec.Code, rec.Body.String())
	}

	// 4. Cross-org instant meeting invite must fail.
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/meetings", aliceTok, map[string]any{
		"title":      "Cross-Org Attempt",
		"member_ids": []string{carol.ID},
	}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cross-org instant meeting = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	// 5. Customer orgs have no administrators: a stored admin role outside the staff org is refused.
	for _, tok := range []string{aliceTok, carolTok} {
		if rec := doBearerJSON(t, srv, http.MethodGet, "/api/admin/agents", tok, nil, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("customer-org admin list agents = %d, want 403: %s", rec.Code, rec.Body.String())
		}
	}

	// Staff administer from their own org and cannot hand a bot to a customer's member.
	_, staffTok := createOrgUser(t, st, "usr_s_sam", "sam", "admin", testStaffOrg)
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/admin/agents", staffTok, map[string]any{
		"name":  "agent-hijack",
		"owner": bob.ID,
	}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("staff create agent for org-alpha owner = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	rec = doBearerJSON(t, srv, http.MethodGet, "/api/admin/agents", staffTok, nil, nil)
	var listAgents struct {
		Owners []struct {
			ID string `json:"id"`
		} `json:"owners"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listAgents)
	for _, o := range listAgents.Owners {
		if o.ID == alice.ID || o.ID == bob.ID {
			t.Fatalf("staff agent owners leaked customer member %s", o.ID)
		}
	}
}

// A customer org's administrator from KyIdentity is a member here; only the staff org operates
// the install.
func TestMultiTenantDirectoryAdminsOnlyFromStaffOrg(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	ctx := context.Background()
	sync := func(id, org string) *store.User {
		body := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"` + id + `","userName":"` + id + `","org_id":"` + org + `","roles":[{"value":"admin"}],"active":true,"meta":{"resourceType":"User","version":"W/\"1\""}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/sso/kyidentity/sync", bytes.NewReader(body))
		h, err := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), "user.created", uuid.NewString(), body)
		if err != nil {
			t.Fatal(err)
		}
		h.Apply(req)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("sync %s = %d: %s", id, rec.Code, rec.Body.String())
		}
		u, err := st.Users().GetUserBySSO(ctx, "kyidentity", id)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	if u := sync("kid-tenant-admin", "00000000-0000-4000-8000-00000000000a"); u.Role != "user" {
		t.Fatalf("customer-org admin stored as %q, want user", u.Role)
	}
	if u := sync("kid-staff-admin", testStaffOrg); u.Role != "admin" {
		t.Fatalf("staff-org admin stored as %q, want admin", u.Role)
	}

	// Even with an admin row, a customer-org account cannot change backups or read the audit log.
	_, tenantTok := createOrgUser(t, st, "usr_a_admin", "alphaadmin", "admin", "00000000-0000-4000-8000-00000000000a")
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/backup/schedule", tenantTok, map[string]any{"interval": "24h"}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("customer-org admin backup schedule = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/admin/audit", tenantTok, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("customer-org admin audit = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	_, staffTok := createOrgUser(t, st, "usr_s_admin", "staffadmin", "admin", testStaffOrg)
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/admin/audit", staffTok, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("staff admin audit = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// A suspended staff org loses the console even before its sessions are swept.
	if err := st.Chat().SetTenantStatus(ctx, testStaffOrg, store.TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/admin/audit", staffTok, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("suspended staff admin audit = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

func TestMultiTenantKyCalendarMeetingSync(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)

	alice, _ := createOrgUser(t, st, "usr_cal_alice", "calalice", "user", "00000000-0000-4000-8000-00000000000a")
	carol, _ := createOrgUser(t, st, "usr_cal_carol", "calcarol", "user", "00000000-0000-4000-8000-00000000000b")

	signedReq := func(method, path string, payload any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		h, err := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), "meeting.sync", uuid.NewString(), raw)
		if err != nil {
			t.Fatal(err)
		}
		h.Apply(req)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	now := time.Now().UTC().Truncate(time.Second)
	// Missing org_id must be rejected in multi-tenant mode.
	rec := signedReq(http.MethodPut, "/api/meetings/ext-1", map[string]any{
		"title":         "Missing Org",
		"organizer_sub": alice.SSOSubject,
		"windows": []map[string]string{{
			"start": now.Format(time.RFC3339),
			"end":   now.Add(time.Hour).Format(time.RFC3339),
		}},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT meeting without org_id = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	// Valid org_id creates meeting scoped to org-alpha and ignores cross-org attendees.
	rec = signedReq(http.MethodPut, "/api/meetings/ext-1", map[string]any{
		"org_id":        "00000000-0000-4000-8000-00000000000a",
		"title":         "Alpha Standup",
		"organizer_sub": alice.SSOSubject,
		"member_subs":   []string{alice.SSOSubject, carol.SSOSubject},
		"windows": []map[string]string{{
			"start": now.Format(time.RFC3339),
			"end":   now.Add(time.Hour).Format(time.RFC3339),
		}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT meeting with org_id = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		RoomID string `json:"room_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	members, err := st.Chat().ListRoomMembers(context.Background(), "00000000-0000-4000-8000-00000000000a", resp.RoomID)
	if err != nil {
		t.Fatalf("ListRoomMembers: %v", err)
	}
	aliceIn := false
	for _, m := range members {
		if m.UserID == carol.ID {
			t.Fatalf("cross-org attendee %s was added to org-alpha meeting room", carol.ID)
		}
		aliceIn = aliceIn || m.UserID == alice.ID
	}
	if !aliceIn {
		t.Fatalf("organizer %s was not resolved into the meeting room: %+v", alice.ID, members)
	}

	// DELETE without org_id fails (400); DELETE with wrong org_id is an idempotent no-op that
	// MUST leave org-alpha's meeting open; DELETE with org-alpha closes it.
	if rec := signedReq(http.MethodDelete, "/api/meetings/ext-1", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("DELETE without org_id = %d, want 400", rec.Code)
	}
	if rec := signedReq(http.MethodDelete, "/api/meetings/ext-1", map[string]any{"org_id": "00000000-0000-4000-8000-00000000000b"}); rec.Code != http.StatusOK {
		t.Fatalf("DELETE with wrong org_id = %d, want idempotent 200", rec.Code)
	}
	stillOpen, _, _, err := st.Chat().GetMeeting(context.Background(), "00000000-0000-4000-8000-00000000000a", "ext-1")
	if err != nil || stillOpen.ClosedAt != nil {
		t.Fatalf("org-alpha meeting should still be open after org-beta DELETE, got %+v err=%v", stillOpen, err)
	}
	if rec := signedReq(http.MethodDelete, "/api/meetings/ext-1", map[string]any{"org_id": "00000000-0000-4000-8000-00000000000a"}); rec.Code != http.StatusOK {
		t.Fatalf("DELETE with matching org_id = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	nowClosed, _, _, err := st.Chat().GetMeeting(context.Background(), "00000000-0000-4000-8000-00000000000a", "ext-1")
	if err != nil || nowClosed.ClosedAt == nil {
		t.Fatalf("org-alpha meeting should be closed after org-alpha DELETE, got %+v err=%v", nowClosed, err)
	}
}

func TestMultiTenantDirectoryWebhookAndOrgLifecycle(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)

	postSync := func(event string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/sso/kyidentity/sync", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/scim+json")
		h, err := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), event, uuid.NewString(), body)
		if err != nil {
			t.Fatal(err)
		}
		h.Apply(req)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	// 1. Missing org_id rejected with 400.
	noOrg := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"kid-no-org","externalId":"kid-no-org","userName":"noorg","roles":[],"active":true,"meta":{"resourceType":"User","version":"W/\"1\""}}`)
	if rec := postSync("user.created", noOrg); rec.Code != http.StatusBadRequest {
		t.Fatalf("user.created without org_id = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	// 2. Valid user.created with org_id provisions user in org-alpha.
	alphaUser := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"kid-100","externalId":"kid-100","userName":"eva","org_id":"00000000-0000-4000-8000-00000000000a","roles":[{"value":"admin"}],"active":true,"meta":{"resourceType":"User","version":"W/\"1\""}}`)
	if rec := postSync("user.created", alphaUser); rec.Code != http.StatusOK {
		t.Fatalf("user.created with org_id = %d: %s", rec.Code, rec.Body.String())
	}
	eva, err := st.Users().GetUserBySSO(context.Background(), "kyidentity", "kid-100")
	if err != nil {
		t.Fatalf("GetUserBySSO: %v", err)
	}
	if eva.OrgID != "00000000-0000-4000-8000-00000000000a" {
		t.Fatalf("eva.OrgID = %q, want org-alpha", eva.OrgID)
	}

	// 3. Re-assigning the same subject to org-beta must fail with 409 + audit sso.org_mismatch.
	mismatchUser := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"kid-100","externalId":"kid-100","userName":"eva","org_id":"00000000-0000-4000-8000-00000000000b","roles":[{"value":"admin"}],"active":true,"meta":{"resourceType":"User","version":"W/\"2\""}}`)
	if rec := postSync("user.updated", mismatchUser); rec.Code != http.StatusConflict {
		t.Fatalf("cross-org reassignment = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	logs, _, err := st.Audit().ListAuditRecords(context.Background(), 0, 20, "sso.org_mismatch")
	if err != nil || len(logs) == 0 {
		t.Fatalf("expected sso.org_mismatch audit log, got len=%d err=%v", len(logs), err)
	}

	// 4. Create session, room, and guest link in org-alpha; also a user in org-beta.
	evaTok := "tok_eva_" + uuid.NewString()
	if err := st.Sessions().CreateSession(context.Background(), &store.Session{
		UserID:    eva.ID,
		TokenHash: crypto.SHA256Hex([]byte(evaTok)),
		IPAddress: "127.0.0.1",
		UserAgent: "test",
		ExpiresAt: time.Now().Add(time.Hour),
	}, ""); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_, betaTok := createOrgUser(t, st, "usr_beta_zoe", "zoe", "user", "00000000-0000-4000-8000-00000000000b")

	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", evaTok, map[string]any{
		"kind": "channel",
		"name": "lifecycle-room",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create room = %d: %s", rec.Code, rec.Body.String())
	}
	var roomCreated struct {
		Room struct {
			ID string `json:"id"`
		} `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &roomCreated)

	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomCreated.Room.ID+"/meeting/guest-link", evaTok, nil, nil)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("create guest link = %d: %s", rec.Code, rec.Body.String())
	}
	var guestCreated struct {
		GuestURL   string `json:"guest_url"`
		GuestToken string
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &guestCreated)
	_, guestCreated.GuestToken, _ = strings.Cut(guestCreated.GuestURL, "/meet/")
	if guestCreated.GuestToken == "" {
		t.Fatalf("guest link response has no /meet/ token: %s", rec.Body.String())
	}

	// An admitted guest holds a live socket into the meeting.
	knockReq := httptest.NewRequest(http.MethodPost, "/api/meet/"+guestCreated.GuestToken+"/knock", strings.NewReader(`{"display_name":"Visitor"}`))
	knockReq.Header.Set("Content-Type", "application/json")
	knockRec := httptest.NewRecorder()
	srv.ServeHTTP(knockRec, knockReq)
	var knocked struct {
		GuestID string `json:"guest_id"`
		RoomID  string `json:"room_id"`
	}
	_ = json.Unmarshal(knockRec.Body.Bytes(), &knocked)
	var guestSecret string
	for _, c := range knockRec.Result().Cookies() {
		if c.Name == "ky_guest_session" {
			guestSecret = c.Value
		}
	}
	if knockRec.Code != http.StatusOK || knocked.GuestID == "" || guestSecret == "" {
		t.Fatalf("guest knock = %d: %s", knockRec.Code, knockRec.Body.String())
	}
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+knocked.RoomID+"/lobby/"+knocked.GuestID+"/admit", evaTok, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("admit guest = %d: %s", rec.Code, rec.Body.String())
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	wsCtx, wsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer wsCancel()
	guestWS, _, err := websocket.Dial(wsCtx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/api/meet/"+guestCreated.GuestToken+"/ws", &websocket.DialOptions{
		HTTPHeader: http.Header{"X-Guest-Session": []string{guestSecret}},
	})
	if err != nil {
		t.Fatalf("guest websocket: %v", err)
	}
	defer guestWS.CloseNow()
	if _, _, err := guestWS.Read(wsCtx); err != nil {
		t.Fatalf("guest hello: %v", err)
	}

	// 5. org.suspended revokes sessions and blocks API and guest link for org-alpha.
	suspendBody := []byte(`{"org_id":"00000000-0000-4000-8000-00000000000a","revision":1}`)
	if rec := postSync("org.suspended", suspendBody); rec.Code != http.StatusOK {
		t.Fatalf("org.suspended = %d: %s", rec.Code, rec.Body.String())
	}
	for {
		if _, _, err := guestWS.Read(wsCtx); err != nil {
			if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
				t.Fatalf("admitted guest socket after org.suspended ended with %v, want policy violation", err)
			}
			break
		}
	}

	// Eva's old session was revoked (401), and no new one can be issued while the org is suspended.
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms", evaTok, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session after org.suspended = %d, want 401", rec.Code)
	}
	evaTok2 := "tok_eva2_" + uuid.NewString()
	mint := func() error {
		return st.Sessions().CreateSession(context.Background(), &store.Session{
			UserID:    eva.ID,
			TokenHash: crypto.SHA256Hex([]byte(evaTok2)),
			IPAddress: "127.0.0.1",
			UserAgent: "test",
			ExpiresAt: time.Now().Add(time.Hour),
		}, "")
	}
	if err := mint(); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session issued for a suspended org: err=%v, want ErrNotFound", err)
	}

	// Guest meeting link for suspended org returns 404.
	guestReq := httptest.NewRequest(http.MethodGet, "/api/meet/"+guestCreated.GuestToken, nil)
	guestRec := httptest.NewRecorder()
	srv.ServeHTTP(guestRec, guestReq)
	if guestRec.Code != http.StatusNotFound {
		t.Fatalf("guest link for suspended org = %d, want 404", guestRec.Code)
	}

	// org-beta is completely unaffected.
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms", betaTok, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("org-beta rooms while org-alpha suspended = %d, want 200", rec.Code)
	}

	// 6. org.unsuspended restores org-alpha.
	if rec := postSync("org.unsuspended", []byte(`{"org_id":"00000000-0000-4000-8000-00000000000a","revision":2}`)); rec.Code != http.StatusOK {
		t.Fatalf("org.unsuspended = %d: %s", rec.Code, rec.Body.String())
	}
	if err := mint(); err != nil {
		t.Fatalf("session after org.unsuspended: %v", err)
	}
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms", evaTok2, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("org-alpha rooms after org.unsuspended = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// 7. org.deleted permanently blocks org-alpha.
	if rec := postSync("org.deleted", []byte(`{"org_id":"00000000-0000-4000-8000-00000000000a","revision":3}`)); rec.Code != http.StatusOK {
		t.Fatalf("org.deleted = %d: %s", rec.Code, rec.Body.String())
	}
	tenant, err := st.Chat().GetTenant(context.Background(), "00000000-0000-4000-8000-00000000000a")
	if err != nil || tenant.Status != store.TenantStatusDeleted {
		t.Fatalf("tenant after org.deleted = %+v err=%v, want deleted", tenant, err)
	}
}

// Sign-out drops the named push subscription under the user's own org.
func TestMultiTenantLogoutDropsPushSubscription(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	ctx := context.Background()
	u, tok := createOrgUser(t, st, "usr_lo_mt", "lomt", "user", "00000000-0000-4000-8000-00000000000a")
	if _, err := st.Chat().UpsertPushSubscription(ctx, crypto.SHA256Hex([]byte(tok)), &store.PushSubscription{
		TenantID: "00000000-0000-4000-8000-00000000000a", UserID: u.ID, Endpoint: "https://push.example/mt", P256DH: "k", AuthSecret: "a",
	}, 10); err != nil {
		t.Fatal(err)
	}
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/auth/logout", tok, map[string]any{"push_endpoint": "https://push.example/mt"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("logout = %d: %s", rec.Code, rec.Body.String())
	}
	if subs, _ := st.Chat().ListPushSubscriptions(ctx, "00000000-0000-4000-8000-00000000000a", u.ID); len(subs) != 0 {
		t.Fatalf("org-alpha push subscription survived sign-out: %d", len(subs))
	}
}

// Every route that names a user or a room answers a caller from another org exactly as it
// answers an unknown ID, and live events never reach a socket in another org.
func TestMultiTenantCrossOrgUserPaths(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	startChatBus(t, srv)
	const orgA, orgB = "00000000-0000-4000-8000-00000000000a", "00000000-0000-4000-8000-00000000000b"
	_, aliceTok := createOrgUser(t, st, "usr_a_alice", "alice", "user", orgA)
	bob, _ := createOrgUser(t, st, "usr_a_bob", "bob", "user", orgA)
	carol, carolTok := createOrgUser(t, st, "usr_b_carol", "carol", "user", orgB)
	_, daveTok := createOrgUser(t, st, "usr_b_dave", "dave", "user", orgB)

	roomOf := func(tok string, body map[string]any) string {
		t.Helper()
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", tok, body, nil)
		if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
			t.Fatalf("create room %v = %d: %s", body, rec.Code, rec.Body.String())
		}
		var resp struct {
			Room struct {
				ID string `json:"id"`
			} `json:"room"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp.Room.ID
	}
	alphaRoom := roomOf(aliceTok, map[string]any{"kind": "channel", "name": "alpha", "member_ids": []string{bob.ID}})
	alphaDM := roomOf(aliceTok, map[string]any{"kind": "dm", "dm_user_id": bob.ID})
	betaRoom := roomOf(daveTok, map[string]any{"kind": "channel", "name": "beta", "member_ids": []string{carol.ID}})

	// Alice owns her channel and still cannot pull org-beta's carol into it, or a ghost ID.
	for _, uid := range []string{carol.ID, "usr_nobody"} {
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+alphaRoom+"/members", aliceTok, map[string]any{"user_id": uid}, nil)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Target user not found") {
			t.Fatalf("add %s to alpha room = %d %s, want the unknown-user 404", uid, rec.Code, rec.Body.String())
		}
	}

	// Carol gets the non-member 404 on every org-alpha room route.
	for _, rm := range []string{alphaRoom, alphaDM} {
		for _, tc := range []struct{ method, path string }{
			{http.MethodPatch, "/api/v1/rooms/" + rm},
			{http.MethodDelete, "/api/v1/rooms/" + rm + "/members/" + bob.ID},
			{http.MethodPost, "/api/v1/rooms/" + rm + "/read"},
			{http.MethodPut, "/api/v1/rooms/" + rm + "/notifications"},
			{http.MethodGet, "/api/v1/rooms/" + rm + "/attachments"},
			{http.MethodGet, "/api/v1/rooms/" + rm + "/calls/state"},
			{http.MethodPost, "/api/v1/rooms/" + rm + "/calls/join"},
			{http.MethodPost, "/api/v1/rooms/" + rm + "/calls/escalate"},
			{http.MethodGet, "/api/v1/rooms/" + rm + "/lobby"},
			{http.MethodPost, "/api/v1/rooms/" + rm + "/lobby/guest_x/admit"},
			{http.MethodPost, "/api/v1/rooms/" + rm + "/meeting/guest-link"},
		} {
			body := map[string]any{"name": "x", "topic": "", "mode": "all", "seq": 1, "audio": true}
			rec := doBearerJSON(t, srv, tc.method, tc.path, carolTok, body, nil)
			if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "Unknown API endpoint") {
				t.Fatalf("cross-org %s %s = %d %s, want the room 404", tc.method, tc.path, rec.Code, rec.Body.String())
			}
		}
	}

	// The DM peer's name never resolves across orgs, and org-alpha rooms never list for carol.
	for _, path := range []string{"/api/v1/rooms", "/api/v1/bootstrap"} {
		rec := doBearerJSON(t, srv, http.MethodGet, path, carolTok, nil, nil)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), alphaRoom) || strings.Contains(rec.Body.String(), alphaDM) || strings.Contains(rec.Body.String(), "usr_a_") {
			t.Fatalf("carol %s = %d, leaks org-alpha: %s", path, rec.Code, rec.Body.String())
		}
	}

	// Live fan-out: carol's socket sees nothing from org-alpha, including a mention of her name.
	ts := httptest.NewServer(srv)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	carolWS, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/api/v1/ws", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + carolTok}, "Origin": []string{"https://chat.example.com"}},
	})
	if err != nil {
		t.Fatalf("carol ws: %v", err)
	}
	defer carolWS.CloseNow()
	if ev := readWSEvent(t, carolWS); ev.Type != chat.EventHello {
		t.Fatalf("carol first frame = %+v, want hello", ev)
	}
	for _, rm := range []string{alphaRoom, alphaDM} {
		if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+rm+"/messages", aliceTok, sealed("@carol @all secret", nil), nil); rec.Code != http.StatusCreated {
			t.Fatalf("alice post = %d: %s", rec.Code, rec.Body.String())
		}
	}
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+betaRoom+"/messages", daveTok, sealed("beta", nil), nil); rec.Code != http.StatusCreated {
		t.Fatalf("dave post = %d: %s", rec.Code, rec.Body.String())
	}
	if ev := readWSEvent(t, carolWS); ev.RoomID != betaRoom || ev.Type != chat.EventMessageNew {
		t.Fatalf("carol's next frame = %+v, want only her org's message in %s", ev, betaRoom)
	}
}

// KyIdentity names the resume event org.resumed; org.unsuspended stays accepted until it confirms.
func TestMultiTenantOrgResumed(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	const org = "00000000-0000-4000-8000-00000000000d"
	_, tok := createOrgUser(t, st, "usr_d_erin", "erin", "user", org)
	post := func(event, body string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/sso/kyidentity/sync", strings.NewReader(body))
		hdr, err := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), event, uuid.NewString(), []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		hdr.Apply(req)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", event, rec.Code, rec.Body.String())
		}
	}
	status := func() string {
		tenant, err := st.Chat().GetTenant(context.Background(), org)
		if err != nil {
			t.Fatal(err)
		}
		return tenant.Status
	}
	post("org.suspended", `{"org_id":"`+org+`","revision":1}`)
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms", tok, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("rooms while suspended = %d, want 401 (sessions revoked)", rec.Code)
	}
	post("org.resumed", `{"org_id":"`+org+`","revision":1}`)
	if status() != store.TenantStatusSuspended {
		t.Fatalf("org.resumed at the suspension's revision applied: %q", status())
	}
	post("org.resumed", `{"org_id":"`+org+`","revision":2}`)
	if status() != store.TenantStatusActive {
		t.Fatalf("org.resumed rev 2 left status %q, want active", status())
	}
	post("org.suspended", `{"org_id":"`+org+`","revision":3}`)
	post("org.unsuspended", `{"org_id":"`+org+`","revision":4}`)
	if status() != store.TenantStatusActive {
		t.Fatalf("legacy org.unsuspended left status %q, want active", status())
	}
	post("org.deleted", `{"org_id":"`+org+`","revision":5}`)
	post("org.resumed", `{"org_id":"`+org+`","revision":6}`)
	if status() != store.TenantStatusDeleted {
		t.Fatalf("org.resumed after deletion = %q, want deleted", status())
	}
}

// A delayed org.unsuspended older than the suspension never re-enables the org, across a restart.
func TestMultiTenantStaleOrgLifecycleIsIgnored(t *testing.T) {
	srv, st, cfg := newMultiTenantTestServer(t)
	ctx := context.Background()
	post := func(h http.Handler, event string, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/sso/kyidentity/sync", strings.NewReader(body))
		hdr, err := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), event, uuid.NewString(), []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		hdr.Apply(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	status := func() string {
		tenant, err := st.Chat().GetTenant(ctx, "00000000-0000-4000-8000-00000000000c")
		if err != nil {
			t.Fatal(err)
		}
		return tenant.Status
	}
	if code := post(srv, "org.suspended", `{"org_id":"00000000-0000-4000-8000-00000000000c"}`); code != http.StatusBadRequest {
		t.Fatalf("lifecycle event without a revision = %d, want 400", code)
	}
	if code := post(srv, "org.suspended", `{"org_id":"00000000-0000-4000-8000-00000000000c","revision":5}`); code != http.StatusOK || status() != store.TenantStatusSuspended {
		t.Fatalf("suspend rev 5 = %d, status %q", code, status())
	}
	if code := post(srv, "org.unsuspended", `{"org_id":"00000000-0000-4000-8000-00000000000c","revision":4}`); code != http.StatusOK || status() != store.TenantStatusSuspended {
		t.Fatalf("stale unsuspend rev 4 = %d, status %q, want suspended", code, status())
	}
	restarted := api.NewServer(cfg, st)
	t.Cleanup(restarted.WaitDetached)
	if code := post(restarted, "org.unsuspended", `{"org_id":"00000000-0000-4000-8000-00000000000c","revision":5}`); code != http.StatusOK || status() != store.TenantStatusSuspended {
		t.Fatalf("replayed rev 5 after restart = %d, status %q, want suspended", code, status())
	}
	if code := post(restarted, "org.unsuspended", `{"org_id":"00000000-0000-4000-8000-00000000000c","revision":6}`); code != http.StatusOK || status() != store.TenantStatusActive {
		t.Fatalf("newer unsuspend rev 6 = %d, status %q, want active", code, status())
	}
	if code := post(restarted, "org.deleted", `{"org_id":"00000000-0000-4000-8000-00000000000c","revision":2}`); code != http.StatusOK || status() != store.TenantStatusDeleted {
		t.Fatalf("delete = %d, status %q, want deleted", code, status())
	}
	if code := post(restarted, "org.unsuspended", `{"org_id":"00000000-0000-4000-8000-00000000000c","revision":99}`); code != http.StatusOK || status() != store.TenantStatusDeleted {
		t.Fatalf("unsuspend after delete = %d, status %q, want deleted", code, status())
	}
}

// Upgrading a used single-tenant database with KY_TENANCY_MODE=multi is refused without locking it.
func TestEnsureTenancyModeRefusesMultiOnAUsedDatabase(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Users().CreateUser(ctx, &store.User{ID: "u_old", Username: "old", Role: "user", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().CreateRoom(ctx, &store.Room{Kind: store.RoomKindChannel, Name: "general", CreatedBy: "u_old"}, []string{"u_old"}); err != nil {
		t.Fatal(err)
	}
	if err := api.EnsureTenancyMode(ctx, st, config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}); err == nil {
		t.Fatal("a database that served single-tenant chat was locked to multi")
	}
	if _, err := st.Settings().GetSetting(ctx, store.TenancyModeSettingKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refused multi boot still stored a mode: %v", err)
	}
	if err := api.EnsureTenancyMode(ctx, st, config.TenancyConfig{Mode: config.TenancySingle}); err != nil {
		t.Fatalf("single boot after the refusal: %v", err)
	}
}

// Org-less directory accounts mark a database as single-tenant even before any room exists; a
// local bootstrap admin alone does not.
func TestEnsureTenancyModeCountsDirectoryAccounts(t *testing.T) {
	ctx := context.Background()
	open := func() store.Store {
		st, err := store.Open(ctx, testdb.Config(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := st.Users().CreateUser(ctx, &store.User{ID: "u_admin", Username: "admin", Role: "admin", Status: "active", SSOProvider: "local"}); err != nil {
			t.Fatal(err)
		}
		return st
	}
	synced := open()
	if err := synced.Users().CreateUser(ctx, &store.User{ID: "u_dir", Username: "dir", Role: "user", Status: "active", SSOProvider: "kyidentity", SSOSubject: "sub-dir"}); err != nil {
		t.Fatal(err)
	}
	if err := api.EnsureTenancyMode(ctx, synced, config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}); err == nil {
		t.Fatal("a database with org-less directory accounts was locked to multi")
	}
	if err := api.EnsureTenancyMode(ctx, open(), config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}); err != nil {
		t.Fatalf("a fresh database with only the bootstrap admin: %v", err)
	}
}
