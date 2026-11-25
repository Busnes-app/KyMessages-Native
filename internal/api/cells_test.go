package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/auth"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/coder/websocket"
	"github.com/google/uuid"
)

const cellKyPostKey = "kypost-cell-pair-secret-0123456789ab"

func admitInCell(t *testing.T, st store.Store, org, cell string, revision int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().ApplyTenantDirectory(ctx, store.TenantDirectoryEntry{TenantID: org, Revision: revision, Status: store.TenantStatusActive, Enabled: true, Valid: true, HomeRegion: cell}); err != nil {
		t.Fatal(err)
	}
}

// C5: once a deployment stops serving an org's cell (a restart with another KY_CELLS), every
// credential of that org is refused at once, with no new listing; an org of a served cell is
// untouched.
func TestCellsRefuseAnotherCellsOrgOnEveryWayIn(t *testing.T) {
	ctx := context.Background()
	srv, _, st, cfg := newReplicas(t, func(cfg *config.Config) {
		cfg.SSO.Enabled = true
		cfg.SSO.KyIdentityIssuer = suiteIssuer
		cfg.KyPost = config.PairConfig{URL: "https://mail.example", Secret: []byte(cellKyPostKey)}
	})
	if err := api.EnsureTenancyMode(ctx, st, config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg, Cells: []string{"us-east-2", "us-east-3"}}); err != nil {
		t.Fatal(err)
	}
	admitInCell(t, st, replicaOrgA, "us-east-2", 1)
	admitInCell(t, st, replicaOrgB, "us-east-3", 1)
	alice, aliceTok := createOrgUser(t, st, "usr_cell_alice", "cellalice", "user", replicaOrgA)
	aliceTwo, _ := createOrgUser(t, st, "usr_cell_alice2", "cellalice2", "user", replicaOrgA)
	bob, bobTok := createOrgUser(t, st, "usr_cell_bob", "cellbob", "user", replicaOrgB)
	bobTwo, _ := createOrgUser(t, st, "usr_cell_bob2", "cellbob2", "user", replicaOrgB)

	// Bob's org holds a bot, a room with a guest link, and a KyCalendar meeting.
	botTok := auth.AgentTokenPrefix + strings.Repeat("ab", 32)
	if err := st.Users().CreateUser(ctx, &store.User{ID: "usr_cell_bot", Username: "cell_bot", Role: "bot", Status: "active", SSOProvider: "bot", OrgID: replicaOrgB}); err != nil {
		t.Fatal(err)
	}
	if err := st.Agents().CreateAgent(ctx, &store.Agent{ID: "agt_cell", UserID: "usr_cell_bot", Username: "cell_bot", OwnerUserID: bob.ID, TokenHash: crypto.SHA256Hex([]byte(botTok)), TokenState: store.AgentTokenActive, CreatedBy: bob.ID, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", bobTok, map[string]any{"kind": store.RoomKindChannel, "name": "cell"}, nil))
	link := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/meeting/guest-link", bobTok, nil, nil)
	var guest struct {
		GuestURL string `json:"guest_url"`
	}
	_ = json.Unmarshal(link.Body.Bytes(), &guest)
	_, guestTok, _ := strings.Cut(guest.GuestURL, "/meet/")
	if guestTok == "" {
		t.Fatalf("guest link: %d %s", link.Code, link.Body.String())
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	type way struct {
		name string
		ok   func(org string) bool
	}
	tokens := map[string]string{replicaOrgA: aliceTok, replicaOrgB: bobTok}
	subs := map[string][2]string{replicaOrgA: {alice.SSOSubject, aliceTwo.SSOSubject}, replicaOrgB: {bob.SSOSubject, bobTwo.SSOSubject}}
	signedDo := func(method, path, event, key string, body any) int {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		h, err := syncauth.Sign([]byte(key), time.Now(), event, uuid.NewString(), raw)
		if err != nil {
			t.Fatal(err)
		}
		h.Apply(req)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code
	}
	ways := []way{
		{"session bearer (REST)", func(org string) bool {
			return doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms", tokens[org], nil, nil).Code == http.StatusOK
		}},
		{"session cookie (REST)", func(org string) bool {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rooms", nil)
			req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: tokens[org]})
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			return rec.Code == http.StatusOK
		}},
		{"/api/v1/ws", func(org string) bool {
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			c, _, err := websocket.Dial(wctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/api/v1/ws", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + tokens[org]}}})
			if err != nil {
				return false
			}
			defer c.CloseNow()
			_, _, err = c.Read(wctx) // a refused org's socket closes instead of saying hello
			return err == nil
		}},
		{"bot token", func(org string) bool {
			if org != replicaOrgB {
				return true // the only bot belongs to org B
			}
			return doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms", botTok, nil, nil).Code == http.StatusOK
		}},
		{"guest meeting token", func(org string) bool {
			if org != replicaOrgB {
				return true
			}
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/meet/"+guestTok, nil))
			return rec.Code == http.StatusOK
		}},
		{"KyPost suite peer call", func(org string) bool {
			return signedDo(http.MethodPost, "/api/suite/chat", "kypost.chat.open", cellKyPostKey, map[string]any{"sub": subs[org][0], "issuer": suiteIssuer, "org_id": org, "target_sub": subs[org][1]}) == http.StatusOK
		}},
		{"KyCalendar suite peer call", func(org string) bool {
			now := time.Now().UTC()
			return signedDo(http.MethodPut, "/api/meetings/cell-"+org[len(org)-2:]+"-"+uuid.NewString()[:8], "meeting.sync", testMultiTenantHMAC, map[string]any{"org_id": org, "title": "Cell", "organizer_sub": subs[org][0],
				"member_subs": []string{subs[org][0]}, "windows": []map[string]string{{"start": now.Format(time.RFC3339), "end": now.Add(time.Hour).Format(time.RFC3339)}}}) == http.StatusOK
		}},
	}
	for _, w := range ways {
		for _, org := range []string{replicaOrgA, replicaOrgB} {
			if !w.ok(org) {
				t.Fatalf("%s: org %s refused while its cell is served", w.name, org)
			}
		}
	}

	// Restart serving only us-east-2: org B's cell is gone from KY_CELLS.
	if err := api.EnsureTenancyMode(ctx, st, config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg, Cells: []string{"us-east-2"}}); err != nil {
		t.Fatal(err)
	}
	for _, w := range ways {
		if w.ok(replicaOrgB) {
			t.Errorf("%s: another cell's org was served", w.name)
		}
		if !w.ok(replicaOrgA) {
			t.Errorf("%s: a served cell's org was refused", w.name)
		}
	}
	// New sessions are refused too, on a sign-in through KyIdentity.
	cfg.SSO.AutoProvision = true
	idp := newFakeIdP(t, cfg)
	fresh := api.NewServer(cfg, st)
	t.Cleanup(fresh.CloseChat)
	for org, want := range map[string]int{replicaOrgB: http.StatusForbidden, replicaOrgA: http.StatusFound} {
		r := idp.signIn(fresh, map[string]any{"sub": "sub-new-" + org[len(org)-2:], "preferred_username": "new" + org[len(org)-2:], "org_id": org})
		if got := sessionCookie(r) != nil; got != (want != http.StatusForbidden) || (!got && r.Code != http.StatusForbidden) {
			t.Errorf("sign-in for %s: %d %s", org, r.Code, r.Body.String())
		}
	}
}

// The listing never creates another cell's org here; one already here (staged by a user
// webhook, or of a cell dropped from KY_CELLS) is suspended. The staff org is served by every
// cell, whatever KyIdentity lists for it.
func TestCellsSyncAdmitsOnlyServedCells(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	e.cfg.Tenancy.Cells = []string{"us-east-2", "us-east-4"}
	e.kyid.SetTenancy(e.cfg.Tenancy)
	if err := api.EnsureTenancyMode(ctx, e.st, e.cfg.Tenancy); err != nil {
		t.Fatal(err)
	}
	served, staged, unknown, unlisted := syncOrgID(1), syncOrgID(2), syncOrgID(3), syncOrgID(4)
	for _, id := range []string{staged, unlisted} { // staged by user webhooks
		if _, err := e.st.Chat().EnsureTenant(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	e.dir.list(
		listedOrg{ID: served, Status: "active", Enabled: true, Revision: 10, HomeRegion: "us-east-2"},
		listedOrg{ID: staged, Status: "active", Enabled: true, Revision: 11, HomeRegion: "us-east-3"},
		listedOrg{ID: unknown, Status: "active", Enabled: true, Revision: 12, HomeRegion: "us-east-3"},
		listedOrg{ID: testStaffOrg, Status: "active", Enabled: true, Revision: 13, HomeRegion: "local"},
	)
	if err := e.kyid.SyncTenancy(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	if got := e.status(t, served); got != store.TenantStatusActive {
		t.Fatalf("served cell's org: %s", got)
	}
	if got := e.status(t, staged); got != store.TenantStatusSuspended {
		t.Fatalf("another cell's staged org: %s", got)
	}
	// Suspended in storage too (not only by readiness), so its grants are revoked.
	active, err := e.st.Chat().ActiveTenantIDs(ctx)
	if err != nil || slices.Contains(active, staged) {
		t.Fatalf("another cell's org stays active: %v %v", active, err)
	}
	if _, err := e.st.Chat().GetTenant(ctx, unknown); err == nil {
		t.Fatal("the listing created another cell's org")
	}
	if got := e.status(t, testStaffOrg); got != store.TenantStatusActive {
		t.Fatalf("staff org: %s", got)
	}
	if cell, err := e.st.Chat().TenantHomeRegion(ctx, served); err != nil || cell != "us-east-2" {
		t.Fatalf("recorded cell: %q %v", cell, err)
	}
	// The staff org keeps its own region whatever KY_CELLS lists, so a restart with the same
	// cells in another order re-applies the unchanged listing and keeps its object keys.
	if cell, err := e.st.Chat().TenantHomeRegion(ctx, testStaffOrg); err != nil || cell != "local" {
		t.Fatalf("staff region: %q %v", cell, err)
	}
	e.cfg.Tenancy.Cells = []string{"us-east-4", "us-east-2"}
	e.kyid.SetTenancy(e.cfg.Tenancy)
	if err := api.EnsureTenancyMode(ctx, e.st, e.cfg.Tenancy); err != nil {
		t.Fatal(err)
	}
	if err := e.kyid.SyncTenancy(ctx, true, true); err != nil {
		t.Fatalf("reordered KY_CELLS refused an unchanged listing: %v", err)
	}
	if cell, _ := e.st.Chat().TenantHomeRegion(ctx, testStaffOrg); cell != "local" || e.status(t, testStaffOrg) != store.TenantStatusActive {
		t.Fatalf("staff after reorder: %q %s", cell, e.status(t, testStaffOrg))
	}
	// A pool report covers only admitted orgs: never another cell's, nor an unlisted one.
	usages, err := e.st.Chat().PoolUsages(ctx, time.Now().UnixMilli(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range usages {
		if u.TenantID != served && u.TenantID != testStaffOrg {
			t.Fatalf("pool report for another cell's org: %+v", u)
		}
	}
}
