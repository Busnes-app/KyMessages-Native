package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

func TestErasureHandsSharedRoomsToTheLongestStandingSuccessor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		admins bool
	}{{"oldest-admin", true}, {"oldest-member", false}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srv, _, st, cfg := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
			owner, ownerToken := createOrgUser(t, st, "handover-owner", "handoverowner", "user", replicaOrgA)
			first, firstToken := createOrgUser(t, st, "handover-first", "handoverfirst", "user", replicaOrgA)
			second, _ := createOrgUser(t, st, "handover-second", "handoversecond", "user", replicaOrgA)
			older, olderToken := createOrgUser(t, st, "handover-member", "handovermember", "user", replicaOrgA)
			outsider, outsiderToken := createOrgUser(t, st, "handover-outsider", "handoveroutsider", "user", replicaOrgB)
			room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", ownerToken, map[string]any{"kind": "channel", "name": "shared"}, nil))
			role := store.RoomRoleMember
			if tc.admins {
				role = store.RoomRoleAdmin
			}
			// joined_at is also the start of this role: channel roles are set only when joining.
			for _, m := range []*store.RoomMember{
				{TenantID: replicaOrgA, RoomID: room, UserID: first.ID, Role: role, JoinedAt: 100},
				{TenantID: replicaOrgA, RoomID: room, UserID: second.ID, Role: role, JoinedAt: 200},
				{TenantID: replicaOrgA, RoomID: room, UserID: older.ID, Role: store.RoomRoleMember, JoinedAt: 10},
				// A corrupt cross-org membership must never become an owner.
				{TenantID: replicaOrgA, RoomID: room, UserID: outsider.ID, Role: store.RoomRoleAdmin, JoinedAt: 1},
			} {
				if err := st.Chat().AddRoomMember(ctx, m); err != nil {
					t.Fatal(err)
				}
			}
			upload := func(token string) store.Attachment {
				t.Helper()
				r := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", token, "file", "f.txt", []byte("retained file"))
				var v struct {
					Attachment store.Attachment `json:"attachment"`
				}
				if err := json.Unmarshal(r.Body.Bytes(), &v); err != nil || r.Code != http.StatusCreated {
					t.Fatalf("upload: %d %s", r.Code, r.Body.String())
				}
				return v.Attachment
			}
			erasedFile, keptFile := upload(ownerToken), upload(firstToken)
			for _, v := range []struct{ token, body, attachment string }{{ownerToken, "erased message", erasedFile.ID}, {firstToken, "surviving message", keptFile.ID}} {
				r := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", v.token, sealed(v.body, map[string]any{"attachment_ids": []string{v.attachment}}), nil)
				if r.Code != http.StatusCreated {
					t.Fatalf("message: %d %s", r.Code, r.Body.String())
				}
			}
			otherRoom := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", outsiderToken, map[string]any{"kind": "channel", "name": "otherorg"}, nil))
			// Fail cleanup after the handover transaction commits; the retry must not pick a new owner.
			api.SetBlobsForTest(srv, &failSecondBlobDelete{Backend: api.BlobsForTest(srv)})
			event := uuid.NewString()
			if r := postErased(t, srv, owner.SSOSubject, replicaOrgA, event); r.Code < 500 {
				t.Fatalf("cleanup failure: %d %s", r.Code, r.Body.String())
			}
			want := first.ID
			if !tc.admins {
				want = older.ID
			}
			assertOwner := func() {
				t.Helper()
				r, err := st.Chat().GetRoom(ctx, replicaOrgA, room)
				if err != nil || r.CreatedBy != want {
					t.Fatalf("creator: %+v %v want %s", r, err, want)
				}
				m, err := st.Chat().GetRoomMember(ctx, replicaOrgA, room, want)
				if err != nil || m.Role != store.RoomRoleOwner {
					t.Fatalf("successor: %+v %v", m, err)
				}
			}
			assertOwner()
			successorToken := firstToken
			if !tc.admins {
				successorToken = olderToken
			}
			if r := doBearerJSON(t, srv, http.MethodPatch, "/api/v1/rooms/"+room, successorToken, map[string]any{"name": "managed by successor"}, nil); r.Code != http.StatusOK {
				t.Fatalf("successor cannot manage room: %d %s", r.Code, r.Body.String())
			}
			for _, id := range []string{event, event, uuid.NewString()} {
				if r := postErased(t, srv, owner.SSOSubject, replicaOrgA, id); r.Code != http.StatusOK {
					t.Fatalf("replay: %d %s", r.Code, r.Body.String())
				}
				assertOwner()
			}
			blob := func(id string) string {
				return filepath.Join(cfg.Database.DataDir, "attachments", "orgs", replicaOrgA, "att", id)
			}
			if _, err := os.Stat(blob(erasedFile.ID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("erased blob: %v", err)
			}
			if _, err := os.Stat(blob(keptFile.ID)); err != nil {
				t.Fatalf("survivor blob removed: %v", err)
			}
			for _, a := range []struct {
				id     string
				status int
			}{{erasedFile.ID, http.StatusNotFound}, {keptFile.ID, http.StatusOK}} {
				r := doBearerJSON(t, srv, http.MethodGet, "/api/v1/attachments/"+a.id, firstToken, nil, nil)
				if r.Code != a.status {
					t.Fatalf("download %s: %d %s", a.id, r.Code, r.Body.String())
				}
			}
			page := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms/"+room+"/messages", firstToken, nil, nil)
			var v struct {
				Messages []store.Message `json:"messages"`
			}
			if err := json.Unmarshal(page.Body.Bytes(), &v); err != nil || len(v.Messages) != 2 {
				t.Fatalf("messages: %d %s", page.Code, page.Body.String())
			}
			for _, m := range v.Messages {
				if m.SenderID == owner.ID && (m.Body != "" || m.DeletedAt == nil || len(m.Attachments) != 0) {
					t.Fatalf("erased message: %+v", m)
				}
				if m.SenderID == first.ID && (m.Body != testEnvelope("surviving message") || len(m.Attachments) != 1) {
					t.Fatalf("survivor message: %+v", m)
				}
			}
			if r, err := st.Chat().GetRoom(ctx, replicaOrgB, otherRoom); err != nil || r.CreatedBy != outsider.ID {
				t.Fatalf("other org: %+v %v", r, err)
			}
			if _, n, err := st.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased"); err != nil || n != 1 {
				t.Fatalf("completion audits: %d %v", n, err)
			}
		})
	}
}

func TestErasureDeletesOnlyOwnedRoomsWithNoRemainingMember(t *testing.T) {
	ctx := context.Background()
	srv, _, st, cfg := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	owner, tok := createOrgUser(t, st, "solo-owner", "soloowner", "user", replicaOrgA)
	disabled, _ := createOrgUser(t, st, "disabled-member", "disabledmember", "user", replicaOrgA)
	solo := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", tok, map[string]any{"kind": "channel", "name": "solo"}, nil))
	shared := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", tok, map[string]any{"kind": "channel", "name": "disabled stays", "member_ids": []string{disabled.ID}}, nil))
	disabled.Status = "inactive"
	if err := st.Users().UpdateProfile(ctx, disabled); err != nil {
		t.Fatal(err)
	}
	up := doMultipartUpload(t, srv, "/api/v1/rooms/"+solo+"/attachments", tok, "file", "f.txt", []byte("solo file"))
	var v struct {
		Attachment store.Attachment `json:"attachment"`
	}
	if err := json.Unmarshal(up.Body.Bytes(), &v); err != nil || up.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", up.Code, up.Body.String())
	}
	for range 2 {
		if r := postErased(t, srv, owner.SSOSubject, replicaOrgA); r.Code != http.StatusOK {
			t.Fatalf("erase: %d %s", r.Code, r.Body.String())
		}
	}
	if _, err := st.Chat().GetRoom(ctx, replicaOrgA, solo); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("solo room remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Database.DataDir, "attachments", "orgs", replicaOrgA, "att", v.Attachment.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("solo blob remains: %v", err)
	}
	if r, err := st.Chat().GetRoom(ctx, replicaOrgA, shared); err != nil || r.CreatedBy != disabled.ID {
		t.Fatalf("disabled member lost shared room: %+v %v", r, err)
	}
	if m, err := st.Chat().GetRoomMember(ctx, replicaOrgA, shared, disabled.ID); err != nil || m.Role != store.RoomRoleOwner {
		t.Fatalf("disabled successor: %+v %v", m, err)
	}
}

// EraseUser is also used directly by restore/sweep integration fixtures. Room selection must
// use the durable actor set even when no earlier deactivation marked its bot inactive.
func TestErasureDeletesOwnedChannelWhoseOnlyOtherMemberIsItsBot(t *testing.T) {
	ctx := context.Background()
	srv, _, st, cfg := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	owner, tok := createOrgUser(t, st, "actor-a-owner", "actorowner", "user", replicaOrgA)
	bot := &store.User{ID: "actor-z-bot", Username: "actorbot", SSOProvider: "bot", OrgID: replicaOrgA, Role: "bot", Status: "active"}
	if err := st.Users().CreateUser(ctx, bot); err != nil {
		t.Fatal(err)
	}
	if err := st.Agents().CreateAgent(ctx, &store.Agent{ID: "actor-bot-agent", UserID: bot.ID, Username: bot.Username, OwnerUserID: owner.ID, TokenHash: "actor-bot-hash", TokenState: store.AgentTokenActive, CreatedBy: owner.ID, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", tok, map[string]any{"kind": "channel", "name": "only erased actors", "member_ids": []string{bot.ID}}, nil))
	up := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", tok, "file", "f.txt", []byte("owned-room bytes"))
	var v struct {
		Attachment store.Attachment `json:"attachment"`
	}
	if err := json.Unmarshal(up.Body.Bytes(), &v); err != nil || up.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", up.Code, up.Body.String())
	}
	if r := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", tok, sealed("erased content", map[string]any{"attachment_ids": []string{v.Attachment.ID}}), nil); r.Code != http.StatusCreated {
		t.Fatalf("post: %d %s", r.Code, r.Body.String())
	}
	late, err := st.Chat().EraseUser(ctx, replicaOrgA, owner)
	if err != nil || len(late) != 1 {
		t.Fatalf("direct erasure lost cleanup keys: %+v %v", late, err)
	}
	if _, err := st.Chat().GetRoom(ctx, replicaOrgA, room); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("owned actor-only channel survived first erasure: %v", err)
	}
	// Cleanup may fail after commit, then retry independently without recreating the room.
	backend := api.BlobsForTest(srv)
	api.SetBlobsForTest(srv, &failKey{Backend: backend, key: v.Attachment.ID})
	if _, err := srv.SweepOrphanAttachments(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if pending, err := st.Chat().PendingBlobDeletes(ctx, 10); err != nil || len(pending) != 1 {
		t.Fatalf("failed cleanup lost: %+v %v", pending, err)
	}
	api.SetBlobsForTest(srv, backend)
	for range 2 {
		if _, err := srv.SweepOrphanAttachments(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.Database.DataDir, "attachments", "orgs", replicaOrgA, "att", v.Attachment.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan blob survived: %v", err)
	}
	for range 2 {
		if _, err := st.Chat().EraseUser(ctx, replicaOrgA, owner); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Chat().GetRoom(ctx, replicaOrgA, room); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replay recreated room: %v", err)
	}
	if _, n, err := st.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased"); err != nil || n != 1 {
		t.Fatalf("completion audit: %d %v", n, err)
	}
}
