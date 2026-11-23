package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestAgentStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t).Agents()
	a := &store.Agent{
		ID:          "agt_1",
		UserID:      "bot_1",
		Username:    "agent-helper",
		DisplayName: "Helper Bot",
		OwnerUserID: "usr_alice",
		TokenHash:   "hash1",
		TokenState:  store.AgentTokenActive,
		CreatedBy:   "admin",
	}
	if err := st.CreateAgent(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAgent(ctx, "agt_1")
	if err != nil || got.Username != a.Username || got.UserID != "bot_1" || got.TokenHash != "hash1" || got.OwnerUserID != "usr_alice" || got.CreatedAt.IsZero() {
		t.Fatalf("GetAgent: %+v %v", got, err)
	}
	byHash, err := st.GetAgentByTokenHash(ctx, "hash1")
	if err != nil || byHash.ID != "agt_1" {
		t.Fatalf("GetAgentByTokenHash: %+v %v", byHash, err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := st.TouchAgentLastUsed(ctx, "agt_1", now); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetAgent(ctx, "agt_1")
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(now) {
		t.Fatalf("LastUsedAt = %v, want %v", got.LastUsedAt, now)
	}

	for _, dup := range []store.Agent{
		{ID: "agt_2", UserID: "bot_2", Username: "agent-helper"},
		{ID: "agt_2", UserID: "bot_1", Username: "agent-other"},
	} {
		dup.OwnerUserID, dup.TokenHash, dup.TokenState, dup.CreatedBy = "usr_bob", "hash2", store.AgentTokenActive, "admin"
		if err := st.CreateAgent(ctx, &dup); !errors.Is(err, store.ErrAlreadyExists) {
			t.Fatalf("duplicate %+v: %v", dup, err)
		}
	}

	if err := st.SetAgentToken(ctx, "agt_1", "hash1", "", store.AgentTokenExpired); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAgentByTokenHash(ctx, "hash1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired token still resolved: %v", err)
	}
	if got, _ := st.GetAgent(ctx, "agt_1"); got.TokenHash != "" || got.TokenState != store.AgentTokenExpired {
		t.Fatalf("after expiry: %+v", got)
	}
	if err := st.SetAgentToken(ctx, "agt_1", "", "hash3", store.AgentTokenActive); err != nil {
		t.Fatal(err)
	}
	// A writer that read an older token hash loses: the newer one stays recorded.
	if err := st.SetAgentToken(ctx, "agt_1", "", "hash4", store.AgentTokenActive); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetAgentToken from a stale token hash: %v", err)
	}
	if err := st.SetAgentToken(ctx, "missing", "", "", store.AgentTokenRevoked); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetAgentToken missing: %v", err)
	}

	byOwner, err := st.ListAgentsByOwner(ctx, "usr_alice")
	if err != nil || len(byOwner) != 1 || byOwner[0].ID != "agt_1" {
		t.Fatalf("ListAgentsByOwner: %+v %v", byOwner, err)
	}
	list, err := st.ListAgents(ctx)
	if err != nil || len(list) != 1 || list[0].TokenHash != "hash3" {
		t.Fatalf("ListAgents: %+v %v", list, err)
	}
	if err := st.DeleteAgent(ctx, "agt_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAgent(ctx, "agt_1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetAgent after delete: %v", err)
	}
	if err := st.DeleteAgent(ctx, "agt_1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteAgent twice: %v", err)
	}
}

// An active token needs its hash; an ended one must not keep one.
func TestAgentTokenStateIsConsistent(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t).Agents()
	bad := []struct{ hash, state string }{
		{"", store.AgentTokenActive},
		{"hash1", store.AgentTokenRevoked},
		{"hash1", store.AgentTokenExpired},
		{"hash1", "bogus"},
	}
	for _, b := range bad {
		a := &store.Agent{ID: "agt", UserID: "bot_x", Username: "agent-x", OwnerUserID: "usr_a", TokenHash: b.hash, TokenState: b.state, CreatedBy: "admin"}
		if err := st.CreateAgent(ctx, a); err == nil {
			t.Fatalf("CreateAgent accepted %+v", b)
		}
	}
	a := &store.Agent{ID: "agt", UserID: "bot_x", Username: "agent-x", OwnerUserID: "usr_a", TokenHash: "hash1", TokenState: store.AgentTokenActive, CreatedBy: "admin"}
	if err := st.CreateAgent(ctx, a); err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		if err := st.SetAgentToken(ctx, "agt", "hash1", b.hash, b.state); err == nil {
			t.Fatalf("SetAgentToken accepted %+v", b)
		}
	}
}

// A prior directory offboarding can remove the human row before staff remove their bot.
// The retained subject mapping is exact provenance; names and audit text are not used.
func TestRemovedAgentRetainsOffboardedOwnerForErasure(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const org = "00000000-0000-4000-8000-0000000000d8"
	if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
		t.Fatal(err)
	}
	owner := &store.User{ID: "history-owner", Username: "history-owner", OrgID: org, SSOProvider: "kyidentity", SSOSubject: "history-sub", Role: "user", Status: "active"}
	bot := &store.User{ID: "history-bot", Username: "agent-history", SSOProvider: "bot", Role: "bot", Status: "active"} // legacy org-less bot
	unrelated := &store.User{ID: "unrelated-bot", Username: "agent-history-other", SSOProvider: "bot", Role: "bot", Status: "active"}
	for _, u := range []*store.User{owner, bot, unrelated} {
		if err := st.Users().CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	a := &store.Agent{ID: "history-agent", UserID: bot.ID, Username: bot.Username, OwnerUserID: owner.ID, TokenHash: "history-hash", TokenState: store.AgentTokenActive, CreatedBy: owner.ID}
	if err := st.Agents().CreateAgent(ctx, a); err != nil {
		t.Fatal(err)
	}
	if applied, err := st.Users().DeleteDirectoryUser(ctx, owner, store.DirectoryEvent{ID: "history-offboard", Revision: 1}); err != nil || !applied {
		t.Fatalf("offboard: %v %v", applied, err)
	}
	if err := st.Agents().DeleteAgent(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Chat().EraseUser(ctx, org, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Users().GetUserByID(ctx, bot.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("historical bot account survived: %v", err)
	}
	if _, err := st.Users().GetUserByID(ctx, unrelated.ID); err != nil {
		t.Fatalf("unrelated bot was guessed from its name: %v", err)
	}
}
