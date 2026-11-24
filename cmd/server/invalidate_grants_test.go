package main

import (
	"context"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestInvalidateGrantsFromMultiEnvironment(t *testing.T) {
	if os.Getenv("KY_TEST_INVALIDATE_GRANTS_CHILD") == "1" {
		runInvalidateGrants(nil)
		return
	}
	dbCfg := testdb.Config(t)
	if dbCfg.Driver != "postgres" {
		t.Skip("multi-tenant maintenance requires PostgreSQL")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dbCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Users().CreateUser(ctx, &store.User{ID: "offline-user", Username: "offline-user", Role: "user", Status: "active", SSOProvider: "kyidentity", SSOSubject: "offline-sub"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Sessions().CreateSession(ctx, &store.Session{UserID: "offline-user", TokenHash: "old-session", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, ""); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"KY_TENANCY_MODE": "multi", "KY_DATA_DIR": t.TempDir(), "KY_DB_DRIVER": "postgres", "KY_DB_DSN": dbCfg.DSN, "KY_STAFF_ORG_ID": "00000000-0000-4000-8000-000000000001", "KY_SESSION_SECRET": "maintenance-session-secret-0123456789", "KY_ENCRYPTION_KEY": strings.Repeat("ab", 32), "KY_PUSH_ENABLED": "false", "KY_CELLS": "us-east-2", "PUSH_RELAY_URL": "", "APNS_RELAY_URL": ""} {
		t.Setenv(key, value)
	}
	if _, err := config.LoadFromEnv(); err == nil {
		t.Fatal("server startup accepted multi mode")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInvalidateGrantsFromMultiEnvironment$")
	cmd.Env = append(os.Environ(), "KY_TEST_INVALIDATE_GRANTS_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("offline command: %v %s", err, out)
	}
	if _, err := st.Sessions().GetSession(ctx, "old-session"); err == nil {
		t.Fatal("offline command left restored session")
	}
	if _, err := config.LoadFromEnv(); err == nil {
		t.Fatal("maintenance lifted server gate")
	}
}
