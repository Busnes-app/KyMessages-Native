package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// Multi mode stores each org's blobs under orgs/<tenant_id>/att/, moves blobs written flat
// before that, and refuses a replica whose attachment directory is not the shared volume.
func TestMultiTenantBlobLayout(t *testing.T) {
	a, _, st, cfg := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	_, tokA := createOrgUser(t, st, "usr_blob_a", "bloba", "user", replicaOrgA)
	_, tokB := createOrgUser(t, st, "usr_blob_b", "blobb", "user", replicaOrgB)
	rec := doBearerJSON(t, a, http.MethodPost, "/api/v1/rooms", tokA, map[string]any{"kind": store.RoomKindChannel, "name": "files"}, nil)
	var room struct {
		Room store.Room `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &room)
	up := doMultipartUpload(t, a, "/api/v1/rooms/"+room.Room.ID+"/attachments", tokA, "file", "a.txt", []byte("org a bytes"))
	if up.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", up.Code, up.Body.String())
	}
	var att struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(up.Body.Bytes(), &att)
	dir := filepath.Join(cfg.Database.DataDir, "attachments")
	orgPath := filepath.Join(dir, "orgs", replicaOrgA, "att", att.Attachment.ID)
	if _, err := os.Stat(orgPath); err != nil {
		t.Fatalf("blob not under its org: %v", err)
	}
	get := func(tok string) int {
		return doBearerJSON(t, a, http.MethodGet, "/api/v1/attachments/"+att.Attachment.ID, tok, nil, nil).Code
	}
	if get(tokA) != http.StatusOK || get(tokB) != http.StatusNotFound {
		t.Fatalf("download owner=%d other org=%d", get(tokA), get(tokB))
	}

	// A blob written flat (before the org layout) is moved by the next sweep, and the
	// relocation is recorded once.
	if err := os.Rename(orgPath, filepath.Join(dir, att.Attachment.ID)); err != nil {
		t.Fatal(err)
	}
	if get(tokA) != http.StatusOK {
		t.Fatal("flat blob unreadable before relocation")
	}
	if _, err := a.SweepOrphanAttachments(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orgPath); err != nil {
		t.Fatalf("flat blob not relocated: %v", err)
	}
	// A replica of an older build may still write flat during a rolling upgrade: the next sweep
	// moves that blob too, and reads find it meanwhile.
	if err := os.Rename(orgPath, filepath.Join(dir, att.Attachment.ID)); err != nil {
		t.Fatal(err)
	}
	if get(tokA) != http.StatusOK {
		t.Fatal("flat blob written after the first relocation is unreadable")
	}
	if _, err := a.SweepOrphanAttachments(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orgPath); err != nil {
		t.Fatalf("late flat blob not relocated: %v", err)
	}
	if get(tokA) != http.StatusOK {
		t.Fatal("relocated blob unreadable")
	}

	// A replica on a private disk refuses to serve attachments (cmd/server then fails startup).
	private := *cfg
	private.Database.DataDir = t.TempDir()
	if err := api.NewServer(&private, st).BlobsError(); err == nil {
		t.Fatal("a replica on a private attachment directory started")
	}
	if err := api.NewServer(cfg, st).BlobsError(); err != nil {
		t.Fatalf("a replica on the shared volume: %v", err)
	}
}
