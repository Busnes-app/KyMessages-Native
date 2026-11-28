package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Busnes-app/ky_server_base/internal/blobs"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/auth"
	"github.com/Busnes-app/ky_server_base/internal/config"
	kycrypto "github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func makeTestPNG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: uint8((x * 7) % 256), G: uint8((y * 13) % 256), B: uint8((x + y) % 256), A: 255})
		}
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.NoCompression}
	if err := enc.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// doMultipartUpload uploads as the web client does: end-to-end encrypted bytes (encrypted=1).
func doMultipartUpload(t *testing.T, handler http.Handler, path, bearer, fieldName, filename string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	if !strings.Contains(path, "?") {
		path += "?encrypted=1"
	}
	return doPlainUpload(t, handler, path, bearer, fieldName, filename, data)
}

// doPlainUpload uploads without encrypted=1, which the server refuses from everyone since E4.
func doPlainUpload(t *testing.T, handler http.Handler, path, bearer, fieldName, filename string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(fw, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// createChatTestBot makes a native bot account owned by ownerID and returns its kybot_ token.
func createChatTestBot(t *testing.T, st store.Store, id, username, ownerID string) string {
	t.Helper()
	ctx := context.Background()
	if err := st.Users().CreateUser(ctx, &store.User{ID: id, Username: username, Role: "bot", Status: "active", SSOProvider: "bot"}); err != nil {
		t.Fatal(err)
	}
	tok := auth.AgentTokenPrefix + kycrypto.RandomHex(32)
	if err := st.Agents().CreateAgent(ctx, &store.Agent{ID: "agt_" + id, UserID: id, Username: username, OwnerUserID: ownerID, TokenHash: kycrypto.SHA256Hex([]byte(tok)), TokenState: store.AgentTokenActive, CreatedBy: ownerID, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return tok
}

// Uploads (a bot's too, since E4) are opaque ciphertext: staged for the uploader only, served to
// members as attachments with strict headers, and removed with their message.
func TestChatAttachmentsUploadLinkDownloadAndCleanup(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()

	_, aliceTok := createChatTestUser(t, st, "u_att_alice", "attalice", "user")
	_, bobTok := createChatTestUser(t, st, "u_att_bob", "attbob", "user")
	_, charlieTok := createChatTestUser(t, st, "u_att_charlie", "attcharlie", "user")
	botTok := createChatTestBot(t, st, "u_att_bot", "attbot", "u_att_alice")

	// Alice creates a channel with Bob and her bot; Charlie is not a member.
	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind":       store.RoomKindChannel,
		"name":       "files-room",
		"member_ids": []string{"u_att_bob", "u_att_bot"},
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create room = %d: %s", rec.Code, rec.Body.String())
	}
	var roomResp struct {
		Room store.Room `json:"room"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &roomResp); err != nil {
		t.Fatal(err)
	}
	roomID := roomResp.Room.ID

	// Bootstrap exposes attachment limits.
	bootRec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/bootstrap", aliceTok, nil, nil)
	if bootRec.Code != http.StatusOK {
		t.Fatalf("bootstrap = %d", bootRec.Code)
	}
	var bootBody struct {
		Attachments struct {
			MaxUploadBytes int64 `json:"max_upload_bytes"`
			MaxPerMessage  int   `json:"max_per_message"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(bootRec.Body.Bytes(), &bootBody); err != nil {
		t.Fatal(err)
	}
	if bootBody.Attachments.MaxUploadBytes <= 1<<20 || bootBody.Attachments.MaxPerMessage != 10 {
		t.Fatalf("unexpected bootstrap attachment limits: %+v", bootBody.Attachments)
	}

	// Non-member Charlie cannot upload to the room (404, not 403).
	smallPNG := makeTestPNG(t, 4, 4)
	if r := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", charlieTok, "file", "snoop.png", smallPNG); r.Code != http.StatusNotFound {
		t.Fatalf("non-member upload = %d, want 404", r.Code)
	}

	// Empty file rejected with 400.
	if r := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", aliceTok, "file", "empty.txt", nil); r.Code != http.StatusBadRequest {
		t.Fatalf("empty upload = %d, want 400", r.Code)
	}

	// Upload a >1 MiB PNG to verify ServeHTTP's generic 1 MiB JSON cap does not block attachments.
	largePNG := makeTestPNG(t, 600, 600) // ~1.44 MiB uncompressed PNG
	if len(largePNG) <= 1<<20 {
		t.Fatalf("expected largePNG > 1 MiB, got %d bytes", len(largePNG))
	}
	// Since E4 a bot's plaintext upload is refused like anyone's; it uploads ciphertext.
	if r := doPlainUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", botTok, "file", "design.png", largePNG); r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "e2ee_required") {
		t.Fatalf("bot plaintext upload = %d %s, want 400 e2ee_required", r.Code, r.Body.String())
	}
	upRec := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", botTok, "file", "../../evil/design.png", largePNG)
	if upRec.Code != http.StatusCreated {
		t.Fatalf("upload large PNG = %d: %s", upRec.Code, upRec.Body.String())
	}
	var upResp struct {
		Attachment store.Attachment `json:"attachment"`
	}
	if err := json.Unmarshal(upRec.Body.Bytes(), &upResp); err != nil {
		t.Fatal(err)
	}
	att := upResp.Attachment
	if att.Filename != "encrypted.bin" || att.MimeType != "application/octet-stream" || att.SizeBytes != int64(len(largePNG)) {
		t.Fatalf("unexpected uploaded attachment metadata: %+v", att)
	}

	// Before linking to a message, the uploading bot can fetch it, but Bob gets 404.
	reqAliceStaged := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+att.ID+"?inline=1", nil)
	reqAliceStaged.Header.Set("Authorization", "Bearer "+botTok)
	recAliceStaged := httptest.NewRecorder()
	srv.ServeHTTP(recAliceStaged, reqAliceStaged)
	if recAliceStaged.Code != http.StatusOK {
		t.Fatalf("uploader preview staged attachment = %d, want 200", recAliceStaged.Code)
	}

	reqBobStaged := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+att.ID, nil)
	reqBobStaged.Header.Set("Authorization", "Bearer "+bobTok)
	recBobStaged := httptest.NewRecorder()
	srv.ServeHTTP(recBobStaged, reqBobStaged)
	if recBobStaged.Code != http.StatusNotFound {
		t.Fatalf("other member fetching staged attachment = %d, want 404", recBobStaged.Code)
	}

	// Bob cannot hijack Alice's staged attachment into his message.
	hijackRec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/messages", bobTok, map[string]any{
		"body":           testEnvelope("mine"),
		"encoding":       "e2ee_room_v1",
		"attachment_ids": []string{att.ID},
	}, nil)
	if hijackRec.Code != http.StatusBadRequest {
		t.Fatalf("hijack attachment send = %d, want 400", hijackRec.Code)
	}

	// The bot sends an attachment-only message (empty body allowed when attachment_ids is non-empty).
	sendRec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/messages", botTok, map[string]any{
		"body":           testEnvelope(""),
		"encoding":       "e2ee_room_v1",
		"attachment_ids": []string{att.ID},
	}, nil)
	if sendRec.Code != http.StatusCreated {
		t.Fatalf("send attachment-only message = %d: %s", sendRec.Code, sendRec.Body.String())
	}
	var msgResp struct {
		Message store.Message `json:"message"`
	}
	if err := json.Unmarshal(sendRec.Body.Bytes(), &msgResp); err != nil {
		t.Fatal(err)
	}
	if len(msgResp.Message.Attachments) != 1 || msgResp.Message.Attachments[0].ID != att.ID {
		t.Fatalf("message missing linked attachment: %+v", msgResp.Message)
	}

	// Bob can now download it with strict security headers, never inline (ciphertext); Charlie
	// still gets 404.
	reqBobInline := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+att.ID+"?inline=1", nil)
	reqBobInline.Header.Set("Authorization", "Bearer "+bobTok)
	recBobInline := httptest.NewRecorder()
	srv.ServeHTTP(recBobInline, reqBobInline)
	if recBobInline.Code != http.StatusOK {
		t.Fatalf("bob download inline = %d", recBobInline.Code)
	}
	if got := recBobInline.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", got)
	}
	if got := recBobInline.Header().Get("Content-Disposition"); !strings.HasPrefix(got, "attachment;") {
		t.Errorf("Content-Disposition = %q, want attachment", got)
	}
	if got := recBobInline.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := recBobInline.Header().Get("Content-Security-Policy"); got != "default-src 'none'; sandbox" {
		t.Errorf("CSP = %q, want sandbox", got)
	}
	if !bytes.Equal(recBobInline.Body.Bytes(), largePNG) {
		t.Error("downloaded PNG bytes do not match uploaded bytes")
	}

	reqCharlie := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+att.ID, nil)
	reqCharlie.Header.Set("Authorization", "Bearer "+charlieTok)
	recCharlie := httptest.NewRecorder()
	srv.ServeHTTP(recCharlie, reqCharlie)
	if recCharlie.Code != http.StatusNotFound {
		t.Fatalf("non-member download = %d, want 404", recCharlie.Code)
	}

	// Deleting the message removes both metadata and blob file on disk.
	blobPath := filepath.Join(cfg.Database.DataDir, "attachments", att.ID)
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("expected blob on disk before delete: %v", err)
	}
	delRec := doBearerJSON(t, srv, http.MethodDelete, "/api/v1/rooms/"+roomID+"/messages/"+msgResp.Message.ID, aliceTok, nil, nil)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete message = %d: %s", delRec.Code, delRec.Body.String())
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Errorf("expected blob removed from disk after DeleteMessage, got err=%v", err)
	}
	reqBobAfterDel := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+att.ID, nil)
	reqBobAfterDel.Header.Set("Authorization", "Bearer "+bobTok)
	recBobAfterDel := httptest.NewRecorder()
	srv.ServeHTTP(recBobAfterDel, reqBobAfterDel)
	if recBobAfterDel.Code != http.StatusNotFound {
		t.Fatalf("download after message delete = %d, want 404", recBobAfterDel.Code)
	}
}

func TestChatAttachmentsXSSDowngradeAndMaxUploadCap(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	cfg.Attachments.MaxUploadBytes = 2048
	srv := api.NewServer(cfg, st)
	startChatBus(t, srv)
	defer srv.CloseChat()

	_, aliceTok := createChatTestUser(t, st, "u_sec_alice", "secalice", "user")
	botTok := createChatTestBot(t, st, "u_sec_bot", "secbot", "u_sec_alice")

	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind":       store.RoomKindChannel,
		"name":       "sec-room",
		"member_ids": []string{"u_sec_bot"},
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create room = %d", rec.Code)
	}
	var roomResp struct {
		Room store.Room `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &roomResp)
	roomID := roomResp.Room.ID

	// Oversized file (> 2048 bytes) rejected with 413.
	over := bytes.Repeat([]byte("A"), 3000)
	if r := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", aliceTok, "file", "big.txt", over); r.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload = %d, want 413", r.Code)
	}

	// SVG XSS payload must downgrade to application/octet-stream and NEVER serve inline even with ?inline=1.
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"></svg>`)
	upSVG := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", botTok, "file", "xss.svg", svg)
	if upSVG.Code != http.StatusCreated {
		t.Fatalf("upload svg = %d: %s", upSVG.Code, upSVG.Body.String())
	}
	var svgResp struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(upSVG.Body.Bytes(), &svgResp)
	if svgResp.Attachment.MimeType != "application/octet-stream" {
		t.Fatalf("svg stored MimeType = %q, want application/octet-stream", svgResp.Attachment.MimeType)
	}

	reqInlineSVG := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+svgResp.Attachment.ID+"?inline=1", nil)
	reqInlineSVG.Header.Set("Authorization", "Bearer "+botTok)
	recInlineSVG := httptest.NewRecorder()
	srv.ServeHTTP(recInlineSVG, reqInlineSVG)
	if recInlineSVG.Code != http.StatusOK {
		t.Fatalf("download svg = %d", recInlineSVG.Code)
	}
	if got := recInlineSVG.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("svg served Content-Type = %q, want application/octet-stream", got)
	}
	if got := recInlineSVG.Header().Get("Content-Disposition"); !strings.HasPrefix(got, "attachment;") {
		t.Errorf("svg Content-Disposition = %q, want attachment (never inline)", got)
	}
}

func listStaged(t *testing.T, srv http.Handler, roomID, tok string) []store.Attachment {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/"+roomID+"/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list staged = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Attachments []store.Attachment `json:"attachments"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Attachments
}

func TestChatAttachmentQuotasDeleteAndOrphanSweep(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	cfg.Attachments.MaxUploadBytes = 2048
	cfg.Attachments.MaxPendingUserBytes = 2500
	cfg.Attachments.MaxTotalBytes = 3500
	cfg.Attachments.PendingTTL = time.Hour
	srv := api.NewServer(cfg, st)
	startChatBus(t, srv)
	defer srv.CloseChat()

	_, aliceTok := createChatTestUser(t, st, "u_q_alice", "qalice", "user")
	_, bobTok := createChatTestUser(t, st, "u_q_bob", "qbob", "user")

	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind": store.RoomKindChannel,
		"name": "quota-room",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create room = %d", rec.Code)
	}
	var roomResp struct {
		Room store.Room `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &roomResp)
	roomID := roomResp.Room.ID

	if r := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/members", aliceTok, map[string]any{
		"user_id": "u_q_bob",
	}, nil); r.Code != http.StatusCreated {
		t.Fatalf("add bob = %d", r.Code)
	}

	// 1. Alice stages 1800 bytes (under 2500 pending quota).
	up1 := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", aliceTok, "file", "a.txt", bytes.Repeat([]byte("a"), 1800))
	if up1.Code != http.StatusCreated {
		t.Fatalf("upload 1 = %d: %s", up1.Code, up1.Body.String())
	}
	var att1Resp struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(up1.Body.Bytes(), &att1Resp)

	// 2. Alice attempting another 1000 bytes exceeds her 2500-byte pending quota (413).
	upOverPending := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", aliceTok, "file", "b.txt", bytes.Repeat([]byte("b"), 1000))
	if upOverPending.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over pending quota = %d, want 413: %s", upOverPending.Code, upOverPending.Body.String())
	}

	// A reloaded composer lists only its own staged uploads.
	if got := listStaged(t, srv, roomID, aliceTok); len(got) != 1 || got[0].ID != att1Resp.Attachment.ID {
		t.Fatalf("alice staged list = %+v, want only her upload", got)
	}
	if got := listStaged(t, srv, roomID, bobTok); len(got) != 0 {
		t.Fatalf("bob sees alice's staged uploads: %+v", got)
	}
	_, carolTok := createChatTestUser(t, st, "u_q_carol", "qcarol", "user")
	reqCarol := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/"+roomID+"/attachments", nil)
	reqCarol.Header.Set("Authorization", "Bearer "+carolTok)
	recCarol := httptest.NewRecorder()
	srv.ServeHTTP(recCarol, reqCarol)
	if recCarol.Code != http.StatusNotFound {
		t.Fatalf("non-member staged list = %d, want 404", recCarol.Code)
	}

	// 3. Bob cannot delete Alice's staged attachment (404).
	reqBobDel := httptest.NewRequest(http.MethodDelete, "/api/v1/attachments/"+att1Resp.Attachment.ID, nil)
	reqBobDel.Header.Set("Authorization", "Bearer "+bobTok)
	recBobDel := httptest.NewRecorder()
	srv.ServeHTTP(recBobDel, reqBobDel)
	if recBobDel.Code != http.StatusNotFound {
		t.Fatalf("bob delete alice staged = %d, want 404", recBobDel.Code)
	}

	// 4. Alice deletes her staged attachment (204), freeing both DB row and disk blob.
	reqAliceDel := httptest.NewRequest(http.MethodDelete, "/api/v1/attachments/"+att1Resp.Attachment.ID, nil)
	reqAliceDel.Header.Set("Authorization", "Bearer "+aliceTok)
	recAliceDel := httptest.NewRecorder()
	srv.ServeHTTP(recAliceDel, reqAliceDel)
	if recAliceDel.Code != http.StatusNoContent {
		t.Fatalf("alice delete staged = %d, want 204: %s", recAliceDel.Code, recAliceDel.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.Attachments.Dir, att1Resp.Attachment.ID)); !os.IsNotExist(err) {
		t.Fatal("deleted staged blob still exists on disk")
	}

	// 5. Alice uploads 1800 bytes again and links it to a message; trying to DELETE a linked
	// attachment must return 409 Conflict.
	upLinked := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", aliceTok, "file", "linked.txt", bytes.Repeat([]byte("c"), 1800))
	if upLinked.Code != http.StatusCreated {
		t.Fatalf("upload linked = %d", upLinked.Code)
	}
	var linkedResp struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(upLinked.Body.Bytes(), &linkedResp)

	sendRec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/messages", aliceTok, map[string]any{
		"body":           testEnvelope("attached"),
		"encoding":       "e2ee_room_v1",
		"attachment_ids": []string{linkedResp.Attachment.ID},
	}, map[string]string{"Idempotency-Key": "idem-quota-1"})
	if sendRec.Code != http.StatusCreated {
		t.Fatalf("send linked message = %d: %s", sendRec.Code, sendRec.Body.String())
	}

	if got := listStaged(t, srv, roomID, aliceTok); len(got) != 0 {
		t.Fatalf("posted attachment still listed as staged: %+v", got)
	}

	reqDelLinked := httptest.NewRequest(http.MethodDelete, "/api/v1/attachments/"+linkedResp.Attachment.ID, nil)
	reqDelLinked.Header.Set("Authorization", "Bearer "+aliceTok)
	recDelLinked := httptest.NewRecorder()
	srv.ServeHTTP(recDelLinked, reqDelLinked)
	if recDelLinked.Code != http.StatusConflict {
		t.Fatalf("delete linked attachment = %d, want 409", recDelLinked.Code)
	}

	// 6. Total tenant storage is 1800/3500. Bob uploading 1800 bytes exceeds tenant total quota (413).
	upOverTotal := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", bobTok, "file", "overtotal.txt", bytes.Repeat([]byte("d"), 1800))
	if upOverTotal.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over tenant total quota = %d, want 413: %s", upOverTotal.Code, upOverTotal.Body.String())
	}

	// 7. Bob stages 1000 bytes (fits within remaining 1700 bytes). Sweeping with now + 2h
	// expires Bob's abandoned staged upload (DB + disk) while keeping Alice's linked blob!
	upOrphan := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", bobTok, "file", "orphan.txt", bytes.Repeat([]byte("e"), 1000))
	if upOrphan.Code != http.StatusCreated {
		t.Fatalf("upload orphan = %d: %s", upOrphan.Code, upOrphan.Body.String())
	}
	var orphanResp struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(upOrphan.Body.Bytes(), &orphanResp)

	// Immediate sweep (now) must keep fresh staged upload.
	if n, err := srv.SweepOrphanAttachments(context.Background(), time.Now()); err != nil || n != 0 {
		t.Fatalf("immediate sweep = (%d, %v), want (0, nil)", n, err)
	}

	// Sweep 2 hours later purges the expired staged upload and removes its blob from disk.
	if n, err := srv.SweepOrphanAttachments(context.Background(), time.Now().Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("future sweep = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Attachments.Dir, orphanResp.Attachment.ID)); !os.IsNotExist(err) {
		t.Fatal("expired orphan blob still exists on disk")
	}
	if _, err := os.Stat(filepath.Join(cfg.Attachments.Dir, linkedResp.Attachment.ID)); err != nil {
		t.Fatalf("linked attachment blob should survive orphan sweep: %v", err)
	}
}

func TestChatAttachmentConcurrentUploadsRespectPendingAndTenantQuotas(t *testing.T) {
	t.Run("pending_user_quota", func(t *testing.T) {
		_, st, cfg := setupTestServer(t)
		cfg.Attachments.MaxUploadBytes = 2048
		cfg.Attachments.MaxPendingUserBytes = 2500
		cfg.Attachments.MaxTotalBytes = 100000
		srv := api.NewServer(cfg, st)
		startChatBus(t, srv)
		defer srv.CloseChat()

		alice, aliceTok := createChatTestUser(t, st, "u_race_alice", "race_alice", "user")
		room := &store.Room{Kind: store.RoomKindChannel, Name: "race-pending", CreatedBy: alice.ID}
		if err := st.Chat().CreateRoom(context.Background(), room, []string{alice.ID}); err != nil {
			t.Fatal(err)
		}
		roomID := room.ID

		const (
			workers  = 12
			fileSize = 800
		)
		start := make(chan struct{})
		var acceptedCount atomic.Int64
		var acceptedBytes atomic.Int64
		errs := make(chan string, workers)
		var wg sync.WaitGroup

		for i := range workers {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				rec := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", aliceTok, "file", fmt.Sprintf("u%d.txt", idx), bytes.Repeat([]byte("a"), fileSize))
				switch rec.Code {
				case http.StatusCreated:
					var resp struct {
						Attachment store.Attachment `json:"attachment"`
					}
					if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
						errs <- fmt.Sprintf("decode 201: %v", err)
						return
					}
					acceptedCount.Add(1)
					acceptedBytes.Add(resp.Attachment.SizeBytes)
				case http.StatusRequestEntityTooLarge:
					// Expected rejection once pending quota is exhausted.
				default:
					errs <- fmt.Sprintf("worker %d got status %d: %s", idx, rec.Code, rec.Body.String())
				}
			}(i)
		}
		close(start)
		wg.Wait()
		close(errs)
		for msg := range errs {
			t.Fatal(msg)
		}

		if acceptedCount.Load() < 1 {
			t.Fatal("expected at least 1 upload to succeed")
		}
		if acceptedBytes.Load() > cfg.Attachments.MaxPendingUserBytes {
			t.Fatalf("acceptedBytes = %d exceeds MaxPendingUserBytes %d", acceptedBytes.Load(), cfg.Attachments.MaxPendingUserBytes)
		}
		dbPending, err := st.Chat().SumPendingAttachmentBytesByUploader(context.Background(), store.DefaultTenantID, alice.ID)
		if err != nil {
			t.Fatal(err)
		}
		if dbPending != acceptedBytes.Load() || dbPending > cfg.Attachments.MaxPendingUserBytes {
			t.Fatalf("dbPending = %d, acceptedBytes = %d, cap = %d", dbPending, acceptedBytes.Load(), cfg.Attachments.MaxPendingUserBytes)
		}

		// Verify rejected uploads left no orphaned blobs on disk.
		entries, err := os.ReadDir(cfg.Attachments.Dir)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(entries)) != acceptedCount.Load() {
			t.Fatalf("blob dir entries = %d, want %d (no leaked blobs for rejected uploads)", len(entries), acceptedCount.Load())
		}

		// Verify rejected uploads released their in-flight reservations: a follow-up upload
		// fitting inside the remaining headroom must succeed.
		remaining := cfg.Attachments.MaxPendingUserBytes - dbPending
		if remaining >= 100 {
			rec := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", aliceTok, "file", "followup.txt", bytes.Repeat([]byte("z"), 100))
			if rec.Code != http.StatusCreated {
				t.Fatalf("follow-up upload within remaining headroom (%d) = %d: %s", remaining, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("workspace_total_quota", func(t *testing.T) {
		_, st, cfg := setupTestServer(t)
		cfg.Attachments.MaxUploadBytes = 2048
		cfg.Attachments.MaxPendingUserBytes = 10000
		cfg.Attachments.MaxTotalBytes = 3000
		srv := api.NewServer(cfg, st)
		startChatBus(t, srv)
		defer srv.CloseChat()

		names := []string{"tot_alice", "tot_bob", "tot_carol", "tot_dave"}
		memberIDs := make([]string, len(names))
		tokens := make([]string, len(names))
		for i, name := range names {
			u, tok := createChatTestUser(t, st, "u_"+name, name, "user")
			memberIDs[i] = u.ID
			tokens[i] = tok
		}
		room := &store.Room{Kind: store.RoomKindChannel, Name: "race-total", CreatedBy: memberIDs[0]}
		if err := st.Chat().CreateRoom(context.Background(), room, memberIDs); err != nil {
			t.Fatal(err)
		}
		roomID := room.ID

		const (
			perUser  = 3
			fileSize = 800
		)
		start := make(chan struct{})
		var acceptedCount atomic.Int64
		var acceptedBytes atomic.Int64
		errs := make(chan string, len(names)*perUser)
		var wg sync.WaitGroup

		for uIdx, tok := range tokens {
			for j := range perUser {
				wg.Add(1)
				go func(userIdx, idx int, token string) {
					defer wg.Done()
					<-start
					rec := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", token, "file", fmt.Sprintf("u%d_%d.txt", userIdx, idx), bytes.Repeat([]byte("b"), fileSize))
					switch rec.Code {
					case http.StatusCreated:
						var resp struct {
							Attachment store.Attachment `json:"attachment"`
						}
						if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
							errs <- fmt.Sprintf("decode 201: %v", err)
							return
						}
						acceptedCount.Add(1)
						acceptedBytes.Add(resp.Attachment.SizeBytes)
					case http.StatusRequestEntityTooLarge:
						// Expected once workspace quota is reached.
					default:
						errs <- fmt.Sprintf("user %d upload %d got status %d: %s", userIdx, idx, rec.Code, rec.Body.String())
					}
				}(uIdx, j, tok)
			}
		}
		close(start)
		wg.Wait()
		close(errs)
		for msg := range errs {
			t.Fatal(msg)
		}

		if acceptedCount.Load() < 1 {
			t.Fatal("expected at least 1 upload to succeed")
		}
		if acceptedBytes.Load() > cfg.Attachments.MaxTotalBytes {
			t.Fatalf("acceptedBytes = %d exceeds MaxTotalBytes %d", acceptedBytes.Load(), cfg.Attachments.MaxTotalBytes)
		}
		dbTotal, err := st.Chat().SumAttachmentBytesByTenant(context.Background(), store.DefaultTenantID)
		if err != nil {
			t.Fatal(err)
		}
		if dbTotal != acceptedBytes.Load() || dbTotal > cfg.Attachments.MaxTotalBytes {
			t.Fatalf("dbTotal = %d, acceptedBytes = %d, cap = %d", dbTotal, acceptedBytes.Load(), cfg.Attachments.MaxTotalBytes)
		}

		entries, err := os.ReadDir(cfg.Attachments.Dir)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(entries)) != acceptedCount.Load() {
			t.Fatalf("blob dir entries = %d, want %d", len(entries), acceptedCount.Load())
		}

		// Confirm reservations were released on rejected uploads.
		remaining := cfg.Attachments.MaxTotalBytes - dbTotal
		if remaining >= 100 {
			rec := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", tokens[0], "file", "followup.txt", bytes.Repeat([]byte("z"), 100))
			if rec.Code != http.StatusCreated {
				t.Fatalf("follow-up upload within remaining tenant headroom (%d) = %d: %s", remaining, rec.Code, rec.Body.String())
			}
		}
	})
}

func TestChatAttachmentStorageInitErrorExposedAndReflectedInBootstrap(t *testing.T) {
	ctx := context.Background()
	dbCfg := testdb.Config(t)
	st, err := store.Open(ctx, dbCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Point Attachments.Dir at an existing regular file so blobs.NewStore fails even under root.
	badPath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(badPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Server:      config.ServerConfig{AppName: "TestApp", AppURL: "http://localhost:8080"},
		Security:    config.SecurityConfig{SessionSecret: "test-secret-key-at-least-32-chars!!", SessionTTL: time.Hour},
		Database:    dbCfg,
		Attachments: config.AttachmentsConfig{Dir: badPath},
	}
	srv := api.NewServer(cfg, st)
	if srv.BlobsError() == nil {
		t.Fatal("expected non-nil BlobsError() when attachment directory cannot be initialized")
	}

	_, aliceTok := createChatTestUser(t, st, "u_att_unavail", "alice_unavail", "user")
	rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/bootstrap", aliceTok, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Attachments struct {
			Available bool `json:"available"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Attachments.Available {
		t.Fatal("expected bootstrap attachments.available=false when blob store failed to initialize")
	}
}

// multipartParts builds a multipart body from parts in order; a part with a filename is a file.
func multipartParts(t *testing.T, parts ...[3]string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, p := range parts {
		var w io.Writer
		var err error
		if p[1] != "" {
			w, err = mw.CreateFormFile(p[0], p[1])
		} else {
			w, err = mw.CreateFormField(p[0])
		}
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, p[2])
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, mw.FormDataContentType()
}

func TestChatAttachmentsEncryptedUploadsAreOpaque(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()

	_, aliceTok := createChatTestUser(t, st, "u_enc_alice", "encalice", "user")
	_, bobTok := createChatTestUser(t, st, "u_enc_bob", "encbob", "user")
	_, carolTok := createChatTestUser(t, st, "u_enc_carol", "enccarol", "user")
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind": store.RoomKindChannel, "name": "sealed-files", "member_ids": []string{"u_enc_bob"},
	}, nil))
	up := "/api/v1/rooms/" + room + "/attachments"
	post := func(path, tok string, parts ...[3]string) *httptest.ResponseRecorder {
		body, ct := multipartParts(t, parts...)
		req := httptest.NewRequest(http.MethodPost, path, body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	// Ciphertext that happens to look like a PNG is still never sniffed or served as one, and the
	// name the client sent is never stored.
	ciphertext := makeTestPNG(t, 4, 4)
	rec := doMultipartUpload(t, srv, up, aliceTok, "file", "secret-plan.png", ciphertext)
	if rec.Code != http.StatusCreated {
		t.Fatalf("encrypted upload = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-plan") {
		t.Fatalf("upload answer leaks the client's file name: %s", rec.Body.String())
	}
	var file struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &file)
	if file.Attachment.Filename != "encrypted.bin" || file.Attachment.MimeType != "application/octet-stream" || file.Attachment.SizeBytes != int64(len(ciphertext)) {
		t.Fatalf("encrypted attachment metadata = %+v", file.Attachment)
	}
	// Quotas count the ciphertext.
	if staged := listStaged(t, srv, room, aliceTok); len(staged) != 1 || staged[0].SizeBytes != int64(len(ciphertext)) {
		t.Fatalf("staged = %+v", staged)
	}

	// A person may not upload plaintext, and an encrypted upload carries nothing but its file.
	for name, r := range map[string]*httptest.ResponseRecorder{
		"plaintext from a person":    doPlainUpload(t, srv, up, aliceTok, "file", "plan.pdf", []byte("plain")),
		"encrypted=0":                doPlainUpload(t, srv, up+"?encrypted=0", aliceTok, "file", "a", []byte("x")),
		"another query parameter":    doPlainUpload(t, srv, up+"?encrypted=1&key=c2VjcmV0", aliceTok, "file", "a", []byte("x")),
		"encrypted given twice":      doPlainUpload(t, srv, up+"?encrypted=1&encrypted=1", aliceTok, "file", "a", []byte("x")),
		"a malformed query":          doPlainUpload(t, srv, up+"?encrypted=1;key=x", aliceTok, "file", "a", []byte("x")),
		"a field before the file":    post(up+"?encrypted=1", aliceTok, [3]string{"file_key", "", "c2VjcmV0"}, [3]string{"file", "a", "x"}),
		"a field after the file":     post(up+"?encrypted=1", aliceTok, [3]string{"file", "a", "x"}, [3]string{"private_key", "", "c2VjcmV0"}),
		"a second file after a file": post(up+"?encrypted=1", aliceTok, [3]string{"file", "a", "x"}, [3]string{"file", "b", "y"}),
	} {
		if r.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400: %s", name, r.Code, r.Body.String())
		}
	}
	if r := doPlainUpload(t, srv, up, aliceTok, "file", "plan.pdf", []byte("plain")); !strings.Contains(r.Body.String(), `"code":"e2ee_required"`) {
		t.Errorf("plaintext refusal = %s", r.Body.String())
	}
	// Refused uploads leave nothing staged and hold no quota.
	if staged := listStaged(t, srv, room, aliceTok); len(staged) != 1 {
		t.Fatalf("refused uploads left staged files: %+v", staged)
	}

	// A file and its thumbnail are both attachments: ten files with thumbnails fit one message.
	ids := []string{file.Attachment.ID}
	for i := 1; i < 2*10; i++ {
		r := doMultipartUpload(t, srv, up, aliceTok, "file", "f", []byte(fmt.Sprintf("ciphertext %d", i)))
		var a struct {
			Attachment store.Attachment `json:"attachment"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &a)
		ids = append(ids, a.Attachment.ID)
	}
	extra := doMultipartUpload(t, srv, up, aliceTok, "file", "f", []byte("one too many"))
	var extraAtt struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(extra.Body.Bytes(), &extraAtt)
	if r := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", aliceTok, map[string]any{
		"body": testEnvelope(""), "encoding": "e2ee_room_v1", "attachment_ids": append(append([]string{}, ids...), extraAtt.Attachment.ID),
	}, nil); r.Code != http.StatusBadRequest {
		t.Fatalf("21 attachments = %d, want 400", r.Code)
	}

	// Staged ciphertext is the uploader's alone.
	get := func(tok, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+file.Attachment.ID+query, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}
	if r := get(bobTok, ""); r.Code != http.StatusNotFound {
		t.Fatalf("bob fetching staged ciphertext = %d, want 404", r.Code)
	}
	if r := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", aliceTok, map[string]any{
		"body": testEnvelope(""), "encoding": "e2ee_room_v1", "attachment_ids": ids,
	}, nil); r.Code != http.StatusCreated {
		t.Fatalf("post 20 attachments = %d: %s", r.Code, r.Body.String())
	}

	// Members get the exact ciphertext as an opaque download, never inline; others get 404.
	r := get(bobTok, "?inline=1")
	if r.Code != http.StatusOK || !bytes.Equal(r.Body.Bytes(), ciphertext) {
		t.Fatalf("bob download = %d (%d bytes)", r.Code, r.Body.Len())
	}
	for header, want := range map[string]string{
		"Content-Type":            "application/octet-stream",
		"Content-Disposition":     "attachment; filename=encrypted.bin",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox",
		"Cache-Control":           "private, no-store",
	} {
		if got := r.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if r := get(carolTok, ""); r.Code != http.StatusNotFound {
		t.Fatalf("non-member download = %d, want 404", r.Code)
	}
}

// An edit replaces only the text: the envelope a message with files was first sent in holds the
// file keys, so the server keeps it and edits never carry them to later room members.
func TestChatEncryptedEditKeepsTheFirstEnvelopeOfAMessageWithFiles(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()
	_, aliceTok := createChatTestUser(t, st, "u_orig_alice", "origalice", "user")
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "orig"}, nil))
	var up struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", aliceTok, "file", "f", []byte("ciphertext")).Body.Bytes(), &up)
	type msgResp struct {
		Message store.Message `json:"message"`
	}
	post := func(body string, ids []string) store.Message {
		var r msgResp
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", aliceTok, map[string]any{"body": body, "encoding": "e2ee_room_v1", "attachment_ids": ids}, nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("post = %d: %s", rec.Code, rec.Body.String())
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return r.Message
	}
	edit := func(id, body string) store.Message {
		var r msgResp
		rec := doBearerJSON(t, srv, http.MethodPatch, "/api/v1/rooms/"+room+"/messages/"+id, aliceTok, map[string]any{"body": body, "encoding": "e2ee_room_v1"}, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("edit = %d: %s", rec.Code, rec.Body.String())
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return r.Message
	}

	first := testEnvelope("with file")
	withFile := post(first, []string{up.Attachment.ID})
	if withFile.OriginalBody != "" {
		t.Fatalf("unedited message has original_body %q", withFile.OriginalBody)
	}
	if got := edit(withFile.ID, testEnvelope("caption 2")); got.OriginalBody != first {
		t.Fatalf("first edit original_body = %q, want the first envelope", got.OriginalBody)
	}
	// Later edits keep the very first envelope, and every read returns it.
	if got := edit(withFile.ID, testEnvelope("caption 3")); got.OriginalBody != first {
		t.Fatalf("second edit original_body = %q", got.OriginalBody)
	}
	var page struct {
		Messages []store.Message `json:"messages"`
	}
	_ = json.Unmarshal(doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms/"+room+"/messages", aliceTok, nil, nil).Body.Bytes(), &page)
	if len(page.Messages) != 1 || page.Messages[0].OriginalBody != first {
		t.Fatalf("listed messages = %+v", page.Messages)
	}
	// A text-only message keeps no copy of what it said before.
	textOnly := post(testEnvelope("typo"), nil)
	if got := edit(textOnly.ID, testEnvelope("fixed")); got.OriginalBody != "" {
		t.Fatalf("text edit kept original_body %q", got.OriginalBody)
	}
	// Deleting the message removes the kept envelope too.
	if rec := doBearerJSON(t, srv, http.MethodDelete, "/api/v1/rooms/"+room+"/messages/"+withFile.ID, aliceTok, nil, nil); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "original_body") {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	page.Messages = nil // json.Unmarshal would keep omitted fields of reused elements
	_ = json.Unmarshal(doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms/"+room+"/messages", aliceTok, nil, nil).Body.Bytes(), &page)
	for _, m := range page.Messages {
		if m.ID == withFile.ID && m.OriginalBody != "" {
			t.Fatalf("deleted message still has original_body")
		}
	}
}

// A refused encrypted upload leaves no blob behind and gives its quota reservation back, and a
// bot's plaintext message still takes at most ten attachments.
func TestChatAttachmentsRefusedUploadsReleaseEverything(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	cfg.Attachments.MaxUploadBytes = 2048
	cfg.Attachments.MaxPendingUserBytes = 2048
	srv := api.NewServer(cfg, st)
	startChatBus(t, srv)
	defer srv.CloseChat()
	_, aliceTok := createChatTestUser(t, st, "u_rel_alice", "relalice", "user")
	botTok := createChatTestBot(t, st, "u_rel_bot", "relbot", "u_rel_alice")
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "rel", "member_ids": []string{"u_rel_bot"}}, nil))
	up := "/api/v1/rooms/" + room + "/attachments"
	blobsOnDisk := func() int {
		entries, err := os.ReadDir(filepath.Join(cfg.Database.DataDir, "attachments"))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range entries {
			if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), ".") {
				n++
			}
		}
		return n
	}

	// Each refused upload reserves about its request size; leaked, six would exceed the 2 KiB cap.
	for i := 0; i < 6; i++ {
		body, ct := multipartParts(t, [3]string{"file", "a", strings.Repeat("c", 300)}, [3]string{"note", "", "trailing"})
		req := httptest.NewRequest(http.MethodPost, up+"?encrypted=1", body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Bearer "+aliceTok)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("trailing part = %d: %s", rec.Code, rec.Body.String())
		}
	}
	if n := blobsOnDisk(); n != 0 {
		t.Fatalf("refused uploads left %d blobs on disk", n)
	}
	// The body is refused before the blob is put in place: not even a temporary file remains for a
	// failed rollback to strand.
	if entries, _ := os.ReadDir(filepath.Join(cfg.Database.DataDir, "attachments")); len(entries) != 0 {
		t.Fatalf("refused uploads left files: %v", entries)
	}
	if rec := doMultipartUpload(t, srv, up, aliceTok, "file", "f", bytes.Repeat([]byte("k"), 1500)); rec.Code != http.StatusCreated {
		t.Fatalf("upload after refusals = %d: %s (a reservation was not released)", rec.Code, rec.Body.String())
	}

	// Since E4 nobody uploads plaintext, bots included.
	if rec := doPlainUpload(t, srv, up, botTok, "file", "b.txt", []byte("bot")); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "e2ee_required") {
		t.Fatalf("bot plaintext upload = %d %s, want 400 e2ee_required", rec.Code, rec.Body.String())
	}
}

// A message from before E5 (plaintext, with plaintext files) keeps no "original" however often it
// is edited, even once it is edited into an encrypted envelope: only a genuine first encrypted
// envelope is ever kept.
func TestChatLegacyAttachmentEditsKeepNoOriginal(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()
	_, aliceTok := createChatTestUser(t, st, "u_leg_alice", "legalice", "user")
	botTok := createChatTestBot(t, st, "u_leg_bot", "legbot", "u_leg_alice")
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "legacy", "member_ids": []string{"u_leg_bot"}}, nil))
	// The bot posted it before E4, when its plaintext was still accepted.
	ctx := context.Background()
	att := &store.Attachment{RoomID: room, UploaderID: "u_leg_bot", Filename: "report.txt", MimeType: "text/plain", SizeBytes: 16}
	if err := st.Chat().CreateAttachment(ctx, att); err != nil {
		t.Fatal(err)
	}
	var posted struct{ Message *store.Message }
	var err error
	posted.Message, _, err = st.Chat().CreateMessage(ctx, store.CreateMessageParams{TenantID: store.DefaultTenantID, RoomID: room, SenderID: "u_leg_bot", Encoding: store.MessageEncodingPlainV1, Body: "report", AttachmentIDs: []string{att.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if rec := doBearerJSON(t, srv, http.MethodPatch, "/api/v1/rooms/"+room+"/messages/"+posted.Message.ID, botTok, map[string]any{"body": "report v2", "encoding": "plain_v1"}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("plaintext edit = %d, want 400", rec.Code)
	}
	for i, edit := range []map[string]any{
		{"body": testEnvelope("report v3"), "encoding": "e2ee_room_v1"},
		{"body": testEnvelope("report v4"), "encoding": "e2ee_room_v1"},
	} {
		rec := doBearerJSON(t, srv, http.MethodPatch, "/api/v1/rooms/"+room+"/messages/"+posted.Message.ID, botTok, edit, nil)
		var got struct {
			Message store.Message `json:"message"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if rec.Code != http.StatusOK || got.Message.OriginalBody != "" || len(got.Message.Attachments) != 1 {
			t.Fatalf("edit %d = %d, original_body %q, %d attachments", i+1, rec.Code, got.Message.OriginalBody, len(got.Message.Attachments))
		}
	}
}

// The exact row a slim bus frame names is served to members only.
func TestChatGetMessageServesMembersOnly(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()
	_, aliceTok := createChatTestUser(t, st, "u_get_alice", "getalice", "user")
	_, eveTok := createChatTestUser(t, st, "u_get_eve", "geteve", "user")
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "get"}, nil))
	var posted struct {
		Message store.Message `json:"message"`
	}
	_ = json.Unmarshal(doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", aliceTok, map[string]any{"body": testEnvelope("first"), "encoding": "e2ee_room_v1"}, nil).Body.Bytes(), &posted)
	if rec := doBearerJSON(t, srv, http.MethodPatch, "/api/v1/rooms/"+room+"/messages/"+posted.Message.ID, aliceTok, map[string]any{"body": testEnvelope("second"), "encoding": "e2ee_room_v1"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("edit = %d", rec.Code)
	}
	path := "/api/v1/rooms/" + room + "/messages/" + posted.Message.ID
	rec := doBearerJSON(t, srv, http.MethodGet, path, aliceTok, nil, nil)
	var got struct {
		Message store.Message `json:"message"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got.Message.Body != testEnvelope("second") || got.Message.EditedAt == nil {
		t.Fatalf("member get = %d %+v", rec.Code, got.Message)
	}
	if rec := doBearerJSON(t, srv, http.MethodGet, path, eveTok, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("non-member get = %d, want 404", rec.Code)
	}
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms/"+room+"/messages/msg_missing", aliceTok, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("missing get = %d, want 404", rec.Code)
	}
}

// flakyBlobs fails every Erase while fail is set, as an unreachable store would.
type flakyBlobs struct {
	blobs.Backend
	fail atomic.Bool
}

func (b *flakyBlobs) Erase(tenantID, key string) error {
	if b.fail.Load() {
		return errors.New("storage unavailable")
	}
	return b.Backend.Erase(tenantID, key)
}

// A staged upload's removal is queued with its row, so a failed blob delete is retried by the
// sweep (single mode too), and a request that died between writing a blob and committing its row
// leaves an intent the sweep erases once the upload's deadline has passed.
func TestChatAttachmentBlobRemovalsAreDurable(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()
	fb := &flakyBlobs{Backend: api.BlobsForTest(srv)}
	api.SetBlobsForTest(srv, fb)
	_, aliceTok := createChatTestUser(t, st, "u_dur_alice", "duralice", "user")
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "durable"}, nil))
	dir := filepath.Join(cfg.Database.DataDir, "attachments")
	onDisk := func(key string) bool {
		_, err := os.Stat(filepath.Join(dir, key))
		return err == nil
	}
	queued := func() int {
		refs, err := st.Chat().PendingBlobDeletes(context.Background(), 100)
		if err != nil {
			t.Fatal(err)
		}
		return len(refs)
	}

	var up struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", aliceTok, "file", "f", []byte("ciphertext")).Body.Bytes(), &up)
	if queued() != 0 {
		t.Fatal("a committed upload left its intent queued")
	}
	fb.fail.Store(true)
	if rec := doBearerJSON(t, srv, http.MethodDelete, "/api/v1/attachments/"+up.Attachment.ID, aliceTok, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete staged = %d", rec.Code)
	}
	if !onDisk(up.Attachment.ID) || queued() != 1 {
		t.Fatalf("failed erase: on disk %v, queued %d; want the blob kept and queued", onDisk(up.Attachment.ID), queued())
	}
	if _, err := srv.SweepOrphanAttachments(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if queued() != 1 {
		t.Fatal("a sweep against unavailable storage dropped the queued delete")
	}
	fb.fail.Store(false)
	// The lease a failed attempt took must pass before the retry.
	if _, err := srv.SweepOrphanAttachments(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if !onDisk(up.Attachment.ID) {
		t.Fatal("a leased delete was retried before its lease ended")
	}
	if _, err := srv.SweepOrphanAttachments(context.Background(), time.Now().Add(11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if onDisk(up.Attachment.ID) || queued() != 0 {
		t.Fatalf("after the lease: on disk %v, queued %d; want erased and cleared", onDisk(up.Attachment.ID), queued())
	}

	// The crash boundary: a blob written, its intent queued, no row (the request died). Once due,
	// the sweep erases it and clears the queue.
	const crashed = "att_00000000-0000-7000-8000-00000000c4a5"
	if err := st.Chat().QueueUploadIntent(context.Background(), "", crashed, time.Now().Add(-time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := fb.Put(store.DefaultTenantID, crashed, strings.NewReader("half an upload"), 1<<20, blobs.PutOptions{Opaque: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.SweepOrphanAttachments(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if onDisk(crashed) {
		t.Fatal("the sweep left a blob whose upload never committed")
	}
}

type lateUploadBlobs struct {
	blobs.Backend
	beforePublish func()
	key           string
}

func (b *lateUploadBlobs) Put(tenantID, key string, r io.Reader, maxBytes int64, opts blobs.PutOptions) (blobs.PutResult, error) {
	b.key = key
	b.beforePublish()
	return b.Backend.Put(tenantID, key, r, maxBytes, opts)
}

func TestChatLatePublicationQueuesCleanupAfterIntentWasSwept(t *testing.T) {
	t.Run("missing intent", func(t *testing.T) {
		testLatePublicationCleanup(t, false, http.StatusRequestTimeout)
	})
	t.Run("quota refusal", func(t *testing.T) {
		testLatePublicationCleanup(t, true, http.StatusRequestEntityTooLarge)
	})
}

func testLatePublicationCleanup(t *testing.T, fillQuota bool, want int) {
	t.Helper()
	srv, st, cfg := setupTestServer(t)
	cfg.Attachments.MaxTotalBytes = 4096
	startChatBus(t, srv)
	defer srv.CloseChat()
	_, token := createChatTestUser(t, st, "u_late_upload", "lateupload", "user")
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", token, map[string]any{"kind": store.RoomKindChannel, "name": "uploads"}, nil))
	ctx := context.Background()
	backend := &lateUploadBlobs{Backend: api.BlobsForTest(srv)}
	backend.beforePublish = func() {
		if _, err := srv.SweepOrphanAttachments(ctx, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if refs, err := st.Chat().PendingBlobDeletes(ctx, 100); err != nil || len(refs) != 0 {
			t.Fatalf("intent after first sweep = %+v, %v", refs, err)
		}
		if fillQuota {
			if err := st.Chat().CreateAttachment(ctx, &store.Attachment{
				RoomID: room, UploaderID: "u_late_upload", Filename: "fill.bin",
				MimeType: "application/octet-stream", SizeBytes: cfg.Attachments.MaxTotalBytes,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	api.SetBlobsForTest(srv, backend)

	rec := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", token, "file", "file.bin", []byte("opaque file"))
	if rec.Code != want {
		t.Fatalf("late upload = %d, want %d: %s", rec.Code, want, rec.Body.String())
	}
	if refs, err := st.Chat().PendingBlobDeletes(ctx, 100); err != nil || len(refs) != 1 || refs[0].Key != backend.key {
		t.Fatalf("late publication cleanup = %+v, %v", refs, err)
	}
	if _, err := srv.SweepOrphanAttachments(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Database.DataDir, "attachments", backend.key)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blob after second sweep: %v, want not found", err)
	}
}

type uncertainUploadCommitStore struct {
	store.Store
	chat *uncertainUploadCommitChat
}

func (s uncertainUploadCommitStore) Chat() store.ChatStore { return s.chat }

type uncertainUploadCommitChat struct {
	store.ChatStore
	attachmentID string
}

func (c *uncertainUploadCommitChat) CommitAttachmentWithQuota(ctx context.Context, reservation string, att *store.Attachment, limits store.AttachmentQuotaLimits) error {
	if err := c.ChatStore.CommitAttachmentWithQuota(ctx, reservation, att, limits); err != nil {
		return err
	}
	c.attachmentID = att.ID
	return io.ErrUnexpectedEOF
}

func TestChatUploadUncertainCommitPreservesCommittedBlob(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()
	_, token := createChatTestUser(t, st, "u_upload", "upload", "user")
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", token, map[string]any{"kind": store.RoomKindChannel, "name": "uploads"}, nil))
	chat := &uncertainUploadCommitChat{ChatStore: st.Chat()}
	api.SetStoreForTest(srv, uncertainUploadCommitStore{Store: st, chat: chat})

	ciphertext := []byte("opaque file")
	rec := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", token, "file", "file.bin", ciphertext)
	if rec.Code != http.StatusInternalServerError || chat.attachmentID == "" {
		t.Fatalf("uncertain upload = %d, attachment %q", rec.Code, chat.attachmentID)
	}
	if _, err := srv.SweepOrphanAttachments(context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rec = doBearerJSON(t, srv, http.MethodGet, "/api/v1/attachments/"+chat.attachmentID, token, nil, nil)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), ciphertext) {
		t.Fatalf("download after uncertain commit = %d, %q", rec.Code, rec.Body.Bytes())
	}
}

type slowAttachmentBlobs struct {
	blobs.Backend
	delay time.Duration
}

func (b slowAttachmentBlobs) Put(tenantID, key string, r io.Reader, maxBytes int64, opts blobs.PutOptions) (blobs.PutResult, error) {
	time.Sleep(b.delay)
	return b.Backend.Put(tenantID, key, r, maxBytes, opts)
}

func (b slowAttachmentBlobs) Open(tenantID, key string, sizeBytes int64) (io.ReadSeekCloser, int64, error) {
	time.Sleep(b.delay)
	return b.Backend.Open(tenantID, key, sizeBytes)
}

func TestChatAttachmentTransfersExtendHTTPWriteDeadline(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()
	_, token := createChatTestUser(t, st, "u_slow_upload", "slowupload", "user")
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", token, map[string]any{"kind": store.RoomKindChannel, "name": "slow-uploads"}, nil))

	const serverDeadline = 200 * time.Millisecond
	api.SetBlobsForTest(srv, slowAttachmentBlobs{Backend: api.BlobsForTest(srv), delay: 2 * serverDeadline})
	server := httptest.NewUnstartedServer(srv)
	server.Config.WriteTimeout = serverDeadline
	server.Start()
	defer server.Close()

	payload := []byte("opaque file")
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	file, err := form.CreateFormFile("file", "encrypted.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, body io.Reader) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", form.FormDataContentType())
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}

	uploaded := request(http.MethodPost, "/api/v1/rooms/"+room+"/attachments?encrypted=1", &body)
	if uploaded.StatusCode != http.StatusCreated {
		t.Fatalf("slow upload = %d", uploaded.StatusCode)
	}
	var result struct {
		Attachment store.Attachment `json:"attachment"`
	}
	if err := json.NewDecoder(uploaded.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	downloaded := request(http.MethodGet, "/api/v1/attachments/"+result.Attachment.ID, nil)
	data, err := io.ReadAll(downloaded.Body)
	if err != nil || downloaded.StatusCode != http.StatusOK || !bytes.Equal(data, payload) {
		t.Fatalf("slow download = %d, %q, %v", downloaded.StatusCode, data, err)
	}
}

// A body that overflows while the handler looks for another part is reported as too large, not
// as an extra part.
func TestChatEncryptedUploadOverflowIsTooLarge(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	cfg.Attachments.MaxUploadBytes = 2048
	srv := api.NewServer(cfg, st)
	startChatBus(t, srv)
	defer srv.CloseChat()
	_, aliceTok := createChatTestUser(t, st, "u_ovf_alice", "ovfalice", "user")
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "ovf"}, nil))
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "encrypted.bin")
	_, _ = fw.Write([]byte("ciphertext"))
	// The next part's header alone exceeds the request limit (upload limit plus 64 KiB).
	_, _ = mw.CreatePart(textproto.MIMEHeader{"X-Padding": {strings.Repeat("p", 80<<10)}})
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rooms/"+room+"/attachments?encrypted=1", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+aliceTok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("overflowing body = %d, want 413: %s", rec.Code, rec.Body.String())
	}
}
