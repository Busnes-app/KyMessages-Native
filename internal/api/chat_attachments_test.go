package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/config"
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

func doMultipartUpload(t *testing.T, handler http.Handler, path, bearer, fieldName, filename string, data []byte) *httptest.ResponseRecorder {
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

func TestChatAttachmentsUploadLinkDownloadAndCleanup(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()

	_, aliceTok := createChatTestUser(t, st, "u_att_alice", "attalice", "user")
	_, bobTok := createChatTestUser(t, st, "u_att_bob", "attbob", "user")
	_, charlieTok := createChatTestUser(t, st, "u_att_charlie", "attcharlie", "user")

	// Alice creates a channel with Bob; Charlie is not a member.
	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind":       store.RoomKindChannel,
		"name":       "files-room",
		"member_ids": []string{"u_att_bob"},
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
	upRec := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", aliceTok, "file", "../../evil/design.png", largePNG)
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
	if att.Filename != "design.png" || att.MimeType != "image/png" || att.SizeBytes != int64(len(largePNG)) {
		t.Fatalf("unexpected uploaded attachment metadata: %+v", att)
	}

	// Before linking to a message, uploader Alice can fetch it, but Bob gets 404.
	reqAliceStaged := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+att.ID+"?inline=1", nil)
	reqAliceStaged.Header.Set("Authorization", "Bearer "+aliceTok)
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

	// Alice sends an attachment-only message (empty body allowed when attachment_ids is non-empty).
	sendRec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/messages", aliceTok, map[string]any{
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

	// Bob can now download it inline with strict security headers; Charlie still gets 404.
	reqBobInline := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+att.ID+"?inline=1", nil)
	reqBobInline.Header.Set("Authorization", "Bearer "+bobTok)
	recBobInline := httptest.NewRecorder()
	srv.ServeHTTP(recBobInline, reqBobInline)
	if recBobInline.Code != http.StatusOK {
		t.Fatalf("bob download inline = %d", recBobInline.Code)
	}
	if got := recBobInline.Header().Get("Content-Type"); got != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", got)
	}
	if got := recBobInline.Header().Get("Content-Disposition"); !strings.HasPrefix(got, "inline;") {
		t.Errorf("Content-Disposition = %q, want inline", got)
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

	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind": store.RoomKindChannel,
		"name": "sec-room",
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
	upSVG := doMultipartUpload(t, srv, "/api/v1/rooms/"+roomID+"/attachments", aliceTok, "file", "xss.svg", svg)
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
	reqInlineSVG.Header.Set("Authorization", "Bearer "+aliceTok)
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
