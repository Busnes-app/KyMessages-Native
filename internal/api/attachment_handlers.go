package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/blobs"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

const (
	maxAttachmentsPerMessage = 10
	// multipartEnvelopeOverhead leaves headroom for multipart boundaries and headers
	// without allowing arbitrary request inflation beyond MaxUploadBytes.
	multipartEnvelopeOverhead = 64 << 10
)

// attachmentUploadDeadline is a minute plus the upload limit at 128 KiB/s (about 1 Mbit/s),
// so a slow uplink can finish the largest allowed file: 25 MiB gets about 4 minutes.
func attachmentUploadDeadline(maxBytes int64) time.Duration {
	return time.Minute + time.Duration(maxBytes/(128<<10))*time.Second
}

var chatLimitUploads = chatLimit{"chat-uploads:", 30}

func (s *Server) maxUploadBytes() int64 {
	if s.config != nil && s.config.Attachments.MaxUploadBytes > 0 {
		return s.config.Attachments.MaxUploadBytes
	}
	return config.DefaultMaxUploadBytes
}

func (s *Server) maxTotalAttachmentBytes() int64 {
	if s.config != nil && s.config.Attachments.MaxTotalBytes > 0 {
		return s.config.Attachments.MaxTotalBytes
	}
	return config.DefaultMaxTotalAttachmentBytes
}

func (s *Server) maxPendingUserBytes() int64 {
	if s.config != nil && s.config.Attachments.MaxPendingUserBytes > 0 {
		return s.config.Attachments.MaxPendingUserBytes
	}
	return config.DefaultMaxPendingUserBytes
}

func (s *Server) pendingAttachmentTTL() time.Duration {
	if s.config != nil && s.config.Attachments.PendingTTL > 0 {
		return s.config.Attachments.PendingTTL
	}
	return config.DefaultPendingAttachmentTTL
}

// isAttachmentUploadPath reports whether path is POST /api/v1/rooms/{id}/attachments.
// ServeHTTP skips the generic 1 MiB JSON cap for this route so handleChatUploadAttachment
// can apply its own MaxUploadBytes + multipart headroom limit immediately.
func isAttachmentUploadPath(path string) bool {
	const prefix = "/api/v1/rooms/"
	const suffix = "/attachments"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return false
	}
	roomID := path[len(prefix) : len(path)-len(suffix)]
	return roomID != "" && !strings.Contains(roomID, "/")
}

// POST /api/v1/rooms/{id}/attachments
// Accepts multipart/form-data with a single "file" part, validates size, storage quotas,
// and magic bytes, writes the blob under a server-generated flat key, and creates an
// unattached attachment record owned by the uploader that can then be linked via
// POST /api/v1/rooms/{id}/messages.
func (s *Server) handleChatUploadAttachment(w http.ResponseWriter, r *http.Request) {
	if s.blobs == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Attachment storage unavailable")
		return
	}
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if !s.allowChatAction(w, user.ID, chatLimitUploads) {
		return
	}

	roomID := r.PathValue("id")
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	if _, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID); !ok {
		return
	}
	room, err := s.store.Chat().GetRoom(r.Context(), tenantID, roomID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Room not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to verify room")
		return
	}
	if room.ClosedAt != nil {
		s.writeError(w, http.StatusConflict, "Room is closed")
		return
	}

	maxBytes := s.maxUploadBytes()
	limits := store.AttachmentQuotaLimits{
		MaxTotalBytes:       s.maxTotalAttachmentBytes(),
		MaxPendingUserBytes: s.maxPendingUserBytes(),
		Pool:                s.poolActive(tenantID),
		ActiveUploader:      s.config.Tenancy.IsMultiTenant(),
	}
	if s.config.Tenancy.IsMultiTenant() {
		limits.MaxTotalBytes = 0 // the org pool replaces the install-wide per-tenant cap
	}

	// Extend read deadline for larger uploads on real connections; ignored on httptest recorders.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(attachmentUploadDeadline(maxBytes)))
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+multipartEnvelopeOverhead)

	mr, err := r.MultipartReader()
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Request must be multipart/form-data with a file field")
		return
	}

	var filePart io.ReadCloser
	var rawFilename string
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				s.writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("File exceeds maximum size of %d bytes", maxBytes))
				return
			}
			s.writeError(w, http.StatusBadRequest, "Malformed multipart upload")
			return
		}
		if part.FormName() == "file" {
			filePart = part
			rawFilename = part.FileName()
			break
		}
		_ = part.Close()
	}
	if filePart == nil {
		s.writeError(w, http.StatusBadRequest, "Missing file field in multipart upload")
		return
	}
	defer filePart.Close()

	requestedBytes := maxBytes
	if r.ContentLength > 0 && r.ContentLength < requestedBytes {
		requestedBytes = r.ContentLength
	}
	reserve := func() (*store.AttachmentQuotaReservation, error) {
		return s.store.Chat().ReserveAttachmentQuota(r.Context(), tenantID, user.ID, requestedBytes, limits, attachmentUploadDeadline(maxBytes)+time.Minute)
	}
	res, err := reserve()
	// No usable grant, or less of it than this upload may need: report the org once and look
	// again (a short reservation is released first, so the report does not count it). The
	// attempt limit keeps a full org from turning every upload into a KyIdentity call.
	short := err == nil && res.LimitingKind == store.AttachmentQuotaLimitPool
	if (short || errors.Is(err, store.ErrPoolUnavailable) || errors.Is(err, store.ErrPoolFull)) &&
		s.allowAccountAttempt("pool-sync:"+tenantID, 6, time.Minute) {
		if short {
			_ = s.store.Chat().ReleaseAttachmentQuota(r.Context(), tenantID, res.ID)
		}
		if rerr := s.refreshOrgPool(r.Context(), tenantID); rerr == nil || short {
			res, err = reserve()
		}
	}
	if err != nil {
		if s.writePoolError(w, err) {
			return
		}
		switch {
		case errors.Is(err, store.ErrAttachmentTenantQuotaExceeded):
			s.writeError(w, http.StatusRequestEntityTooLarge, "Workspace attachment storage quota exceeded")
		case errors.Is(err, store.ErrAttachmentPendingQuotaExceeded):
			s.writeError(w, http.StatusRequestEntityTooLarge, "Pending attachment quota exceeded; send or remove staged uploads first")
		default:
			s.writeError(w, http.StatusInternalServerError, "Failed to reserve attachment storage quota")
		}
		return
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		relCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		_ = s.store.Chat().ReleaseAttachmentQuota(relCtx, tenantID, res.ID)
	}()

	quotaErrMsg := fmt.Sprintf("File exceeds maximum size of %d bytes", maxBytes)
	switch res.LimitingKind {
	case store.AttachmentQuotaLimitPending:
		quotaErrMsg = "Pending attachment quota exceeded; send or remove staged uploads first"
	case store.AttachmentQuotaLimitTenant:
		quotaErrMsg = "Workspace attachment storage quota exceeded"
	}

	attID := "att_" + uuid.Must(uuid.NewV7()).String()
	putRes, err := s.blobs.Put(tenantID, attID, filePart, res.ReservedBytes)
	if err != nil {
		var maxErr *http.MaxBytesError
		switch {
		case (errors.Is(err, blobs.ErrTooLarge) || errors.As(err, &maxErr)) && res.LimitingKind == store.AttachmentQuotaLimitPool:
			s.writePoolError(w, store.ErrPoolFull)
		case errors.Is(err, blobs.ErrTooLarge) || errors.As(err, &maxErr):
			s.writeError(w, http.StatusRequestEntityTooLarge, quotaErrMsg)
		case errors.Is(err, blobs.ErrEmpty):
			s.writeError(w, http.StatusBadRequest, "File cannot be empty")
		default:
			s.writeError(w, http.StatusInternalServerError, "Failed to store uploaded file")
		}
		return
	}

	att := &store.Attachment{
		ID:         attID,
		TenantID:   tenantID,
		RoomID:     roomID,
		UploaderID: user.ID,
		BlobKey:    putRes.Key,
		Filename:   blobs.SanitizeFilename(rawFilename),
		MimeType:   putRes.MimeType,
		SizeBytes:  putRes.SizeBytes,
		SHA256Hex:  putRes.SHA256Hex,
	}
	if err := s.store.Chat().CommitAttachmentWithQuota(r.Context(), res.ID, att, limits); err != nil {
		_ = s.blobs.Delete(tenantID, putRes.Key)
		if s.writePoolError(w, err) {
			return
		}
		switch {
		case errors.Is(err, store.ErrAttachmentTenantQuotaExceeded):
			s.writeError(w, http.StatusRequestEntityTooLarge, "Workspace attachment storage quota exceeded")
		case errors.Is(err, store.ErrAttachmentPendingQuotaExceeded):
			s.writeError(w, http.StatusRequestEntityTooLarge, "Pending attachment quota exceeded; send or remove staged uploads first")
		case errors.Is(err, store.ErrForbidden):
			s.writeError(w, http.StatusForbidden, "Account is disabled or inactive")
		default:
			s.writeError(w, http.StatusInternalServerError, "Failed to save attachment metadata")
		}
		return
	}
	committed = true

	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusCreated, map[string]any{"attachment": att})
}

// GET /api/v1/attachments/{id}
// Verifies room membership (returning 404 on missing/unauthorized to prevent enumeration),
// restricts unattached staged blobs to their uploader, rejects blobs belonging to deleted
// messages, and serves bytes with strict anti-XSS headers. Inline disposition is granted
// only when ?inline=1 is requested AND the stored MIME type is a verified safe raster image.
func (s *Server) handleChatDownloadAttachment(w http.ResponseWriter, r *http.Request) {
	if s.blobs == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Attachment storage unavailable")
		return
	}
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	attID := strings.TrimSpace(r.PathValue("id"))
	if !blobs.ValidKey(attID) {
		s.writeError(w, http.StatusNotFound, "Attachment not found")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}

	att, err := s.store.Chat().GetAttachment(r.Context(), tenantID, attID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Attachment not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to load attachment")
		return
	}

	if _, err := s.store.Chat().GetRoomMember(r.Context(), tenantID, att.RoomID, user.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Attachment not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to verify room membership")
		return
	}

	// Unattached (staged) uploads are private to the uploader until posted in a message.
	if att.MessageID == "" {
		if att.UploaderID != user.ID {
			s.writeError(w, http.StatusNotFound, "Attachment not found")
			return
		}
	} else {
		msg, err := s.store.Chat().GetMessage(r.Context(), tenantID, att.RoomID, att.MessageID)
		if err != nil || msg.DeletedAt != nil {
			s.writeError(w, http.StatusNotFound, "Attachment not found")
			return
		}
	}

	f, _, err := s.blobs.Open(att.TenantID, att.BlobKey)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, blobs.ErrInvalidKey) {
			s.writeError(w, http.StatusNotFound, "Attachment not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to open attachment")
		return
	}
	defer f.Close()

	safeMIME := blobs.SafeServeMIME(att.MimeType)
	dispositionType := "attachment"
	if r.URL.Query().Get("inline") == "1" && blobs.IsInlineSafeImage(safeMIME) {
		dispositionType = "inline"
	}
	disposition := mime.FormatMediaType(dispositionType, map[string]string{
		"filename": blobs.SanitizeFilename(att.Filename),
	})
	if disposition == "" {
		disposition = dispositionType
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", safeMIME)
	w.Header().Set("Content-Disposition", disposition)

	modTime := time.UnixMilli(att.CreatedAt).UTC()
	http.ServeContent(w, r, blobs.SanitizeFilename(att.Filename), modTime, f)
}

// GET /api/v1/rooms/{id}/attachments
// Lists the caller's own staged uploads in a room they belong to, so a reloaded composer can
// show, send or remove what still counts against their pending quota.
func (s *Server) handleChatListStagedAttachments(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	roomID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.store.Chat().GetRoomMember(r.Context(), tenantID, roomID, user.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Room not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to verify room membership")
		return
	}
	list, err := s.store.Chat().ListStagedAttachments(r.Context(), tenantID, roomID, user.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list attachments")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]any{"attachments": list})
}

// DELETE /api/v1/attachments/{id}
// Allows an uploader to discard an unposted (staged) attachment before sending a message,
// freeing both the database row and disk blob immediately.
func (s *Server) handleChatDeleteAttachment(w http.ResponseWriter, r *http.Request) {
	if s.blobs == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Attachment storage unavailable")
		return
	}
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	attID := strings.TrimSpace(r.PathValue("id"))
	if !blobs.ValidKey(attID) {
		s.writeError(w, http.StatusNotFound, "Attachment not found")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	blobKey, err := s.store.Chat().DeleteStagedAttachment(r.Context(), tenantID, attID, user.ID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			s.writeError(w, http.StatusNotFound, "Attachment not found")
		case errors.Is(err, store.ErrAttachmentInvalid):
			s.writeError(w, http.StatusConflict, "Attachment is already attached to a message")
		default:
			s.writeError(w, http.StatusInternalServerError, "Failed to delete attachment")
		}
		return
	}
	_ = s.blobs.Delete(tenantID, blobKey)
	w.WriteHeader(http.StatusNoContent)
}

// SweepOrphanAttachments removes expired unposted (staged) attachments from the database
// and local blob store, along with stale crashed .upload-* temp files.
func (s *Server) SweepOrphanAttachments(ctx context.Context, now time.Time) (int, error) {
	if s.blobs == nil {
		return 0, nil
	}
	if err := s.relocateFlatBlobs(ctx); err != nil && ctx.Err() == nil {
		log.Printf("[ATTACHMENTS] flat blob relocation incomplete (retrying next sweep): %v", err)
	}
	if s.config.Tenancy.IsMultiTenant() {
		if err := s.drainPendingBlobDeletes(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[ATTACHMENTS] queued blob deletes incomplete (retrying next sweep): %v", err)
		}
	}
	cutoff := now.Add(-s.pendingAttachmentTTL()).UnixMilli()
	deleted := 0
	for {
		keys, err := s.store.Chat().PurgeOrphanAttachments(ctx, cutoff, 200)
		if err != nil {
			return deleted, err
		}
		for _, key := range keys {
			_ = s.blobs.Delete(key.TenantID, key.Key)
			deleted++
		}
		if len(keys) < 200 {
			break
		}
	}
	s.blobs.SweepStaleTemps(time.Hour)
	return deleted, nil
}

// sharedBlobVolume makes a multi-mode store prove it is the volume every replica shares.
func sharedBlobVolume(st store.Store, bs *blobs.Store) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return bs.EnsureStoreID(func(id string) (string, error) {
		return st.Settings().SetSettingOnce(ctx, "blobs.store_id", id)
	})
}

// relocateFlatBlobs moves blobs stored flat (written before the org layout, or by a replica of
// an older build during a rolling upgrade) to their org paths. It runs on every attachment
// sweep, under that job's lease; a flat file is cheap to find (the directory's top level), and
// reads find it meanwhile through the flat fallback. A file with no attachment row (an upload
// still committing, or an orphan) is left alone.
func (s *Server) relocateFlatBlobs(ctx context.Context) error {
	disk, ok := s.blobs.(*blobs.Store)
	if !ok || !disk.OrgLayout() {
		return nil
	}
	keys, err := disk.FlatKeys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		tenantID, err := s.store.Chat().AttachmentTenant(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		// A row whose org is not a valid name was never servable; skip it.
		if err := disk.Relocate(tenantID, key); err != nil && !errors.Is(err, blobs.ErrInvalidKey) {
			return err
		}
	}
	return nil
}

// eraseUser deletes one person's data for user.erased. First the account stops serving and
// loses every grant, then its sockets, calls and bots are disconnected, so nothing admitted
// later can recreate access. Then the blobs go, then the rows (store.EraseUser), whose returned
// blobs (an upload that committed meanwhile) go too, and a last disconnect catches a call joined
// in between. A failure part way leaves rows naming every blob still there, and the retried
// delivery finishes the job.
func (s *Server) eraseUser(ctx context.Context, user *store.User, revoke func(context.Context, string)) error {
	if err := s.store.Chat().DeactivateForErasure(ctx, user.OrgID, user.ID); err != nil {
		return err
	}
	if err := s.store.Sessions().DeleteUserSessions(ctx, user.ID); err != nil {
		return err
	}
	revoke(ctx, user.ID)
	refs, err := s.store.Chat().ErasureBlobs(ctx, user.OrgID, user.ID)
	if err != nil {
		return err
	}
	if err := s.deleteBlobs(refs); err != nil {
		return err
	}
	late, err := s.store.Chat().EraseUser(ctx, user.OrgID, user)
	if err != nil {
		return err
	}
	revoke(ctx, user.ID)
	// EraseUser queued these; a failure here leaves them for the attachment sweep.
	if err := s.deleteBlobs(late); err != nil {
		return err
	}
	return s.store.Chat().ClearPendingBlobDeletes(ctx, append(refs, late...))
}

// drainPendingBlobDeletes finishes blob deletes an erasure committed but could not complete.
// Each entry is tried on its own: successes are cleared, failures stay queued, and the batch is
// a random sample, so a blob that keeps failing cannot hold back the others.
func (s *Server) drainPendingBlobDeletes(ctx context.Context) error {
	refs, err := s.store.Chat().PendingBlobDeletes(ctx, 500)
	if err != nil || len(refs) == 0 || s.blobs == nil {
		return err
	}
	var done []store.BlobRef
	var failed []error
	for _, ref := range refs {
		if err := s.blobs.Delete(ref.TenantID, ref.Key); err != nil && !errors.Is(err, blobs.ErrInvalidKey) {
			failed = append(failed, err)
			continue
		}
		done = append(done, ref)
	}
	return errors.Join(append(failed, s.store.Chat().ClearPendingBlobDeletes(ctx, done))...)
}

func (s *Server) deleteBlobs(refs []store.BlobRef) error {
	if s.blobs == nil {
		return nil
	}
	for _, ref := range refs {
		if err := s.blobs.Delete(ref.TenantID, ref.Key); err != nil && !errors.Is(err, blobs.ErrInvalidKey) {
			return err
		}
	}
	return nil
}

// PurgeDeletedOrgs deletes the data of every deleted org not purged yet (multi mode): attachment
// blobs then their rows, in batches, then the org's prefix (orphans included), then every other
// row. held re-checks the job's lease before each batch; when it fails the purge stops, so two
// replicas never purge the same batch. An interrupted purge resumes on the next run.
func (s *Server) PurgeDeletedOrgs(ctx context.Context, held func() bool) error {
	if !s.config.Tenancy.IsMultiTenant() || s.store == nil {
		return nil
	}
	chat := s.store.Chat()
	ids, err := chat.DeletedUnpurgedTenants(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		for {
			if !held() {
				return nil
			}
			refs, err := chat.PurgeAttachmentBatch(ctx, id, 200)
			if err != nil {
				return err
			}
			if len(refs) == 0 {
				break
			}
			if s.blobs != nil {
				for _, ref := range refs {
					if err := s.blobs.Delete(ref.TenantID, ref.Key); err != nil && !errors.Is(err, blobs.ErrInvalidKey) {
						return err
					}
				}
			}
			if err := chat.DeleteAttachmentRows(ctx, id, refs); err != nil {
				return err
			}
		}
		if !held() {
			return nil
		}
		// Rows first (under the upload commit's lock, so no commit lands after), then the whole
		// prefix, which also takes any blob an in-flight upload wrote, then the purged mark.
		if err := chat.PurgeTenantRows(ctx, id); err != nil {
			return err
		}
		if s.blobs != nil {
			if err := s.blobs.DeletePrefix(id); err != nil && !errors.Is(err, blobs.ErrInvalidKey) {
				return err
			}
		}
		if err := chat.MarkTenantPurged(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// SyncTenancy is the leased tenancy-sync job's tick: incremental, or full once a day.
func (s *Server) SyncTenancy(ctx context.Context, _ time.Time) error {
	if !s.config.Tenancy.IsMultiTenant() {
		return nil
	}
	return s.kyidentity.SyncTenancy(ctx, s.kyidentity.FullSyncDue(ctx), false)
}

// StartupTenancySync is the full read every multi-mode replica makes before it serves.
func (s *Server) StartupTenancySync(ctx context.Context) error {
	return s.kyidentity.StartupSync(ctx)
}
