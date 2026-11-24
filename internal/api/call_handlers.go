package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Busnes-app/ky_server_base/internal/chat"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// GET /api/v1/rooms/{id}/calls/state
func (s *Server) handleCallState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	roomID := r.PathValue("id")
	if _, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID); !ok {
		return
	}
	if s.config.Tenancy.IsMultiTenant() {
		room, err := s.store.Chat().GetRoom(r.Context(), tenantID, roomID)
		if err != nil {
			s.writeError(w, http.StatusServiceUnavailable, "Call state is temporarily unavailable")
			return
		}
		if room.ClosedAt != nil {
			s.writeJSON(w, http.StatusOK, map[string]any{"call": nil, "sfu_available": s.calls.SFUAvailable(), "ice_servers": s.calls.ICEServers()})
			return
		}
	}
	if !s.requireCallOwner(w, r, tenantID, roomID) {
		return
	}
	state := s.calls.GetState(roomID)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"call":          state,
		"sfu_available": s.calls.SFUAvailable(),
		"ice_servers":   s.calls.ICEServers(),
	})
}

// POST /api/v1/rooms/{id}/calls/join
func (s *Server) handleCallJoin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, sess, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if user.Role == "bot" {
		s.writeError(w, http.StatusForbidden, "Bot accounts cannot join calls")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	roomID := r.PathValue("id")
	if _, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID); !ok {
		return
	}
	if s.config.Tenancy.IsMultiTenant() && user.Role != "user" {
		s.writeError(w, http.StatusForbidden, "Member account required")
		return
	}
	room, err := s.store.Chat().GetRoom(r.Context(), tenantID, roomID)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Room not found")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load room")
		return
	}
	if room.ClosedAt != nil {
		s.writeError(w, http.StatusConflict, "This room is closed")
		return
	}

	var body struct {
		Audio       *bool           `json:"audio"`
		Video       bool            `json:"video"`
		ScreenShare bool            `json:"screen_share"`
		ProtectIP   bool            `json:"protect_ip"`
		ECDHPubJWK  json.RawMessage `json:"ecdh_pub_jwk"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	audio := true
	if body.Audio != nil {
		audio = *body.Audio
	}

	if !s.requireCallOwner(w, r, tenantID, roomID) {
		return
	}
	resp, err := s.calls.Join(r.Context(), chat.JoinCallRequest{
		TenantID:    tenantID,
		SessionHash: sess.TokenHash,
		RoomID:      roomID,
		UserID:      user.ID,
		DisplayName: displayNameFor(user),
		IsGuest:     false,
		Audio:       audio,
		Video:       body.Video,
		ScreenShare: body.ScreenShare,
		ProtectIP:   body.ProtectIP,
		ECDHPubJWK:  body.ECDHPubJWK,
	})
	if err != nil && s.config.Tenancy.IsMultiTenant() {
		valid, checkErr := chatSessionValid(r.Context(), s.store, user.ID, sess.TokenHash)
		if checkErr == nil && !valid {
			s.writeError(w, http.StatusUnauthorized, "Authentication required")
			return
		}
		if checkErr != nil {
			s.writeError(w, http.StatusServiceUnavailable, "Call admission is temporarily unavailable")
			return
		}
	}
	if errors.Is(err, store.ErrCallOwnerLost) || errors.Is(err, store.ErrCallCleanupPending) || errors.Is(err, store.ErrCallStateStale) {
		w.Header().Set("Retry-After", "1")
		s.writeError(w, http.StatusServiceUnavailable, "Call control is temporarily unavailable; retry")
		return
	}
	if errors.Is(err, chat.ErrCallSeatLost) {
		s.writeError(w, http.StatusConflict, "The call seat ended while joining; join again")
		return
	}
	if errors.Is(err, chat.ErrTenantInactive) {
		s.writeError(w, http.StatusForbidden, "Organization is suspended or inactive")
		return
	}
	if errors.Is(err, chat.ErrSFUUnavailable) {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "LiveKit SFU is required for this call policy or IP privacy setting, but LiveKit is not configured on this server",
			"code":  "sfu_unavailable",
		})
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to join call")
		return
	}
	// Multi mode: an erasure (or any deactivation) that landed while this join was in flight
	// gets no seat and no credentials. Erasure deactivates before its final disconnect, so a
	// join either sees the deactivation here or registered early enough for that disconnect.
	if s.config.Tenancy.IsMultiTenant() {
		if fresh, err := s.store.Users().GetUserByID(r.Context(), user.ID); err != nil || fresh.Status != "active" {
			s.calls.Leave(context.WithoutCancel(r.Context()), roomID, user.ID)
			s.writeError(w, http.StatusUnauthorized, "Authentication required")
			return
		}
	}
	if resp.Started {
		starter := displayNameFor(user)
		s.pushAsync(r.Context(), func(ctx context.Context) {
			s.dispatchCallPush(ctx, tenantID, roomID, user.ID, starter)
		})
	}
	if s.config.Tenancy.IsMultiTenant() {
		resp.CallWSPath = "/api/v1/rooms/" + url.PathEscape(roomID) + "/calls/ws"
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// POST /api/v1/rooms/{id}/calls/leave
func (s *Server) handleCallLeave(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	roomID := r.PathValue("id")
	if _, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID); !ok {
		return
	}
	if !s.requireCallOwner(w, r, tenantID, roomID) {
		return
	}
	if err := s.calls.LeaveCall(r.Context(), roomID, user.ID); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Call departure cleanup is pending; retry")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"left": true})
}

// POST /api/v1/rooms/{id}/calls/escalate
func (s *Server) handleCallEscalate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	roomID := r.PathValue("id")
	if _, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID); !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if !s.requireCallOwner(w, r, tenantID, roomID) {
		return
	}
	state, err := s.calls.ForceEscalate(r.Context(), roomID, user.ID, strings.TrimSpace(body.Reason))
	switch {
	case errors.Is(err, chat.ErrCallNotActive):
		s.writeError(w, http.StatusNotFound, "No active call in this room")
	case errors.Is(err, store.ErrForbidden):
		s.writeError(w, http.StatusForbidden, "Join the call before escalating")
	case errors.Is(err, chat.ErrSFUUnavailable):
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "LiveKit SFU is not configured on this server",
			"code":  "sfu_unavailable",
		})
	case errors.Is(err, store.ErrCallOwnerLost), errors.Is(err, store.ErrCallCleanupPending), errors.Is(err, store.ErrCallStateStale):
		w.Header().Set("Retry-After", "1")
		s.writeError(w, http.StatusServiceUnavailable, "Call control is temporarily unavailable; retry")
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to escalate call")
	default:
		s.writeJSON(w, http.StatusOK, map[string]any{"call": state})
	}
}

// GET /api/v1/rooms/{id}/lobby
func (s *Server) handleRoomLobbyList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	roomID := r.PathValue("id")
	if _, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID); !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"guests": s.lobby.ListWaiting(roomID),
	})
}

// POST /api/v1/rooms/{id}/lobby/{gid}/admit
func (s *Server) handleRoomLobbyAdmit(w http.ResponseWriter, r *http.Request) {
	s.handleRoomLobbyDecide(w, r, true)
}

// POST /api/v1/rooms/{id}/lobby/{gid}/deny
func (s *Server) handleRoomLobbyDeny(w http.ResponseWriter, r *http.Request) {
	s.handleRoomLobbyDecide(w, r, false)
}

func (s *Server) handleRoomLobbyDecide(w http.ResponseWriter, r *http.Request, admit bool) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	roomID := r.PathValue("id")
	guestID := r.PathValue("gid")
	if _, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID); !ok {
		return
	}
	sess, err := s.lobby.Decide(r.Context(), roomID, guestID, user.ID, admit)
	if errors.Is(err, chat.ErrGuestNotFound) {
		s.writeError(w, http.StatusNotFound, "Waiting guest not found")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to update lobby decision")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"guest": sess})
}

// GET /api/admin/media-policy
func (s *Server) handleAdminGetMediaPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	tenant, err := s.store.Chat().GetTenant(r.Context(), tenantID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load tenant media policy")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"policy": map[string]any{
			"p2p_policy":      tenant.P2PPolicy,
			"p2p_max_video":   tenant.P2PMaxVideo,
			"p2p_max_audio":   tenant.P2PMaxAudio,
			"guest_force_sfu": tenant.GuestForceSFU,
		},
		"rtc": map[string]any{
			"sfu_available": s.calls.SFUAvailable(),
			"livekit_url":   s.calls.LiveKitURL(),
			"stun_urls":     s.config.RTC.STUNURLs,
		},
		"stats": s.calls.Stats(),
	})
}

// PUT /api/admin/media-policy
func (s *Server) handleAdminUpdateMediaPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	var req struct {
		P2PPolicy     string `json:"p2p_policy"`
		P2PMaxVideo   int    `json:"p2p_max_video"`
		P2PMaxAudio   int    `json:"p2p_max_audio"`
		GuestForceSFU bool   `json:"guest_force_sfu"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if req.P2PPolicy != store.P2PPolicyHybrid && req.P2PPolicy != store.P2PPolicySFUOnly {
		s.writeError(w, http.StatusBadRequest, "p2p_policy must be 'hybrid' or 'sfu_only'")
		return
	}
	if req.P2PMaxVideo < 2 || req.P2PMaxVideo > 6 {
		s.writeError(w, http.StatusBadRequest, "p2p_max_video must be between 2 and 6")
		return
	}
	if req.P2PMaxAudio < 2 || req.P2PMaxAudio > 8 {
		s.writeError(w, http.StatusBadRequest, "p2p_max_audio must be between 2 and 8")
		return
	}
	updated, err := s.store.Chat().UpdateTenantMediaPolicy(
		r.Context(),
		tenantID,
		req.P2PPolicy,
		req.P2PMaxVideo,
		req.P2PMaxAudio,
		req.GuestForceSFU,
	)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to update media policy")
		return
	}
	s.audit(r.Context(), user.ID, r, "admin.media_policy_updated", "tenant:"+updated.ID, updated.P2PPolicy)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"policy": map[string]any{
			"p2p_policy":      updated.P2PPolicy,
			"p2p_max_video":   updated.P2PMaxVideo,
			"p2p_max_audio":   updated.P2PMaxAudio,
			"guest_force_sfu": updated.GuestForceSFU,
		},
	})
}

// Owner contention is retryable without exposing internal replica addresses or permitting
// a second call. The edge hashes the room segment identically for HTTP and WebSocket.
func (s *Server) requireCallOwner(w http.ResponseWriter, r *http.Request, tenant, room string) bool {
	if !s.config.Tenancy.IsMultiTenant() {
		return true
	}
	if err := s.calls.ClaimRoom(r.Context(), tenant, room); err != nil {
		w.Header().Set("Retry-After", "1")
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Call room is temporarily unavailable; retry through its room route", "code": "call_owner_unavailable"})
		return false
	}
	return true
}
