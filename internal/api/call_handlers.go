package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
	user, _, ok := s.currentUser(r)
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

	resp, err := s.calls.Join(r.Context(), chat.JoinCallRequest{
		TenantID:    tenantID,
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
	if resp.Started {
		starter := displayNameFor(user)
		s.pushAsync(r.Context(), func(ctx context.Context) {
			s.dispatchCallPush(ctx, tenantID, roomID, user.ID, starter)
		})
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
	s.calls.Leave(r.Context(), roomID, user.ID)
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
