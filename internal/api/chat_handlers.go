package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/chat"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

const (
	maxRoomNameLen    = 100
	maxRoomTopicLen   = 500
	maxMessageBodyLen = 16 << 10 // 16 KiB
	maxEmojiLen       = 32
	maxSearchQueryLen = 200
	// The column is VARCHAR(128) on Postgres.
	maxIdempotencyKeyLen = 128
)

func (s *Server) currentUser(r *http.Request) (*store.User, *store.Session, bool) {
	user, sess, err := s.sessions.AuthenticateRequest(r)
	if err != nil {
		return nil, nil, false
	}
	return user, sess, true
}

func displayNameFor(u *store.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
}

// Per-user chat limits per minute. Rooms covers what reaches other users' room
// lists: creating rooms and DMs, adding members, renaming, creating webhooks.
var (
	chatLimitRooms  = chatLimit{"chat-rooms:", 30}
	chatLimitWrites = chatLimit{"chat-writes:", 240}
)

type chatLimit struct {
	scope     string
	perMinute int
}

// allowChatAction counts one action against the user's limit, writing 429 when it is spent.
func (s *Server) allowChatAction(w http.ResponseWriter, userID string, l chatLimit) bool {
	if s.allowAccountAttempt(l.scope+userID, l.perMinute, time.Minute) {
		return true
	}
	w.Header().Set("Retry-After", "60")
	s.writeError(w, http.StatusTooManyRequests, "Too many chat actions; try again shortly")
	return false
}

// activeChatUser loads a user who can be put in a room within tenantID. A suspended,
// deleted, or cross-organization account reads as not found, like an unknown ID.
func (s *Server) activeChatUser(ctx context.Context, tenantID, id string) (*store.User, error) {
	u, err := s.store.Users().GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if u.Status != "active" {
		return nil, store.ErrNotFound
	}
	if s.config.Tenancy.IsMultiTenant() && u.OrgID != tenantID {
		return nil, store.ErrNotFound
	}
	return u, nil
}

func isRoomModerator(member *store.RoomMember, user *store.User) bool {
	if user != nil && user.Role == "admin" {
		return true
	}
	return member != nil && (member.Role == store.RoomRoleOwner || member.Role == store.RoomRoleAdmin)
}

func (s *Server) requireRoomMember(w http.ResponseWriter, r *http.Request, tenantID, roomID, userID string) (*store.RoomMember, bool) {
	m, err := s.store.Chat().GetRoomMember(r.Context(), tenantID, roomID, userID)
	if errors.Is(err, store.ErrNotFound) {
		// Return 404 (not 403) so non-members cannot enumerate room IDs.
		s.writeError(w, http.StatusNotFound, "Room not found")
		return nil, false
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to verify room membership")
		return nil, false
	}
	return m, true
}

type chatDirectoryUser struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role,omitempty"`
}

func (s *Server) resolveDMRoomNames(r *http.Request, tenantID, selfID string, rooms []*store.RoomSummary) {
	ctx := r.Context()
	for _, rm := range rooms {
		if rm.Kind != store.RoomKindDM || rm.Name != "" {
			continue
		}
		members, err := s.store.Chat().ListRoomMembers(ctx, tenantID, rm.ID)
		if err != nil {
			continue
		}
		peerID := selfID
		for _, m := range members {
			if m.UserID != selfID {
				peerID = m.UserID
				break
			}
		}
		if peer, err := s.store.Users().GetUserByID(ctx, peerID); err == nil {
			rm.Name = displayNameFor(peer)
		}
	}
}

// GET /api/v1/bootstrap
func (s *Server) handleChatBootstrap(w http.ResponseWriter, r *http.Request) {
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
		s.writeError(w, http.StatusInternalServerError, "Failed to load tenant")
		return
	}
	rooms, err := s.store.Chat().ListUserRooms(r.Context(), tenantID, user.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load rooms")
		return
	}
	s.resolveDMRoomNames(r, tenantID, user.ID, rooms)
	activeCalls := make(map[string]*chat.CallStatePayload)
	if s.calls != nil {
		for _, rm := range rooms {
			if st := s.calls.GetState(rm.ID); st != nil {
				activeCalls[rm.ID] = st
			}
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"user":         user,
		"tenant":       tenant,
		"rooms":        rooms,
		"active_calls": activeCalls,
		"rtc": map[string]any{
			"sfu_available": s.calls != nil && s.calls.SFUAvailable(),
			"ice_servers":   s.calls.ICEServers(),
		},
		"attachments": map[string]any{
			"available":        s.blobs != nil,
			"max_upload_bytes": s.maxUploadBytes(),
			"max_per_message":  maxAttachmentsPerMessage,
		},
		"push": map[string]any{
			"available":        s.push != nil,
			"vapid_public_key": s.PushVAPIDPublicKey(),
		},
	})
}

// GET /api/v1/users
func (s *Server) handleChatListUsers(w http.ResponseWriter, r *http.Request) {
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
	filter := store.UserFilter{}
	if s.config.Tenancy.IsMultiTenant() {
		filter.OrgID = tenantID
	}
	users, _, err := s.store.Users().ListUsers(r.Context(), 0, 500, filter)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list directory")
		return
	}
	dir := make([]chatDirectoryUser, 0, len(users))
	for _, u := range users {
		if u.Status != "" && u.Status != "active" {
			continue
		}
		dir = append(dir, chatDirectoryUser{
			ID:          u.ID,
			Username:    u.Username,
			DisplayName: displayNameFor(u),
			Role:        u.Role,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"users": dir})
}

// GET /api/v1/rooms
func (s *Server) handleChatListRooms(w http.ResponseWriter, r *http.Request) {
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
	rooms, err := s.store.Chat().ListUserRooms(r.Context(), tenantID, user.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load rooms")
		return
	}
	s.resolveDMRoomNames(r, tenantID, user.ID, rooms)
	s.writeJSON(w, http.StatusOK, map[string]any{"rooms": rooms})
}

type createRoomRequest struct {
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Topic     string   `json:"topic"`
	IsPrivate bool     `json:"is_private"`
	MemberIDs []string `json:"member_ids"`
	DMUserID  string   `json:"dm_user_id"`
}

// POST /api/v1/rooms
func (s *Server) handleChatCreateRoom(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if user.Role == "bot" {
		s.writeError(w, http.StatusForbidden, "Bot accounts cannot create rooms")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	if !s.allowChatAction(w, user.ID, chatLimitRooms) {
		return
	}
	var req createRoomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	kind := strings.TrimSpace(req.Kind)
	if kind == "" {
		kind = store.RoomKindChannel
	}

	switch kind {
	case store.RoomKindDM:
		targetID := strings.TrimSpace(req.DMUserID)
		if targetID == "" {
			s.writeError(w, http.StatusBadRequest, "dm_user_id is required for DM rooms")
			return
		}
		if _, err := s.activeChatUser(r.Context(), tenantID, targetID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				s.writeError(w, http.StatusNotFound, "Target user not found")
				return
			}
			s.writeError(w, http.StatusInternalServerError, "Failed to verify target user")
			return
		}
		room, created, err := s.store.Chat().GetOrCreateDM(r.Context(), tenantID, user.ID, targetID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to create DM")
			return
		}
		if created {
			for _, uid := range []string{user.ID, targetID} {
				_ = s.chatHub.PublishRoom(r.Context(), room.ID, chat.Event{
					Type:   chat.EventRoomMember,
					RoomID: room.ID,
					Data:   chat.MustMarshalData(chat.RoomMemberDelta{Action: "added", UserID: uid, Role: store.RoomRoleMember}),
				})
			}
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		s.writeJSON(w, status, map[string]any{"room": room, "created": created})

	case store.RoomKindChannel:
		name := strings.TrimSpace(req.Name)
		topic := strings.TrimSpace(req.Topic)
		if name == "" || len(name) > maxRoomNameLen {
			s.writeError(w, http.StatusBadRequest, "Room name must be 1 to 100 characters")
			return
		}
		if len(topic) > maxRoomTopicLen {
			s.writeError(w, http.StatusBadRequest, "Room topic must be at most 500 characters")
			return
		}
		validMembers := make([]string, 0, len(req.MemberIDs))
		for _, uid := range req.MemberIDs {
			uid = strings.TrimSpace(uid)
			if uid == "" || uid == user.ID {
				continue
			}
			if _, err := s.activeChatUser(r.Context(), tenantID, uid); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					s.writeError(w, http.StatusBadRequest, "Unknown member user_id")
					return
				}
				s.writeError(w, http.StatusInternalServerError, "Failed to validate member")
				return
			}
			validMembers = append(validMembers, uid)
		}

		room := &store.Room{
			TenantID:  tenantID,
			Kind:      store.RoomKindChannel,
			Name:      name,
			Topic:     topic,
			IsPrivate: req.IsPrivate,
			CreatedBy: user.ID,
		}
		if err := s.store.Chat().CreateRoom(r.Context(), room, validMembers); err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to create room")
			return
		}

		// Subscribe creator and initial members on all pods immediately.
		_ = s.chatHub.PublishRoom(r.Context(), room.ID, chat.Event{
			Type:   chat.EventRoomMember,
			RoomID: room.ID,
			Data:   chat.MustMarshalData(chat.RoomMemberDelta{Action: "added", UserID: user.ID, Role: store.RoomRoleOwner}),
		})
		for _, uid := range validMembers {
			_ = s.chatHub.PublishRoom(r.Context(), room.ID, chat.Event{
				Type:   chat.EventRoomMember,
				RoomID: room.ID,
				Data:   chat.MustMarshalData(chat.RoomMemberDelta{Action: "added", UserID: uid, Role: store.RoomRoleMember}),
			})
		}

		s.writeJSON(w, http.StatusCreated, map[string]any{"room": room})

	default:
		s.writeError(w, http.StatusBadRequest, "Unsupported room kind")
	}
}

// GET /api/v1/rooms/{id}
func (s *Server) handleChatGetRoom(w http.ResponseWriter, r *http.Request) {
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

	member, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID)
	if !ok {
		return
	}
	room, err := s.store.Chat().GetRoom(r.Context(), tenantID, roomID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Room not found")
		return
	}
	members, err := s.store.Chat().ListRoomMembers(r.Context(), tenantID, roomID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list room members")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"room":    room,
		"member":  member,
		"members": members,
	})
}

type updateRoomRequest struct {
	Name  string `json:"name"`
	Topic string `json:"topic"`
}

// PATCH /api/v1/rooms/{id}
func (s *Server) handleChatUpdateRoom(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	if !s.allowChatAction(w, user.ID, chatLimitRooms) {
		return
	}
	roomID := r.PathValue("id")

	member, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID)
	if !ok {
		return
	}
	if !isRoomModerator(member, user) {
		s.writeError(w, http.StatusForbidden, "Room moderator role required")
		return
	}
	var req updateRoomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	name := strings.TrimSpace(req.Name)
	topic := strings.TrimSpace(req.Topic)
	if name == "" || len(name) > maxRoomNameLen {
		s.writeError(w, http.StatusBadRequest, "Room name must be 1 to 100 characters")
		return
	}
	if len(topic) > maxRoomTopicLen {
		s.writeError(w, http.StatusBadRequest, "Room topic must be at most 500 characters")
		return
	}

	room, err := s.store.Chat().UpdateRoom(r.Context(), tenantID, roomID, name, topic)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to update room")
		return
	}
	_ = s.chatHub.PublishRoom(r.Context(), roomID, chat.Event{
		Type:   chat.EventRoomUpdated,
		RoomID: roomID,
		Data:   chat.MustMarshalData(room),
	})
	s.writeJSON(w, http.StatusOK, map[string]any{"room": room})
}

type addMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// POST /api/v1/rooms/{id}/members
func (s *Server) handleChatAddMember(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	if !s.allowChatAction(w, user.ID, chatLimitRooms) {
		return
	}
	roomID := r.PathValue("id")

	actorMember, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID)
	if !ok {
		return
	}
	if !isRoomModerator(actorMember, user) {
		s.writeError(w, http.StatusForbidden, "Room moderator role required")
		return
	}
	room, err := s.store.Chat().GetRoom(r.Context(), tenantID, roomID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Room not found")
		return
	}
	if room.Kind == store.RoomKindDM {
		s.writeError(w, http.StatusBadRequest, "Cannot add members to a direct message")
		return
	}

	var req addMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	targetID := strings.TrimSpace(req.UserID)
	if targetID == "" {
		s.writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = store.RoomRoleMember
	}
	if role != store.RoomRoleMember && role != store.RoomRoleAdmin {
		s.writeError(w, http.StatusBadRequest, "role must be member or admin")
		return
	}
	if _, err := s.activeChatUser(r.Context(), tenantID, targetID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Target user not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to verify user")
		return
	}

	member := &store.RoomMember{
		TenantID: tenantID,
		RoomID:   roomID,
		UserID:   targetID,
		Role:     role,
	}
	if err := s.store.Chat().AddRoomMember(r.Context(), member); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			s.writeError(w, http.StatusConflict, "User is already a member")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to add member")
		return
	}

	_ = s.chatHub.PublishRoom(r.Context(), roomID, chat.Event{
		Type:   chat.EventRoomMember,
		RoomID: roomID,
		Data:   chat.MustMarshalData(chat.RoomMemberDelta{Action: "added", UserID: targetID, Role: role}),
	})
	s.writeJSON(w, http.StatusCreated, map[string]any{"member": member})
}

// DELETE /api/v1/rooms/{id}/members/{uid}
func (s *Server) handleChatRemoveMember(w http.ResponseWriter, r *http.Request) {
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
	targetID := r.PathValue("uid")

	actorMember, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID)
	if !ok {
		return
	}
	if targetID != user.ID && !isRoomModerator(actorMember, user) {
		s.writeError(w, http.StatusForbidden, "Room moderator role required to remove other members")
		return
	}
	room, err := s.store.Chat().GetRoom(r.Context(), tenantID, roomID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Room not found")
		return
	}
	if room.Kind == store.RoomKindDM {
		s.writeError(w, http.StatusBadRequest, "Cannot remove members from a direct message")
		return
	}

	promoted, err := s.store.Chat().RemoveRoomMember(r.Context(), tenantID, roomID, targetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Member not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to remove member")
		return
	}

	if s.calls != nil {
		s.calls.Leave(r.Context(), roomID, targetID)
	}
	_ = s.chatHub.PublishRoom(r.Context(), roomID, chat.Event{
		Type:   chat.EventRoomMember,
		RoomID: roomID,
		Data:   chat.MustMarshalData(chat.RoomMemberDelta{Action: "removed", UserID: targetID}),
	})
	if promoted != "" {
		_ = s.chatHub.PublishRoom(r.Context(), roomID, chat.Event{
			Type:   chat.EventRoomMember,
			RoomID: roomID,
			Data:   chat.MustMarshalData(chat.RoomMemberDelta{Action: "role", UserID: promoted, Role: store.RoomRoleOwner}),
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"removed": true})
}

// GET /api/v1/rooms/{id}/messages?before=&after=&limit=
// POST /api/v1/messages/state {ids} answers, for up to 50 message IDs, which ones the caller
// can still read and when each was last edited. On-device search checks its hits with it, so a
// message deleted, edited or left behind while this browser was away is never shown.
func (s *Server) handleChatMessageStates(w http.ResponseWriter, r *http.Request) {
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
		IDs []string `json:"ids"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.IDs) == 0 || len(req.IDs) > 50 {
		s.writeError(w, http.StatusBadRequest, "Name 1 to 50 message IDs")
		return
	}
	states, err := s.store.Chat().MessageStates(r.Context(), tenantID, user.ID, req.IDs)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to check messages")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"messages": states})
}

func (s *Server) handleChatListMessages(w http.ResponseWriter, r *http.Request) {
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

	q := store.MessagePageQuery{
		TenantID: tenantID,
		RoomID:   roomID,
		Limit:    50,
	}
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			s.writeError(w, http.StatusBadRequest, "Invalid before cursor")
			return
		}
		q.BeforeSeq = n
	}
	if v := r.URL.Query().Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			s.writeError(w, http.StatusBadRequest, "Invalid after cursor")
			return
		}
		q.AfterSeq = n
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			s.writeError(w, http.StatusBadRequest, "limit must be between 1 and 100")
			return
		}
		q.Limit = n
	}

	msgs, hasMore, err := s.store.Chat().ListMessages(r.Context(), q)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list messages")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"messages": msgs,
		"has_more": hasMore,
	})
}

type sendMessageRequest struct {
	Body           string   `json:"body"`
	ReplyToID      string   `json:"reply_to_id"`
	Encoding       string   `json:"encoding"`
	IdempotencyKey string   `json:"idempotency_key"`
	AttachmentIDs  []string `json:"attachment_ids"`
}

// POST /api/v1/rooms/{id}/messages
func (s *Server) handleChatSendMessage(w http.ResponseWriter, r *http.Request) {
	user, sess, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	if !s.allowChatAction(w, user.ID, chatLimitWrites) {
		return
	}
	roomID := r.PathValue("id")

	var req sendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	attIDs := make([]string, 0, len(req.AttachmentIDs))
	seenAtt := make(map[string]struct{}, len(req.AttachmentIDs))
	for _, rawID := range req.AttachmentIDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			continue
		}
		if _, dup := seenAtt[id]; dup {
			continue
		}
		seenAtt[id] = struct{}{}
		attIDs = append(attIDs, id)
	}
	if len(attIDs) > maxAttachmentIDsPerMessage {
		s.writeError(w, http.StatusBadRequest, "At most 10 files (and their thumbnails) per message")
		return
	}
	body := strings.TrimSpace(req.Body)
	if body == "" && len(attIDs) == 0 {
		s.writeError(w, http.StatusBadRequest, "Message body must be 1 to 16384 bytes (or include at least one attachment)")
		return
	}
	encoding, err := s.messageEncoding(w, user, sess, req.Encoding, body)
	if err != nil {
		return
	}
	// Only encrypted messages carry thumbnails as attachments of their own.
	if encoding == store.MessageEncodingPlainV1 && len(attIDs) > maxAttachmentsPerMessage {
		s.writeError(w, http.StatusBadRequest, "At most 10 attachments per message")
		return
	}
	idemKey := strings.TrimSpace(req.IdempotencyKey)
	if idemKey == "" {
		idemKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	}
	if len(idemKey) > maxIdempotencyKeyLen {
		s.writeError(w, http.StatusBadRequest, "idempotency_key too long")
		return
	}

	msg, created, err := s.store.Chat().CreateMessage(r.Context(), store.CreateMessageParams{
		TenantID:       tenantID,
		RoomID:         roomID,
		SenderID:       user.ID,
		SenderName:     displayNameFor(user),
		ReplyToID:      strings.TrimSpace(req.ReplyToID),
		Encoding:       encoding,
		Body:           body,
		IdempotencyKey: idemKey,
		AttachmentIDs:  attIDs,
	})
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Room not found")
		return
	}
	if errors.Is(err, store.ErrRoomClosed) {
		s.writeError(w, http.StatusConflict, "Room is closed")
		return
	}
	if errors.Is(err, store.ErrReplyNotFound) {
		s.writeError(w, http.StatusBadRequest, "reply_to_id is not a message in this room")
		return
	}
	if errors.Is(err, store.ErrAttachmentInvalid) {
		s.writeError(w, http.StatusBadRequest, "One or more attachments are invalid, already used, or belong to another room or user")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to send message")
		return
	}

	if created {
		_ = s.chatHub.PublishRoom(r.Context(), roomID, chat.Event{
			Type:   chat.EventMessageNew,
			RoomID: roomID,
			Seq:    msg.Seq,
			Data:   chat.MustMarshalData(msg),
		})
		s.pushAsync(r.Context(), func(ctx context.Context) { s.dispatchMessagePush(ctx, tenantID, roomID, msg) })
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	s.writeJSON(w, status, map[string]any{"message": msg})
}

type editMessageRequest struct {
	Body     string `json:"body"`
	Encoding string `json:"encoding"`
}

// PATCH /api/v1/rooms/{id}/messages/{mid}
func (s *Server) handleChatEditMessage(w http.ResponseWriter, r *http.Request) {
	user, sess, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	if !s.allowChatAction(w, user.ID, chatLimitWrites) {
		return
	}
	roomID := r.PathValue("id")
	msgID := r.PathValue("mid")

	if _, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID); !ok {
		return
	}
	var req editMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	body := strings.TrimSpace(req.Body)
	if body == "" {
		s.writeError(w, http.StatusBadRequest, "Message body must be 1 to 16384 bytes")
		return
	}
	encoding, err := s.messageEncoding(w, user, sess, req.Encoding, body)
	if err != nil {
		return
	}

	msg, err := s.store.Chat().EditMessage(r.Context(), tenantID, roomID, msgID, user.ID, body, encoding)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Message not found")
		return
	}
	if errors.Is(err, store.ErrForbidden) {
		s.writeError(w, http.StatusForbidden, "Only the message sender can edit it")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to edit message")
		return
	}

	_ = s.chatHub.PublishRoom(r.Context(), roomID, chat.Event{
		Type:   chat.EventMessageEdit,
		RoomID: roomID,
		Seq:    msg.Seq,
		Data:   chat.MustMarshalData(msg),
	})
	s.writeJSON(w, http.StatusOK, map[string]any{"message": msg})
}

// DELETE /api/v1/rooms/{id}/messages/{mid}
func (s *Server) handleChatDeleteMessage(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	if !s.allowChatAction(w, user.ID, chatLimitWrites) {
		return
	}
	roomID := r.PathValue("id")
	msgID := r.PathValue("mid")

	member, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID)
	if !ok {
		return
	}

	linkedAttachments, _ := s.store.Chat().ListMessageAttachments(r.Context(), tenantID, roomID, msgID)

	msg, err := s.store.Chat().DeleteMessage(r.Context(), tenantID, roomID, msgID, user.ID, isRoomModerator(member, user))
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Message not found")
		return
	}
	if errors.Is(err, store.ErrForbidden) {
		s.writeError(w, http.StatusForbidden, "Not allowed to delete this message")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to delete message")
		return
	}

	if s.blobs != nil {
		for _, att := range linkedAttachments {
			_ = s.blobs.Delete(att.TenantID, att.BlobKey)
		}
	}

	_ = s.chatHub.PublishRoom(r.Context(), roomID, chat.Event{
		Type:   chat.EventMessageDelete,
		RoomID: roomID,
		Seq:    msg.Seq,
		Data: chat.MustMarshalData(map[string]any{
			"id":         msg.ID,
			"deleted_at": msg.DeletedAt,
		}),
	})
	s.writeJSON(w, http.StatusOK, map[string]any{"message": msg})
}

// PUT /api/v1/rooms/{id}/messages/{mid}/reactions/{emoji}
func (s *Server) handleChatAddReaction(w http.ResponseWriter, r *http.Request) {
	s.handleChatReaction(w, r, true)
}

// DELETE /api/v1/rooms/{id}/messages/{mid}/reactions/{emoji}
func (s *Server) handleChatRemoveReaction(w http.ResponseWriter, r *http.Request) {
	s.handleChatReaction(w, r, false)
}

func (s *Server) handleChatReaction(w http.ResponseWriter, r *http.Request, add bool) {
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	if !s.allowChatAction(w, user.ID, chatLimitWrites) {
		return
	}
	roomID := r.PathValue("id")
	msgID := r.PathValue("mid")
	emoji := strings.TrimSpace(r.PathValue("emoji"))

	if emoji == "" || len(emoji) > maxEmojiLen {
		s.writeError(w, http.StatusBadRequest, "Invalid reaction emoji")
		return
	}
	if _, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID); !ok {
		return
	}

	var err error
	if add {
		err = s.store.Chat().AddReaction(r.Context(), tenantID, roomID, msgID, user.ID, emoji)
	} else {
		err = s.store.Chat().RemoveReaction(r.Context(), tenantID, roomID, msgID, user.ID, emoji)
	}
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Message not found")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to update reaction")
		return
	}

	_ = s.chatHub.PublishRoom(r.Context(), roomID, chat.Event{
		Type:   chat.EventReactionSet,
		RoomID: roomID,
		Data: chat.MustMarshalData(map[string]any{
			"message_id": msgID,
			"user_id":    user.ID,
			"emoji":      emoji,
			"added":      add,
		}),
	})
	s.writeJSON(w, http.StatusOK, map[string]any{
		"message_id": msgID,
		"emoji":      emoji,
		"added":      add,
	})
}

type readCursorRequest struct {
	Seq int64 `json:"seq"`
}

// POST /api/v1/rooms/{id}/read
func (s *Server) handleChatMarkRead(w http.ResponseWriter, r *http.Request) {
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

	var req readCursorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Seq < 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid seq")
		return
	}

	cur, err := s.store.Chat().UpdateReadCursor(r.Context(), tenantID, roomID, user.ID, req.Seq)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Room not found")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to update read cursor")
		return
	}

	_ = s.chatHub.PublishUser(r.Context(), user.ID, chat.Event{
		Type:   chat.EventReadSync,
		UserID: user.ID,
		Data:   chat.MustMarshalData(chat.ReadSyncPayload{RoomID: roomID, LastReadSeq: cur}),
	})
	s.writeJSON(w, http.StatusOK, map[string]any{"room_id": roomID, "last_read_seq": cur})
}

// POST /api/v1/webhooks/in/{id}: incoming webhooks were removed so every room can be end-to-end
// encrypted (docs/superpowers/specs/2026-11-22-e2ee-design.md §8). It answers every sender alike,
// without looking the ID up, so it says nothing about which webhooks existed.
func (s *Server) handleChatIncomingWebhook(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusGone, map[string]string{
		"error": "Incoming webhooks were removed because rooms are end-to-end encrypted; post through a bot (Bots & Agents) instead",
		"code":  "gone",
	})
}
