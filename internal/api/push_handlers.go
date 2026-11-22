package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/push"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

const (
	maxPushSubsPerUser = 20
	maxPushPreviewLen  = 180
)

type registerPushRequest struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256DH string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

type deletePushRequest struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
}

type updateRoomNotificationsRequest struct {
	NotifyMode string `json:"notify_mode"`
}

// SetPushDispatcher replaces the server's push dispatcher (used in tests).
func (s *Server) SetPushDispatcher(d *push.Dispatcher) {
	if s.push != nil {
		s.push.Close()
	}
	s.push = d
}

// PushVAPIDPublicKey returns the server's base64url VAPID public key, or "" if Web Push is disabled.
func (s *Server) PushVAPIDPublicKey() string {
	if s.push == nil || s.push.Sender() == nil {
		return ""
	}
	return s.push.Sender().VAPIDPublicKey()
}

// GET /api/v1/push/subscriptions
func (s *Server) handleListPushSubscriptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	subs, err := s.store.Chat().ListPushSubscriptions(r.Context(), store.DefaultTenantID, user.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list push subscriptions")
		return
	}
	if subs == nil {
		subs = []*store.PushSubscription{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"subscriptions":    subs,
		"vapid_public_key": s.PushVAPIDPublicKey(),
	})
}

// POST /api/v1/push/subscriptions
func (s *Server) handleRegisterPushSubscription(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if !s.allowChatAction(w, user.ID, chatLimitRooms) {
		return
	}
	if s.push == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Web Push is disabled on this server")
		return
	}

	var req registerPushRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	endpoint := strings.TrimSpace(req.Endpoint)
	allowPrivate := s.config != nil && s.config.Push.AllowPrivate
	if _, err := push.ValidateEndpoint(endpoint, allowPrivate); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid or disallowed push endpoint URL")
		return
	}
	p256dh := strings.TrimSpace(req.Keys.P256DH)
	authSecret := strings.TrimSpace(req.Keys.Auth)
	if _, _, err := push.ValidateSubscriptionKeys(p256dh, authSecret); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid push subscription keys")
		return
	}

	sub, err := s.store.Chat().UpsertPushSubscription(r.Context(), &store.PushSubscription{
		TenantID:   store.DefaultTenantID,
		UserID:     user.ID,
		Endpoint:   endpoint,
		P256DH:     p256dh,
		AuthSecret: authSecret,
		UserAgent:  strings.TrimSpace(r.UserAgent()),
	}, maxPushSubsPerUser)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save push subscription")
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"subscription": sub})
}

// DELETE /api/v1/push/subscriptions
func (s *Server) handleDeletePushSubscription(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	var req deletePushRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	id := strings.TrimSpace(req.ID)
	endpoint := strings.TrimSpace(req.Endpoint)
	if id == "" && endpoint == "" {
		s.writeError(w, http.StatusBadRequest, "id or endpoint is required")
		return
	}
	var err error
	if id != "" {
		err = s.store.Chat().DeletePushSubscriptionByID(r.Context(), store.DefaultTenantID, user.ID, id)
	} else {
		err = s.store.Chat().DeletePushSubscriptionByEndpoint(r.Context(), store.DefaultTenantID, user.ID, endpoint)
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to delete push subscription")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// PUT /api/v1/rooms/{id}/notifications
func (s *Server) handleUpdateRoomNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if !s.allowChatAction(w, user.ID, chatLimitRooms) {
		return
	}
	roomID := r.PathValue("id")
	tenantID := store.DefaultTenantID

	if _, ok := s.requireRoomMember(w, r, tenantID, roomID, user.ID); !ok {
		return
	}
	var req updateRoomNotificationsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	mode := strings.TrimSpace(req.NotifyMode)
	if !store.ValidNotifyMode(mode) {
		s.writeError(w, http.StatusBadRequest, "notify_mode must be one of: all, mentions, mute")
		return
	}
	if err := s.store.Chat().UpdateRoomNotifyMode(r.Context(), tenantID, roomID, user.ID, mode); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Room membership not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to update notification mode")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"room_id":     roomID,
		"notify_mode": mode,
	})
}

// dispatchMessagePush fans out encrypted Web Push alerts for a newly created message,
// respecting each room member's notify_mode (all | mentions | mute).
func (s *Server) dispatchMessagePush(ctx context.Context, tenantID, roomID string, msg *store.Message) {
	if s.push == nil || msg == nil || s.store == nil {
		return
	}
	room, err := s.store.Chat().GetRoom(ctx, tenantID, roomID)
	if err != nil {
		return
	}
	members, err := s.store.Chat().ListRoomMembers(ctx, tenantID, roomID)
	if err != nil || len(members) == 0 {
		return
	}

	isPlain := msg.Encoding == store.MessageEncodingPlainV1
	broadcastMention := isPlain && (bodyHasMention(msg.Body, "all") || bodyHasMention(msg.Body, "here") || bodyHasMention(msg.Body, "channel"))

	var recipientIDs []string
	var checkMentionMembers []*store.RoomMember
	for _, m := range members {
		if m.UserID == msg.SenderID || m.Role == store.RoomRoleBot {
			continue
		}
		switch m.NotifyMode {
		case store.NotifyModeMute:
			continue
		case store.NotifyModeMentions:
			if room.Kind == store.RoomKindDM || broadcastMention {
				recipientIDs = append(recipientIDs, m.UserID)
			} else if isPlain {
				checkMentionMembers = append(checkMentionMembers, m)
			}
		default: // "all" or unset
			recipientIDs = append(recipientIDs, m.UserID)
		}
	}

	for _, m := range checkMentionMembers {
		u, err := s.store.Users().GetUserByID(ctx, m.UserID)
		if err != nil || u == nil || u.Status != "active" {
			continue
		}
		if bodyHasMention(msg.Body, u.Username) {
			recipientIDs = append(recipientIDs, m.UserID)
		}
	}
	if len(recipientIDs) == 0 {
		return
	}

	subs, err := s.store.Chat().ListPushSubscriptionsForUsers(ctx, tenantID, recipientIDs)
	if err != nil || len(subs) == 0 {
		return
	}

	senderName := strings.TrimSpace(msg.SenderName)
	if senderName == "" {
		senderName = "Someone"
	}
	roomName := strings.TrimSpace(room.Name)
	title := senderName
	if room.Kind != store.RoomKindDM && roomName != "" {
		title = senderName + " in #" + roomName
	}

	bodyPreview := buildPushMessageBody(msg)
	payload := push.Payload{
		Kind:       "message",
		RoomID:     roomID,
		RoomName:   roomName,
		SenderName: senderName,
		Title:      title,
		Body:       bodyPreview,
		URL:        "/#room=" + roomID,
	}

	for _, sub := range subs {
		s.push.Enqueue(push.Job{
			Subscription: push.Subscription{
				ID:         sub.ID,
				Endpoint:   sub.Endpoint,
				P256DH:     sub.P256DH,
				AuthSecret: sub.AuthSecret,
			},
			Payload: payload,
			Options: push.SendOptions{
				Urgency: "normal",
			},
		})
	}
}

// dispatchCallPush sends high-urgency incoming call Web Push alerts to non-muted room members.
func (s *Server) dispatchCallPush(ctx context.Context, tenantID, roomID, starterUserID, starterName string) {
	if s.push == nil || s.store == nil {
		return
	}
	room, err := s.store.Chat().GetRoom(ctx, tenantID, roomID)
	if err != nil {
		return
	}
	members, err := s.store.Chat().ListRoomMembers(ctx, tenantID, roomID)
	if err != nil || len(members) == 0 {
		return
	}

	var recipientIDs []string
	for _, m := range members {
		if m.UserID == starterUserID || m.Role == store.RoomRoleBot || m.NotifyMode == store.NotifyModeMute {
			continue
		}
		recipientIDs = append(recipientIDs, m.UserID)
	}
	if len(recipientIDs) == 0 {
		return
	}

	subs, err := s.store.Chat().ListPushSubscriptionsForUsers(ctx, tenantID, recipientIDs)
	if err != nil || len(subs) == 0 {
		return
	}

	caller := strings.TrimSpace(starterName)
	if caller == "" {
		caller = "Someone"
	}
	roomName := strings.TrimSpace(room.Name)
	title := "Incoming call"
	body := caller + " started a call"
	if room.Kind != store.RoomKindDM && roomName != "" {
		title = "Incoming call in #" + roomName
	} else {
		title = "Incoming call from " + caller
	}

	payload := push.Payload{
		Kind:       "call",
		RoomID:     roomID,
		RoomName:   roomName,
		SenderName: caller,
		Title:      title,
		Body:       body,
		URL:        "/#room=" + roomID,
	}

	for _, sub := range subs {
		s.push.Enqueue(push.Job{
			Subscription: push.Subscription{
				ID:         sub.ID,
				Endpoint:   sub.Endpoint,
				P256DH:     sub.P256DH,
				AuthSecret: sub.AuthSecret,
			},
			Payload: payload,
			Options: push.SendOptions{
				TTL:     push.CallTTL(),
				Urgency: "high",
			},
		})
	}
}

func buildPushMessageBody(msg *store.Message) string {
	if msg.Encoding == store.MessageEncodingE2EERoomV1 {
		return "New encrypted message"
	}
	text := strings.TrimSpace(msg.Body)
	if text == "" {
		if len(msg.Attachments) == 1 {
			return "Sent an attachment: " + msg.Attachments[0].Filename
		}
		if len(msg.Attachments) > 1 {
			return "Sent attachments"
		}
		return "New message"
	}
	// Collapse newlines for single-line notification previews and clamp runes cleanly.
	text = strings.Join(strings.Fields(text), " ")
	runes := []rune(text)
	if len(runes) > maxPushPreviewLen {
		return string(runes[:maxPushPreviewLen-1]) + "…"
	}
	return text
}

// bodyHasMention reports whether body contains an @handle token at word boundaries (case-insensitive).
func bodyHasMention(body, handle string) bool {
	handle = strings.ToLower(strings.TrimSpace(handle))
	if handle == "" || body == "" {
		return false
	}
	needle := "@" + handle
	lower := strings.ToLower(body)
	offset := 0
	for {
		idx := strings.Index(lower[offset:], needle)
		if idx < 0 {
			return false
		}
		pos := offset + idx
		beforeOK := pos == 0 || !isHandleChar(rune(lower[pos-1]))
		end := pos + len(needle)
		afterOK := end >= len(lower) || !isHandleChar(rune(lower[end]))
		if beforeOK && afterOK {
			return true
		}
		offset = pos + len(needle)
		if offset >= len(lower) {
			return false
		}
	}
}

func isHandleChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.'
}

func initPushDispatcher(cfg *config.Config, st store.Store) *push.Dispatcher {
	if cfg != nil && cfg.Push.Disabled {
		return nil
	}
	var key *push.VAPIDKey
	var err error
	switch {
	case cfg != nil && cfg.Push.VAPIDPrivateKey != "":
		key, err = push.ParseVAPIDPrivateKey(cfg.Push.VAPIDPrivateKey)
	case cfg != nil && strings.TrimSpace(cfg.Database.DataDir) != "":
		key, err = push.LoadOrCreateVAPIDKey(filepath.Join(cfg.Database.DataDir, "vapid.key"))
	default:
		key, err = push.GenerateVAPIDKey()
	}
	if err != nil {
		log.Printf("[PUSH] failed to initialize VAPID key: %v", err)
		return nil
	}
	var configuredSub, appURL string
	var allowPrivate bool
	if cfg != nil {
		configuredSub = cfg.Push.VAPIDSubject
		appURL = cfg.Server.AppURL
		allowPrivate = cfg.Push.AllowPrivate
	}
	sender := push.NewSender(push.SenderOptions{
		VAPID:        key,
		Subject:      push.DefaultVAPIDSubject(configuredSub, appURL),
		AllowPrivate: allowPrivate,
	})
	var onGone, onSent func(context.Context, string)
	if st != nil {
		onGone = func(ctx context.Context, subID string) {
			_ = st.Chat().DeletePushSubscriptionInternal(ctx, subID)
		}
		onSent = func(ctx context.Context, subID string) {
			_ = st.Chat().TouchPushSubscription(ctx, subID, time.Now().UTC().UnixMilli())
		}
	}
	return push.NewDispatcher(sender, onGone, onSent)
}
