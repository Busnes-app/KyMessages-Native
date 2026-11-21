package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/chat"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/coder/websocket"
	"github.com/google/uuid"
)

const (
	guestSessionCookieName = "ky_guest_session"
	maxMeetingMembers      = 100
	maxMeetingGuests       = 100
	maxMeetingWindows      = 400
	maxMeetingAheadDays    = 90
	guestKnockRateLimit    = 10
	guestKnockRateWindow   = 15 * time.Minute
)

// ---------------------------------------------------------------------
// KyCalendar Sync Endpoints: PUT /api/meetings/{id}, DELETE /api/meetings/{id}
// ---------------------------------------------------------------------

func (s *Server) verifyMeetingSync(r *http.Request, body []byte) bool {
	secret := strings.TrimSpace(s.config.RTC.MeetingSyncSecret)
	if len(secret) < syncauth.MinKeyBytes {
		return false
	}
	_, err := syncauth.Verify([]byte(secret), syncauth.FromRequest(r), body, syncauth.Options{})
	return err == nil
}

// PUT /api/meetings/{id}
func (s *Server) handleKyCalendarUpsertMeeting(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	meetingID := strings.TrimSpace(r.PathValue("id"))
	if meetingID == "" || len(meetingID) > 128 {
		s.writeError(w, http.StatusBadRequest, "Invalid meeting ID")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}
	if !s.verifyMeetingSync(r, body) {
		s.writeError(w, http.StatusUnauthorized, "Meeting sync signature invalid or not configured")
		return
	}

	var req struct {
		OrganizerSub string   `json:"organizer_sub"`
		Title        string   `json:"title"`
		MemberSubs   []string `json:"member_subs"`
		Guests       []struct {
			Key string `json:"key"`
		} `json:"guests"`
		Windows []struct {
			Start string `json:"start"`
			End   string `json:"end"`
		} `json:"windows"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = "Meeting"
	}
	if len(title) > maxRoomNameLen {
		title = title[:maxRoomNameLen]
	}
	if len(req.MemberSubs) > maxMeetingMembers {
		s.writeError(w, http.StatusBadRequest, "Too many meeting members (max 100)")
		return
	}
	if len(req.Guests) > maxMeetingGuests {
		s.writeError(w, http.StatusBadRequest, "Too many external guests (max 100)")
		return
	}
	if len(req.Windows) > maxMeetingWindows {
		s.writeError(w, http.StatusBadRequest, "Too many meeting windows (max 400)")
		return
	}

	now := time.Now().UTC()
	maxHorizon := now.Add(maxMeetingAheadDays * 24 * time.Hour)
	windows := make([]store.MeetingWindow, 0, len(req.Windows))
	for _, rw := range req.Windows {
		start, err1 := time.Parse(time.RFC3339, rw.Start)
		end, err2 := time.Parse(time.RFC3339, rw.End)
		if err1 != nil || err2 != nil || !end.After(start) {
			s.writeError(w, http.StatusBadRequest, "Invalid meeting window RFC3339 timestamps")
			return
		}
		if start.After(maxHorizon) {
			s.writeError(w, http.StatusBadRequest, "Meeting window exceeds 90-day horizon")
			return
		}
		windows = append(windows, store.MeetingWindow{
			MeetingID: meetingID,
			StartsAt:  start.UTC().UnixMilli(),
			EndsAt:    end.UTC().UnixMilli(),
		})
	}

	// Resolve organizer & internal member subs to local user IDs.
	resolveSub := func(sub string) string {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			return ""
		}
		if u, err := s.store.Users().GetUserBySSO(r.Context(), "kyidentity", sub); err == nil {
			return u.ID
		}
		if u, err := s.store.Users().GetUserByID(r.Context(), sub); err == nil {
			return u.ID
		}
		return ""
	}

	orgID := resolveSub(req.OrganizerSub)
	memberIDs := make([]string, 0, len(req.MemberSubs)+1)
	if orgID != "" {
		memberIDs = append(memberIDs, orgID)
	}
	for _, sub := range req.MemberSubs {
		if uid := resolveSub(sub); uid != "" {
			memberIDs = append(memberIDs, uid)
		}
	}

	keepGuests := make(map[string]struct{}, len(req.Guests))
	newGuestTokens := make(map[string]store.MeetingGuest, len(req.Guests))
	rawGuestTokens := make(map[string]string, len(req.Guests))
	for _, g := range req.Guests {
		key := strings.TrimSpace(g.Key)
		if key == "" || len(key) > 128 {
			continue
		}
		keepGuests[key] = struct{}{}
		rawTok, err := chat.GenerateOpaqueToken()
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to mint guest token")
			return
		}
		rawGuestTokens[key] = rawTok
		newGuestTokens[key] = store.MeetingGuest{
			MeetingID: meetingID,
			GuestKey:  key,
			TokenHash: chat.HashMeetingToken(rawTok),
		}
	}

	res, err := s.store.Chat().UpsertMeeting(r.Context(), store.UpsertMeetingParams{
		ID:             meetingID,
		TenantID:       store.DefaultTenantID,
		OrganizerID:    orgID,
		OrganizerSub:   strings.TrimSpace(req.OrganizerSub),
		Title:          title,
		MemberUserIDs:  memberIDs,
		Windows:        windows,
		NewGuestTokens: newGuestTokens,
		KeepGuestKeys:  keepGuests,
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to sync meeting")
		return
	}

	// Emit real-time room membership deltas for added/removed members.
	for _, uid := range res.AddedMemberIDs {
		_ = s.chatHub.PublishRoom(r.Context(), res.Room.ID, chat.Event{
			Type:   chat.EventRoomMember,
			RoomID: res.Room.ID,
			Data:   chat.MustMarshalData(chat.RoomMemberDelta{Action: "added", UserID: uid, Role: store.RoomRoleMember}),
		})
	}
	for _, uid := range res.RemovedMemberIDs {
		_ = s.chatHub.PublishRoom(r.Context(), res.Room.ID, chat.Event{
			Type:   chat.EventRoomMember,
			RoomID: res.Room.ID,
			Data:   chat.MustMarshalData(chat.RoomMemberDelta{Action: "removed", UserID: uid}),
		})
	}
	// Evict any live guests whose invite keys were removed.
	for _, gk := range res.RevokedGuestKeys {
		s.lobby.RevokeGuestKey(r.Context(), meetingID, gk)
	}

	baseURL := strings.TrimRight(s.config.Server.AppURL, "/")
	guestURLs := make(map[string]string, len(res.IssuedGuestKeys))
	for _, gk := range res.IssuedGuestKeys {
		if tok := rawGuestTokens[gk]; tok != "" {
			guestURLs[gk] = baseURL + "/meet/" + tok
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"meeting_id": res.Meeting.ID,
		"room_id":    res.Room.ID,
		"member_url": baseURL + "/chat/" + res.Room.ID,
		"guest_urls": guestURLs,
	})
}

// DELETE /api/meetings/{id}
func (s *Server) handleKyCalendarCloseMeeting(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	meetingID := strings.TrimSpace(r.PathValue("id"))
	if meetingID == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid meeting ID")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}
	if !s.verifyMeetingSync(r, body) {
		s.writeError(w, http.StatusUnauthorized, "Meeting sync signature invalid or not configured")
		return
	}

	closed, err := s.store.Chat().CloseMeeting(r.Context(), store.DefaultTenantID, meetingID)
	if errors.Is(err, store.ErrNotFound) {
		s.writeJSON(w, http.StatusOK, map[string]bool{"closed": true})
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to close meeting")
		return
	}

	s.lobby.RevokeMeeting(r.Context(), closed.RoomID)
	_ = s.chatHub.PublishRoom(r.Context(), closed.RoomID, chat.Event{
		Type:   chat.EventRoomClosed,
		RoomID: closed.RoomID,
		Data:   chat.MustMarshalData(map[string]any{"room_id": closed.RoomID, "meeting_id": closed.ID}),
	})
	s.writeJSON(w, http.StatusOK, map[string]bool{"closed": true})
}

// ---------------------------------------------------------------------
// Instant Native Meeting & Guest Invite Generation (Authenticated Users)
// ---------------------------------------------------------------------

// POST /api/v1/meetings — creates an instant meeting room + shareable external guest invite link.
func (s *Server) handleCreateInstantMeeting(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if user.Role == "bot" {
		s.writeError(w, http.StatusForbidden, "Bot accounts cannot create meetings")
		return
	}
	var req struct {
		Title     string   `json:"title"`
		MemberIDs []string `json:"member_ids"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = displayNameFor(user) + "'s Meeting"
	}
	if len(title) > maxRoomNameLen {
		title = title[:maxRoomNameLen]
	}

	meetingID := "mtg_" + uuid.Must(uuid.NewV7()).String()
	rawTok, err := chat.GenerateOpaqueToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate invite link")
		return
	}
	guestKey := "invite-" + uuid.Must(uuid.NewV7()).String()[:8]

	members := append([]string{user.ID}, req.MemberIDs...)
	res, err := s.store.Chat().UpsertMeeting(r.Context(), store.UpsertMeetingParams{
		ID:            meetingID,
		TenantID:      store.DefaultTenantID,
		OrganizerID:   user.ID,
		OrganizerSub:  user.ID,
		Title:         title,
		MemberUserIDs: members,
		Windows:       nil, // Ad-hoc meeting: open until closed
		NewGuestTokens: map[string]store.MeetingGuest{
			guestKey: {MeetingID: meetingID, GuestKey: guestKey, TokenHash: chat.HashMeetingToken(rawTok)},
		},
		KeepGuestKeys: map[string]struct{}{guestKey: {}},
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to create meeting")
		return
	}

	for _, uid := range res.AddedMemberIDs {
		role := store.RoomRoleMember
		if uid == user.ID {
			role = store.RoomRoleOwner
		}
		_ = s.chatHub.PublishRoom(r.Context(), res.Room.ID, chat.Event{
			Type:   chat.EventRoomMember,
			RoomID: res.Room.ID,
			Data:   chat.MustMarshalData(chat.RoomMemberDelta{Action: "added", UserID: uid, Role: role}),
		})
	}

	baseURL := strings.TrimRight(s.config.Server.AppURL, "/")
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"meeting":    res.Meeting,
		"room":       res.Room,
		"member_url": baseURL + "/chat/" + res.Room.ID,
		"guest_url":  baseURL + "/meet/" + rawTok,
		"guest_path": "/meet/" + rawTok,
	})
}

// POST /api/v1/rooms/{id}/meeting/guest-link — mints a fresh external guest invite link for a meeting room.
func (s *Server) handleCreateRoomGuestLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if user.Role == "bot" {
		s.writeError(w, http.StatusForbidden, "Bot accounts cannot create meeting links")
		return
	}
	roomID := r.PathValue("id")
	if _, ok := s.requireRoomMember(w, r, store.DefaultTenantID, roomID, user.ID); !ok {
		return
	}
	room, err := s.store.Chat().GetRoom(r.Context(), store.DefaultTenantID, roomID)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Room not found")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load room")
		return
	}
	if room.ClosedAt != nil {
		s.writeError(w, http.StatusConflict, "Room is closed")
		return
	}

	meeting, _, err := s.store.Chat().GetMeetingByRoomID(r.Context(), store.DefaultTenantID, roomID)
	if errors.Is(err, store.ErrNotFound) {
		// Allow attaching a guest link to any non-DM room by creating an ad-hoc meeting record.
		if room.Kind == store.RoomKindDM {
			s.writeError(w, http.StatusBadRequest, "External guest links are only available in channels and meeting rooms")
			return
		}
		meetingID := "mtg_" + uuid.Must(uuid.NewV7()).String()
		rawTok, err := chat.GenerateOpaqueToken()
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to generate guest token")
			return
		}
		// Insert meeting directly linked to existing room via CreateMeetingGuest after creating meeting row.
		// Reuse UpsertMeeting? No, UpsertMeeting inserts a new room; for an existing channel we only mint on meeting rooms
		// OR return a new meeting link cleanly. Let's keep guest links strictly on meeting rooms or attach directly!
		if _, err := s.store.Chat().UpsertMeeting(r.Context(), store.UpsertMeetingParams{
			ID:            meetingID,
			TenantID:      store.DefaultTenantID,
			OrganizerID:   user.ID,
			OrganizerSub:  user.ID,
			Title:         room.Name + " (Guest Meeting)",
			MemberUserIDs: []string{user.ID},
			NewGuestTokens: map[string]store.MeetingGuest{
				"guest-1": {MeetingID: meetingID, GuestKey: "guest-1", TokenHash: chat.HashMeetingToken(rawTok)},
			},
			KeepGuestKeys: map[string]struct{}{"guest-1": {}},
		}); err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to create guest meeting link")
			return
		}
		baseURL := strings.TrimRight(s.config.Server.AppURL, "/")
		s.writeJSON(w, http.StatusCreated, map[string]any{
			"guest_url":  baseURL + "/meet/" + rawTok,
			"guest_path": "/meet/" + rawTok,
		})
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load meeting")
		return
	}
	if meeting.ClosedAt != nil {
		s.writeError(w, http.StatusConflict, "Meeting is closed")
		return
	}

	rawTok, err := chat.GenerateOpaqueToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate guest token")
		return
	}
	guest := &store.MeetingGuest{
		MeetingID: meeting.ID,
		GuestKey:  "invite-" + uuid.Must(uuid.NewV7()).String()[:8],
		TokenHash: chat.HashMeetingToken(rawTok),
	}
	if err := s.store.Chat().CreateMeetingGuest(r.Context(), guest); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save guest invite")
		return
	}
	baseURL := strings.TrimRight(s.config.Server.AppURL, "/")
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"guest_url":  baseURL + "/meet/" + rawTok,
		"guest_path": "/meet/" + rawTok,
	})
}

// ---------------------------------------------------------------------
// External Guest Waiting Room & Confined Meeting API (/api/meet/{token}...)
// ---------------------------------------------------------------------

func (s *Server) lookupGuestToken(r *http.Request) (*store.MeetingGuest, *store.Meeting, []store.MeetingWindow, error) {
	rawTok := strings.TrimSpace(r.PathValue("token"))
	if len(rawTok) < 16 || len(rawTok) > 128 {
		return nil, nil, nil, store.ErrNotFound
	}
	return s.store.Chat().GetMeetingGuestByTokenHash(r.Context(), chat.HashMeetingToken(rawTok))
}

func (s *Server) authenticateGuestRequest(w http.ResponseWriter, r *http.Request, requireAdmitted bool) (*chat.GuestSession, *store.Meeting, bool) {
	guestRow, meeting, windows, err := s.lookupGuestToken(r)
	if errors.Is(err, store.ErrNotFound) || guestRow.RevokedAt != nil || meeting.ClosedAt != nil {
		s.writeError(w, http.StatusNotFound, "Meeting link is invalid or has ended")
		return nil, nil, false
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to verify meeting link")
		return nil, nil, false
	}
	if !chat.IsWithinMeetingWindows(time.Now().UTC(), windows) {
		s.writeError(w, http.StatusForbidden, "This meeting is outside its scheduled time window")
		return nil, nil, false
	}

	secret := strings.TrimSpace(r.Header.Get("X-Guest-Session"))
	if secret == "" {
		if c, err := r.Cookie(guestSessionCookieName); err == nil {
			secret = c.Value
		}
	}
	sess, ok := s.lobby.GetBySecret(secret)
	if !ok || sess.MeetingID != meeting.ID || subtle.ConstantTimeCompare([]byte(sess.GuestKey), []byte(guestRow.GuestKey)) != 1 {
		s.writeError(w, http.StatusUnauthorized, "Guest session expired — please knock again")
		return nil, nil, false
	}
	if requireAdmitted && sess.Status != "admitted" {
		s.writeError(w, http.StatusForbidden, "Waiting for a meeting participant to admit you")
		return nil, nil, false
	}
	return sess, meeting, true
}

// GET /api/meet/{token}
func (s *Server) handleGuestMeetInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.allowClientAttempt("meet_info", r, 60, time.Minute) {
		s.writeError(w, http.StatusTooManyRequests, "Too many requests")
		return
	}
	guestRow, meeting, windows, err := s.lookupGuestToken(r)
	if errors.Is(err, store.ErrNotFound) || guestRow.RevokedAt != nil {
		s.writeError(w, http.StatusNotFound, "Meeting link is invalid or revoked")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to look up meeting")
		return
	}

	inWindow := meeting.ClosedAt == nil && chat.IsWithinMeetingWindows(time.Now().UTC(), windows)
	resp := map[string]any{
		"meeting_title": meeting.Title,
		"closed":        meeting.ClosedAt != nil,
		"in_window":     inWindow,
		"pow_required":  s.config.Captcha.Provider == "pow",
		"sfu_available": s.calls.SFUAvailable(),
	}
	// If guest already has a valid session cookie for this link, report their current status.
	if c, err := r.Cookie(guestSessionCookieName); err == nil {
		if sess, ok := s.lobby.GetBySecret(c.Value); ok && sess.MeetingID == meeting.ID && sess.GuestKey == guestRow.GuestKey {
			resp["session"] = map[string]any{
				"guest_id":     sess.GuestID,
				"display_name": sess.DisplayName,
				"status":       sess.Status,
				"room_id":      sess.RoomID,
			}
		}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// POST /api/meet/{token}/knock
func (s *Server) handleGuestMeetKnock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !jsonRequest(r) {
		s.writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	if !s.allowClientAttempt("meet_knock", r, guestKnockRateLimit, guestKnockRateWindow) {
		s.writeError(w, http.StatusTooManyRequests, "Too many knock attempts; try again later")
		return
	}

	guestRow, meeting, windows, err := s.lookupGuestToken(r)
	if errors.Is(err, store.ErrNotFound) || guestRow.RevokedAt != nil {
		s.writeError(w, http.StatusNotFound, "Meeting link is invalid or revoked")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to look up meeting")
		return
	}

	var req struct {
		DisplayName  string `json:"display_name"`
		CaptchaToken string `json:"captcha_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if s.config.Captcha.Provider == "pow" && !s.pow.Spend(req.CaptchaToken, s.config.Security.SessionSecret) {
		s.writeError(w, http.StatusForbidden, "Proof-of-work verification failed")
		return
	}

	sess, err := s.lobby.Knock(r.Context(), guestRow, meeting, windows, req.DisplayName)
	switch {
	case errors.Is(err, chat.ErrMeetingClosed), errors.Is(err, chat.ErrGuestTokenRevoked):
		s.writeError(w, http.StatusGone, "This meeting has ended")
		return
	case errors.Is(err, chat.ErrMeetingNotInWindow):
		s.writeError(w, http.StatusForbidden, "This meeting is not currently open")
		return
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to enter waiting room")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     guestSessionCookieName,
		Value:    sess.SessionSecret,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.config.Security.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   4 * 60 * 60,
	})
	s.writeJSON(w, http.StatusOK, map[string]any{
		"guest_id":      sess.GuestID,
		"display_name":  sess.DisplayName,
		"status":        sess.Status,
		"meeting_title": meeting.Title,
		"room_id":       meeting.RoomID,
	})
}

// GET /api/meet/{token}/ws — confined WebSocket for waiting or admitted meeting guest.
func (s *Server) handleGuestMeetWS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !sameOrigin(origin, s.config.Server.AppURL) {
			s.writeError(w, http.StatusForbidden, "Origin not allowed")
			return
		}
	} else if _, err := r.Cookie(guestSessionCookieName); err == nil && r.Header.Get("X-Guest-Session") == "" {
		s.writeError(w, http.StatusForbidden, "Origin header required for cookie WebSocket upgrade")
		return
	}

	sess, meeting, ok := s.authenticateGuestRequest(w, r, false)
	if !ok {
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Origin strictly checked above against AppURL.
	})
	if err != nil {
		return
	}

	s.lobby.MarkConnected(sess.GuestID)
	var rooms []string
	if sess.Status == "admitted" {
		rooms = []string{meeting.RoomID}
	}
	s.chatHub.ServeGuestConn(r.Context(), conn, meeting.TenantID, sess.GuestID, rooms)
}

// POST /api/meet/{token}/call/join
func (s *Server) handleGuestCallJoin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess, meeting, ok := s.authenticateGuestRequest(w, r, true)
	if !ok {
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
		TenantID:    meeting.TenantID,
		RoomID:      meeting.RoomID,
		UserID:      sess.GuestID,
		DisplayName: sess.DisplayName + " (Guest)",
		IsGuest:     true,
		Audio:       audio,
		Video:       body.Video,
		ScreenShare: body.ScreenShare,
		ProtectIP:   body.ProtectIP,
		ECDHPubJWK:  body.ECDHPubJWK,
	})
	if errors.Is(err, chat.ErrSFUUnavailable) {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "External guest calls require LiveKit SFU when Guest Force SFU policy is enabled",
			"code":  "sfu_unavailable",
		})
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to join meeting call")
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// POST /api/meet/{token}/call/leave
func (s *Server) handleGuestCallLeave(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess, meeting, ok := s.authenticateGuestRequest(w, r, false)
	if !ok {
		return
	}
	s.calls.Leave(r.Context(), meeting.RoomID, sess.GuestID)
	s.writeJSON(w, http.StatusOK, map[string]bool{"left": true})
}

// GET /api/meet/{token}/messages
func (s *Server) handleGuestListMessages(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, meeting, ok := s.authenticateGuestRequest(w, r, true)
	if !ok {
		return
	}
	q := store.MessagePageQuery{
		TenantID: meeting.TenantID,
		RoomID:   meeting.RoomID,
		Limit:    50,
	}
	if v := r.URL.Query().Get("after_seq"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			q.AfterSeq = n
		}
	}
	msgs, hasMore, err := s.store.Chat().ListMessages(r.Context(), q)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load meeting chat")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"messages": msgs,
		"has_more": hasMore,
	})
}

// POST /api/meet/{token}/messages
func (s *Server) handleGuestSendMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess, meeting, ok := s.authenticateGuestRequest(w, r, true)
	if !ok {
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	body := strings.TrimSpace(req.Body)
	if body == "" || len(body) > maxMessageBodyLen {
		s.writeError(w, http.StatusBadRequest, "Message body is required and must be <= 16 KiB")
		return
	}
	msg, created, err := s.store.Chat().CreateMessage(r.Context(), store.CreateMessageParams{
		TenantID:        meeting.TenantID,
		RoomID:          meeting.RoomID,
		SenderID:        sess.GuestID,
		SenderName:      sess.DisplayName + " (Guest)",
		Encoding:        store.MessageEncodingPlainV1,
		Body:            body,
		SkipMemberCheck: true, // Guest admission was just verified strictly for this one meeting room
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to send message")
		return
	}
	if created {
		_ = s.chatHub.PublishRoom(r.Context(), meeting.RoomID, chat.Event{
			Type:   chat.EventMessageNew,
			RoomID: meeting.RoomID,
			Seq:    msg.Seq,
			Data:   chat.MustMarshalData(msg),
		})
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"message": msg})
}
