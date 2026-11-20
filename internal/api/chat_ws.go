package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Busnes-app/ky_server_base/internal/chat"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/coder/websocket"
)

// ChatHub exposes the real-time WebSocket hub for metrics, revocation, and tests.
func (s *Server) ChatHub() *chat.Hub {
	return s.chatHub
}

// RunChatBus runs the backing EventBus (PostgreSQL LISTEN/NOTIFY or in-memory) until ctx is canceled.
func (s *Server) RunChatBus(ctx context.Context) error {
	if s.chatHub == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	return s.chatHub.Run(ctx)
}

// CloseChat gracefully disconnects all live WebSocket clients during shutdown.
func (s *Server) CloseChat() {
	if s.chatHub != nil {
		s.chatHub.Close()
	}
}

// chatSessionValid repeats AuthenticateRequest's checks for a live socket: the session
// still exists and is unexpired, and its user is active, allowed and not restricted.
// A lookup failure is returned as an error, never as a revocation.
func chatSessionValid(ctx context.Context, st store.Store, userID, sessionHash string) (bool, error) {
	sess, err := st.Sessions().GetSession(ctx, sessionHash)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSessionExpired) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if sess.UserID != userID {
		return false, nil
	}
	user, err := st.Users().GetUserByID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if user.Status != "active" || user.MustChangePassword {
		return false, nil
	}
	return st.InstallerUserAllowed(ctx, user)
}

func hasBearerAuth(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func (s *Server) handleChatWS(w http.ResponseWriter, r *http.Request) {
	// Strict Cross-Site WebSocket Hijacking (CSWSH) protection:
	// 1. Any supplied Origin must match the configured AppURL origin.
	// 2. Cookie-authenticated upgrades must present a valid same-origin Origin header
	//    (browsers always send Origin on RFC 6455 upgrades; non-browser clients use Bearer tokens).
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !sameOrigin(origin, s.config.Server.AppURL) {
			s.writeError(w, http.StatusForbidden, "Origin not allowed")
			return
		}
	} else if s.sessions.HasSessionCookie(r) && !hasBearerAuth(r) {
		s.writeError(w, http.StatusForbidden, "Origin header required for cookie WebSocket upgrade")
		return
	}

	user, sess, err := s.sessions.AuthenticateRequest(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	tenantID := store.DefaultTenantID
	roomIDs, err := s.store.Chat().ListUserRoomIDs(r.Context(), tenantID, user.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load room memberships")
		return
	}

	// Origin was validated strictly above via sameOrigin(origin, AppURL).
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}

	s.chatHub.ServeConn(r.Context(), conn, tenantID, user.ID, sess.TokenHash, roomIDs)
}
