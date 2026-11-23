package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/auth"
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
	done := make(chan struct{})
	go func() { defer close(done); s.reconcileCallsLoop(ctx) }()
	defer func() { <-done }()
	return s.chatHub.Run(ctx)
}

// callReconcileInterval bounds how long a call seat outlives its org after a missed
// tenant.revoked notification.
const callReconcileInterval = 30 * time.Second

func (s *Server) reconcileCallsLoop(ctx context.Context) {
	if s.calls == nil || !s.config.Tenancy.IsMultiTenant() {
		return
	}
	t := time.NewTicker(callReconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			s.calls.ReconcileTenants(rctx)
			cancel()
		}
	}
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
	if rest, ok := strings.CutPrefix(sessionHash, auth.AgentSessionPrefix); ok {
		agentID, tokenHash, splitOK := strings.Cut(rest, ":")
		if !splitOK || agentID == "" || tokenHash == "" {
			return false, nil
		}
		agent, err := st.Agents().GetAgentByTokenHash(ctx, tokenHash)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if agent.ID != agentID || agent.UserID != userID || agent.TokenState != store.AgentTokenActive {
			return false, nil
		}
		botUser, err := st.Users().GetUserByID(ctx, userID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if botUser.Status != "active" || botUser.Role != "bot" {
			return false, nil
		}
		owner, err := st.Users().GetUserByID(ctx, agent.OwnerUserID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if owner.Status != "active" {
			return false, nil
		}
		return st.InstallerUserAllowed(ctx, owner)
	}
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

	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return
	}
	roomIDs, err := s.store.Chat().ListUserRoomIDs(r.Context(), tenantID, user.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load room memberships")
		return
	}

	callRoom := r.PathValue("id")
	if callRoom != "" {
		if _, ok := s.requireRoomMember(w, r, tenantID, callRoom, user.ID); !ok {
			return
		}
		if user.Role != "user" {
			s.writeError(w, http.StatusForbidden, "Member account required")
			return
		}
		if !s.requireCallOwner(w, r, tenantID, callRoom) {
			return
		}
	}
	// Origin was validated strictly above via sameOrigin(origin, AppURL).
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}

	if callRoom != "" {
		s.chatHub.ServeRoomCallConn(r.Context(), conn, tenantID, user.ID, sess.TokenHash, callRoom)
	} else {
		s.chatHub.ServeConn(r.Context(), conn, tenantID, user.ID, sess.TokenHash, roomIDs)
	}
}
