package api

import (
	"errors"
	"mime"
	"net/http"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// The token is this public route's only credential. All state changes are transactional.
func (s *Server) handleKyIdentityLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.config.SSO.Enabled {
		s.writeError(w, 404, "Unknown API endpoint")
		return
	}
	if !s.allowClientAttempt("sso-logout", r, 60, time.Minute) {
		s.writeError(w, 429, "Try again later")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		s.writeError(w, 400, "Expected logout token form")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil || len(r.PostForm["logout_token"]) != 1 {
		s.writeError(w, 400, "Expected one logout token")
		return
	}
	claims, err := s.kyidentity.VerifyLogout(r.Context(), r.PostForm.Get("logout_token"))
	if err != nil {
		s.writeError(w, 400, "Invalid logout token")
		return
	}
	userID, hashes, err := s.store.Sessions().ApplySSOLogout(r.Context(), s.kyidentity.EffectiveIssuer(), claims.Subject, claims.OrgID, claims.SID, claims.JTI, claims.IssuedAt)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrAlreadyExists) {
		s.writeError(w, 400, "Logout token refused")
		return
	}
	if err != nil {
		s.writeError(w, 503, "Logout unavailable")
		return
	}
	for _, hash := range hashes {
		_ = s.chatHub.RevokeSession(r.Context(), userID, hash)
	}
	s.audit(r.Context(), userID, r, "sso.logout", "session", "")
	s.writeJSON(w, 200, map[string]bool{"logged_out": true})
}
