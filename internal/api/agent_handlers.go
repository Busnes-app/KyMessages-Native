package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	agentskill "github.com/Busnes-app/ky_server_base/agent-skill"
	"github.com/Busnes-app/ky_server_base/internal/auth"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

// agentIdle is how long a bot token may go unused before ExpireIdleAgents revokes it.
const agentIdle = 90 * 24 * time.Hour

const agentTimeout = 10 * time.Second

// agentName enforces the agent- prefix so bots are always unmistakably identifiable.
var agentName = regexp.MustCompile(`^agent-[a-z0-9-]{1,32}$`).MatchString

type agentOwnerView struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"` // owner's user status, or "unknown"
}

type agentView struct {
	ID          string         `json:"id"`
	UserID      string         `json:"user_id"`
	Username    string         `json:"username"`
	DisplayName string         `json:"display_name"`
	Owner       agentOwnerView `json:"owner"`
	TokenState  string         `json:"token_state"` // active, revoked, expired
	LastUsedAt  *time.Time     `json:"last_used_at"`
	CreatedAt   time.Time      `json:"created_at"`
}

func mintAgentToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = auth.AgentTokenPrefix + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

func (s *Server) loadUsersByID(ctx context.Context) (map[string]*store.User, error) {
	users, _, err := s.store.Users().ListUsers(ctx, 0, 10000, store.UserFilter{})
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*store.User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	return byID, nil
}

func ownerViewFor(users map[string]*store.User, ownerID string) agentOwnerView {
	v := agentOwnerView{ID: ownerID, Status: "unknown"}
	if u := users[ownerID]; u != nil {
		v.ID = u.ID
		v.Username = u.Username
		v.DisplayName = displayNameFor(u)
		v.Status = u.Status
	}
	return v
}

func toAgentView(a *store.Agent, users map[string]*store.User) agentView {
	dn := a.DisplayName
	if dn == "" {
		dn = a.Username
	}
	return agentView{
		ID:          a.ID,
		UserID:      a.UserID,
		Username:    a.Username,
		DisplayName: dn,
		Owner:       ownerViewFor(users, a.OwnerUserID),
		TokenState:  a.TokenState,
		LastUsedAt:  a.LastUsedAt,
		CreatedAt:   a.CreatedAt,
	}
}

// handleAgents lists native bot/agent accounts and active non-bot users eligible to own one.
func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), agentTimeout)
	defer cancel()
	users, err := s.loadUsersByID(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not load users")
		return
	}
	agents, err := s.store.Agents().ListAgents(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not read agents")
		return
	}
	out := make([]agentView, 0, len(agents))
	for _, a := range agents {
		out = append(out, toAgentView(a, users))
	}
	owners := make([]agentOwnerView, 0)
	for _, u := range users {
		if u.Status == "active" && u.Role != "bot" {
			owners = append(owners, agentOwnerView{
				ID:          u.ID,
				Username:    u.Username,
				DisplayName: displayNameFor(u),
				Status:      u.Status,
			})
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"agents":    out,
		"owners":    owners,
		"idle_days": int(agentIdle / (24 * time.Hour)),
	})
}

type agentTokenReply struct {
	Agent   agentView         `json:"agent"`
	Token   string            `json:"token"`
	Configs map[string]string `json:"configs"`
}

// tokenReply is the only reply that carries a plaintext token; it is never stored or logged.
func (s *Server) tokenReply(w http.ResponseWriter, v agentView, token string) {
	configs := map[string]string{}
	serverURL := strings.TrimRight(s.config.Server.AppURL, "/")
	for _, rt := range agentskill.Runtimes {
		c, err := agentskill.Config(rt, agentskill.Values{
			ServerURL:   serverURL,
			AccessToken: token,
			Owner:       v.Owner.Username,
		})
		if err == nil {
			configs[rt] = c
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, agentTokenReply{Agent: v, Token: token, Configs: configs})
}

// agentAction runs an agent change detached so a dropped connection cannot leave a token
// minted or revoked without its audit row.
func (s *Server) agentAction(r *http.Request, action string) (ctx context.Context, cancel func(), record func(resource, outcome string)) {
	actor := s.actorID(r)
	ctx, cancel = context.WithTimeout(context.WithoutCancel(r.Context()), agentTimeout)
	record = func(resource, outcome string) {
		actx, acancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer acancel()
		s.audit(actx, actor, r, action, resource, auditFields(outcome))
	}
	return ctx, cancel, record
}

func (s *Server) handleAgentCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Owner       string `json:"owner"` // KyMessages user ID
	}
	if !decodeStrict(w, r, &req) {
		s.writeError(w, http.StatusBadRequest, `Body must be {"name", "owner", "display_name"?}`)
		return
	}
	ctx, cancel, record := s.agentAction(r, "agent.create")
	defer cancel()
	refuse := func(status int, msg string) {
		record(clip200(req.Name), "refused: "+msg)
		s.writeError(w, status, msg)
	}
	if !agentName(req.Name) {
		refuse(http.StatusBadRequest, "Name must be agent- followed by 1-32 of a-z, 0-9, -")
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = req.Name
	}
	if len(displayName) > 80 {
		refuse(http.StatusBadRequest, "Display name must be at most 80 characters")
		return
	}
	owner, err := s.store.Users().GetUserByID(ctx, req.Owner)
	if err != nil || owner.Status != "active" || owner.Role == "bot" {
		refuse(http.StatusBadRequest, "The owner must be an active member")
		return
	}

	rawToken, tokenHash, err := mintAgentToken()
	if err != nil {
		record(req.Name, "error: "+err.Error())
		s.writeError(w, http.StatusInternalServerError, "Could not generate agent token")
		return
	}

	botUser := &store.User{
		ID:          "bot_" + uuid.Must(uuid.NewV7()).String(),
		Username:    req.Name,
		DisplayName: displayName,
		Role:        "bot",
		Status:      "active",
		SSOProvider: "bot",
	}
	if err := s.store.Users().CreateUser(ctx, botUser); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			refuse(http.StatusConflict, "That username is already taken")
			return
		}
		record(req.Name, "error: "+err.Error())
		s.writeError(w, http.StatusInternalServerError, "Could not create bot user")
		return
	}

	a := &store.Agent{
		ID:          uuid.NewString(),
		UserID:      botUser.ID,
		Username:    req.Name,
		DisplayName: displayName,
		OwnerUserID: owner.ID,
		TokenHash:   tokenHash,
		TokenState:  store.AgentTokenActive,
		CreatedBy:   s.actorID(r),
	}
	if err := s.store.Agents().CreateAgent(ctx, a); err != nil {
		// Roll back the backing bot user so no orphan user remains.
		botUser.Status = "deleted"
		_ = s.store.Users().UpdateUser(ctx, botUser)
		record(req.Name, "error: "+err.Error())
		s.writeError(w, http.StatusInternalServerError, "Could not record the agent")
		return
	}
	// Reload created_at assigned by store.
	if stored, err := s.store.Agents().GetAgent(ctx, a.ID); err == nil {
		a = stored
	}
	record(a.Username, "created")
	users := map[string]*store.User{owner.ID: owner}
	s.tokenReply(w, toAgentView(a, users), rawToken)
}

func (s *Server) agentFor(w http.ResponseWriter, r *http.Request, ctx context.Context) (*store.Agent, bool) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid agent ID")
		return nil, false
	}
	a, err := s.store.Agents().GetAgent(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "No such agent")
		return nil, false
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not read the agent")
		return nil, false
	}
	return a, true
}

func (s *Server) disconnectBot(ctx context.Context, botUserID string) {
	if s.chatHub != nil && botUserID != "" {
		_ = s.chatHub.RevokeUser(ctx, botUserID)
	}
}

func (s *Server) handleAgentRotate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, record := s.agentAction(r, "agent.rotate")
	defer cancel()
	a, ok := s.agentFor(w, r, ctx)
	if !ok {
		return
	}
	owner, err := s.store.Users().GetUserByID(ctx, a.OwnerUserID)
	if err != nil || owner.Status != "active" {
		record(a.Username, "refused: owner inactive")
		s.writeError(w, http.StatusConflict, "The agent's owner is no longer active")
		return
	}
	rawToken, tokenHash, err := mintAgentToken()
	if err != nil {
		record(a.Username, "error: "+err.Error())
		s.writeError(w, http.StatusInternalServerError, "Could not generate agent token")
		return
	}
	if err := s.store.Agents().SetAgentToken(ctx, a.ID, a.TokenHash, tokenHash, store.AgentTokenActive); err != nil {
		record(a.Username, "error: "+err.Error())
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusConflict, "The agent changed meanwhile; retry rotation")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Could not record the new token")
		return
	}
	s.disconnectBot(ctx, a.UserID)
	outcome := "rotated"
	if a.TokenState != store.AgentTokenActive {
		outcome = "reissued"
	}
	a.TokenHash = tokenHash
	a.TokenState = store.AgentTokenActive
	record(a.Username, outcome)
	users := map[string]*store.User{owner.ID: owner}
	s.tokenReply(w, toAgentView(a, users), rawToken)
}

func (s *Server) revokeAgent(ctx context.Context, a *store.Agent, state string) error {
	for range 3 {
		err := s.store.Agents().SetAgentToken(ctx, a.ID, a.TokenHash, "", state)
		if err == nil {
			a.TokenHash, a.TokenState = "", state
			s.disconnectBot(ctx, a.UserID)
			return nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		a, err = s.store.Agents().GetAgent(ctx, a.ID)
		if err != nil {
			return err
		}
	}
	return errors.New("the agent's token kept changing; try again")
}

func (s *Server) handleAgentRevoke(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, record := s.agentAction(r, "agent.revoke")
	defer cancel()
	a, ok := s.agentFor(w, r, ctx)
	if !ok {
		return
	}
	if err := s.revokeAgent(ctx, a, store.AgentTokenRevoked); err != nil {
		record(a.Username, "error: "+err.Error())
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "No such agent")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Could not revoke the agent token")
		return
	}
	record(a.Username, "revoked")
	s.writeJSON(w, http.StatusOK, map[string]string{"outcome": "revoked"})
}

// handleAgentDelete revokes the token, marks the backing bot user deleted (preserving chat
// history attribution), and deletes the agent row.
func (s *Server) handleAgentDelete(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, record := s.agentAction(r, "agent.delete")
	defer cancel()
	a, ok := s.agentFor(w, r, ctx)
	if !ok {
		return
	}
	if err := s.revokeAgent(ctx, a, store.AgentTokenRevoked); err != nil {
		record(a.Username, "error: "+err.Error())
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "No such agent")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Could not revoke the agent")
		return
	}
	if botUser, err := s.store.Users().GetUserByID(ctx, a.UserID); err == nil {
		botUser.Status = "deleted"
		_ = s.store.Users().UpdateUser(ctx, botUser)
	}
	if err := s.store.Agents().DeleteAgent(ctx, a.ID); err != nil {
		record(a.Username, "error: "+err.Error())
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "No such agent")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Could not delete the agent")
		return
	}
	s.disconnectBot(ctx, a.UserID)
	record(a.Username, "deleted")
	s.writeJSON(w, http.StatusOK, map[string]string{"outcome": "deleted"})
}

// handleAgentSkill serves the skill folder as a zip; it holds no secret.
func (s *Server) handleAgentSkill(w http.ResponseWriter, r *http.Request) {
	data, err := agentskill.Zip()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not build the skill")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="kymessages-skill.zip"`)
	_, _ = w.Write(data)
}

// revokeAgentsForOwner immediately revokes all active bots owned by ownerUserID and closes
// their live WebSockets. Called whenever an owner is disabled or deleted via SSO/SCIM/directory.
func (s *Server) revokeAgentsForOwner(ctx context.Context, ownerUserID string) {
	if s.store == nil || ownerUserID == "" {
		return
	}
	agents, err := s.store.Agents().ListAgentsByOwner(ctx, ownerUserID)
	if err != nil {
		return
	}
	for _, a := range agents {
		if a.TokenState != store.AgentTokenActive {
			continue
		}
		outcome := "revoked"
		if err := s.revokeAgent(ctx, a, store.AgentTokenRevoked); err != nil && !errors.Is(err, store.ErrNotFound) {
			outcome = "error: " + err.Error()
		}
		actx, acancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = s.store.Audit().LogAudit(actx, &store.AuditRecord{
			Action:   "agent.owner_inactive",
			Resource: a.Username,
			Details:  auditFields(outcome, "owner", ownerUserID),
		})
		acancel()
	}
}

// ExpireIdleAgents revokes every active agent token unused for agentIdle (90 days), and
// revokes any active agent whose owner is no longer active. cmd/server's maintenance loop
// runs it hourly.
func (s *Server) ExpireIdleAgents(ctx context.Context, now time.Time) error {
	if s.store == nil {
		return nil
	}
	agents, err := s.store.Agents().ListAgents(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, a := range agents {
		if a.TokenState != store.AgentTokenActive {
			continue
		}
		// Check owner status first: offboarded owners must never keep active bots.
		owner, oerr := s.store.Users().GetUserByID(ctx, a.OwnerUserID)
		if errors.Is(oerr, store.ErrNotFound) || (oerr == nil && owner.Status != "active") {
			outcome := "revoked"
			if err := s.revokeAgent(ctx, a, store.AgentTokenRevoked); err != nil && !errors.Is(err, store.ErrNotFound) {
				errs = append(errs, err)
				outcome = "error: " + err.Error()
			}
			actx, acancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			if err := s.store.Audit().LogAudit(actx, &store.AuditRecord{
				Action:   "agent.owner_inactive",
				Resource: a.Username,
				Details:  auditFields(outcome, "owner", a.OwnerUserID),
			}); err != nil {
				errs = append(errs, err)
			}
			acancel()
			continue
		}
		if oerr != nil {
			errs = append(errs, oerr)
			continue
		}

		since := a.CreatedAt
		if a.LastUsedAt != nil && !a.LastUsedAt.IsZero() {
			since = *a.LastUsedAt
		}
		if since.IsZero() || now.Sub(since) < agentIdle {
			continue
		}
		outcome := "expired"
		if err := s.revokeAgent(ctx, a, store.AgentTokenExpired); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
			outcome = "error: " + err.Error()
		}
		actx, acancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if err := s.store.Audit().LogAudit(actx, &store.AuditRecord{
			Action:   "agent.expire",
			Resource: a.Username,
			Details:  auditFields(outcome, "idle_since", since.UTC().Format(time.RFC3339)),
		}); err != nil {
			errs = append(errs, err)
		}
		acancel()
	}
	return errors.Join(errs...)
}
