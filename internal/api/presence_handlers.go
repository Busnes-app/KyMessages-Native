package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"

	"github.com/Busnes-app/ky_server_base/internal/presence"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// Per-user budgets an hour (tenancy spec §4.5-§4.7).
const (
	presenceCalendarPerUser = 120
	presenceOOOPerUser      = 60
	presenceMePerUser       = 60
	presenceLookupPerUser   = 300
)

// presenceUser resolves the request's caller (spec §4.2 rule 4) and spends one of their budget.
// It answers 404 no_user, 429 or 503 itself and returns nil.
func (s *Server) presenceUser(w http.ResponseWriter, r *http.Request, ev syncauth.Event, u presence.User, orgID, action string, limit int) *store.User {
	user, err := s.suiteUser(r.Context(), r, u.Sub, u.Issuer, orgID)
	if err != nil {
		s.presenceFailed(w, r, ev, "", action)
		return nil
	}
	if user == nil {
		s.audit(r.Context(), "", r, action, "", "refused: no_user")
		s.suiteRefusal(w, http.StatusNotFound, "no_user", "account not found")
		return nil
	}
	if s.suiteRateLimited(w, ev, action+":"+user.ID, limit) {
		s.audit(r.Context(), user.ID, r, action, "", "refused: rate_limited")
		return nil
	}
	return user
}

func (s *Server) presenceBadBody(w http.ResponseWriter, r *http.Request, action string) {
	s.audit(r.Context(), "", r, action, "", "refused: bad_body")
	s.suiteRefusal(w, http.StatusBadRequest, "bad_body", "Invalid request")
}

// presenceFailed lets the sender retry under the same event ID.
func (s *Server) presenceFailed(w http.ResponseWriter, r *http.Request, ev syncauth.Event, userID, action string) {
	s.forgetSuiteEvent(ev)
	s.audit(r.Context(), userID, r, action, "", "error")
	s.suiteRefusal(w, http.StatusServiceUnavailable, "unavailable", "Try again later")
}

func (s *Server) presenceOutcome(w http.ResponseWriter, r *http.Request, userID, action, outcome string) {
	s.audit(r.Context(), userID, r, action, "", outcome)
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]string{"outcome": outcome})
}

// handlePresenceCalendar answers POST /api/suite/presence/calendar: KyCalendar's busy blocks.
func (s *Server) handlePresenceCalendar(w http.ResponseWriter, r *http.Request) {
	const action = "presence.calendar"
	body, ev, ok := s.verifySuite(w, r, s.kycal, presence.EventBusy)
	if !ok {
		return
	}
	orgID, rest, err := s.suitePayload(body)
	p, derr := presence.DecodeBusy(rest, time.Now())
	if err != nil || derr != nil {
		s.presenceBadBody(w, r, action)
		return
	}
	user := s.presenceUser(w, r, ev, p.User, orgID, action, presenceCalendarPerUser)
	if user == nil {
		return
	}
	busy := make([]store.BusyWindow, len(p.Busy))
	for i, b := range p.Busy {
		busy[i] = store.BusyWindow{Start: b.Start, End: b.End}
	}
	out, err := s.store.Presence().SetCalendar(r.Context(), s.suiteTenant(orgID), user.ID, p.Revision, busy)
	if err != nil {
		s.presenceFailed(w, r, ev, user.ID, action)
		return
	}
	s.presenceOutcome(w, r, user.ID, action, string(out))
}

// handlePresenceOOO answers POST /api/suite/presence/out-of-office: KyPost's out-of-office.
func (s *Server) handlePresenceOOO(w http.ResponseWriter, r *http.Request) {
	const action = "presence.ooo"
	body, ev, ok := s.verifySuite(w, r, s.kypost, presence.EventOOO)
	if !ok {
		return
	}
	orgID, rest, err := s.suitePayload(body)
	p, derr := presence.DecodeOOO(rest)
	if err != nil || derr != nil {
		s.presenceBadBody(w, r, action)
		return
	}
	user := s.presenceUser(w, r, ev, p.User, orgID, action, presenceOOOPerUser)
	if user == nil {
		return
	}
	var start, end time.Time
	if p.Away {
		start, end = *p.Start, *p.End
	}
	out, err := s.store.Presence().SetOutOfOffice(r.Context(), s.suiteTenant(orgID), user.ID, p.Revision, start, end)
	if err != nil {
		s.presenceFailed(w, r, ev, user.ID, action)
		return
	}
	s.presenceOutcome(w, r, user.ID, action, string(out))
}

type presenceManual struct {
	State string    `json:"state"`
	Until time.Time `json:"until"`
}

// handlePresenceMe answers POST /api/suite/presence/me: the user's own switch and manual
// status, after any change the request asks for.
func (s *Server) handlePresenceMe(w http.ResponseWriter, r *http.Request) {
	const action = "presence.me"
	body, ev, ok := s.verifySuite(w, r, s.kycal, presence.EventMe)
	if !ok {
		return
	}
	now := time.Now()
	orgID, rest, err := s.suitePayload(body)
	req, manual, clear, derr := presence.DecodeMe(rest, now)
	if err != nil || derr != nil {
		s.presenceBadBody(w, r, action)
		return
	}
	user := s.presenceUser(w, r, ev, req.User, orgID, action, presenceMePerUser)
	if user == nil {
		return
	}
	st, tenant, outcome := s.store.Presence(), s.suiteTenant(orgID), "read"
	if req.Share != nil {
		if err := st.SetSharing(r.Context(), tenant, user.ID, *req.Share); err != nil {
			s.presenceFailed(w, r, ev, user.ID, action)
			return
		}
		outcome = "changed"
	}
	if manual != nil || clear {
		m := presence.Manual{}
		if manual != nil {
			m = *manual
		}
		err := st.SetManual(r.Context(), tenant, user.ID, m.State, m.Until)
		if errors.Is(err, store.ErrSharingOff) {
			s.audit(r.Context(), user.ID, r, action, "", "refused: sharing_off")
			s.suiteRefusal(w, http.StatusConflict, "sharing_off", "Turn on status sharing first")
			return
		}
		if err != nil {
			s.presenceFailed(w, r, ev, user.ID, action)
			return
		}
		outcome = "changed"
	}
	rows, err := st.Presence(r.Context(), tenant, []string{user.ID})
	if err != nil {
		s.presenceFailed(w, r, ev, user.ID, action)
		return
	}
	p := rows[user.ID]
	out := map[string]any{"share": !p.ShareOff, "manual": nil}
	if p.ManualState != "" && now.Before(p.ManualUntil) {
		out["manual"] = presenceManual{p.ManualState, p.ManualUntil}
	}
	s.audit(r.Context(), user.ID, r, action, "", outcome)
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, out)
}

type presencePerson struct {
	Sub   string     `json:"sub"`
	State string     `json:"state"`
	Until *time.Time `json:"until,omitempty"`
}

// handlePresenceLookup answers POST /api/suite/presence/lookup: colleagues' coarse status.
// Anyone outside the caller's org, and anyone who opted out, reads unknown.
func (s *Server) handlePresenceLookup(w http.ResponseWriter, r *http.Request) {
	const action = "presence.lookup"
	pair, event := s.kypost, presence.EventLookupKyPost
	if syncauth.FromRequest(r).EventType == presence.EventLookupKyCalendar {
		pair, event = s.kycal, presence.EventLookupKyCalendar
	}
	body, ev, ok := s.verifySuite(w, r, pair, event)
	if !ok {
		return
	}
	orgID, rest, err := s.suitePayload(body)
	if err != nil {
		s.presenceBadBody(w, r, action)
		return
	}
	req, err := presence.DecodeLookup(rest)
	if errors.Is(err, presence.ErrTooMany) {
		s.audit(r.Context(), "", r, action, "", "refused: too_many via="+pair.client)
		s.suiteRefusal(w, http.StatusBadRequest, "too_many", "At most 50 people at a time")
		return
	}
	if err != nil {
		s.presenceBadBody(w, r, action)
		return
	}
	user := s.presenceUser(w, r, ev, req.User, orgID, action, presenceLookupPerUser)
	if user == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	// Only active everyday accounts in the caller's org are looked up (spec §4.2 rule 5).
	ids := make(map[string]string, len(req.Subs))
	var members []string
	for _, sub := range req.Subs {
		u, err := s.suiteAccount(ctx, sub)
		if err != nil {
			s.presenceFailed(w, r, ev, user.ID, action)
			return
		}
		if u != nil && (!s.config.Tenancy.IsMultiTenant() || u.OrgID == orgID) {
			ids[sub] = u.ID
			members = append(members, u.ID)
		}
	}
	rows, err := s.store.Presence().Presence(ctx, s.suiteTenant(orgID), members)
	if err != nil {
		s.presenceFailed(w, r, ev, user.ID, action)
		return
	}
	now := time.Now()
	people := make([]presencePerson, len(req.Subs))
	for i, sub := range req.Subs {
		id, member := ids[sub]
		p, ok := rows[id]
		state, until := presence.Status(p, member && ok, now)
		people[i] = presencePerson{Sub: sub, State: state}
		if !until.IsZero() {
			u := until.UTC()
			people[i].Until = &u
		}
	}
	s.audit(r.Context(), user.ID, r, action, "", "answered via="+pair.client+" count="+strconv.Itoa(len(req.Subs)))
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]any{"people": people})
}
