package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/ky-primitives/syncauth"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// Signed suite peer routes (docs/superpowers/specs/2026-11-22-tenancy-design.md §4).
const (
	chatEventKyPost     = "kypost.chat.open"
	chatEventKyCalendar = "kycalendar.chat.open"
	chatPerUser         = 60 // lookups per caller an hour, across both pairs
	suiteMaxBody        = 64 << 10
	// suiteReplayKeep outlives the ±5 minute signature window by far, so a pruned ID can never
	// verify again.
	suiteReplayKeep = 24 * time.Hour
)

// Pair lookup timing. Variables so tests can shorten them.
var (
	pairFirstWait = 5 * time.Second
	pairRefresh   = time.Hour   // a working pair is fetched again this often
	pairRetry     = time.Minute // first retry after a failure, doubling up to pairRefresh
	pairMinGap    = time.Minute // a kick (a refused signature) waits this long after the last lookup
)

// Why a suite pair is missing (pairView.Reason).
const (
	pairPending       = "pending"
	pairNoKyIdentity  = "no_kyidentity"
	pairNoPeer        = "no_peer"
	pairUnauthorized  = "unauthorized"
	pairUnreachable   = "unreachable"
	pairInvalidPeer   = "invalid_peer"
	pairNoCredentials = "no_credentials"
)

const (
	pairSourceEnvironment = "environment"
	pairSourceKyIdentity  = "kyidentity"
)

var errSuiteBadBody = errors.New("suite: bad body")

// suitePeer is one paired app's origin and secret. The secret lives only here, in memory.
type suitePeer struct {
	URL    string
	Secret []byte
	Source string
}

// suitePair is one suite app paired with KyMessages: the environment's pair when it names one,
// else KyIdentity's, kept fresh.
type suitePair struct {
	client string // suitedir client ID, also the refusal code prefix and log name
	env    config.PairConfig
	kick   chan struct{}

	mu      sync.Mutex
	peer    *suitePeer
	reason  string    // "" while paired
	checked time.Time // the last lookup; zero for an environment pair
}

func newSuitePair(client string, env config.PairConfig) *suitePair {
	p := &suitePair{client: client, env: env, kick: make(chan struct{}, 1), reason: pairPending}
	if env.URL != "" {
		p.peer, p.reason = &suitePeer{URL: env.URL, Secret: env.Secret, Source: pairSourceEnvironment}, ""
	}
	return p
}

func (p *suitePair) Peer() *suitePeer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peer
}

func (p *suitePair) state() (*suitePeer, string, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peer, p.reason, p.checked
}

func (p *suitePair) setPeer(peer *suitePeer, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.peer, p.reason, p.checked = peer, reason, time.Now()
}

// kickNow asks for a lookup soon: the peer signed with a secret we do not hold.
func (p *suitePair) kickNow() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// StartSuitePairs pairs KyPost and KyCalendar through KyIdentity where the environment names
// none: it waits up to pairFirstWait for the first lookups, then keeps the pairs fresh until
// ctx ends. cmd/server calls it before serving.
func (s *Server) StartSuitePairs(ctx context.Context) {
	first, cancel := context.WithTimeout(ctx, pairFirstWait)
	defer cancel()
	var wg sync.WaitGroup
	for _, p := range []*suitePair{s.kypost, s.kycal} {
		if p.env.URL == "" {
			wg.Go(func() {
				ok := s.resolvePair(first, p)
				go s.pairLoop(ctx, p, ok)
			})
		}
	}
	wg.Wait()
}

func (s *Server) pairLoop(ctx context.Context, p *suitePair, ok bool) {
	last, failures := time.Now(), 0
	if !ok {
		failures = 1
	}
	for {
		wait := pairRefresh
		if failures > 0 {
			wait = min(pairRetry<<min(failures-1, 16), pairRefresh)
		}
		next := last.Add(wait)
	sleep:
		for {
			t := time.NewTimer(time.Until(next))
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
				break sleep
			case <-p.kick:
				t.Stop()
				if soon := last.Add(pairMinGap); soon.Before(next) {
					next = soon
				}
			}
		}
		last = time.Now()
		if s.resolvePair(ctx, p) {
			failures = 0
		} else {
			failures++
		}
	}
}

// resolvePair asks KyIdentity for p's app and pairs it, reporting whether the lookup worked. A
// refusal unpairs; an unreachable KyIdentity keeps a pair it issued. The secret is never logged.
func (s *Server) resolvePair(ctx context.Context, p *suitePair) bool {
	dir, err := s.kyidentity.SuiteDirectory()
	if err != nil {
		return p.unpair(pairNoCredentials, err)
	}
	if dir == nil {
		return p.unpair(pairNoKyIdentity, nil)
	}
	peer, err := dir.Peer(ctx, p.client)
	switch {
	case errors.Is(err, suitedir.ErrNoPeer):
		return p.unpair(pairNoPeer, nil)
	case errors.Is(err, suitedir.ErrUnauthorized):
		return p.unpair(pairUnauthorized, err)
	case err != nil:
		if p.Peer() != nil {
			log.Printf("[%s] KyIdentity lookup failed, keeping the current pair: %v", strings.ToUpper(p.client), err)
			return false
		}
		return p.unpair(pairUnreachable, err)
	}
	u, err := config.PeerOrigin(peer.URL)
	if err != nil {
		return p.unpair(pairInvalidPeer, nil)
	}
	if cur := p.Peer(); cur == nil || cur.URL != u || !bytes.Equal(cur.Secret, peer.Secret) {
		log.Printf("[%s] paired through KyIdentity: %s", strings.ToUpper(p.client), u)
	}
	p.setPeer(&suitePeer{URL: u, Secret: peer.Secret, Source: pairSourceKyIdentity}, "")
	return true
}

// unpair drops the pair for reason, logging once per change of reason.
func (p *suitePair) unpair(reason string, err error) bool {
	if _, prev, _ := p.state(); prev != reason {
		if err != nil {
			log.Printf("[%s] not paired through KyIdentity (%s): %v", strings.ToUpper(p.client), reason, err)
		} else {
			log.Printf("[%s] not paired through KyIdentity (%s)", strings.ToUpper(p.client), reason)
		}
	}
	p.setPeer(nil, reason)
	return false
}

// pairView is the console's row for a pair. It never carries the secret.
type pairView struct {
	Connected bool       `json:"connected"`
	Source    string     `json:"source,omitempty"`
	URL       string     `json:"url,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}

// handlePairStatus answers GET /api/admin/kypost and /api/admin/kycalendar.
func (s *Server) handlePairStatus(p *suitePair) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var v pairView
		peer, reason, checked := p.state()
		if !checked.IsZero() {
			v.CheckedAt = &checked
		}
		if peer != nil {
			v.Connected, v.Source, v.URL = true, peer.Source, peer.URL
		} else {
			v.Reason = reason
		}
		w.Header().Set("Cache-Control", "no-store")
		s.writeJSON(w, http.StatusOK, v)
	}
}

// errReplayStore marks a replay ledger that could not answer, so the caller answers 503.
var errReplayStore = errors.New("suite: replay ledger unavailable")

// dbReplay is syncauth's replay guard on suite_replay_events, shared by every replica.
type dbReplay struct {
	ctx context.Context
	st  store.SuiteReplayStore
}

func (d dbReplay) Check(id string, at time.Time) error {
	fresh, err := d.st.Record(d.ctx, id, time.Now().Unix(), at.Add(suiteReplayKeep).Unix())
	switch {
	case err != nil:
		return errors.Join(errReplayStore, err)
	case !fresh:
		return syncauth.ErrReplay
	}
	return nil
}

// suiteRefusal answers a suite peer with the contract's {"error","code"} body.
func (s *Server) suiteRefusal(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, status, map[string]string{"error": msg, "code": code})
}

// verifySuite reads and verifies one signed request for eventType under pair's secret, and
// records its event ID. It answers the request itself (refusal, or 200 duplicate for a
// replay) and returns ok false when the handler must stop.
func (s *Server) verifySuite(w http.ResponseWriter, r *http.Request, pair *suitePair, eventType string) (body []byte, ev syncauth.Event, ok bool) {
	peer := pair.Peer()
	if peer == nil {
		s.suiteRefusal(w, http.StatusNotFound, pair.client+"_off", "Not paired with this server")
		return nil, ev, false
	}
	headers := syncauth.FromRequest(r)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, suiteMaxBody))
	if err == nil && headers.EventType != eventType {
		err = syncauth.ErrBadSignature
	}
	if err == nil {
		ev, err = syncauth.Verify(peer.Secret, headers, body, syncauth.Options{Replay: dbReplay{r.Context(), s.store.SuiteReplay()}})
	}
	switch {
	case err == nil:
		return body, ev, true
	case errors.Is(err, syncauth.ErrReplay):
		w.Header().Set("Cache-Control", "no-store")
		s.writeJSON(w, http.StatusOK, map[string]string{"outcome": "duplicate"})
	case errors.Is(err, errReplayStore):
		log.Printf("[SUITE] replay ledger unavailable: %v", err)
		s.suiteRefusal(w, http.StatusServiceUnavailable, "unavailable", "Try again later")
	default:
		if peer.Source == pairSourceKyIdentity && errors.Is(err, syncauth.ErrBadSignature) {
			pair.kickNow() // the peer may hold a rotated secret; lookups stay rate limited
		}
		s.suiteRefusal(w, http.StatusUnauthorized, "bad_signature", "Bad signature")
	}
	return nil, ev, false
}

// forgetSuiteEvent releases a recorded event ID after a refusal the sender should retry
// (429, 503), so the retry under the same ID is processed instead of acknowledged as a replay.
func (s *Server) forgetSuiteEvent(ev syncauth.Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.store.SuiteReplay().Forget(ctx, ev.ID); err != nil {
		log.Printf("[SUITE] could not release event %q: %v", ev.ID, err)
	}
}

// suiteOrgID applies the org_id rule for the tenancy mode to one JSON object: in multi a
// canonical lowercase UUID is required and returned; in single the key must be absent (even
// as "" or null). It also returns the object's fields without org_id.
func (s *Server) suiteOrgID(body []byte) (string, map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return "", nil, errSuiteBadBody
	}
	raw, has := fields["org_id"]
	delete(fields, "org_id")
	if !s.config.Tenancy.IsMultiTenant() {
		if has {
			return "", nil, errSuiteBadBody
		}
		return "", fields, nil
	}
	var orgID string
	if !has || json.Unmarshal(raw, &orgID) != nil || !config.IsCanonicalUUID(orgID) {
		return "", nil, errSuiteBadBody
	}
	return orgID, fields, nil
}

// decodeSuiteBody checks org_id with suiteOrgID, then strictly decodes the remaining fields
// into v (unknown fields refused). v must not declare org_id itself.
func (s *Server) decodeSuiteBody(body []byte, v any) (string, error) {
	orgID, fields, err := s.suiteOrgID(body)
	if err != nil {
		return "", err
	}
	rest, err := json.Marshal(fields)
	if err != nil {
		return "", errSuiteBadBody
	}
	dec := json.NewDecoder(bytes.NewReader(rest))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		return "", errSuiteBadBody
	}
	return orgID, nil
}

// suiteText is 1 to max bytes of UTF-8 without control characters.
func suiteText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

// suiteUser resolves (sub, issuer) to an active everyday account: never an administrator,
// and in multi mode only one bound to orgID in an active org. Every miss is nil with no error,
// so callers answer it exactly like an unknown subject; err is only a store failure.
func (s *Server) suiteUser(ctx context.Context, r *http.Request, sub, issuer, orgID string) (*store.User, error) {
	want := s.kyidentity.EffectiveIssuer()
	if want == "" || strings.TrimRight(issuer, "/") != want {
		return nil, nil
	}
	u, err := s.store.Users().GetUserBySSO(ctx, "kyidentity", sub)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if u.Status != "active" || u.Role != "user" {
		return nil, nil
	}
	if !s.config.Tenancy.IsMultiTenant() {
		return u, nil
	}
	if u.OrgID != orgID {
		s.audit(ctx, u.ID, r, "suite.org_mismatch", "suite", "")
		return nil, nil
	}
	active, err := s.isTenantActive(ctx, orgID)
	if err != nil || !active {
		return nil, err
	}
	return u, nil
}

// suiteRateLimited counts one request against key and, over limit, releases the event and
// answers 429 with Retry-After.
func (s *Server) suiteRateLimited(w http.ResponseWriter, ev syncauth.Event, key string, limit int) bool {
	if s.allowAccountAttempt(key, limit, time.Hour) {
		return false
	}
	s.forgetSuiteEvent(ev)
	w.Header().Set("Retry-After", strconv.Itoa(int(s.accountAttempts.resetIn(key).Seconds())+1))
	s.suiteRefusal(w, http.StatusTooManyRequests, "rate_limited", "Too many requests")
	return true
}

// handleSuiteChat answers POST /api/suite/chat with a link that opens a DM with the target
// in this PWA. It creates nothing; the PWA opens the DM under the user's own session.
func (s *Server) handleSuiteChat(w http.ResponseWriter, r *http.Request) {
	// The event type picks the pair; Verify then requires that pair's secret, so neither app
	// can speak for the other.
	pair, event := s.kypost, chatEventKyPost
	if syncauth.FromRequest(r).EventType == chatEventKyCalendar {
		pair, event = s.kycal, chatEventKyCalendar
	}
	body, ev, ok := s.verifySuite(w, r, pair, event)
	if !ok {
		return
	}
	via := "via=" + pair.client
	var req struct {
		Sub       string `json:"sub"`
		Issuer    string `json:"issuer"`
		TargetSub string `json:"target_sub"`
	}
	orgID, err := s.decodeSuiteBody(body, &req)
	if err != nil || !suiteText(req.Sub, 255) || !suiteText(req.Issuer, 512) || !suiteText(req.TargetSub, 255) {
		s.audit(r.Context(), "", r, "chat.open", "", "refused: bad_body "+via)
		s.suiteRefusal(w, http.StatusBadRequest, "bad_body", "Invalid request")
		return
	}
	caller, err := s.suiteUser(r.Context(), r, req.Sub, req.Issuer, orgID)
	if err != nil {
		s.forgetSuiteEvent(ev)
		s.suiteRefusal(w, http.StatusServiceUnavailable, "unavailable", "Try again later")
		return
	}
	if caller == nil {
		s.audit(r.Context(), "", r, "chat.open", "", "refused: no_user "+via)
		s.suiteRefusal(w, http.StatusNotFound, "no_user", "account not found")
		return
	}
	if s.suiteRateLimited(w, ev, "suite-chat:"+caller.ID, chatPerUser) {
		s.audit(r.Context(), caller.ID, r, "chat.open", "", "refused: rate_limited "+via)
		return
	}
	var target *store.User
	if req.TargetSub != req.Sub {
		if target, err = s.suiteUser(r.Context(), r, req.TargetSub, req.Issuer, orgID); err != nil {
			s.forgetSuiteEvent(ev)
			s.suiteRefusal(w, http.StatusServiceUnavailable, "unavailable", "Try again later")
			return
		}
	}
	if target == nil {
		s.audit(r.Context(), caller.ID, r, "chat.open", "", "refused: no_target "+via)
		s.suiteRefusal(w, http.StatusNotFound, "no_target", "This person isn't on KyMessages yet")
		return
	}
	s.audit(r.Context(), caller.ID, r, "chat.open", target.ID, "opened "+via)
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]string{"url": strings.TrimRight(s.config.Server.AppURL, "/") + "/#dm=" + target.ID})
}
