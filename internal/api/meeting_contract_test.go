package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

// withKyCalendar pairs the server with KyCalendar (secret testMultiTenantHMAC) and names the
// KyIdentity issuer the meeting bodies carry.
func withKyCalendar(cfg *config.Config) {
	cfg.SSO.Enabled, cfg.SSO.KyIdentityIssuer = true, suiteIssuer
	cfg.KyCalendar = config.PairConfig{URL: "https://cal.example", Secret: []byte(testMultiTenantHMAC)}
}

// calSigned sends body as KyCalendar does (contract B): signed under secret with the route's
// event type, a fresh event ID, and the path's meeting ID as "id" and suiteIssuer as "issuer"
// unless the body names them.
func calSigned(srv http.Handler, secret, method, path string, body map[string]any) *httptest.ResponseRecorder {
	if _, ok := body["id"]; !ok {
		body["id"] = path[strings.LastIndex(path, "/")+1:]
	}
	if _, ok := body["issuer"]; !ok && body["sub"] != nil {
		body["issuer"] = suiteIssuer
	}
	raw, _ := json.Marshal(body)
	event := "kycalendar.meeting.put"
	if method == http.MethodDelete {
		event = "kycalendar.meeting.close"
	}
	h, _ := syncauth.Sign([]byte(secret), time.Now(), event, "evt-"+uuid.NewString(), raw)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	h.Apply(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// KyCalendar's request bytes (internal/kymessages PutRequest and Close on KyCalendar
// origin/main 8bc3104, marshalled verbatim), with the suite env's issuer and org.
const (
	calPutSingle = `{"id":"abcdefghijklmnop_-12","sub":"sub-alice","issuer":"https://id.example","title":"Weekly sync","member_subs":["sub-bob","sub-nobody"]}`
	calPutMulti  = `{"id":"abcdefghijklmnop_-12","sub":"sub-alice","issuer":"https://id.example","org_id":"00000000-0000-4000-8000-00000000000a","title":"Weekly sync","member_subs":["sub-bob","sub-carol","sub-nobody"]}`
	calClose     = `{"id":"abcdefghijklmnop_-12","sub":"sub-alice","issuer":"https://id.example"}`
	calMeetPath  = "/api/meetings/abcdefghijklmnop_-12"
)

func (e *suiteEnv) meetingMembers(tenant, body string) map[string]bool {
	e.t.Helper()
	var res struct {
		RoomID string `json:"room_id"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil || res.RoomID == "" {
		e.t.Fatalf("PUT answer %s", body)
	}
	members, err := e.st.Chat().ListRoomMembers(context.Background(), tenant, res.RoomID)
	if err != nil {
		e.t.Fatal(err)
	}
	in := map[string]bool{}
	for _, m := range members {
		in[m.UserID] = true
	}
	return in
}

// KyCalendar's own bytes, signed with the kycalendar pair secret, create the room with the
// organizer in it, and its close closes it.
func TestKyCalendarMeetingBytesMakeTheOrganizerAMember(t *testing.T) {
	e := newSuiteEnv(t, config.TenancySingle)
	alice, bob := e.user("alice", "user", ""), e.user("bob", "user", "")
	rec := e.do(e.srv, signed{method: http.MethodPut, path: calMeetPath, event: "kycalendar.meeting.put", key: suiteKyCalKey, raw: []byte(calPutSingle)})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	if in := e.meetingMembers(store.DefaultTenantID, rec.Body.String()); !in[alice.ID] || !in[bob.ID] || len(in) != 2 {
		t.Fatalf("members %v, want the organizer and bob", in)
	}
	var res struct {
		MemberURL   string   `json:"member_url"`
		SkippedSubs []string `json:"skipped_subs"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if !strings.HasPrefix(res.MemberURL, suiteAppURL+"/") || len(res.SkippedSubs) != 1 || res.SkippedSubs[0] != suiteUnknownSub {
		t.Fatalf("answer %s", rec.Body.String())
	}
	rec = e.do(e.srv, signed{method: http.MethodDelete, path: calMeetPath, event: "kycalendar.meeting.close", key: suiteKyCalKey, raw: []byte(calClose)})
	if m, _, _, err := e.st.Chat().GetMeeting(context.Background(), store.DefaultTenantID, "abcdefghijklmnop_-12"); rec.Code != http.StatusOK || err != nil || m.ClosedAt == nil {
		t.Fatalf("DELETE = %d %s, meeting %+v err %v", rec.Code, rec.Body.String(), m, err)
	}
}

// Only the kycalendar pair secret, under the route's own event type, is accepted: not
// KyIdentity's HMAC secret (the old fallback), not KyPost's pair, not another route's event.
func TestKyCalendarMeetingRefusesAnotherSecret(t *testing.T) {
	e := newSuiteEnv(t, config.TenancySingle)
	e.user("alice", "user", "")
	for name, s := range map[string]signed{
		"kyidentity hmac": {key: testMultiTenantHMAC, event: "kycalendar.meeting.put"},
		"kypost pair":     {key: suiteKyPostKey, event: "kycalendar.meeting.put"},
		"chat event":      {key: suiteKyCalKey, event: "kycalendar.chat.open"},
		"close event":     {key: suiteKyCalKey, event: "kycalendar.meeting.close"},
	} {
		s.method, s.path, s.raw = http.MethodPut, calMeetPath, []byte(calPutSingle)
		wantCode(t, e.do(e.srv, s), http.StatusUnauthorized, "bad_signature", name)
	}
	close := signed{method: http.MethodDelete, path: calMeetPath, event: "kycalendar.meeting.put", key: suiteKyCalKey, raw: []byte(calClose)}
	wantCode(t, e.do(e.srv, close), http.StatusUnauthorized, "bad_signature", "close under the put event")
	if _, _, _, err := e.st.Chat().GetMeeting(context.Background(), store.DefaultTenantID, "abcdefghijklmnop_-12"); err == nil {
		t.Fatal("a refused PUT created the meeting")
	}
}

// The organizer must be an everyday account under this server's issuer, and the body must
// name the path's meeting.
func TestKyCalendarMeetingOrganizerRules(t *testing.T) {
	e := newSuiteEnv(t, config.TenancySingle)
	e.user("alice", "user", "")
	e.user("root", "admin", "")
	put := func(body string) *httptest.ResponseRecorder {
		return e.do(e.srv, signed{method: http.MethodPut, path: calMeetPath, event: "kycalendar.meeting.put", key: suiteKyCalKey, raw: []byte(body)})
	}
	for name, body := range map[string]string{
		"unknown organizer": strings.Replace(calPutSingle, "sub-alice", suiteUnknownSub, 1),
		"other issuer":      strings.Replace(calPutSingle, "https://id.example", "https://evil.example", 1),
		"administrator":     strings.Replace(calPutSingle, "sub-alice", "sub-root", 1),
	} {
		wantCode(t, put(body), http.StatusNotFound, "no_user", name)
	}
	for name, body := range map[string]string{
		"other meeting":      strings.Replace(calPutSingle, "abcdefghijklmnop_-12", "zzzzzzzzzzzzzzzz_-12", 1),
		"no id":              strings.Replace(calPutSingle, `"id":"abcdefghijklmnop_-12",`, "", 1),
		"organizer_sub only": `{"id":"abcdefghijklmnop_-12","organizer_sub":"sub-alice","title":"x"}`,
	} {
		wantCode(t, put(body), http.StatusBadRequest, "bad_body", name)
	}
	close := signed{method: http.MethodDelete, path: calMeetPath, event: "kycalendar.meeting.close", key: suiteKyCalKey,
		raw: []byte(strings.Replace(calClose, "abcdefghijklmnop_-12", "zzzzzzzzzzzzzzzz_-12", 1))}
	wantCode(t, e.do(e.srv, close), http.StatusBadRequest, "bad_body", "close of another meeting")
}

// Multi mode: the organizer must belong to the body's org; members of another org are skipped,
// never added.
func TestKyCalendarMeetingKeepsToTheOrg(t *testing.T) {
	e := newSuiteEnv(t, config.TenancyMulti)
	alice, bob := e.user("alice", "user", suiteOrgA), e.user("bob", "user", suiteOrgA)
	carol := e.user("carol", "user", suiteOrgB)
	put := func(body string) *httptest.ResponseRecorder {
		return e.do(e.srv, signed{method: http.MethodPut, path: calMeetPath, event: "kycalendar.meeting.put", key: suiteKyCalKey, raw: []byte(body)})
	}
	wantCode(t, put(strings.Replace(calPutMulti, suiteOrgA, suiteOrgB, 1)), http.StatusNotFound, "no_user", "organizer under another org")
	if _, _, _, err := e.st.Chat().GetMeeting(context.Background(), suiteOrgB, "abcdefghijklmnop_-12"); err == nil {
		t.Fatal("another org got the meeting")
	}
	rec := put(calPutMulti)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	in := e.meetingMembers(suiteOrgA, rec.Body.String())
	if !in[alice.ID] || !in[bob.ID] || in[carol.ID] || len(in) != 2 {
		t.Fatalf("members %v, want alice and bob only", in)
	}
	if !strings.Contains(rec.Body.String(), `"skipped_subs":["sub-carol","sub-nobody"]`) {
		t.Fatalf("answer %s", rec.Body.String())
	}
}
