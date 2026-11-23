package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
)

// presence event types, their routes and the pair secret each verifies under.
var presenceRoutes = map[string]struct{ path, key string }{
	"kycalendar.presence.busy":   {"/api/suite/presence/calendar", suiteKyCalKey},
	"kycalendar.presence.me":     {"/api/suite/presence/me", suiteKyCalKey},
	"kypost.presence.ooo":        {"/api/suite/presence/out-of-office", suiteKyPostKey},
	"kypost.presence.lookup":     {"/api/suite/presence/lookup", suiteKyPostKey},
	"kycalendar.presence.lookup": {"/api/suite/presence/lookup", suiteKyCalKey},
}

func (e *suiteEnv) presence(event string, body map[string]any) *httptest.ResponseRecorder {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	route := presenceRoutes[event]
	return e.do(e.srv, signed{path: route.path, event: event, key: route.key, raw: raw})
}

// pbody is a presence body for sub, with org_id when org is set, plus kv pairs.
func pbody(sub, org string, kv ...any) map[string]any {
	m := map[string]any{"sub": sub, "issuer": suiteIssuer}
	if org != "" {
		m["org_id"] = org
	}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func window(from, to time.Duration) map[string]string {
	now := time.Now().UTC().Truncate(time.Second)
	return map[string]string{"start": now.Add(from).Format(time.RFC3339), "end": now.Add(to).Format(time.RFC3339)}
}

type personStatus struct {
	Sub   string     `json:"sub"`
	State string     `json:"state"`
	Until *time.Time `json:"until"`
}

func (e *suiteEnv) lookup(caller, org string, subs ...string) map[string]personStatus {
	e.t.Helper()
	rec := e.presence("kypost.presence.lookup", pbody(caller, org, "subs", subs))
	if rec.Code != http.StatusOK {
		e.t.Fatalf("lookup = %d %s", rec.Code, rec.Body.String())
	}
	var resp struct{ People []personStatus }
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.People) != len(subs) {
		e.t.Fatalf("lookup answered %d of %d", len(resp.People), len(subs))
	}
	out := map[string]personStatus{}
	for i, p := range resp.People {
		if p.Sub != subs[i] {
			e.t.Fatalf("lookup order: %v", resp.People)
		}
		out[p.Sub] = p
	}
	return out
}

func wantOutcome(t *testing.T, rec *httptest.ResponseRecorder, outcome, what string) {
	t.Helper()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"outcome":"`+outcome+`"`) {
		t.Fatalf("%s = %d %s, want outcome %s", what, rec.Code, rec.Body.String(), outcome)
	}
}

func TestSuitePresenceMultiTenant(t *testing.T) {
	e := newSuiteEnv(t, config.TenancyMulti)
	alice := e.user("alice", "user", suiteOrgA)
	bob := e.user("bob", "user", suiteOrgA)
	dan := e.user("dan", "user", suiteOrgA)
	carol := e.user("carol", "user", suiteOrgB)
	staff := e.user("staff", "admin", testStaffOrg)

	// Inputs: Bob out of office, Dan in back-to-back meetings, Carol (org B) out of office.
	wantOutcome(t, e.presence("kypost.presence.ooo", pbody(bob.SSOSubject, suiteOrgA, "revision", 2, "away", true, "start", window(-time.Hour, 0)["start"], "end", window(0, 48*time.Hour)["end"])), "applied", "bob ooo")
	wantOutcome(t, e.presence("kypost.presence.ooo", pbody(bob.SSOSubject, suiteOrgA, "revision", 1, "away", false)), "stale", "older ooo")
	wantOutcome(t, e.presence("kycalendar.presence.busy", pbody(dan.SSOSubject, suiteOrgA, "revision", 1, "busy", []map[string]string{window(-time.Hour, time.Hour), window(time.Hour, 2*time.Hour)})), "applied", "dan busy")
	wantOutcome(t, e.presence("kypost.presence.ooo", pbody(carol.SSOSubject, suiteOrgB, "revision", 1, "away", true, "start", window(-time.Hour, 0)["start"], "end", window(0, time.Hour)["end"])), "applied", "carol ooo")

	got := e.lookup(alice.SSOSubject, suiteOrgA, bob.SSOSubject, dan.SSOSubject, carol.SSOSubject, staff.SSOSubject, suiteUnknownSub)
	if got[bob.SSOSubject].State != "out_of_office" || got[bob.SSOSubject].Until == nil {
		t.Fatalf("bob = %+v", got[bob.SSOSubject])
	}
	if d := got[dan.SSOSubject]; d.State != "in_a_meeting" || d.Until == nil || d.Until.Sub(time.Now()) < 90*time.Minute {
		t.Fatalf("dan = %+v, want in_a_meeting until the end of the merged run", d)
	}
	// #4 and #8: another org, an administrator and an unknown subject all read the same unknown.
	for _, sub := range []string{carol.SSOSubject, staff.SSOSubject, suiteUnknownSub} {
		if p := got[sub]; p.State != "unknown" || p.Until != nil {
			t.Fatalf("%s = %+v, want unknown", sub, p)
		}
	}

	// #1 a wrong org_id answers exactly like an unknown subject on every presence route.
	for event := range presenceRoutes {
		body := map[string]any{"revision": 9, "away": false, "busy": []any{}, "subs": []string{bob.SSOSubject}}
		switch event {
		case "kypost.presence.ooo":
			delete(body, "busy")
			delete(body, "subs")
		case "kycalendar.presence.busy":
			delete(body, "away")
			delete(body, "subs")
		case "kycalendar.presence.me":
			body = map[string]any{}
		default:
			body = map[string]any{"subs": []string{bob.SSOSubject}}
		}
		kv := func(org, sub string) map[string]any {
			m := pbody(sub, org)
			for k, v := range body {
				m[k] = v
			}
			return m
		}
		unknown := e.presence(event, kv(suiteOrgA, suiteUnknownSub))
		wantCode(t, unknown, http.StatusNotFound, "no_user", event+" unknown sub")
		wrong := e.presence(event, kv(suiteOrgB, alice.SSOSubject))
		if wrong.Code != unknown.Code || wrong.Body.String() != unknown.Body.String() {
			t.Fatalf("%s wrong org = %d %s, want the unknown-sub answer %s", event, wrong.Code, wrong.Body, unknown.Body)
		}
		// #2 missing or malformed org_id.
		for _, org := range []any{nil, "", strings.ToUpper(suiteOrgA), 7} {
			m := kv("", alice.SSOSubject)
			if org != nil {
				m["org_id"] = org
			}
			wantCode(t, e.presence(event, m), http.StatusBadRequest, "bad_body", event+" bad org_id")
		}
	}
}

func TestSuitePresenceSingleTenantAndPrivacy(t *testing.T) {
	e := newSuiteEnv(t, config.TenancySingle)
	alice := e.user("alice", "user", "")
	bob := e.user("bob", "user", "")

	// #7 the single-tenant wire is unchanged: no org_id in, none out.
	end := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	wantOutcome(t, e.presence("kypost.presence.ooo", pbody(bob.SSOSubject, "", "revision", 1, "away", true, "start", time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), "end", end.Format(time.RFC3339))), "applied", "ooo")
	raw, _ := json.Marshal(pbody(alice.SSOSubject, "", "subs", []string{bob.SSOSubject}))
	rec := e.do(e.srv, signed{path: "/api/suite/presence/lookup", event: "kypost.presence.lookup", raw: raw})
	if want := `{"people":[{"sub":"` + bob.SSOSubject + `","state":"out_of_office","until":"` + end.Format(time.RFC3339) + `"}]}` + "\n"; rec.Body.String() != want {
		t.Fatalf("single lookup = %q, want %q", rec.Body.String(), want)
	}
	// #3 org_id is refused in single mode on every presence route.
	for event := range presenceRoutes {
		for _, org := range []any{suiteOrgA, "", nil} {
			m := pbody(alice.SSOSubject, "", "subs", []string{bob.SSOSubject})
			m["org_id"] = org
			wantCode(t, e.presence(event, m), http.StatusBadRequest, "bad_body", event+" single org_id")
		}
	}

	// #9 privacy: reply text and unknown fields are refused; too many people; sharing off.
	wantCode(t, e.presence("kypost.presence.ooo", pbody(bob.SSOSubject, "", "revision", 3, "away", false, "comment_html", "<p>away</p>")), http.StatusBadRequest, "bad_body", "ooo reply text")
	subs := make([]string, 51)
	for i := range subs {
		subs[i] = "sub-x"
	}
	wantCode(t, e.presence("kypost.presence.lookup", pbody(alice.SSOSubject, "", "subs", subs)), http.StatusBadRequest, "too_many", "51 people")
	me := e.presence("kycalendar.presence.me", pbody(bob.SSOSubject, "", "share", false, "manual", nil))
	if me.Code != http.StatusOK || me.Body.String() != `{"manual":null,"share":false}`+"\n" {
		t.Fatalf("sharing off = %d %s", me.Code, me.Body.String())
	}
	if p := e.lookup(alice.SSOSubject, "", bob.SSOSubject)[bob.SSOSubject]; p.State != "unknown" {
		t.Fatalf("opted-out bob = %+v", p)
	}
	wantOutcome(t, e.presence("kypost.presence.ooo", pbody(bob.SSOSubject, "", "revision", 4, "away", false)), "sharing_off", "ooo while off")
	until := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	wantCode(t, e.presence("kycalendar.presence.me", pbody(bob.SSOSubject, "", "manual", map[string]string{"state": "busy", "until": until})), http.StatusConflict, "sharing_off", "manual while off")
	// Back on with a manual status, which wins over everything else.
	if rec := e.presence("kycalendar.presence.me", pbody(bob.SSOSubject, "", "share", true)); rec.Code != http.StatusOK {
		t.Fatalf("share on = %d", rec.Code)
	}
	if rec := e.presence("kycalendar.presence.me", pbody(bob.SSOSubject, "", "manual", map[string]string{"state": "busy", "until": until})); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"busy"`) {
		t.Fatalf("manual = %d %s", rec.Code, rec.Body.String())
	}
	if p := e.lookup(alice.SSOSubject, "", bob.SSOSubject)[bob.SSOSubject]; p.State != "busy" || p.Until != nil {
		t.Fatalf("manual bob = %+v", p)
	}
	// Each presence event verifies only under its own pair.
	wantCode(t, e.do(e.srv, signed{path: "/api/suite/presence/out-of-office", event: "kypost.presence.ooo", key: suiteKyCalKey, raw: []byte(`{}`)}), http.StatusUnauthorized, "bad_signature", "ooo under the kycalendar secret")
	wantCode(t, e.do(e.srv, signed{path: "/api/suite/presence/calendar", event: "kypost.presence.ooo", raw: []byte(`{}`)}), http.StatusUnauthorized, "bad_signature", "ooo event on the calendar route")
}
