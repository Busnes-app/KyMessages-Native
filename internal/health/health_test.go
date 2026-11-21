package health

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckIsParallelAndBounded(t *testing.T) {
	block := func(ctx context.Context) (string, error) { <-ctx.Done(); return "", ctx.Err() }
	probes := []Probe{{"a", block}, {"b", block}, {"c", block}, {"d", block}, {"e", block}}
	start := time.Now()
	got := Check(context.Background(), 200*time.Millisecond, probes)
	if d := time.Since(start); d > 700*time.Millisecond {
		t.Fatalf("took %s: probes ran in series or ignored the timeout", d)
	}
	for i, c := range got {
		if c.Name != probes[i].Name || c.Status != "down" || !strings.Contains(c.Error, "deadline exceeded") {
			t.Errorf("%+v", c)
		}
	}
}

func TestResultFormatsVersionAndRefusesOddText(t *testing.T) {
	app := result("kymessages", "v0.4.2", nil, nil)
	if app.Status != "up" || app.Version != "0.4.2" || app.Error != "" {
		t.Errorf("app: %+v", app)
	}
	for _, v := range []string{"<html><body>", "javascript:alert(1)", strings.Repeat("9", 80)} {
		c := result("kymessages", v, nil, nil)
		if c.Version != "" || c.Status != "up" || c.Error != "unrecognised version string" {
			t.Errorf("%q: %+v", v, c)
		}
	}
}

func TestResultRedactsSecrets(t *testing.T) {
	c := result("livekit", "", errors.New(`secret "hunter2" rejected for hunter2`), []string{"", "hunter2"})
	if c.Status != "down" || strings.Contains(c.Error, "hunter2") || !strings.Contains(c.Error, "[redacted]") {
		t.Errorf("%+v", c)
	}
	u := result("livekit", "", versionUnknown{errors.New("version header missing")}, nil)
	if u.Status != "up" || u.Error != "version unknown: version header missing" {
		t.Errorf("version unknown: %+v", u)
	}
}

func TestLiveKitProbe(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, "OK")
			return
		}
		http.NotFound(w, r)
	}))
	defer okSrv.Close()

	hc := NewHTTPClient()
	if v, err := LiveKit(hc, okSrv.URL)(context.Background()); err != nil || v != "" {
		t.Fatalf("healthy livekit: %q %v", v, err)
	}

	downSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer downSrv.Close()
	if _, err := LiveKit(hc, downSrv.URL)(context.Background()); err == nil {
		t.Fatal("503 livekit passed")
	}
}

func TestCheckReturnsAtDeadlineWhenProbeIgnoresContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	stuck := func(context.Context) (string, error) { <-release; return "1.0.0", nil }
	fine := func(context.Context) (string, error) { return "0.4.2", nil }
	start := time.Now()
	got := Check(context.Background(), 100*time.Millisecond, []Probe{{"livekit", stuck}, {"kymessages", fine}})
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("took %s", d)
	}
	if got[0].Status != "down" || !strings.Contains(got[0].Error, "timed out") || got[0].Version != "" {
		t.Errorf("stuck: %+v", got[0])
	}
	if got[1].Status != "up" || got[1].Version != "0.4.2" {
		t.Errorf("fine: %+v", got[1])
	}
}
