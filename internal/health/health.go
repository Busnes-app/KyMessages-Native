// Package health probes each component of a KyMessages deployment once, in parallel.
package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Component is one probe's result. Error is probe text for the admin screen; secrets passed
// to Check are redacted from it.
type Component struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // "up" or "down"
	Version  string `json:"version"`
	Pinned   string `json:"pinned"`
	Mismatch bool   `json:"mismatch"`
	Source   string `json:"source"`
	Error    string `json:"error"`
}

// Probe checks one component and returns its running version ("" when it has none).
type Probe struct {
	Name string
	Run  func(ctx context.Context) (string, error)
}

// versionUnknown marks a component that answered but would not say its version: it is up.
type versionUnknown struct{ err error }

func (v versionUnknown) Error() string { return "version unknown: " + v.err.Error() }

// Check runs every probe in parallel, each under its own timeout, and returns results in
// probe order. It returns by the deadline even when a probe ignores its context; that
// probe is reported down and its late answer is discarded.
func Check(ctx context.Context, timeout time.Duration, probes []Probe, secrets ...string) []Component {
	out := make([]Component, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Go(func() {
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			type answer struct {
				v   string
				err error
			}
			ch := make(chan answer, 1) // buffered: a probe that outlives its deadline still exits
			go func() {
				v, err := p.Run(pctx)
				ch <- answer{v, err}
			}()
			select {
			case a := <-ch:
				out[i] = result(p.Name, a.v, a.err, secrets)
			case <-pctx.Done():
				out[i] = result(p.Name, "", fmt.Errorf("timed out: %w", pctx.Err()), secrets)
			}
		})
	}
	wg.Wait()
	return out
}

var versionText = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$`)

func result(name, version string, err error, secrets []string) Component {
	c := Component{Name: name, Status: "up"}
	if err != nil {
		var vu versionUnknown
		if !errors.As(err, &vu) {
			c.Status = "down"
		}
		c.Error = clip(redact(err.Error(), secrets))
	}
	switch version = strings.TrimPrefix(strings.TrimSpace(version), "v"); {
	case version == "":
	case versionText.MatchString(version):
		c.Version = version
	case c.Error == "":
		c.Error = "unrecognised version string"
	}
	return c
}

func redact(s string, secrets []string) string {
	for _, x := range secrets {
		if x != "" {
			s = strings.ReplaceAll(s, x, "[redacted]")
		}
	}
	return s
}

func clip(s string) string {
	if len(s) <= 300 {
		return s
	}
	return strings.ToValidUTF8(s[:300], "") + "…"
}

// NewHTTPClient is the probes' client: no proxy from the environment, no redirects.
func NewHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// fetch GETs u and returns at most 64 KiB of its body when the answer is 200.
func fetch(ctx context.Context, hc *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// LiveKit probes a configured LiveKit SFU server's root health endpoint (GET / -> 200 OK).
func LiveKit(hc *http.Client, base string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		_, err := fetch(ctx, hc, strings.TrimRight(base, "/")+"/")
		return "", err
	}
}
