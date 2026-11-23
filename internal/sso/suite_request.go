package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrSuiteOff is a suite call on an install without KyIdentity configured.
var ErrSuiteOff = errors.New("sso: KyIdentity suite directory not configured")

// SuiteRequest calls KyIdentity's /api/suite/<path> with this app's client credentials
// (client_secret_basic), for the routes ky-primitives/suitedir does not cover (the storage pool,
// the erased list). Like suitedir it needs an https issuer (loopback http excepted), never
// follows a redirect, bounds the answer to limit bytes, and keeps the query out of errors.
func (k *KyIdentityClient) SuiteRequest(ctx context.Context, method, path string, q url.Values, body, out any, limit int64) error {
	dir, err := k.SuiteDirectory()
	if err != nil {
		return err
	}
	if dir == nil {
		return ErrSuiteOff
	}
	base, err := url.Parse(strings.TrimRight(dir.Issuer, "/"))
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		base.Scheme != "https" && !(base.Scheme == "http" && isLoopback(base.Hostname())) {
		return errors.New("sso: KyIdentity issuer must be https")
	}
	u := base.JoinPath("api", "suite", path)
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(dir.ClientID, dir.ClientSecret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are refused") }}
	resp, err := client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("sso: suite %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("sso: suite %s: %w", path, err)
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("sso: suite %s: answer exceeds %d bytes", path, limit)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sso: suite %s: status %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("sso: suite %s: %w", path, err)
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
