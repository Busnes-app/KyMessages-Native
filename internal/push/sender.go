package push

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxEndpointLength = 2048
	defaultPushTTL    = 86400 // 24h for messages
	callPushTTL       = 60    // 60s for incoming calls
	sendTimeout       = 10 * time.Second
	maxResponseDrain  = 4096
	defaultQueueSize  = 256
	defaultWorkers    = 4
)

// ErrEndpointBlocked indicates an endpoint failed URL or SSRF validation.
var ErrEndpointBlocked = errors.New("push: endpoint URL is not allowed")

// Subscription is a single browser Web Push subscription.
type Subscription struct {
	ID         string
	Endpoint   string
	P256DH     string
	AuthSecret string
}

// Payload is the encrypted JSON body delivered to the browser service worker.
type Payload struct {
	Kind       string `json:"kind"` // "message" | "call"
	RoomID     string `json:"room_id"`
	RoomName   string `json:"room_name"`
	SenderName string `json:"sender_name,omitempty"`
	Title      string `json:"title"`
	Body       string `json:"body"`
	URL        string `json:"url"`
}

// SendOptions tunes Web Push headers for a single delivery.
type SendOptions struct {
	TTL     int    // seconds; defaults to 86400
	Urgency string // "very-low" | "low" | "normal" | "high"
	Topic   string // optional RFC 8030 Topic (alphanumeric/url-safe, max 32 chars)
}

// SendResult captures the outcome of a single Web Push HTTP POST.
type SendResult struct {
	StatusCode int
	Gone       bool // true on HTTP 404 or 410 (subscription expired/unsubscribed)
}

// ValidateEndpoint checks that rawURL is a safe HTTPS Web Push endpoint and does not target
// loopback, private, link-local, multicast, CGNAT, or reserved IP addresses.
// When allowPrivate is true (tests only), loopback/private targets and non-443 ports are permitted.
func ValidateEndpoint(rawURL string, allowPrivate bool) (*url.URL, error) {
	s := strings.TrimSpace(rawURL)
	if s == "" || len(s) > MaxEndpointLength {
		return nil, fmt.Errorf("%w: endpoint must be 1..%d bytes", ErrEndpointBlocked, MaxEndpointLength)
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f {
			return nil, fmt.Errorf("%w: endpoint contains invalid characters", ErrEndpointBlocked)
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed URL", ErrEndpointBlocked)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: endpoint must use https", ErrEndpointBlocked)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: endpoint must not contain credentials", ErrEndpointBlocked)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: endpoint host is empty", ErrEndpointBlocked)
	}
	if port := u.Port(); port != "" && port != "443" && !allowPrivate {
		return nil, fmt.Errorf("%w: endpoint must use standard HTTPS port 443", ErrEndpointBlocked)
	}
	if !allowPrivate {
		lower := strings.ToLower(host)
		if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") {
			return nil, fmt.Errorf("%w: local hostnames are blocked", ErrEndpointBlocked)
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			if !isPublicUnicast(addr) {
				return nil, fmt.Errorf("%w: non-public IP address is blocked", ErrEndpointBlocked)
			}
		}
	}
	return u, nil
}

// isPublicUnicast reports whether addr is safe for outbound server-initiated Web Push POSTs.
func isPublicUnicast(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() ||
		addr.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "This" network (RFC 1122)
	netip.MustParsePrefix("100.64.0.0/10"),   // Carrier-grade NAT (RFC 6598)
	netip.MustParsePrefix("169.254.0.0/16"),  // Link-local / cloud metadata
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // Reserved / broadcast
	netip.MustParsePrefix("100::/64"),        // Discard-Only (RFC 6666)
	netip.MustParsePrefix("2001:db8::/32"),   // Documentation
	netip.MustParsePrefix("fc00::/7"),        // Unique local IPv6
	netip.MustParsePrefix("fe80::/10"),       // Link-local IPv6
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"),  // NAT64 local-use prefix
}

// Sender encrypts and transmits RFC 8291/8292 Web Push notifications over an SSRF-safe HTTP client.
type Sender struct {
	vapid        *VAPIDKey
	subject      string
	allowPrivate bool
	client       *http.Client
	now          func() time.Time
}

// SenderOptions configures a Web Push Sender.
type SenderOptions struct {
	VAPID        *VAPIDKey
	Subject      string
	AllowPrivate bool          // tests only
	TLSConfig    *tls.Config   // optional custom TLS config for tests
	Resolver     *net.Resolver // optional custom resolver
}

// NewSender constructs an SSRF-hardened Web Push Sender.
func NewSender(opts SenderOptions) *Sender {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	transport := &http.Transport{
		Proxy:               nil, // never follow ambient proxy env for SSRF-checked endpoints
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     opts.TLSConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid dial address", ErrEndpointBlocked)
			}
			if !opts.AllowPrivate && port != "443" {
				return nil, fmt.Errorf("%w: blocked port", ErrEndpointBlocked)
			}
			if ip, err := netip.ParseAddr(host); err == nil {
				if !opts.AllowPrivate && !isPublicUnicast(ip) {
					return nil, fmt.Errorf("%w: blocked IP literal", ErrEndpointBlocked)
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			}
			ips, err := resolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("push: resolve host failed: %w", err)
			}
			// Reject the host if ANY resolved address is non-public (blocks dual-homed / rebinding tricks),
			// then pin the dial strictly to a validated IP literal.
			var chosen []netip.Addr
			for _, ip := range ips {
				if !opts.AllowPrivate && !isPublicUnicast(ip) {
					return nil, fmt.Errorf("%w: endpoint resolved to non-public IP", ErrEndpointBlocked)
				}
				chosen = append(chosen, ip.Unmap())
			}
			var lastErr error
			for _, ip := range chosen {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   sendTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Never follow redirects from untrusted push endpoints.
			return http.ErrUseLastResponse
		},
	}

	return &Sender{
		vapid:        opts.VAPID,
		subject:      opts.Subject,
		allowPrivate: opts.AllowPrivate,
		client:       client,
		now:          time.Now,
	}
}

// VAPIDPublicKey returns the base64url uncompressed P-256 public key for clients.
func (s *Sender) VAPIDPublicKey() string {
	if s == nil || s.vapid == nil {
		return ""
	}
	return s.vapid.PublicKeyBase64()
}

// Send encrypts payload and POSTs it to sub.Endpoint with RFC 8292 VAPID authorization.
func (s *Sender) Send(ctx context.Context, sub Subscription, payload Payload, opts SendOptions) (SendResult, error) {
	if s == nil || s.vapid == nil {
		return SendResult{}, errors.New("push: sender not initialized")
	}
	u, err := ValidateEndpoint(sub.Endpoint, s.allowPrivate)
	if err != nil {
		return SendResult{}, err
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return SendResult{}, fmt.Errorf("push: marshal payload: %w", err)
	}
	body, err := EncryptPayload(plain, sub.P256DH, sub.AuthSecret)
	if err != nil {
		return SendResult{}, err
	}
	authHeader, err := s.vapid.AuthorizationHeader(u, s.subject, 12*time.Hour, s.now().UTC())
	if err != nil {
		return SendResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return SendResult{}, fmt.Errorf("push: build request: %w", err)
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultPushTTL
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.Itoa(ttl))
	if opts.Urgency != "" {
		req.Header.Set("Urgency", opts.Urgency)
	}
	if opts.Topic != "" && validTopic(opts.Topic) {
		req.Header.Set("Topic", opts.Topic)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return SendResult{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseDrain))
		_ = resp.Body.Close()
	}()

	res := SendResult{
		StatusCode: resp.StatusCode,
		Gone:       resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone,
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return res, nil
	}
	return res, fmt.Errorf("push: upstream returned HTTP %d", resp.StatusCode)
}

func validTopic(t string) bool {
	if len(t) == 0 || len(t) > 32 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// Job represents one asynchronous Web Push delivery task.
type Job struct {
	Subscription Subscription
	Payload      Payload
	Options      SendOptions
}

// Dispatcher runs a bounded background worker pool for Web Push delivery so HTTP/WS handlers
// never block on external push endpoints.
type Dispatcher struct {
	sender *Sender
	onGone func(ctx context.Context, subID string)
	onSent func(ctx context.Context, subID string)

	mu     sync.RWMutex
	closed bool
	jobs   chan Job
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDispatcher creates and starts a bounded async Web Push dispatcher.
func NewDispatcher(sender *Sender, onGone func(ctx context.Context, subID string), onSent func(ctx context.Context, subID string)) *Dispatcher {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dispatcher{
		sender: sender,
		onGone: onGone,
		onSent: onSent,
		jobs:   make(chan Job, defaultQueueSize),
		ctx:    ctx,
		cancel: cancel,
	}
	for i := 0; i < defaultWorkers; i++ {
		d.wg.Add(1)
		go d.worker()
	}
	return d
}

// Sender returns the underlying Sender (for VAPID public key access).
func (d *Dispatcher) Sender() *Sender {
	if d == nil {
		return nil
	}
	return d.sender
}

// Enqueue schedules a push notification non-blockingly. Returns false if the queue is full or closed.
func (d *Dispatcher) Enqueue(job Job) bool {
	if d == nil || d.sender == nil {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return false
	}
	select {
	case d.jobs <- job:
		return true
	default:
		return false
	}
}

// Close stops accepting new jobs, cancels in-flight deliveries, and waits for workers to exit.
func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	close(d.jobs)
	d.cancel()
	d.mu.Unlock()
	d.wg.Wait()
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for job := range d.jobs {
		if d.ctx.Err() != nil {
			return
		}
		reqCtx, cancel := context.WithTimeout(d.ctx, sendTimeout)
		res, err := d.sender.Send(reqCtx, job.Subscription, job.Payload, job.Options)
		cancel()
		if res.Gone && d.onGone != nil && job.Subscription.ID != "" {
			cbCtx, cbCancel := context.WithTimeout(context.Background(), 3*time.Second)
			d.onGone(cbCtx, job.Subscription.ID)
			cbCancel()
		} else if err == nil && d.onSent != nil && job.Subscription.ID != "" {
			cbCtx, cbCancel := context.WithTimeout(context.Background(), 3*time.Second)
			d.onSent(cbCtx, job.Subscription.ID)
			cbCancel()
		}
	}
}

// CallTTL returns the recommended Web Push TTL for incoming call notifications.
func CallTTL() int { return callPushTTL }
