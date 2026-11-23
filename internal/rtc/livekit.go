package rtc

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultTokenTTL is the default validity for a native call or meeting LiveKit JWT.
	DefaultTokenTTL = 15 * time.Minute
	minTokenTTL     = 5 * time.Second
	maxTokenTTL     = 60 * time.Minute
)

// Client talks to a LiveKit SFU using its Twirp RoomService API and signs HS256 access tokens.
// Zero third-party dependencies: only Go standard library crypto and net/http.
type Client struct {
	base   string // http://host or https://host
	wsURL  string // ws://host or wss://host
	key    string
	secret []byte
	http   *http.Client
	now    func() time.Time
}

// NewClient constructs a LiveKit client from an http(s) or ws(s) origin and API credentials.
func NewClient(rawURL, apiKey, apiSecret string) *Client {
	trimmed := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	base := trimmed
	wsURL := trimmed
	switch {
	case strings.HasPrefix(trimmed, "wss://"):
		base = "https://" + strings.TrimPrefix(trimmed, "wss://")
	case strings.HasPrefix(trimmed, "ws://"):
		base = "http://" + strings.TrimPrefix(trimmed, "ws://")
	case strings.HasPrefix(trimmed, "https://"):
		wsURL = "wss://" + strings.TrimPrefix(trimmed, "https://")
	case strings.HasPrefix(trimmed, "http://"):
		wsURL = "ws://" + strings.TrimPrefix(trimmed, "http://")
	}
	return &Client{
		base:   base,
		wsURL:  wsURL,
		key:    apiKey,
		secret: []byte(apiSecret),
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy: nil,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}
}

// WSURL returns the browser-facing WebSocket URL (wss://... or ws://...) for LiveKit.
func (c *Client) WSURL() string { return c.wsURL }

// HTTPURL returns the Twirp base URL (https://... or http://...) for LiveKit.
func (c *Client) HTTPURL() string { return c.base }

// JoinToken mints an HS256 LiveKit participant JWT scoped to a single room and identity.
func (c *Client) JoinToken(room, identity, displayName, metadata string, ttl time.Duration) string {
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	if ttl < minTokenTTL {
		ttl = minTokenTTL
	}
	if ttl > maxTokenTTL {
		ttl = maxTokenTTL
	}
	return c.signJWT(jwtClaims{
		Iss:      c.key,
		Sub:      identity,
		Name:     displayName,
		Metadata: metadata,
		Video: videoGrant{
			Room:             room,
			RoomJoin:         true,
			CanPublish:       boolPtr(true),
			CanSubscribe:     boolPtr(true),
			CanPublishData:   boolPtr(true),
			CanUpdateOwnMeta: boolPtr(true),
		},
	}, ttl)
}

// CreateRoom ensures the named LiveKit room exists with sane auto-cleanup timeouts.
func (c *Client) CreateRoom(ctx context.Context, name, metadata string) error {
	return c.twirp(ctx, "CreateRoom", videoGrant{RoomCreate: true}, map[string]any{
		"name":              name,
		"metadata":          metadata,
		"empty_timeout":     60,
		"departure_timeout": 20,
	}, nil)
}

// DeleteRoom retires every participant/token target of an old owner epoch or purged org.
func (c *Client) DeleteRoom(ctx context.Context, room string) error {
	err := c.twirp(ctx, "DeleteRoom", videoGrant{RoomCreate: true}, map[string]any{"room": room}, nil)
	if err != nil && strings.Contains(err.Error(), "status 404") {
		return nil
	}
	return err
}

// RemoveParticipant forcefully disconnects a participant from a LiveKit room.
// LiveKit returns 404 when the room or participant is already gone; that is treated as success.
func (c *Client) RemoveParticipant(ctx context.Context, room, identity string) error {
	err := c.twirp(ctx, "RemoveParticipant", videoGrant{RoomAdmin: true, Room: room}, map[string]any{
		"room":     room,
		"identity": identity,
	}, nil)
	if err != nil && strings.Contains(err.Error(), "status 404") {
		return nil
	}
	return err
}

func (c *Client) twirp(ctx context.Context, method string, grant videoGrant, reqBody any, dst any) error {
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/twirp/livekit.RoomService/"+method, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.signJWT(jwtClaims{Iss: c.key, Video: grant}, 30*time.Second))

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("livekit %s: %w", method, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("livekit %s: read body: %w", method, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("livekit %s: status %d: %s", method, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if dst != nil && len(body) > 0 {
		if err := json.Unmarshal(body, dst); err != nil {
			return fmt.Errorf("livekit %s: decode: %w", method, err)
		}
	}
	return nil
}

type jwtClaims struct {
	Iss      string     `json:"iss"`
	Sub      string     `json:"sub,omitempty"`
	Name     string     `json:"name,omitempty"`
	Metadata string     `json:"metadata,omitempty"`
	Iat      int64      `json:"iat"`
	Nbf      int64      `json:"nbf"`
	Exp      int64      `json:"exp"`
	Video    videoGrant `json:"video"`
}

type videoGrant struct {
	RoomCreate       bool   `json:"roomCreate,omitempty"`
	RoomAdmin        bool   `json:"roomAdmin,omitempty"`
	RoomJoin         bool   `json:"roomJoin,omitempty"`
	Room             string `json:"room,omitempty"`
	CanPublish       *bool  `json:"canPublish,omitempty"`
	CanSubscribe     *bool  `json:"canSubscribe,omitempty"`
	CanPublishData   *bool  `json:"canPublishData,omitempty"`
	CanUpdateOwnMeta *bool  `json:"canUpdateOwnMetadata,omitempty"`
}

func boolPtr(v bool) *bool { return &v }

var jwtHeaderB64 = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

func (c *Client) signJWT(claims jwtClaims, ttl time.Duration) string {
	now := c.now().Unix()
	claims.Iat = now
	claims.Nbf = now
	claims.Exp = now + int64(ttl.Seconds())
	payload, _ := json.Marshal(claims)
	unsigned := jwtHeaderB64 + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
