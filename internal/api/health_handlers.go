package api

import (
	"context"
	"net/http"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/health"
)

const (
	probeTimeout  = 3 * time.Second
	healthTimeout = 5 * time.Second
)

// handleHealth probes every native component in parallel: KyMessages, its database, and
// LiveKit SFU when configured.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
	defer cancel()
	probes := []health.Probe{
		{Name: "kymessages", Run: func(context.Context) (string, error) { return config.AppVersion, nil }},
		{Name: "database", Run: func(ctx context.Context) (string, error) { return "", s.store.Ping(ctx) }},
	}
	if s.config.RTC.LiveKitEnabled() {
		probes = append(probes, health.Probe{Name: "livekit", Run: health.LiveKit(s.probeHTTP, s.config.RTC.LiveKitURL)})
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"components": health.Check(ctx, probeTimeout, probes, s.config.RTC.LiveKitAPIKey, s.config.RTC.LiveKitAPISecret),
	})
}
