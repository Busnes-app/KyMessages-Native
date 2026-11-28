package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/Busnes-app/ky_server_base/internal/e2eeid"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// E4 of docs/superpowers/specs/2026-11-22-e2ee-design.md: a bot's devices are vouched for by its
// owner's master key. The owner's browser signs the list of the bot's devices and their keys
// (kymessages.bot-devices.v1) after comparing each device's code with the one the bot shows;
// colleagues trust only devices on the newest list they have seen, so the server can neither add
// a bot device nor bring back one the owner removed.

// e2eeBotDevicesPut is PUT /api/v1/keys/bots/{id}/devices.
type e2eeBotDevicesPut struct {
	Version       int64              `json:"version"`
	ExpectedEpoch int64              `json:"expected_epoch"`
	Epoch         int64              `json:"epoch"`
	Devices       []e2eeid.BotDevice `json:"devices"`
	Signature     string             `json:"signature"`
}

// e2eeBotDevicesJSON is a bot's list in a key query.
type e2eeBotDevicesJSON struct {
	OwnerID   string             `json:"owner_id"`
	Version   int64              `json:"version"`
	Epoch     int64              `json:"epoch"`
	Devices   []e2eeid.BotDevice `json:"devices"`
	Signature string             `json:"signature"`
}

// PUT /api/v1/keys/bots/{id}/devices stores the device list of the caller's own bot {id} (its
// user ID), signed by the caller's current master key: compare-and-swap on the epoch. Only the
// bot's owner, signed in as a person, may write it; each device must be one the bot uploaded,
// with exactly those keys.
func (s *Server) handleE2EEPutBotDevices(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	botID := r.PathValue("id")
	if !s.ownsBot(r, user, botID) {
		s.writeError(w, http.StatusNotFound, "No such bot")
		return
	}
	var req e2eeBotDevicesPut
	if !decodeIdentity(w, r, e2eeIdentityBody, &req) || req.Version < 1 || req.ExpectedEpoch < 0 || req.Epoch <= req.ExpectedEpoch || req.Devices == nil || len(req.Devices) > e2eeMaxDeviceList {
		s.writeError(w, http.StatusBadRequest, "Invalid bot device list")
		return
	}
	msg, err := e2eeid.BotDevicesMessage(tenantID, user.ID, req.Version, botID, req.Epoch, req.Devices)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid bot device list")
		return
	}
	for _, d := range req.Devices {
		dev, err := s.store.E2EE().GetDevice(r.Context(), botID, d.DeviceID)
		if err != nil || dev.TenantID != tenantID || dev.Curve25519 != d.Curve25519 || dev.Ed25519 != d.Ed25519 {
			s.writeError(w, http.StatusBadRequest, "The bot has no such device")
			return
		}
	}
	devices, _ := json.Marshal(req.Devices)
	b := &store.E2EEBotDevices{TenantID: tenantID, BotUserID: botID, OwnerUserID: user.ID, OwnerVersion: req.Version, Epoch: req.Epoch, Devices: string(devices), Signature: req.Signature}
	switch err := s.store.E2EE().PutBotDevices(r.Context(), b, req.ExpectedEpoch, proofOf(e2eeid.DomainBotDevices, msg, req.Signature)); {
	case errors.Is(err, errProof):
		s.writeError(w, http.StatusBadRequest, "The bot device list is not validly signed")
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The bot device list changed; reload it")
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to store the bot device list")
	default:
		s.audit(r.Context(), user.ID, r, "e2ee.bot_devices_set", botID, "epoch="+strconv.FormatInt(req.Epoch, 10))
		s.writeJSON(w, http.StatusOK, map[string]int64{"epoch": req.Epoch})
	}
}

// GET /api/v1/bots lists the caller's active bots, whose devices the caller may vouch for.
func (s *Server) handleOwnBots(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	type bot struct {
		UserID      string `json:"user_id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
	}
	out := []bot{}
	if user.Role != "bot" {
		agents, err := s.store.Agents().ListAgentsByOwner(r.Context(), user.ID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to load bots")
			return
		}
		for _, a := range agents {
			if a.TokenState == store.AgentTokenActive {
				out = append(out, bot{a.UserID, a.Username, a.DisplayName})
			}
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"bots": out})
}

// ownsBot reports whether a person (never a bot token) owns the active agent whose user is botID.
func (s *Server) ownsBot(r *http.Request, user *store.User, botID string) bool {
	if user.Role == "bot" {
		return false
	}
	agents, err := s.store.Agents().ListAgentsByOwner(r.Context(), user.ID)
	if err != nil {
		return false
	}
	for _, a := range agents {
		if a.UserID == botID && a.TokenState == store.AgentTokenActive {
			return true
		}
	}
	return false
}

// botLists answers the owner-signed device lists of the named users that are bots, with their
// owners' master keys, which a client needs to check them. A list signed by a master key version
// that is no longer current (the owner reset their identity) is left out: it vouches for nothing.
func (s *Server) botLists(r *http.Request, tenantID string, userIDs []string) (map[string]e2eeBotDevicesJSON, []store.E2EEMasterKey, error) {
	lists, err := s.store.E2EE().ListBotDevices(r.Context(), tenantID, userIDs)
	if err != nil || len(lists) == 0 {
		return nil, nil, err
	}
	owners := make([]string, 0, len(lists))
	for _, l := range lists {
		owners = append(owners, l.OwnerUserID)
	}
	masters, err := s.store.E2EE().ListMasterKeys(r.Context(), tenantID, owners)
	if err != nil {
		return nil, nil, err
	}
	current := map[string]int64{}
	for _, m := range masters {
		current[m.UserID] = m.Version
	}
	out := map[string]e2eeBotDevicesJSON{}
	for _, l := range lists {
		var devs []e2eeid.BotDevice
		if current[l.OwnerUserID] != l.OwnerVersion || json.Unmarshal([]byte(l.Devices), &devs) != nil {
			continue
		}
		out[l.BotUserID] = e2eeBotDevicesJSON{OwnerID: l.OwnerUserID, Version: l.OwnerVersion, Epoch: l.Epoch, Devices: append([]e2eeid.BotDevice{}, devs...), Signature: l.Signature}
	}
	return out, masters, nil
}
