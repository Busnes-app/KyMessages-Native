package migrations

// Old experimental shared sessions cannot prove which invitation admitted them. Retire
// their actual media before invalidating them; never backfill a current token onto an old
// principal. Product single-mode sessions are in memory and do not use this table.
const guestInviteBindingSchema = `
INSERT INTO pending_call_evictions(tenant_id,livekit_room,peer_id,user_id)
 SELECT tenant_id,livekit_room,peer_id,user_id FROM call_seats
 WHERE session_hash='' AND livekit_room<>'' ON CONFLICT DO NOTHING;
UPDATE call_sessions SET epoch=epoch+1,livekit_room='ky_' || id || '_e' || CAST(epoch+1 AS TEXT)
 WHERE ended_at IS NULL AND mode='sfu_livekit' AND id IN(SELECT call_id FROM call_seats WHERE session_hash='');
DELETE FROM call_seats WHERE session_hash='';
DELETE FROM meeting_guest_sessions;
ALTER TABLE meeting_guest_sessions ADD COLUMN invite_hash VARCHAR(64) NOT NULL DEFAULT '';
`
