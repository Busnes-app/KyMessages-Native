package migrations

const callRoutingSchema = `
CREATE TABLE call_room_owners (
 room_id VARCHAR(64) PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE,
 tenant_id VARCHAR(64) NOT NULL,
 holder VARCHAR(128) NOT NULL,
 generation BIGINT NOT NULL,
 expires_at BIGINT NOT NULL
);
CREATE INDEX idx_call_room_owners_tenant ON call_room_owners(tenant_id);
CREATE TABLE call_seats (
 room_id VARCHAR(64) NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
 tenant_id VARCHAR(64) NOT NULL,
 user_id VARCHAR(64) NOT NULL,
 session_hash VARCHAR(64) NOT NULL DEFAULT '',
 livekit_room VARCHAR(255) NOT NULL DEFAULT '',
 media_epoch INTEGER NOT NULL DEFAULT 1,
 peer_id VARCHAR(64) NOT NULL,
 call_id VARCHAR(64) NOT NULL REFERENCES call_sessions(id) ON DELETE CASCADE,
 PRIMARY KEY(room_id,user_id)
);
CREATE INDEX idx_call_seats_user ON call_seats(user_id,tenant_id);
CREATE INDEX idx_call_seats_session ON call_seats(session_hash);
CREATE TABLE pending_call_evictions (
 tenant_id VARCHAR(64) NOT NULL,
 livekit_room VARCHAR(255) NOT NULL,
 peer_id VARCHAR(64) NOT NULL DEFAULT '',
 user_id VARCHAR(64) NOT NULL DEFAULT '',
 PRIMARY KEY(tenant_id,livekit_room,peer_id)
);
CREATE INDEX idx_pending_call_evictions_user ON pending_call_evictions(user_id,tenant_id);
`

// Session deletion (logout, SID logout, expiry and account cascade) is the shared revocation
// boundary. Keep cleanup and media-address fencing in that same transaction on both engines.
const revokeSessionCallSeats = `
 INSERT INTO pending_call_evictions(tenant_id,livekit_room,peer_id,user_id)
 SELECT p.tenant_id,p.livekit_room,p.peer_id,p.user_id FROM call_seats p
 JOIN call_sessions c ON c.id=p.call_id AND c.tenant_id=p.tenant_id AND c.room_id=p.room_id
 WHERE p.session_hash=OLD.token_hash AND p.user_id=OLD.user_id AND p.livekit_room<>''
 ON CONFLICT DO NOTHING;
 UPDATE call_sessions SET epoch=epoch+1,livekit_room='ky_' || id || '_e' || CAST(epoch+1 AS TEXT)
 WHERE ended_at IS NULL AND mode='sfu_livekit' AND livekit_room IS NOT NULL AND livekit_room<>''
 AND id IN(SELECT call_id FROM call_seats WHERE session_hash=OLD.token_hash AND user_id=OLD.user_id);
 DELETE FROM call_seats WHERE session_hash=OLD.token_hash AND user_id=OLD.user_id;
`

const callRoutingSQLite = callRoutingSchema + `
CREATE TRIGGER call_seats_session_revoked BEFORE DELETE ON sessions BEGIN
` + revokeSessionCallSeats + ` END;`

const callRoutingPostgres = callRoutingSchema + `
CREATE FUNCTION revoke_session_call_seats() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p RECORD;
BEGIN
 FOR p IN DELETE FROM call_seats WHERE session_hash=OLD.token_hash AND user_id=OLD.user_id
 RETURNING tenant_id,call_id,peer_id,user_id,livekit_room LOOP
  IF p.livekit_room<>'' THEN
   INSERT INTO pending_call_evictions(tenant_id,livekit_room,peer_id,user_id)
   VALUES(p.tenant_id,p.livekit_room,p.peer_id,p.user_id) ON CONFLICT DO NOTHING;
  END IF;
  UPDATE call_sessions SET epoch=epoch+1,livekit_room='ky_' || id || '_e' || CAST(epoch+1 AS TEXT)
  WHERE id=p.call_id AND tenant_id=p.tenant_id AND ended_at IS NULL AND mode='sfu_livekit'
  AND livekit_room IS NOT NULL AND livekit_room<>''
  AND EXISTS(SELECT 1 FROM tenants WHERE id=p.tenant_id AND status<>'deleted');
 END LOOP;
 RETURN OLD;
END $$;
CREATE TRIGGER call_seats_session_revoked BEFORE DELETE ON sessions
FOR EACH ROW EXECUTE FUNCTION revoke_session_call_seats();`
