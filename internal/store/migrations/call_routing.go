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
 peer_id VARCHAR(64) NOT NULL,
 call_id VARCHAR(64) NOT NULL REFERENCES call_sessions(id) ON DELETE CASCADE,
 PRIMARY KEY(room_id,user_id)
);
CREATE INDEX idx_call_seats_user ON call_seats(user_id,tenant_id);
CREATE TABLE pending_call_evictions (
 tenant_id VARCHAR(64) NOT NULL,
 livekit_room VARCHAR(255) NOT NULL,
 peer_id VARCHAR(64) NOT NULL DEFAULT '',
 user_id VARCHAR(64) NOT NULL DEFAULT '',
 PRIMARY KEY(tenant_id,livekit_room,peer_id)
);
CREATE INDEX idx_pending_call_evictions_user ON pending_call_evictions(user_id,tenant_id);
`
