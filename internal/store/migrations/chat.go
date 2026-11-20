package migrations

// nativeChatSchemaCommon defines the multi-tenant native KyMessages schema (migration 23).
// All timestamps are Unix milliseconds (BIGINT). Both SQLite and PostgreSQL run this DDL;
// Postgres additionally adds a partial GIN full-text index on plain_v1 messages.
const nativeChatSchemaCommon = `
CREATE TABLE tenants (
    id VARCHAR(64) PRIMARY KEY,
    slug VARCHAR(128) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    plan VARCHAR(32) NOT NULL DEFAULT 'business',
    p2p_policy VARCHAR(32) NOT NULL DEFAULT 'hybrid',
    p2p_max_video INTEGER NOT NULL DEFAULT 2,
    p2p_max_audio INTEGER NOT NULL DEFAULT 4,
    guest_force_sfu INTEGER NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL
);

INSERT INTO tenants (id, slug, display_name, plan, p2p_policy, p2p_max_video, p2p_max_audio, guest_force_sfu, created_at)
VALUES ('default', 'default', 'Default', 'business', 'hybrid', 2, 4, 1, 0)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE rooms (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    kind VARCHAR(32) NOT NULL,
    dm_pair_key VARCHAR(255),
    name VARCHAR(255) NOT NULL DEFAULT '',
    topic TEXT NOT NULL DEFAULT '',
    is_private INTEGER NOT NULL DEFAULT 1,
    last_seq BIGINT NOT NULL DEFAULT 0,
    closed_at BIGINT,
    created_by VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (tenant_id, dm_pair_key)
);
CREATE INDEX idx_rooms_tenant_kind ON rooms(tenant_id, kind);

CREATE TABLE room_members (
    tenant_id VARCHAR(64) NOT NULL,
    room_id VARCHAR(64) NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'member',
    last_read_seq BIGINT NOT NULL DEFAULT 0,
    notify_mode VARCHAR(32) NOT NULL DEFAULT 'all',
    joined_at BIGINT NOT NULL,
    PRIMARY KEY (room_id, user_id)
);
CREATE INDEX idx_room_members_user ON room_members(tenant_id, user_id);

CREATE TABLE messages (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    room_id VARCHAR(64) NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    seq BIGINT NOT NULL,
    sender_id VARCHAR(64) NOT NULL,
    sender_name VARCHAR(255) NOT NULL DEFAULT '',
    reply_to_id VARCHAR(64),
    encoding VARCHAR(32) NOT NULL DEFAULT 'plain_v1',
    body TEXT NOT NULL,
    edited_at BIGINT,
    deleted_at BIGINT,
    idempotency_key VARCHAR(128),
    created_at BIGINT NOT NULL,
    UNIQUE (room_id, seq),
    UNIQUE (room_id, sender_id, idempotency_key)
);
CREATE INDEX idx_messages_room_seq ON messages(room_id, seq DESC);
CREATE INDEX idx_messages_tenant_created ON messages(tenant_id, created_at DESC);

CREATE TABLE message_reactions (
    message_id VARCHAR(64) NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL,
    emoji VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (message_id, user_id, emoji)
);

CREATE TABLE attachments (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    room_id VARCHAR(64) NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    message_id VARCHAR(64) REFERENCES messages(id) ON DELETE SET NULL,
    uploader_id VARCHAR(64) NOT NULL,
    blob_key VARCHAR(512) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(128) NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256_hex VARCHAR(64) NOT NULL,
    enc_meta TEXT,
    created_at BIGINT NOT NULL
);
CREATE INDEX idx_attachments_room ON attachments(room_id, created_at DESC);

CREATE TABLE meetings (
    id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    room_id VARCHAR(64) NOT NULL UNIQUE REFERENCES rooms(id) ON DELETE CASCADE,
    organizer_sub VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    closed_at BIGINT,
    updated_at BIGINT NOT NULL
);

CREATE TABLE meeting_windows (
    meeting_id VARCHAR(128) NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
    starts_at BIGINT NOT NULL,
    ends_at BIGINT NOT NULL,
    PRIMARY KEY (meeting_id, starts_at, ends_at)
);

CREATE TABLE meeting_guests (
    id VARCHAR(64) PRIMARY KEY,
    meeting_id VARCHAR(128) NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
    guest_key VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    revoked_at BIGINT,
    created_at BIGINT NOT NULL,
    UNIQUE (meeting_id, guest_key)
);

CREATE TABLE call_sessions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    room_id VARCHAR(64) NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    mode VARCHAR(32) NOT NULL,
    epoch INTEGER NOT NULL DEFAULT 1,
    sfu_sticky INTEGER NOT NULL DEFAULT 0,
    livekit_room VARCHAR(160),
    started_by VARCHAR(64) NOT NULL,
    started_at BIGINT NOT NULL,
    ended_at BIGINT
);
CREATE INDEX idx_call_sessions_active ON call_sessions(room_id) WHERE ended_at IS NULL;

CREATE TABLE room_webhooks (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    room_id VARCHAR(64) NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    direction VARCHAR(16) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    target_url TEXT,
    created_by VARCHAR(64) NOT NULL,
    revoked_at BIGINT,
    created_at BIGINT NOT NULL
);
CREATE INDEX idx_room_webhooks_room ON room_webhooks(tenant_id, room_id);
`

const nativeChatSchemaSQLite = nativeChatSchemaCommon

const nativeChatSchemaPostgres = nativeChatSchemaCommon + `
CREATE INDEX idx_messages_body_fts ON messages USING GIN (to_tsvector('simple', body)) WHERE encoding = 'plain_v1' AND deleted_at IS NULL;
`
