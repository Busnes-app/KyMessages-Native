package migrations

const ssoLifecycleSchema = `
ALTER TABLE push_subscriptions ADD COLUMN sso_sid TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_push_subs_sso ON push_subscriptions(user_id, sso_sid);
ALTER TABLE directory_sync_state ADD COLUMN restore_generation BIGINT NOT NULL DEFAULT 0;
CREATE TABLE directory_mfa_resets (
    provider TEXT NOT NULL, subject TEXT NOT NULL,
    restore_generation BIGINT NOT NULL, reset_key TEXT NOT NULL,
    PRIMARY KEY (provider, subject, restore_generation, reset_key)
);
ALTER TABLE sessions ADD COLUMN sso_sid TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN sso_issued_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN sso_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE device_pairings ADD COLUMN sso_sid TEXT NOT NULL DEFAULT '';
ALTER TABLE device_pairings ADD COLUMN sso_issued_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE device_pairings ADD COLUMN sso_generation BIGINT NOT NULL DEFAULT 0;
CREATE TABLE sso_logout_events (
    issuer TEXT NOT NULL,
    jti TEXT NOT NULL,
    PRIMARY KEY (issuer, jti)
);
CREATE TABLE sso_generation (id INTEGER PRIMARY KEY, generation BIGINT NOT NULL);
INSERT INTO sso_generation (id, generation) VALUES (1, 0);
CREATE TABLE sso_revocations (
    user_id TEXT NOT NULL,
    sid TEXT NOT NULL,
    issued_before BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    PRIMARY KEY (user_id, sid)
);
-- Existing sessions and pairings remain unbound (empty sso_sid) until a new sign-in.
`
