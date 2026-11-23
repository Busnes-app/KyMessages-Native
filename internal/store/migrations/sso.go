package migrations

const ssoLifecycleSchema = `
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
