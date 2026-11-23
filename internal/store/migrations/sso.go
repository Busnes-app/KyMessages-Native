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
-- Existing sessions have no verifiable IdP binding. Require a fresh suite sign-in.
DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE sso_provider = 'kyidentity');
DELETE FROM device_pairings WHERE user_id IN (SELECT id FROM users WHERE sso_provider = 'kyidentity');
DELETE FROM push_subscriptions WHERE user_id IN (SELECT id FROM users WHERE sso_provider = 'kyidentity');
`
