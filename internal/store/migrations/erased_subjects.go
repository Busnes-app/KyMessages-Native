package migrations

const erasedSubjectsSchema = `
CREATE TABLE erased_subjects (
 subject VARCHAR(255) PRIMARY KEY,
 org_id VARCHAR(64) NOT NULL,
 erased_at BIGINT NOT NULL
);
INSERT INTO erased_subjects (subject, org_id, erased_at)
SELECT p.subject, p.org_id, MIN(COALESCE(e.completed_at, 0))
FROM user_subjects p JOIN user_erasure_state e ON e.user_id = p.user_id AND e.tenant_id = p.org_id
WHERE p.provider = 'kyidentity' GROUP BY p.subject, p.org_id;
UPDATE users SET status = 'deleted' WHERE sso_provider = 'kyidentity' AND org_id <> ''
 AND EXISTS (SELECT 1 FROM erased_subjects e WHERE e.subject = users.sso_subject);
`

const erasedSubjectsSQLite = erasedSubjectsSchema + `
CREATE TRIGGER erased_subjects_kept_update BEFORE UPDATE ON erased_subjects BEGIN
 SELECT RAISE(ABORT, 'erased_subject_immutable'); END;
CREATE TRIGGER erased_subjects_kept_delete BEFORE DELETE ON erased_subjects BEGIN
 SELECT RAISE(ABORT, 'erased_subject_immutable'); END;
CREATE TRIGGER users_erased_subject_insert BEFORE INSERT ON users
WHEN NEW.sso_provider = 'kyidentity' AND NEW.org_id <> ''
 AND EXISTS (SELECT 1 FROM erased_subjects WHERE subject = NEW.sso_subject)
BEGIN SELECT RAISE(ABORT, 'erased_subject'); END;
CREATE TRIGGER users_erased_subject_update BEFORE UPDATE OF sso_provider, sso_subject, org_id, status ON users
WHEN NEW.sso_provider = 'kyidentity' AND NEW.org_id <> '' AND NEW.status = 'active'
 AND EXISTS (SELECT 1 FROM erased_subjects WHERE subject = NEW.sso_subject)
BEGIN SELECT RAISE(ABORT, 'erased_subject'); END;
`

const erasedSubjectsPostgres = erasedSubjectsSchema + `
CREATE FUNCTION keep_erased_subject() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'erased_subject_immutable'; END $$;
CREATE TRIGGER erased_subjects_kept BEFORE UPDATE OR DELETE ON erased_subjects
FOR EACH ROW EXECUTE FUNCTION keep_erased_subject();
CREATE FUNCTION refuse_erased_subject() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.sso_provider = 'kyidentity' AND NEW.org_id <> '' THEN
  IF TG_OP = 'INSERT' THEN
   PERFORM pg_advisory_xact_lock(hashtext('kymessages:erased-subject:' || current_schema()), hashtext(NEW.sso_subject));
  END IF;
  IF (TG_OP = 'INSERT' OR NEW.status = 'active') AND EXISTS (SELECT 1 FROM erased_subjects WHERE subject = NEW.sso_subject) THEN
   RAISE EXCEPTION 'erased_subject' USING ERRCODE = '23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER users_erased_subject_insert BEFORE INSERT ON users
FOR EACH ROW EXECUTE FUNCTION refuse_erased_subject();
CREATE TRIGGER users_erased_subject_update BEFORE UPDATE OF sso_provider, sso_subject, org_id, status ON users
FOR EACH ROW EXECUTE FUNCTION refuse_erased_subject();
`
