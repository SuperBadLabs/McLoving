-- CTRL-005: exact-fence log bytes and build positions are durable counters.
-- One migration-time aggregate replaces scans on every live-log append.
LOCK TABLE attempt_log_chunks IN ACCESS EXCLUSIVE MODE;

CREATE TABLE attempt_log_accounting (
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    fence bigint NOT NULL CHECK (fence >= 0),
    committed_bytes bigint NOT NULL CHECK (committed_bytes BETWEEN 0 AND 67108864),
    PRIMARY KEY (organization_id, attempt_id, fence),
    FOREIGN KEY (attempt_id, organization_id)
        REFERENCES attempts(id, organization_id) ON DELETE CASCADE
);

INSERT INTO attempt_log_accounting (organization_id, attempt_id, fence, committed_bytes)
SELECT organization_id, attempt_id, fence, sum(octet_length(content))::bigint
FROM attempt_log_chunks
GROUP BY organization_id, attempt_id, fence;

GRANT SELECT, INSERT, UPDATE, DELETE ON attempt_log_accounting TO mcloving_tenant;
ALTER TABLE attempt_log_accounting ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempt_log_accounting FORCE ROW LEVEL SECURITY;
CREATE POLICY attempt_log_accounting_tenant_policy ON attempt_log_accounting
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE builds ADD COLUMN committed_log_position bigint NOT NULL DEFAULT 0
    CHECK (committed_log_position >= 0);
UPDATE builds AS b
SET committed_log_position = positions.last_position
FROM (
    SELECT organization_id, build_id, max(build_position) AS last_position
    FROM attempt_log_chunks GROUP BY organization_id, build_id
) AS positions
WHERE b.organization_id = positions.organization_id AND b.id = positions.build_id;

-- Every writer, including a pre-v44 controller, obtains the attempt lock
-- before the build lock. Allocate a position only for a new exact chunk key;
-- a legacy ON CONFLICT retry retains the existing position without consuming
-- a counter value. A failed statement rolls all counter updates back.
CREATE FUNCTION attempt_log_chunks_prepare_accounting()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    chunk_org uuid;
    chunk_attempt uuid;
    chunk_fence bigint;
    chunk_build uuid;
    existing_position bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        chunk_org := OLD.organization_id;
        chunk_attempt := OLD.attempt_id;
        chunk_fence := OLD.fence;
    ELSE
        chunk_org := NEW.organization_id;
        chunk_attempt := NEW.attempt_id;
        chunk_fence := NEW.fence;
    END IF;
    IF TG_OP = 'UPDATE' AND
       (NEW.organization_id, NEW.attempt_id, NEW.fence, NEW.sequence,
        NEW.build_id, NEW.build_position, NEW.stream, NEW.step_ordinal)
       IS DISTINCT FROM
       (OLD.organization_id, OLD.attempt_id, OLD.fence, OLD.sequence,
        OLD.build_id, OLD.build_position, OLD.stream, OLD.step_ordinal) THEN
        RAISE EXCEPTION 'log chunk identity is immutable' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'mcloving.log.' || chunk_org::text || '.' || chunk_attempt::text || '.' || chunk_fence::text, 0
    ));
    SELECT n.build_id INTO chunk_build
    FROM attempts AS a JOIN nodes AS n
      ON n.organization_id = a.organization_id AND n.id = a.node_id
    WHERE a.organization_id = chunk_org AND a.id = chunk_attempt;
    IF chunk_build IS NULL THEN
        RAISE EXCEPTION 'log chunk attempt has no build' USING ERRCODE = 'foreign_key_violation';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'mcloving.log.build.' || chunk_org::text || '.' || chunk_build::text, 0
    ));
    IF TG_OP = 'INSERT' THEN
        SELECT l.build_position INTO existing_position
        FROM attempt_log_chunks AS l
        WHERE l.organization_id = chunk_org AND l.attempt_id = chunk_attempt
          AND l.fence = chunk_fence AND l.sequence = NEW.sequence;
        NEW.build_id := chunk_build;
        IF FOUND THEN
            NEW.build_position := existing_position;
        ELSE
            UPDATE builds SET committed_log_position = committed_log_position + 1
            WHERE organization_id = chunk_org AND id = chunk_build
            RETURNING committed_log_position INTO NEW.build_position;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'log chunk build is unavailable' USING ERRCODE = 'foreign_key_violation';
            END IF;
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION attempt_log_chunks_prepare_accounting() FROM PUBLIC;

CREATE FUNCTION attempt_log_chunks_commit_accounting()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO attempt_log_accounting (organization_id, attempt_id, fence, committed_bytes)
        VALUES (NEW.organization_id, NEW.attempt_id, NEW.fence, octet_length(NEW.content))
        ON CONFLICT (organization_id, attempt_id, fence)
        DO UPDATE SET committed_bytes = attempt_log_accounting.committed_bytes + EXCLUDED.committed_bytes;
    ELSIF TG_OP = 'UPDATE' THEN
        UPDATE attempt_log_accounting
        SET committed_bytes = committed_bytes + octet_length(NEW.content) - octet_length(OLD.content)
        WHERE organization_id = OLD.organization_id AND attempt_id = OLD.attempt_id AND fence = OLD.fence;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'log accounting row is missing' USING ERRCODE = 'check_violation';
        END IF;
    ELSE
        UPDATE attempt_log_accounting
        SET committed_bytes = committed_bytes - octet_length(OLD.content)
        WHERE organization_id = OLD.organization_id AND attempt_id = OLD.attempt_id AND fence = OLD.fence;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'log accounting row is missing' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION attempt_log_chunks_commit_accounting() FROM PUBLIC;

DROP TRIGGER attempt_log_chunks_fill_compatibility_position ON attempt_log_chunks;
DROP FUNCTION attempt_log_chunks_fill_compatibility_position();
CREATE TRIGGER attempt_log_chunks_prepare_accounting
BEFORE INSERT OR UPDATE OR DELETE ON attempt_log_chunks
FOR EACH ROW EXECUTE FUNCTION attempt_log_chunks_prepare_accounting();
CREATE TRIGGER attempt_log_chunks_commit_accounting
AFTER INSERT OR UPDATE OR DELETE ON attempt_log_chunks
FOR EACH ROW EXECUTE FUNCTION attempt_log_chunks_commit_accounting();
