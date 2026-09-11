-- PAR-013: every log chunk carries its build and its position in that
-- build's commit order, assigned at commit under the per-build log lock, so
-- a follower's cursor is build-scoped (the table-wide cursor_id never leaves
-- the store) and a page after a position is one ordered range scan of the
-- (organization, build, position) index rather than a re-ranking of the
-- ledger or a merge across the build's attempts. Positions count every
-- chunk ever committed for the build across all fences, so they stay
-- stable when an attempt is re-fenced.
ALTER TABLE attempt_log_chunks ADD COLUMN build_id uuid;
ALTER TABLE attempt_log_chunks ADD COLUMN build_position bigint;

UPDATE attempt_log_chunks AS l
SET build_id = ranked.build_id,
    build_position = ranked.position
FROM (
    SELECT l2.organization_id, l2.attempt_id, l2.fence, l2.sequence, b.id AS build_id,
           row_number() OVER (
               PARTITION BY b.organization_id, b.id ORDER BY l2.cursor_id
           ) AS position
    FROM attempt_log_chunks AS l2
    JOIN attempts AS a ON a.id = l2.attempt_id AND a.organization_id = l2.organization_id
    JOIN nodes AS n ON n.id = a.node_id AND n.organization_id = a.organization_id
    JOIN builds AS b ON b.id = n.build_id AND b.organization_id = n.organization_id
) AS ranked
WHERE l.organization_id = ranked.organization_id
  AND l.attempt_id = ranked.attempt_id
  AND l.fence = ranked.fence
  AND l.sequence = ranked.sequence;

ALTER TABLE attempt_log_chunks ALTER COLUMN build_id SET NOT NULL;
ALTER TABLE attempt_log_chunks ALTER COLUMN build_position SET NOT NULL;
ALTER TABLE attempt_log_chunks
    ADD CONSTRAINT attempt_log_chunks_build_position_positive CHECK (build_position > 0);
ALTER TABLE attempt_log_chunks
    ADD CONSTRAINT attempt_log_chunks_build_position_unique
        UNIQUE (organization_id, build_id, build_position);

-- ADR 0012: a pre-v39 controller admitted during the rolling-upgrade window
-- still inserts chunks with the old column list. Derive the build and the
-- next position for such a legacy write under the same build-scoped lock
-- the v39 writer takes, so its chunk lands in the build's commit order
-- instead of failing the NOT NULL constraints; a v39 writer supplies both
-- and never enters the trigger body.
CREATE FUNCTION attempt_log_chunks_fill_compatibility_position()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    chunk_build_id uuid;
BEGIN
    SELECT n.build_id INTO chunk_build_id
    FROM attempts AS a
    JOIN nodes AS n
      ON n.id = a.node_id AND n.organization_id = a.organization_id
    WHERE a.organization_id = NEW.organization_id
      AND a.id = NEW.attempt_id;
    IF chunk_build_id IS NULL THEN
        RAISE EXCEPTION 'log chunk for attempt % has no build', NEW.attempt_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'mcloving.log.build.' || NEW.organization_id::text || '.' || chunk_build_id::text,
            0
        )
    );
    NEW.build_id := chunk_build_id;
    SELECT COALESCE(MAX(l.build_position), 0) + 1 INTO NEW.build_position
    FROM attempt_log_chunks AS l
    WHERE l.organization_id = NEW.organization_id
      AND l.build_id = chunk_build_id;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION attempt_log_chunks_fill_compatibility_position() FROM PUBLIC;
CREATE TRIGGER attempt_log_chunks_fill_compatibility_position
BEFORE INSERT ON attempt_log_chunks
FOR EACH ROW
WHEN (NEW.build_id IS NULL OR NEW.build_position IS NULL)
EXECUTE FUNCTION attempt_log_chunks_fill_compatibility_position();
