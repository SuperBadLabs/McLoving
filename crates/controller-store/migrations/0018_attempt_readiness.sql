-- Persist the dependency generation that made each attempt eligible to run.
-- `created_at` remains admission history; blocked attempts stay NULL until
-- their dependencies are satisfied.
ALTER TABLE attempts
ADD COLUMN ready_at timestamptz DEFAULT clock_timestamp();

-- During the declared rolling-upgrade window, a pre-v18 controller omits the
-- new column.  The default makes those runnable attempts ready.  A legacy DAG
-- admission also omits the column for blocked attempts, so the compatibility
-- trigger clears the generated default while the owning node is blocked.
-- New controllers can still explicitly insert NULL for a dependency-blocked
-- retry whose node transition occurs later in the same transaction.
CREATE FUNCTION attempts_preserve_compatibility_readiness()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'queued' AND EXISTS (
        SELECT 1
        FROM nodes AS node
        WHERE node.organization_id = NEW.organization_id
          AND node.id = NEW.node_id
          AND node.status = 'blocked'
    ) THEN
        NEW.ready_at := NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER attempts_preserve_compatibility_readiness
BEFORE INSERT ON attempts
FOR EACH ROW
EXECUTE FUNCTION attempts_preserve_compatibility_readiness();

-- Pre-v18 retry writers insert the new queued attempt while its node is still
-- running/terminal, then move the node back to queued.  Translate that second
-- statement under the same build-scoped lock used by v18 writers so a reopened
-- dependency cannot leave the legacy retry prematurely ready.
CREATE FUNCTION nodes_translate_compatibility_retry_readiness()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    dependencies_ready boolean;
    compatibility_ready_at timestamptz;
BEGIN
    IF OLD.status IS NOT DISTINCT FROM NEW.status
       OR NEW.status NOT IN ('queued', 'blocked') THEN
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('mcloving.dag.retry.' || NEW.build_id::text, 0)
    );
    SELECT NOT EXISTS (
        SELECT 1
        FROM node_dependencies AS dependency
        JOIN nodes AS parent
          ON parent.id = dependency.parent_node_id
         AND parent.organization_id = dependency.organization_id
        WHERE dependency.organization_id = NEW.organization_id
          AND dependency.child_node_id = NEW.id
          AND (
              (
                  dependency.condition = 'succeeded'
                  AND parent.status <> 'succeeded'
              )
              OR (
                  dependency.condition = 'completed'
                  AND parent.status NOT IN (
                      'succeeded', 'failed', 'aborted', 'skipped'
                  )
              )
          )
    ) INTO dependencies_ready;

    IF NEW.status = 'blocked' OR NOT dependencies_ready THEN
        NEW.status := 'blocked';
        NEW.queued_at := OLD.queued_at;
        UPDATE attempts AS attempt
        SET ready_at = NULL
        WHERE attempt.id = (
            SELECT candidate.id
            FROM attempts AS candidate
            WHERE candidate.organization_id = NEW.organization_id
              AND candidate.node_id = NEW.id
              AND candidate.status = 'queued'
            ORDER BY candidate.ordinal DESC
            LIMIT 1
        );
    ELSE
        compatibility_ready_at := clock_timestamp();
        NEW.queued_at := compatibility_ready_at;
        UPDATE attempts AS attempt
        SET ready_at = GREATEST(attempt.created_at, compatibility_ready_at)
        WHERE attempt.id = (
            SELECT candidate.id
            FROM attempts AS candidate
            WHERE candidate.organization_id = NEW.organization_id
              AND candidate.node_id = NEW.id
              AND candidate.status = 'queued'
            ORDER BY candidate.ordinal DESC
            LIMIT 1
        );
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER nodes_translate_compatibility_retry_readiness
BEFORE UPDATE OF status ON nodes
FOR EACH ROW
EXECUTE FUNCTION nodes_translate_compatibility_retry_readiness();

-- Historical running/terminal attempts predate explicit readiness.  The first
-- durable running event is the narrowest safe reconstruction; attempts that
-- never ran use completion as their generation decision point.  Currently
-- runnable attempts use their node's durable queue timestamp.  Still-blocked
-- attempts intentionally remain NULL.
UPDATE attempts AS attempt
SET ready_at = CASE
    WHEN node.status = 'blocked' AND attempt.status = 'queued' THEN NULL
    ELSE GREATEST(
        attempt.created_at,
        COALESCE(
            (
                SELECT MIN(event.created_at)
                FROM build_events AS event
                WHERE event.organization_id = attempt.organization_id
                  AND event.kind = 'attempt.running'
                  AND event.payload @> jsonb_build_object(
                      'attempt_id', attempt.id,
                      'fence', attempt.fence
                  )
            ),
            attempt.completed_at,
            node.queued_at,
            attempt.created_at
        )
    )
END
FROM nodes AS node
WHERE node.organization_id = attempt.organization_id
  AND node.id = attempt.node_id;

ALTER TABLE attempts
ADD CONSTRAINT attempts_ready_after_creation
CHECK (ready_at IS NULL OR ready_at >= created_at);
