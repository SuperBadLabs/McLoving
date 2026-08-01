-- Persist the dependency generation that made each attempt eligible to run.
-- `created_at` remains admission history; blocked attempts stay NULL until
-- their dependencies are satisfied.
ALTER TABLE attempts
ADD COLUMN ready_at timestamptz;

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
