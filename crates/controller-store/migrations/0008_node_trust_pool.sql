-- Existing nodes cannot be assigned a trust pool safely from a global
-- default. Operators may create and populate this table before the upgrade
-- for nodes whose owning agent session is no longer durable. The migration
-- consumes and drops it only after every node has an explicit answer.
CREATE TABLE IF NOT EXISTS node_trust_pool_migration_map (
    organization_id uuid NOT NULL,
    node_id uuid NOT NULL,
    required_trust_pool text NOT NULL
        CHECK (btrim(required_trust_pool) <> ''),
    PRIMARY KEY (organization_id, node_id),
    FOREIGN KEY (node_id, organization_id)
        REFERENCES nodes(id, organization_id)
);

ALTER TABLE nodes
    ADD COLUMN required_trust_pool text;

-- For owned nodes, the latest attempt's durable owner identifies the exact
-- authenticated session trust pool. This is evidence, not an inferred
-- platform default.
WITH latest_owned_attempt AS (
    SELECT DISTINCT ON (a.organization_id, a.node_id)
           a.organization_id,
           a.node_id,
           s.trust_pool
    FROM attempts AS a
    JOIN agent_sessions AS s
      ON s.agent_id = a.lease_owner
    WHERE a.lease_owner IS NOT NULL
      AND a.status IN (
          'offered', 'accepted', 'running', 'finalizing', 'cancelling',
          'reconciliation_required'
      )
    ORDER BY a.organization_id, a.node_id, a.ordinal DESC
)
UPDATE nodes AS n
SET required_trust_pool = latest_owned_attempt.trust_pool
FROM latest_owned_attempt
WHERE n.organization_id = latest_owned_attempt.organization_id
  AND n.id = latest_owned_attempt.node_id;

-- Explicit operator mappings are authoritative and may intentionally
-- override a still-present historical session.
UPDATE nodes AS n
SET required_trust_pool = migration.required_trust_pool
FROM node_trust_pool_migration_map AS migration
WHERE n.organization_id = migration.organization_id
  AND n.id = migration.node_id;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM nodes WHERE required_trust_pool IS NULL) THEN
        RAISE EXCEPTION USING
            MESSAGE = 'node trust-pool migration requires explicit mappings',
            HINT = 'before retrying, create and populate node_trust_pool_migration_map for every unmapped node';
    END IF;
END
$$;

ALTER TABLE nodes
    ALTER COLUMN required_trust_pool SET NOT NULL,
    ADD CONSTRAINT nodes_required_trust_pool_nonempty
        CHECK (btrim(required_trust_pool) <> '');

CREATE INDEX nodes_trust_pool_claim_idx
    ON nodes (organization_id, required_trust_pool, priority DESC, queued_at, id)
    WHERE status = 'queued';

DROP TABLE node_trust_pool_migration_map;
