-- Bounded checkpoint state belongs to one build; terminal receipts retain no file bytes.
ALTER TABLE builds
    ADD COLUMN workspace_namespace uuid UNIQUE,
    ADD COLUMN workspace_generation bigint NOT NULL DEFAULT 0 CHECK (workspace_generation >= 0),
    ADD COLUMN workspace_snapshot jsonb,
    ADD COLUMN workspace_receipt jsonb,
    ADD COLUMN workspace_closed boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT builds_workspace_shape CHECK (
        (workspace_namespace IS NULL AND workspace_generation = 0
         AND workspace_snapshot IS NULL AND workspace_receipt IS NULL AND NOT workspace_closed)
        OR (workspace_namespace IS NOT NULL AND dag_mode
            AND dag_contract -> 'workspace_transfer' IS NOT DISTINCT FROM '{"version":1}'::jsonb
            AND ((workspace_closed AND workspace_snapshot IS NULL)
                 OR (NOT workspace_closed AND workspace_snapshot IS NOT NULL)))
    ),
    ADD CONSTRAINT builds_workspace_receipt_shape CHECK (
        (workspace_generation = 0) = (workspace_receipt IS NULL)
    ),
    ADD CONSTRAINT builds_workspace_snapshot_bound CHECK (
        workspace_snapshot IS NULL OR octet_length(workspace_snapshot::text) <= 65536
    );
