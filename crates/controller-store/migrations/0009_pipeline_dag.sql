ALTER TABLE builds
    ADD COLUMN dag_mode boolean NOT NULL DEFAULT false;

ALTER TABLE nodes DROP CONSTRAINT nodes_status_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_status_check CHECK (
    status IN (
        'blocked',
        'queued',
        'offered',
        'running',
        'succeeded',
        'failed',
        'aborted',
        'skipped',
        'reconciliation_required'
    )
);

ALTER TABLE nodes
    ADD COLUMN node_kind text NOT NULL DEFAULT 'work'
        CHECK (node_kind IN ('work', 'join', 'post')),
    ADD COLUMN fail_fast boolean NOT NULL DEFAULT false,
    ADD COLUMN max_attempts integer NOT NULL DEFAULT 1
        CHECK (max_attempts BETWEEN 1 AND 16),
    ADD COLUMN logical_outcome text
        CHECK (logical_outcome IN ('succeeded', 'failed', 'aborted', 'skipped')),
    ADD COLUMN cancellation_requested_at timestamptz;

ALTER TABLE nodes
    ADD CONSTRAINT nodes_dag_identity_unique
    UNIQUE (id, organization_id, build_id);

CREATE TABLE node_dependencies (
    organization_id uuid NOT NULL,
    build_id uuid NOT NULL,
    parent_node_id uuid NOT NULL,
    child_node_id uuid NOT NULL,
    condition text NOT NULL CHECK (condition IN ('succeeded', 'completed')),
    PRIMARY KEY (organization_id, parent_node_id, child_node_id),
    CHECK (parent_node_id <> child_node_id),
    FOREIGN KEY (build_id, organization_id)
        REFERENCES builds(id, organization_id),
    FOREIGN KEY (parent_node_id, organization_id, build_id)
        REFERENCES nodes(id, organization_id, build_id),
    FOREIGN KEY (child_node_id, organization_id, build_id)
        REFERENCES nodes(id, organization_id, build_id)
);

CREATE INDEX node_dependencies_child_idx
    ON node_dependencies (organization_id, child_node_id, parent_node_id);
CREATE INDEX nodes_dag_ready_idx
    ON nodes (organization_id, required_trust_pool, priority DESC, queued_at, id)
    WHERE status = 'queued';

GRANT SELECT, INSERT, UPDATE, DELETE ON node_dependencies TO mcloving_tenant;

ALTER TABLE node_dependencies ENABLE ROW LEVEL SECURITY;
ALTER TABLE node_dependencies FORCE ROW LEVEL SECURITY;
CREATE POLICY node_dependencies_tenant_policy ON node_dependencies
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
