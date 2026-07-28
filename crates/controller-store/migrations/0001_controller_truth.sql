CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE projects (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    slug text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (organization_id, slug),
    UNIQUE (id, organization_id)
);

CREATE TABLE builds (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    pipeline_digest bytea NOT NULL CHECK (octet_length(pipeline_digest) = 32),
    status text NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'aborted')),
    priority integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    UNIQUE (project_id, idempotency_key),
    UNIQUE (id, organization_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE TABLE nodes (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    build_id uuid NOT NULL,
    node_key text NOT NULL,
    status text NOT NULL CHECK (status IN ('queued', 'offered', 'running', 'succeeded', 'failed', 'aborted')),
    required_capabilities text[] NOT NULL DEFAULT '{}',
    priority integer NOT NULL DEFAULT 0,
    queued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (build_id, node_key),
    UNIQUE (id, organization_id),
    FOREIGN KEY (build_id, organization_id)
        REFERENCES builds(id, organization_id)
);

CREATE TABLE attempts (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    node_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal > 0),
    status text NOT NULL CHECK (
        status IN (
            'queued',
            'offered',
            'accepted',
            'running',
            'finalizing',
            'succeeded',
            'failed',
            'cancelling',
            'aborted',
            'reconciliation_required'
        )
    ),
    fence bigint NOT NULL DEFAULT 0 CHECK (fence >= 0),
    lease_owner text,
    lease_expires_at timestamptz,
    terminal_summary jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    UNIQUE (node_id, ordinal),
    UNIQUE (id, organization_id),
    FOREIGN KEY (node_id, organization_id)
        REFERENCES nodes(id, organization_id)
);

CREATE TABLE build_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id uuid NOT NULL,
    build_id uuid NOT NULL,
    kind text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (build_id, organization_id)
        REFERENCES builds(id, organization_id)
);

CREATE TABLE outbox (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    topic text NOT NULL,
    aggregate_id uuid NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    published_at timestamptz
);

CREATE INDEX nodes_claim_order_idx
    ON nodes (priority DESC, queued_at, id)
    WHERE status = 'queued';
CREATE INDEX nodes_capabilities_idx
    ON nodes USING gin (required_capabilities)
    WHERE status = 'queued';
CREATE INDEX attempts_active_lease_idx
    ON attempts (lease_expires_at, id)
    WHERE status IN ('offered', 'accepted', 'running', 'finalizing');
CREATE INDEX build_events_build_order_idx
    ON build_events (organization_id, build_id, id);
CREATE INDEX outbox_unpublished_idx
    ON outbox (id)
    WHERE published_at IS NULL;
