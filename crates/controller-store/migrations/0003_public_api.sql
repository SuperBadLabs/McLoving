ALTER TABLE nodes
    ADD COLUMN execution_spec jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE builds
    ADD COLUMN cancellation_requested_at timestamptz;

CREATE TABLE attempt_log_chunks (
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    fence bigint NOT NULL CHECK (fence >= 0),
    sequence bigint NOT NULL CHECK (sequence >= 0),
    stream text NOT NULL CHECK (stream IN ('stdout', 'stderr')),
    content bytea NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, attempt_id, fence, sequence),
    FOREIGN KEY (attempt_id, organization_id)
        REFERENCES attempts(id, organization_id)
);

CREATE INDEX attempt_log_chunks_read_idx
    ON attempt_log_chunks (organization_id, attempt_id, sequence);

GRANT SELECT, INSERT, UPDATE, DELETE ON attempt_log_chunks TO mcloving_tenant;

ALTER TABLE attempt_log_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempt_log_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY attempt_log_chunks_tenant_policy ON attempt_log_chunks
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
