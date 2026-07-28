CREATE TABLE attempt_objects (
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    fence bigint NOT NULL CHECK (fence >= 0),
    kind text NOT NULL CHECK (kind IN ('log', 'artifact', 'result')),
    name text NOT NULL,
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    bytes bigint NOT NULL CHECK (bytes >= 0),
    status text NOT NULL DEFAULT 'available' CHECK (
        status IN ('available', 'missing', 'corrupt')
    ),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, attempt_id, fence, kind, name),
    FOREIGN KEY (attempt_id, organization_id)
        REFERENCES attempts(id, organization_id)
);

CREATE INDEX attempt_objects_digest_idx
    ON attempt_objects (organization_id, object_digest);
CREATE INDEX attempt_objects_gap_idx
    ON attempt_objects (organization_id, status, checked_at)
    WHERE status <> 'available';

GRANT SELECT, INSERT, UPDATE ON attempt_objects TO mcloving_tenant;

ALTER TABLE attempt_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempt_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY attempt_objects_tenant_policy ON attempt_objects
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
