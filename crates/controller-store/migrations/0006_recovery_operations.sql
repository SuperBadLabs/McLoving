CREATE TABLE controller_metadata (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    restore_epoch bigint NOT NULL CHECK (restore_epoch > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO controller_metadata (singleton, restore_epoch)
VALUES (true, 1);

CREATE TABLE recovery_points (
    backup_id text PRIMARY KEY CHECK (length(backup_id) BETWEEN 1 AND 256),
    restore_epoch bigint NOT NULL CHECK (restore_epoch > 0),
    recovery_lsn pg_lsn,
    sealed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE restore_epochs (
    restore_epoch bigint PRIMARY KEY CHECK (restore_epoch > 1),
    backup_id text NOT NULL UNIQUE REFERENCES recovery_points(backup_id),
    recovery_lsn pg_lsn NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    affected_attempts bigint NOT NULL CHECK (affected_attempts >= 0),
    activated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE builds DROP CONSTRAINT builds_status_check;
ALTER TABLE builds ADD CONSTRAINT builds_status_check CHECK (
    status IN (
        'queued',
        'running',
        'succeeded',
        'failed',
        'aborted',
        'reconciliation_required'
    )
);

ALTER TABLE nodes DROP CONSTRAINT nodes_status_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_status_check CHECK (
    status IN (
        'queued',
        'offered',
        'running',
        'succeeded',
        'failed',
        'aborted',
        'reconciliation_required'
    )
);

ALTER TABLE attempts
    ADD COLUMN restore_epoch bigint NOT NULL DEFAULT 1
    CHECK (restore_epoch > 0);

CREATE INDEX attempts_restore_epoch_idx
    ON attempts (restore_epoch, status, id)
    WHERE status IN (
        'offered',
        'accepted',
        'running',
        'finalizing',
        'cancelling'
    );

CREATE TABLE object_retention (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    retain_until timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, object_digest)
);

CREATE TABLE legal_holds (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    hold_key text NOT NULL CHECK (length(hold_key) BETWEEN 1 AND 256),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    released_at timestamptz,
    UNIQUE (organization_id, object_digest, hold_key)
);

CREATE INDEX legal_holds_active_idx
    ON legal_holds (organization_id, object_digest, hold_key)
    WHERE released_at IS NULL;

CREATE TABLE object_deletion_claims (
    object_digest bytea PRIMARY KEY CHECK (octet_length(object_digest) = 32),
    claim_token uuid NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('claimed', 'deleted')),
    claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    CHECK (
        (status = 'claimed' AND completed_at IS NULL)
        OR (status = 'deleted' AND completed_at IS NOT NULL)
    )
);

CREATE FUNCTION mcloving_object_deletion_claim_exists(candidate bytea)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM object_deletion_claims
        WHERE object_digest = candidate
    )
$$;

REVOKE ALL ON FUNCTION mcloving_object_deletion_claim_exists(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mcloving_object_deletion_claim_exists(bytea)
TO mcloving_tenant;

GRANT SELECT ON controller_metadata TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE ON object_retention, legal_holds
TO mcloving_tenant;

ALTER TABLE object_retention ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_retention FORCE ROW LEVEL SECURITY;
CREATE POLICY object_retention_tenant_policy ON object_retention
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE legal_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE legal_holds FORCE ROW LEVEL SECURITY;
CREATE POLICY legal_holds_tenant_policy ON legal_holds
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
