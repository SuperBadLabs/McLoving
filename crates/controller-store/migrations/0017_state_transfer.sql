CREATE TABLE state_transfer_receipts (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    direction text NOT NULL CHECK (
        direction IN ('jenkins_to_mcloving', 'mcloving_to_jenkins')
    ),
    source_kind text NOT NULL CHECK (length(source_kind) BETWEEN 1 AND 64),
    source_instance_id text NOT NULL CHECK (
        length(source_instance_id) BETWEEN 1 AND 512
    ),
    source_generation text NOT NULL CHECK (
        length(source_generation) BETWEEN 1 AND 512
    ),
    source_configuration_digest bytea NOT NULL CHECK (
        octet_length(source_configuration_digest) = 32
    ),
    destination_kind text NOT NULL CHECK (
        length(destination_kind) BETWEEN 1 AND 64
    ),
    destination_instance_id text NOT NULL CHECK (
        length(destination_instance_id) BETWEEN 1 AND 512
    ),
    destination_generation text NOT NULL CHECK (
        length(destination_generation) BETWEEN 1 AND 512
    ),
    destination_configuration_digest bytea NOT NULL CHECK (
        octet_length(destination_configuration_digest) = 32
    ),
    source_export_digest bytea NOT NULL CHECK (
        octet_length(source_export_digest) = 32
    ),
    transform_implementation_digest bytea NOT NULL CHECK (
        octet_length(transform_implementation_digest) = 32
    ),
    transform_configuration_digest bytea NOT NULL CHECK (
        octet_length(transform_configuration_digest) = 32
    ),
    binding_digest bytea NOT NULL CHECK (octet_length(binding_digest) = 32),
    bundle_digest bytea NOT NULL CHECK (octet_length(bundle_digest) = 32),
    canonical_bundle bytea NOT NULL CHECK (
        octet_length(canonical_bundle) BETWEEN 1 AND 67108864
    ),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (id, organization_id),
    UNIQUE (
        organization_id,
        project_id,
        direction,
        source_kind,
        source_instance_id,
        source_generation,
        destination_kind,
        destination_instance_id,
        destination_generation,
        source_export_digest,
        transform_implementation_digest,
        transform_configuration_digest
    ),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE TABLE state_transfer_records (
    organization_id uuid NOT NULL,
    receipt_id uuid NOT NULL,
    record_id text NOT NULL CHECK (length(record_id) BETWEEN 1 AND 1024),
    source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32),
    provenance text NOT NULL CHECK (length(provenance) BETWEEN 1 AND 4096),
    PRIMARY KEY (organization_id, receipt_id, record_id),
    FOREIGN KEY (receipt_id, organization_id)
        REFERENCES state_transfer_receipts(id, organization_id)
);

CREATE TABLE state_transfer_protections (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    retention_policy_id text NOT NULL CHECK (
        length(retention_policy_id) BETWEEN 1 AND 512
    ),
    retention_policy_version text NOT NULL CHECK (
        length(retention_policy_version) BETWEEN 1 AND 128
    ),
    retention_policy_digest bytea NOT NULL CHECK (
        octet_length(retention_policy_digest) = 32
    ),
    retain_until_unix_ms bigint NOT NULL CHECK (retain_until_unix_ms >= 0),
    active_holds jsonb NOT NULL CHECK (jsonb_typeof(active_holds) = 'array'),
    protection_digest bytea NOT NULL CHECK (octet_length(protection_digest) = 32),
    receipt_id uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, project_id, subject_digest),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (receipt_id, organization_id)
        REFERENCES state_transfer_receipts(id, organization_id)
);

CREATE FUNCTION mcloving_state_transfer_receipt_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'mcloving state-transfer receipt is immutable';
END
$$;

REVOKE ALL ON FUNCTION mcloving_state_transfer_receipt_immutable() FROM PUBLIC;

CREATE TRIGGER state_transfer_receipts_immutable
BEFORE UPDATE OR DELETE ON state_transfer_receipts
FOR EACH ROW EXECUTE FUNCTION mcloving_state_transfer_receipt_immutable();

CREATE TRIGGER state_transfer_records_immutable
BEFORE UPDATE OR DELETE ON state_transfer_records
FOR EACH ROW EXECUTE FUNCTION mcloving_state_transfer_receipt_immutable();

CREATE FUNCTION mcloving_state_transfer_protection_monotonic()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.subject_digest IS DISTINCT FROM OLD.subject_digest
       OR NEW.retain_until_unix_ms < OLD.retain_until_unix_ms
       OR NOT (NEW.active_holds @> OLD.active_holds)
       OR (
           NEW.retain_until_unix_ms = OLD.retain_until_unix_ms
           AND (
               NEW.retention_policy_id IS DISTINCT FROM OLD.retention_policy_id
               OR NEW.retention_policy_version IS DISTINCT FROM OLD.retention_policy_version
               OR NEW.retention_policy_digest IS DISTINCT FROM OLD.retention_policy_digest
           )
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer protection cannot regress';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_state_transfer_protection_monotonic() FROM PUBLIC;

CREATE TRIGGER state_transfer_protections_monotonic
BEFORE UPDATE ON state_transfer_protections
FOR EACH ROW EXECUTE FUNCTION mcloving_state_transfer_protection_monotonic();

GRANT SELECT, INSERT ON state_transfer_receipts, state_transfer_records
TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE ON state_transfer_protections
TO mcloving_tenant;

ALTER TABLE state_transfer_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE state_transfer_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY state_transfer_receipts_tenant_policy ON state_transfer_receipts
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE state_transfer_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE state_transfer_records FORCE ROW LEVEL SECURITY;
CREATE POLICY state_transfer_records_tenant_policy ON state_transfer_records
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE state_transfer_protections ENABLE ROW LEVEL SECURITY;
ALTER TABLE state_transfer_protections FORCE ROW LEVEL SECURITY;
CREATE POLICY state_transfer_protections_tenant_policy ON state_transfer_protections
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
