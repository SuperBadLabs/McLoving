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
    input_bundle_digest bytea NOT NULL CHECK (
        octet_length(input_bundle_digest) = 32
    ),
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

CREATE FUNCTION mcloving_state_transfer_holds_valid(holds jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = public, pg_temp
AS $$
    SELECT jsonb_typeof(holds) = 'array'
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_array_elements(holds) AS entry(value)
           WHERE jsonb_typeof(value) <> 'object'
              OR jsonb_typeof(value -> 'record') IS DISTINCT FROM 'object'
              OR jsonb_typeof(value -> 'hold_id') IS DISTINCT FROM 'string'
              OR length(value ->> 'hold_id') NOT BETWEEN 1 AND 256
              OR jsonb_typeof(value -> 'scope') IS DISTINCT FROM 'string'
              OR length(value ->> 'scope') NOT BETWEEN 1 AND 1024
              OR jsonb_typeof(value -> 'reason') IS DISTINCT FROM 'string'
              OR length(value ->> 'reason') NOT BETWEEN 1 AND 1024
              OR CASE
                     WHEN jsonb_typeof(value -> 'placed_at_unix_ms') = 'number'
                      AND (value ->> 'placed_at_unix_ms') ~ '^(0|[1-9][0-9]*)$'
                     THEN (value ->> 'placed_at_unix_ms')::numeric
                          NOT BETWEEN 0 AND 9223372036854775807::numeric
                     ELSE true
                 END
              OR CASE
                     WHEN jsonb_typeof(value -> 'generation') = 'number'
                      AND (value ->> 'generation') ~ '^(0|[1-9][0-9]*)$'
                     THEN (value ->> 'generation')::numeric
                          NOT BETWEEN 1 AND 18446744073709551615::numeric
                     ELSE true
                 END
              OR jsonb_typeof(value -> 'release_authority') IS DISTINCT FROM 'string'
              OR length(value ->> 'release_authority') NOT BETWEEN 1 AND 512
              OR jsonb_typeof(value -> 'record' -> 'id') IS DISTINCT FROM 'string'
              OR length(value -> 'record' ->> 'id') NOT BETWEEN 1 AND 1024
              OR jsonb_typeof(value -> 'record' -> 'source_digest') IS DISTINCT FROM 'array'
              OR CASE
                     WHEN jsonb_typeof(value -> 'record' -> 'source_digest') = 'array'
                     THEN jsonb_array_length(value -> 'record' -> 'source_digest') <> 32
                     ELSE true
                 END
              OR EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(
                      CASE
                          WHEN jsonb_typeof(value -> 'record' -> 'source_digest') = 'array'
                          THEN value -> 'record' -> 'source_digest'
                          ELSE '[]'::jsonb
                      END
                  ) AS digest_element(value)
                  WHERE jsonb_typeof(digest_element.value) IS DISTINCT FROM 'number'
                     OR CASE
                            WHEN digest_element.value::text ~ '^(0|[1-9][0-9]{0,2})$'
                            THEN (digest_element.value::text)::integer NOT BETWEEN 0 AND 255
                            ELSE true
                        END
              )
              OR jsonb_typeof(value -> 'record' -> 'provenance') IS DISTINCT FROM 'string'
              OR length(value -> 'record' ->> 'provenance') NOT BETWEEN 1 AND 4096
       )
       AND (
           SELECT count(*) = count(DISTINCT value ->> 'hold_id')
           FROM jsonb_array_elements(holds) AS entry(value)
       )
$$;

REVOKE ALL ON FUNCTION mcloving_state_transfer_holds_valid(jsonb) FROM PUBLIC;

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
    active_holds jsonb NOT NULL CHECK (
        mcloving_state_transfer_holds_valid(active_holds)
    ),
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
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer protection cannot be deleted';
    END IF;
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
BEFORE UPDATE OR DELETE ON state_transfer_protections
FOR EACH ROW EXECUTE FUNCTION mcloving_state_transfer_protection_monotonic();

GRANT SELECT, INSERT ON state_transfer_receipts, state_transfer_records
TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE ON state_transfer_protections
TO mcloving_tenant;
GRANT EXECUTE ON FUNCTION mcloving_state_transfer_holds_valid(jsonb)
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
