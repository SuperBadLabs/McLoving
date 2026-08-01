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
    binding_digest bytea NOT NULL CHECK (
        octet_length(binding_digest) = 32
        AND binding_digest <> decode(repeat('00', 32), 'hex')
    ),
    canonical_binding bytea NOT NULL CHECK (
        octet_length(canonical_binding) BETWEEN 1 AND 1048576
        AND binding_digest = sha256(canonical_binding)
    ),
    input_bundle_digest bytea NOT NULL CHECK (
        octet_length(input_bundle_digest) = 32
        AND input_bundle_digest <> decode(repeat('00', 32), 'hex')
    ),
    bundle_digest bytea NOT NULL CHECK (
        octet_length(bundle_digest) = 32
        AND bundle_digest <> decode(repeat('00', 32), 'hex')
    ),
    canonical_bundle bytea NOT NULL CHECK (
        octet_length(canonical_bundle) BETWEEN 1 AND 67108864
        AND bundle_digest = sha256(canonical_bundle)
    ),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (id, organization_id),
    UNIQUE (id, organization_id, project_id),
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

CREATE FUNCTION mcloving_state_transfer_digest_json(digest_value bytea)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = public, pg_temp
AS $$
    SELECT jsonb_agg(get_byte(digest_value, byte_index) ORDER BY byte_index)
    FROM generate_series(0, 31) AS offsets(byte_index)
$$;

REVOKE ALL ON FUNCTION mcloving_state_transfer_digest_json(bytea) FROM PUBLIC;

CREATE FUNCTION mcloving_validate_state_transfer_receipt()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    bundle_value jsonb;
    binding_value jsonb;
    expected_direction text;
BEGIN
    BEGIN
        bundle_value := convert_from(NEW.canonical_bundle, 'UTF8')::jsonb;
        binding_value := convert_from(NEW.canonical_binding, 'UTF8')::jsonb;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer receipt contains invalid canonical JSON';
    END;
    expected_direction := CASE NEW.direction
        WHEN 'jenkins_to_mcloving' THEN 'jenkins_to_mc_loving'
        WHEN 'mcloving_to_jenkins' THEN 'mc_loving_to_jenkins'
        ELSE NULL
    END;
    IF jsonb_typeof(bundle_value) IS DISTINCT FROM 'object'
       OR jsonb_typeof(binding_value) IS DISTINCT FROM 'object'
       OR bundle_value -> 'binding' IS DISTINCT FROM binding_value
       OR binding_value ->> 'schema' IS DISTINCT FROM 'mcloving.state-transfer/v1'
       OR binding_value ->> 'direction' IS DISTINCT FROM expected_direction
       OR binding_value -> 'source' ->> 'kind' IS DISTINCT FROM NEW.source_kind
       OR binding_value -> 'source' ->> 'instance_id'
            IS DISTINCT FROM NEW.source_instance_id
       OR binding_value -> 'source' ->> 'generation'
            IS DISTINCT FROM NEW.source_generation
       OR binding_value -> 'source' -> 'configuration_digest'
            IS DISTINCT FROM mcloving_state_transfer_digest_json(
                NEW.source_configuration_digest
            )
       OR binding_value -> 'destination' ->> 'kind'
            IS DISTINCT FROM NEW.destination_kind
       OR binding_value -> 'destination' ->> 'instance_id'
            IS DISTINCT FROM NEW.destination_instance_id
       OR binding_value -> 'destination' ->> 'generation'
            IS DISTINCT FROM NEW.destination_generation
       OR binding_value -> 'destination' -> 'configuration_digest'
            IS DISTINCT FROM mcloving_state_transfer_digest_json(
                NEW.destination_configuration_digest
            )
       OR binding_value -> 'source_export_digest'
            IS DISTINCT FROM mcloving_state_transfer_digest_json(
                NEW.source_export_digest
            )
       OR binding_value -> 'transform_implementation_digest'
            IS DISTINCT FROM mcloving_state_transfer_digest_json(
                NEW.transform_implementation_digest
            )
       OR binding_value -> 'transform_configuration_digest'
            IS DISTINCT FROM mcloving_state_transfer_digest_json(
                NEW.transform_configuration_digest
            )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer receipt binding is invalid';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_validate_state_transfer_receipt() FROM PUBLIC;

CREATE TRIGGER state_transfer_receipts_validate
BEFORE INSERT ON state_transfer_receipts
FOR EACH ROW EXECUTE FUNCTION mcloving_validate_state_transfer_receipt();

CREATE FUNCTION mcloving_state_transfer_normalize_holds(holds jsonb)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = public, pg_temp
AS $$
    SELECT COALESCE(jsonb_agg(value ORDER BY value ->> 'hold_id'), '[]'::jsonb)
    FROM jsonb_array_elements(holds) AS entry(value)
$$;

REVOKE ALL ON FUNCTION mcloving_state_transfer_normalize_holds(jsonb) FROM PUBLIC;

CREATE FUNCTION mcloving_state_transfer_protection_digest(
    policy_id text,
    policy_version text,
    policy_digest bytea,
    retain_until bigint,
    holds jsonb
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = public, pg_temp
AS $$
    SELECT sha256(convert_to(jsonb_build_object(
        'schema', 'mcloving.state-transfer-protection-row/v1',
        'retention_policy_id', policy_id,
        'retention_policy_version', policy_version,
        'retention_policy_digest', encode(policy_digest, 'hex'),
        'retain_until_unix_ms', retain_until,
        'active_holds', mcloving_state_transfer_normalize_holds(holds)
    )::text, 'UTF8'))
$$;

REVOKE ALL ON FUNCTION mcloving_state_transfer_protection_digest(
    text, text, bytea, bigint, jsonb
) FROM PUBLIC;

CREATE FUNCTION mcloving_state_transfer_receipt_has_protection(
    expected_organization_id uuid,
    expected_project_id uuid,
    expected_receipt_id uuid,
    expected_subject_digest bytea,
    expected_policy_id text,
    expected_policy_version text,
    expected_policy_digest bytea,
    expected_retain_until bigint,
    expected_holds jsonb
)
RETURNS boolean
LANGUAGE sql
STABLE
STRICT
SET search_path = public, pg_temp
AS $$
    WITH receipt AS (
        SELECT convert_from(canonical_bundle, 'UTF8')::jsonb AS bundle
        FROM state_transfer_receipts
        WHERE id = expected_receipt_id
          AND organization_id = expected_organization_id
          AND project_id = expected_project_id
    ),
    candidates AS (
        SELECT build.value AS entity
        FROM receipt
        CROSS JOIN LATERAL jsonb_array_elements(bundle -> 'jobs') AS job(value)
        CROSS JOIN LATERAL jsonb_array_elements(job.value -> 'builds') AS build(value)
        UNION ALL
        SELECT artifact.value
        FROM receipt
        CROSS JOIN LATERAL jsonb_array_elements(bundle -> 'jobs') AS job(value)
        CROSS JOIN LATERAL jsonb_array_elements(job.value -> 'builds') AS build(value)
        CROSS JOIN LATERAL jsonb_array_elements(build.value -> 'artifacts') AS artifact(value)
        UNION ALL
        SELECT workspace.value
        FROM receipt
        CROSS JOIN LATERAL jsonb_array_elements(bundle -> 'jobs') AS job(value)
        CROSS JOIN LATERAL jsonb_array_elements(job.value -> 'retained_workspaces') AS workspace(value)
        UNION ALL
        SELECT dependency.value
        FROM receipt
        CROSS JOIN LATERAL jsonb_array_elements(bundle -> 'jobs') AS job(value)
        CROSS JOIN LATERAL jsonb_array_elements(job.value -> 'persistent_dependencies') AS dependency(value)
    ),
    expected AS (
        SELECT mcloving_state_transfer_digest_json(expected_subject_digest) AS subject,
               jsonb_build_object(
                   'retention', jsonb_build_object(
                       'policy_id', expected_policy_id,
                       'policy_version', expected_policy_version,
                       'policy_digest', mcloving_state_transfer_digest_json(
                           expected_policy_digest
                       ),
                       'retain_until_unix_ms', expected_retain_until
                   ),
                   'active_holds', mcloving_state_transfer_normalize_holds(expected_holds)
               ) AS protection
    )
    SELECT EXISTS (
        SELECT 1
        FROM candidates
        CROSS JOIN expected
        WHERE entity -> 'record' -> 'source_digest' = expected.subject
          AND jsonb_set(
                  entity -> 'protection',
                  '{active_holds}',
                  mcloving_state_transfer_normalize_holds(
                      entity -> 'protection' -> 'active_holds'
                  )
              ) = expected.protection
    )
$$;

REVOKE ALL ON FUNCTION mcloving_state_transfer_receipt_has_protection(
    uuid, uuid, uuid, bytea, text, text, bytea, bigint, jsonb
) FROM PUBLIC;

CREATE TABLE state_transfer_protections (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    subject_digest bytea NOT NULL CHECK (
        octet_length(subject_digest) = 32
        AND subject_digest <> decode(repeat('00', 32), 'hex')
    ),
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
    protection_digest bytea NOT NULL CHECK (
        octet_length(protection_digest) = 32
        AND protection_digest = mcloving_state_transfer_protection_digest(
            retention_policy_id,
            retention_policy_version,
            retention_policy_digest,
            retain_until_unix_ms,
            active_holds
        )
    ),
    receipt_id uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, project_id, subject_digest),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (receipt_id, organization_id, project_id)
        REFERENCES state_transfer_receipts(id, organization_id, project_id)
);

-- SCM change records used by the migration rehearsal are a separate,
-- migration-writer-owned authority surface. The ordinary controller runtime
-- may read these rows but cannot create, replace, or delete them. Canonical
-- bytes are retained so PostgreSQL can enforce their exact digest without
-- depending on jsonb rendering details.
CREATE TABLE state_transfer_scm_evidence (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    receipt_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    fence bigint NOT NULL CHECK (fence >= 0),
    restore_epoch bigint NOT NULL CHECK (restore_epoch >= 0),
    agent_id text NOT NULL CHECK (length(agent_id) BETWEEN 1 AND 512),
    evidence_key text NOT NULL CHECK (length(evidence_key) BETWEEN 1 AND 256),
    canonical_evidence bytea NOT NULL CHECK (
        octet_length(canonical_evidence) BETWEEN 1 AND 1048576
    ),
    evidence_digest bytea NOT NULL CHECK (
        octet_length(evidence_digest) = 32
        AND evidence_digest = sha256(canonical_evidence)
    ),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, attempt_id, fence, evidence_key),
    FOREIGN KEY (receipt_id, organization_id, project_id)
        REFERENCES state_transfer_receipts(id, organization_id, project_id),
    FOREIGN KEY (attempt_id, organization_id)
        REFERENCES attempts(id, organization_id)
);

CREATE FUNCTION mcloving_state_transfer_scm_evidence_fenced()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM attempts AS a
        JOIN nodes AS n
          ON n.organization_id = a.organization_id
         AND n.id = a.node_id
        JOIN builds AS b
          ON b.organization_id = n.organization_id
         AND b.id = n.build_id
        CROSS JOIN controller_metadata AS m
        WHERE a.organization_id = NEW.organization_id
          AND a.id = NEW.attempt_id
          AND a.fence = NEW.fence
          AND a.restore_epoch = NEW.restore_epoch
          AND a.lease_owner = NEW.agent_id
          AND a.lease_expires_at > clock_timestamp()
          AND a.status IN ('running', 'finalizing')
          AND a.restore_epoch = m.restore_epoch
          AND b.project_id = NEW.project_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer SCM evidence lacks active fenced authority';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_state_transfer_scm_evidence_fenced() FROM PUBLIC;

CREATE TRIGGER state_transfer_scm_evidence_fenced
BEFORE INSERT ON state_transfer_scm_evidence
FOR EACH ROW EXECUTE FUNCTION mcloving_state_transfer_scm_evidence_fenced();

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

CREATE TRIGGER state_transfer_scm_evidence_immutable
BEFORE UPDATE OR DELETE ON state_transfer_scm_evidence
FOR EACH ROW EXECUTE FUNCTION mcloving_state_transfer_receipt_immutable();

CREATE FUNCTION mcloving_state_transfer_record_insert_open()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM audit_events
        WHERE organization_id = NEW.organization_id
          AND category = 'migration'
          AND action = 'state_transfer.imported'
          AND payload ->> 'receipt_id' = NEW.receipt_id::text
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer receipt is sealed against provenance appends';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_state_transfer_record_insert_open() FROM PUBLIC;

CREATE TRIGGER state_transfer_records_insert_open
BEFORE INSERT ON state_transfer_records
FOR EACH ROW EXECUTE FUNCTION mcloving_state_transfer_record_insert_open();

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
    IF NEW.protection_digest IS DISTINCT FROM
           mcloving_state_transfer_protection_digest(
               NEW.retention_policy_id,
               NEW.retention_policy_version,
               NEW.retention_policy_digest,
               NEW.retain_until_unix_ms,
               NEW.active_holds
           )
       OR NOT mcloving_state_transfer_receipt_has_protection(
           NEW.organization_id,
           NEW.project_id,
           NEW.receipt_id,
           NEW.subject_digest,
           NEW.retention_policy_id,
           NEW.retention_policy_version,
           NEW.retention_policy_digest,
           NEW.retain_until_unix_ms,
           NEW.active_holds
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer protection lineage is invalid';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
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
BEFORE INSERT OR UPDATE OR DELETE ON state_transfer_protections
FOR EACH ROW EXECUTE FUNCTION mcloving_state_transfer_protection_monotonic();

CREATE FUNCTION mcloving_state_transfer_receipt_complete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    bundle_value jsonb;
    expected_record_count bigint;
    record_sets_match boolean;
    actual_protection_count bigint;
    protection_sets_match boolean;
    expected_payload jsonb;
BEGIN
    bundle_value := convert_from(NEW.canonical_bundle, 'UTF8')::jsonb;
    IF jsonb_typeof(bundle_value -> 'expected_record_ids') IS DISTINCT FROM 'array'
       OR (CASE
              WHEN jsonb_typeof(bundle_value -> 'expected_record_ids') = 'array'
              THEN jsonb_array_length(bundle_value -> 'expected_record_ids') = 0
              ELSE true
          END)
       OR jsonb_typeof(bundle_value -> 'jobs') IS DISTINCT FROM 'array'
       OR (CASE
              WHEN jsonb_typeof(bundle_value -> 'jobs') = 'array'
              THEN jsonb_array_length(bundle_value -> 'jobs') = 0
              ELSE true
          END)
       OR EXISTS (
           SELECT 1
           FROM jsonb_array_elements(
               CASE
                   WHEN jsonb_typeof(bundle_value -> 'jobs') = 'array'
                   THEN bundle_value -> 'jobs'
                   ELSE '[]'::jsonb
               END
           ) AS job(value)
           WHERE jsonb_typeof(value) IS DISTINCT FROM 'object'
              OR jsonb_typeof(value -> 'record') IS DISTINCT FROM 'object'
              OR jsonb_typeof(value -> 'builds') IS DISTINCT FROM 'array'
              OR jsonb_typeof(value -> 'retained_workspaces') IS DISTINCT FROM 'array'
              OR jsonb_typeof(value -> 'persistent_dependencies') IS DISTINCT FROM 'array'
       )
       OR EXISTS (
           SELECT 1
           FROM jsonb_array_elements(bundle_value -> 'expected_record_ids') AS item(value)
           WHERE jsonb_typeof(value) IS DISTINCT FROM 'string'
              OR length(value #>> '{}') NOT BETWEEN 1 AND 1024
       )
       OR EXISTS (
           SELECT 1
           FROM jsonb_array_elements_text(
               bundle_value -> 'expected_record_ids'
           ) AS item(record_id)
           GROUP BY record_id
           HAVING count(*) <> 1
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer expected record set is invalid';
    END IF;
    WITH expected_ids AS MATERIALIZED (
        SELECT value AS record_id
        FROM jsonb_array_elements_text(
            bundle_value -> 'expected_record_ids'
        ) AS item(value)
    ),
    canonical_records AS MATERIALIZED (
        SELECT record_value ->> 'id' AS record_id,
               record_value -> 'source_digest' AS source_digest,
               record_value ->> 'provenance' AS provenance
        FROM jsonb_path_query(
            bundle_value,
            'strict $.**.record'
        ) AS item(record_value)
    ),
    stored_records AS MATERIALIZED (
        SELECT record_id,
               mcloving_state_transfer_digest_json(source_digest) AS source_digest,
               provenance
        FROM state_transfer_records
        WHERE organization_id = NEW.organization_id
          AND receipt_id = NEW.id
    )
    SELECT (SELECT count(*) FROM expected_ids),
           (SELECT count(*) FROM canonical_records) =
               (SELECT count(*) FROM expected_ids)
           AND (SELECT count(*) FROM stored_records) =
               (SELECT count(*) FROM expected_ids)
           AND NOT EXISTS (
               SELECT record_id FROM expected_ids
               EXCEPT
               SELECT record_id FROM canonical_records
           )
           AND NOT EXISTS (
               SELECT record_id FROM canonical_records
               EXCEPT
               SELECT record_id FROM expected_ids
           )
           AND NOT EXISTS (
               SELECT record_id, source_digest, provenance FROM canonical_records
               EXCEPT
               SELECT record_id, source_digest, provenance FROM stored_records
           )
           AND NOT EXISTS (
               SELECT record_id, source_digest, provenance FROM stored_records
               EXCEPT
               SELECT record_id, source_digest, provenance FROM canonical_records
           )
    INTO expected_record_count, record_sets_match;
    IF NOT record_sets_match THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer provenance rows are incomplete';
    END IF;
    WITH candidates AS MATERIALIZED (
        SELECT build.value AS entity
        FROM jsonb_array_elements(bundle_value -> 'jobs') AS job(value)
        CROSS JOIN LATERAL jsonb_array_elements(
            job.value -> 'builds'
        ) AS build(value)
        UNION ALL
        SELECT artifact.value
        FROM jsonb_array_elements(bundle_value -> 'jobs') AS job(value)
        CROSS JOIN LATERAL jsonb_array_elements(
            job.value -> 'builds'
        ) AS build(value)
        CROSS JOIN LATERAL jsonb_array_elements(
            build.value -> 'artifacts'
        ) AS artifact(value)
        UNION ALL
        SELECT workspace.value
        FROM jsonb_array_elements(bundle_value -> 'jobs') AS job(value)
        CROSS JOIN LATERAL jsonb_array_elements(
            job.value -> 'retained_workspaces'
        ) AS workspace(value)
        UNION ALL
        SELECT dependency.value
        FROM jsonb_array_elements(bundle_value -> 'jobs') AS job(value)
        CROSS JOIN LATERAL jsonb_array_elements(
            job.value -> 'persistent_dependencies'
        ) AS dependency(value)
    ),
    expected_protections AS MATERIALIZED (
        SELECT DISTINCT jsonb_build_object(
            'subject_digest', entity -> 'record' -> 'source_digest',
            'retention_policy_id',
                entity -> 'protection' -> 'retention' -> 'policy_id',
            'retention_policy_version',
                entity -> 'protection' -> 'retention' -> 'policy_version',
            'retention_policy_digest',
                entity -> 'protection' -> 'retention' -> 'policy_digest',
            'retain_until_unix_ms',
                entity -> 'protection' -> 'retention' -> 'retain_until_unix_ms',
            'active_holds', mcloving_state_transfer_normalize_holds(
                entity -> 'protection' -> 'active_holds'
            )
        ) AS protection
        FROM candidates
    ),
    stored_protections AS MATERIALIZED (
        SELECT jsonb_build_object(
            'subject_digest',
                mcloving_state_transfer_digest_json(subject_digest),
            'retention_policy_id', retention_policy_id,
            'retention_policy_version', retention_policy_version,
            'retention_policy_digest',
                mcloving_state_transfer_digest_json(retention_policy_digest),
            'retain_until_unix_ms', retain_until_unix_ms,
            'active_holds',
                mcloving_state_transfer_normalize_holds(active_holds)
        ) AS protection
        FROM state_transfer_protections
        WHERE organization_id = NEW.organization_id
          AND project_id = NEW.project_id
          AND receipt_id = NEW.id
    )
    SELECT (SELECT count(*) FROM stored_protections),
           (SELECT count(*) FROM expected_protections) =
               (SELECT count(*) FROM stored_protections)
           AND NOT EXISTS (
               SELECT protection FROM expected_protections
               EXCEPT
               SELECT protection FROM stored_protections
           )
           AND NOT EXISTS (
               SELECT protection FROM stored_protections
               EXCEPT
               SELECT protection FROM expected_protections
           )
    INTO actual_protection_count, protection_sets_match;
    IF NOT protection_sets_match THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer protection rows are incomplete';
    END IF;
    expected_payload := jsonb_build_object(
        'receipt_id', NEW.id,
        'project_id', NEW.project_id,
        'direction', NEW.direction,
        'binding_digest', encode(NEW.binding_digest, 'hex'),
        'bundle_digest', encode(NEW.bundle_digest, 'hex'),
        'source_export_digest', encode(NEW.source_export_digest, 'hex'),
        'record_count', expected_record_count,
        'protection_count', actual_protection_count
    );
    IF (
           SELECT count(*)
           FROM outbox
           WHERE organization_id = NEW.organization_id
             AND topic = 'state_transfer.imported'
             AND aggregate_id = NEW.id
             AND payload = expected_payload
       ) <> 1
       OR (
           SELECT count(*)
           FROM audit_events
           WHERE organization_id = NEW.organization_id
             AND category = 'migration'
             AND actor_subject = NEW.actor_subject
             AND action = 'state_transfer.imported'
             AND subject = format(
                 'project:%s:state-transfer:%s',
                 NEW.project_id,
                 NEW.id
             )
             AND payload = expected_payload
       ) <> 1
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving state-transfer receipt lacks its exact audit/outbox proof';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_state_transfer_receipt_complete() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER state_transfer_receipts_complete
AFTER INSERT ON state_transfer_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mcloving_state_transfer_receipt_complete();

-- Runtime controller sessions may consume committed transfer truth, but they
-- cannot construct it with direct SQL. Imports use the separately privileged
-- migration connection only after the Rust validator has accepted the complete
-- canonical schema and semantic invariants.
GRANT SELECT ON state_transfer_receipts, state_transfer_records,
    state_transfer_protections, state_transfer_scm_evidence
TO mcloving_tenant;
GRANT EXECUTE ON FUNCTION mcloving_state_transfer_holds_valid(jsonb)
TO mcloving_tenant;
GRANT EXECUTE ON FUNCTION mcloving_state_transfer_digest_json(bytea)
TO mcloving_tenant;
GRANT EXECUTE ON FUNCTION mcloving_state_transfer_normalize_holds(jsonb)
TO mcloving_tenant;
GRANT EXECUTE ON FUNCTION mcloving_state_transfer_protection_digest(
    text, text, bytea, bigint, jsonb
) TO mcloving_tenant;
GRANT EXECUTE ON FUNCTION mcloving_state_transfer_receipt_has_protection(
    uuid, uuid, uuid, bytea, text, text, bytea, bigint, jsonb
) TO mcloving_tenant;

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

ALTER TABLE state_transfer_scm_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE state_transfer_scm_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY state_transfer_scm_evidence_tenant_policy
ON state_transfer_scm_evidence
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
