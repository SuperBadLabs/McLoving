CREATE TABLE external_read_consumer_versions (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    consumer_id text NOT NULL
        CHECK (consumer_id = btrim(consumer_id) AND length(consumer_id) BETWEEN 1 AND 256),
    generation bigint NOT NULL CHECK (generation > 0),
    authority text NOT NULL CHECK (authority IN ('jenkins_source', 'mcloving_target')),
    binding_digest bytea NOT NULL CHECK (octet_length(binding_digest) = 32),
    contract_digest bytea NOT NULL CHECK (octet_length(contract_digest) = 32),
    source_inventory_digest bytea NOT NULL CHECK (octet_length(source_inventory_digest) = 32),
    source_inventory_generation text NOT NULL
        CHECK (source_inventory_generation = btrim(source_inventory_generation)
               AND length(source_inventory_generation) BETWEEN 1 AND 512),
    source_endpoint text NOT NULL
        CHECK (source_endpoint = btrim(source_endpoint) AND length(source_endpoint) BETWEEN 1 AND 2048),
    source_caller text NOT NULL
        CHECK (source_caller = btrim(source_caller) AND length(source_caller) BETWEEN 1 AND 512),
    target_identity_id uuid NOT NULL,
    target_subject text NOT NULL
        CHECK (target_subject = btrim(target_subject) AND length(target_subject) BETWEEN 1 AND 512),
    target_api_base text NOT NULL
        CHECK (target_api_base = btrim(target_api_base) AND length(target_api_base) BETWEEN 1 AND 2048),
    target_api_version text NOT NULL CHECK (target_api_version = 'v1'),
    endpoint_contracts jsonb NOT NULL CHECK (jsonb_typeof(endpoint_contracts) = 'array'),
    retention_semantics text NOT NULL
        CHECK (retention_semantics = btrim(retention_semantics)
               AND length(retention_semantics) BETWEEN 1 AND 2048),
    url_semantics text NOT NULL
        CHECK (url_semantics = btrim(url_semantics) AND length(url_semantics) BETWEEN 1 AND 2048),
    rate_limit_per_minute bigint NOT NULL CHECK (rate_limit_per_minute BETWEEN 1 AND 1000000),
    observation_started_unix_ms bigint NOT NULL CHECK (observation_started_unix_ms > 0),
    observation_ended_unix_ms bigint NOT NULL
        CHECK (observation_ended_unix_ms > observation_started_unix_ms),
    source_reads_observed bigint NOT NULL CHECK (source_reads_observed >= 0),
    positive_authorization_digest bytea NOT NULL CHECK (octet_length(positive_authorization_digest) = 32),
    negative_authorization_digest bytea NOT NULL CHECK (octet_length(negative_authorization_digest) = 32),
    equivalence_digest bytea NOT NULL CHECK (octet_length(equivalence_digest) = 32),
    artifact_retrieval_digest bytea NOT NULL CHECK (octet_length(artifact_retrieval_digest) = 32),
    pagination_resume_digest bytea NOT NULL CHECK (octet_length(pagination_resume_digest) = 32),
    outage_behavior_digest bytea NOT NULL CHECK (octet_length(outage_behavior_digest) = 32),
    rollback_from_generation bigint CHECK (rollback_from_generation > 0),
    rollback_evidence_digest bytea CHECK (
        rollback_evidence_digest IS NULL OR octet_length(rollback_evidence_digest) = 32
    ),
    reviewer text NOT NULL
        CHECK (reviewer = btrim(reviewer) AND length(reviewer) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, project_id, consumer_id, generation),
    FOREIGN KEY (project_id, organization_id) REFERENCES projects(id, organization_id),
    FOREIGN KEY (target_identity_id, organization_id) REFERENCES identities(id, organization_id),
    CHECK (
        (rollback_from_generation IS NULL AND rollback_evidence_digest IS NULL)
        OR
        (rollback_from_generation IS NOT NULL AND rollback_evidence_digest IS NOT NULL)
    )
);

CREATE TABLE external_read_consumer_current (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    consumer_id text NOT NULL,
    current_generation bigint NOT NULL CHECK (current_generation > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, project_id, consumer_id),
    FOREIGN KEY (organization_id, project_id, consumer_id, current_generation)
        REFERENCES external_read_consumer_versions(
            organization_id, project_id, consumer_id, generation
        )
);

CREATE FUNCTION mcloving_guard_external_read_consumer_history()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514',
        MESSAGE = 'external read consumer history is immutable';
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_external_read_consumer_history() FROM PUBLIC;
CREATE TRIGGER external_read_consumer_versions_immutable
BEFORE UPDATE OR DELETE ON external_read_consumer_versions
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_external_read_consumer_history();

CREATE FUNCTION mcloving_guard_external_read_consumer_advance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.consumer_id IS DISTINCT FROM OLD.consumer_id
       OR NEW.current_generation <= OLD.current_generation
    THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'external read consumer pointer must advance monotonically';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_external_read_consumer_advance() FROM PUBLIC;
CREATE TRIGGER external_read_consumer_current_monotonic
BEFORE UPDATE ON external_read_consumer_current
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_external_read_consumer_advance();

GRANT SELECT ON external_read_consumer_versions, external_read_consumer_current
TO mcloving_tenant;

ALTER TABLE external_read_consumer_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_read_consumer_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY external_read_consumer_versions_tenant_policy
ON external_read_consumer_versions
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE external_read_consumer_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_read_consumer_current FORCE ROW LEVEL SECURITY;
CREATE POLICY external_read_consumer_current_tenant_policy
ON external_read_consumer_current
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);
