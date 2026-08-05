CREATE TABLE external_admin_client_versions (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    client_id text NOT NULL
        CHECK (client_id = btrim(client_id) AND length(client_id) BETWEEN 1 AND 256),
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
    source_authentication text NOT NULL
        CHECK (source_authentication = btrim(source_authentication)
               AND length(source_authentication) BETWEEN 1 AND 512),
    source_scope text NOT NULL
        CHECK (source_scope = btrim(source_scope) AND length(source_scope) BETWEEN 1 AND 512),
    target_identity_id uuid NOT NULL,
    target_subject text NOT NULL
        CHECK (target_subject = btrim(target_subject) AND length(target_subject) BETWEEN 1 AND 512),
    target_api_base text NOT NULL
        CHECK (target_api_base = btrim(target_api_base) AND length(target_api_base) BETWEEN 1 AND 2048),
    target_api_version text NOT NULL CHECK (target_api_version = 'v1'),
    operation_contracts jsonb NOT NULL CHECK (jsonb_typeof(operation_contracts) = 'array'),
    observation_started_unix_ms bigint NOT NULL CHECK (observation_started_unix_ms > 0),
    observation_ended_unix_ms bigint NOT NULL
        CHECK (observation_ended_unix_ms > observation_started_unix_ms),
    source_writes_observed bigint NOT NULL CHECK (source_writes_observed >= 0),
    positive_authorization_digest bytea NOT NULL CHECK (octet_length(positive_authorization_digest) = 32),
    negative_authorization_digest bytea NOT NULL CHECK (octet_length(negative_authorization_digest) = 32),
    convergence_digest bytea NOT NULL CHECK (octet_length(convergence_digest) = 32),
    ordering_idempotency_digest bytea NOT NULL CHECK (octet_length(ordering_idempotency_digest) = 32),
    partial_failure_retry_digest bytea NOT NULL CHECK (octet_length(partial_failure_retry_digest) = 32),
    conflict_digest bytea NOT NULL CHECK (octet_length(conflict_digest) = 32),
    rollback_from_generation bigint CHECK (rollback_from_generation > 0),
    rollback_evidence_digest bytea CHECK (
        rollback_evidence_digest IS NULL OR octet_length(rollback_evidence_digest) = 32
    ),
    reviewer text NOT NULL
        CHECK (reviewer = btrim(reviewer) AND length(reviewer) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, project_id, client_id, generation),
    FOREIGN KEY (project_id, organization_id) REFERENCES projects(id, organization_id),
    FOREIGN KEY (target_identity_id, organization_id) REFERENCES identities(id, organization_id),
    CHECK (
        (rollback_from_generation IS NULL AND rollback_evidence_digest IS NULL)
        OR
        (rollback_from_generation IS NOT NULL AND rollback_evidence_digest IS NOT NULL)
    )
);

CREATE TABLE external_admin_client_current (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    client_id text NOT NULL,
    current_generation bigint NOT NULL CHECK (current_generation > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, project_id, client_id),
    FOREIGN KEY (organization_id, project_id, client_id, current_generation)
        REFERENCES external_admin_client_versions(
            organization_id, project_id, client_id, generation
        )
);

CREATE FUNCTION mcloving_guard_external_admin_client_history()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514',
        MESSAGE = 'external admin client history is immutable';
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_external_admin_client_history() FROM PUBLIC;
CREATE TRIGGER external_admin_client_versions_immutable
BEFORE UPDATE OR DELETE ON external_admin_client_versions
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_external_admin_client_history();

CREATE FUNCTION mcloving_guard_external_admin_client_advance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.client_id IS DISTINCT FROM OLD.client_id
       OR NEW.current_generation <= OLD.current_generation
    THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'external admin client pointer must advance monotonically';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_external_admin_client_advance() FROM PUBLIC;
CREATE TRIGGER external_admin_client_current_monotonic
BEFORE UPDATE ON external_admin_client_current
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_external_admin_client_advance();

GRANT SELECT ON external_admin_client_versions, external_admin_client_current
TO mcloving_tenant;

ALTER TABLE external_admin_client_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_admin_client_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY external_admin_client_versions_tenant_policy
ON external_admin_client_versions
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE external_admin_client_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_admin_client_current FORCE ROW LEVEL SECURITY;
CREATE POLICY external_admin_client_current_tenant_policy
ON external_admin_client_current
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);
