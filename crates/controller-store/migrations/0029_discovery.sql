CREATE TABLE discovery_parent_definitions (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    current_generation bigint NOT NULL CHECK (current_generation > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, parent_id),
    UNIQUE (organization_id, project_id, pipeline_id, parent_id),
    FOREIGN KEY (organization_id, project_id, pipeline_id)
        REFERENCES pipeline_definitions(organization_id, project_id, pipeline_id)
);

CREATE TABLE discovery_parent_versions (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    parent_kind text NOT NULL CHECK (
        parent_kind IN ('multibranch_pipeline', 'organization_folder')
    ),
    state text NOT NULL CHECK (state IN ('enabled', 'quiesced')),
    implementation_sha256 bytea NOT NULL CHECK (
        octet_length(implementation_sha256) = 32
        AND implementation_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    protocol_version text NOT NULL CHECK (
        protocol_version = btrim(protocol_version)
        AND length(protocol_version) BETWEEN 1 AND 128
    ),
    configuration_sha256 bytea NOT NULL CHECK (
        octet_length(configuration_sha256) = 32
        AND configuration_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    provider text NOT NULL CHECK (
        provider IN ('github', 'gitlab', 'bitbucket', 'gitea')
    ),
    provider_identity text NOT NULL CHECK (
        provider_identity = btrim(provider_identity)
        AND length(provider_identity) BETWEEN 1 AND 512
    ),
    organization_identity text CHECK (
        organization_identity IS NULL OR (
            organization_identity = btrim(organization_identity)
            AND length(organization_identity) BETWEEN 1 AND 512
        )
    ),
    repositories jsonb NOT NULL CHECK (
        jsonb_typeof(repositories) = 'array'
        AND octet_length(repositories::text) <= 65536
    ),
    branch_includes jsonb NOT NULL CHECK (
        jsonb_typeof(branch_includes) = 'array'
        AND octet_length(branch_includes::text) <= 65536
    ),
    branch_excludes jsonb NOT NULL CHECK (
        jsonb_typeof(branch_excludes) = 'array'
        AND octet_length(branch_excludes::text) <= 65536
    ),
    pull_request_strategy text NOT NULL CHECK (
        pull_request_strategy IN ('none', 'origin_only', 'origin_and_forks')
    ),
    fork_trust_strategy text NOT NULL CHECK (
        fork_trust_strategy IN ('none', 'named_repositories', 'all')
    ),
    trusted_fork_repositories jsonb NOT NULL CHECK (
        jsonb_typeof(trusted_fork_repositories) = 'array'
        AND octet_length(trusted_fork_repositories::text) <= 65536
    ),
    jenkinsfile_path text NOT NULL CHECK (
        jenkinsfile_path = btrim(jenkinsfile_path)
        AND length(jenkinsfile_path) BETWEEN 1 AND 1024
    ),
    jenkinsfile_selection text NOT NULL CHECK (
        jenkinsfile_selection = 'exact_path'
    ),
    child_configuration_policy_sha256 bytea NOT NULL CHECK (
        octet_length(child_configuration_policy_sha256) = 32
        AND child_configuration_policy_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    orphan_policy text NOT NULL CHECK (orphan_policy IN ('retain', 'retire')),
    authorization_generation bigint NOT NULL CHECK (authorization_generation > 0),
    authorization_policy_sha256 bytea NOT NULL CHECK (
        octet_length(authorization_policy_sha256) = 32
        AND authorization_policy_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    trigger_id uuid NOT NULL,
    trigger_generation bigint NOT NULL CHECK (trigger_generation > 0),
    trigger_configuration_sha256 bytea NOT NULL CHECK (
        octet_length(trigger_configuration_sha256) = 32
        AND trigger_configuration_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    source_implementation_sha256 bytea NOT NULL CHECK (
        octet_length(source_implementation_sha256) = 32
        AND source_implementation_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    source_protocol_version text NOT NULL CHECK (
        source_protocol_version = btrim(source_protocol_version)
        AND length(source_protocol_version) BETWEEN 1 AND 128
    ),
    source_configuration_sha256 bytea NOT NULL CHECK (
        octet_length(source_configuration_sha256) = 32
        AND source_configuration_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    restored_from_generation bigint CHECK (
        restored_from_generation IS NULL OR restored_from_generation > 0
    ),
    actor_subject text NOT NULL CHECK (
        actor_subject = btrim(actor_subject)
        AND length(actor_subject) BETWEEN 1 AND 512
    ),
    reason text NOT NULL CHECK (
        reason = btrim(reason) AND length(reason) BETWEEN 1 AND 2048
    ),
    idempotency_key text NOT NULL CHECK (
        idempotency_key = btrim(idempotency_key)
        AND length(idempotency_key) BETWEEN 1 AND 256
    ),
    audit_sequence bigint NOT NULL CHECK (audit_sequence > 0),
    audit_event_hash bytea NOT NULL CHECK (octet_length(audit_event_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, parent_id, generation),
    UNIQUE (organization_id, parent_id, idempotency_key),
    FOREIGN KEY (organization_id, project_id, pipeline_id, parent_id)
        REFERENCES discovery_parent_definitions(
            organization_id, project_id, pipeline_id, parent_id
        ),
    FOREIGN KEY (organization_id, trigger_id, trigger_generation)
        REFERENCES pipeline_trigger_versions(
            organization_id, trigger_id, generation
        ),
    FOREIGN KEY (organization_id, project_id, authorization_generation)
        REFERENCES authorization_policy_versions(
            organization_id, project_id, generation
        ),
    FOREIGN KEY (organization_id, audit_sequence)
        REFERENCES audit_events(organization_id, sequence)
);

ALTER TABLE discovery_parent_definitions
    ADD CONSTRAINT discovery_parent_definitions_current_generation_fkey
    FOREIGN KEY (organization_id, parent_id, current_generation)
    REFERENCES discovery_parent_versions(organization_id, parent_id, generation)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE discovery_scans (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    parent_generation bigint NOT NULL CHECK (parent_generation > 0),
    scan_id text NOT NULL CHECK (
        scan_id = btrim(scan_id) AND length(scan_id) BETWEEN 1 AND 512
    ),
    source_kind text NOT NULL CHECK (
        source_kind IN ('webhook', 'periodic', 'recovery')
    ),
    source_event_id text CHECK (
        source_event_id IS NULL OR (
            source_event_id = btrim(source_event_id)
            AND length(source_event_id) BETWEEN 1 AND 512
        )
    ),
    source_cursor bigint NOT NULL CHECK (source_cursor > 0),
    complete_snapshot boolean NOT NULL,
    provider_snapshot_sha256 bytea NOT NULL CHECK (
        octet_length(provider_snapshot_sha256) = 32
        AND provider_snapshot_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    request_sha256 bytea NOT NULL CHECK (
        octet_length(request_sha256) = 32
        AND request_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    observation_count integer NOT NULL CHECK (observation_count >= 0),
    actor_subject text NOT NULL CHECK (
        actor_subject = btrim(actor_subject)
        AND length(actor_subject) BETWEEN 1 AND 512
    ),
    audit_sequence bigint NOT NULL CHECK (audit_sequence > 0),
    audit_event_hash bytea NOT NULL CHECK (octet_length(audit_event_hash) = 32),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, parent_id, scan_id),
    UNIQUE (organization_id, parent_id, source_cursor),
    FOREIGN KEY (organization_id, project_id, pipeline_id, parent_id)
        REFERENCES discovery_parent_definitions(
            organization_id, project_id, pipeline_id, parent_id
        ),
    FOREIGN KEY (organization_id, parent_id, parent_generation)
        REFERENCES discovery_parent_versions(
            organization_id, parent_id, generation
        ),
    FOREIGN KEY (organization_id, audit_sequence)
        REFERENCES audit_events(organization_id, sequence),
    CHECK (
        (source_kind = 'webhook' AND source_event_id IS NOT NULL
         AND NOT complete_snapshot)
        OR
        (source_kind IN ('periodic', 'recovery') AND source_event_id IS NULL
         AND complete_snapshot)
    )
);

CREATE UNIQUE INDEX discovery_scans_source_event_idx
    ON discovery_scans (organization_id, parent_id, source_event_id)
    WHERE source_event_id IS NOT NULL;

CREATE TABLE discovery_scan_results (
    organization_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    scan_id text NOT NULL,
    active_count integer NOT NULL CHECK (active_count >= 0),
    quarantined_count integer NOT NULL CHECK (quarantined_count >= 0),
    retired_count integer NOT NULL CHECK (retired_count >= 0),
    selected_count integer NOT NULL CHECK (selected_count >= 0),
    PRIMARY KEY (organization_id, parent_id, scan_id),
    FOREIGN KEY (organization_id, parent_id, scan_id)
        REFERENCES discovery_scans(organization_id, parent_id, scan_id)
);

CREATE TABLE discovery_child_identities (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    child_key text NOT NULL CHECK (
        child_key = btrim(child_key) AND length(child_key) BETWEEN 1 AND 1024
    ),
    child_pipeline_id uuid NOT NULL,
    repository_identity text NOT NULL CHECK (
        repository_identity = btrim(repository_identity)
        AND length(repository_identity) BETWEEN 1 AND 512
    ),
    ref_kind text NOT NULL CHECK (ref_kind IN ('branch', 'pull_request')),
    ref_name text NOT NULL CHECK (
        ref_name = btrim(ref_name) AND length(ref_name) BETWEEN 1 AND 512
    ),
    pull_request_number bigint CHECK (
        pull_request_number IS NULL OR pull_request_number > 0
    ),
    head_repository_identity text NOT NULL CHECK (
        head_repository_identity = btrim(head_repository_identity)
        AND length(head_repository_identity) BETWEEN 1 AND 512
    ),
    is_fork boolean NOT NULL,
    first_scan_id text NOT NULL CHECK (
        first_scan_id = btrim(first_scan_id)
        AND length(first_scan_id) BETWEEN 1 AND 512
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, parent_id, child_key),
    UNIQUE (organization_id, parent_id, child_pipeline_id),
    FOREIGN KEY (organization_id, project_id, pipeline_id, parent_id)
        REFERENCES discovery_parent_definitions(
            organization_id, project_id, pipeline_id, parent_id
        ),
    FOREIGN KEY (organization_id, parent_id, first_scan_id)
        REFERENCES discovery_scans(organization_id, parent_id, scan_id),
    CHECK (
        (ref_kind = 'branch' AND pull_request_number IS NULL AND NOT is_fork)
        OR (ref_kind = 'pull_request' AND pull_request_number IS NOT NULL)
    )
);

CREATE TABLE discovery_observations (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    scan_id text NOT NULL,
    child_key text NOT NULL CHECK (
        child_key = btrim(child_key) AND length(child_key) BETWEEN 1 AND 1024
    ),
    child_pipeline_id uuid NOT NULL,
    repository_identity text NOT NULL CHECK (
        repository_identity = btrim(repository_identity)
        AND length(repository_identity) BETWEEN 1 AND 512
    ),
    ref_kind text NOT NULL CHECK (ref_kind IN ('branch', 'pull_request')),
    ref_name text NOT NULL CHECK (
        ref_name = btrim(ref_name) AND length(ref_name) BETWEEN 1 AND 512
    ),
    pull_request_number bigint CHECK (
        pull_request_number IS NULL OR pull_request_number > 0
    ),
    head_repository_identity text NOT NULL CHECK (
        head_repository_identity = btrim(head_repository_identity)
        AND length(head_repository_identity) BETWEEN 1 AND 512
    ),
    is_fork boolean NOT NULL,
    present boolean NOT NULL,
    trusted boolean NOT NULL,
    authorized boolean NOT NULL,
    disposition text NOT NULL CHECK (
        disposition IN ('active', 'quarantined', 'filtered', 'absent')
    ),
    revision text NOT NULL CHECK (
        revision = btrim(revision) AND revision ~ '^[0-9A-Fa-f]{7,128}$'
    ),
    provenance_sha256 bytea NOT NULL CHECK (
        octet_length(provenance_sha256) = 32
        AND provenance_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    jenkinsfile_path text NOT NULL CHECK (
        jenkinsfile_path = btrim(jenkinsfile_path)
        AND length(jenkinsfile_path) BETWEEN 1 AND 1024
    ),
    jenkinsfile_sha256 bytea NOT NULL CHECK (
        octet_length(jenkinsfile_sha256) = 32
        AND jenkinsfile_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    child_configuration_sha256 bytea NOT NULL CHECK (
        octet_length(child_configuration_sha256) = 32
        AND child_configuration_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    observation_sha256 bytea NOT NULL CHECK (
        octet_length(observation_sha256) = 32
        AND observation_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    PRIMARY KEY (organization_id, parent_id, scan_id, child_key),
    FOREIGN KEY (organization_id, parent_id, scan_id)
        REFERENCES discovery_scans(organization_id, parent_id, scan_id)
);

CREATE TABLE discovery_children (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    child_key text NOT NULL CHECK (
        child_key = btrim(child_key) AND length(child_key) BETWEEN 1 AND 1024
    ),
    child_pipeline_id uuid NOT NULL,
    repository_identity text NOT NULL CHECK (
        repository_identity = btrim(repository_identity)
        AND length(repository_identity) BETWEEN 1 AND 512
    ),
    ref_kind text NOT NULL CHECK (ref_kind IN ('branch', 'pull_request')),
    ref_name text NOT NULL CHECK (
        ref_name = btrim(ref_name) AND length(ref_name) BETWEEN 1 AND 512
    ),
    pull_request_number bigint CHECK (
        pull_request_number IS NULL OR pull_request_number > 0
    ),
    head_repository_identity text NOT NULL CHECK (
        head_repository_identity = btrim(head_repository_identity)
        AND length(head_repository_identity) BETWEEN 1 AND 512
    ),
    is_fork boolean NOT NULL,
    state text NOT NULL CHECK (state IN ('active', 'quarantined', 'retired')),
    state_generation bigint NOT NULL CHECK (state_generation > 0),
    revision text NOT NULL CHECK (
        revision = btrim(revision) AND revision ~ '^[0-9A-Fa-f]{7,128}$'
    ),
    provenance_sha256 bytea NOT NULL CHECK (
        octet_length(provenance_sha256) = 32
        AND provenance_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    jenkinsfile_path text NOT NULL CHECK (
        jenkinsfile_path = btrim(jenkinsfile_path)
        AND length(jenkinsfile_path) BETWEEN 1 AND 1024
    ),
    jenkinsfile_sha256 bytea NOT NULL CHECK (
        octet_length(jenkinsfile_sha256) = 32
        AND jenkinsfile_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    child_configuration_sha256 bytea NOT NULL CHECK (
        octet_length(child_configuration_sha256) = 32
        AND child_configuration_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    parent_generation bigint NOT NULL CHECK (parent_generation > 0),
    source_cursor bigint NOT NULL CHECK (source_cursor > 0),
    last_scan_id text NOT NULL CHECK (
        last_scan_id = btrim(last_scan_id)
        AND length(last_scan_id) BETWEEN 1 AND 512
    ),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, parent_id, child_key),
    UNIQUE (organization_id, parent_id, child_pipeline_id),
    FOREIGN KEY (organization_id, project_id, pipeline_id, parent_id)
        REFERENCES discovery_parent_definitions(
            organization_id, project_id, pipeline_id, parent_id
        ),
    FOREIGN KEY (organization_id, parent_id, parent_generation)
        REFERENCES discovery_parent_versions(
            organization_id, parent_id, generation
        ),
    FOREIGN KEY (organization_id, parent_id, last_scan_id)
        REFERENCES discovery_scans(organization_id, parent_id, scan_id),
    CHECK (
        (ref_kind = 'branch' AND pull_request_number IS NULL)
        OR (ref_kind = 'pull_request' AND pull_request_number IS NOT NULL)
    )
);

CREATE INDEX discovery_children_state_idx
    ON discovery_children (organization_id, parent_id, state, child_key);

CREATE FUNCTION mcloving_reject_discovery_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514',
        MESSAGE = 'discovery history is immutable';
END
$$;

REVOKE ALL ON FUNCTION mcloving_reject_discovery_history_mutation() FROM PUBLIC;

CREATE TRIGGER discovery_parent_versions_immutable
BEFORE UPDATE OR DELETE ON discovery_parent_versions
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_discovery_history_mutation();

CREATE TRIGGER discovery_scans_immutable
BEFORE UPDATE OR DELETE ON discovery_scans
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_discovery_history_mutation();

CREATE TRIGGER discovery_observations_immutable
BEFORE UPDATE OR DELETE ON discovery_observations
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_discovery_history_mutation();

CREATE TRIGGER discovery_child_identities_immutable
BEFORE UPDATE OR DELETE ON discovery_child_identities
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_discovery_history_mutation();

CREATE TRIGGER discovery_scan_results_immutable
BEFORE UPDATE OR DELETE ON discovery_scan_results
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_discovery_history_mutation();

CREATE FUNCTION mcloving_guard_discovery_parent_definition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.pipeline_id IS DISTINCT FROM OLD.pipeline_id
       OR NEW.parent_id IS DISTINCT FROM OLD.parent_id
       OR NEW.current_generation <> OLD.current_generation + 1
    THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'discovery parent identity is immutable and generation must advance once';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_discovery_parent_definition() FROM PUBLIC;

CREATE TRIGGER discovery_parent_definitions_generation_guard
BEFORE UPDATE ON discovery_parent_definitions
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_discovery_parent_definition();

CREATE FUNCTION mcloving_guard_discovery_child_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.pipeline_id IS DISTINCT FROM OLD.pipeline_id
       OR NEW.parent_id IS DISTINCT FROM OLD.parent_id
       OR NEW.child_key IS DISTINCT FROM OLD.child_key
       OR NEW.child_pipeline_id IS DISTINCT FROM OLD.child_pipeline_id
       OR NEW.repository_identity IS DISTINCT FROM OLD.repository_identity
       OR NEW.ref_kind IS DISTINCT FROM OLD.ref_kind
       OR NEW.ref_name IS DISTINCT FROM OLD.ref_name
       OR NEW.pull_request_number IS DISTINCT FROM OLD.pull_request_number
       OR NEW.head_repository_identity IS DISTINCT FROM OLD.head_repository_identity
       OR NEW.is_fork IS DISTINCT FROM OLD.is_fork
       OR NEW.state_generation <> OLD.state_generation + 1
       OR NEW.source_cursor <= OLD.source_cursor
    THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'discovery child identity is immutable and state must advance once';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_discovery_child_transition() FROM PUBLIC;

CREATE TRIGGER discovery_children_transition_guard
BEFORE UPDATE ON discovery_children
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_discovery_child_transition();

GRANT SELECT, INSERT, UPDATE ON discovery_parent_definitions TO mcloving_tenant;
GRANT SELECT, INSERT ON discovery_parent_versions TO mcloving_tenant;
GRANT SELECT, INSERT ON discovery_scans TO mcloving_tenant;
GRANT SELECT, INSERT ON discovery_scan_results TO mcloving_tenant;
GRANT SELECT, INSERT ON discovery_child_identities TO mcloving_tenant;
GRANT SELECT, INSERT ON discovery_observations TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE ON discovery_children TO mcloving_tenant;

ALTER TABLE discovery_parent_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_parent_definitions FORCE ROW LEVEL SECURITY;
CREATE POLICY discovery_parent_definitions_tenant_policy
ON discovery_parent_definitions
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE discovery_parent_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_parent_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY discovery_parent_versions_tenant_policy
ON discovery_parent_versions
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE discovery_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_scans FORCE ROW LEVEL SECURITY;
CREATE POLICY discovery_scans_tenant_policy
ON discovery_scans
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE discovery_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY discovery_observations_tenant_policy
ON discovery_observations
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE discovery_child_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_child_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY discovery_child_identities_tenant_policy
ON discovery_child_identities
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE discovery_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_scan_results FORCE ROW LEVEL SECURITY;
CREATE POLICY discovery_scan_results_tenant_policy
ON discovery_scan_results
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE discovery_children ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_children FORCE ROW LEVEL SECURITY;
CREATE POLICY discovery_children_tenant_policy
ON discovery_children
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);
