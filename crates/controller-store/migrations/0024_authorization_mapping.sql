CREATE TABLE authorization_policy_versions (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    source_realm_implementation text NOT NULL
        CHECK (source_realm_implementation = btrim(source_realm_implementation)
               AND length(source_realm_implementation) BETWEEN 1 AND 512),
    source_realm_digest bytea NOT NULL CHECK (octet_length(source_realm_digest) = 32),
    source_inventory_digest bytea NOT NULL CHECK (octet_length(source_inventory_digest) = 32),
    reviewer text NOT NULL
        CHECK (reviewer = btrim(reviewer) AND length(reviewer) BETWEEN 1 AND 512),
    restored_from_generation bigint
        CHECK (restored_from_generation IS NULL OR restored_from_generation > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, project_id, generation),
    FOREIGN KEY (project_id, organization_id) REFERENCES projects(id, organization_id)
);

CREATE TABLE authorization_principal_mappings (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    policy_generation bigint NOT NULL,
    mapping_id uuid NOT NULL,
    target_identity_id uuid NOT NULL,
    source_identity_id text NOT NULL
        CHECK (source_identity_id = btrim(source_identity_id)
               AND length(source_identity_id) BETWEEN 1 AND 512),
    source_alias_history jsonb NOT NULL CHECK (jsonb_typeof(source_alias_history) = 'array'),
    source_membership_generation bigint NOT NULL CHECK (source_membership_generation > 0),
    source_lifecycle_state text NOT NULL
        CHECK (source_lifecycle_state IN ('active', 'disabled', 'deleted')),
    source_acl_entry_id text NOT NULL
        CHECK (source_acl_entry_id = btrim(source_acl_entry_id)
               AND length(source_acl_entry_id) BETWEEN 1 AND 1024),
    source_acl_scope text NOT NULL
        CHECK (source_acl_scope = btrim(source_acl_scope)
               AND length(source_acl_scope) BETWEEN 1 AND 1024),
    source_acl_generation text NOT NULL
        CHECK (source_acl_generation = btrim(source_acl_generation)
               AND length(source_acl_generation) BETWEEN 1 AND 512),
    source_permissions jsonb NOT NULL CHECK (jsonb_typeof(source_permissions) = 'array'),
    target_provider_id uuid,
    target_external_subject text,
    target_lifecycle_generation bigint NOT NULL CHECK (target_lifecycle_generation > 0),
    target_group_generation bigint NOT NULL CHECK (target_group_generation > 0),
    target_provenance_digest bytea NOT NULL CHECK (octet_length(target_provenance_digest) = 32),
    resulting_role text NOT NULL
        CHECK (resulting_role = btrim(resulting_role) AND length(resulting_role) BETWEEN 1 AND 128),
    mapping_digest bytea NOT NULL CHECK (octet_length(mapping_digest) = 32),
    PRIMARY KEY (organization_id, project_id, policy_generation, mapping_id),
    FOREIGN KEY (organization_id, project_id, policy_generation)
        REFERENCES authorization_policy_versions(organization_id, project_id, generation),
    FOREIGN KEY (target_identity_id, organization_id)
        REFERENCES identities(id, organization_id),
    CHECK (
        (target_provider_id IS NULL AND target_external_subject IS NULL)
        OR
        (target_provider_id IS NOT NULL AND target_external_subject IS NOT NULL
         AND target_external_subject = btrim(target_external_subject)
         AND length(target_external_subject) BETWEEN 1 AND 512)
    )
);

CREATE TABLE authorization_action_grants (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    policy_generation bigint NOT NULL,
    mapping_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN (
        'project_view', 'build_trigger', 'build_cancel', 'project_configure',
        'approval_act', 'build_retry', 'artifact_read', 'artifact_write',
        'test_read', 'log_read', 'secret_use', 'audit_read'
    )),
    decision text NOT NULL CHECK (decision IN ('allow', 'deny')),
    PRIMARY KEY (
        organization_id, project_id, policy_generation, mapping_id, action
    ),
    FOREIGN KEY (organization_id, project_id, policy_generation, mapping_id)
        REFERENCES authorization_principal_mappings(
            organization_id, project_id, policy_generation, mapping_id
        )
);

CREATE TABLE authorization_project_policies (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    current_generation bigint NOT NULL CHECK (current_generation > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, project_id),
    FOREIGN KEY (organization_id, project_id, current_generation)
        REFERENCES authorization_policy_versions(organization_id, project_id, generation),
    FOREIGN KEY (project_id, organization_id) REFERENCES projects(id, organization_id)
);

CREATE FUNCTION mcloving_guard_authorization_history()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514',
        MESSAGE = 'authorization policy history is immutable';
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_authorization_history() FROM PUBLIC;

CREATE TRIGGER authorization_policy_versions_immutable
BEFORE UPDATE OR DELETE ON authorization_policy_versions
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_authorization_history();

CREATE TRIGGER authorization_principal_mappings_immutable
BEFORE UPDATE OR DELETE ON authorization_principal_mappings
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_authorization_history();

CREATE TRIGGER authorization_action_grants_immutable
BEFORE UPDATE OR DELETE ON authorization_action_grants
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_authorization_history();

CREATE FUNCTION mcloving_guard_authorization_policy_advance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.current_generation <= OLD.current_generation
    THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'authorization policy pointer must advance monotonically';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_authorization_policy_advance() FROM PUBLIC;
CREATE TRIGGER authorization_project_policies_monotonic
BEFORE UPDATE ON authorization_project_policies
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_authorization_policy_advance();

GRANT SELECT ON
    authorization_policy_versions,
    authorization_principal_mappings,
    authorization_action_grants,
    authorization_project_policies
TO mcloving_tenant;

ALTER TABLE authorization_policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_policy_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY authorization_policy_versions_tenant_policy
ON authorization_policy_versions
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE authorization_principal_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_principal_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY authorization_principal_mappings_tenant_policy
ON authorization_principal_mappings
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE authorization_action_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_action_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY authorization_action_grants_tenant_policy
ON authorization_action_grants
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE authorization_project_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_project_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY authorization_project_policies_tenant_policy
ON authorization_project_policies
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);
