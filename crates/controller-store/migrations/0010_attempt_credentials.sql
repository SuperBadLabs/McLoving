CREATE TABLE protected_environments (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    environment text NOT NULL,
    action text NOT NULL,
    required_approvals smallint NOT NULL CHECK (required_approvals BETWEEN 0 AND 8),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, project_id, environment, action),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE TABLE environment_approvals (
    id uuid NOT NULL,
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    build_id uuid NOT NULL,
    pipeline_digest bytea NOT NULL CHECK (octet_length(pipeline_digest) = 32),
    environment text NOT NULL,
    action text NOT NULL,
    approver_subject text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_by_attempt uuid,
    consumed_fence bigint CHECK (consumed_fence >= 0),
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, id),
    CHECK (
        (consumed_by_attempt IS NULL AND consumed_fence IS NULL AND consumed_at IS NULL)
        OR
        (consumed_by_attempt IS NOT NULL AND consumed_fence IS NOT NULL AND consumed_at IS NOT NULL)
    ),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (build_id, organization_id)
        REFERENCES builds(id, organization_id),
    FOREIGN KEY (consumed_by_attempt, organization_id)
        REFERENCES attempts(id, organization_id)
);

CREATE TABLE credential_grants (
    id uuid NOT NULL,
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    build_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    fence bigint NOT NULL CHECK (fence >= 0),
    pipeline_digest bytea NOT NULL CHECK (octet_length(pipeline_digest) = 32),
    environment text NOT NULL,
    action text NOT NULL,
    target_name text NOT NULL,
    secret_value bytea NOT NULL CHECK (
        octet_length(secret_value) BETWEEN 1 AND 65536
    ),
    expires_at timestamptz NOT NULL,
    delivered_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, attempt_id, fence, target_name),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (build_id, organization_id)
        REFERENCES builds(id, organization_id),
    FOREIGN KEY (attempt_id, organization_id)
        REFERENCES attempts(id, organization_id)
);

CREATE INDEX environment_approvals_active_idx
    ON environment_approvals (
        organization_id,
        build_id,
        environment,
        action,
        expires_at
    )
    WHERE consumed_at IS NULL;
CREATE INDEX credential_grants_delivery_idx
    ON credential_grants (
        organization_id,
        attempt_id,
        fence,
        expires_at
    )
    WHERE delivered_at IS NULL;

CREATE FUNCTION guard_environment_approval_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.build_id IS DISTINCT FROM OLD.build_id
       OR NEW.pipeline_digest IS DISTINCT FROM OLD.pipeline_digest
       OR NEW.environment IS DISTINCT FROM OLD.environment
       OR NEW.action IS DISTINCT FROM OLD.action
       OR NEW.approver_subject IS DISTINCT FROM OLD.approver_subject
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.consumed_at IS NOT NULL
       OR (
           NEW.consumed_at IS NOT NULL
           AND (
               NEW.consumed_by_attempt IS NULL
               OR NEW.consumed_fence IS NULL
           )
       )
    THEN
        RAISE EXCEPTION 'environment approval identity is immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER environment_approval_identity_guard
BEFORE UPDATE ON environment_approvals
FOR EACH ROW EXECUTE FUNCTION guard_environment_approval_identity();

CREATE FUNCTION guard_credential_grant_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.delivered_at IS NULL
       AND OLD.expires_at <= clock_timestamp()
       AND NEW.delivered_at IS NULL
    THEN
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.build_id IS DISTINCT FROM OLD.build_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.fence IS DISTINCT FROM OLD.fence
       OR NEW.pipeline_digest IS DISTINCT FROM OLD.pipeline_digest
       OR NEW.environment IS DISTINCT FROM OLD.environment
       OR NEW.action IS DISTINCT FROM OLD.action
       OR NEW.target_name IS DISTINCT FROM OLD.target_name
       OR NEW.secret_value IS DISTINCT FROM OLD.secret_value
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.delivered_at IS NOT NULL
       OR NEW.delivered_at IS NULL
    THEN
        RAISE EXCEPTION 'credential grant identity is immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER credential_grant_identity_guard
BEFORE UPDATE ON credential_grants
FOR EACH ROW EXECUTE FUNCTION guard_credential_grant_identity();

GRANT SELECT, INSERT, UPDATE ON
    protected_environments,
    environment_approvals,
    credential_grants
TO mcloving_tenant;

ALTER TABLE protected_environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE protected_environments FORCE ROW LEVEL SECURITY;
CREATE POLICY protected_environments_tenant_policy ON protected_environments
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE environment_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE environment_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY environment_approvals_tenant_policy ON environment_approvals
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE credential_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_grants_tenant_policy ON credential_grants
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
