CREATE TABLE identities (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    subject text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('human', 'service')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (organization_id, subject),
    UNIQUE (id, organization_id)
);

CREATE TABLE project_memberships (
    identity_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'viewer')),
    PRIMARY KEY (identity_id, project_id),
    FOREIGN KEY (identity_id, organization_id)
        REFERENCES identities(id, organization_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE TABLE service_scopes (
    identity_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    scope text NOT NULL,
    PRIMARY KEY (identity_id, scope),
    FOREIGN KEY (identity_id, organization_id)
        REFERENCES identities(id, organization_id)
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcloving_tenant') THEN
        CREATE ROLE mcloving_tenant NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO mcloving_tenant;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM mcloving_tenant;
GRANT SELECT ON
    organizations,
    projects
TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    identities,
    project_memberships,
    service_scopes,
    builds,
    nodes,
    attempts,
    build_events,
    outbox
TO mcloving_tenant;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mcloving_tenant;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organizations_tenant_policy ON organizations
    USING (id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
CREATE POLICY projects_tenant_policy ON projects
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE identities FORCE ROW LEVEL SECURITY;
CREATE POLICY identities_tenant_policy ON identities
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE project_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY project_memberships_tenant_policy ON project_memberships
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE service_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY service_scopes_tenant_policy ON service_scopes
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE builds ENABLE ROW LEVEL SECURITY;
ALTER TABLE builds FORCE ROW LEVEL SECURITY;
CREATE POLICY builds_tenant_policy ON builds
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE nodes FORCE ROW LEVEL SECURITY;
CREATE POLICY nodes_tenant_policy ON nodes
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY attempts_tenant_policy ON attempts
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE build_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE build_events FORCE ROW LEVEL SECURITY;
CREATE POLICY build_events_tenant_policy ON build_events
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_tenant_policy ON outbox
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
