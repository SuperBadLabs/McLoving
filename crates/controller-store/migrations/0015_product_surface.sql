CREATE TABLE pipeline_definitions (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    slug text NOT NULL CHECK (
        length(slug) BETWEEN 1 AND 128
        AND slug = btrim(slug)
    ),
    current_revision bigint NOT NULL DEFAULT 1 CHECK (current_revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, pipeline_id),
    UNIQUE (organization_id, project_id, slug),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE TABLE pipeline_revisions (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    source text NOT NULL CHECK (octet_length(source) BETWEEN 1 AND 1048576),
    source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
    semantic_digest bytea NOT NULL CHECK (octet_length(semantic_digest) = 32),
    schema_major integer NOT NULL CHECK (schema_major > 0),
    schema_minor integer NOT NULL CHECK (schema_minor >= 0),
    parameter_schema jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, pipeline_id, revision),
    FOREIGN KEY (organization_id, pipeline_id)
        REFERENCES pipeline_definitions(organization_id, pipeline_id)
);

CREATE TABLE component_packages (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    name text NOT NULL CHECK (
        length(name) BETWEEN 1 AND 128
        AND name = btrim(name)
    ),
    version_major integer NOT NULL CHECK (version_major > 0),
    version_minor integer NOT NULL CHECK (version_minor >= 0),
    canonical_bytes bytea NOT NULL CHECK (
        octet_length(canonical_bytes) BETWEEN 1 AND 1048576
    ),
    source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, digest),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE INDEX pipeline_definitions_list_idx
    ON pipeline_definitions (
        organization_id, project_id, slug, pipeline_id
    );
CREATE INDEX pipeline_revisions_digest_idx
    ON pipeline_revisions (
        organization_id, project_id, semantic_digest
    );
CREATE INDEX component_packages_list_idx
    ON component_packages (
        organization_id, project_id, name, digest
    );
CREATE INDEX builds_product_list_idx
    ON builds (
        organization_id, project_id, created_at DESC, id DESC
    );

CREATE FUNCTION mcloving_reject_product_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'mcloving product history is immutable';
END
$$;

REVOKE ALL ON FUNCTION mcloving_reject_product_history_mutation() FROM PUBLIC;

CREATE TRIGGER pipeline_revisions_immutable
BEFORE UPDATE OR DELETE ON pipeline_revisions
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_product_history_mutation();

CREATE TRIGGER component_packages_immutable
BEFORE UPDATE OR DELETE ON component_packages
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_product_history_mutation();

GRANT SELECT, INSERT, UPDATE ON pipeline_definitions TO mcloving_tenant;
GRANT SELECT, INSERT ON pipeline_revisions, component_packages TO mcloving_tenant;

ALTER TABLE pipeline_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pipeline_definitions FORCE ROW LEVEL SECURITY;
CREATE POLICY pipeline_definitions_tenant_policy ON pipeline_definitions
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE pipeline_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pipeline_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY pipeline_revisions_tenant_policy ON pipeline_revisions
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE component_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE component_packages FORCE ROW LEVEL SECURITY;
CREATE POLICY component_packages_tenant_policy ON component_packages
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
