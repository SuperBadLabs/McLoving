CREATE TABLE normalized_test_reports (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    report_id uuid NOT NULL,
    project_id uuid NOT NULL,
    build_id uuid NOT NULL,
    node_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    fence bigint NOT NULL CHECK (fence > 0),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    raw_artifact_name text NOT NULL CHECK (
        length(raw_artifact_name) BETWEEN 1 AND 512
    ),
    raw_object_digest bytea NOT NULL CHECK (octet_length(raw_object_digest) = 32),
    raw_bytes bigint NOT NULL CHECK (raw_bytes > 0),
    aggregate jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, report_id),
    UNIQUE (
        organization_id, attempt_id, fence,
        raw_artifact_name, raw_object_digest
    ),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (build_id, organization_id)
        REFERENCES builds(id, organization_id),
    FOREIGN KEY (node_id, organization_id)
        REFERENCES nodes(id, organization_id),
    FOREIGN KEY (attempt_id, organization_id)
        REFERENCES attempts(id, organization_id)
);

CREATE TABLE normalized_test_suites (
    organization_id uuid NOT NULL,
    report_id uuid NOT NULL,
    suite_ordinal integer NOT NULL CHECK (suite_ordinal >= 0),
    name text NOT NULL CHECK (octet_length(name) <= 16384),
    aggregate jsonb NOT NULL,
    PRIMARY KEY (organization_id, report_id, suite_ordinal),
    FOREIGN KEY (organization_id, report_id)
        REFERENCES normalized_test_reports(organization_id, report_id)
);

CREATE TABLE normalized_test_cases (
    organization_id uuid NOT NULL,
    report_id uuid NOT NULL,
    suite_ordinal integer NOT NULL CHECK (suite_ordinal >= 0),
    case_ordinal integer NOT NULL CHECK (case_ordinal >= 0),
    duplicate_ordinal integer NOT NULL CHECK (duplicate_ordinal >= 0),
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 16384),
    classname text NOT NULL CHECK (octet_length(classname) <= 16384),
    outcome text NOT NULL CHECK (
        outcome IN ('passed', 'failed', 'error', 'skipped')
    ),
    duration_ms bigint NOT NULL CHECK (duration_ms >= 0),
    message text CHECK (message IS NULL OR octet_length(message) <= 16384),
    PRIMARY KEY (
        organization_id, report_id, suite_ordinal, case_ordinal
    ),
    FOREIGN KEY (organization_id, report_id, suite_ordinal)
        REFERENCES normalized_test_suites(
            organization_id, report_id, suite_ordinal
        )
);

CREATE INDEX normalized_test_history_idx
    ON normalized_test_cases (
        organization_id, classname, name, report_id
    );

CREATE FUNCTION mcloving_reject_normalized_test_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'mcloving normalized test evidence is append-only';
END
$$;

REVOKE ALL ON FUNCTION mcloving_reject_normalized_test_mutation() FROM PUBLIC;

CREATE TRIGGER normalized_test_reports_immutable
BEFORE UPDATE OR DELETE ON normalized_test_reports
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_normalized_test_mutation();

CREATE TRIGGER normalized_test_suites_immutable
BEFORE UPDATE OR DELETE ON normalized_test_suites
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_normalized_test_mutation();

CREATE TRIGGER normalized_test_cases_immutable
BEFORE UPDATE OR DELETE ON normalized_test_cases
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_normalized_test_mutation();

GRANT SELECT, INSERT ON
    normalized_test_reports,
    normalized_test_suites,
    normalized_test_cases
TO mcloving_tenant;

ALTER TABLE normalized_test_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE normalized_test_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY normalized_test_reports_tenant_policy
ON normalized_test_reports
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE normalized_test_suites ENABLE ROW LEVEL SECURITY;
ALTER TABLE normalized_test_suites FORCE ROW LEVEL SECURITY;
CREATE POLICY normalized_test_suites_tenant_policy
ON normalized_test_suites
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE normalized_test_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE normalized_test_cases FORCE ROW LEVEL SECURITY;
CREATE POLICY normalized_test_cases_tenant_policy
ON normalized_test_cases
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
