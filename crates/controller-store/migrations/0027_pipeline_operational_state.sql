ALTER TABLE pipeline_definitions
    ADD COLUMN operational_generation bigint NOT NULL DEFAULT 1
        CHECK (operational_generation > 0),
    ADD CONSTRAINT pipeline_definitions_project_identity_unique
        UNIQUE (organization_id, project_id, pipeline_id);

CREATE TABLE pipeline_operational_state_history (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL CHECK (state IN ('enabled', 'disabled')),
    reason text NOT NULL CHECK (
        reason = btrim(reason) AND length(reason) BETWEEN 1 AND 2048
    ),
    actor_subject text NOT NULL CHECK (
        actor_subject = btrim(actor_subject)
        AND length(actor_subject) BETWEEN 1 AND 512
    ),
    source_identity text NOT NULL CHECK (
        source_identity = btrim(source_identity)
        AND length(source_identity) BETWEEN 1 AND 512
    ),
    source_generation text NOT NULL CHECK (
        source_generation = btrim(source_generation)
        AND length(source_generation) BETWEEN 1 AND 512
    ),
    source_effective_at_unix_ms bigint NOT NULL
        CHECK (source_effective_at_unix_ms >= 0),
    source_provenance_sha256 bytea NOT NULL CHECK (
        octet_length(source_provenance_sha256) = 32
        AND source_provenance_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    idempotency_key text NOT NULL CHECK (
        idempotency_key = btrim(idempotency_key)
        AND length(idempotency_key) BETWEEN 1 AND 256
    ),
    effective_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    audit_sequence bigint CHECK (audit_sequence > 0),
    audit_event_hash bytea CHECK (
        audit_event_hash IS NULL OR octet_length(audit_event_hash) = 32
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, pipeline_id, generation),
    UNIQUE (organization_id, pipeline_id, idempotency_key),
    FOREIGN KEY (organization_id, project_id, pipeline_id)
        REFERENCES pipeline_definitions(
            organization_id, project_id, pipeline_id
        ),
    FOREIGN KEY (organization_id, audit_sequence)
        REFERENCES audit_events(organization_id, sequence),
    CHECK (
        (source_identity = 'migration:v27'
         AND generation = 1
         AND audit_sequence IS NULL
         AND audit_event_hash IS NULL)
        OR
        (source_identity <> 'migration:v27'
         AND audit_sequence IS NOT NULL
         AND audit_event_hash IS NOT NULL)
    )
);

INSERT INTO pipeline_operational_state_history (
    organization_id, project_id, pipeline_id, generation, state,
    reason, actor_subject, source_identity, source_generation,
    source_effective_at_unix_ms, source_provenance_sha256,
    idempotency_key, effective_at
)
SELECT organization_id, project_id, pipeline_id, 1, 'enabled',
       'migration v27: existing pipeline remains enabled',
       'system:migration:v27', 'migration:v27', 'v27',
       (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint,
       decode('f273d5d5e707fa11f9b359b29c986fcaf68ad4e9159bf294b9fb224c52a950b7', 'hex'),
       'migration:v27:existing-enabled', clock_timestamp()
FROM pipeline_definitions;

ALTER TABLE pipeline_definitions
    ADD CONSTRAINT pipeline_definitions_operational_generation_fkey
    FOREIGN KEY (organization_id, pipeline_id, operational_generation)
    REFERENCES pipeline_operational_state_history(
        organization_id, pipeline_id, generation
    )
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE builds
    ADD COLUMN pipeline_id uuid,
    ADD COLUMN pipeline_revision bigint,
    ADD COLUMN pipeline_operational_generation bigint,
    ADD CONSTRAINT builds_pipeline_binding_complete CHECK (
        (pipeline_id IS NULL
         AND pipeline_revision IS NULL
         AND pipeline_operational_generation IS NULL)
        OR
        (pipeline_id IS NOT NULL
         AND pipeline_revision IS NOT NULL
         AND pipeline_revision > 0
         AND pipeline_operational_generation IS NOT NULL
         AND pipeline_operational_generation > 0)
    ),
    ADD CONSTRAINT builds_pipeline_identity_fkey
        FOREIGN KEY (organization_id, project_id, pipeline_id)
        REFERENCES pipeline_definitions(
            organization_id, project_id, pipeline_id
        ),
    ADD CONSTRAINT builds_pipeline_revision_fkey
        FOREIGN KEY (organization_id, pipeline_id, pipeline_revision)
        REFERENCES pipeline_revisions(
            organization_id, pipeline_id, revision
        ),
    ADD CONSTRAINT builds_pipeline_operational_generation_fkey
        FOREIGN KEY (
            organization_id, pipeline_id, pipeline_operational_generation
        )
        REFERENCES pipeline_operational_state_history(
            organization_id, pipeline_id, generation
        );

CREATE INDEX pipeline_operational_state_current_idx
    ON pipeline_operational_state_history (
        organization_id, pipeline_id, generation, state
    );

CREATE INDEX builds_pipeline_operational_fence_idx
    ON builds (
        organization_id, pipeline_id, pipeline_operational_generation, status
    )
    WHERE pipeline_id IS NOT NULL;

CREATE FUNCTION mcloving_reject_pipeline_operational_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'pipeline operational-state history is immutable';
END
$$;

REVOKE ALL ON FUNCTION mcloving_reject_pipeline_operational_history_mutation()
FROM PUBLIC;

CREATE TRIGGER pipeline_operational_state_history_immutable
BEFORE UPDATE OR DELETE ON pipeline_operational_state_history
FOR EACH ROW
EXECUTE FUNCTION mcloving_reject_pipeline_operational_history_mutation();

CREATE FUNCTION mcloving_guard_pipeline_operational_generation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.pipeline_id IS DISTINCT FROM OLD.pipeline_id
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'pipeline operational-state identity is immutable';
    END IF;
    IF NEW.operational_generation IS DISTINCT FROM OLD.operational_generation
       AND NEW.operational_generation <> OLD.operational_generation + 1
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'pipeline operational-state generation must advance exactly once';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_pipeline_operational_generation()
FROM PUBLIC;

CREATE TRIGGER pipeline_definitions_operational_generation_guard
BEFORE UPDATE ON pipeline_definitions
FOR EACH ROW
EXECUTE FUNCTION mcloving_guard_pipeline_operational_generation();

GRANT SELECT, INSERT ON pipeline_operational_state_history TO mcloving_tenant;

ALTER TABLE pipeline_operational_state_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE pipeline_operational_state_history FORCE ROW LEVEL SECURITY;
CREATE POLICY pipeline_operational_state_history_tenant_policy
ON pipeline_operational_state_history
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
