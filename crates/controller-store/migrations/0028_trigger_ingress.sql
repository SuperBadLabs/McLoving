CREATE TABLE pipeline_trigger_definitions (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    trigger_id uuid NOT NULL,
    current_generation bigint NOT NULL CHECK (current_generation > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, trigger_id),
    UNIQUE (organization_id, project_id, pipeline_id, trigger_id),
    FOREIGN KEY (organization_id, project_id, pipeline_id)
        REFERENCES pipeline_definitions(
            organization_id, project_id, pipeline_id
        )
);

CREATE TABLE pipeline_trigger_versions (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    trigger_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    trigger_kind text NOT NULL CHECK (
        trigger_kind IN (
            'scm_webhook', 'schedule', 'upstream', 'remote_api', 'plugin'
        )
    ),
    state text NOT NULL CHECK (state IN ('enabled', 'paused')),
    implementation_sha256 bytea NOT NULL CHECK (
        octet_length(implementation_sha256) = 32
        AND implementation_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    configuration_sha256 bytea NOT NULL CHECK (
        octet_length(configuration_sha256) = 32
        AND configuration_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    filter_sha256 bytea NOT NULL CHECK (
        octet_length(filter_sha256) = 32
        AND filter_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    event_source_identity text NOT NULL CHECK (
        event_source_identity = btrim(event_source_identity)
        AND length(event_source_identity) BETWEEN 1 AND 512
    ),
    source_generation text NOT NULL CHECK (
        source_generation = btrim(source_generation)
        AND length(source_generation) BETWEEN 1 AND 512
    ),
    configuration jsonb NOT NULL CHECK (
        jsonb_typeof(configuration) = 'object'
        AND octet_length(configuration::text) <= 65536
    ),
    deduplication_window_seconds bigint NOT NULL CHECK (
        deduplication_window_seconds BETWEEN 1 AND 2592000
    ),
    max_delivery_attempts integer NOT NULL CHECK (
        max_delivery_attempts BETWEEN 1 AND 100
    ),
    delivery_ttl_seconds bigint NOT NULL CHECK (
        delivery_ttl_seconds BETWEEN 1 AND 2592000
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
    PRIMARY KEY (organization_id, trigger_id, generation),
    UNIQUE (organization_id, trigger_id, idempotency_key),
    FOREIGN KEY (organization_id, project_id, pipeline_id, trigger_id)
        REFERENCES pipeline_trigger_definitions(
            organization_id, project_id, pipeline_id, trigger_id
        ),
    FOREIGN KEY (organization_id, audit_sequence)
        REFERENCES audit_events(organization_id, sequence)
);

ALTER TABLE pipeline_trigger_definitions
    ADD CONSTRAINT pipeline_trigger_definitions_current_generation_fkey
    FOREIGN KEY (organization_id, trigger_id, current_generation)
    REFERENCES pipeline_trigger_versions(
        organization_id, trigger_id, generation
    )
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE trigger_deliveries (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    trigger_id uuid NOT NULL,
    trigger_generation bigint NOT NULL CHECK (trigger_generation > 0),
    delivery_id text NOT NULL CHECK (
        delivery_id = btrim(delivery_id)
        AND length(delivery_id) BETWEEN 1 AND 512
    ),
    event_id text NOT NULL CHECK (
        event_id = btrim(event_id)
        AND length(event_id) BETWEEN 1 AND 512
    ),
    event_kind text NOT NULL CHECK (
        event_kind = btrim(event_kind)
        AND length(event_kind) BETWEEN 1 AND 256
    ),
    caller_identity text NOT NULL CHECK (
        caller_identity = btrim(caller_identity)
        AND length(caller_identity) BETWEEN 1 AND 512
    ),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    canonical_payload jsonb NOT NULL CHECK (
        jsonb_typeof(canonical_payload) = 'object'
        AND octet_length(canonical_payload::text) <= 262144
    ),
    parameters jsonb NOT NULL CHECK (
        jsonb_typeof(parameters) = 'object'
        AND octet_length(parameters::text) <= 65536
    ),
    requested_platform text NOT NULL CHECK (
        requested_platform = btrim(requested_platform)
        AND length(requested_platform) BETWEEN 1 AND 128
    ),
    requested_trust_pool text NOT NULL CHECK (
        requested_trust_pool = btrim(requested_trust_pool)
        AND length(requested_trust_pool) BETWEEN 1 AND 128
    ),
    event_time_unix_ms bigint NOT NULL CHECK (event_time_unix_ms >= 0),
    accepted_at_unix_ms bigint NOT NULL CHECK (accepted_at_unix_ms >= 0),
    expires_at_unix_ms bigint NOT NULL CHECK (
        expires_at_unix_ms > accepted_at_unix_ms
    ),
    status text NOT NULL CHECK (
        status IN ('pending', 'retry_wait', 'admitted', 'dead_lettered')
    ),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at_unix_ms bigint NOT NULL CHECK (next_attempt_at_unix_ms >= 0),
    claim_owner text CHECK (
        claim_owner IS NULL OR (
            claim_owner = btrim(claim_owner)
            AND length(claim_owner) BETWEEN 1 AND 512
        )
    ),
    claim_fence bigint NOT NULL DEFAULT 0 CHECK (claim_fence >= 0),
    claim_expires_at_unix_ms bigint CHECK (claim_expires_at_unix_ms >= 0),
    redrive_of_delivery_id text,
    redrive_ordinal integer CHECK (
        redrive_ordinal IS NULL OR redrive_ordinal > 0
    ),
    build_id uuid,
    terminal_reason text CHECK (
        terminal_reason IS NULL OR (
            terminal_reason = btrim(terminal_reason)
            AND length(terminal_reason) BETWEEN 1 AND 2048
        )
    ),
    audit_sequence bigint NOT NULL CHECK (audit_sequence > 0),
    audit_event_hash bytea NOT NULL CHECK (octet_length(audit_event_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, trigger_id, delivery_id),
    UNIQUE (organization_id, trigger_id, event_id),
    UNIQUE (
        organization_id, trigger_id, redrive_of_delivery_id, redrive_ordinal
    ),
    FOREIGN KEY (organization_id, project_id, pipeline_id, trigger_id)
        REFERENCES pipeline_trigger_definitions(
            organization_id, project_id, pipeline_id, trigger_id
        ),
    FOREIGN KEY (organization_id, trigger_id, trigger_generation)
        REFERENCES pipeline_trigger_versions(
            organization_id, trigger_id, generation
        ),
    FOREIGN KEY (build_id, organization_id)
        REFERENCES builds(id, organization_id),
    FOREIGN KEY (organization_id, trigger_id, redrive_of_delivery_id)
        REFERENCES trigger_deliveries(
            organization_id, trigger_id, delivery_id
        ),
    FOREIGN KEY (organization_id, audit_sequence)
        REFERENCES audit_events(organization_id, sequence),
    CHECK (
        (status IN ('pending', 'retry_wait') AND build_id IS NULL
         AND terminal_reason IS NULL
         AND ((claim_owner IS NULL AND claim_expires_at_unix_ms IS NULL)
              OR (claim_owner IS NOT NULL
                  AND claim_expires_at_unix_ms IS NOT NULL)))
        OR
        (status = 'admitted' AND build_id IS NOT NULL
         AND terminal_reason IS NULL AND claim_owner IS NULL
         AND claim_expires_at_unix_ms IS NULL)
        OR
        (status = 'dead_lettered' AND build_id IS NULL
         AND terminal_reason IS NOT NULL AND claim_owner IS NULL
         AND claim_expires_at_unix_ms IS NULL)
    ),
    CHECK (
        (redrive_of_delivery_id IS NULL AND redrive_ordinal IS NULL)
        OR (redrive_of_delivery_id IS NOT NULL AND redrive_ordinal IS NOT NULL)
    )
);

CREATE TABLE trigger_schedule_watermarks (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    trigger_id uuid NOT NULL,
    trigger_generation bigint NOT NULL CHECK (trigger_generation > 0),
    timezone text NOT NULL CHECK (
        timezone = btrim(timezone) AND length(timezone) BETWEEN 1 AND 128
    ),
    calendar text NOT NULL CHECK (
        calendar = btrim(calendar) AND length(calendar) BETWEEN 1 AND 128
    ),
    expression text NOT NULL CHECK (
        expression = btrim(expression) AND length(expression) BETWEEN 1 AND 512
    ),
    schedule_identity_sha256 bytea NOT NULL CHECK (
        octet_length(schedule_identity_sha256) = 32
    ),
    last_resolved_slot_unix_ms bigint CHECK (last_resolved_slot_unix_ms >= 0),
    last_delivery_id text CHECK (
        last_delivery_id IS NULL OR (
            last_delivery_id = btrim(last_delivery_id)
            AND length(last_delivery_id) BETWEEN 1 AND 512
        )
    ),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, trigger_id, trigger_generation),
    FOREIGN KEY (organization_id, project_id, pipeline_id, trigger_id)
        REFERENCES pipeline_trigger_definitions(
            organization_id, project_id, pipeline_id, trigger_id
        ),
    FOREIGN KEY (organization_id, trigger_id, trigger_generation)
        REFERENCES pipeline_trigger_versions(
            organization_id, trigger_id, generation
        ),
    FOREIGN KEY (organization_id, trigger_id, last_delivery_id)
        REFERENCES trigger_deliveries(
            organization_id, trigger_id, delivery_id
        ) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX trigger_deliveries_due_idx
    ON trigger_deliveries (
        organization_id, status, next_attempt_at_unix_ms, trigger_id, delivery_id
    )
    WHERE status IN ('pending', 'retry_wait');

CREATE INDEX trigger_deliveries_expiry_idx
    ON trigger_deliveries (organization_id, expires_at_unix_ms)
    WHERE status IN ('pending', 'retry_wait');

CREATE FUNCTION mcloving_reject_pipeline_trigger_version_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'pipeline trigger versions are immutable';
END
$$;

REVOKE ALL ON FUNCTION mcloving_reject_pipeline_trigger_version_mutation()
FROM PUBLIC;

CREATE TRIGGER pipeline_trigger_versions_immutable
BEFORE UPDATE OR DELETE ON pipeline_trigger_versions
FOR EACH ROW
EXECUTE FUNCTION mcloving_reject_pipeline_trigger_version_mutation();

CREATE FUNCTION mcloving_guard_pipeline_trigger_definition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.pipeline_id IS DISTINCT FROM OLD.pipeline_id
       OR NEW.trigger_id IS DISTINCT FROM OLD.trigger_id
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'pipeline trigger identity is immutable';
    END IF;
    IF NEW.current_generation <> OLD.current_generation + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'pipeline trigger generation must advance exactly once';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_pipeline_trigger_definition()
FROM PUBLIC;

CREATE TRIGGER pipeline_trigger_definitions_generation_guard
BEFORE UPDATE ON pipeline_trigger_definitions
FOR EACH ROW
EXECUTE FUNCTION mcloving_guard_pipeline_trigger_definition();

CREATE FUNCTION mcloving_guard_trigger_delivery_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.pipeline_id IS DISTINCT FROM OLD.pipeline_id
       OR NEW.trigger_id IS DISTINCT FROM OLD.trigger_id
       OR NEW.trigger_generation IS DISTINCT FROM OLD.trigger_generation
       OR NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
       OR NEW.event_id IS DISTINCT FROM OLD.event_id
       OR NEW.event_kind IS DISTINCT FROM OLD.event_kind
       OR NEW.caller_identity IS DISTINCT FROM OLD.caller_identity
       OR NEW.payload_sha256 IS DISTINCT FROM OLD.payload_sha256
       OR NEW.canonical_payload IS DISTINCT FROM OLD.canonical_payload
       OR NEW.parameters IS DISTINCT FROM OLD.parameters
       OR NEW.requested_platform IS DISTINCT FROM OLD.requested_platform
       OR NEW.requested_trust_pool IS DISTINCT FROM OLD.requested_trust_pool
       OR NEW.event_time_unix_ms IS DISTINCT FROM OLD.event_time_unix_ms
       OR NEW.accepted_at_unix_ms IS DISTINCT FROM OLD.accepted_at_unix_ms
       OR NEW.expires_at_unix_ms IS DISTINCT FROM OLD.expires_at_unix_ms
       OR NEW.redrive_of_delivery_id IS DISTINCT FROM OLD.redrive_of_delivery_id
       OR NEW.redrive_ordinal IS DISTINCT FROM OLD.redrive_ordinal
       OR NEW.audit_sequence IS DISTINCT FROM OLD.audit_sequence
       OR NEW.audit_event_hash IS DISTINCT FROM OLD.audit_event_hash
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'trigger delivery identity and accepted payload are immutable';
    END IF;
    IF OLD.status IN ('admitted', 'dead_lettered') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'terminal trigger delivery is immutable';
    END IF;
    IF NEW.attempt_count < OLD.attempt_count
       OR NEW.attempt_count > OLD.attempt_count + 1
       OR NEW.claim_fence < OLD.claim_fence
       OR NEW.claim_fence > OLD.claim_fence + 1
       OR (NEW.claim_fence = OLD.claim_fence + 1
           AND (NEW.claim_owner IS NULL
                OR NEW.claim_expires_at_unix_ms IS NULL))
       OR (NEW.claim_fence = OLD.claim_fence
           AND NEW.claim_owner IS DISTINCT FROM OLD.claim_owner
           AND NEW.claim_owner IS NOT NULL)
       OR (OLD.status = 'pending' AND NEW.status NOT IN (
             'pending', 'retry_wait', 'admitted', 'dead_lettered'
          ))
       OR (OLD.status = 'retry_wait' AND NEW.status NOT IN (
             'retry_wait', 'admitted', 'dead_lettered'
          ))
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'invalid trigger delivery transition';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_trigger_delivery_mutation()
FROM PUBLIC;

CREATE TRIGGER trigger_deliveries_transition_guard
BEFORE UPDATE ON trigger_deliveries
FOR EACH ROW
EXECUTE FUNCTION mcloving_guard_trigger_delivery_mutation();

CREATE FUNCTION mcloving_guard_trigger_schedule_watermark()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.pipeline_id IS DISTINCT FROM OLD.pipeline_id
       OR NEW.trigger_id IS DISTINCT FROM OLD.trigger_id
       OR NEW.trigger_generation IS DISTINCT FROM OLD.trigger_generation
       OR NEW.timezone IS DISTINCT FROM OLD.timezone
       OR NEW.calendar IS DISTINCT FROM OLD.calendar
       OR NEW.expression IS DISTINCT FROM OLD.expression
       OR NEW.schedule_identity_sha256 IS DISTINCT FROM OLD.schedule_identity_sha256
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'trigger schedule watermark identity is immutable';
    END IF;
    IF OLD.last_resolved_slot_unix_ms IS NULL
       OR NEW.last_resolved_slot_unix_ms IS NULL
       OR NEW.last_resolved_slot_unix_ms <= OLD.last_resolved_slot_unix_ms
       OR NEW.last_delivery_id IS NULL
       OR NEW.last_delivery_id IS NOT DISTINCT FROM OLD.last_delivery_id
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'trigger schedule watermark must advance to a new delivery';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_trigger_schedule_watermark()
FROM PUBLIC;

CREATE TRIGGER trigger_schedule_watermarks_transition_guard
BEFORE UPDATE ON trigger_schedule_watermarks
FOR EACH ROW
EXECUTE FUNCTION mcloving_guard_trigger_schedule_watermark();

GRANT SELECT, INSERT, UPDATE ON pipeline_trigger_definitions TO mcloving_tenant;
GRANT SELECT, INSERT ON pipeline_trigger_versions TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE ON trigger_deliveries TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE ON trigger_schedule_watermarks TO mcloving_tenant;

ALTER TABLE pipeline_trigger_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pipeline_trigger_definitions FORCE ROW LEVEL SECURITY;
CREATE POLICY pipeline_trigger_definitions_tenant_policy
ON pipeline_trigger_definitions
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE pipeline_trigger_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pipeline_trigger_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY pipeline_trigger_versions_tenant_policy
ON pipeline_trigger_versions
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE trigger_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE trigger_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY trigger_deliveries_tenant_policy
ON trigger_deliveries
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE trigger_schedule_watermarks ENABLE ROW LEVEL SECURITY;
ALTER TABLE trigger_schedule_watermarks FORCE ROW LEVEL SECURITY;
CREATE POLICY trigger_schedule_watermarks_tenant_policy
ON trigger_schedule_watermarks
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
