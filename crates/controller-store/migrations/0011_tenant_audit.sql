CREATE TABLE audit_chain_heads (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id),
    next_sequence bigint NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
    last_hash bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
        CHECK (octet_length(last_hash) = 32),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE audit_events (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_id uuid NOT NULL,
    category text NOT NULL CHECK (length(category) BETWEEN 1 AND 64),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 512),
    action text NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 1024),
    payload jsonb NOT NULL,
    occurred_at_unix_ms bigint NOT NULL CHECK (occurred_at_unix_ms >= 0),
    previous_hash bytea NOT NULL CHECK (octet_length(previous_hash) = 32),
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, sequence),
    UNIQUE (organization_id, event_id),
    UNIQUE (organization_id, event_hash)
);

CREATE INDEX audit_events_export_idx
    ON audit_events (organization_id, sequence);

CREATE TABLE audit_retention_policies (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id),
    retain_until_unix_ms bigint NOT NULL CHECK (retain_until_unix_ms >= 0),
    legal_hold boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION mcloving_reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'mcloving audit events are append-only';
END
$$;

REVOKE ALL ON FUNCTION mcloving_reject_audit_event_mutation() FROM PUBLIC;

CREATE TRIGGER audit_events_immutable
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION mcloving_reject_audit_event_mutation();

CREATE FUNCTION mcloving_guard_audit_retention_regression()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.retain_until_unix_ms < OLD.retain_until_unix_ms
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'mcloving audit retention cannot move backwards';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_audit_retention_regression() FROM PUBLIC;

CREATE TRIGGER audit_retention_monotonic
BEFORE UPDATE ON audit_retention_policies
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_audit_retention_regression();

GRANT SELECT, INSERT ON audit_events TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE ON audit_chain_heads, audit_retention_policies
TO mcloving_tenant;

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_tenant_policy ON audit_events
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_chain_heads_tenant_policy ON audit_chain_heads
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE audit_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_retention_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_retention_policies_tenant_policy ON audit_retention_policies
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
