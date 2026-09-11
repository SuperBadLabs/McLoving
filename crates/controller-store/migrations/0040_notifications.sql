-- PAR-004: build notifications. A build carries, from admission, the targets
-- its pipeline named for its terminal outcome (resolved against the
-- deployment's notification mapping catalog, so each target already names the
-- repository or destination the mapping owns). The transaction that derives
-- the build's terminal status inserts one delivery row per target under the
-- same commit, so a terminal build has its deliveries or is not terminal; a
-- worker claims due rows with SKIP LOCKED, delivers at least once with
-- exponential backoff, and abandons after a bounded number of attempts.
ALTER TABLE builds
    ADD COLUMN notify_targets jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(notify_targets) = 'array');

CREATE TABLE notification_deliveries (
    organization_id uuid NOT NULL REFERENCES organizations (id),
    build_id uuid NOT NULL,
    target_index integer NOT NULL CHECK (target_index >= 0),
    kind text NOT NULL CHECK (kind IN ('github_status', 'webhook')),
    mapping_id text NOT NULL CHECK (
        mapping_id = btrim(mapping_id)
        AND length(mapping_id) BETWEEN 1 AND 128
    ),
    target jsonb NOT NULL CHECK (jsonb_typeof(target) = 'object'),
    build_status text NOT NULL CHECK (build_status IN ('succeeded', 'failed', 'aborted')),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'abandoned')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_error text CHECK (last_error IS NULL OR length(last_error) BETWEEN 1 AND 1024),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    delivered_at timestamptz,
    PRIMARY KEY (organization_id, build_id, target_index),
    FOREIGN KEY (build_id, organization_id) REFERENCES builds (id, organization_id)
);

CREATE INDEX notification_deliveries_due_idx
    ON notification_deliveries (organization_id, next_attempt_at)
    WHERE state = 'pending';

GRANT SELECT, INSERT, UPDATE ON notification_deliveries TO mcloving_tenant;

ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_deliveries_tenant_policy
ON notification_deliveries
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
