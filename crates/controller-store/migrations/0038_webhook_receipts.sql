-- PAR-001: the durable receipt of a webhook delivery the receiver
-- authenticated but did not admit (ignored event, tag push, deletion, ping,
-- or a filter miss). A delivery id's first authenticated decision is
-- durable: an admitted delivery lives in trigger_deliveries, an unadmitted
-- one here, both keyed by (organization, trigger, delivery id), both written
-- under the trigger lock, and each write refuses an id the other table
-- holds. The event header and the body digest are kept so a repeat is
-- compared against what was authenticated the first time.
CREATE TABLE webhook_receipts (
    organization_id uuid NOT NULL REFERENCES organizations (id),
    trigger_id uuid NOT NULL,
    delivery_id text NOT NULL CHECK (
        delivery_id = btrim(delivery_id)
        AND length(delivery_id) BETWEEN 1 AND 512
    ),
    event text NOT NULL CHECK (
        event = btrim(event)
        AND length(event) BETWEEN 1 AND 512
    ),
    body_sha256 bytea NOT NULL CHECK (octet_length(body_sha256) = 32),
    status text NOT NULL CHECK (status IN ('ignored', 'filtered')),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    caller_identity text NOT NULL CHECK (
        caller_identity = btrim(caller_identity)
        AND length(caller_identity) BETWEEN 1 AND 512
    ),
    recorded_at_unix_ms bigint NOT NULL CHECK (recorded_at_unix_ms >= 0),
    audit_sequence bigint NOT NULL CHECK (audit_sequence > 0),
    PRIMARY KEY (organization_id, trigger_id, delivery_id)
);

GRANT SELECT, INSERT ON webhook_receipts TO mcloving_tenant;

ALTER TABLE webhook_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_receipts_tenant_policy
ON webhook_receipts
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
