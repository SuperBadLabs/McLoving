-- CTRL-007: delivered status observation is work with its own durable budget
-- and leased, token-fenced claims. It never changes the truth that a POST was
-- accepted; GitHub may still apply an earlier timed-out request afterwards.
ALTER TABLE notification_deliveries
    ADD COLUMN reconciliation_attempts integer NOT NULL DEFAULT 0
        CHECK (reconciliation_attempts BETWEEN 0 AND 12),
    ADD COLUMN reconciliation_due_at timestamptz,
    ADD COLUMN reconciliation_claim uuid,
    ADD COLUMN reconciliation_lease_until timestamptz,
    ADD COLUMN reconciliation_error text
        CHECK (reconciliation_error IS NULL OR length(reconciliation_error) BETWEEN 1 AND 1024),
    ADD CONSTRAINT notification_reconciliation_claim_pair CHECK (
        (reconciliation_claim IS NULL) = (reconciliation_lease_until IS NULL)
    );

-- Previously delivered rows are also observed, without resetting deliveries.
UPDATE notification_deliveries
SET reconciliation_due_at = COALESCE(delivered_at, clock_timestamp()) + interval '35 seconds'
WHERE state = 'delivered' AND kind = 'github_status';

CREATE INDEX notification_reconciliation_due_idx
ON notification_deliveries (organization_id, reconciliation_due_at)
WHERE state = 'delivered' AND kind = 'github_status'
  AND reconciliation_attempts < 12;
