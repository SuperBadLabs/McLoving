ALTER TABLE attempt_effects
    ADD COLUMN outcome_receipt jsonb,
    ADD COLUMN outcome_receipt_digest bytea,
    ADD COLUMN reconciliation_receipt jsonb,
    ADD COLUMN reconciliation_receipt_digest bytea,
    ADD COLUMN observation_receipt jsonb,
    ADD COLUMN observation_receipt_digest bytea,
    ADD COLUMN shadow_replay_receipt jsonb,
    ADD COLUMN shadow_replay_receipt_digest bytea,
    ADD CONSTRAINT attempt_effects_outcome_receipt_pair CHECK (
        (outcome_receipt IS NULL) = (outcome_receipt_digest IS NULL)
        AND (outcome_receipt_digest IS NULL OR octet_length(outcome_receipt_digest) = 32)
    ),
    ADD CONSTRAINT attempt_effects_observation_receipt_pair CHECK (
        (observation_receipt IS NULL) = (observation_receipt_digest IS NULL)
        AND (observation_receipt_digest IS NULL OR octet_length(observation_receipt_digest) = 32)
    ),
    ADD CONSTRAINT attempt_effects_reconciliation_receipt_pair CHECK (
        (reconciliation_receipt IS NULL) = (reconciliation_receipt_digest IS NULL)
        AND (reconciliation_receipt_digest IS NULL OR octet_length(reconciliation_receipt_digest) = 32)
    ),
    ADD CONSTRAINT attempt_effects_shadow_receipt_pair CHECK (
        (shadow_replay_receipt IS NULL) = (shadow_replay_receipt_digest IS NULL)
        AND (shadow_replay_receipt_digest IS NULL OR octet_length(shadow_replay_receipt_digest) = 32)
    );
