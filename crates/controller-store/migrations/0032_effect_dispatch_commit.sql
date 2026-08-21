ALTER TABLE attempt_effects
    ADD COLUMN dispatch_committed_at timestamptz;

CREATE INDEX attempt_effects_dispatch_committed_idx
    ON attempt_effects (organization_id, attempt_id, fence)
    WHERE dispatch_committed_at IS NOT NULL;
