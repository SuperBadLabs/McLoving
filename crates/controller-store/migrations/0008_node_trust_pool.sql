ALTER TABLE nodes
    ADD COLUMN required_trust_pool text NOT NULL DEFAULT 'trusted-linux',
    ADD CONSTRAINT nodes_required_trust_pool_nonempty
        CHECK (btrim(required_trust_pool) <> '');

CREATE INDEX nodes_trust_pool_claim_idx
    ON nodes (organization_id, required_trust_pool, priority DESC, queued_at, id)
    WHERE status = 'queued';
