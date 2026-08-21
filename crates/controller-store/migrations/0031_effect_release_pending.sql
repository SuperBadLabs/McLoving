ALTER TABLE attempt_effects
    DROP CONSTRAINT attempt_effects_status_check,
    ADD CONSTRAINT attempt_effects_status_check CHECK (
        status IN (
            'prepared',
            'applied',
            'confirmed',
            'uncertain',
            'release_pending',
            'abandoned'
        )
    );

CREATE INDEX attempt_effects_release_pending_idx
    ON attempt_effects (organization_id, updated_at, attempt_id)
    WHERE status = 'release_pending';
