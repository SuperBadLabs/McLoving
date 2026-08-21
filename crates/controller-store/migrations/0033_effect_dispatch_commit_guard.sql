ALTER TABLE attempt_effects
    ADD CONSTRAINT attempt_effects_dispatch_commit_release_check CHECK (
        dispatch_committed_at IS NULL
        OR status NOT IN ('release_pending', 'abandoned')
    );
