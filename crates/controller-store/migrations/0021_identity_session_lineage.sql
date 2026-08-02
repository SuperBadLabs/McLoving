ALTER TABLE identity_sessions
    ADD COLUMN family_id uuid;

-- Earlier schema versions did not retain enough information to reconstruct an
-- exact rotation lineage. Fail closed at the upgrade boundary instead of
-- guessing across independent devices; users with a live pre-v21 session must
-- authenticate again.
UPDATE identity_sessions
SET revoked_at_unix_ms = GREATEST(
        issued_at_unix_ms,
        (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint
    ),
    revocation_reason = 'session_lineage_migration'
WHERE revoked_at_unix_ms IS NULL;

UPDATE identity_sessions
SET family_id = session_id
WHERE family_id IS NULL;

ALTER TABLE identity_sessions
    ALTER COLUMN family_id SET NOT NULL;

CREATE INDEX identity_sessions_family_active_idx
    ON identity_sessions (organization_id, family_id)
    WHERE revoked_at_unix_ms IS NULL;
