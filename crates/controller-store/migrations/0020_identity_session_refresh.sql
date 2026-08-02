ALTER TABLE identity_sessions
    ADD COLUMN refresh_token_digest bytea
        CHECK (refresh_token_digest IS NULL OR octet_length(refresh_token_digest) = 32),
    ADD COLUMN refresh_expires_at_unix_ms bigint
        CHECK (refresh_expires_at_unix_ms IS NULL OR refresh_expires_at_unix_ms > issued_at_unix_ms),
    ADD CONSTRAINT identity_sessions_refresh_shape CHECK (
        (refresh_token_digest IS NULL AND refresh_expires_at_unix_ms IS NULL)
        OR
        (refresh_token_digest IS NOT NULL AND refresh_expires_at_unix_ms IS NOT NULL
         AND refresh_expires_at_unix_ms > expires_at_unix_ms)
    );

CREATE UNIQUE INDEX identity_sessions_refresh_token_unique
    ON identity_sessions (organization_id, refresh_token_digest)
    WHERE refresh_token_digest IS NOT NULL;
