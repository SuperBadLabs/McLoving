CREATE TABLE credential_namespace_reservations (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    reservation_kind text NOT NULL
        CHECK (reservation_kind = 'artifact_agent'),
    reservation_subject text NOT NULL
        CHECK (reservation_subject = btrim(reservation_subject)
               AND length(reservation_subject) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, token_digest)
);

GRANT SELECT, INSERT ON credential_namespace_reservations TO mcloving_tenant;

ALTER TABLE credential_namespace_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_namespace_reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_namespace_reservations_tenant_policy
    ON credential_namespace_reservations
    USING (
        organization_id = NULLIF(
            current_setting('mcloving.organization_id', true), ''
        )::uuid
    )
    WITH CHECK (
        organization_id = NULLIF(
            current_setting('mcloving.organization_id', true), ''
        )::uuid
    );
