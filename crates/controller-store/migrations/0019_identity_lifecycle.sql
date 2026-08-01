CREATE TABLE identity_providers (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    provider_id uuid NOT NULL,
    issuer text NOT NULL CHECK (issuer = btrim(issuer) AND length(issuer) BETWEEN 1 AND 2048),
    audience text NOT NULL CHECK (audience = btrim(audience) AND length(audience) BETWEEN 1 AND 512),
    authorization_endpoint text NOT NULL CHECK (authorization_endpoint = btrim(authorization_endpoint) AND length(authorization_endpoint) BETWEEN 1 AND 2048),
    token_endpoint text NOT NULL CHECK (token_endpoint = btrim(token_endpoint) AND length(token_endpoint) BETWEEN 1 AND 2048),
    jwks_uri text NOT NULL CHECK (jwks_uri = btrim(jwks_uri) AND length(jwks_uri) BETWEEN 1 AND 2048),
    client_id text NOT NULL CHECK (client_id = btrim(client_id) AND length(client_id) BETWEEN 1 AND 512),
    group_claim text NOT NULL CHECK (group_claim = btrim(group_claim) AND length(group_claim) BETWEEN 1 AND 128),
    configuration_generation bigint NOT NULL CHECK (configuration_generation > 0),
    configuration_digest bytea NOT NULL CHECK (octet_length(configuration_digest) = 32),
    jwks_generation bigint NOT NULL CHECK (jwks_generation > 0),
    jwks_digest bytea NOT NULL CHECK (octet_length(jwks_digest) = 32),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, provider_id),
    UNIQUE (organization_id, issuer)
);

ALTER TABLE identities
    ADD COLUMN lifecycle_state text NOT NULL DEFAULT 'active'
        CHECK (lifecycle_state IN ('active', 'disabled', 'deleted')),
    ADD COLUMN lifecycle_generation bigint NOT NULL DEFAULT 1
        CHECK (lifecycle_generation > 0),
    ADD COLUMN provider_id uuid,
    ADD COLUMN external_subject text,
    ADD COLUMN group_generation bigint NOT NULL DEFAULT 1
        CHECK (group_generation > 0),
    ADD COLUMN group_digest bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
        CHECK (octet_length(group_digest) = 32),
    ADD COLUMN source_realm_digest bytea
        CHECK (source_realm_digest IS NULL OR octet_length(source_realm_digest) = 32),
    ADD COLUMN source_identity_id text,
    ADD COLUMN source_membership_generation bigint
        CHECK (source_membership_generation IS NULL OR source_membership_generation > 0),
    ADD COLUMN alias_history jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(alias_history) = 'array'),
    ADD COLUMN provenance_digest bytea
        CHECK (provenance_digest IS NULL OR octet_length(provenance_digest) = 32),
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();

-- Human identities created before provider binding existed cannot be trusted as
-- login principals. Quarantine them during the upgrade instead of making the
-- migration fail or silently assigning an OIDC subject.
UPDATE identities
SET lifecycle_state = 'disabled',
    lifecycle_generation = 2,
    updated_at = clock_timestamp()
WHERE kind = 'human'
  AND provider_id IS NULL;

ALTER TABLE identities
    ADD CONSTRAINT identities_oidc_shape CHECK (
        (kind = 'human' AND (
            (provider_id IS NOT NULL AND external_subject IS NOT NULL
             AND external_subject = btrim(external_subject)
             AND length(external_subject) BETWEEN 1 AND 512)
            OR
            (provider_id IS NULL AND external_subject IS NULL
             AND lifecycle_state = 'disabled')
        ))
        OR
        (kind = 'service' AND provider_id IS NULL AND external_subject IS NULL)
    ),
    ADD CONSTRAINT identities_source_provenance_shape CHECK (
        (source_realm_digest IS NULL AND source_identity_id IS NULL
         AND source_membership_generation IS NULL AND provenance_digest IS NULL)
        OR
        (source_realm_digest IS NOT NULL AND source_identity_id IS NOT NULL
         AND source_identity_id = btrim(source_identity_id)
         AND length(source_identity_id) BETWEEN 1 AND 512
         AND source_membership_generation IS NOT NULL AND provenance_digest IS NOT NULL)
    ),
    ADD CONSTRAINT identities_provider_fk FOREIGN KEY (organization_id, provider_id)
        REFERENCES identity_providers(organization_id, provider_id);

CREATE UNIQUE INDEX identities_external_subject_unique
    ON identities (organization_id, provider_id, external_subject)
    WHERE kind = 'human';

CREATE TABLE identity_group_snapshots (
    organization_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    groups jsonb NOT NULL CHECK (jsonb_typeof(groups) = 'array'),
    group_digest bytea NOT NULL CHECK (octet_length(group_digest) = 32),
    provider_configuration_generation bigint NOT NULL CHECK (provider_configuration_generation > 0),
    provider_jwks_generation bigint NOT NULL CHECK (provider_jwks_generation > 0),
    observed_at_unix_ms bigint NOT NULL CHECK (observed_at_unix_ms >= 0),
    PRIMARY KEY (organization_id, identity_id, generation),
    FOREIGN KEY (identity_id, organization_id) REFERENCES identities(id, organization_id)
);

CREATE TABLE oidc_login_attempts (
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    state_digest bytea NOT NULL CHECK (octet_length(state_digest) = 32),
    nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest) = 32),
    pkce_verifier text NOT NULL CHECK (pkce_verifier = btrim(pkce_verifier) AND length(pkce_verifier) BETWEEN 43 AND 128),
    redirect_uri text NOT NULL CHECK (redirect_uri = btrim(redirect_uri) AND length(redirect_uri) BETWEEN 1 AND 2048),
    provider_configuration_generation bigint NOT NULL CHECK (provider_configuration_generation > 0),
    expires_at_unix_ms bigint NOT NULL CHECK (expires_at_unix_ms >= 0),
    consumed_at_unix_ms bigint CHECK (consumed_at_unix_ms IS NULL OR consumed_at_unix_ms >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, attempt_id),
    UNIQUE (organization_id, state_digest),
    FOREIGN KEY (organization_id, provider_id) REFERENCES identity_providers(organization_id, provider_id)
);

CREATE TABLE identity_sessions (
    organization_id uuid NOT NULL,
    session_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    provider_configuration_generation bigint NOT NULL CHECK (provider_configuration_generation > 0),
    provider_jwks_generation bigint NOT NULL CHECK (provider_jwks_generation > 0),
    identity_lifecycle_generation bigint NOT NULL CHECK (identity_lifecycle_generation > 0),
    group_generation bigint NOT NULL CHECK (group_generation > 0),
    issued_at_unix_ms bigint NOT NULL CHECK (issued_at_unix_ms >= 0),
    expires_at_unix_ms bigint NOT NULL CHECK (expires_at_unix_ms > issued_at_unix_ms),
    last_seen_at_unix_ms bigint NOT NULL CHECK (last_seen_at_unix_ms >= issued_at_unix_ms),
    revoked_at_unix_ms bigint CHECK (revoked_at_unix_ms IS NULL OR revoked_at_unix_ms >= issued_at_unix_ms),
    revocation_reason text CHECK (revocation_reason IS NULL OR (revocation_reason = btrim(revocation_reason) AND length(revocation_reason) BETWEEN 1 AND 256)),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, session_id),
    UNIQUE (organization_id, token_digest),
    FOREIGN KEY (identity_id, organization_id) REFERENCES identities(id, organization_id)
);

CREATE INDEX identity_sessions_identity_active_idx
    ON identity_sessions (organization_id, identity_id, expires_at_unix_ms)
    WHERE revoked_at_unix_ms IS NULL;

CREATE TABLE oidc_token_replays (
    organization_id uuid NOT NULL,
    id_token_digest bytea NOT NULL CHECK (octet_length(id_token_digest) = 32),
    identity_id uuid NOT NULL,
    expires_at_unix_ms bigint NOT NULL CHECK (expires_at_unix_ms >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, id_token_digest),
    FOREIGN KEY (identity_id, organization_id) REFERENCES identities(id, organization_id)
);

CREATE TABLE service_credentials (
    organization_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    issued_at_unix_ms bigint NOT NULL CHECK (issued_at_unix_ms >= 0),
    expires_at_unix_ms bigint CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms > issued_at_unix_ms),
    revoked_at_unix_ms bigint CHECK (revoked_at_unix_ms IS NULL OR revoked_at_unix_ms >= issued_at_unix_ms),
    revocation_reason text CHECK (revocation_reason IS NULL OR (revocation_reason = btrim(revocation_reason) AND length(revocation_reason) BETWEEN 1 AND 256)),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, credential_id),
    UNIQUE (organization_id, identity_id, generation),
    UNIQUE (organization_id, token_digest),
    FOREIGN KEY (identity_id, organization_id) REFERENCES identities(id, organization_id)
);

CREATE FUNCTION mcloving_guard_identity_key_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF (NEW.id IS DISTINCT FROM OLD.id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.subject IS DISTINCT FROM OLD.subject
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.external_subject IS DISTINCT FROM OLD.external_subject
       OR NEW.source_realm_digest IS DISTINCT FROM OLD.source_realm_digest
       OR NEW.source_identity_id IS DISTINCT FROM OLD.source_identity_id
       OR NEW.source_membership_generation IS DISTINCT FROM OLD.source_membership_generation
       OR NEW.alias_history IS DISTINCT FROM OLD.alias_history
       OR NEW.provenance_digest IS DISTINCT FROM OLD.provenance_digest
       ) AND NOT (
           OLD.kind = 'human'
           AND OLD.provider_id IS NULL
           AND OLD.external_subject IS NULL
           AND OLD.source_realm_digest IS NULL
           AND OLD.source_identity_id IS NULL
           AND OLD.source_membership_generation IS NULL
           AND OLD.provenance_digest IS NULL
           AND OLD.lifecycle_state = 'disabled'
           AND OLD.lifecycle_generation = 2
           AND NEW.id = OLD.id
           AND NEW.organization_id = OLD.organization_id
           AND NEW.kind = OLD.kind
           AND NEW.subject = OLD.subject
           AND NEW.provider_id IS NOT NULL
           AND NEW.external_subject IS NOT NULL
           AND NEW.source_realm_digest IS NOT NULL
           AND NEW.source_identity_id IS NOT NULL
           AND NEW.source_membership_generation IS NOT NULL
           AND NEW.provenance_digest IS NOT NULL
           AND NEW.lifecycle_state = OLD.lifecycle_state
           AND NEW.lifecycle_generation = OLD.lifecycle_generation
           AND NEW.group_generation = OLD.group_generation
           AND NEW.group_digest = OLD.group_digest
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'mcloving identity binding is immutable';
    END IF;
    IF NEW.lifecycle_generation < OLD.lifecycle_generation
       OR NEW.group_generation < OLD.group_generation
       OR (OLD.lifecycle_state = 'deleted' AND NEW.lifecycle_state <> 'deleted')
    THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'mcloving identity generation or deletion cannot move backwards';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_identity_key_mutation() FROM PUBLIC;
CREATE TRIGGER identities_immutable_binding
BEFORE UPDATE ON identities
FOR EACH ROW EXECUTE FUNCTION mcloving_guard_identity_key_mutation();

GRANT SELECT ON identity_providers, identities, project_memberships,
    service_scopes TO mcloving_tenant;
GRANT UPDATE (group_generation, group_digest, updated_at)
    ON identities TO mcloving_tenant;
GRANT SELECT, INSERT, DELETE ON identity_group_snapshots, oidc_token_replays TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_sessions TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE ON service_credentials TO mcloving_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_login_attempts TO mcloving_tenant;

ALTER TABLE identity_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_providers_tenant_policy ON identity_providers
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE identity_group_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_group_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_group_snapshots_tenant_policy ON identity_group_snapshots
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE oidc_login_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_login_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_login_attempts_tenant_policy ON oidc_login_attempts
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE identity_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_sessions_tenant_policy ON identity_sessions
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE oidc_token_replays ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_token_replays FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_token_replays_tenant_policy ON oidc_token_replays
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);

ALTER TABLE service_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY service_credentials_tenant_policy ON service_credentials
    USING (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid);
