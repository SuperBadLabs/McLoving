ALTER TABLE attempts
    ADD COLUMN retry_of uuid,
    ADD CONSTRAINT attempts_retry_parent_fk
        FOREIGN KEY (retry_of, organization_id)
        REFERENCES attempts(id, organization_id);

CREATE TABLE attempt_effects (
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    fence bigint NOT NULL CHECK (fence >= 0),
    effect_key text NOT NULL,
    effect_class text NOT NULL CHECK (
        effect_class IN ('idempotent', 'externally_idempotent', 'non_idempotent')
    ),
    status text NOT NULL CHECK (
        status IN ('prepared', 'applied', 'confirmed', 'uncertain')
    ),
    payload jsonb NOT NULL,
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, attempt_id, fence, effect_key),
    FOREIGN KEY (attempt_id, organization_id)
        REFERENCES attempts(id, organization_id)
);

CREATE TABLE dead_letters (
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 1024),
    payload jsonb NOT NULL,
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, attempt_id),
    FOREIGN KEY (attempt_id, organization_id)
        REFERENCES attempts(id, organization_id)
);

CREATE INDEX attempt_effects_uncertain_idx
    ON attempt_effects (organization_id, updated_at, attempt_id)
    WHERE status = 'uncertain';
CREATE UNIQUE INDEX attempts_retry_parent_idx
    ON attempts (organization_id, retry_of)
    WHERE retry_of IS NOT NULL;

GRANT SELECT, INSERT, UPDATE ON attempt_effects TO mcloving_tenant;
GRANT SELECT, INSERT ON dead_letters TO mcloving_tenant;

ALTER TABLE attempt_effects ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempt_effects FORCE ROW LEVEL SECURITY;
CREATE POLICY attempt_effects_tenant_policy ON attempt_effects
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

ALTER TABLE dead_letters ENABLE ROW LEVEL SECURITY;
ALTER TABLE dead_letters FORCE ROW LEVEL SECURITY;
CREATE POLICY dead_letters_tenant_policy ON dead_letters
    USING (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id =
        NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );
