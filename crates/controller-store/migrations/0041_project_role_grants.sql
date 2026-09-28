-- PAR-003: human project roles are granted and revoked at runtime, by the
-- offline admin tool (which bootstraps a project's first Owner) and by a
-- project principal through the API. Each membership records who granted it
-- and when; existing rows predate the record and say so. Membership revision
-- advances from a per-identity counter that survives revocation, so If-Match
-- "0" stays reserved for absent memberships and a deleted-then-restored
-- membership never reuses an earlier revision. The runtime role writes
-- memberships and bumps an identity's lifecycle generation so a revocation
-- fences that identity's live sessions at once, the same fence a lifecycle
-- transition applies. Rows stay tenant-scoped by the forced policy from 0002.
ALTER TABLE project_memberships
    ADD COLUMN granted_by text NOT NULL DEFAULT 'unrecorded' CHECK (
        granted_by = btrim(granted_by)
        AND length(granted_by) BETWEEN 1 AND 512
    ),
    ADD COLUMN granted_at_unix_ms bigint NOT NULL DEFAULT 0 CHECK (granted_at_unix_ms >= 0),
    ADD COLUMN membership_revision bigint NOT NULL DEFAULT 1 CHECK (membership_revision >= 1);

CREATE TABLE project_membership_revision_counters (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    last_revision bigint NOT NULL CHECK (last_revision >= 1),
    PRIMARY KEY (organization_id, project_id, identity_id)
);

ALTER TABLE project_membership_revision_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_membership_revision_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY project_membership_revision_counters_tenant_policy
    ON project_membership_revision_counters
    USING (
        organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );


-- Existing memberships already carry membership_revision = 1 from the
-- column default; seed counters so the next allocate advances past that
-- value instead of reissuing 1 after an upgrade.
INSERT INTO project_membership_revision_counters (
    organization_id, project_id, identity_id, last_revision
)
SELECT organization_id, project_id, identity_id, membership_revision
FROM project_memberships
ON CONFLICT (organization_id, project_id, identity_id) DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON project_membership_revision_counters TO mcloving_tenant;
GRANT INSERT, UPDATE, DELETE ON project_memberships TO mcloving_tenant;
GRANT UPDATE (lifecycle_generation) ON identities TO mcloving_tenant;
