-- PAR-003: human project roles are granted and revoked at runtime, by the
-- offline admin tool (which bootstraps a project's first Owner) and by a
-- project principal through the API. Each membership records who granted it
-- and when; existing rows predate the record and say so. Membership revision
-- starts at 1 and advances on every role mutation so HTTP If-Match never
-- collides with the absent-resource sentinel 0 or with same-millisecond
-- granted_at values. The runtime role writes memberships and bumps an
-- identity's lifecycle generation so a revocation fences that identity's live
-- sessions at once, the same fence a lifecycle transition applies. Rows stay
-- tenant-scoped by the forced policy from 0002.
ALTER TABLE project_memberships
    ADD COLUMN granted_by text NOT NULL DEFAULT 'unrecorded' CHECK (
        granted_by = btrim(granted_by)
        AND length(granted_by) BETWEEN 1 AND 512
    ),
    ADD COLUMN granted_at_unix_ms bigint NOT NULL DEFAULT 0 CHECK (granted_at_unix_ms >= 0),
    ADD COLUMN membership_revision bigint NOT NULL DEFAULT 1 CHECK (membership_revision >= 1);

GRANT INSERT, UPDATE, DELETE ON project_memberships TO mcloving_tenant;
GRANT UPDATE (lifecycle_generation) ON identities TO mcloving_tenant;
