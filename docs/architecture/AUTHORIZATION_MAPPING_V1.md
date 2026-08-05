# Authorization mapping v1

Status: AUTHZ-001 implementation and recovery complete; independent exact-head
review pending.

McLoving preserves effective Jenkins authorization without forcing independent
permissions into the native four-role lattice. A reviewed Jenkins job maps to
one McLoving project. Once that project has an imported policy, the current
explicit action grants are authoritative and missing grants deny. Native
projects without an imported policy retain the existing role and service-scope
behavior.

## Action vocabulary

Imported policy separates:

- project view;
- build trigger, cancel, and retry/replay;
- project configuration;
- approval/input action;
- artifact read and write;
- test read;
- log read;
- secret use; and
- audit read.

Scheduler control is not mappable from a Jenkins ACL. It remains a separate
McLoving service scope. A target `allow` must be implied by the normalized
source Jenkins permission set (or source `overall.administer`); otherwise the
import fails. Dropping source authority is permitted as an owner-reviewed
more-restrictive mapping. Unknown permissions never imply target authority.

## Durable policy truth

Migration 0024 installs four tenant-scoped, forced-RLS tables:

- immutable policy generations bind source realm implementation/configuration,
  the complete MIG-000 inventory digest, reviewer, canonical policy digest, and
  optional rollback source generation;
- immutable principal mappings bind source identity, alias history, membership
  and lifecycle generations, exact ACL entry/scope/generation/permissions,
  target identity/provider/subject and lifecycle/group generations, provenance,
  resulting role, and mapping digest;
- immutable action rows carry one explicit `allow` or `deny`; and
- one monotonic project pointer selects the current generation.

Installation is a privileged, optimistic operation. The complete canonical
policy is SHA-256 bound, the expected current generation must match, and the new
generation must advance by exactly one. Rollback republishes retained reviewed
semantics as a new generation and records the older source generation; the
active pointer never moves backwards. Every successful change appends to the
tenant hash-chained audit log. The constrained runtime role can read current
policy through RLS but cannot insert, update, or delete policy truth.

## Runtime decision

Authentication loads two distinct facts:

1. every project with an imported current policy, regardless of whether the
   principal has a valid grant; and
2. only current action rows whose target identity still matches lifecycle,
   group, provider/subject, source-realm, immutable source identity, membership,
   alias, and provenance truth.

The first fact disables lattice fallback. The second supplies decisions. If
multiple reviewed mappings (for example direct and group-derived entries)
produce the same action, `deny` wins. A missing, stale, or explicit-deny row is
denied. Group/lifecycle advancement therefore removes old authority on the
next authenticated request without waiting for policy replacement. Existing
IDP session and credential fencing denies stale human sessions and rotated or
revoked service credentials before authorization.

Public API routes use the granular actions: configuration validation/planning
and catalog writes require configure; submissions require trigger; retry is
independent; approvals require approval action; artifact publication and read
are distinct; test and log reads are distinct; cancellation, secrets, audit,
and scheduler control retain their own checks.

## Verification

`crates/controller-store/tests/authorization_mapping.rs` proves against real
PostgreSQL:

- canonical install, update conflict, complete revocation, and monotonic
  rollback;
- positive and negative action decisions, missing-grant denial, deny-wins
  conflict resolution, and legacy-role fallback suppression;
- target-authority broadening and scheduler-authority rejection;
- source-realm substitution rejection and exact human provenance binding;
- live group-generation change, old-session invalidation, and stale-policy
  denial;
- service credential rotation and emergency revocation;
- hash-chained authorization audit records; and
- runtime read-only privileges and forced RLS.

`scripts/test-backup-restore.sh` additionally restores a deterministic policy,
service credential, action decision set, current pointer, and audit chain into
a fresh PostgreSQL target and re-proves positive and negative decisions.

This substrate grants no Jenkins migration, canary, cutover, or production
effect authority. Case-specific policy parity remains a DIFF-002 obligation;
external reader/writer migration remains CONSUMER-001 and ADMIN-001.
