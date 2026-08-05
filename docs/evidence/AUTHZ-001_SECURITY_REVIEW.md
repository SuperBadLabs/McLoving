# AUTHZ-001 security and recovery closure

Date: 2026-08-04

Verdict: final PASS. Independent security review of exact implementation head
`8b9b11dcb6a51f491b3c052beb7cdf2282e55702` found no remaining major issue
after the reported lifecycle, generation-race, and audit-scope defects were
fixed and regression-tested.

This is a bounded review of the Jenkins-to-McLoving authorization mapping
substrate. It is not the later whole-product `SEC-004` campaign, does not certify
any production Jenkins population, and grants no canary or cutover authority.

## Reviewed boundary

The current AUTHZ-001 change includes:

- migration 0024 immutable policy generations, provenance mappings, explicit
  action decisions, current-generation pointer, history guards, forced RLS, and
  runtime read-only grants;
- canonical policy/mapping digests, optimistic generation fencing, source-to-
  target non-broadening validation, lifecycle/provenance validation, audit, and
  monotonic rollback metadata;
- deny-by-default mapped-project evaluation with deny-wins conflicts and no
  legacy lattice fallback;
- runtime loading that excludes stale group, lifecycle, provider, subject,
  realm, immutable source identity, membership, alias, or provenance rows;
- granular API checks for view, trigger, cancel, configure, approve/input,
  retry, artifact read/write, test, log, secret, audit, and scheduler actions;
  and
- real PostgreSQL and logical restore tests.

The durable identity substrate continues to own issuer/provider validation,
session generation fencing, service credential rotation/revocation, immutable
human source provenance, and cross-tenant authentication denial. AUTHZ-001
consumes those facts and never treats authentication as authority.

## Executable security receipt

The real PostgreSQL contract proves:

- explicit positive decisions and missing/negative decisions;
- a direct allow plus another matching deny resolves to deny;
- a seeded legacy `owner` role cannot fill a missing imported permission;
- a target allow not implied by the source ACL is rejected;
- Jenkins project ACL input cannot map tenant-wide audit read or scheduler
  control;
- disabled or deleted source principals cannot produce target allows;
- source-realm substitution is rejected;
- group-generation advancement invalidates the old session and makes the old
  policy grant stale for the new session;
- concurrent first-generation installation has one winner and one stable
  optimistic conflict, and stale updates also conflict;
- a complete empty generation revokes project authority;
- a retained reviewed policy can be restored only as a new monotonic generation;
- service policy survives credential rotation while old and explicitly revoked
  tokens remain denied;
- policy changes preserve the hash-chained audit log; and
- the runtime role cannot mutate any authorization policy table.

The full controller/PostgreSQL gate passed after the change: 42 controller
truth tests, three identity lifecycle tests, four non-ignored authorization
mapping tests, two OIDC API tests, seven execution-spine tests, two deployable
runtime tests, one DIFF-001 test, and one remote mTLS-agent test.

## Executable recovery receipt

`scripts/test-backup-restore.sh` seeds deterministic IDP-001 and AUTHZ-001
fixtures in an isolated source PostgreSQL instance, performs a custom-format
logical dump and restore into a fresh instance, and then verifies both. The
authorization verifier reauthenticates the restored scoped service identity,
checks positive view and negative cancel/configure decisions, verifies the
current policy generation, and validates the restored tenant audit chain.

Successful HeMan run:

```text
backup_restore_drill=passed
idp001_identity_restore=passed
authz001_authorization_restore=passed
dump_sha256=bedab6d03126ebd805d0a3b98df2d46f401607433184eb4ced8cbbe8eba4d6ae
restore_policy=all_pre_restore_leases_reconciliation_required
```

The dump digest identifies this run and is not a golden value because audit
timestamps intentionally vary. The executable assertions and pinned images are
the reproducibility gate.

## Residual risk and disposition

Trusted MIG-000 inventory, authorization reviewers, the target identity
provider, and migration-role database operators remain authoritative within
their scope. Group-derived Jenkins ACLs are installed as explicit reviewed
target-identity mappings; a changed membership generation removes the old
grant and requires a new reviewed policy generation. Exact population policy
parity remains DIFF-002, and unsupported or unrepresentable policy remains
ineligible rather than widened.

The clean independent implementation review, green protected checks, real
PostgreSQL receipt, and logical restore receipt close AUTHZ-001. Dispatch slot
1 advances to `CONSUMER-001`; production-population parity remains gated by
DIFF-002.
