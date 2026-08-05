# IDP-001 security and recovery closure

Date: 2026-08-04

Verdict: PASS for IDP-001. No unresolved blocker or must-fix finding remains.

This is a bounded closure review of the production authentication and identity
lifecycle substrate. It is not the later whole-product `SEC-004` adversarial
campaign and grants no production canary or cutover authority by itself.

## Reviewed implementation

- Squash merge: `1da73ee8362e5977b922e531cf03f89cfc760e6f`
- Git tree: `938539e091248243047c0c862642a83f94c6f64a`
- Pull request: #24, `IDP-001: durable identity and OIDC lifecycle`
- Current-branch comparison: the controller startup, offline identity admin,
  OIDC implementation, durable identity store, and migrations 0019 through
  0023 are byte-identical to the reviewed merge.

The review covered OIDC authorization code with PKCE, exact redirect and
provider binding, bounded no-redirect token/JWKS retrieval, RSA signature and
issuer/audience/authorized-party/time/nonce validation, one-time state and
ID-token consumption, session and refresh lineage, provider/JWKS/group/lifecycle
generation fencing, human provenance immutability, service credential scope and
rotation, tenant RLS, active-active serialization, offline administration,
startup atomicity, audit publication, and database restore behavior.

## Independent review receipt

PR #24 received repeated exact-head GitHub Codex security/correctness reviews.
Sixteen actionable findings were repaired during the review cycle. The bounded
terminal review found no remaining correctness or security defect; a final
consistency pass found only the intentionally open board/evidence state. This
closure pass independently re-read the merged security-critical paths and the
resulting migration constraints and found no new actionable issue.

The reviewed controls close the implementation obligations in TM-027, TM-028,
and the IDP-scoped part of TM-029. The existing residual risks remain unchanged:
a compromised target identity provider or trusted migration operator remains
authoritative within its grant, and hostile Internet exposure still requires an
upstream authenticated edge because the controller-local OIDC-start limiter is
not a distributed perimeter control.

## Executable recovery receipt

`scripts/test-backup-restore.sh` now includes deterministic IDP-001 source and
restore canaries using isolated source and target PostgreSQL containers. The
source fixture binds an immutable contained Jenkins realm identity to a
contained target provider, advances a human group generation, rotates a scoped
service credential, and creates both stale and current credentials. After
`pg_dump` and `pg_restore`, the verifier proves:

- exact provider configuration/JWKS generations and digests survive;
- source-realm digest, immutable source ID, membership generation, alias
  history, and provenance digest survive;
- stale-group human sessions and rotated service credentials remain denied;
- current human and service credentials retain their exact roles/scopes;
- restored provenance rejects source-realm substitution; and
- all five identity audit families remain present.

Successful HeMan run:

```text
backup_restore_drill=passed
idp001_identity_restore=passed
dump_sha256=59fe396bfecaadf04d2176ce245e79e5902c9bbfcce5e025ce164aeb5cdaec8e
restore_policy=all_pre_restore_leases_reconciliation_required
```

The dump digest identifies this run and is not a golden value; PostgreSQL audit
timestamps intentionally make independently generated dumps distinct. The
executable assertions, pinned images, and CI job are the reproducibility gate.

## Disposition

IDP-001 may advance to `DONE`. `AUTHZ-001` is the identity lane's next ticket.
Production authority remains blocked by its own downstream differential,
package, canary, cutover, security, and recovery gates.
