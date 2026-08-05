# ADMIN-001 security and migration closure

Date: 2026-08-05

Verdict: PASS for the implementation gate at exact implementation head
`8d342d98969d3a3f67282b45f577cdc8e1110f3d`. All nine protected checks passed,
and independent exact-head review found no major issues.

PR #31 closure candidate `c6a5dcffbc743ccece63839390da355807900cb2`
then added only this receipt's final gate counts and the execution-board
transition from ADMIN-001 to INPUT-001. All nine protected checks passed on that
exact candidate. Its exact-head review found no implementation defect and one
P2 audit-document finding: the first receipt revision did not distinguish the
implementation head from the later closure candidate. This revision corrects
that finding. The final squash-merge commit is necessarily unknowable from
inside its own pre-merge contents; the immutable PR #31 exact-head checks plus
the post-merge protected-main verification are the final closure attestation.

This receipt is not a production caller cutover, owner-retirement, or Jenkins
decommissioning receipt.

## Inventory denominator

The sealed Mario identity/client manifest SHA-256 is
`a4227af8021c7d5fb6f7cc72be84af756ce1f95d33cd2ec9bad721beab587549`.
It declares exactly one client: `owner-operator`, direction `read-write`,
principal `oracle-admin`, Jenkins private-realm session, owner-designated
oracle-controller scope, and corpus-oracle administration use. ADMIN-001 does
not rewrite the source manifest or invent another writer.

## Reviewed implementation boundary

- migration 0026 records immutable per-client authority generations and a
  monotonic current pointer under forced tenant RLS;
- all 15 configuration and operational write families must be classified
  exactly once, including folder/node/controller/credential and queue/input/run
  control paths;
- five existing authenticated v1 API/CLI operations have exact method,
  endpoint, schema, precondition, idempotency, action, and scope contracts;
- the new `mcloving apply` command exposes pipeline desired-state convergence
  through the existing `PUT` plus quoted `If-Match` contract;
- unsupported paths cannot claim v1 support and require non-zero owner evidence
  before `owner_retired`; pending paths block target authority;
- a stable digest prevents source caller/endpoint/authentication/scope, target
  identity/API, or operation-denominator substitution at an authority
  transition, while each generation binds its exact dispositions and contracts;
- target authority requires zero observed Jenkins writes and authorization of
  the exact active target principal for every admitted action under the same
  project-policy lock used by AUTHZ-001;
- rollback is a new monotonic generation bound to the immediately preceding
  target generation and independent evidence; and
- migration-only writes, immutable history, client-level serialization, and
  hash-chained audit prevent runtime or racing writers from fabricating state.

## Executable receipt

The first real-PostgreSQL run exposed and then corrected the exact RLS preflight
table count for migration 0026. The complete contained PostgreSQL/controller/
agent gate then passed at the exact implementation head:

```text
controller truth: 42 passed, 2 backup-only ignored
identity lifecycle: 3 passed, 2 backup-only ignored
authorization mapping: 4 passed, 2 backup-only ignored
external read consumers: 2 passed
external admin clients: 3 passed
OIDC flow: 2 passed
execution spine: 7 passed
deployable runtime: 2 passed
DIFF-001: 1 passed
remote mTLS agent: 1 passed
total: 67 passed, 6 backup-only ignored
```

Pinned Rust check, clippy with warnings denied, formatting, the CLI suite, all
nine protected checks, execution-board tests, and the execution-board verifier
also passed. The verifier reported 84 tickets and 31 remaining before this
ticket's board closure. A P2 documentation comment that incorrectly suggested
input submission was already supported was fixed by naming the actual
protected-environment approval operation; the superseded thread was resolved
after clean exact-head review.

The admin tests prove incomplete classification, residual Jenkins writes,
caller/endpoint/digest substitution, missing action authority, stale generation,
concurrent first-generation and identity-lifecycle races, cross-tenant reads,
history mutation, exact rollback, and audit behavior. The
CLI journey proves bearer-only public API use and the exact revision and desired
state request.

## Operational boundary and residual risk

Mario remains Jenkins-source-authoritative for writes. The repository has no
real zero-write observation and no real owner-retirement receipt; test fixtures
are synthetic. Therefore this implementation cannot authorize a production
transition by itself. A later per-caller generation must bind the real
observation window and evidence before any affected canary/cutover, and
DECOM-001 separately authorizes irreversible retirement.

Trusted inventory, evidence collection/review, target identity provider, and
migration-role operation remain bounded authorities. Collusion between the
reviewer and migration operator could attest false external observations;
DIFF-003, production transition receipts, SEC-004, and decommissioning gates
remain required.
