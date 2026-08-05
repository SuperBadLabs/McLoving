# CONSUMER-001 security and migration closure

Date: 2026-08-04

Verdict: implementation PASS; independent exact-head review and protected-main
merge are pending. This receipt must not be interpreted as a production caller
cutover or Jenkins retirement receipt.

## Inventory denominator

The sealed Mario identity/client manifest has SHA-256
`a4227af8021c7d5fb6f7cc72be84af756ce1f95d33cd2ec9bad721beab587549`
and declares exactly one external client: `owner-operator`, direction
`read-write`, Jenkins principal `oracle-admin`, private-realm session,
owner-designated oracle-controller scope. CONSUMER-001 closes the versioned
read path; ADMIN-001 retains the write path. No unsealed second reader was
invented and the source manifest was not rewritten.

## Reviewed implementation boundary

- public client and CLI commands expose pipeline/job metadata and paginated
  build/queue reads in addition to existing status, graph, logs/watch, tests,
  artifact metadata, and authenticated artifact download;
- paired build and complete log cursors fail locally when incomplete;
- migration 0025 stores immutable, canonical per-consumer authority generations
  and a monotonic current pointer under forced tenant RLS;
- a stable binding digest prevents authority transitions from substituting the
  caller, source endpoint, target identity/API, or query/rate/retention contract;
- generations bind caller/target identity, tenant/project, source inventory and
  endpoint, API version, endpoint/query/pagination, retention/URL/rate semantics,
  evidence digests, observation window, reviewer, and rollback source;
- target authority requires a retained Jenkins-source generation and exactly
  zero observed Jenkins reads, plus successful runtime authorization of the
  exact active target principal for every declared read resource under a row
  lock that serializes lifecycle transitions;
- resource tags must match exact v1 endpoint templates and query-name sets
  before they select an authorization action;
- Jenkins restoration must bind the immediately preceding target generation
  and separate rollback evidence; and
- migration-only writes, per-consumer advisory serialization, and hash-chained
  audit prevent runtime or racing writers from fabricating cutover state.

## Executable receipt

The real PostgreSQL controller gate passed with the new tests enabled:

```text
controller truth: 42 passed, 2 backup-only ignored
identity lifecycle: 3 passed, 2 backup-only ignored
authorization mapping: 4 passed, 2 backup-only ignored
external read consumers: 2 passed
OIDC flow: 2 passed
execution spine: 7 passed
deployable runtime: 2 passed
DIFF-001: 1 passed
remote mTLS agent: 1 passed
```

The consumer-specific tests prove stale-digest and independently redigested
cross-generation source endpoint/contract substitution,
cross-tenant project substitution, inactive/substituted target identity,
active target identity without the required project read authority,
target lifecycle race serialization, resource/endpoint mismatch, canonical
digest mismatch, concurrent first-generation conflict, residual Jenkins-read
rejection, exact monotonic cutover and rollback, audited history, runtime
mutation denial, and forced-RLS inclusion. The API-only CLI gate proves
Bearer-authenticated pipeline and queued-build queries with exact cursors plus
status and resumable log/watch behavior. Existing protected API and store gates
cover missing/cross-tenant authorization, stable errors, historical/live build
truth, normalized tests, immutable artifact metadata/content, retention, and
outage-visible uncertain watch state.

## Operational boundary and residual risk

Mario remains the designated Jenkins oracle. Therefore its operator's current
ledger state is intentionally `jenkins_source`; this change does not manufacture
a zero-read production observation. A later corresponding job cutover remains
ineligible until a privileged reviewed `mcloving_target` generation binds the
real observation window and zero residual Jenkins reads. The ledger makes that
precondition executable while retaining exact rollback.

Trusted sealed inventory, evidence collection/review, target identity provider,
and migration-role database operation remain authoritative in their bounded
scope. A compromised reviewer and migration operator could attest false
external observations; later MIG-008/SEC-004 independent receipts remain
required. ADMIN-001 must migrate or explicitly retire the same client's write
slice before any affected Jenkins scope is retired.

Final closure requires a clean independent review of the exact implementation
head, all protected checks green, protected-main merge verification, and board
advancement to ADMIN-001.
