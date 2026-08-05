# External read consumers v1

Status: CONSUMER-001 implementation under review.

McLoving migrates Jenkins readers without treating a configured client as a
completed cutover. The sealed MIG-000 identity/client inventory is the source
denominator. For the owner-designated Mario oracle it contains exactly one
`read-write` client, `owner-operator`, authenticated as Jenkins principal
`oracle-admin`. CONSUMER-001 owns that client's read slice; ADMIN-001 owns its
higher-authority write slice. The sealed manifest remains unchanged at
`migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/identity-clients.yaml`
(SHA-256 `a4227af8021c7d5fb6f7cc72be84af756ce1f95d33cd2ec9bad721beab587549`).

## Read contract

The replacement is the authenticated public API v1 and Rust CLI. No
compatibility adapter or privileged controller/database shortcut is admitted.
The contract binds each consumer to one immutable McLoving identity and exact
tenant/project, plus one or more typed resources:

| Resource | API/CLI contract |
|---|---|
| Job metadata | `GET .../pipelines`; `mcloving pipelines`; exclusive lexical slug cursor |
| Queue and build list | `GET .../builds`; `mcloving builds --status queued`; paired creation-microsecond/build-UUID cursor |
| Status and graph | `GET .../builds/{build}` and `/graph`; `status` and `graph`; snapshot response |
| Logs | `GET .../logs`; `logs`/`watch`; complete attempt/fence/sequence/stream cursor |
| Tests | `GET .../tests`; `tests`; bounded complete normalized report set |
| Artifacts | `GET .../artifacts` and authenticated content route; `artifacts`/`artifact-download`; immutable digest-bound content |

Every request carries a separately revocable service credential or current
OIDC session. AUTHZ-001 enforces project view plus distinct artifact, test, and
log read actions. Missing, stale, cross-tenant, inactive, or insufficient
identity truth denies. API page limits remain server-bounded; a consumer
generation additionally records its reviewed per-minute request limit,
endpoint/query grammar, pagination rules, retention behavior, and URL rules.
Artifact content URLs remain authenticated McLoving URLs and never expose a
Jenkins URL.

## Authority ledger

Migration 0025 installs two forced-RLS tables. The immutable version table
binds source inventory/generation/endpoint/caller, target identity/subject/API
version, typed endpoint contracts, rate/retention/URL semantics, observation
window and source-read count, positive/negative authorization, historical/live
equivalence, artifact, pagination/resume, outage, rollback evidence, reviewer,
and a canonical SHA-256 contract digest. A separate stable binding digest covers
the sealed source caller/endpoint and target identity/API/query/rate/retention
contract. A monotonic pointer selects the current generation.

Generation one must retain `jenkins_source` authority. A later
`mcloving_target` generation is rejected unless the immediately prior
generation is Jenkins-authoritative and the bounded observation reports
exactly zero Jenkins reads. The cutover transaction also loads the exact active
target principal through the runtime identity/authorization path and requires
every declared resource's action (`project_view`, `log_read`, `test_read`, or
`artifact_read`) for the bound project; identity existence alone is never
sufficient. Restoring Jenkins must immediately follow a target generation,
name that exact generation, retain the stable binding digest, and bind
independent rollback evidence. Cutover likewise cannot substitute either side.
A fresh recutover is another new target generation; pointers never move
backward and authority cannot be skipped or repeated. Per-consumer transaction
advisory locks make simultaneous first writers deterministic.

Each successful registration, cutover, or restoration appends a hash-chained
tenant audit event. Only the migration role can write the ledger. The runtime
role receives RLS-constrained `SELECT` and cannot fabricate a readiness or
cutover receipt.

## Operational interpretation

The current Mario Jenkins controller is still an intentional oracle, so this
ticket does not claim that its operator has already stopped reading it.
Instead, the ledger makes that fact explicit as `jenkins_source` and prevents
any corresponding job from passing a later cutover gate until a reviewed
`mcloving_target` generation records zero residual reads. This avoids turning
implementation completeness into fabricated production evidence.

## Verification

`bins/cli/tests/api_only.rs` proves authenticated API-only pipeline metadata,
queued-build pagination, validation, status, and resumable log/watch behavior.
The broader API/store suites retain positive journeys, stable error envelopes,
cross-tenant/missing-authority route denial, normalized tests, and immutable
artifact retrieval. `crates/controller-store/tests/external_read_consumers.rs`
uses real PostgreSQL to prove canonical binding, source/target/tenant
substitution denial, zero-residual-read enforcement, exact monotonic rollback,
active-but-read-ineligible target denial, concurrent generation fencing,
hash-chained audit, forced RLS, and runtime mutation denial.

This ledger grants no build/effect authority and does not retire Jenkins.
Population cutover evidence is installed only when the real caller changes;
ADMIN-001 separately migrates every write operation of the same mixed client.
