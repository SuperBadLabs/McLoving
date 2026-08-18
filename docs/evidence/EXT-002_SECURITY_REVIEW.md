# EXT-002 security and closure review

Date: 2026-08-17

Verdict: IMPLEMENTATION AND MARIO REHEARSAL PASS; exact-head review,
protected CI, merge, and protected-main verification remain open.

## Scope

EXT-002 connects the typed Pipeline IR connector intent to the shipped
controller execution path without granting native workloads a destination
endpoint, credential, or connector RPC. The controller admits only an exact
deployment-owned mapping ID and digest, freezes a signed one-action request,
persists `prepared` before dispatch, and invokes digest-pinned out-of-process
connector, observer, and deny-authority shadow services. Downstream terminal
publication remains closed until the complete signed evidence join is durable.

The public status API returns only effect state and SHA-256 evidence digests.
It never returns the frozen payload or receipt bodies. A service timeout,
signed-but-substituted connector/observer/shadow response, invalid
reconciliation response, cancellation after dispatch, or controller loss after
dispatch freezes the effect as `uncertain` and routes the attempt to explicit
reconciliation. Lease expiry protects every controller-runtime prepared row,
including externally idempotent rows; it cannot transfer the frozen one-action
grant to a new fence.

## Exact implementation evidence

- Exact implementation head:
  `b87609857226fb7a44d124a2f1002f75f4bd22c8`.
- Deployment mapping admission rejects an unknown mapping, a floating or stale
  digest, a duplicate catalog entry, a substituted catalog file, partial
  configuration, and plan/catalog drift at validation, planning, persistence,
  build admission, and shipped-controller startup.
- The real-PostgreSQL harness passed 42 controller-store tests and 14
  execution-spine tests, plus the deployable controller, admitted differential,
  and shipped mTLS agent tests. The runtime cases cover successful and
  ambiguous/reconciled outcomes, pre-dispatch executable substitution,
  post-dispatch timeout, signed connector/observer/shadow response
  substitution, cancellation after dispatch, crash after dispatch, lease loss,
  controller restart, retry denial, durable outcome/observation/reconciliation/
  shadow evidence, and exactly one physical fixture dispatch.
- The positive path holds the shadow reply open and observes the attempt still
  `running` after outcome and independent observation are durable. Only the
  durable signed shadow receipt permits terminal publication.
- Redacted store and HTTP projections expose the payload and four evidence
  digests while omitting frozen values, request bodies, receipt bodies,
  protected outputs, and credentials.

## Mario effect-free rehearsal

Mario ran the complete 14-test real execution spine at the exact implementation
head using real PostgreSQL. Compilation occurred before runtime. Runtime used a
fresh internal-only container network, a disposable database, the process-
isolated connector/observer/shadow fixture, and three pairwise-distinct Ed25519
receipt roles. The run completed with zero failed tests, exactly-once dispatch
assertions true, complete container/network teardown, and every production,
canary, and cutover authority flag false.

- Owner-only evidence directory:
  `/home/srikanth/.local/share/mcloving/ext002-runs/ext002-20260818T021748Z-95a32de1`
- Result receipt SHA-256:
  `44ad8eb55386a38dfbe42a62407fd198b87aac53c9eca709f8a387bb0a81d8c7`
- Evidence checksum file SHA-256:
  `08133a26ad6ee4e46065869cf18943222f56d661dd6a83b283a29d5db984a244`
- Fixture SHA-256:
  `9fcd3559fd0a45d6c13604bd1976d258f0155007ec2619f2ec95044dea088fbd`
- Test binary SHA-256:
  `b0daea7e1b5f974af2e32ea032d859e7e0ea4dfb51b0701d09646f72c9d9c0e6`

The evidence directory is mode `0700`; every retained file is mode `0600`.
The rehearsal created no production mapping, endpoint, credential, action,
canary, or authority transfer.

## Remaining closure gates

EXT-002 stays `ACTIVE` until its final exact head passes independent review and
all protected checks, every actionable review thread is resolved, the pull
request is squash-merged, and the resulting protected-main commit passes the
required post-merge Foundation and Windows verification. Those final identities
and run numbers will be recorded here and on the execution board.

## Residual boundary

This implementation proves product wiring and fail-closed effect truth. It
grants no production endpoint, credential, connector, observation, effect,
canary, cutover, rollback, recutover, or decommission authority. The first
production action remains exclusively a fresh `CANARY-001` ceremony for one
fully eligible migrated case under a separate explicit one-action owner grant.
