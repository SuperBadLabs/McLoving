# EXT-002 security and closure review

Date: 2026-08-18

Verdict: EXACT-HEAD MARIO REHEARSAL PASSES; fresh exact-head review, protected
CI, merge, and protected-main verification remain open.

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

- Exact implementation and Mario-rehearsal head:
  `6f737080cf7546e1982fd45c2283663d941f4448`.
- Core runtime implementation head
  `edc392524a5c229c3e5d2a1462b14d45d4611f27` supplies the product behavior.
  Closure head `6f73708` also makes the Mario harness wait for the pinned
  PostgreSQL container's final PID 1 server, rather than accepting the
  temporary initialization server immediately before its intentional restart,
  and adds the harness to the protected Foundation Bash syntax gate.
- Deployment mapping admission rejects an unknown mapping, a floating or stale
  digest, a duplicate catalog entry, a substituted catalog file, partial
  configuration, and plan/catalog drift at validation, planning, persistence,
  build admission, and shipped-controller startup.
- The real-PostgreSQL harness passed 43 controller-store tests and 17
  execution-spine tests, plus the deployable controller, admitted differential,
  and shipped mTLS agent tests. The runtime cases cover successful and
  ambiguous/reconciled outcomes, pre-dispatch executable substitution,
  post-dispatch timeout, signed connector/observer/shadow response
  substitution, cancellation after dispatch, crash after dispatch, lease loss,
  controller restart, retry denial, durable outcome/observation/reconciliation/
  shadow evidence, and exactly one physical fixture dispatch.
- The post-action observer request must bind the exact frozen pre-action
  receipt before dispatch. A mismatched predecessor produces a terminal
  abandoned effect with zero receipt slots and zero connector dispatches.
- Explicit reconciliation may fill only missing immutable receipt slots for an
  exact fenced effect while the attempt has no executable lease. The regression
  rejects a substituted restore epoch, completes outcome, observation, and
  shadow receipts without restoring dispatch authority, and permits terminal
  publication only after confirmation of the complete join.
- Pipeline IR's `sha256:<64 lowercase hex>` downstream-control reference is
  compared to the shipped connector receipt's raw 64-character digest at an
  explicit canonical boundary. The contained fixture now uses the shipped
  receipt format, so it can no longer mask a format mismatch.
- A connector intent's protected-reference schema is closed and string-only at
  admission. Outcome validation projects each protected reference as its
  required taint/name to opaque provider reference, rejecting missing, extra,
  duplicate-taint, malformed, or wrong-type references before downstream work.
- The positive path holds the shadow reply open and observes the attempt still
  `running` after outcome and independent observation are durable. Only the
  durable signed shadow receipt permits terminal publication.
- Redacted store and HTTP projections expose every fence of the exact attempt,
  including historical restore fences, plus the payload digest and four
  evidence digests. They omit frozen values, request bodies, receipt bodies,
  protected outputs, and credentials.

## Earlier-candidate Mario effect-free rehearsal

Mario ran the complete 14-test real execution spine at the then-current
candidate using real PostgreSQL. Compilation occurred before runtime. Runtime used a
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

This retained receipt predates implementation head `edc3925` and is not used as
exact-head closure evidence.

## Exact-head Mario effect-free rehearsal

The first authorized run of reviewed head `200ed5f` retained a truthful
`complete:false` receipt before test launch. Its owner-only directory is
`/home/srikanth/.local/share/mcloving/ext002-runs/ext002-20260818T141333Z-8541cc5f`
and its result SHA-256 is
`c3795c49428fc3ec54f2e581a114b9cd5f756148dcedc7a6b8a62a50291e7ef7`.
The build completed, the temporary PostgreSQL initialization server answered
`pg_isready`, and the harness's immediate final probe then landed during the
pinned image's intentional transition to the final server. Cleanup removed the
exact disposable container and internal network; no test or effect ran.

An unchanged Bash-traced retry at `200ed5f` completed all 17 tests and localized
that host-harness race. It is retained as diagnostic evidence only. Closure
head `6f737080cf7546e1982fd45c2283663d941f4448` requires both final PID 1
`postgres` identity and readiness, and its fresh bundle-backed Mario run passed:

- Owner-only evidence directory:
  `/home/srikanth/.local/share/mcloving/ext002-runs/ext002-20260818T172613Z-2af4ab8f`
- Result receipt SHA-256:
  `733f870961474d0be581d9aba46b244a0fc767b4c680bd4aac96c115d39163ac`
- Evidence checksum file SHA-256:
  `c170cdbaae81aea781f6c46721e64c30ef2ee6e966c6f5f7293bb72b829470d7`
- Fixture SHA-256:
  `b30a40056d682cfdf6ff259a690431103bceb96ec3d54c354a9f6445ccafb0a6`
- Test binary SHA-256:
  `a00843c2b348542309d183b2245ebe2432f52389f5f074995c56543edf692250`

Independent verification recomputed every manifest entry, observed exactly 17
passing real-PostgreSQL spine tests, confirmed the exact source head and clean
checkout, and confirmed the internal network and exact PostgreSQL container
were absent after cleanup. The directory is mode `0700`; every retained file is
mode `0600`. Production endpoint, credential, effect, canary, and cutover
authority are all explicitly false.

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
