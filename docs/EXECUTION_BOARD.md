# McLoving execution board

Updated: 2026-09-10

Status values: `PENDING`, `ACTIVE`, `BLOCKED`, `DONE`, `DEFERRED`.

Execution classes: `SERIAL`, `BATCH`, `PARALLEL`.

## Current state and dispatch queue

**Product parity (2026-09-10 re-orientation): make McLoving something a Jenkins
team can switch to, measured by one dogfood pipeline.**

On 2026-09-10 a code-level audit compared shipped behaviour against Jenkins and
the owner re-oriented the board: daily-workflow parity first, native YAML as
the product, compile-only Jenkinsfile widening as a migration aid, the
migration-authority ceremony and web-interface chains `DEFERRED` until a real
team runs real pipelines, and the owner's GitHub repositories plus McLoving
itself as first users. The parity chain and its distance metric are in the
"Parity tickets" section; ADR 0016 records the decision and ADR 0006 carries
the GROOVY-001 answer. The Jenkins M1 milestone below closed on 2026-09-10 and
its receipts stand; they remain bounded evidence, not general Declarative
support. McLoving is not release-ready and has no production authority.

Run the board and closure verifiers for live totals rather than copying counts
from prose.

| Slot | Current ticket | Status | Dependency-critical successors |
|---:|---|---|---|
| 1 | `PAR-000` | ACTIVE | Re-orient the board; the parity chain `PAR-010` onward follows in order |

### Historical: Jenkins compatibility M1 notes (2026-09-08 to 2026-09-10)

M1 success meant at least ten supported-input fixtures plus explicit rejection
fixtures, with zero unexplained execution differences. The formal M1 rows below
own acceptance. Authored-fixture evidence and the original 228-source corpus
must have separate denominators; old evidence remains immutable.

Before starting implementation, refresh protected-main custody, open PRs,
alerts, workflow outcomes and protection settings, then run the full Foundation
gate. The September 6 thaw is historical evidence; before starting on any new head, observe successful Foundation and Windows Agent runs for that exact head. The
Jenkins oracle host/profile and contained test environment must also be verified
before the paired campaign. `JCOMP-001`, `JCOMP-002` and `JCOMP-002A` are `DONE`; `JCOMP-002B` and `AGENT-007` are `DONE`, and `JCOMP-002C` is `DONE`; `JCOMP-003` has earned its separately reviewed contained execution claim; `EXEC-005` is ACTIVE on bounded cache and input product-path slices; all five helper gates remain required for its closure.
The contract and authored expectations are in
`docs/architecture/JENKINS_SEQUENTIAL_DECLARATIVE_V1.md` and
`compat/jenkins-worker/fixtures/sequential-v1/manifest.json`. Their Foundation
authoring gate grants no compiler admission or execution-equivalence claim.

The September 9 UTC earned closure observation after PR #130 is 115 tickets,
90 `DONE`, and 25 remaining, with 35 receipts, 34 attributed reviews and the
unchanged 37-item historical debt. Exact merge and post-merge checks are
recorded in the JCOMP-002A review receipt.

The original runtime inspection found two prerequisites beyond compilation:
multiple-step admission and build-workspace continuity. JCOMP-002A and JCOMP-002B
have now earned those contained implementation closures, and AGENT-007 has
closed the corrected lease-survival behavior. A subsequent original-corpus capture retained six unverified compiler/admission diagnostic disagreements. JCOMP-002C earned its bounded correction on protected PR #135 and successful exact-main verification; JCOMP-003 subsequently earned fresh contained paired and corpus evidence on its reviewed freeze; compiler acceptance alone
cannot establish runnable support. Workspace lifecycle/non-collision is bounded by
JCOMP-002B; denial of sibling-workspace access by hostile same-UID workloads
remains SEC-005 and is not an M1 claim. CI-004 is now closed on verified PR #125
merge and post-merge evidence; see its receipt below.

EXEC-005 implements bounded Linux cache publish/read and adds operator-mapped
public input capture through the submitted-job path, with private response
verification and public receipt identities. Input verification is tracked in the
ACTIVE review; implementation alone earns no product or publication gate. This
is partial implementation, not five-helper closure, general cache restoration
or downstream input-value use. SCM acquisition, dependency resolution and
dynamic provisioning remain unwired. All production cases remain ineligible
for CANARY-001 and CUTOVER-001 pending their implementation and downstream
qualification gates. The initial no-caller inspection in the acceptance row
is historical; it must not erase remaining helper gates. The bounded contracts
are `docs/architecture/CACHE_PRODUCT_PATH_V1.md` and
`docs/architecture/INPUT_PRODUCT_PATH_V1.md`.

The standalone source-helper custody prerequisite supports a pinned acquisition
configuration and execution from a sealed caller image while preserving the
native source boundary. It adds no submitted-job source path. Source-only
profile selection, nested-process cancellation, retained-tree verification
and bounded retention ownership remain prerequisites to that integration;
see `docs/architecture/SOURCE_ACQUISITION_V1.md`.

After M1, the production-readiness track is `EXEC-005` -> `SECRET-002` ->
`SEC-005` -> `CASE-001`, followed by the existing release, deployment,
recertification, and separately authorized canary gates. `EXEC-005` now also
depends on `JCOMP-003` so later runtime work cannot overtake this milestone.
`CASE-001` still requires an owner-designated real enabled effectful Jenkins
job; M1 neither selects that job nor closes its certification gate.

`GROOVY-001` and `HYG-003` remain pending parallel lanes outside
the selected slot. M1 retains the compile-only architecture of ADR 0006 and
does not port an interpreter. Serialize any compatibility-plane decision that
changes M1's contract or threat boundary before affected implementation; a
port requires a separate ticket. Coordinate hygiene work before concurrent
edits to shared board, handoff, or verifier files.

The chief owns integration, sequencing, board accuracy, and claim approval.
Use independent subagents for compiler/admission inspection and differential
fixture design. After verifying HeMan's installed Qwen model and connectivity,
use it for cited corpus classification and fixture drafts, reviewed by an agent.
Model-generated analysis is never Jenkins oracle evidence. HeMan's local Qwen service was verified and used for reviewed fixture/corpus
drafts during September 8 preparation; refresh connectivity before reuse.
Qwen remains optional support, not a milestone dependency.

## Working rules

- Keep a ticket `ACTIVE` until its required exact-head checks, independent
  review, protected merge, and post-merge Foundation and native Windows
  verification have completed. Record the observed merge SHA and run receipts
  in a subsequent closure update before marking it `DONE` or adding closure
  attribution. A passing candidate does not satisfy downstream dependencies.

- Classify every remaining ticket as `SERIAL`, `BATCH`, or `PARALLEL` in the
  remaining execution topology. `SERIAL` tickets begin only after the named
  predecessor is merged and verified on protected `main`; `BATCH` tickets use
  ordered commits in one pull request because they share one bounded contract;
  `PARALLEL` tickets use separate worktrees, branches, pull requests, generated
  artifacts, and evidence directories.
- Keep at most three mutable implementation pull requests active. An isolated
  read-only or destructive-host evidence campaign does not consume a slot only
  when it cannot mutate repository, schema, package, fixture, or sealed evidence
  owned by an active pull request.
- Prefer batches of two to four small, tightly coupled tickets. Compiler,
  persistence, identity, authorization, secret, connector, observer, release,
  cutover, rollback, decommissioning, and other authority-bearing boundaries
  are one ticket per pull request unless this board explicitly classifies the
  tickets as `BATCH`.
- A ticket that certifies, measures, or signs the runtime depends on every
  ticket that changes the runtime. Certification evidence, capacity envelopes,
  and release signatures all describe the executor that existed when they were
  produced; if that executor is replaced afterwards, nothing in the graph
  regenerates them and the campaign carries evidence for something that no
  longer exists. Adding the dependency is always preferable to requiring a
  rerun, because a rerun depends on someone remembering.
- The converse — the late-correction rule — binds every correction that arrives
  after the evidence. Several tickets legitimately complete after `REL-003`,
  `DEPLOY-002`, `CASE-002`, and the production canary — security review,
  capacity measurement, war and disaster campaigns, recertification, rollback
  and re-cutover drills — and each may surface a correction to the runtime,
  deployment configuration, mappings, or packaged artifacts. Whatever ticket
  hosts such a correction, the correction is complete only when every receipt
  it invalidated is regenerated: the corrected executables and packages
  re-signed under the `REL-003` ceremony, the `DEPLOY-002` revalidation —
  install, upgrade, rollback, and the full `SEC-005` denial-probe rerun —
  re-passed against the corrected signed release, and whatever case,
  ceremony-fixture, canary, or capacity evidence the change invalidated re-run
  and re-sealed. The hosting ticket may not close, and `REL-002` may not join,
  on evidence that describes the pre-correction system. A dependency edge
  cannot express this because the invalidated tickets are already `DONE`, so
  the obligation binds the correcting ticket's own closure.
- If two nominally parallel tickets touch the same schema, protocol, policy,
  generated fixture, migration, package, or threat-model boundary, serialize
  them before implementation instead of resolving integration conflicts after
  review.
- Use one `codex/` branch and pull request per batch or standalone ticket.
- Keep one coherent commit per ticket where practical.
- Address every actionable Copilot review thread before merge.
- The six granular Foundation contexts plus the `Foundation` and `Windows`
  aggregates, strict exact-head synchronization, independent review of every
  merge-authority workflow, classifier, verifier, and oracle change, review-
  thread resolution, exact commit, clean
  worktree, admin enforcement, conversation resolution, and a fresh
  protection-rule readback must be verified before protected-main merge. All
  eight required contexts must be reported by GitHub Actions application id
  `15368`; that binding authenticates the reporting app, not the candidate-
  controlled workflow definition.
- No implementation ticket may become `DONE` until
  `docs/threat-model/README.md` is reviewed for all affected boundaries,
  including authentication, authorization, secrets, protocol,
  compiler/execution, persistence, connector, agent pool, supply chain,
  deployment, migration, and decommissioning, and updated with the affected
  threats, mitigations, verification evidence, and residual risks; unchanged
  sections require an explicit reviewed no-change receipt.
- Independently of ticket status, before the first `CANARY-001` production
  authority/effect grant, each `CUTOVER-001` or `RECUTOVER-001` authoritative
  cutover, every `ROLLBACK-001` authority reversal, and every `DECOM-001`
  irreversible Jenkins decommissioning action, review the current threat model
  for all affected boundaries and bind its content digest, mitigations,
  verification evidence, residual-risk acceptance, reviewers, and timestamp to
  the signed transition receipt. Any relevant implementation/configuration,
  threat, mitigation, or evidence change invalidates the receipt and blocks the
  action until re-review; post-action review cannot satisfy this gate.
- Action ownership is explicit: `SHADOW-001` owns effect-free paired execution,
  `CANARY-001` owns every graduated production effect grant, `CUTOVER-001` owns
  the first authoritative cutover transaction, `ROLLBACK-001` owns the rehearsal
  authority reversal, `RECUTOVER-001` owns the fresh post-rehearsal authority
  transfer, and `DECOM-001` owns each irreversible Jenkins retirement.
  `MIG-008` and `MIG-009` are receipt-verification closure gates only; neither
  may grant authority or retroactively satisfy a pre-action gate.
- Every Working rule that names a `CUTOVER-001` precondition, freeze,
  quiescence, transfer, or receipt also applies independently to
  `RECUTOVER-001` against fresh current source, target, state, history, runtime,
  client, trigger, effect, observer, threat-model, and inventory receipts. The
  first cutover's receipt cannot authorize the final transfer.
- After merge, select the next unblocked batch without waiting for ceremony.
- No job may enter `CANARY-001` effect-authoritative canary or `CUTOVER-001`
  authoritative cutover while an inventoried external reader still consumes
  that job's effect-free or stale Jenkins-side truth or an inventoried
  administrative writer still targets only that job's Jenkins definition,
  enclosing folder/controller configuration, queue, live execution, approval,
  or input state. Each affected caller must first pass `CONSUMER-001` or
  `ADMIN-001`, respectively, or have explicit owner-approved retirement, with
  tested caller cutover and rollback evidence.
- Every reference to an administrative writer in `MIG-000`, `ADMIN-001`,
  canary/cutover gates, and decommissioning includes every effective Jenkins
  write path regardless of authentication mode: named clients, service
  identities, anonymous/public principals, unauthenticated endpoints, legacy
  tokens, seed execution, CLI, and direct/plugin APIs. Inventory caller or
  observed source, endpoint/action, authorization behavior, scope, owner, and
  use; migrate it to an authenticated least-authority McLoving path or obtain
  explicit owner-approved retirement. Prove anonymous/unauthenticated write
  denial in the replacement and zero residual Jenkins writes.
- Administrative writers include operational run-control paths, not only
  configuration writers: build trigger/replay/retry, queue cancel/reorder,
  running-build stop/terminate/kill, input or protected-environment approval,
  submitted parameter/value, and resume/pause actions. `MIG-000` must inventory
  every such effective path and its observed caller or source; `ADMIN-001` must
  migrate its semantics, authorization, idempotency/fencing, audit, failure,
  cutover, and rollback behavior or obtain explicit owner-approved retirement.
  During every `SHADOW-001` or `CANARY-001` paired execution, only the
  authoritative control endpoint may accept the external operation. `ADMIN-001`
  must atomically bind
  that accepted operation to its mapped execution and logical event cursor and
  emit one immutable signed replay receipt containing operation type, canonical
  caller/decision identity, authorization decision, idempotency/fence, sequence
  and timing, and either canonical public submitted values or
  confidentiality-safe tainted secret references/digests without raw secret
  material. A deny-authority replay adapter injects that receipt exactly once at
  the corresponding shadow state-machine point; it carries no principal,
  credential, connector, scheduling, or external run-control authority, and the
  shadow cannot accept the original operation directly. Compare receipt
  consumption, approval/input/cancel/retry behavior, audit provenance, terminal
  outcome, and resulting effect intent. If secret-dependent semantics cannot be
  reproduced from an approved protected reference or normalized surrogate
  without disclosing the secret, the job is ineligible. Before `CUTOVER-001` or
  `DECOM-001`, also prove the replacement operation affects the
  authoritative execution exactly once, a non-authoritative runner accepts only
  the bound replay receipt, and no residual Jenkins operational write remains.
- `AUTHZ-001` must represent the effective Jenkins permission matrix with
  versioned action-scoped custom roles or grants when the built-in McLoving role
  lattice couples independent actions. Preserve separate view, trigger, cancel,
  configure, approve/input, retry/replay, artifact/test/log, audit, and
  administrative permissions at the narrowest folder/job/project scope; deny
  broadening a principal merely to fit an existing role. Prove grant creation,
  update, revocation, group/lifecycle changes, conflict resolution, stale-token
  denial, positive/negative action decisions, and rollback. A policy that
  cannot be represented exactly or more restrictively with owner approval is
  explicitly ineligible for canary/cutover, never silently widened.
- The `CUTOVER-001` atomic cutover freeze must re-read and match each deployed
  replacement trigger's implementation digest in addition to its class and
  configuration, and each deployed Multibranch Pipeline or Organization Folder
  discovery implementation's binary or image digest, protocol/version, live
  configuration digest, provider/organization/repository scope, branch and PR
  trust/filter strategy, Jenkinsfile selection policy, child identity policy,
  and orphan policy. Any change invalidates prior proof and requires
  recertification before authoritative cutover.
- The `CANARY-001` pre-effect and `CUTOVER-001` cutover freezes, and every
  post-cutover build admission, scheduling decision, and effect grant, must
  re-read and match the packaged certified McLoving controller/release identity
  plus every separately deployed runtime implementation used by the job,
  including SCM acquisition, trigger, dependency resolver, cache service,
  secret provider adapter, connector, independent destination observer, and
  agent components: exact binary/image or release-component digest,
  protocol/version, deployment/service identity, endpoint, live configuration
  digest, and policy digest. Matching logical requests, resolved outputs, or
  cache contents without the certified implementation identities is
  insufficient. Any runtime drift atomically quarantines the job, pauses new
  trigger admission and scheduling, withholds all effect grants, and reconciles
  already accepted work until the exact changed runtime completes every affected
  `DIFF-001`, `DIFF-002`, or `DIFF-003` scenario, a refreshed `MIG-006`
  aggregate closure, the `CANARY-001` canary gate, and a new package receipt;
  prior authority is never grandfathered across an upgrade.
- Every independently observed destination-state or reconciliation receipt used
  by `DIFF-003`, the `MIG-006` aggregate closure, `CANARY-001`, `CUTOVER-001`,
  `RECUTOVER-001`, or `ROLLBACK-001` must bind an
  observer that is separate from the effectful connector and runner. `OBS-001`
  owns its implementation,
  deployment, identity and grant separation, certification, and receipt
  protocol; no dependent differential, canary, cutover, or rollback gate may
  pass until that ticket is `DONE`. Inventory and certify its exact
  implementation/image digest, protocol/version, deployment and operator trust
  identity, endpoint/account/resource scope, live configuration/policy digest,
  read-only credential or grant identity/version/scope, query and freshness
  cursor, response digest/signature, and observation timestamp. Prove through
  permission-negative tests that it cannot mutate the destination and that the
  connector cannot control, impersonate, configure, credential, or fabricate
  the observer; shared write credentials, process authority, or administrative
  trust is ineligible. Before each production effect, at `CUTOVER-001` cutover,
  and at `ROLLBACK-001` rollback, re-read and match all observer identities and
  configuration,
  verify a fresh independent observation, and recertify on any drift before the
  receipt may authorize another effect or authority transition.
- Every production external effect, regardless of how `MIG-004` classifies or
  maps the originating Jenkins step, must execute through an exact certified
  `EXT-001` out-of-process connector protocol. Native processes and reusable
  components may perform only contained workspace/result transformations and
  receive no production write-capable network path, destination credential,
  deployment grant, or external-effect authority. A direct native/component
  effect mapping is ineligible and must be remapped to a connector or rejected
  fail-closed. Therefore every reference in this board to a "connector-backed"
  effect or job includes every authoritative external effect; `DIFF-003` must
  certify the connector boundary and `MIG-006` must verify that exact evidence,
  while `CANARY-001`/`CUTOVER-001` may grant or transfer no such authority until
  `EXT-001` is `DONE` for the exact connector action,
  identity, implementation, permission, fencing, deduplication, and
  reconciliation contract.
- Every live external read whose response can influence pipeline control flow,
  effect arguments, result, or published output—including feature flags,
  deployment metadata, databases, configuration/secret stores, and arbitrary
  remote APIs—requires a typed `INPUT-001` contract. `MIG-000` must inventory
  endpoint/data-source identity, implementation/protocol/schema version,
  authenticated read-only caller/grant, query and scope, consistency/freshness
  cursor, response provenance/signature, confidentiality/taint, size/rate
  bounds, owner, and failure/default policy. `MIG-002` must define bounded
  success, branch, stale, missing, malformed, oversized, unauthorized,
  substituted, outage, replay, and secret-marker fixtures; `DIFF-003` must use
  only exact fixture-local implementations and compare response-consumption and
  non-disclosure. `CANARY-001` and `CUTOVER-001` must keep the job ineligible until
  `INPUT-001` is `DONE`. During every `SHADOW-001` or `CANARY-001` comparison, the
  authorized adapter must capture one bounded response at one exact
  cursor/snapshot, bind its canonical value digest and non-secret provenance to
  a receipt, and supply that identical response and cursor receipt to both
  runners under the declared confidentiality/taint policy; neither runner may
  independently sample the mutable production source for a compared decision.
  Compare the response-consumption trace, resulting control flow, effect intent,
  result, and published output. Then freeze the exact deployed adapter,
  endpoint, schema, grant, policy, and freshness/provenance contract before
  every `CANARY-001` effect, `CUTOVER-001` authority transfer, or `ROLLBACK-001`
  authority reversal. A read that cannot be safely captured and identically
  supplied, or that is untyped, mutable,
  unverifiable, overprivileged, or confidentiality-unsafe, is fail-closed and
  unsupported.
- Every job that relies on Jenkins cloud agents, Kubernetes pod templates,
  EC2/VM/container provisioning, or another dynamically created execution
  target requires `PROV-001`. `MIG-000` must inventory provider/account/region,
  exact provisioner implementation/protocol, effective template and inheritance,
  image/AMI and bootstrap/toolchain digests, platform/capabilities/trust pool,
  network/volume/workspace/cache policy, identity/IAM grants, labels, quotas,
  lifecycle/retention, owner, and cleanup/rollback contract. `MIG-002` and
  `DIFF-003` must certify exact contained fixtures plus substitution, exhaustion,
  interruption, orphan, stale-instance, and cleanup cases. `CANARY-001` and
  `CUTOVER-001` must keep every dependent job ineligible until `PROV-001` is `DONE`
  and freeze the exact deployed provisioner, template, image, policy, identity,
  and health/configuration digests before scheduling or authority transfer.
  Static fixture-agent proof cannot certify a live dynamic provisioner;
  unowned or mutable provisioning is fail-closed and unsupported.
- During every shadow, dual-run, canary, cutover, and rollback window, exactly
  one fenced runner may possess a production write-capable connector path or
  destination credential. The other runner must emit a canonical signed
  dry-run request/intent into an isolated no-authority comparison sink. Before
  any production connector submission, buffer the authoritative runner's
  canonical signed intent as well, bind both intents to the same input receipts,
  execution identities, certified mapping and release, and require exact
  agreement on action, target, preconditions, all effect arguments, and
  idempotency/fencing identity. Only a successful comparison receipt may issue
  the one narrowly scoped connector grant and release the authoritative intent;
  missing, late, ambiguous, or mismatched intent comparison freezes the grant
  and produces zero production request. After the authoritative connector
  returns, `EXT-001` must emit one bounded signed outcome receipt binding the
  compared request, connector/destination identity, response schema and status,
  canonical public return values, confidentiality-safe tainted secret
  references/digests, external identifiers, retry/ambiguity truth, and
  independently observed destination-state receipt. A deny-authority outcome
  replay adapter validates the certified mapping and injects that receipt
  exactly once as the shadow step result before either execution continues to
  downstream control flow; it has no production endpoint, credential, connector
  grant, or effect authority. Compare receipt consumption, later branches,
  outputs, and subsequent intents. The shadow may never submit to the
  production effect endpoint, even with a shared idempotency key, because
  request ordering could commit the wrong payload. Idempotency is required only
  for retries and reconciliation by the single authoritative runner. Any
  external system or migration design that cannot buffer and compare before
  submission, cannot safely replay the authoritative outcome without secret
  disclosure, or requires both runners to submit production writes, is
  ineligible until redesigned; request acceptance, deduplication, or later
  reconciliation cannot retroactively satisfy the effect-free-shadow gate.
- Every effective Jenkins node/agent property consumed by an in-scope job is
  migration input, including node-scoped environment variables, tool-location
  overrides, labels, custom workspace/root paths, usage mode, retention,
  launcher/remoting settings, and plugin-defined properties. `MIG-000` must
  inventory the property source, resolution/override order, effective value or
  protected redaction digest, node/label scope, owner, and configuration digest;
  `MIG-002` must bind it into the corpus profile and equivalence cases; and
  `DIFF-001` must certify the resulting environment, tool identity, scheduling,
  and authority behavior. The `CANARY-001` pre-effect and `CUTOVER-001` atomic cutover
  freezes must re-read the live effective-property set and exact configuration
  digest for every eligible agent target. Missing, changed, newly effective, or
  secret-bearing unredacted properties invalidate certification and block
  authority transfer until recertified.
- The Jenkins-provided built-in environment namespace is explicit migration
  input, not ambient process state. `MIG-000` must inventory every referenced
  built-in variable—including `BUILD_NUMBER`, `BUILD_ID`, `BUILD_TAG`,
  `BUILD_URL`, `JOB_NAME`, `JOB_BASE_NAME`, `JENKINS_URL`, `NODE_NAME`,
  `NODE_LABELS`, `EXECUTOR_NUMBER`, and `WORKSPACE`—with its exact
  Jenkins-core/plugin-profile derivation, scope and evaluation phase, type,
  confidentiality, stability, downstream semantic use, and owner. `MIG-002`
  must define single- and multi-build, multi-job/folder, rename, parallel-agent,
  restart, forward-handoff, cutover, and rollback cases. `MIG-003` emits typed
  references rather than host environment lookups, and `MIG-004` owns a
  versioned mapping that classifies each value as exact-equality,
  deterministic translation/normalization, or unsupported: preserve transferred
  build numbers and canonical job identity, bind URL values to the certified
  route/consumer mapping, bind node values to the certified agent mapping, and
  normalize workspace roots while preserving relative-path and isolation truth.
  `DIFF-001` must inject the receipt-bound per-run values into both exact-profile
  executions and compare their consumption, shell/process environments,
  normalized outputs, artifact tags/links/paths, and effect arguments across
  those cases. `CANARY-001` and `CUTOVER-001` must derive and freeze each live per-run
  value from the certified identity, history, route, agent, and workspace
  receipts before comparison or authority transfer. An unknown, ambient,
  confidentiality-unsafe, or semantically unmapped built-in variable is
  fail-closed and makes the job ineligible.
- Every in-scope job must also bind its complete enclosing regular-folder chain,
  not only Organization Folder or job configuration. `MIG-000` must inventory
  each ancestor's identity, configuration digest, property source and
  resolution order, including inherited environment, tools, shared libraries,
  credential references without secret material, authorization, and
  plugin-defined properties. `MIG-002`, `DIFF-001`, and `DIFF-002` must bind and certify the
  resulting effective values and precedence. The `CANARY-001` pre-effect and
  `CUTOVER-001` cutover freezes must re-read every ancestor and the effective
  property-set digest; any changed, inserted, removed, newly effective, or
  unredacted secret-bearing property invalidates certification.
- A completed `MIG-000` export is a versioned inventory epoch, not permanent
  proof of population completeness. Before every `CANARY-001` production effect
  grant, `CUTOVER-001` authority transfer, `ROLLBACK-001` authority reversal, or
  `DECOM-001` Jenkins decommissioning action, quiesce mutations to the affected
  scope and reconcile a fresh live
  export against the latest signed epoch. Reconcile all jobs and parent chains,
  triggers and pending deliveries, readers, configuration and run-control
  writers, identities/authorization, agents/properties, runtime dependencies,
  state, retention/holds, and external effects; bind the live export and
  population-delta digests into the transition receipt. A new, changed,
  deleted, or previously unobserved object or caller must complete its required
  inventory, classification, migration, certification, cutover/retirement, and
  rollback gates before the transition; absence from the old inventory never
  implies eligibility. Decommissioning requires zero unreconciled objects or
  clients across the entire retiring scope and endpoint.
- Jobs that read wall-clock or calendar time through conditions, shell/process
  commands, language APIs, timestamps, or plugins must inventory each clock
  source, timezone, locale calendar, tzdata/runtime version, and allowed skew.
  `MIG-002` must define deterministic controlled-clock cases for relevant
  boundaries, including DST gaps/folds, date rollover, leap-day, skew, and
  restart; `DIFF-001` must run both oracles against the same receipt-bound virtual
  clock and compare all time-derived arguments, state, logs, artifacts, and
  outcomes. During every `SHADOW-001` or `CANARY-001` comparison, capture one
  receipt-bound wall-clock instant and, where the job observes elapsed time, one
  bounded clock stream; supply the identical values and consumption contract to
  both runners and compare their clock-consumption traces and all time-derived
  semantics. Independently sampled live clocks are not equivalent. `CANARY-001`
  and `CUTOVER-001` must freeze the production clock injection, policy, timezone,
  tzdata/runtime, and synchronization configuration through cutover and the
  rollback window. Any uncontrolled time dependency, drift, or unsupported
  clock injection is fail-closed and ineligible rather than assumed equivalent.
- For every Jenkins schedule using `H`, ranges/steps containing `H`, or another
  identity-derived slot, `MIG-000` must inventory the exact Jenkins core/plugin
  hash algorithm/version, canonical full job/folder identity and other hash
  inputs, seed/salt identity without exposing protected material, timezone,
  calendar, original expression, and resolved firing slots. `TRIG-001` must
  reproduce and differentially prove the exact slots across restart, controller
  migration, cutover, rollback, job/folder rename, clone, daylight-saving
  transition, and hash-boundary cases; a new stable-but-different hash is not
  equivalent. `CANARY-001` and `CUTOVER-001` freeze all hash inputs, implementation,
  configuration, and resolved-slot digests and reconcile the schedule watermark
  before authority transfer. Any unresolvable or drifting hashed schedule is
  ineligible until explicitly remapped with owner-approved timing delta.
- Jobs whose control flow, effect arguments, identifiers, retry timing, or
  outputs consume randomness or entropy—including shell RNGs, random devices,
  UUID APIs, language runtimes, and plugins—must inventory each source,
  algorithm/provider/runtime identity, consumption point, semantic use, and
  security classification. `MIG-002` must define bounded deterministic seed or
  byte-stream fixtures that force every relevant branch/outcome; `DIFF-001` must
  give both deny-authority oracles the same receipt-bound test stream, compare
  consumption traces and semantic outputs, and repeat seeds to prove
  determinism. Non-semantic random identifiers require an explicit normalization
  rule that preserves uniqueness/correlation truth. Production security
  randomness must remain cryptographically strong and unseeded by test data;
  `CANARY-001` and `CUTOVER-001` freeze its exact provider/runtime, policy, and health
  configuration and audit the resulting decision/identifier provenance without
  recording secret entropy. During every `SHADOW-001` or `CANARY-001`
  comparison, every semantically relevant non-security entropy source must be one
  receipt-bound input stream whose exact bytes and consumption contract are
  supplied identically to both runners and whose consumption traces and semantic
  outputs are compared; independently generated streams or merely identical
  provider policies are not equivalent. `CUTOVER-001` freezes that certified
  injection and mapping through cutover, and `ROLLBACK-001` preserves it through
  the rollback window. A job is
  ineligible if the shared stream cannot be injected safely, or if
  security-classified entropy affects compared control flow, effect arguments,
  retry timing, identifiers, or outputs beyond an approved normalization that
  does not disclose or seed the secret entropy. Any semantically relevant source
  that cannot be controlled in differential fixtures or mapped to this certified
  production comparison contract is fail-closed and unsupported.
- Jenkins decommissioning must quiesce before the final export: pause and
  verify all trigger ingress and administrative writes, freeze new scheduling
  and external-effect authority, drain or explicitly reconcile every accepted
  but not yet materialized trigger delivery, delayed/retry/dead-letter delivery,
  queued or running build, lease, lock, retry, and uncertain effect, and prove
  zero active work, unaccounted trigger input, or ambiguous destination state.
  Only then capture and verify the final configuration/build/artifact/audit
  export, revoke remaining read and write authority, credentials, and network
  paths, and retire compute and secrets.
- `MIG-000` must inventory every Jenkins retention schedule and active legal
  hold covering configuration, build history, console logs, tests, artifacts,
  workspaces/state, and audit evidence, including record scope, policy digest,
  owner/custodian, expiry, and hold/release authority. Before `DECOM-001` retires
  any affected scope, reconcile every protected record against the final
  export, import it with equivalent or stronger `OPS-002` retention and hold
  metadata plus immutable provenance, prove deletion remains blocked, and
  verify indexed retrieval and backup restore. Missing records, weaker policy,
  untested restore, or an unapproved hold release blocks retirement.
- Every `CUTOVER-001` per-job authoritative cutover must quiesce first, including
  stateless and effect-free jobs:
  pause and verify scheduled, webhook, upstream, remote, manual, and API build
  ingress plus administrative writers for the job and affected enclosing scope;
  freeze new scheduling and effect-authority transfers; drain or reconcile
  every accepted but not yet materialized trigger delivery, delivery retry or
  dead letter, queued/running build, build retry, issued grant, lease, lock, and
  uncertain effect; and prove zero active source work or authority. Bind and
  transfer each trigger's delivery cursor, event/deduplication ledger, pending
  delivery set, retry/dead-letter state, and schedule timezone/calendar
  watermark under the exact `TRIG-001` implementation and configuration
  digests. For stateful jobs, only then re-export, transform, import, and verify
  state. Atomically import that trigger state and switch trigger, reader,
  writer, and effect authority afterward; failure restores the frozen Jenkins
  authorities and original trigger state without skipped or duplicated
  deliveries, builds, state, or effects.
- Every later `ROLLBACK-001` rollback repeats that entire protocol with McLoving
  as the relinquishing side and Jenkins as the gaining side. Quiesce both ingress
  and authority transitions; export the current McLoving delivery cursor,
  event/deduplication ledger, pending deliveries, retry/dead-letter state, and
  schedule timezone/calendar watermark; transform and import them through the
  exact certified reverse mapping; verify the destination ledger and pending
  set; then atomically fence McLoving and resume Jenkins. A pre-cutover Jenkins
  snapshot or generic `TRIG-001` rehearsal is insufficient. Any untransferable,
  stale, missing, duplicated, or ambiguous delivery keeps both sides frozen
  until reconciled without skipped or duplicated deliveries, builds, or effects.
- A job using a shared lock, throttle, or resource cohort cannot enter
  `CANARY-001` effect-authoritative canary or `CUTOVER-001` cutover while any cohort
  member can execute under an independent platform-local lock. During dual-run
  and rollback, both Jenkins and McLoving must acquire the same external
  lease/fence identity through one tested coordinator with atomic ownership,
  expiry, cancellation, restart, partition, stale-holder, and rollback proof;
  otherwise quiesce and migrate the entire cohort atomically. Reconciliation
  must prove one holder and one effect authority for every transition.
- Jobs connected by previous/last-result, upstream/downstream build identity,
  cross-job artifact, retained-workspace, or other cross-job state edges cannot
  enter `CANARY-001` effect-authoritative canary or `CUTOVER-001` cutover independently
  while producers and consumers would read different platform-local truth.
  Either provide one receipt-bound continuous bridge with a single authoritative
  source, monotonic sequence/build mapping, immutable content/provenance
  digests, exact deduplication, bounded lag, restart/replay, partition and
  failure-freeze, and bidirectional rollback proof, or quiesce, snapshot,
  transform, import, verify, and switch the entire dependency cohort atomically.
  Any stale, missing, divergent, or ambiguous edge blocks effects and cutover.
- A Multibranch Pipeline or Organization Folder cannot transfer parent
  `CANARY-001` or `CUTOVER-001` authority until the relinquishing discovery/indexing
  owner has paused webhook, periodic, and manual indexing ingress; drained or
  reconciled in-flight scans/events; exported the content-hashed discovery
  cursor, repository/branch/PR set, child identities/configurations, and orphan
  timers; and imported and verified them on the gaining side. Atomically fence
  exactly one discovery generation/owner before resuming ingress. Apply the
  same protocol in reverse and prove duplicate/reordered event, restart,
  partition, rollback, missing-child, duplicate-child, and orphan outcomes.
- After any migrated standalone Pipeline, SCM-backed Pipeline, Multibranch
  Pipeline, Organization Folder, or discovered child becomes authoritative in
  McLoving, every later source revision, newly discovered child, or changed
  Jenkinsfile, inline script, shared library, job, parent, or effective-property
  revision is created only as a quarantined candidate with no scheduling,
  trigger, credential/grant, connector, production network, or external-effect
  authority. The previously certified package may continue only for its exact
  frozen source revision and may not silently consume the later commit. A
  candidate may become runnable only by matching an existing `MIG-007` package
  whose complete exact
  source/profile/dependency/mapping/runtime and effective-input digests still
  match, or by completing its own current `MIG-002` through `MIG-007`
  classification, differential certification, authorization, state, and
  release gates. It remains quarantined and effect-free after `MIG-007` until
  that exact revision completes its own `SHADOW-001` production shadow and
  `CANARY-001` graduated canary against the current trigger, connector, observer,
  input,
  provisioner, runtime, authorization, rollback, and threat-model gates; parent
  authority or an earlier revision's canary cannot substitute. A separately
  submitted native strict-YAML definition may use
  the normal reviewed native admission path but cannot inherit migration
  certification from the parent. `DISC-001` must prove quarantine survives
  webhook/reindex races, duplicate/reordered events, restart, rollback,
  parent-policy drift, and simultaneous revision discovery; absence of a
  certified package is an explicit disabled/effect-free outcome, never implicit
  parent authorization.
- Before every `CANARY-001` effect-authoritative canary action, atomically re-read
  and match the complete live input and deployment set required by the
  `CUTOVER-001` cutover freeze against its certified receipt, including source and
  shared libraries, Jenkins/controller inputs, compiler/mapping/components,
  state transforms, release, platform/agent/toolchain, authorization, trigger
  and discovery, connector and SCM acquisition, credential mapping and
  rotation/revocation state, dependencies, cache, and destination identity.
  Issue the fenced effect grant only after that match succeeds. Any drift,
  missing identity, or partial comparison keeps the canary effect-free until
  recertification; post-effect detection cannot satisfy this gate.
- Before the first `CANARY-001` production effect grant and every later
  `CANARY-001` grant, `CUTOVER-001` transfer, or `ROLLBACK-001` reversal of
  effect authority, quiesce the runner
  relinquishing authority: pause and verify its ingress, freeze its new
  scheduling and grants, then drain, revoke, or explicitly reconcile all
  queued/running work, issued credentials/grants, connector authority, leases,
  locks, retries, and uncertain effects. Prove no execution from the
  relinquishing runner retains effect authority before issuing the gaining
  runner's fenced grant; this applies Jenkins-to-McLoving and
  McLoving-to-Jenkins, and input receipt matching alone cannot replace
  quiescence.
- `MIG-005A` owns versioned deterministic forward and reverse transforms for
  the complete execution-history record of every job, regardless of
  stateless/stateful classification: trigger/cause, build and queue identity,
  invocation parameter names/types plus resolved public values and
  confidentiality-safe secret-reference/taint provenance without secret
  material, each checkout's provider/repository/ref/revision, previous-revision
  baseline, canonical change entries and changelog provenance, timing, result,
  graph/stage/node/attempt lineage, approvals and submitted values, normalized
  tests, logs, artifacts and retrieval metadata, applicable retention-policy
  identity/version and deadline, legal-hold identity/scope/reason/provenance,
  placement time and generation, release-authority policy, audit linkage, and
  record provenance. Its existing build-number, previous-result, cross-build
  artifact, workspace, and persistent-state requirements are additive for jobs
  that use them. Each transform must preserve equivalent-or-stronger retention,
  union active holds, forbid deadline shortening or hold release, and map an
  unsupported policy fail-closed. `MIG-005A` must prove both directions,
  idempotent replay, gaps/conflicts/duplicate denial, and exact-profile
  destination retrieval before `DONE`; `DIFF-002` must certify these mappings,
  and `MIG-007` must package their exact implementation/configuration digests
  and receipts. `CANARY-001`, `CUTOVER-001`, and `ROLLBACK-001` may use only
  those packaged certified transforms—never ad hoc handoff or rollback import
  logic.
- For every `CANARY-001` grant, `CUTOVER-001` authority transfer, or
  `ROLLBACK-001` authority reversal, regardless of whether the job is classified
  as stateless, after quiescing the relinquishing
  runner and before granting the gaining runner, take a fresh content-hashed
  live export from the currently authoritative side. Apply the exact certified
  direction-specific transform and import and verify every execution record
  created since the prior transfer: trigger/cause identity, build number,
  invocation parameter schema, resolved public values and protected
  secret-reference/taint provenance without secret material, queue/start/end
  time, terminal result, each checkout's provider/repository/ref/revision,
  previous-revision baseline, canonical change entries and changelog provenance,
  stage/node/attempt lineage, approvals, normalized tests, logs, artifacts and
  retrieval metadata, applicable retention-policy identity/version and deadline,
  every legal-hold identity/scope/reason/provenance, placement time and
  generation, release-authority policy, audit linkage, record-level provenance,
  and destination digests. Verify equivalent-or-stronger retention and every
  active hold on the gaining side before granting any reader, build admission,
  scheduling, or effect authority; a shorter deadline, missing hold, or
  unapproved release keeps the gaining side quarantined. Stateful jobs additionally
  transfer and verify previous-result mappings, cross-build artifacts, retained
  workspace, and every persistent dependency through the exact `MIG-005A`
  transform. An actual `ROLLBACK-001` rollback therefore imports every McLoving
  build and state change produced since cutover into Jenkins before Jenkins regains
  any trigger, reader, writer, scheduling, or effect authority. Empty, stale,
  partial, conflicting, duplicate, or unverifiable execution/state history
  keeps the gaining runner effect-free; the prior runner resumes only after its
  authority and history remain or are restored consistently. A pre-cutover
  snapshot or rehearsal receipt alone is insufficient.
- In every `DIFF-001`, `DIFF-002`, and `DIFF-003` fixture, "no network or host
  mounts" means no external, host,
  production, staging, shared-service, or cross-fixture network or mounts; the
  private network contained wholly inside one disposable fixture is permitted.
  "No secrets, database, agent, scheduler, or controller authority" means no
  production, staging, shared-service, or cross-fixture authority or secrets.
  The Jenkins oracle and McLoving runner each receive a separate disposable,
  exact-profile test stack containing only the controller, PostgreSQL or other
  required state store, scheduler, bounded agent pool, object store, and API
  endpoints needed for that side's declared scenarios. Use synthetic
  short-lived credentials, a private deny-by-default test fabric, no external
  effects, immutable outputs, negative production/cross-fixture reachability
  tests, and complete teardown after receipt sealing.
- `MIG-005A` owns the versioned forward/reverse state transforms and executable
  seeded-history rehearsal before differential certification. Every
  `DIFF-002` transition case must use those exact content-hashed transforms and
  receipts; ad hoc import/export logic cannot earn equivalence. `MIG-007`
  packages the already-certified mapping and receipts rather than defining a
  downstream replacement.
- Every `MIG-005A`, `MIG-007`, `SHADOW-001`, `CANARY-001`, `CUTOVER-001`,
  `ROLLBACK-001`, and `DECOM-001` workspace/state export, transform, backup,
  final retirement export, receipt, and reverse
  import is secret-aware. Classify and
  scan every record before and after transformation; omit credential files,
  tokens, keys, encrypted Jenkins secrets, and other secret material from
  portable state, retaining only reviewed typed redaction references and keyed
  digests in protected evidence. Required credentials must be freshly
  rebrokered through the mapped `SECRET-001` provider and scoped grant; stale,
  revoked, unclassified, or undecipherable secret-bearing state fails closed.
  An active legal hold changes preservation, not runtime exposure: if a held
  log, artifact, workspace, or state record contains secret material,
  `MIG-005A` must either seal the original bytes in a separately encrypted,
  immutable, tenant/case-bound held-evidence store governed by the original hold
  and custodian/release authority, with separate keys, least-access retrieval,
  complete access audit, backup/restore, and digest verification, or execute an
  explicit signed custodian-approved legal-redaction workflow before removing
  any bytes. The portable operational copy contains only the approved redaction
  reference and keyed digest; no workload, runner, connector, or ordinary
  service principal can read the held original. Prove held-evidence retrieval,
  hold continuity, release denial, and restoration before reader/execution
  authority transfer or Jenkins decommissioning. Injected markers may exist
  only inside that explicitly held evidence; prove they never enter destination
  operational state, logs, artifacts, ordinary backups, receipts, APIs, or the
  reverse transform.
- Treat every retained workspace/state filesystem import in either direction as
  hostile input. Parse a canonical manifest inside an isolated staging root;
  enforce bounded entries, total/apparent/extracted bytes, depth, path and name
  length, metadata, time, and compression ratio; reject absolute/traversal,
  NUL, case/Unicode collisions, reserved names, symlinks, hardlinks, devices,
  FIFOs, sockets, sparse/overlapping entries, setuid/setgid, capabilities,
  unapproved ACLs/xattrs, and unsupported file types. Materialize regular files
  and directories with no-follow beneath-root operations, quotas, immutable
  content verification, atomic destination promotion, and failure cleanup.
  Hostile archive/workspace fixtures must prove escape, overwrite, race, and
  resource-exhaustion denial for forward and reverse transforms.
- A corpus case whose production semantics depend on an implementation not yet
  complete at its first differential run and `MIG-006` closure—including
  `DEP-001` dependency resolution
  or `CACHE-001` cache behavior—cannot count as native, mappable, runnable, or
  certified through fixture/ad hoc behavior. After the required implementation
  is complete, rerun every affected `DIFF-001`, `DIFF-002`, or `DIFF-003`
  scenario against its exact deployed binary/image, configuration, policy, and
  provenance identities, refresh the `MIG-006` aggregate closure, regenerate
  the `MIG-007` package and receipts, and pass exact-head review
  before `CANARY-001` effect authority. This recertification rule applies to any
  later trigger, discovery, connector, SCM, secret, dependency, cache, agent,
  or other runtime implementation that changes certified behavior.
- `MIG-000` must inventory every Jenkins Pipeline durability/resume setting and
  dependency, including durability hints, disabled resume, durable tasks,
  preserved stashes, controller checkpoints, and agent reconnect/loss behavior.
  `MIG-002` defines bounded controller restart/crash, agent disconnect/reconnect
  and loss, executor/container kill, network partition, checkpoint replay,
  preserved-stash recovery, retry, cancellation, and duplicate-effect scenarios;
  `DIFF-001` and `DIFF-002` run them through both exact-profile systems and compare resumed
  node/attempt lineage, state, logs, artifacts, results, effects, and audit.
  Unimplemented or uncertified durability semantics are explicit unsupported
  classifications and make affected jobs ineligible for canary or cutover.
- `MIG-000` must inventory every interactive approval/input parameter's type,
  schema, confidentiality, default-presence policy, submitter restriction, and
  downstream use without retaining secret values or defaults. `MIG-002` adds
  public and secret input equivalence classes plus unique marker scans.
  `MIG-003` may map a secret input only as an invocation-only tainted reference:
  accept it over the authenticated approval channel, immediately broker it into
  an expiry-bound, attempt/action-scoped `SEC-003` grant, persist and audit only
  the redacted typed reference and policy/result metadata, and exclude raw
  values from IR/YAML, diagnostics, database/state, logs, artifacts, tests,
  audit, backups, and API/UI/CLI responses. Unsupported handling or any marker
  disclosure rejects the job fail-closed and cannot count as runnable.
- Stop only for an owner-level decision, new authority, or genuine blocker.

## Batch ledger

| Batch | Tickets | Status | Outcome |
|---|---|---|---|
| W0-A | FOUND-001 | DONE | PR #1 established private repository and architecture baseline |
| W0-CI | CI-001 | DONE | Cancel superseded PR runs, restore digest-pinned Rust caches, and use a tested dependency-closure router to move the full Windows war gate to agent-impacting PRs plus every main push |
| W0-CI2 | CI-002 | DONE | Make Foundation execute the PostgreSQL, feature-gated observer, and Jenkins compatibility contracts that the canonical local gates already require; make backup and compatibility receipts reject zero-test success |
| W0-CI3 | CI-003 | DONE | Complete app-bound merge authority: six granular Foundation contexts plus fail-closed Foundation and classified Windows aggregates, exact-head review, protected-main verification, and live protection readback |
| W0-B | ARCH-001, FOUND-002, SEC-001 | DONE | Finite formal model, reproducible HeMan gate, and owned threat model |
| W0-C | IR-001, IR-002, ARCH-002 | DONE | Bounded strict YAML, canonical IR v1, and admission properties |
| W1-A | CTRL-001, CTRL-002, SEC-002 | DONE | PostgreSQL truth, outbox, scheduler, and tenant enforcement |
| W1-B | AGENT-001, AGENT-002, AGENT-003 | DONE | Outbound mTLS contract, fenced sessions, durable journal, Linux process-tree containment |
| W1-C | UX-001, E2E-001, E2E-002, E2E-003 | DONE | Truthful CLI-driven end-to-end spine and recovery |
| W2-A | CTRL-003, OPS-001, OPS-002 | DONE | PR #7 merged recoverable execution, staged object truth, restore fencing, retention, and legal holds |
| W2-B | WIN-001, WIN-002, WIN-003 | DONE | PR #8 merged the Windows service/runtime foundation and hosted destructive fixture; all three tickets are now closed on persistent NucBoxG3 with signed-package, controller-loss, cancellation, and physical-reboot evidence |
| W2-C | AGENT-004, AGENT-005, AGENT-006, WIN-004 | DONE | PR #9 closes production remote work, atomic/replay-safe finalization, non-reusable Linux containment identity, and atomic Windows Job membership |
| W3-A | IR-003, IR-004, CTRL-004 | DONE | Native pipeline semantics: typed parameters and bounded expressions, digest-pinned reusable components, deterministic matrix expansion, and durable parallel DAG execution |
| W3-B | SEC-003, AUDIT-001, OPS-003, TEST-001 | DONE | Fenced grants and protected environments, tenant hash-chain audit, staged artifact product journeys, and immutable normalized test truth |
| W3-C | API-002, UX-002, UI-001 | DONE | Documented REST surface, end-to-end CLI journeys, and an API-only CSP-locked static UI |
| W4-A | INV-001, INV-002, INV-003, INV-004, MIG-000 | DONE | Owner-designated Mario `jenkins-oracle-228` offline epoch sealed four source-truth manifests and one conservative eligibility ledger for 230 disabled parse-oracle jobs |
| W4-B | MIG-001, MIG-002, MIG-003 | DONE | Isolated compiler boundary, exact inventory-derived Jenkins corpus, and first deterministic Declarative translation |

The completed ledger ends at `W4-B`. Earlier coarse future batches are removed:
they mixed independent trust boundaries into oversized pull requests and hid
false serialization. The forward ledger is the remaining execution topology
below. Its lane, class, start gate, and merge rule are authoritative. The
certification join at `MIG-006` remains mandatory; no migration package,
canary, or authority transfer can skip either translation or parity-substrate
evidence.

## Remaining execution topology

The class describes integration behavior, not business priority. A `SERIAL`
ticket may run in a lane that is globally parallel with another lane, but only
one ticket in that lane may mutate state at a time. A `BATCH` is one reviewed
pull request. A `PARALLEL` ticket is always a standalone pull request and may
run concurrently only under the isolation rules above. No remaining ticket is
currently classified `BATCH`: after the recent review history, every remaining
boundary is too large or authority-sensitive to share a pull request safely.

### Active and translation lanes

| Lane | Ticket or ordered chain | Class | Start gate | Streamlined execution rule |
|---|---|---|---|---|
| Sequential Declarative support | `JCOMP-003` | DONE | `JCOMP-002B`, `AGENT-007` and `JCOMP-002C` earned closure; review the fresh exact runtime/compiler freeze before campaigns | One contract, then compiler/admission, sequential step execution, contained workspace continuity, and paired product execution; one PR per ticket and no production authority |
| Library compiler | `MIG-005` | DONE | `MIG-002`, `MIG-003` are done | Separate deny-authority worker/ledger PR; exact 228-file reconciliation and prefetched-source verification are complete |
| State transforms | `MIG-005A` | DONE | Exact admitted-case corrective closure verified | The exact one-build `build-history` denominator now has bounded deterministic forward/reverse transforms, idempotent PostgreSQL import/retrieval proof, a durable imported-cursor/predecessor-bound effect-free McLoving continuation, and pinned Jenkins reverse-import/restart/next-build continuity; private source bytes and seal metadata remain only on HeMan |

### Repository integrity

| Lane | Ticket or ordered chain | Class | Start gate | Streamlined execution rule |
|---|---|---|---|---|
| Merge authority | `CI-003` | DONE | Protected-main merge and post-merge Foundation/Windows verification complete | Complete app-bound merge authority retains the six granular Foundation contexts and adds fail-closed Foundation and classified Windows aggregates; exact-head review, protected-main verification, and the live protection readback are recorded in `docs/evidence/CI-003_SECURITY_REVIEW.md`; this grants repository merge gating only, no product or production authority |
| Deployment smoke cost | `CI-004` | DONE | `CI-003`, `DEPLOY-003` are done | PR #125 merged as `1d81127c7913a92a43402e377eb62289897356e0`; exact post-merge Foundation and native Windows passed. Closure: `docs/evidence/CI-004_SECURITY_REVIEW.md`; measured timings remain subject to runner variance |

### Parity substrate lanes

| Lane | Ticket or ordered chain | Class | Start gate | Streamlined execution rule |
|---|---|---|---|---|
| Operational ingress | `TRIG-001` | DONE | `JOBSTATE-001` merged and protected-main verified | The typed authenticated ingress boundary is complete at exact reviewed head `2e471342f1d15bbc4448196f9edeb7df9c6b3b7a`; protected-main merge `c9e295a5ad61b74af367f9504c5f9071627a7df9` passed post-merge Foundation and Windows verification, and its `DISC-001` serial successor is also complete |
| Source acquisition | `SCM-001` | DONE | `SEC-003`, `AGENT-004` are done | The isolated source trust boundary is complete at exact implementation head `02f0d09a273abc5bd21039d3a7d0b8de069b0bd6` after thirty focused tests, all nine protected checks, clean independent exact-head review, and resolution of forty-seven actionable implementation findings; the sealed Mario denominator still grants zero live SCM or credential authority, so production source acquisition and later authority-transfer gates remain separate |
| Live inputs | `INPUT-001` | DONE | `SEC-003`, `AUDIT-001` are done | The isolated typed read-only adapter and executable receipt boundary are complete; any real production input, canary, cutover, rollback, or decommission claim remains separately gated |
| Dynamic agents | `PROV-001` | DONE | `SEC-003`, `AGENT-004`, `OPS-001` are done | The contained provisioner identity, lifecycle, cleanup, and retained-evidence boundary is complete; any production provider, canary, cutover, rollback, or decommission claim remains separately gated |
| Effects | `EXT-001` | DONE | protected-main merge and post-merge Foundation/Windows verification complete | The contained one-action connector and deny-authority shadow-replay boundary are complete at exact reviewed head `186f48df1ac83c78f4c9dc9e085f2a8fb757b9da`; protected-main merge `dae140e038c52a655489ab99f112ecfa4252aede` passed post-merge Foundation and Windows verification, while Mario retains zero production connector or credential authority |
| Observation | `OBS-001` | DONE | protected-main merge and post-merge Foundation/Windows verification complete | The contained observer boundary is complete at exact reviewed head `2f3999b8f9f734b93d646100a66dd6ba5c87ba83`; protected-main merge `aa43e088242bd125422dd4352df071e23ca4f24f` passed post-merge Foundation and Windows verification, while Mario retains zero production destination-observer authority |
| Release provenance | `REL-001` | DONE | Protected-main protocol repair, exact-head artifact, and HeMan ceremony verified | McLoving v0.1.0 for `private-linux-x86_64` is signed under the one-time genesis policy. The secondary attestation is public in Rekor, the canonical evidence manifest has an independently verified DigiCert RFC 3161 anchor, and the complete private evidence package is retained on HeMan; no binary placement or production deployment is claimed |
| Cache | `CACHE-001` | DONE | `DEP-001` merged and protected-main verified | The contained cache boundary is complete at exact reviewed head `87e3f75936e1d5f153b99167e1340308e92ac9ac`; protected-main merge `f58986cd36019588b9731150a663e5dff32773bd` passed post-merge Foundation and Windows verification, while Mario retains zero production cache authority |
| Secret mapping | `SECRET-001` | DONE | protected-main merge and post-merge Foundation/Windows verification complete | The contained credential-mapping and short-lived grant broker is complete at exact reviewed head `87951abddf174829dc5fe70b22dd6a4a07724f5c`; protected-main merge `f08756fd91810268a0ea18321d9e333895501ab7` passed post-merge Foundation and Windows verification, while Mario retains zero production credential, provider, grant, canary, or authority-transfer capability |
| Discovery | `DISC-001` | DONE | protected-main merge and post-merge Foundation/Windows verification complete | The versioned discovery boundary is complete at exact reviewed head `f02eddfffbc295dd86eef0a8a000f3f3b6a10554`; protected-main merge `41248d7dd4f1a694494ddec7a22fd51eed1f1987` passed post-merge Foundation and Windows verification, while Mario retains zero production discovery authority |
| Dependencies | `DEP-001` | DONE | `SCM-001` is done | Exact implementation head `075634f6ce6ee6f1ef5e371cbad313dddab4aaf3` replaces transient and durable dynamic directory trees with exclusive regular archives, closes the two repeated creation-to-open namespace races, marker-scans the authenticated permanent commit before persistence and after replay loading, carries one marker scanner across the complete transport plan, carries one stateful guard across the exact generated archive serialization, routes final archive-sync failure through exact cleanup or poisoned ambiguity, serializes complete fetches, establishes immediate pending poison before caller-deadline-bounded external slot fencing, and uses a four-state atomic handshake to linearize fetch success against poison before slot release. All 123 focused tests pass, including production-wired cross-artifact, header-to-payload, sync-failure, archive/root metadata, real non-file/device/zero-inode validation, second-fetch denial, overlapping-fetch, both atomic poison/success orders, external-poison deadline, active-success denial, and deterministic post-verification-barrier queued-fetch proofs. Complete PR head `5e356449cda88cb43c694cbd6f525f24463e3e89` passed all nine protected checks and fresh independent review before all sixty-seven fixed threads were resolved; protected-main squash commit `82a5108284d0152b57230995dd53a754b0aae5c4` passed post-merge Foundation and Windows verification. The complete audit contains 140 actionable findings across 145 important seams. Mario's sealed denominator still grants zero workload dependency or repository authority, so cache, production dependency, and later authority-transfer gates remain separate. |
| External clients | `ADMIN-001` | DONE | `CONSUMER-001` is done | The sealed client's higher-authority administrative write contract and implementation gate are complete; production cutover remains separately gated |

### Certification, authority, and proof lanes

| Lane | Ticket or ordered chain | Class | Start gate | Streamlined execution rule |
|---|---|---|---|---|
| Product alpha | `ALPHA-001` | DONE | Protected-main merge and post-merge verification complete | The accepted clean-checkout Mario journey is retained with zero production or Jenkins authority |
| Performance | `PERF-001` | SERIAL | `MIG-006`, `REL-001`, `EXEC-004` done, `SEC-005`, `EXEC-005`, `CASE-001`, `DEPLOY-002`, `CASE-002`; long-step envelopes measure work rather than a session-epoch collision, and must measure the contained executor rather than one that is about to be replaced | Isolated reproducible capacity lane; may run while later migration gates advance |
| Helper runtime integration | `EXEC-005` | PARALLEL | `EXT-002` done, `DEPLOY-001`, `JCOMP-003` | Wire the sealed helpers into the product path so a submitted job can reach them; packaging a binary nothing calls ships a dormant executable, not a capability |
| Production secret broker | `SECRET-002` | SERIAL | `SECRET-001` done, `DEPLOY-001`, `EXEC-005` | Build the broker executable and bind its authority: a secret boundary reviewed on its own, before any release ceremony packages it |
| Deployment revalidation | `DEPLOY-002` | SERIAL | `DEPLOY-001`, `DEPLOY-003`, `DEPLOY-004`, `REL-003` | Prove the release that actually ships can be installed, started, upgraded, and rolled back on a clean host, on every platform still eligible; the DEPLOY-001 proof covers an artifact that predates the helpers, broker, driver, and verifier |
| Release completeness | `REL-003` | SERIAL | `REL-001` done, `DEPLOY-001`, `SEC-005`, `SECRET-002`, `EXEC-005`, `AGENT-007`, `CANARY-002`, `CASE-001`, `UI-009` | Package and sign every executable the deployment lane installs, including the sealed helpers that dispatch external effects; `CUTOVER-001` cannot re-read a digest that no release contains. Completeness is per platform as well as per executable: `REL-001` covers `private-linux-x86_64` only, so a Windows canary needs a Windows release artifact or explicit ineligibility. No credential-dependent case is eligible until the broker ships |
| Workload containment | `SEC-005` | SERIAL | `DEPLOY-001`, `DEPLOY-003`, `CI-004`, `EXEC-005`, `SECRET-002` | Contain the spawned step so submitting a pipeline is not equivalent to reading the host's deployment credentials. It precedes case qualification and is a **gate**: `CANARY-001`, `CUTOVER-001`, and `REL-002` all depend on it, because granting a production effect, cutting over, or declaring release readiness while any pipeline submitter can read the deployment credentials and the agent's mTLS private key would carry a known credential escape past the exact decisions those gates exist to make |

### Product hardening lanes

Standalone defect and operational-gap tickets earned by owner-run external
benches (PR #41) and by the 2026-08-18 whole-repository code review. Each is a
separate reviewed pull request; none touches migration evidence or grants any
authority, so they may proceed in parallel with the qualification lanes under
the three-mutable-PR cap. `EXEC-004` was ranked first and is closed. Its
premise did not survive contact with the code: renewal always ran concurrently
with step execution. The wedge was a shared-agent-identity session-epoch war —
`agent_sessions` is keyed by `agent_id` alone — which rejected a renewal
mid-step. `SEC-005` now carries the highest rank among the open hardening
tickets, because it gates `CANARY-001`, `CUTOVER-001`, and `REL-002`.

| Lane | Ticket or ordered chain | Class | Start gate | Streamlined execution rule |
|---|---|---|---|---|
| Claim staleness | `HYG-003` | PARALLEL | `HYG-002` is done | Standalone hygiene pull request generalising the existing protected-main pin rule to the class review measured. Nothing is proved yet: the ticket must show each new check red against real pre-fix text taken from history and green against the receipts that record observations correctly, and must name the cases it leaves to written convention rather than gating |
| Lease survival | `AGENT-007` | DONE | `EXEC-004` is done | DONE after independent review, protected merge and exact-main Foundation/native Windows execution; JCOMP-003 must bind this corrected runtime in its separate execution freeze. Review record `docs/evidence/AGENT-007_SECURITY_REVIEW.md` |

### Parity lane

| Lane | Ticket or ordered chain | Class | Start gate | Streamlined execution rule |
|---|---|---|---|---|
| Product parity | `PAR-000` -> `PAR-010` -> `PAR-011` -> `PAR-012` -> `PAR-001` -> `PAR-013` -> `PAR-014` -> `PAR-004` -> `PAR-005` -> `PAR-003` -> `PAR-002` -> `PAR-015` | SERIAL | `PAR-000` starts on the owner's 2026-09-10 decision; each later ticket starts after its predecessor is merged and verified | One pull request per ticket in this order; the chain is the dispatch queue and the distance metric; proof commands recorded in each pull request |

### Dispatch discipline

The dispatch queue is the parity lane above, in order, starting at `PAR-000`.
Advance only after the predecessor is merged and verified on protected `main`.
The Jenkins M1 chain `JCOMP-001` through `JCOMP-003` is complete. `SECRET-002`,
`SEC-005`, `REL-003`, `DEPLOY-002` and `PERF-001` keep their rows and their
dependencies on deferred tickets; those dependencies are re-derived when the
parity phase closes, not silently dropped. `MIG-005A` and `MIG-007`
are completed historical work, not dispatch candidates.

Use one standalone pull request per milestone ticket. At most three mutable
pull requests may coexist, but shared compiler, schema, fixture, or threat
boundaries must be serialized. Read-only analysis can proceed independently.

## One-day product priority override — completed

For the working day beginning 2026-08-16, `ALPHA-001` was the sole definition
of progress and the broad migration/authority sequence was paused. Exact head
`d22bd08e75593e76e72af4eae46548b58ea6eab3` passed the retained native demo on
Mario as build `48ff5fb3-d3b9-48e7-909d-fbac89c74972`; its 41-file payload
manifest has SHA-256
`3f18af3db77e512054f0502c40d5a21f2dbd78081894b075d01c9a9b20d64ba0`.
All seven review threads were resolved, PR #71 squash-merged as protected-main
commit `db1073c37ff6630ebc4824f138c23b7d82a5a013`, and all nine post-merge checks
passed. The owner accepted that retained demo and explicitly resumed the board
on 2026-08-17, ending the override. The alpha granted zero production or
Jenkins authority. `CANARY-000` is complete: exact reviewed head
`2ca737a28fca8926e3c4d7c92b339567213a78fd` squash-merged through PR #70 as
protected-main commit `c6a238ae9acdc997d14850d1752cecd54feec8b9`, whose
Foundation run `32080011592` and Windows run `32080011587` passed. `EXT-002` is
complete, merged as `03a1f5d` through PR #72; the production qualification lane leads to `CASE-001` after the
remaining helper, broker, and containment prerequisites. `DEPLOY-001` has a **bounded closure from 2026-08-27**:
one hand-run systemd arm exercised the service-managed path and the
deployable-runtime gate against an installed deployment. `DEPLOY-003` is now
closed: the manager-query path and complete source unions run per pull request
under a controlled disposable user manager. The then-selected successor was `EXEC-005`; the September 8 milestone
selection above supersedes that dispatch.
`CANARY-001` remains the production ceremony, and any production effect still requires a separate fresh
one-action owner authorization and every pre-action gate.

## CI-003 historical protection correction

Before `CI-003`, the board's phrases "all nine protected checks" and
"Foundation and Windows merge authority" described nine observed successful
workflow outcomes, not nine branch-required contexts. Those runs remain valid
test evidence because the named jobs did execute and pass, but the live branch
protection rule required only six Foundation child contexts. It omitted
`Backup and restore`, `Deployment lane`, and the complete Windows workflow,
and four of its six contexts were not bound to their reporting GitHub App.
They therefore did not prove that GitHub would have blocked a merge when an
omitted lane failed. `CI-003` owns that repository-governance correction; it
does not reopen the product behavior those historical runs verified. App
binding authenticates GitHub Actions as the reporter; it does not authenticate
a particular workflow definition. Candidate merge-authority source—including
workflows, classifier, verifier, and their test oracles—therefore remains inside
the reviewed source boundary.

## Historical closure-evidence debt

The 2026-08-30 QA review found twelve closed tickets without the repository's
later receipt convention and thirty-nine tickets without machine-readable
threat-model attribution. Retrospective reviews now close the seven current
product/runtime gaps: `CANARY-000`, `EXEC-001` through `EXEC-004`,
`OUTBOX-001`, and `HYG-001`. Five migration-era receipt gaps and thirty-two
attribution gaps remain admitted and are printed by
`scripts/verify-ticket-closure-receipts.py`; membership is ratcheted so new
debt cannot enter. They are not silently exempted, and `--strict` remains the
gate for a zero-debt ceremony.

## Wave 0 — Architecture and foundation

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| FOUND-001 | DONE | — | Private monorepo, ADRs 1–15, board, threat model skeleton, CI, clean protected merge |
| CI-001 | DONE | FOUND-001 | Preserve every protected required check while cancelling superseded PR runs, restoring commit-pinned Rust caches keyed by the lockfile/toolchain, and tiering the full Windows native-service/crash-recovery war gate to Windows-agent-impacting PRs and every push to `main`; a tested Linux router must compare changed source paths, the complete production-and-test package closure, resolved dependency graph, and normalized workspace build policy so an unrelated workspace-member/lockfile addition skips Windows without hiding an agent dependency change; persistent-host `WIN-003` evidence was completed as a separate release gate |
| CI-002 | DONE | CI-001 | Close false-green Foundation coverage. The hosted PostgreSQL job now executes the real execution-spine, unsupported-spec, controller differential/capability, and shipped remote-agent suites already named by `scripts/test-controller-postgres.sh`; each newly authoritative target requires the database URL before Cargo starts and proves its exact denominator. Complete local runs exposed both a remote-agent gate that counted two tenant wakeups as terminal and raced durable truth, and parallel process-launching tests that could collide during non-atomic loopback-port handoff. The gate now re-reads PostgreSQL after each wakeup and stops only at a terminal state without polling, the focused process-launching binaries run serially, and shipped agent children do not inherit the harness's database connection configuration. The boundary job runs the 58-test feature-gated destination-observer contract target and proves its exact denominator; the architecture job runs the six-test Clojure compatibility suite under an immutable setup-action pin plus the plugin-directory contract; and every backup/restore exact-filter canary proves one test executed before printing its receipt. The shared Rust-summary verifier has negative controls for zero, partial, missing, multiple, and failed summaries, while the Clojure runner refuses any denominator other than six. Closure: `docs/evidence/CI-002_SECURITY_REVIEW.md`. |
| CI-003 | DONE | CI-002 | Establish complete, app-bound merge authority -- **closed**. The pre-ticket branch protection required six Foundation child contexts, omitted `Backup and restore`, `Deployment lane`, and Windows, and left four contexts unbound to a reporting app. The merged gate adds one always-running Foundation aggregate over every Foundation lane and one always-running Windows aggregate that accepts only classifier success plus either required-Windows success or an intentional non-impact skip. Exhaustive and mutation tests prove omitted, failed, cancelled, skipped, invalid, and fail-open structural variants close rather than waive the gates; digest-verified actionlint covers every workflow. Live strict protection retains the six granular contexts as defense in depth and requires both aggregates, with all eight contexts bound to GitHub Actions app id `15368`, admin enforcement, linear history, and conversation resolution. App binding authenticates the reporter rather than candidate-controlled source, so authority-sensitive edits retain the independent exact-head review obligation. Exact reviewed head `0ee95767a96d5664b41a7c035558e41c09f39270` passed both aggregates, and protected-main squash `463ad646fecccf993fa8a837eb7b9a9c19eb71c7` passed them again. Closure receipt `docs/evidence/CI-003_SECURITY_REVIEW.md`. This grants repository merge gating only, no product or production authority. |
| CI-004 | DONE | CI-003, DEPLOY-003 | Reduce the measured deployment smoke critical path in `deploy/test-deployment.sh` by removing only debug sections from disposable fixture copies before checksums are sealed. Exact corrected implementation `3880043226f54b35984defc0d09957e5ff1d26ac` passed Foundation run `34289733746` and classified Windows run `34289733750`, with independent source and threat review. Original build outputs, compiled assertions, symbols, unwind data, every smoke case, and exact systemd installed/controller byte identity remain unchanged. Hosted smoke was 10m59s versus the adjacent baseline 16m23s; this is an observed comparison subject to runner variance. The failed systemd-stripping precursor and complete evidence remain in `docs/evidence/CI-004_SECURITY_REVIEW.md`. Closure: `docs/evidence/CI-004_SECURITY_REVIEW.md`. Final reviewed head `7ff7d726632cb1f0ee128b78a5cb92ec5432839a` passed all eight protected checks with no unresolved review items; PR #125 merged as `1d81127c7913a92a43402e377eb62289897356e0`. Exact post-merge Foundation `34293282546` and native Windows Agent `34293282632` passed. Post-merge Foundation took 19m39s versus the earlier candidate 15m32s; neither observation guarantees a fixed percentage improvement. No production authority is granted. |
| ARCH-001 | DONE | FOUND-001 | Finite TLC model; lease type, stale publication rejection, fencing, terminal monotonicity, and completion stability checked in CI |
| FOUND-002 | DONE | FOUND-001 | Digest-pinned Rust/gitleaks, checksummed tools, documented cache policy, one-command HeMan validation |
| SEC-001 | DONE | FOUND-001 | Actors, assets, boundaries, assumptions, 24 owned threats, mitigations, residual risk, and verification map |
| IR-001 | DONE | ARCH-001, SEC-001 | Restricted YAML 1.2 parser; stable errors; duplicate/alias/anchor/tag/directive rejection; byte-exact UTF-8 spans; six resource limits; arbitrary-input and seven-fixture negative gates |
| IR-002 | DONE | IR-001 | Pipeline/process IR v1; source/compiler provenance; structural validator; deterministic binary encoding and SHA-256; golden digest; explicit compatibility; independent byte validator |
| ARCH-002 | DONE | IR-001, IR-002 | Property gates prove deterministic admission, bounded sequence expansion, arbitrary-input panic freedom, and unknown-field fail-closed behavior at every schema level |

## Wave 1 — Smallest truthful end-to-end slice

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| CTRL-001 | DONE | IR-002 | PostgreSQL migrations and one transaction for build/node/attempt/event/outbox with real-DB race tests |
| CTRL-002 | DONE | CTRL-001 | Fenced single-node scheduler, indexed claims, capability filtering, fairness seed, explainable wait reason |
| SEC-002 | DONE | SEC-001, CTRL-001 | Organization/project identity, tenant-keyed schema, PostgreSQL RLS, centralized deny-by-default authorization |
| AGENT-001 | DONE | ARCH-001, CTRL-001 | Outbound mTLS, enrollment, certificate rotation, session epoch, protocol negotiation, stale-session fencing |
| AGENT-002 | DONE | AGENT-001 | SQLite WAL acceptance-before-ack, journal recovery, log/result spool metadata, reconciliation report |
| AGENT-003 | DONE | AGENT-002 | Linux workspace/process group, durable logs, timeout/cancel tree cleanup, no escaped descendants |
| UX-001 | DONE | CTRL-002 | Rust CLI submit/status/logs/cancel/explain through documented public API and idempotency keys |
| E2E-001 | DONE | IR-002, CTRL-002, AGENT-003, UX-001 | One-stage strict-YAML process through real PostgreSQL, outbox, scheduler, agent, logs, terminal result |
| E2E-002 | DONE | E2E-001 | Controller kill/restart at every durable transition without lost or duplicate logical execution |
| E2E-003 | DONE | E2E-001 | Agent disconnect/restart reconciliation and complete descendant-process cancellation proof |
| ALPHA-001 | DONE | E2E-001, UX-002, UI-001, AUDIT-001 | The operator-facing native alpha defined in `docs/ALPHA_DEMO.md` passed on Mario at exact head `d22bd08e75593e76e72af4eae46548b58ea6eab3` as build `48ff5fb3-d3b9-48e7-909d-fbac89c74972`. The retained 41-file payload manifest has SHA-256 `3f18af3db77e512054f0502c40d5a21f2dbd78081894b075d01c9a9b20d64ba0`; restart recovery, idempotent resubmission, owner-only retention, zero duplicate completion markers, zero production effects, and non-interference with the existing Mario containers were independently verified. All seven review threads were resolved, PR #71 squash-merged as protected-main commit `db1073c37ff6630ebc4824f138c23b7d82a5a013`, and all nine post-merge checks passed before owner acceptance ended the one-day override. |

## Wave 2 — Durability and platform parity

| Ticket | Status | Depends on | Objective |
|---|---|---|---|
| CTRL-003 | DONE | E2E-002 | Durable retry, timeout, post, cleanup, and uncertain-effect reconciliation |
| OPS-001 | DONE | E2E-001 | Staged object storage, immutable artifacts, checksummed log chunks, explicit gaps and quotas |
| OPS-002 | DONE | OPS-001 | Backup, PITR checkpoint contract, restore epoch, object reconciliation, retention and legal-hold drills |
| AGENT-004 | DONE | AGENT-002, CTRL-002 | Production tenant-bound mTLS poll/claim, exact certificate-bound trust-pool scheduling, transaction-bound session epochs on every production work mutation, journal-before-ack acceptance, negotiated `work-delivery-v1`, fenced start/lease/cancellation, lease-loss execution cancellation, explicit allowlisted child environments, native execution, bounded streamed log publication, and explicit terminal publication; real PostgreSQL shipped-controller/shipped-agent gates prove remote stdout/stderr and success |
| AGENT-005 | DONE | AGENT-004, OPS-001 | One immediate SQLite transaction persists the terminal phase plus complete log/result descriptors before upload; no-follow canonical result paths reject workload redirection; reconnect retains exact authority, verifies every spool digest/size, deterministically replays the original work or cancellation protocol, accepts only exact terminal replay without self-revoking renewal, and idempotently reclaims acknowledged local spools while preserving terminal history; forced response-loss and agent-crash gates converge to one terminal event |
| AGENT-006 | DONE | AGENT-003 | SQLite journal v2 migrates legacy rows fail-closed and persists Linux boot ID plus `/proc` birth ticks; cancellation revalidates identity before TERM and KILL, never signals a recycled PGID, never treats a missing group leader as proof of an empty group, and returns distinct completed, already-exited, retire-stale, and reconciliation-required outcomes with idempotent controller truth |
| WIN-004 | DONE | AGENT-003 | Win32 creates every workload suspended with atomic kill-on-close Job membership through `PROC_THREAD_ATTRIBUTE_JOB_LIST`, records durable process identity before resume, and uses a restricted inherited-handle list; native forced-crash gates at every creation boundary and after descendant spawn leave no escaped process |
| WIN-001 | DONE | AGENT-003, AGENT-004, AGENT-005 | Build a native Windows service agent with the existing outbound enrollment/session protocol and SQLite WAL journal; prove hosted Windows install/start/stop/uninstall, monotonic session epochs, process restart, and journal reconciliation |
| WIN-002 | DONE | WIN-001, WIN-004 | Add explicit direct-process, `cmd.exe`, and PowerShell execution modes; isolate each attempt in a race-free Job Object and ACL-owned workspace; prove timeout/cancel/service-crash kills every descendant and preserves durable stdout/stderr/result evidence |
| WIN-003 | DONE | WIN-002, E2E-003 | Maintain one versioned Linux/Windows semantic-parity matrix and run destructive hosted-Windows proof; then close with a signed package on a persistent Windows host through controller/network interruption and machine reboot, requiring matching terminal outcomes, logs, artifacts, cancellation, stale-authority rejection, and zero escaped descendants |

## Wave 3 — Native product surface

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| IR-003 | DONE | IR-002, ARCH-002 | Add typed pipeline parameters and a non-Turing-complete expression language with explicit contexts, stable diagnostics, canonical encoding, deterministic evaluation, secret-taint propagation, and independently enforced depth/node/string/operation limits; arbitrary-input and boundary properties must remain panic-free and bounded |
| IR-004 | DONE | IR-003 | Add versioned reusable components resolved by immutable digest; bind input/output types and provenance, reject cycles and floating references, cap expansion depth/count/bytes before scheduling, and prove presentation-independent canonical expansion plus component-substitution resistance |
| CTRL-004 | DONE | IR-004, CTRL-003 | Compile matrix axes deterministically into a bounded DAG; persist dependency, fan-out, join, fail-fast, retry, post, and cancellation truth transactionally; schedule ready nodes fairly across exact platform/trust-pool constraints and prove parallel races, restart recovery, terminal monotonicity, and one logical outcome per node in real PostgreSQL |
| SEC-003 | DONE | SEC-002, CTRL-004 | Issue attempt-scoped credential grants and protected-environment approvals bound to organization, project, build, IR digest, environment, action, and expiry; deliver secrets only to the exact fenced attempt, redact every supported sink, reject stale/replayed approvals, and prove cross-tenant and cross-attempt denial |
| AUDIT-001 | DONE | SEC-003, OPS-002 | Persist an append-only tenant-keyed audit stream for identity, authorization, scheduling, grant, approval, artifact, and administrative actions; hash chained segments, externally verifiable export, retention/legal-hold integration, mutation denial, and gap/tamper detection are required |
| OPS-003 | DONE | OPS-001, CTRL-004 | Expose artifact upload, commit, list, metadata, and download journeys over staged immutable object truth; bind every artifact to tenant/build/node/attempt/name/digest/size/media type, enforce quotas and no-overwrite semantics, and prove partial upload, substitution, restore, and retention behavior |
| TEST-001 | DONE | OPS-003 | Normalize bounded JUnit-style test reports into versioned suite/case outcomes with provenance and raw immutable source retention; reject entity expansion and malformed/oversized input, preserve duplicate-name identity explicitly, aggregate deterministically, and expose flaky/retry history without rewriting prior outcomes |
| API-002 | DONE | CTRL-004, SEC-003, AUDIT-001, OPS-003, TEST-001 | Complete the documented REST API for pipelines/components, parameters, builds/nodes/attempts, approvals/grants, logs/artifacts/tests/audit, pagination/filtering, idempotency, optimistic concurrency, stable errors, OpenAPI, and tenant-scoped authorization; contract and real-PostgreSQL tests must cover every route and deny path |
| UX-002 | DONE | API-002 | Complete Rust CLI journeys for validate/plan/submit/watch/explain/cancel/retry/approve, logs, artifacts, tests, and audit; support machine-stable JSON plus human output, resumable watch, explicit uncertain states, shell completion, and API-only end-to-end tests |
| UI-001 | DONE | API-002 | Ship a content-security-policy-locked static web UI that uses only the public API for dashboard, pipeline/build graph, live logs, approvals, artifacts, tests, audit, and explainability; no privileged backend path, embedded secret, or client-side authorization claim is allowed, with accessibility and browser journey gates |

## External differential bench findings (games round 1, 2026-08)

Findings from the owner-run cross-engine bench on luigi (2026-08-06/09) against
protected-main `b75165d`, production remote-agent lane over mTLS. Evidence
bundle: luigi `~/games-round1-receipts.tgz` (environment fingerprint, heat
logs, controller/agent logs, and the preserved agent journal). The bench also
measured ~500 ms wall per single-step stage with both controller and agent
polls recorded at 10 ms in its environment fingerprint. A later-found agent
defect — the work loop ran one assignment per poll tick, making per-stage
cost max(agent poll interval, work); fixed by `b1301e9` (PR #103) — produces
exactly this figure at the agent's shipped 500 ms default (496.4 ms/stage,
recorded in `b1301e9` against its parent tree `bed6c0f`) but cannot produce
it at a 10 ms poll, so either the recorded environment did not reach the bench's agent
process or its ~500 ms had a distinct cause on the `b75165d`-era tree that
was never isolated. The observation belonged to `PERF-001` and its receipts
live there. These four tickets were first
drafted in PR #41 and are adopted here with their measured evidence unchanged.

PR #103 (`b1301e9`) is partial `PERF-001` evidence, not a separate unnamed
ticket and not closure: it removes the fixed poll interval from the path
between work already returned by a poll and the next claim, and its remote-work
gate proves the agent drains a returned batch without interval pacing. The
capacity envelopes, pinned deployment profiles, saturation measurements, and
reviewed regression margins in the `PERF-001` acceptance remain pending.

Four further protected-main merges are partial `PERF-001` evidence in the
same sense as PR #103 — measured, labeled, and not closure. PR #105
(`30a206b`) cut the per-attempt agent-to-controller protocol from seven
serialized round trips to four behind negotiated features; paired
same-host cells on a fresh database measured 242.7 to 218.4 ms/stage
(Mario, shipped 500 ms interval). PR #106 (`6f6b97f`) collapsed the
controller's evidence write from seven statements to two and its
per-RPC authorization to one, measuring 220.4 to 208.3 ms/stage on the
same rig and configuration. PR #107 (`23b2273`) removed a rare
fail-closed freeze — an unrelated process dying mid-scan parked an
attempt as `reconciliation_required` and stopped the agent's lane —
found and churn-validated at roughly one occurrence per few thousand
attempts. PR #108 (`ef08716`) turned the agent's per-attempt durability
fsyncs into concurrent batched barriers under named crash-recovery
properties, measuring 271.5 to 228.0 and 291.9 to 238.5 ms/stage across
two interleaved rounds (Luigi, whose fsync measured ~14 ms against
Mario's 1.9 ms — per-stage numbers are within-rig, within-configuration
deltas and must never be paired across rigs or poll settings).

The externally filed 2026-08-29 observation "replace the fixed-interval
polling regime with event-driven waits" (measured against `83a6d6c`, an
unmerged two-commit lineage atop protected-main `6ac9be9` whose full
source identity, raw commit objects, and runtime-crate equivalence to
that ancestor are preserved in
`docs/evidence/PERF-001_POLLING_BASELINE_2026-08-29.md`; pre-dating all
of the above) is CLOSED against its own acceptance criteria: per-stage cost at shipped defaults with no interval lowered —
71.2018 ms/stage median on the `release-embedded` profile, and on the
filed remote-agent profile itself 167.9 and 174.3 ms/stage medians
across two cells (the confirming cell under the bar on both estimators;
raw cells and build identity retained in
`docs/evidence/PERF-001_POLLING_BASELINE_2026-08-29.md`) against its
183 ms bar; idle CPU 1.099% of one
core for the complete stack against its 5% bar; every property its
sleeps guarded kept a gate (work-loop drain, submission wake, lease
renewal, cancellation observation, reconciliation cadence, stale-fence
rejection); and the measurements carry median and minimum estimators
under its own admissibility rule. Its headline attribution — 19% of
per-stage cost recoverable by event-driven waits — was true of the
build it measured and not of later main: `893e06f` (PR #78) enrolled
acceptance, start, renewal, and terminal publication in the same
per-organization advisory lock the claim path already took, so an
in-flight poll's claim waits out a concurrent finalize and claims its
freshly queued successor the moment that finalize commits, instead of
returning empty and sleeping an interval — replicated on
pre-event-wait protected-main `bed6c0f`, the filed 41.3 ms of poll
sensitivity (its poll-10ms cell at 215.8 ms/stage minus its poll-1ms
cell at 174.5, the matching-durability pair) measured 3.7 ms; both the
filing's raw cells and the replication's are retained in
`docs/evidence/PERF-001_POLLING_BASELINE_2026-08-29.md` — and the shipped-default cost the filing never observed was the drain
defect fixed by `b1301e9`. The filing campaign's
own report marks its McLoving figures superseded (they were measured at
a 10 ms poll, where the drain defect is invisible). Closure of the
observation does not close `PERF-001`.

PR #109 (`4f77485`) and PR #110 (`0f6499f`) close the bounded event-wait
dimension without closing `PERF-001`: remote, schedulable embedded, and
reconciliation-only controller paths subscribe before reading authoritative
state, wake on committed tenant hints or an earlier lease deadline, and retain
a 20-second lost/coalesced-hint fallback independent of the compatibility poll
setting. Exact reviewed source `e57f7c9` (tree `b4d4b86`) measured 71.2018
ms/stage median on Mario; the idle-CPU result is the separate
`docs/evidence/PERF-001_EVENT_WAIT_QA_2026-08-31_IDLE.tsv` receipt at 1.099%
complete-stack idle CPU, while the JSON receipt's idle-CPU fields are not the
reported measurement in this bundle. Immutable receipts, review identities,
rejected estimator runs, and the protected-main tree mapping are in
`docs/evidence/PERF-001_EVENT_WAIT_QA_2026-08-31.md`. The broader capacity,
saturation/backpressure, storage, recovery, regression-margin, and
eligible-platform envelopes below remain pending.

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| EXEC-001 | DONE | — | Fail closed end-to-end on unsupported execution specifications. Measured: a strict-YAML pipeline with 100 process steps in ONE stage passed `validate` and admission, scheduled, and was refused at claim time by the execution spine (`spec.steps.len() != 1`); the agent treated the permanent refusal as transient and retried the claim in an infinite session loop while the build reported `running` indefinitely (1,460+ build events accumulated before manual cancellation). A permanent condition presenting as progress is the silent worst outcome this board exists to prevent. Acceptance: validate/admission reject — or plan into per-attempt units — every spec the spine cannot execute, so validate-accepted implies runnable; an unsupported-spec refusal at claim time is terminal and fail-closed with a named code, never retried; a regression gate submits the 100-step single-stage pipeline and asserts a terminal state within one lease, never unbounded running **Closure:** merged to protected main as `5f9aa31` (PR #79). `validate` and admission now plan every accepted specification into per-attempt units, so validate-accepted implies runnable; a spec the spine cannot execute is refused at claim time as a named terminal failure that the agent never retries; and a gate submits the 100-step single-stage pipeline and asserts a bounded terminal outcome instead of an unbounded `running`. |
| EXEC-002 | DONE | — | Capability vocabulary parity for the embedded worker. Measured: the controller-embedded worker configured with `MCLOVING_AGENT_CAPABILITIES=linux` never claimed any work — submissions default to requiring `platform:linux`, so every build queued indefinitely; `explain` correctly named the missing capability (the diagnostic worked; the configuration surface lied silently at startup). Acceptance: one documented capability vocabulary; embedded-worker startup fails closed with a named error when its declared capabilities cannot match the default submission requirement; a gate proves embedded-only execution of a default `--platform linux` submission end to end **Closure:** merged to protected main as `75e618d` (PR #82). One sealed vocabulary in `crates/domain`: the `platform:` namespace is closed, `platform:linux` and `platform:windows` are the supported set, and `classify_embedded_worker_capabilities` returns `Schedulable`, `Disabled`, or one of four named errors. A Windows-only worker declaring `platform:windows` is schedulable and starts — what fails closed is a token inside the closed namespace naming an unsupported platform, a declaration naming no supported platform, an empty declaration, and the disable sentinel mixed with other capabilities. |
| EXEC-003 | DONE | — | Name the identity collision and give the operator a resolution verb. Measured: two executors (embedded worker + remote agent) misconfigured with one agent identity and one journal broke a work-delivery session mid-build; the attempt was journaled recovered, the agent fail-closed refused all further work (correct), the build parked in `reconciliation_required` (correct), and CLI cancel was refused (defensible) — but no diagnostic named the collision, and no documented operator path existed to discharge the orphaned recovered attempt short of journal replacement. Fail-closed held; explainability did not. Acceptance: a gate reproduces the shared-identity collision and asserts a named diagnostic on both agent and controller; a documented, implemented operator resolution for an orphaned recovered attempt; the cancel refusal states its reason. Evidence: preserved journal in the bench archive **Closure:** merged to protected main as `2c3c266` (PR #80). A gate reproduces the shared-identity collision and asserts a named diagnostic on both the agent and the controller, the cancel refusal states its reason, and the operator has a documented, implemented verb that discharges an orphaned recovered attempt without replacing the journal. |
| EXEC-004 | DONE | — | **A shared agent identity ends the session that a mid-step renewal depends on.** Measured (build-Jenkins duel, 2026-08-10, main `0ca0142`, production remote-agent lane): with `MCLOVING_LEASE_SECONDS=30` the agent wedged into `reconciliation_required` roughly 27 seconds into a ~200-second Maven step — deterministically, on every attempt; with the lease raised to 600 the IDENTICAL pipeline SUCCEEDED in 341 s and produced a verified `jenkins.war`. **The original diagnosis on this row was wrong and is kept here as a caution:** it read the lease term as the variable and concluded renewal never runs during a step. Review of `bins/agent/src/worker.rs` disproved that — `run_assignment` spawns `renew_lease` before awaiting the process and it renews at the configured interval throughout. `agent_sessions` is keyed by `agent_id` alone, so a second executor sharing the identity advances the session epoch and the mid-step renewal is rejected; a longer lease only widened the window before that happened. What the measurement did establish is real and stands: no gate in the repository ran a step longer than a few seconds, so nothing exercised authority being held WHILE work happens, and every real-world build step exceeds one lease term. Acceptance: the agent renews its lease concurrently with step execution; a gate runs ONE step lasting at least three lease terms to terminal success on the remote lane; lease-loss cancellation (AGENT-004) is re-proven by a gate that BLOCKS renewal deliberately, never by a step merely outrunning it; and a long step under a short lease produces a NAMED diagnostic on agent and controller, not a silent `reconciliation_required`. Evidence: luigi `~/duel-mcloving-receipts.tgz` — env, logs, and four wrecked journals across five rounds, each labeled with what wrecked it **Closure:** merged to protected main as `8fb8ac5` (PR #74) after five rounds of independent review. The ticket premise was corrected by evidence: renewal always ran during steps; the wedge was a shared-agent-identity session-epoch war, since `agent_sessions` is keyed by `agent_id` alone, which rejected a renewal mid-step. Ships concurrent renewal with named lease-loss diagnostics on agent and controller, a gate running one step across more than three lease terms, and a deliberately blocked-renewal gate. |

## Product hardening tickets (2026-08-18 code review)

Operational gaps surfaced by a whole-repository review of protected `main` at
the `CANARY-000` merge. None of these tickets touches sealed migration
evidence or grants any authority.

`DEPLOY-001`'s `DONE` cell remains a bounded implementation closure: one
hand-run service-managed arm plus the installed-runtime gate. `DEPLOY-003` has
since closed its manager-query, full-source-union, transition-lock, PID-identity,
and controlled per-PR systemd obligations. Its two accepted residuals are
carried explicitly below: point-in-time rather than TOCTOU-free validation, and
the external restart-time trust anchor now required by `DEPLOY-002`.

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| OUTBOX-001 | DONE | CTRL-001, CTRL-003 | The controller writes outbox rows in the same transaction as every durable state change, but no shipped binary drains them: `publish_outbox` is invoked only from `execution-spine` tests, so a deployed controller accumulates `published_at IS NULL` rows without bound. The 2026-08-19 scouted disposition is bounded retention with recorded no-consumer truth: keep the transactional write (the outbox is load-bearing for state-transfer receipt admission through the migration 0017 constraint trigger, and every row is triplicated into `build_events` and tamper-evident `audit_events`), add a fail-closed retention reaper in `bins/controller` that excludes `state_transfer.imported`, expose backlog observability, and amend ADR 0005 to record that no consumer is shipped and any future consumer arrives with its own contract bounded by retention. A publisher without a consumer and a mid-campaign retirement were both rejected with written rationale. Silent accumulation is not a neutral state. **Closure:** merged to protected main as `ec1529b` (PR #75). Bounded retention reaper in `bins/controller` excluding `state_transfer.imported`, backlog observability, and an ADR 0005 amendment recording that no consumer is shipped. |
| HYG-001 | DONE | — | Workspace hygiene with three bounded items. First, retire or absorb the placeholder crates `crates/domain` (14 lines) and `crates/state-machine` (18 lines, a stale second `AttemptPhase` definition diverging from the real phase truth in `controller-store` and `agent-runtime`); `bins/agent` must not depend on a placeholder. Second, give `crates/object-store` — the only core-plane crate with no integration test suite despite owning artifact immutability, quotas, redaction, and gap typing — a real `tests/` gate covering staged publication, quota enforcement, no-overwrite, and gap classification. Third, prove `OidcClientConfig::allow_insecure_loopback_for_tests` cannot be enabled from environment or configuration in the shipped controller binary with a permission-negative test. **Closure:** merged to protected main as `880fb2c` (PR #83). The placeholder `crates/state-machine` and its stale second `AttemptPhase` are gone and `crates/domain` is now the real shared vocabulary rather than a stub `bins/agent` depended on; `crates/object-store` has an integration suite covering staged publication, quota enforcement, no-overwrite, and gap classification; and a permission-negative test proves `OidcClientConfig::allow_insecure_loopback_for_tests` cannot be enabled from environment or configuration in the shipped controller binary. |
| HYG-002 | DONE | HYG-001 | Replace the closure gate's prose inference with a machine-readable attribution, and finish hardening the board parsers -- **closed**. The gate decided whether a `DONE` ticket had been reviewed by reading English in three structural shapes with a negation veto; four successive tightenings were each defeated by the same denial in a new wrapper, and the predicate's own docstring conceded that a denial phrased without a vetoed word would still pass. **What it was actually reading is worse than that.** SEVENTEEN of the thirty-eight credited reviews came from the table headed `Area` / `First implementation ticket`, which records which ticket first implemented an area and asserts nothing about a review; two more came from a register cell whose only cited document is another ticket's closure evidence. The predicate could be satisfied by structures asserting something else entirely, with no denial written at all. **What landed.** A `## Closure attribution` table whose two cells are fullmatched -- a ticket id, and a backticked path under `docs/` -- so a denial is not something the gate detects but a cell that is not a ticket id; the veto, its window and all three shapes are deleted rather than kept alongside it. Attribution is now checked BOTH ways: an evidence path that does not exist, and an attribution naming a ticket that never closed, are errors. **The migration is a disclosure, not a regression.** Credited reviews go 38 -> 19 and closure debt 31 -> 50; the nineteen tickets that lost a credit each lost one they should never have had, and each is recorded in `THREAT_MODEL_DEBT` with that reason. `THREAT_MODEL_DEBT_BASELINE` is widened once, deliberately, with the argument beside it -- the second time it has widened for this reason after the `MIG-002/006/007` block -- and the debt bound in `test_the_repository_never_slips_backwards` moves with its own argument, as that comment requires. A ratchet that could never widen would have forced the opposite choice: keep reading the ownership table as an attestation and keep the number at 31. **One correction to this row's own text**: it said 37 credited; the gate reports 38, and the thirty-eighth is `DEPLOY-004`, made so by `cced27e` -- work that preceded this ticket moved the number. Every check is mutation-proved: each one, removed, turns a named test red, and one mutation that proved nothing (it hit the wrong of two identical lines) is recorded in the receipt rather than quietly fixed. Closure receipt `docs/evidence/HYG-002_SECURITY_REVIEW.md`. |
| HYG-003 | PENDING | HYG-002 | Refuse claims that are true when written and false when read. `HYG-002` replaced one prose inference with a machine-readable attribution; this is the same principle applied to a class that review has now measured. PR #120 and PR #121 were documentation-only and drew **nine review rounds between them, every finding of this one shape and not one of them a code defect**. The population, each with its pre-fix text recoverable from history: `docs/handoffs/CURRENT.md` asserted the September freeze governed through 2026-09-30 after the owner had lifted it, which would have told the next custodian to refuse authorized work; two successive drafts declared the successor-head verification gate discharged at a named commit, each already wrong about its own successor because the merge that carried it moved the head; the comment above `EXPECTED_TABLES` in `scripts/verify-ticket-closure-receipts.py` restated the table counts held by the constant beneath it and went stale on the first ratchet raise; a Release Builder ledger said three runs while enumerating four, and counted pull-request-triggered runs whose number rises with every push, so it was stale by construction on the next one; and the September freeze recorded all of its evidence at `c17bbaf` while naming its own publication pull request the final September change, leaving the head it actually left behind described by no receipt. The repository already refuses exactly one phrasing of one of these: `scripts/verify-execution-board.py` rejects current-state prose that pins protected main to a forty-character commit. That rule is this class, caught once, and the ticket is to generalize it. Acceptance, fail-closed. (1) Record the population above with citations, because a convention argued from one anecdote gets waived at the second inconvenient case. (2) Generalize the existing pin rule across `docs/EXECUTION_BOARD.md` and `docs/handoffs/`: a document may RECORD that a named commit was observed in a stated condition at a stated time, and may not ASSERT that a named commit is currently the head, is current, or is verified now. That distinction is the whole ticket. Permissive by a word and the defect is re-admitted; strict by a word and every legitimate receipt is refused, which is the failure mode `DEPLOY-004` found by assigning a reviewer to hunt for refusals of correct work. The gate is therefore proved BOTH ways: red against the actual pre-fix text of the drafts named above, taken from history rather than synthesised, and green against the merged receipts that correctly record observations. (3) A count restated in prose beside the constant that holds it is refused, proved red against the pre-`HYG-003` `EXPECTED_TABLES` comment. (4) A governance document asserting a window that has since closed is refused, proved red against the pre-thaw `docs/handoffs/CURRENT.md`. (5) Where a case is not mechanically checkable it gets a written convention in `CONTRIBUTING.md` and explicitly NOT a gate that pretends to check it, because an unenforceable rule recorded as enforced is the failure this repository has already named six times. State which cases those are and why. (6) Every check is mutation-proved: removed, it turns a named test red, to `HYG-002`'s standard. (7) No false-alarm regression: the existing tree passes, or each refusal is argued in the receipt. **Bounded deliberately:** this does not re-audit the prose of closed tickets, does not touch sealed evidence, and grants no authority. It is a hygiene lane and may run beside the qualification lanes. |
| DEPLOY-001 | DONE | REL-001, CANARY-000 | `CUTOVER-001` must re-read every deployed implementation digest, yet `deploy/kubernetes`, `deploy/podman`, and `deploy/systemd` are README stubs and only the AppArmor profiles are real. Implement one supported production deployment lane — systemd units or podman quadlets for the controller and agent, with the database bootstrap as its own unit — with digest-pinned release artifacts, split migration/runtime database roles, explicit environment contracts, health checks, and a documented install/upgrade/rollback runbook. Acceptance: a scripted install on a clean host brings up the controller and agent and passes the deployable-runtime gate, and the cutover freeze can read every deployed digest from this lane without hand-assembled state. **Bounded deliberately:** the signed `REL-001` artifact packages `mcloving-agent`, `mcloving-cli`, and `mcloving-controller` only — those are the three installed into `components/bin` and the three recorded in `components.json`. This lane also needs `mcloving-identity-admin` for the database bootstrap, so this change adds it to the release build as a fourth component with role `migration_tool`; `mcloving-release-provenance` builds the bundle and is not packaged in it. The sealed helper executables the spine spawns — `mcloving-source-acquirer`, `mcloving-dependency-resolver`, `mcloving-cache`, `mcloving-input-adapter`, `mcloving-provisioner`, `mcloving-external-connector`, `mcloving-external-shadow-replay`, and `mcloving-destination-observer` — are outside that release, as is `mcloving-canary-qualification`, so this lane cannot install them from signed, digest-pinned artifacts and does not claim to. That gap is `REL-003`, which gates cutover. **Bounded service-managed evidence, 2026-08-27; this closes only the original implementation acceptance.** `deploy/test-deployment-systemd.sh` installs to a dedicated lingering service account's passwd home WITHOUT `--no-systemd` and lets the manager work: daemon-reload, Quadlet actually generating `mcloving-postgres.service` from the `.container`, the library's generated-name model checked against the generator rather than against a remembered example, `Requires=`/`After=` read back from the manager, `StateDirectory=` creating the agent workspace at 0700 unaided, `require_service_stable` against real units, `mcloving-health --unit` answering through the manager, and a service-managed upgrade AND rollback (`932de69ff63e` -> `a1eeefbc0b19` -> `932de69ff63e`, both services active at each end). Every one of those was previously asserted by nothing. Evidence `docs/evidence/DEPLOY-001_SYSTEMD_LANE.md`. **Two shipped defects found, both only findable by running systemd, both fixed here.** The documented install procedure's final step failed -- `systemctl --user enable --now mcloving-postgres ...` errors because systemd refuses to enable a Quadlet-GENERATED unit -- so the installer's printed text and `docs/operations/DEPLOYMENT_V1.md` step 5 were wrong and are corrected, with the corrected sequence now a gate. And `mcloving-upgrade` could not upgrade the lane it is written for: Quadlet stamps `Environment=PODMAN_SYSTEMD_UNIT=%n` onto every generated unit and the default-deny rule refused it; the rule now allows exactly that specifier, by value like `PATH`, since `%n` cannot designate another unit. **The second clause is met too, and it needed the gate fixed first.** The acceptance also says *passes the deployable-runtime gate*, and that gate RETURNED SUCCESS WITH NO ASSERTIONS when `MCLOVING_TEST_DATABASE_URL` was unset -- a silent skip inside an acceptance criterion, so the criterion was satisfiable by not running. It is now `#[ignore]`d, so a plain `cargo test` reports it as ignored rather than passed, and a missing database is a hard failure when it is invoked explicitly; both real invocations pass `-- --ignored`. It also takes an optional runtime URL, because a real deployment gives the migration and runtime roles DIFFERENT passwords and a single URL cannot derive the other -- that split being the very property the gate checks. The arm then runs it against THIS deployment's database and roles, read from the contract systemd starts the controller with, having first asserted the controller the gate spawns is byte-identical to the installed one. That assertion fired on its first run and was right: a later rebuild had moved the build tree out of step with the staged release. Both tests pass. **And the arm no longer takes the gate's word for it.** Judging that gate by exit status alone rebuilt the very defect above one level up -- a Rust test binary that runs NO tests exits 0, measured, so a rename out of `--ignored`, a deleted test or a stray filter would have printed `gate passed` having checked nothing -- so step 10 counts what executed and refuses fewer than two, by name. No reviewer raised that one. Evidence `docs/evidence/DEPLOY-001_SYSTEMD_LANE.md`. |
| DEPLOY-003 | DONE | DEPLOY-001, DEPLOY-004 | Bound the deployment lane's validation surface against the trust boundary now decided in `docs/architecture/DEPLOYMENT_TRUST_BOUNDARY_V1.md` and recorded as `TM-050`. `DEPLOY-001` merged after **162 review findings over 81 rounds** -- a flat 2.0 per round whose per-day rate (37, 39, 43, 43) never once declined -- with **83% of findings (134/162) in four validation scripts** rather than in the units, quadlets or contracts they validate. Every finding was valid, which is the point: a population that does not converge is a design property paid for one patch at a time, and under the owner's standing correction-round cap the response is this ticket rather than more rounds. The boundary decision is status quo taken deliberately -- the service account keeps its tree, because a root-owned root retires none of the thirteen consecutive rounds that never converged (those concern which unit systemd selects across sixteen load paths; measured, 3 are root-owned system directories, 3 are owned by the service account -- one of them the deployment's own unit directory -- and 10 are absent, so a root-owned deployment root reaches the unit directory but not the system paths or the `/run/user/<uid>` generator and transient directories that drop-ins also merge from) and because a local user can write nothing today under a sound ancestor chain. The lane therefore detects a misconfigured host rather than stopping an attacker with a foothold, and is scoped accordingly. It runs after `DEPLOY-004` rather than beside it: both rewrite the ancestor and validation logic in `deploy/bin/mcloving-deploy-lib.sh` and `deploy/test-deployment.sh` and both move the same `TM-050` boundary, which the Working rules require serializing before implementation rather than reconciling after review. `DEPLOY-004` goes first because it is the smaller change and closes a vulnerability open on `main`, and because this ticket's union validation rewrites the very walk `DEPLOY-004` repairs -- landing them in the other order would rebase a security fix onto a surface that had just moved under it. Acceptance, fail-closed: (1) the manager is ASKED for what it will do rather than modelled, closing the three obligations that received none of round 34's principle -- `show -p DropInPaths` returns the exact merged drop-in list in merge order, and `-p Exec*`/`-p EnvironmentFiles`/`-p WorkingDirectory` return systemd's own post-parse values, resolving every one of the five constructs the lane currently refuses by name, together **517 lines and 79 gates** of re-derivation; (2) unit selection is replaced by union validation -- every location the manager's own `UnitPath` could serve a fragment or drop-in from is judged, measured at 43 nodes in 2.6 ms, so precedence, replacement, masking and XDG ordering stop being load-bearing and cannot be modelled wrongly; (3) the retained obligations are O4 (glob is un-askable, measured: `EnvironmentFiles=` reports the wildcard literally, and the ancestor walk is the lane's own invariant) and O6 (artifact identity is not a systemd question), each with its reason recorded, and no other obligation retained without one; (4) **the suite is made able to exercise the manager-query path before any of the above lands** -- today 20 of 600 gates (3.3%) reach a real query because every ask is gated on the manager serving the target home and the suite installs into `mktemp -d` trees, so the suite currently specifies the fallback rather than the ask, and this is the first task rather than an afterthought; (5) `deploy/test-deployment.sh` otherwise passes unchanged, or every removed gate is removed with the finding it guarded named and re-argued, because that suite is the lane's specification and deleting a gate silently deletes a requirement; (6) the seven audit observations carried from the closure receipt are closed or explicitly deferred with reasons -- a mask answer that is asked for and then discarded in favour of a derived verdict that refuses the transition, an unbounded PID-recycling window on `ExecMainPID` -> `/proc/PID/environ`, four unlabelled derived fallbacks, an install-time integrity check taken outside the transition lock while upgrade and rollback take it inside, `mcloving-env-guard` re-walking ancestors under no lock, `NoNewPrivileges=` absent from the db-init unit and both quadlets, and no start-time verification of the unit, the guard executable, or the selected release binary, since systemd loads the unit before any `ExecStartPre` runs and the guard walks only the environment file and the configured secret and state paths; (7) no hardening directive is added without a runtime proof that it is in effect, because **thirteen systemd directives are measured accepted and silently ignored under a user manager on Ubuntu 24.04+ while the unit reports success**, in four classes -- nine needing a mount namespace, one needing a network namespace (`PrivateNetwork=`, which fails for a different reason and must not be remediated as a mount case), one needing BPF, two needing an undelegated cgroup controller -- `ProtectHome=tmpfs` left a home fully readable and a `ReadOnlyPaths=` target was overwritten -- and `systemd-analyze --user security` reports a checkmark for directives it has not verified are enforced. **Systemd-arm scope amendment.** The same failure population repeated in the service-managed arm added by PR #101: 21 findings across 11 review rounds, with 19 corrections landing in `deploy/test-deployment-systemd.sh` while the shipped product changes had already settled. The final findings came from the arm maintaining three divergent models of existing host state across probe, `--reset`, and teardown. The sharpest miss let a high-precedence `systemd/user.control` drop-in customise a unit while the arm continued to report clean-host evidence. PR #109 subsequently closed the two immediate reset regressions by verifying PostgreSQL volume removal and by cleaning and verifying both home and runtime manager load paths. One structural gap remains acceptance work here: reproducible per-PR evidence from an ephemeral systemd-capable host whose global unit paths are controlled; a fresh lingering account on a shared host is insufficient because root-owned `UnitPath` entries remain shared. The `PODMAN_SYSTEMD_UNIT=%n` allowlist already has mutation-checked CI coverage in `deploy/test-deployment.sh` and is not pending work. **Acceptance clause (8):** derive the arm host-state model once for probe, reset, and teardown, retaining union validation of shared global paths, or preferably make clean true by construction on an ephemeral host with controlled system paths and delete that mutable-host reconciliation surface; then reproduce the service-managed evidence.  This ticket grants no production or Jenkins authority and re-litigates none of the merged fixes; they are correct for the design that was, and the question was whether that design is the one to keep. |
| DEPLOY-004 | DONE | DEPLOY-001 | Validate the deployment home's OWN ancestors -- **closed**. `deployment_ancestor_chain` stopped at the deployment home for any path inside it, and every ownership rule in the library derived its expected uid from `stat` of the home -- so nothing above the home was validated by anything, and a substituted home became its OWN trust anchor: an attacker-authored unit with an arbitrary `ExecStart` passed `require_integrity_files`, the rule whose own comment promises to stop exactly that, and because the user manager runs that unit AS the service account the renamed-aside home's 0600 contracts and mTLS key were readable. Credential compromise, not merely arbitrary execution. Reproduced on `96ef05f`: a home sitting directly inside a 0777 directory was ACCEPTED, and so was a home this account does not own. **What landed.** The walk reaches `/` for the home's own chain as well as for every managed root, resolved COMPONENT BY COMPONENT in filesystem order so `..` survives until after symlink resolution rather than being collapsed lexically by `abspath`/`normpath` ahead of it; the directory HOLDING each intermediate symlink joins the chain, and each symlink's own inode is judged by `lstat` rather than through its target; every node arrives CLASSIFIED as one the lane merely traverses or one whose CONTENTS it enumerates, and the sticky exemption can reach only the first kind, and only where every entry the walk enters inside it already exists and is owned by root or the service account -- because `S_ISVTX` restricts renaming and unlinking other people's entries but NOT creating one, and drop-ins are merged, so a managed root at 1777 or a sibling root sharing a sticky ancestor with the home is one previously absent `.conf` away from arbitrary execution; the expected uid is pinned to `${EUID}`, the pin `require_secret_files` has always used, so the anchor can no longer be supplied by the tree it judges; and `mcloving-deployed-digests` records a traversed ancestor by mode, uid and gid alone, excluding size, mtime and ctime from both the record and the retry decision, so ordinary churn in a shared directory such as /tmp can neither move the digest nor exhaust the retries into `kind: unstable_entry` -- skipping `entries_sha256` alone would not have been sufficient, and the `CUTOVER-001` freeze stays verifiable. **Evidence.** Twelve scenarios measured against five library baselines: this branch, `96ef05f`, both earlier attempts (`9cda125`, `f457fcc`), and this branch's own pre-review state -- which is in the table because review found a hole in it. Twelve gates in `deploy/test-deployment.sh` carry ten of them, plus a chain-content assertion and a digest-sensitivity assertion. A refusal counts only where it NAMES its own offender: six of the twelve refuse on `96ef05f` for a wholly unrelated reason -- five naming a 1777 directory, one dying on an opaque `cannot statx` -- and three more are outright accepted. That ambiguity is where two of the five inherited findings had been sitting recorded as unverified. All five P1 findings that stopped those attempts are closed, and each has a gate that is RED against the library carrying it -- including the three round-2 findings the previous author could not verify: `..` after a symlink and the sibling-root sticky leak were ACCEPTED by both earlier attempts, and the trust-anchor inversion made `f457fcc` refuse a legitimate ancestor for being owned by this account instead of by the attacker. **One measured correction to the finding record**: the foreign-owned-symlink case is bounded by `fs.protected_symlinks=1`, the Linux default, under which the kernel refuses to follow such a link inside a world-writable sticky directory before any of the lane's rules run -- so its practical effect on a stock host is denial of service rather than substitution. The `lstat` rule is kept for hosts that disable that sysctl, and because a named refusal is worth more to an operator than an opaque `cannot statx`. **What review changed.** Two independent reviewers, one told to break the check and one told to find where it refuses CORRECT work, independently found the same real bypass: the sticky exemption's child scan piped `printf '%s'` through `tr` into `while read`, which drops the final unterminated field -- so a sticky ancestor with exactly ONE walked entry, the ordinary case, had ZERO children checked and the exemption collapsed to "the list is non-empty". Reproduced against the host's real `/var/tmp`. Three failures at once, and the third is the one worth carrying: the fail-closed guard written one line above the hole made it look handled, and **the evidence matrix was green for a reason unrelated to correctness** -- the sibling-root fixture's absent root sorted before its present one, so the checked child was the absent one by alphabetical luck. The scan now splits in the shell with no pipeline, the fixture is renamed so its absent entry sorts last, and a further gate covers the one-child case. The refusal's remedy text was also wrong for every offender above the home -- it said `chmod go-w`, which for /tmp is between useless and destructive -- and is now stated per clause. **Deliberate non-change**: `deployment_runtime_root` and the unit load-path derivation still read a uid from `stat` of the home. They SELECT where to look rather than deciding trust, everything they select is then judged by the classified walk, and that walk now refuses a foreign-owned home outright. Boundary record `docs/architecture/DEPLOYMENT_TRUST_BOUNDARY_V1.md`, threat entry `TM-050`, closure receipt `docs/evidence/DEPLOY-004_SECURITY_REVIEW.md`. |
| AGENT-007 | DONE | AGENT-004, AGENT-005, EXEC-003, EXEC-004 | Preserve running work through controller outages while the held execution lease still permits safe termination. The historical `84705da` outage finding and exploratory Jenkins comparison are retained in `docs/evidence/AGENT-007_SECURITY_REVIEW.md`; they are motivation, not sealed equivalence evidence. Answered fencing/session/renewal refusals still cancel immediately with distinct causes. Retry unusable renewal answers at the smaller of one second and the configured cadence, capped near expiry by the fixed response allowance. Set that allowance once per renewal cycle to the smaller of one second and half the initially remaining held cancellation budget; cap each pending RPC by the held cancellation deadline and count its wait toward retry cadence, without extending held authority until a valid renewal receipt. Bound the held term by request-start time plus the granted duration minus the full configured termination grace and one-second margin; clamp the periodic wake to that bound and reject timing configurations without a usable execution interval. Before spawning runnable work, explicitly renew for the requested agent term, regardless of folded-accept negotiation, so a shorter controller claim cannot be mistaken for a longer agent lease. Preserve processless refusal folding. Refuse already-cancelled execution before process spawn and check Windows cancellation before suspended-process resume. Prove short-outage success without replay/requeue, immediate answered refusal, and long-outage cancellation under `renewal_unanswered_until_expiry`. Use actual TERM-resistant leader/descendant identities, default and extended grace, and a mismatched initial controller/agent term; observe both processes absent before the stopped controller's persisted expiry. Require actual higher-fence relief execution after expiry and a named stale-retirement or discharge reply for the returning original journal. Process inspection failures must fail the proof; fixture cleanup must not orphan running work. Demonstrate the grace-removal mutation fails the actual-process gate, retain historical mutation evidence with its source qualifications, and independently review anchors and cancellation paths. Configuration validation and one additional pre-spawn RPC are deliberate behavior changes. No fencing, controller schema or protocol authority is broadened; no resume after agent death, hostile same-UID containment, production authority or sealed Jenkins parity is claimed. Bounded host scheduling/process-supervision assumptions remain explicit. Earned closure records the corrected runtime's protected merge and exact-main Foundation/native Windows verification in `docs/evidence/AGENT-007_SECURITY_REVIEW.md`; JCOMP-003 still needs its own reviewed execution freeze and campaigns. |
| UI-002 | DONE | UI-001, API-002 | Make the current web UI provable before anything replaces it. `UI-001`'s closure record asserts that **the browser journey gate proves the full desktop flow, strict-YAML validation, audit/explainability views, clean console, and a 390-pixel viewport without page overflow** — and no such gate runs. `crates/controller-api/examples/ui_browser_fixture.rs` is in the tree, a mock controller that serves the static UI with stubbed public routes and is plainly the target that gate was written for, and **nothing references it**: no workflow, no script, no test, and there is no browser driver in the repository at all. The one executing check, `static_ui_is_csp_locked_external_only_and_accessibility_structured` in `crates/controller-api/tests/route_denials.rs`, asserts on the served HTML **as text** — the locked CSP, the absence of external references, and landmark structure — and never renders anything. So "clean console" and "390 pixels without overflow" are claims no check in this repository can make, and none ever will: `UI-001` is named in both exemption sets of the closure-receipt verifier as pre-dating the receipt and threat-model conventions, so it carries no receipt, no attribution, and no share of the recorded debt. This is the absence-looks-like-success class the board has already named six times, and it is load-bearing now for a second reason: **the whole shipped UI is 639 lines** (`index.html` 161, `app.js` 424, `app.css` 54) embedded into the controller, there is no rendered artifact of it anywhere in the repository, and a replacement therefore cannot be shown to have preserved anything. Acceptance, fail-closed. (1) An executing browser gate drives `ui_browser_fixture` and is wired into CI with a pinned expected test count, exactly as the Rust suites are; a browser driver is introduced deliberately, pinned by version and digest, and the choice is argued rather than assumed. (2) The gate earns each claim `UI-001` made and could not support: the desktop flow across every view the client ships, strict-YAML validation refusal surfaced to the user, the audit and explainability views, a console with no errors, and a 390-pixel viewport with no horizontal overflow. It also covers the original accessibility claims in the rendered browser: landmark structure, actual label/control associations, keyboard-visible focus through the journeys and repeated live updates, and live-status changes. Each is a separate named assertion. The current fixture validator always returns `valid: true`; it cannot prove strict-YAML rejection. Earn that validation claim through the actual production parser/validation path, or label an injected refusal solely as UI error-rendering evidence and join it to a separate actual-validation gate. Where assistive-technology behavior cannot be checked mechanically, name the manual convention and retire or qualify the unsupported original closure claim rather than presenting a static markup assertion as browser or accessibility evidence. (3) Capture and retain a source-bound initial rendered baseline of every view and every observed failing assertion before repairs. Permit minimal served-client repairs necessary to earn the required browser and accessibility claims, including focus preservation across refreshes. Retain the pre-repair failures and baseline unchanged, then capture a separate accepted baseline bound to the repaired source for `UI-006` and later comparisons. After a repair, rerun the affected assertions and the full relevant browser and existing static-contract suites; a repaired screenshot alone is not verification. (4) Every gate is mutation-proved to `HYG-002`'s standard: removed, it turns a named test red. (5) Correct `UI-001`'s historical closure record with the exact evidence scope and repaired-source identity; do not claim the original implementation passed because its repaired successor does. Retain the named manual conventions or qualifications allowed in clause (2), but do not retire or weaken a required mechanically checkable assertion merely because it fails: repair that failure and rerun the gates before closing `UI-002`. **Bounded deliberately:** test infrastructure, versioned evidence and only minimal served-client repairs necessary for the required browser/accessibility contracts. No redesign, new view, route, CSP, authorization or threat-boundary change is included, and no authority is granted. It is worth doing whether or not any replacement UI is ever built, which is why it does not depend on the decision in `UI-003`. **Closed 2026-09-10.** The gate exists and runs: `scripts/test-ui-browser.sh` drives `ui_browser_fixture` through a pinned, digest-verified Chrome for Testing 153.0.8010.36 inside a contained namespace, makes **18 separately named assertions**, and is wired into the `ui-browser` Foundation lane with the count pinned -- and into `FOUNDATION_JOBS` and the aggregate's `needs`, so it blocks rather than being a lane nobody required. **The lane is conditional and its waiver is explicit.** It is the most expensive on the board -- the mutation proof is twenty-two browser runs -- so `scripts/ui-browser-impact.py` classifies each change into `run-ui-gate` (~6 min; any client, serving or gate-definition change) and `run-ui-mutations` (~28 min, twenty-two browser runs; a gate-definition change, or a client change of at least 20 lines), with `crates/pipeline-ir/` also requiring the gate because one assertion checks the real parser's refusal wording. A `paths:` filter was refused because a filtered job reports `skipped` and a skipped required check reads as a pass -- the `TM-052` shape -- so the lane follows the Windows-agent pattern instead: `ui-impact` is itself unconditional, its decision must be one of two literal strings, `true` demands `success` and `false` demands `skipped`, and the complete decision-by-result cross product is enumerated in `scripts/test-workflow-aggregate.py`. The cheap half of the mutation guarantee -- that every mutation still targets real client text -- runs unconditionally on every push in the Architecture records lane, so the mutation set cannot rot; what a sub-threshold change forgoes is the re-demonstration that each assertion fails when its property breaks, and that residual is named in the receipt. The driver and boundary choice is argued in `docs/architecture/UI_BROWSER_GATE_V1.md`. **The claims were not all true of the client `UI-001` shipped**: against the original source fourteen assertions passed and **four failed** -- keyboard focus destroyed on every dashboard refresh AND on the build view's own two-second timer, horizontal overflow at a 390-pixel viewport on two views, and a `favicon.ico` 404 logged on every page load. That pre-repair baseline is `docs/evidence/ui-002-browser-v1/README.md`, retained unchanged; the accepted post-repair baseline bound to the repaired source is `docs/evidence/ui-002-browser-v2/README.md`, which `UI-006` compares against. The repairs are served-client only -- no route, CSP, authorization or threat-boundary change -- and the same focus defect was fixed in `renderArtifacts` as well as `refreshBuilds` rather than only where it was observed. The strict-YAML claim is earned through the production path: the fixture now compiles submitted source with `compile_strict_yaml_with_parameters`, the same entry point `validate_pipeline` uses, so the rendered refusal is the real parser's wording. Every assertion is mutation-proved -- 21 mutations across 18 assertions, all caught, `docs/evidence/ui-002-mutation-v1/README.md` -- and `scripts/verify-ui-browser-gate.py` refuses drift between the pinned count, the emitted assertions and the mutation set. `UI-001`'s historical record is corrected below rather than restated, and its unsupported accessibility claim is **qualified, not retired**: assistive-technology announcement is a named manual convention, not a gate. **Review found the gate's own coverage was the weakest part of it.** Its first version made sixteen assertions, all green and all mutation-proved, while the entire artifact surface sat outside it: the fixture served `[]`, so `renderArtifacts` never ran, and the focus repair claimed for it had no evidence behind it -- the same absence-looks-like-success defect this ticket exists to correct, reproduced inside the work correcting it. No mutation could have detected that, because a mutation can only break code an assertion already reaches. The fixture now serves real artifact records, a seventeenth assertion drives the client's own timer rather than a clicked refresh, and running the completed gate against the original client showed a **fourth** pre-existing failure that the first version could not see. Threat model `TM-053`. Closure receipt `docs/evidence/UI-002_SECURITY_REVIEW.md`. |
| UI-003 | DEFERRED | UI-002 | Decide the browser trust and session model before any server-rendered UI is written. **Server-rendered HTML and a bearer-token API are in tension, and the tension is a threat boundary rather than a coding detail.** `UI-001`'s property is that the client uses only the documented public API, that the controller is the sole authorization authority, and that no privileged backend path, embedded secret, or client-side authorization claim exists. Rendering tenant data into HTML in the controller changes that shape in three ways that must be decided together. First, the controller gains a second representation of every resource and with it an **output-encoding boundary it does not have today**: every rendered value is an injection site, and JSON-to-DOM and server-rendered HTML do not fail the same way. Second, the browser must carry credentials on authenticated fragment requests, and the credential choices have distinct properties. The current client reads the token input into its JavaScript context and leaves the input value in the DOM; it is not a memory-only implementation. A **cookie session** and **bearer transport through an Authorization header** are both choices to assess. Bearer transport does not require embedding credentials in server-rendered HTML or DOM attributes, but it needs client code to attach the header: ordinary initial navigation cannot do so, and authenticated progressive behavior without scripting must be limited or use a separately decided mechanism. Assess XSS exposure, CSRF, token-entry handling, JavaScript/DOM copies and persistent browser storage separately for the chosen design; a transport choice alone does not settle those risks. The existing OIDC `SessionResponse` returns both an `access_token` and a longer-lived `refresh_token`, so the decision must explicitly cover storage, lifetime, rotation/revocation and XSS/CSRF exposure for both credentials. Moving only the access token into a cookie or memory leaves the refresh credential unresolved. Existing OIDC start/callback/refresh/logout routes do not decide the browser session model. Record the navigation and progressive-behavior costs without forcing a cookie session or token-in-document design. Third, whichever is chosen, **authorization must not be re-implemented in a view layer** — the HTML path has to run the same authorization code as the JSON path, and that has to be proved rather than asserted. The measured constraint the decision must respect: the shipped policy is `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, existing executing checks enforce parts of that CSP together with structural HTML, landmark, form and client-contract assertions; they do not establish rendered browser behavior. The shipped policy forbids inline script, inline style and evaluated strings. Any client library must therefore be vendored and served from the origin rather than a CDN, inline event-handler attributes are unavailable, and every library feature that evaluates a string is unavailable unless the policy is weakened. Acceptance, decision-shaped and fail-closed. (1) An architecture record that decides the session model, states the alternative it rejected and the cost it accepted, and does not defer the CSRF question to implementation. (2) A threat-model entry for the output-encoding boundary, with the register row and the attribution it requires. (3) The `UI-001` property restated in terms the chosen model makes true, so a later reader is not left comparing a new design against a sentence written for the old one. (4) The decision must preserve the shipped CSP for this lane, matching the unchanged-policy requirements of `UI-004` and `UI-006`. Any proposed relaxation requires a separate explicit owner decision and a coordinated board revision before implementation; it cannot be authorized implicitly by this ticket. (5) If a client library is chosen, it is pinned to an exact version and digest with its supported-upgrade story recorded, including whichever fallback applies if that version is withdrawn. **Bounded deliberately:** this is a decision and records it; no source, schema, route, asset or CSP change lands here, and it grants no authority. An implementation that changes the served UI is a separate ticket and must not be folded into this one, for the same reason `GROOVY-001` separates deciding the compatibility plane from building it. |
| UI-004 | DEFERRED | UI-003 | Bring the owner-selected client library into the tree under the policy that already exists. The owner selected **htmx 4** for a server-rendered interface; `UI-003` decides the trust boundary that selection sits inside, and this ticket does the acquisition once that decision stands. The constraint is measured, not assumed: the shipped policy is `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, existing executing checks enforce parts of that CSP together with structural HTML, landmark, form and client-contract assertions, while rendered browser behavior remains unearned. The shipped policy forbids inline script, inline style and evaluated strings. Three consequences follow and none of them is negotiable by convenience: the library is **vendored and served from this origin**, because a CDN tag is refused outright by `script-src`; inline handler attributes such as `hx-on:` are unavailable; and every feature that evaluates a string — value expressions with a scripting prefix, event filters, and the scripting extension — is unavailable. **The release is twelve days old at filing.** htmx 4.0.0 published 2026-08-28; on the public registry the 2.x line keeps the default tag until early 2027 while 4.0.0 is published under the npm `next` tag, htmx 2 is supported indefinitely, and upstream describes explicit attribute inheritance as the largest migration burden of the release. That is a recorded early-adoption choice, not a discovered one. Acceptance, fail-closed. (1) The library is embedded like the existing assets, with no runtime toolchain requirement, pinned to an exact version AND a SHA-256 that is verified where the other pinned digests in this repository are verified — a version alone is not a pin. (2) **The policy is unchanged.** A gate proves the interface functions with the shipped header in force, and separately proves that no inline handler attribute and no evaluated-string feature is used, so a later edit reintroducing one fails rather than silently requiring a weaker policy. (3) The upgrade and withdrawal story is recorded: which line is tracked, what triggers a move, and the named fallback if this version is withdrawn. (4) Each check is mutation-proved to `HYG-002`'s standard. **Bounded deliberately:** no view is migrated here and no representation is added; this ticket makes the library present, pinned and provably compatible with the policy, and nothing else. If `UI-003` decides against a client library, retain this ticket and its dependency edges and close it only as a reviewed decision-only, no-acquisition disposition under the normal closure gates. Its receipt must cite the decision, state that no library was acquired and no library-specific compatibility test ran, and preserve the unchanged CSP constraints for downstream tickets. `UI-005` can then depend on an honestly completed disposition; neither a fictional acquisition nor an unrecognized status is used. |
| UI-005 | DEFERRED | UI-004 | Add server-rendered representations behind the SAME authorization path, and prove they are the same. This is where the boundary `UI-003` decided actually moves, so it is the ticket that carries the proof. Today the controller answers one representation per resource; a server-rendered interface gives it a second, and the risk is not that the new one is missing a check but that it grows its own. Acceptance, fail-closed. (1) **Denial parity, proved by construction rather than by inspection.** Define a denial-applicability matrix for each resource and HTTP method given a rendered representation by this ticket. Consider unauthenticated, wrong tenant, wrong project, stale fence, retired session epoch and absent object against that method's actual authority model; record an explicit reason and policy reference for every not-applicable case, such as an organization-only audit route having no project parameter or a collection read having no object identity. Not-applicable does not mean untested: it cannot be used to omit a denial the existing route enforces. Drive the JSON and HTML counterparts through identical tests for every applicable denial and require the SAME refusal from both, preserving all existing authorization obligations. A representation that answers where its counterpart refuses is the defect this clause exists to catch, and removing the parity check must make a named mutation test fail. (2) **Every rendered resource route introduced here has an existing public API counterpart and uses the same authorization path**, enforced mechanically against the route table rather than by review. Do not require every API route to gain a rendered view here: filling the remaining interface coverage belongs to `UI-007`. A rendered-only resource with no existing authorized counterpart must be filed as separate API work before its view is introduced. Successful HTML must derive from the same authorized public response DTO or an equivalent field-by-field authorized projection, never an unfiltered controller/store record. Gate disclosure parity for every rendered field: presentation derived solely from authorized public values is allowed, but additional internal fields are not. For example, store `BuildSnapshot.execution_spec` is absent from public `BuildResponse` and must not become visible through HTML. Include a named mutation that introduces an internal-only field and prove the disclosure gate refuses it; shared authorization and escaping alone do not establish this property. (3) **Output encoding is proved against hostile values**, not asserted: a corpus of injection-shaped strings is carried through every rendered field of every view — names, slugs, log lines, failure reasons, audit payloads, artifact paths — and the rendered document is checked to contain them inert. Log and failure text are the sharpest cases because they are attacker-influenced by construction, and they get their own named cases. (4) Whatever credential shape `UI-003` chose is implemented exactly as decided, with its stated defence — if that decision was a cookie session, its cross-site request defence is gated here and proved to refuse a forged request; if it was bearer transport, the gate proves neither access nor refresh credentials are embedded or reflected by the server into rendered HTML or attributes, while actual token-entry handling and browser DOM/JavaScript/storage copies conform to the explicit `UI-003` contract. A user-entered token field must not be confused with server reflection or silently exempted from the chosen handling requirements. (5) `crates/controller-api/tests/route_denials.rs` keeps every assertion it has today. (6) Each check is mutation-proved. **Bounded deliberately:** representations of resources that already exist, and nothing new — no view is migrated, no missing interface is added, no route is invented. The authorization code is reused, never re-implemented; a second implementation of an authorization decision is out of scope by construction, not by discipline. |
| UI-006 | DEFERRED | UI-005 | Migrate the six views that ship today, one at a time, against the accepted source-bound baseline `UI-002` captured, retaining both its initial and accepted baselines unchanged. The shipped interface is `crates/controller-api/ui/index.html` at 161 lines, `crates/controller-api/ui/app.js` at 424 and `crates/controller-api/ui/app.css` at 54, drawing the dashboard, pipeline, build, audit and explainability views plus the context form. A rewrite of a client that had no rendered artifact of itself would be unfalsifiable, which is exactly why `UI-002` comes first and why this ticket is written against its output rather than against an impression of what the old client did. Acceptance, fail-closed. (1) The reusable `UI-002` browser gate passes against the migrated implementation, with comparisons to its unchanged accepted baseline **view by view**, each view landing as its own reviewable step rather than one replacement of everything. (2) Every behavioural difference from the baseline is **enumerated and argued in the receipt before it merges** — a difference discovered afterwards by a user is a regression, and the same difference argued beforehand is a decision. This clause is the whole point of the ticket. (3) The client script shrinks to what genuinely cannot be served as a document, and what remains is justified line by line rather than carried across out of habit. (4) The policy is unchanged, and the `UI-004` unchanged-policy constraints and the applicable proof that no inline handler or evaluated-string feature is used still hold over the migrated views, including a no-library disposition. (5) Progressive behaviour is stated and gated: whether a view functions with scripting unavailable, and if not, which and why. If a client library was selected, state and test the behavior when it is unavailable. If `UI-004` closed with no library acquired, test the chosen ordinary browser behavior instead; do not assume a client-library implementation. (6) Each gate is mutation-proved. **Bounded deliberately:** the six views that exist, and no others; interfaces for routes that have none today are `UI-007`. No new public route, no schema change, no authority. |
| UI-007 | DEFERRED | UI-006 | Give an interface to public operations missing from the current client. The filing inventory must distinguish HTTP methods and operations, not just resource names. The current interface covers builds, a build, its graph, logs, tests, artifact listing and content download, approvals, audit, explainability, validate, plan, cancellation, pipeline PUT/submission and pipeline-state GET/PUT. It does not call attempt retry (`POST .../attempts/{attempt_id}/retry`), component listing/detail (`GET .../components` and `GET .../components/{digest}`), or component publication (`PUT .../components/{digest}`). These belong in the missing-interface set alongside sign-in (`auth/oidc/{provider_id}/start`, its callback, session refresh and logout, all four unused since they were built), the `performance` tenant-transaction counter (guarded by `SchedulerControl`, not scheduler-capacity or build-history data), triggers with their events and delivery redrive, source discovery with its children and scans, artifact uploads and the separate `GET .../artifacts/metadata` operation (not the existing artifact listing), credential grants, or pipeline catalogue/detail GET operations (not the existing pipeline PUT and state controls). An operator cannot see who a build authenticated as, why the scheduler placed it, what triggered it, what it was granted, or what pipelines exist. Further desired screens require an explicit data-source review: **an agent view**, **scheduler capacity and placement**, and a **build history trend**. The concurrency model is N agent processes, but the `performance` tenant-transaction counter cannot supply agent inventory, capacity, placement or historical build data. Reuse adequate existing authorized resources, including build list/detail data where sufficient; file any missing data/API work separately and complete the required prerequisite before implementing the affected view. This ticket does not invent those routes or treat the counter as their data source. Acceptance, fail-closed. (1) Retain a method-level inventory joining every public route and HTTP method to actual client calls, browser-journey evidence and its coverage disposition. The inventory may mark an operation missing while work is open. At closure, every operation identified above or by that reconciliation must be covered or explicitly deferred with a reason tied to an approved scope/board decision and cited in the receipt; any unresolved missing operation keeps `UI-007` open. A GET does not cover the same resource's PUT or POST, and a category label cannot stand in for this inventory. Silence about an operation is not a deferral. (2) Extend the reusable browser gate introduced by `UI-002` to every new view on the same assertion terms as the migrated ones. Capture added views in a distinct versioned baseline bound to the exact `UI-007` source; retain the `UI-002` initial and accepted baselines unchanged, without adding later views to their historical evidence. Every representation added by `UI-007` must also pass the existing `UI-005` representation gates. (3) Any public route this needs that does not exist yet is **named in this ticket's own record and filed as its own work** rather than added quietly alongside an interface, because a route is an authority surface and an interface is not. (4) Sign-in is implemented exactly as `UI-003` decided and adds no second credential path. (5) Each gate is mutation-proved. **Bounded deliberately:** interfaces for existing authority, not new authority. No route gains a capability here, no configuration-by-form is introduced — the competitor's per-object configuration screens are the root of the mutable-file sprawl this system does not have, and are refused on purpose. |
| UI-008 | DEFERRED | UI-007 | Show a running build without polling for it. The interface currently re-asks for build status and log content on a timer, which is the same shape as the competitor's fixed poll quantum and costs the controller a request per viewer per interval whether or not anything moved. Serialized behind `UI-007` rather than beside it because both rewrite the same rendered views and the working rules require serializing a shared surface before implementation rather than reconciling it after review. Acceptance, fail-closed. (1) Build status and log tailing advance without a client-side timer, under the **unchanged** policy — which rules out any transport needing an evaluated string or an inline handler, and that exclusion is gated rather than remembered. (2) **Degradation is a requirement, not a fallback story**: when the live transport is unavailable or refused, the view returns to asking on a timer and remains correct, and a gate proves it rather than a paragraph promising it. (3) A gate proves a running build's log advances in a real browser and that a dropped connection recovers without duplicating or losing a line — a live log that silently drops a line is worse than one that polls. (4) Before implementation, preregister and review a comparison against the shipped two-second polling baseline under equivalent viewer counts and update rates, covering idle and active builds. Specify delivery correctness and freshness requirements alongside controller and database work, including any polling performed internally by the live transport and work shared across viewers. For each scenario, choose an explicit reviewed improvement target or a justified maximum-cost bound relative to the measured baseline; do not select the threshold after observing the replacement. The gate must require the chosen cost bound and delivery correctness/freshness requirements together, so dropping or delaying updates cannot masquerade as reduced load. Retain the comparison and measurements; recording cost alone does not satisfy acceptance, and exceeding a bound or failing delivery requirements keeps `UI-008` open. (5) Authority is re-checked on the live path exactly as on the request path: a viewer whose session ends mid-stream stops receiving, proved by a gate, since a long-lived connection outliving its authorization is precisely the shape that request-scoped checks miss. (6) Each gate is mutation-proved. **Bounded deliberately:** live delivery for build status and logs. No new resource, no new authority, no schema change, and no change to what a viewer is permitted to see. |
| UI-009 | DEFERRED | UI-008 | Re-earn the accessibility and viewport claims against the interface that actually ships. `UI-001` asserts that **accessibility contracts cover landmarks, labels, keyboard-visible focus and live status**, and that the journey gate proves **a 390-pixel viewport without page overflow**. `UI-002` earns those for the client that exists today; this ticket earns them again for the one that replaces it, because a claim proved against a deleted implementation is not evidence for its successor — and because a server-rendered interface moves exactly the things those claims are about: focus after a fragment swap, whether assistive technology is told that a region changed, and whether a swapped region keeps the landmark structure the document started with. Acceptance, fail-closed. (1) Landmarks, labels, keyboard-visible focus and live-status announcement hold across **every** view, including the ones `UI-007` added, and each is a separate named assertion rather than one aggregate pass. Compare each view to the appropriate retained versioned baseline: the accepted `UI-002` baseline for original views and the source-bound `UI-007` baseline for added views. Bind current observations to the exact successor source and record differences without rewriting either earlier baseline. (2) **Focus and announcement across a swap** are gated in their own right: after a fragment replaces a region, focus is somewhere a keyboard user can continue from, and a region that changed says so. This risk also exists in the current client: refreshes call `replaceChildren` and recreate artifact download buttons. The `UI-002` baseline and this successor gate must both check focus and live-status behavior across repeated updates; a client-side replacement is not evidence that focus was preserved. (3) The 390-pixel viewport holds with no horizontal overflow on every view, proved by the browser gate rather than by a stylesheet reading. (4) Where a contract cannot be checked mechanically it gets a written convention and explicitly **not** a gate that pretends to check it, with the cases named — an unenforceable rule recorded as enforced is the failure this repository has already named six times. (5) Each gate is mutation-proved. **Bounded deliberately:** the contracts `UI-001` already claimed, proved against the current implementation. No new view, no new route, no visual redesign, and no authority. |

### DEPLOY-003 closure (2026-08-31)

This closure amendment supersedes the row's historical pre-implementation
phrases that all five refused constructs would be resolved, only O4/O6 would
remain local, 3.3% manager coverage was current, and the controlled-host arm
remained pending. The row is preserved as the acceptance record; the measured
result and residual disposition below are the current state.

The acceptance above is closed by `docs/evidence/DEPLOY-003_SECURITY_REVIEW.md`.
The deployment lane now consumes typed manager D-Bus properties for composed
unit truth, validates the complete manager `UnitPath` fragment union and the
independent Quadlet source union, repeats install integrity under the exclusive
transition lock and after `daemon-reload`, and binds service-environment reads
to a held `/proc` descriptor plus a stable manager invocation/PID/start tuple.
The protected `Deployment lane` runs the real service-managed arm under a
disposable account with controlled unit, generator, HOME/XDG, and container
configuration inputs. Account commands use direct UID/GID transitions rather
than PAM-opening `sudo -u` sessions, and the disposable manager drop-in invokes
the user manager directly through `env -i` without a shell or inherited
executable lookup, so neither the system manager nor PAM can add to the exact
manager process environment. Its controlled PATH must equal systemd's compiled
user-manager default before startup. Every installed user environment
generator is masked before startup so later manager reloads cannot repopulate
the block from hosted image configuration. The account is created without a
skeleton home; its empty disposable home then has inherited access/default ACLs
removed and its exact owner, 0755 mode, and three-entry ACL proved before any
account child is created, so a host `/home` default ACL cannot silently defeat
the arm's umask.
After the fresh manager reaches a quiescent running
state, the job uses its private socket to install and prove an exact
fourteen-entry environment before starting packaged D-Bus, so the daemon
inherits only that block. It then atomically replaces the typed manager
environment over D-Bus and reads it back by exact count and value before any
Podman operation. Its shared early
preparation removes group/world write only from the known image-owned
`/usr/share` union roots and explicit `/usr/local` Podman/Quadlet chain and
regular executables after their image-provider digests match the reviewed pins; its
unchanged preflight then accepts only Ubuntu's `/usr` Podman/Quadlet layout or the hosted
runner's version-matched `/usr/local` static-bundle layout,
validates the exact root-owned generator target, and refuses overrides, mixed
layouts, or writable inputs without invoking Podman before the generated
volume unit. Immediately before the short-lived account exists, the disposable
job changes the exact image-owned runner home from 0750 to 0751, granting only
the search permission needed to traverse to its reviewed build/release inputs,
then restores 0750 on every exit path.
Property-labelled typed manager command tuples then bind every
generated start and present stop command to the selected absolute Podman path,
and its version is compared with Quadlet after cold start. That arm proved
the exact hardening split: `NoNewPrivileges=yes` and a kernel bit on the three
compatible native services, deliberately absent on the two generated Podman
services after a separate fresh-account implementation probe measured the bit blocking rootless
`newuidmap`/`newgidmap` namespace creation. The generated volume unit performs
the account's first Podman operation; the arm then proves rootless PostgreSQL,
ordered controller/agent start, health, upgrade, rollback, and both runtime
integration tests.

One architecture-note premise was corrected by measurement: systemd 255 leaves
a bare executable bare in its typed `ExecStart` tuple. The lane retains its
named non-absolute-executable refusal rather than guessing systemd's internal
search path. Audit observations 1–4 are closed; observation 6 is dispositioned
below. Observation 5 remains the
documented point-in-time/TOCTOU residual because taking the transition lock in
`ExecStartPre` would deadlock the transition that is waiting for the service.
Observation 6 is therefore closed on the native services and explicitly,
empirically deferred on the generated Podman services. Observation 7 requires
a mandatory verifier outside the replaceable
service-owned unit/tree and is now an explicit `DEPLOY-002` acceptance blocker;
until that external anchor lands, ordinary or crash restart after permission
drift is not claimed as protected. No production or Jenkins authority is
granted by this closure.

## Compatibility-plane decision (2026-09-06 Fogell campaign)

A measurement campaign run on Fogell on 2026-09-05 and 2026-09-06 proposed that
McLoving absorb Fogell's Groovy parser and structurally-sandboxed interpreter,
on the grounds that McLoving "has no interpreter and provably evaluates no
Groovy". The second half of that sentence is accurate and is not an oversight:
it is `ADR 0006` taken deliberately, and it is the mitigation `TM-020` claims.
Whether to give it up is an architecture decision, not an import, so it gets a
ticket before any code crosses.

Those measurements are Fogell-side evidence. Under `docs/related-work/FOGELL.md`
rules 1 and 2 they may shape this ticket's design and its expected outcome, and
they license no McLoving claim, tier assignment, or board status.

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| GROOVY-001 | DEFERRED | — | Answered NO on 2026-09-10 by the amendment to `ADR 0006`, which lists the permanently unsupported constructs and dispositions the measured malformed-quoting over-acceptance defect: nothing is absorbed, McLoving's compiler refuses the input naming its offender, and the compiler-exposure ticket of the parity phase must add the negative fixture. The row is DEFERRED rather than DONE because that fixture and this ticket's closure receipt are not yet earned; the residual is tracked there, not dropped. Original text follows. Decide whether McLoving evaluates Groovy, and if so under what trust boundary -- a decision, with no interpreter code crossing in this ticket. `ADR 0006` chose an isolated, pinned, deterministic compiler with sealed provenance and accepted a lowering tax to get it; `docs/architecture/JENKINS_COMPILER_WORKER_V1.md` records that Groovy is used only to construct a CONVERSION-phase AST; and `TM-020` mitigates "compatibility worker executes untrusted Groovy" with the words *never evaluated*. An interpreter retires that sentence, so the threat entry is not amended around the change: it is re-derived against whatever boundary replaces it, or the decision is NO. Fogell's founding measurement was a 74.3% lowering tax against exactly this shape, and its `fogell:docs/adr/0002` answers it by interpreting the AST directly; `docs/related-work/FOGELL.md` already records that only differential receipts and `docs/adr/0011-performance-contract.md` can arbitrate between the two positions. The 2026-09-05/06 campaign is the first evidence that bears on it, and it does not support the tax being a product-level cost: across six real OSS builds McLoving beat the pinned Jenkins oracle by more than Fogell did, the trivial-step microbenchmark ranked the two engines in the opposite order from real work, and under six concurrent builds the engine choice and no engine at all were indistinguishable. None of that is a McLoving receipt and none of it decides this ticket; it is why the ticket exists rather than the answer. Acceptance, fail-closed. (1) An ADR that records the decision and its consequence for compatibility scope, in one of two shapes: NO, McLoving continues to compile rather than evaluate, and the ADR states plainly which Jenkinsfile constructs are therefore permanently out of scope rather than merely unimplemented; or YES, with the execution trust boundary named and `TM-020` re-derived against it. A YES that leaves `TM-020` reading *never evaluated* is not a decision, it is a contradiction with a merge commit. (2) A YES additionally requires a threat-model entry for evaluating attacker-authored pipeline source, and it must state the isolation the boundary actually has rather than the isolation it wants: neither project today has hostile-tenant execution isolation, Fogell's own threat model records that a VM boundary is required for it, and McLoving's hardened rootless-Podman worker is closer but is not that boundary either. (3) Either shape must state what happens to the over-acceptance defect the campaign measured, because an absorbed interpreter inherits it: given a Jenkinsfile whose quoting is malformed, the pinned Jenkins oracle refuses it at compilation and runs nothing, while Fogell parses it and executes two stages including a real Maven invocation. That is fail-open admission, and it is the exact inverse of the property `ARCH-002` proves at every schema level today. No differential case covers it in either project. A YES therefore requires a McLoving differential case that reproduces it and FAILS against any candidate interpreter before that interpreter is eligible for a port ticket -- a refusal that does not name its own offender does not count, and a case that passes for the wrong reason is why this is stated as a red-first gate rather than a checklist item. (4) Any port that follows is a separate ticket with its own review, threat-model and evidence gates, as `docs/related-work/FOGELL.md` rule 4 already requires; this ticket does not pre-authorize it and does not estimate it. (5) This ticket grants no production, canary, cutover, credential, or Jenkins authority, and closes none of the open compatibility work. |

## Migration campaign tickets

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| JCOMP-001 | DONE | MIG-003, DIFF-001 | Define a versioned executable contract for Linux sequential Declarative pipelines: pipeline, agent any mapped to a contained Linux worker, named sequential stages, and one or more literal sh steps per stage. Pin the existing Jenkins oracle core/plugin profile and source identities; lock fixture expectations and comparison/normalization rules before collecting results. Specify at least ten supported-input fixtures covering multiple stages, multiple steps, quoting, multiline scripts, workspace continuity, and first/middle/last-step failures (expected build failure is a positive compatibility case). Add separate negative fixtures for Scripted Pipeline, dynamic interpolation, plugin steps, and unsupported directives. Keep authored fixtures and the 228-source corpus as separate denominators. Exclude production effects, credentials, live SCM, Windows translation, generalized shared libraries, parallel/matrix execution, unsupported directives, and expanded history migration. Implementation: `docs/architecture/JENKINS_SEQUENTIAL_DECLARATIVE_V1.md`, the sequential-v1 fixture manifest, and `scripts/test-jenkins-sequential-contract.sh` preregister 10 authored supported, 12 negative, and one historical expectation. Local checks verify 23 records, all 17 mutation tests, and 11 pinned Groovy literal comparisons; these are authoring checks only. Review: `docs/evidence/JCOMP-001_SECURITY_REVIEW.md`. PR #127 merged as `533dbff671b5a2d58e4d92339708375601d5b7d2`; exact post-merge Foundation `34306662841` and native Windows `34306662842` passed. This subsequent update records earned closure; no generalized compilation or execution claim is added. |
| JCOMP-002 | DONE | JCOMP-001 | Generalize isolated compilation and independent Rust admission for the JCOMP-001 contract beyond the single pinned hello-world source identity. Preserve source/profile provenance, bounded parsing, versioned IR and canonical YAML validation, and disabled imported operational state. Unsupported input must produce deterministic diagnostics and schedule no work. Verify supported syntax and semantic lowering with the contract fixtures and independent rejection tests; do not broaden operational authority or replace historical migration receipts. Keep generalized output compile-only and imported jobs disabled until runtime prerequisites JCOMP-002A and JCOMP-002B land; preserve product admission guards so accepted-for-execution still means runnable. No new production API is planned. Completed compiler implementation: additive protocol/compiler v2, grammar-based source recognition, independent Rust source-to-YAML/IR admission, disabled document provenance, and immutable-image launch receipts. The fixed compiler campaign is separate from runtime and 228-source classification evidence. Review: `docs/evidence/JCOMP-002_SECURITY_REVIEW.md`. PR #128 merged as `904fd1fed083cd17a6fc371e0a300c3696d93483`, tree `26240208f51f6028bf6bb6e619a2dcd5d19555f0`, matching reviewed head `3d9ca5f`. Exact-main Foundation `34317917356` and native Windows `34317917395` passed. This subsequent update records earned compile-only closure. |
| JCOMP-002A | DONE | JCOMP-002 | Deliver actual sequential execution of every literal shell step under the JCOMP-001 contract through the controller and agent, preserving stage/step identities and durable terminal results. Each step uses a fresh shell; environment changes and working-directory changes do not leak to later shells. Prove first/middle/last-step failure stops later steps and stages, with explicit skipped results and correct build aggregation. Preserve lease/fence, cancellation, retry and recovery semantics with focused tests and independent review. Removing the one-step admission guard or concatenating commands into one opaque shell is insufficient. Keep unsupported workspace-dependent cases execution-ineligible until JCOMP-002B; compile-only acceptance grants no execution or production authority. Architecture: `docs/architecture/SEQUENTIAL_STEP_EXECUTION_V1.md`; closure: `docs/evidence/JCOMP-002A_SECURITY_REVIEW.md`. PR #130 merged as `c2aaa0da6aaf5f5a5800bca252fd0514584f56fa`, tree `77bc88fa006123ab72ae497334c1733dc0ac749b`, matching final head `d7be0f7`. All eight protected checks and independent review passed; exact-main Foundation `34351767851` and actual native Windows `34351767843` succeeded. The contained four-store/six-agent campaign proves this bounded runtime; workspace continuity and paired Jenkins execution remain unearned. |
| JCOMP-002B | DONE | JCOMP-002A | Deliver build-workspace continuity across steps and stages for the JCOMP-001 contract in disposable contained fixtures, using an explicit build lifecycle or verified state transfer. Define agent placement/transfer, controller/agent ownership, unique per-build namespace allocation, bounded storage, fence/lease-loss handling, cancellation/recovery, and whole-build cleanup. Prove earlier workspace files remain available to later fresh shells, separate builds are never assigned the same workspace or each other's state by the controller/agent, stale ownership/fence lifecycle operations are refused, and final outputs are observed before cleanup. Merely reusing an attempt path or disabling cleanup is insufficient. Exercise the actual controller/agent with focused lifecycle tests and independent review before broadening runnable admission. This ticket proves lifecycle continuity and non-collision, not denial of direct filesystem access by hostile same-UID workloads; sibling-workspace read/write isolation and general workload containment remain SEC-005. No production containment closure or operational authority is granted. |
| JCOMP-002C | DONE | JCOMP-002 | Correct independently reproduced negative diagnostic precedence disagreements for the six original corpus cases 018, 019, 023, 065, 160 and 162 retained as unverified by the JCOMP-003 capture. Use concrete reduced source regressions and a mutation restoring the disagreement; require exact-source agreement between the bounded Clojure worker and independent Rust admission for the corrected negative outcomes. Preserve unknown or unproved forms as unverified, all source identities, the supported grammar, full Groovy parsing and AST checks before admission, disabled definitions, and the original 23-fixture contract. Do not add an admitted form, runtime behavior, source allowlist, production authority or borrowed corpus classification. Preserve pre-correction failures and independently review the bounded source change and focused evidence. Earn protected merge and successful exact-main Foundation/native Windows gates before closure; JCOMP-003 then refreshes its freeze and captures. Review record: `docs/evidence/JCOMP-002C_SECURITY_REVIEW.md`. Earned on PR #135 merge `01137b54b8fbefdc0deb0214a5d4d8979a773575` with exact-main Foundation `34450761533` attempt 1 and native Windows `34450761576` attempt 1 successful; retained receipt `docs/evidence/JCOMP-002C_CLOSURE.json`. |
| JCOMP-003 | DONE | JCOMP-002B, AGENT-007, JCOMP-002C | Earn the JCOMP-001 claim with paired execution on pinned disposable Jenkins and the actual McLoving controller/agent through explicit contained submissions, preserving disabled imported job state. Require verified step-execution and workspace prerequisites from JCOMP-002A and JCOMP-002B before collecting evidence, and certify that exact runtime. Any campaign finding requiring runtime changes must return to a separate bounded implementation ticket and regenerate affected evidence before closure. Run all contract fixtures including the original corpus-052 source; require zero unexplained differences in stage/step order, shell arguments, terminal results, downstream skipping, normalized logs, and workspace outputs. Negative fixtures must schedule no work. Reclassify all 228 original corpus sources with the new compiler and publish supported/rejected counts and reasons separately from authored-fixture execution coverage; compilation alone is not runtime parity. Retain exact source/profile/compiler/runtime identities and reproducible evidence under a new versioned differential contract and report without overwriting historical receipts. This certifies only the exact contained milestone runtime; subsequent runtime changes require fresh evidence under the existing case recertification and late-correction rules. No production endpoints or credentials may be reachable; unsupported behavior remains explicit. Fresh f263ad4 captures now have an independently verified paired report and complete original-corpus classification; retained evidence and offline CI checks are recorded in `docs/evidence/JCOMP-003_SECURITY_REVIEW.md`. Earned on PR #136 merge `ca79f7b4c5573c17f9bd7607f47c65f13f683840`, exact-main Foundation `34456846575` and native Windows `34456846592`, with the byte-preserved audit in `docs/evidence/JCOMP-003_CLOSURE.json`. |
| INV-001 | DONE | API-002, AUDIT-001 | Produce an immutable controller/job-graph manifest for every in-scope Jenkins controller: core and plugin profiles, controller-global environment/tool/managed-file/plugin settings, folders, matrix jobs, Multibranch Pipeline and Organization Folder parents/children and discovery configuration, job definitions, Jenkinsfile or inline source, shared-library references, enabled/disabled operational state with generation/reason/actor, trigger declarations, platform/agent label/toolchain requirements, effective node authority, artifact/test publication, and owner. Bind canonical source location, content digest, export implementation/version, controller identity, collection time, and provenance; reconcile parent/child counts and live configuration digests; secret-scan before persistence; and record retired or out-of-scope objects only with owner approval. |
| INV-002 | DONE | API-002, AUDIT-001 | Produce an immutable identity-and-client manifest: exact Jenkins security-realm implementation/configuration and upstream identity-provider generation; immutable user/group identifiers, aliases and rename history, membership provenance/generation, lifecycle state and collision rules; effective folder/matrix/job ACL entries; every external read-side consumer; and every effective administrative writer regardless of authentication mode. Include named clients and service identities, anonymous/public principals, unauthenticated endpoints, legacy tokens, seed execution, Jenkins Job Builder, JCasC/Terraform, CLI, REST, and direct/plugin APIs. Bind endpoint/action/query contracts, canonical caller identity or observed source, authentication and authorization behavior, scope, owner, observed use, and live generation. Reconcile every ACL principal, reader, and writer, reject name-only or ambiguous identity, and preserve disabled/deleted and deleted-name-reuse evidence. |
| INV-003 | DONE | API-002, AUDIT-001 | Produce an immutable runtime-dependency manifest per job: public/secret parameters and confidentiality, credential references and exact consumer/taint classification without secret material, source checkout, workload dependency repository/lock policy, approval/input policy, every trigger class, live external read, mutable agent-local file/mount/host input with canonical path/origin/content digest/refresh policy, agent image/capability/trust pool, cache mapping, external effect, dynamic provisioner, shared lock/throttle, controller-global runtime value, and Jenkins built-in environment dependency. Bind owner, implementation/configuration identity, endpoint/account/resource scope, mutability, provenance, and supported/unsupported disposition. Replace embedded or encrypted values with reviewed typed redaction references and protected-evidence keyed digests. |
| INV-004 | DONE | OPS-002, OPS-003, AUDIT-001 | Produce an immutable persistent-state-and-evidence manifest per job: build-number and previous-result dependencies, per-build SCM revision/previous-revision/changelog baselines, cross-build artifact lookups, retained workspaces and mutable state, build/log/artifact/test/audit history, retention policy/deadline, legal holds with identity/scope/reason/generation/release authority, and external consumers of that history. Bind record counts, source export and content digests, ownership, confidentiality, restore/rollback target, conflict policy, and provenance; reconcile live state and prove protected evidence retains every required original without leaking secret material into the repository. |
| MIG-000 | DONE | INV-001, INV-002, INV-003, INV-004 | Reconcile the four immutable inventory manifests into one owner-reviewed production population and eligibility ledger before compiler or corpus design. Every controller, parent/child job, operational state, source principal/ACL, read/write client, runtime dependency, persistent-state record class, retention/hold obligation, and owner must resolve exactly once or carry explicit owner-approved retirement. Before closure, bind every manifest to one coherent immutable controller snapshot/export epoch that includes the effective global configuration, job definitions and operational generations, security realm/ACL generation, client/runtime-dependency generations, and persistent-state snapshot or cursor. If Jenkins cannot supply one atomic source epoch, quiesce all affected configuration, identity/ACL, client, runtime-dependency, job-state, retention/hold, and persistent-state mutations; collect or re-export all four manifests inside one bounded epoch; then re-read and match the source generations and content digests before releasing quiescence. Any intervening drift discards the mixed manifests and requires a new complete four-manifest export. Cross-manifest identities, references, generations, content digests, and counts must agree; source/export/manifests are content-hashed and provenance-bound; secret scans pass; missing stable identity, mutable or unresolved dependency, unclassified state/effect/input/credential consumer, unsupported rollback obligation, manifest conflict, or mixed source epoch is an explicit blocker. Publish immutable coverage denominators, corpus strata, state-transform demand, parity-substrate demand, and per-job native/mappable/scripted/unsupported eligibility without granting execution or effect authority. |
| MIG-001 | DONE | MIG-000, API-002, SEC-003 | Build an isolated Jenkins import/compiler worker for the exact inventory-derived JDK, Groovy, Jenkins core, and plugin-profile versions plus content hashes. It receives read-only corpus input, has no network, bounded CPU/memory/time/output, a versioned protocol, complete provenance, an explicit target profile, and fail-closed results. Launch clears and allowlists its environment, mounts, files, and local sockets; the worker receives no execution secrets, database credentials or reachability, agent credentials or protocol authority, scheduler identity, or controller filesystem access. Reproducibility, hostile-input containment, sandbox escape attempts, and authority-negative secrets/database/agent tests must be proven independently. |
| MIG-002 | DONE | MIG-000, MIG-001 | Commit the exact secret-scanned Jenkins migration corpus and oracle manifest, stratified from the reconciled production inventory plus pinned OSS fixtures, with source hashes, licenses, provenance, reviewed typed redaction references and protected-evidence digests instead of embedded values, Jenkins/plugin target profile, every referenced effective controller-global setting and value/configuration digest, each job's enabled/disabled operational-state receipt, both execution platforms, agent label/image/capability/trust-pool mappings, toolchain identities, and immutable fixture mappings for every admitted mutable agent-local runtime input, plus expected parse, validation, and execution traces. For every behavior-changing public or secret parameter, condition, matrix, timeout, retry, cancellation, `catchError`, unstable-stage/result, post path, parallel branch, join, fail-fast sibling-cancellation path, job-level concurrency/supersession option, enabled/disabled transition, interactive approval/input path, cross-job shared-resource mapping, agent selection, mutable agent-local runtime input, cache mapping, authorization policy, workload dependency resolution, and persistent cross-build state/history dependency, define bounded equivalence classes and success/failure scenarios rather than one default execution. Secret-parameter cases require an explicit invocation-only tainted secret mapping or deterministic fail-closed classification, never a stored default/value, and inject unique markers whose absence is scanned across corpus/canonical bytes, diagnostics, logs, artifacts, tests, audit, and every API/UI/CLI response. Multi-build cases must cover simultaneous triggers, queue/start order, serialization, abort-previous behavior, cancellation propagation, and effect authority; operational-state cases must prove disabled jobs reject manual/API/upstream/webhook/schedule ingress before queue materialization and emit no scheduled work, credential grant, or effect, while reviewed re-enable and rollback restore exact generation and denial/acceptance behavior; retry/result cases must cover each failed/successful attempt, retry lineage, caught errors, node/stage/build result divergence, and eventual success or exhaustion; multi-job cases must cover contention, release, cancellation, restart, and effect authority; agent cases must cover label matches/misses, required capabilities, trust-pool selection, and denial of under- or over-privileged pools; local-input cases must cover exact staged content, missing input, path/content/origin substitution, declared refresh, undeclared mutation, and deterministic unsupported classification; approval cases must cover allowed and denied identities, submitter restrictions, submitted values, rejection, expiry, timeout, and cancellation; authorization cases must cover positive and negative view/trigger/cancel/configure decisions for effective principals; dependency cases must cover locked resolution, repository or artifact substitution, missing content, and mutable-resolution rejection; cache cases must cover cold, valid-hit, corrupt, key-substitution, untrusted-write/trusted-read, generation rotation, and cleanup paths; transition cases must seed Jenkins history and prove build-number mapping, previous-result lookup, cross-build artifact retrieval, retained-workspace handling, and the first authoritative McLoving execution. Classify every case as native, mappable, scripted, or unsupported; preserve immutable result deltas; and report production-population coverage, parse reach, native runnable coverage, actionable migration, and certified equivalence separately. |
| MIG-003 | DONE | MIG-001, MIG-002, IR-004 | Compile the admitted Jenkins Declarative subset into versioned McLoving IR and canonical strict YAML plus a separate versioned `JOBSTATE-001` operational-state record that preserves the source enabled/disabled state, generation, reason and provenance without making it mutable pipeline code. Preserve stage order, conditions, environment, public parameter schemas, invocation-only tainted secret-parameter references with no default/value persistence, matrices, post behavior, agent selection through an explicit normalized Jenkins-label-to-platform/capability/trust-pool mapping, typed immutable references for every admitted agent-local runtime input, admitted options including job-level concurrency and supersession, the parallel branch DAG and join semantics, fail-fast sibling cancellation, per-node/stage/build result semantics including caught errors and unstable outcomes, retry attempt identity and lineage, and interactive approval policy including allowed approvers, submitter restrictions, values, expiry, rejection, and cancellation; emit stable diagnostics for everything else; bind exact source/profile/compiler digests; and prove deterministic output with differential compiler fixtures. Rust independently reparses and validates every worker result before admission; adversarial worker-output gates reject malformed, unsupported, noncanonical, provenance- or profile-substituted IR/YAML or operational state, undeclared or mutable host-path access, and any secret default, literal, or taint downgrade. |
| MIG-004 | DONE | MIG-003 | Ship a versioned step and plugin mapping catalog to native processes, reusable components, connectors, and immutable staged agent-local inputs. Every mapping declares schema, types, effects, trust requirements, supported target profiles, and provenance; local-input mappings additionally bind canonical logical name, source path and origin, content digest, media type, confidentiality/taint, refresh generation, read-only destination path, and live freeze/rollback checks; mappings with lock, throttle, or shared-resource semantics additionally bind the canonical resource identity, coordination scope across jobs, queue and fairness policy, lease/release behavior, cancellation/restart recovery, and effect fencing; cache mappings bind key derivation, immutable generation/content digests, trust class, read/write policy, expiry, and cleanup. Floating mappings, undeclared host reads, and silent fallback are forbidden; substitution resistance and corpus-earned coverage are gated. |
| MIG-005A | DONE | MIG-002, MIG-003, OPS-003, AUDIT-001 | Implement versioned, deterministic, idempotent forward and reverse state transforms for every admitted build-number, previous-result, per-build SCM provider/repository/ref/revision, previous-revision and canonical changelog/change-entry baseline, cross-build artifact, retained workspace, persistent-state dependency, retention policy/deadline, and active legal hold with its identity/scope/reason/provenance/generation/release authority. Bind immutable source export, transform implementation/configuration, destination state, record-level provenance, conflict policy, and verification digests; reject gaps, duplicate mappings, divergent replays, provenance substitution, unclassified state, deadline shortening, hold omission, and unauthorized release. Before `DONE`, execute both directions against disposable exact-profile Jenkins and McLoving instances with seeded history: include jobs whose `when { changeset ... }`, `when { changelog ... }`, or equivalent step consumes the prior SCM/change-set record plus records under shorter/longer/expired retention, multiple overlapping holds, and attempted unauthorized hold release; import state, prove equivalent-or-stronger retention and the union of active holds before reader or execution authority, deliver a pinned next revision with known canonical changes, prove the first destination build selects the same branches and effect intents from the transferred baseline, run a McLoving state-authoritative but externally effect-free build, freeze new work, reverse-reconcile its number, result, SCM revision/baseline/change entries, retention/holds, artifacts, retained workspace/state, and audit linkage, then deliver another pinned revision and prove Jenkins resumes with the same predicate decisions and without stale lookups, missing changes, missing artifacts, premature deletion, missing holds, duplicate mappings, duplicate work, or duplicate effects. Every stateful, SCM-baseline-dependent, retained, or held job requires a successful case-specific rehearsal before `CANARY-001` may grant production effect authority; the later receipt-only `MIG-008` closure cannot satisfy this pre-effect gate. Corrective closure: the exact admitted job `corpus-052-cinqict_jenkinsdev` has one retained aborted `build-history` record. Its bounded five-file private source reproduced public tree digest `b47cc3e1c19e1d486a2df2fc76343e3031ee370a79564fe88a471adbf6e53107`, passed the pinned networkless zero-finding scan, and remained owner-only on HeMan. The canonical forward transform preserved build 1, `ABORTED`, `nextBuildNumber=2`, indefinite retention, provenance, and the build-history dependency; exact replay reused the PostgreSQL receipt. One externally effect-free McLoving build actually executed the exact pinned `/bin/sh -xe` process, captured both file descriptors through one shared ordered sink so xtrace precedes stdout in two durable records, produced build 2 and `Hello World`, then the inverse transform produced contiguous reverse history and `nextBuildNumber=3`. A fresh pinned Jenkins loaded build 1 as `ABORTED` and the reverse-imported build 2 as `SUCCESS` without reexecution, exposed the exact `Build` workflow stage and both process log records, restarted, executed build 3 once as `SUCCESS`, and advanced to `nextBuildNumber=4`; numeric history remained exactly `[1,2,3]`, the internal network denied public egress, and all authority stayed false. Both final exact-head evidence packages verify under owner-only retention on HeMan; their private digests and contents are intentionally absent from GitHub. No raw source bytes or private source-seal metadata enter the repository. This closes only the recorded exact dependency plus the earlier synthetic denominator and grants no production identity, trigger, scheduler, credential, effect, shadow, canary, cutover, rollback, or decommission authority. |
| MIG-005 | DONE | MIG-002, MIG-003 | Inventory and resolve Jenkins shared libraries by pinned SCM reference and content digest, including `vars`, `src`, and `resources`, while classifying load-time, runtime, sandbox, CPS, plugin, and credential dependencies. The worker ingests only owner-approved, prefetched, digest-verified read-only source and never receives direct SCM or credential authority. Arbitrary Groovy never runs in the controller; any future bounded isolated evaluation is owner-approved, meets the MIG-001 deny-authority boundary, and produces explicit unsupported receipts outside its admitted subset. |
| DIFF-001 | DONE | MIG-002, MIG-003, MIG-004, MIG-005 | Certify core execution semantics in separate independently tested deny-authority Jenkins and McLoving sandboxes with exact platform/image/locale/toolchain/input-fixture receipts and bounded CPU/memory/time/output. Run every admitted parameter, condition, matrix, timeout, retry, caught-error, unstable-result, cancellation, post, parallel, join, fail-fast, multi-build, shared-resource, agent-selection, approval, dependency, cache, artifact, test, stdout/stderr, and success/failure scenario. Compare canonical stage/step arguments, normalized node/stage/build outcomes, attempt lineage, concurrency/order, cancellation, workspace and published artifact digests/metadata/API retrieval, normalized tests, logs/gaps, and deterministic classification. Scripted/unsupported cases must remain non-executable with zero work, grant, or effect. |
| DIFF-002 | DONE | MIG-005A, IDP-001, AUTHZ-001, JOBSTATE-001, AUDIT-001 | Certify identity, authorization, operational state, and persistent-history semantics. Compare immutable source-to-target principal mappings and positive/negative view/trigger/cancel/configure decisions; enabled/disabled generations and pre-queue denial; build-number/previous-result/SCM-changelog baselines; cross-build artifacts; retained workspace/state; retention and legal holds; approval identity/value/expiry behavior; retry/result history; first-authoritative-run decisions; and forward/reverse reconciliation. Include rename/collision/deleted-identity reuse, group changes, disable races, stale generations, history gaps, hold omission/release denial, restart, and rollback fixtures. Closure: `docs/architecture/STATE_POLICY_DIFFERENTIAL_V1.md`; exact implementation head `f0b3f6dced45f33e9ef6d0ea88af013912cb76bd` sealed `/sn8100/runs/mcloving/diff002-state-policy-20260814T103536Z` with a self-excluding 19-file manifest SHA-256 of `10fbbaed1d819ad9ec6962710de3f557e35c834fb6741f7cb08b085526a81786`. Exact PR head `c6baebe3ec3a702ee94c8fb1ad211a446fc787c8` passed all nine protected checks and a clean independent exact-head review after all nineteen actionable review threads were fixed and resolved. PR #55 squash-merged as protected-main commit `5e02566ac3f76d8261b6578f71ccb438bd51bda3`; Windows run `31795542752` passed, and Foundation run `31795542707` passed on unchanged-head attempt 2. Attempt 1's only failure was an unrelated short-lived agent-runtime containment timing case; the exact test immediately passed twenty consecutive times on HeMan, and the unchanged rerun passed the complete workspace, resolver, connector-denial, and AppArmor gates. The required threat-model closure review updates TM-030 and TM-038, adds TM-043 for the cross-system persistent-history boundary, and records explicit reviewed no-change receipts for TM-027, TM-028, TM-005, TM-014, TM-017, TM-019, TM-022, and TM-025. Live production-population mapping, drift reconciliation, and case-specific rehearsal remain explicit `MIG-007`, `SHADOW-001`, and `CANARY-001` gates. This closure grants no production identity, trigger, scheduler, credential, effect, canary, cutover, rollback, or decommission authority. |
| DIFF-003 | DONE | TRIG-001, SCM-001, SECRET-001, INPUT-001, PROV-001, EXT-001, OBS-001, DISC-001, DEP-001, CACHE-001, CONSUMER-001, ADMIN-001, REL-001 | Certify every live boundary through exact typed receipts and permission-negative fixtures: canonical trigger capture/replay, source acquisition and later revisions, secret consumer/taint eligibility, external runtime reads, dynamic provisioning, dependency/cache resolution, multibranch discovery, external read/write client migration, trusted release provenance, authoritative connector outcomes, and independently observed destination state. Compare implementation/configuration/account/resource/content/generation identities, downstream control flow, effect intents/outcomes, retry/ambiguity truth, observation freshness, and rollback restoration. Prove runner/connector/observer non-collusion, zero secret-marker disclosure, no residual Jenkins read/write client, no shadow production endpoint, substitution/replay/stale/outage denial, and zero duplicate effect. Closure: `docs/evidence/DIFF-003_SECURITY_REVIEW.md`; exact implementation head `296238dfb7aefaef1518a72c2398848f7b5fd2ec` passed all nine protected checks and exact-head review after all actionable findings were fixed and all review threads resolved. The independently verified contained ceremony sealed 175 files under self-excluding evidence-manifest SHA-256 `40ff90e57bd29b16044706b8cd6686211527131a6459a0eea8cf85c024074fd5`, with 13/13 authenticated live receipts, 48/48 executed adversarial scenarios, 11/11 compatible joins, and zero production mappings, production effects, duplicate effects, cutover claims, or secret-marker disclosures. PR #59 squash-merged as protected-main commit `6156e70fa2b869b2f2b3097e65a618e8e741936e`, which passed post-merge Foundation and Windows verification. This closure grants no production endpoint, credential, deployment, client cutover, canary, rollback, or decommission authority. |
| MIG-006 | DONE | DIFF-001, DIFF-002, DIFF-003 | Close the exact committed-corpus differential gate by verifying and aggregating all three immutable evidence sets without rerunning alternative logic. Require complete per-case coverage, matching source/oracle/profile/compiler/mapping/component/release identities across the evidence sets, zero unclassified jobs or mismatches for certified cases, deterministic fail-closed receipts for scripted/unsupported cases, and stable mismatch/regression taxonomies. The migration package does not exist yet and is neither an input nor an acceptance condition here; `MIG-007` creates it and binds it to this exact closure. Report production-population coverage, parse reach, native runnable coverage, actionable migration, deterministic rejection coverage, and certified equivalence separately; no metric can borrow another metric's denominator or imply production authority. Closure: `docs/architecture/DIFFERENTIAL_AGGREGATE_V1.md`; the two-file immutable aggregate is sealed at SHA-256 `90ef410114812982f7dc98cabafea8215a1f87739023f0636853f77b1f9a77a9`, and the independently reproduced exact-head evidence manifest has SHA-256 `e23e1c754330033659e03f8dd83e9e5b2841323ae3568e74d102621cc4e784d2`. The canonical verifier authenticates twelve immutable inputs, composes the three canonical differential verifiers directly over those exact in-memory bytes, and fails closed on substitution, alias, reparse, hardlink, unbounded-tree, taxonomy, identity, coverage, or cross-evidence mismatch on Linux and Windows. Exact denominators are 230/230 disabled production jobs, 140/228 parse reach, 1/228 native runnable, 1/228 actionable migration, 227/227 deterministic rejection for non-admitted cases, and certified equivalence of 1/1 admitted cases and 1/228 corpus-wide. Exact PR head `ab7c0061c9004c2e5cd33c50b55ddc35fb306d38` passed Foundation run `31912421075`, Windows run `31912421043`, strict local and HeMan verification, and clean exact-head review after all twenty-two actionable review threads were fixed and resolved. PR #61 squash-merged as protected-main commit `2a8f983838b4bd063bd029b3e164f7ac36c20439`, with post-merge Foundation run `31914011695` and Windows run `31914011627`. This closure creates no migration package and grants no production identity, trigger, scheduler, credential, effect, canary, cutover, rollback, or decommission authority. |
| MIG-007 | DONE | MIG-005A, MIG-006 | Generate a reviewable migration package containing canonical strict YAML, the exact reviewed `JOBSTATE-001` operational-state record, provenance, diagnostics, a mapping lock, exact source/oracle/profile/compiler digests, and the exact already-certified `MIG-005A` bidirectional state transforms plus `MIG-006` seeded-history differential and rehearsal receipts for every admitted state dependency. The package must round-trip to identical IR and operational state, contain no credential material, expose every substitution and unsupported boundary explicitly, bind immutable source export, forward/reverse transform, destination state, and verification digests for cutover and rollback, and reproduce the packaged receipt verification without invoking alternative transform logic. The merged public v1 remains deliberately incomplete and rejects all 228 cases. The owner-private v1 package embeds that exact public baseline plus both complete owner-manifest-pinned MIG-005A archives, authenticates the effective-user-owned and owner-only sealed source, requires separately supplied owner-private forward and reverse implementation pins, reconstructs the exact forward and reverse bundles through canonical state-transfer logic, cross-checks implementation/configuration identities, Jenkins build/import/provenance sidecars, the retained job configuration against the reviewed public fixture, retained build-2/build-3 manifest-path identities and XML results/timings, every imported/restarted/retained build-one log, retained build-2/build-3 console logs, ordered normalized log entries against both captured stream chunks, and every workflow/stage/shell receipt including mandatory stage IDs, and verifies build/result/log/restart/build-1/next-build/permalink/network-denial continuity plus exclusive attachment to both captured internal networks. Every private anchor and immediate parent belongs to the invoking effective user; package/pin paths are descriptor-traversed without following aliases, and a writable ancestor must belong to that user or be root-owned and sticky; private publication requires durable staging-link cleanup. The owner-private package verifies one packaged case and 227 deterministic rejections with `package_complete=true`, `shadow_eligible=true`, and every production/canary/cutover/rollback/credential/trigger/scheduler/effect authority false. Its bytes and owner pins remain only on HeMan. Exact implementation head `3cfa8922bf9f7d3a879d7b362755ee8d36d724ef` passed Foundation run `31948881612`, Windows run `31948881614`, strict HeMan verification, and clean exact-head review after all review threads were resolved. PR #65 squash-merged as protected-main commit `d36f2a67004fe48d7f066f22c23a9d29befa264d`. This closure admits only deny-authority shadow eligibility and grants no production, canary, cutover, rollback, credential, trigger, scheduler, or effect authority. |
| SHADOW-001 | DONE | MIG-007, JOBSTATE-001, AUTHZ-001, TRIG-001, SCM-001, SECRET-001, INPUT-001 | Prove deny-authority shadow execution before any production effect. Atomically freeze source/target enabled state, package/release/runtime identities, source revision, authz generation, agent-local inputs, clock/elapsed-time and non-security entropy streams. Capture each authenticated trigger, external read, approval/input/cancel/retry action, connector outcome, and other behavior-changing event once as a bounded receipt and replay it at the same state-machine point to both runners. The shadow has no production credentials, connector/deployment grants, scheduler/database/controller authority, host mounts, or write-capable network path; secret-dependent logic is admitted only through confidentiality-safe source/outcome receipts. Require exact MIG-006 trace comparison, isolated outputs, zero production request, and quarantine on drift, missing receipt, mismatch, or ambiguous authority. Closure: `docs/architecture/SHADOW_QUALIFICATION_V1.md`; exact PR head `b8f422ce2deaa9640a863ff2730373ebd242781e` passed all nine protected checks and a clean exact-head review after all review threads were resolved. PR #68 squash-merged as protected-main commit `dbc3bad735bc45241ee048e1d364ed478eae7e3c`, whose Foundation run `31973862276` and Windows run `31973862272` passed. The owner-private HeMan ceremony retained under `/sn8100/runs/mcloving/shadow001-ceremony-20260816T221103Z` authenticated five source events, five matching replays, one exact paired trace, zero mismatches, one packaged case, and 227 deterministic rejections with `shadow_qualified=true` and `production_authority=false`; no private bytes, pins, or digests enter GitHub. This closure grants no production execution, credential, trigger, scheduler, connector, effect, canary, cutover, rollback, or decommission authority. |
| CANARY-000 | DONE | SHADOW-001, REL-001, EXT-001, OBS-001, DISC-001, DEP-001, CACHE-001, PROV-001 | The effect-free `mcloving-canary-qualification` foundation verifies seven independently signed pre-action gates, eleven pairwise-distinct signer identities, the source-controller/relinquishing-runner binding, a connector-signed single dispatch time after grant issuance, a shadow-replayer-sampled signed replay-completion time taken after its durable replay claim, exact EXT-001/shadow/OBS-001 receipt joins, one-action quotas, optional Windows interruption evidence, and the independently signed final authority ledger without granting authority; `authority_granted_by_verifier` is always false. Its sealed-inventory test digest-pins the scenario contract and eligibility ledger and proves the current Mario population has zero eligible production canaries. Exact reviewed head `2ca737a28fca8926e3c4d7c92b339567213a78fd` passed all protected checks after all 23 review threads were resolved; PR #70 squash-merged as verified protected-main commit `c6a238ae9acdc997d14850d1752cecd54feec8b9`, whose Foundation run `32080011592` and Windows run `32080011587` passed. The merged verifier cannot perform or authorize a production action. |
| CASE-001 | DEFERRED | EXT-002, MIG-000, MIG-007, SHADOW-001, MIG-005A, SEC-005, EXEC-005, AGENT-007, SECRET-002 | Owner-designated first effectful production case. The sealed Mario population is a disabled parse-oracle corpus whose 230 jobs are all `unsupported`, so no production ceremony can exist until the owner designates one real enabled Jenkins job with exactly one connector-backed external effect class as the first canary candidate. Then complete, for that exact case and under the existing Working rules: a fresh signed inventory epoch through the `MIG-000` reconciliation protocol covering the job, its enclosing chain, readers/writers, runtime dependencies, and persistent state; a fresh `MIG-002` corpus stratum and scenario-contract revision with the effect and approval families no longer vacuous; `MIG-003` compilation and Rust re-admission; a `MIG-004` mapping-catalog revision binding the case's steps including the effect mapping to a certified `EXT-001` connector action; implemented generalized `MIG-005A` build-history forward and reverse transforms for the case's record classes, replacing the `mcloving/build-history-forward-unimplemented-v1` and `mcloving/build-history-rollback-unimplemented-v1` dispositions; refreshed `DIFF-001`, `DIFF-002`, and `DIFF-003` scenarios, a refreshed `MIG-006` aggregate closure, and a new `MIG-007` package whose packaged-case count includes this job; and fresh `SHADOW-001` qualification, under a v2 receipt schema if the case carries any live input, secret, connector-outcome, semantic-time, or semantic-entropy dependency, because the v1 schema is denial-parity only and a nonempty dependency count cannot be smuggled into it. This ticket grants no execution, credential, trigger, scheduler, connector, effect, canary, cutover, rollback, or decommission authority; the one production action remains a separately owner-authorized `CANARY-001` ceremony. Oversized boundaries discovered during execution split into owner-reviewed sub-tickets rather than sharing one pull request. |
| CASE-002 | DEFERRED | CASE-001, DEPLOY-002 | Recertify the designated case against the deployment that actually ships. `CASE-001` necessarily completes before `REL-003` and `DEPLOY-002`: those depend on it, so the ordering cannot be reversed. Its differential, `MIG-006`/`MIG-007`, and shadow evidence therefore describe the runtime and provenance that existed when the case was certified, not the installed helper, broker, driver, and verifier topology the first production effect will actually run on. `DEPLOY-002` reruns the deployment and containment gates and does not re-certify the case, and `CANARY-001` only joins completed statuses. Acceptance: on the complete installed deployment, the case's differential, `MIG-006` and `MIG-007` joins, and shadow replay are re-run and re-sealed against the exact deployed configuration and provenance, and this ticket closes only with **zero unresolved divergence** from the `CASE-001` evidence. Reporting a divergence is not closing one: a recorded difference with `CASE-002` marked DONE would let `CANARY-001` perform the first production effect on a runtime already known not to match the certified case. A divergence is either resolved and re-sealed, or the case is declared ineligible — and ineligibility closes nothing by itself: with the sole designated case ineligible, both case tickets would read DONE while `CANARY-001` held no eligible effectful case, and no remaining ticket selects or certifies a replacement, permanently blocking `MIG-008` and the authority-transfer chain behind it. On the ineligibility branch this ticket therefore stays open until the owner designates a replacement real enabled Jenkins job with exactly one connector-backed external effect class, that replacement completes the full per-case certification protocol `CASE-001` defines, under the same Working rules, and this ticket's own recertification — differential, `MIG-006` and `MIG-007` joins, and shadow replay — is re-run and re-sealed for the replacement case against the exact deployed configuration and provenance with zero unresolved divergence. One correction obligation applies on **whichever branch a correction arrives** — a resolved divergence or a replacement designation, which necessarily changes the `MIG-007` package: any correction that changes the `MIG-006`/`MIG-007` package, the mappings, the receipt schema, or the runtime invalidates evidence that nothing downstream regenerates, because `REL-003` and `DEPLOY-002` are already DONE when this ticket runs. Before this ticket closes, the corrected executables and case package are re-packaged and re-signed under the `REL-003` ceremony, the `DEPLOY-002` revalidation — install, upgrade, rollback, and the full `SEC-005` denial-probe rerun — passes against that corrected signed release, and `CANARY-002`'s end-to-end and abort-path fixture evidence is regenerated against the corrected contract; re-signing and redeploying the driver does not rerun those fixtures, and closing on corrected code or configuration outside the signed and deployment-validated artifact would let `CANARY-001` join stale DONE statuses and dispatch through a driver proved only against the pre-correction protocol. These obligations live here rather than as `CANARY-002`, `REL-003`, or `DEPLOY-002` dependencies because the graph forbids every such edge: `CANARY-002` precedes `REL-003`, which precedes `DEPLOY-002`, which precedes this ticket. The replacement obligation lives here as acceptance criteria for the same reason: `CASE-001` is an ancestor of `REL-003` and `DEPLOY-002`, so neither reopening it nor adding an edge that routes replacement certification back through the release and deployment chain can be expressed without a cycle. This exists as its own ticket because the dependency graph forbids the alternative — making `CASE-001` wait for `DEPLOY-002` would be a cycle. |
| CANARY-002 | DEFERRED | CANARY-000, EXT-002, CASE-001 | Implement the producer side of the one-action ceremony so `CANARY-001` has a driver: signed gate-receipt assembly for the eleven pairwise-distinct signing roles, independent pin generation, canonical session assembly, and an owner-driven orchestration CLI that executes the seven pre-action gates, the fenced single connector dispatch under an `EXT-002`-enforced effect grant, pre/post/reconciliation destination observations, the exactly-once shadow outcome replay, and the final authority ledger — against contained fixture destinations only, with every production authority flag false. Acceptance: the merged `CANARY-000` verifier accepts a fixture-produced session end to end; every abort path — gate failure, freeze drift, intent mismatch, quota exhaustion, ambiguity freeze, missing receipt — produces a session the verifier rejects fail-closed; signing keys and pins remain owner-private on HeMan; no production endpoint, credential, connector grant, or destination is reachable from any ceremony component under test. |
| CANARY-001 | DEFERRED | CANARY-000, EXT-002, CASE-001, CASE-002, CANARY-002, SHADOW-001, REL-001, EXT-001, OBS-001, DISC-001, DEP-001, CACHE-001, PROV-001, SEC-005, REL-003, DEPLOY-002 | Prove graduated per-job effect authority one action at a time under bounded quotas, retention, audit, failure thresholds, and abort rules. Before each grant, satisfy and bind the current pre-action threat-model receipt, live inventory reconciliation, quiescence proof, and complete runtime/input/authority freeze required by the Working rules; post-effect review or drift detection cannot satisfy the gate. Buffer both canonical intents and require exact match before granting the authoritative runner a production connector; the shadow remains effect-free and can never reach a production endpoint. Replay the authoritative bounded outcome into the shadow before downstream control flow, and require an independently observed destination-state/reconciliation receipt binding account/resource, precondition, request, result, freshness, and observer provenance. Ambiguity freezes new effects until reconciliation. Windows jobs require completed persistent-host interruption/reboot proof; unimplemented trigger, discovery, source, secret, dependency, cache, provisioner, observer, connector, or runtime effect-integration classes remain ineligible. This ticket stays `PENDING` until `EXT-002` is merged and verified, `CASE-001` delivers one fully certified effectful case, and `CANARY-002` delivers a fixture-proven ceremony driver. The exact action then requires a fresh explicit one-action owner grant; nothing in this board authorizes it. |
| MIG-008 | DEFERRED | SHADOW-001, CANARY-001 | Close shadow and graduated-canary readiness by verifying every per-job receipt against the exact MIG-007 package and MIG-006 certified case. Require zero unclassified mismatch, zero duplicate or shadow production effect, stable source/target/package/runtime identities, exact operational-state and authorization parity, complete trigger/input/outcome replay, successful abort/freeze behavior, independently observed effects, and explicit ineligibility for scripted/unsupported or workload-visible secret-dependent jobs. Partial truth or a regression budget can never trigger automatic cutover. |
| CUTOVER-001 | DEFERRED | MIG-008, MIG-007, REL-001, AUTHZ-001, JOBSTATE-001, DEPLOY-001, SEC-005, REL-003, DEPLOY-002 | Define and prove the per-job cutover freeze and switch. Before the transaction, satisfy and bind the current pre-action threat-model receipt, live inventory reconciliation, quiescence proof, and complete runtime/input/authority freeze required by the Working rules; post-cutover review cannot satisfy the gate. Under owner approval and one signed transaction, atomically re-read every certified source and target identity: Jenkinsfile/library/job/core/plugin/global settings; source/target operational state and authz; trigger/discovery/source/secret/input/dependency/cache/provisioner/connector/observer configurations and generations; platform/agent/toolchain/local-input digests; migration package/YAML/IR/mapping/component/state transforms; McLoving release/SBOM/signature; and authoritative destination-state receipts. Any drift aborts without transferring trigger, scheduler, credential, or effect authority. Disabled, scripted, unsupported, unresolved, or uncertified jobs remain ineligible. |
| ROLLBACK-001 | DEFERRED | CUTOVER-001, MIG-005A, OPS-002 | Prove bounded per-job rollback after at least one authoritative McLoving build plus denial-only disabled-job probes. Freeze new triggers/effects, reconcile build number/result/SCM baseline/changelog, artifacts, retained workspace/state, retention/legal holds, audit linkage, operational state, agent-local inputs, and external outcomes through the exact MIG-005A reverse transform; restore the pinned Jenkins core/plugin/configuration, trigger/discovery/client authority, identity/authz and dependency/cache/source/secret mappings; then deliver a later revision/event and prove Jenkins resumes without stale lookup, missing evidence, unintended enablement, duplicate mapping, work, or effect. |
| RECUTOVER-001 | DEFERRED | ROLLBACK-001, MIG-008, MIG-007, REL-001, AUTHZ-001, JOBSTATE-001 | After `ROLLBACK-001` leaves Jenkins authoritative and proves a later Jenkins revision/build, execute the entire `CUTOVER-001` protocol again as a fresh transaction. Reconcile a new live inventory epoch; freeze current source/target/runtime/security/client identities; quiesce both sides; transfer every post-rollback trigger cursor, delivery, build/history/state, retention/hold, reader/writer, scheduler, credential, and effect-authority change through the exact certified transforms; and re-read all pre-action receipts. Prove McLoving becomes the sole current authority, Jenkins is fenced but still rollback-capable, the later Jenkins build and state are queryable on McLoving, and no delivery, work, history, reader/write operation, or effect is skipped or duplicated. A prior cutover receipt, stale snapshot, or closure-only verification cannot satisfy this ticket. |
| DECOM-001 | DEFERRED | RECUTOVER-001, CONSUMER-001, ADMIN-001 | Prove explicit owner-approved Jenkins scope decommissioning only after the rollback rehearsal, fresh final cutover, and rollback window. Re-read and bind the current `RECUTOVER-001` receipt and prove McLoving—not Jenkins—is authoritative immediately before retirement. Every production job must be cut over or owner-retired, every read-side consumer and administrative writer migrated or owner-retired, and no ineligible dependency may remain. Preserve and verify the final export and legal-hold evidence, then revoke Jenkins triggers, credentials, network, read APIs, administrative write APIs and compute; prove zero production traffic, caller, scheduled work, valid credential, live agent, or remaining Jenkins authority. Decommissioning is separately authorized from cutover. |
| MIG-009 | DEFERRED | CUTOVER-001, ROLLBACK-001, RECUTOVER-001, DECOM-001 | Close authority transfer by verifying signed rehearsal-cutover, rollback, fresh-final-cutover, and decommission evidence without invoking alternative migration logic. Require per-job eligibility, exact freeze identities, bounded dual-run and rollback windows, successful seeded-history transition, a current receipt proving McLoving holds sole authority immediately before retirement, no residual reader/writer/trigger/credential/compute authority, preserved retention/legal holds and final export, and zero duplicate work or effect. Publish the immutable disposition of every inventoried job, client, state class, and Jenkins scope; an unresolved item blocks closure. |

## Migration parity substrate tickets

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| EXT-001 | DONE | SEC-003, CTRL-003 | Define the scoped out-of-process connector identity and versioned protocol for external effects. A connector has no scheduler, database, agent, controller-filesystem, or unrelated-secret authority; each action binds tenant/project/build/attempt/fence, exact connector and request digests, idempotency class, expiry, and audit provenance. Define a bounded signed authoritative-outcome receipt with typed response schema/status, canonical public values, protected secret references/taint, external identifiers, retry/ambiguity truth, and `OBS-001` destination-state linkage plus a deny-authority exactly-once shadow replay protocol that cannot reach the production endpoint. Prove downstream control-flow and later-intent equivalence after success, failure, retry, timeout, ambiguous completion, public/secret-bearing result, malformed/substituted/replayed outcome, and replay-adapter restart. Permission-negative integration, stale/replay denial, bounded retry, exact deduplication, and ambiguous-effect reconciliation gates are required before any connector-backed canary or cutover. Closure: `docs/evidence/EXT-001_SECURITY_REVIEW.md`; exact implementation head `186f48df1ac83c78f4c9dc9e085f2a8fb757b9da` passed the 20-test protected Linux focused gate, strict Clippy, all protected checks, and a clean exact-head independent review after all sixty-one actionable review threads were fixed and resolved. PR #49 squash-merged as protected-main commit `dae140e038c52a655489ab99f112ecfa4252aede`, which passed post-merge Foundation and Windows verification. Mario's sealed denominator contains zero admitted production connector mappings or credential authority, so production effects, credentials, canary, cutover, rollback, and decommission remain separately gated. |
| EXT-002 | DONE | CANARY-000, EXT-001, OBS-001, SHADOW-001 | Integrate the certified effect boundary into the shipped product path described by `docs/architecture/RUNTIME_EFFECT_INTEGRATION_V1.md`: the typed connector-intent and execution-spec path, strict deployment-owned mapping ID/digest resolution, immutable controller-owned prepared/outcome/observation/reconciliation/shadow truth, shipped-format downstream digest comparison, closed protected-reference validation, all-fence redacted API evidence, digest-pinned out-of-process connector/observer/shadow services, frozen pre-action predecessor binding, signed response-substitution denial, no-lease receipt completion under explicit reconciliation, and lease/crash/timeout/cancellation/retry/ambiguity handling with exactly one fixture dispatch, closed by a real-PostgreSQL readiness gate. PR #72 carries the implementation with an owner-only internal-network Mario rehearsal whose production/canary/cutover authority flags are all false. Closure requires independent exact-head review, protected CI, thread resolution, squash merge, and post-merge protected-main verification. Native process execution remains network/credential/effect denied, and the first production action remains exclusively a separately authorized `CANARY-001` ceremony. **Closure:** merged to protected main as `03a1f5d` (PR #72) after four rounds of independent review resolving, among others, an abandoned dispatch-committed effect, observer join-window and read-grant coverage, four lock-order inversions, event forgery, a cancellation decision that was not atomic with publication, an over-strict observation publication deadline that refused valid signed receipts after the connector had acted, and a malformed effect plan that requeued forever instead of failing at startup. |
| OBS-001 | DONE | SEC-003, AUDIT-001 | Implement typed independently deployed read-only destination observers for every authoritative effect class discovered by MIG-000. Bind the exact observer implementation/image, protocol, deployment and operator trust identity, tenant/project/build/attempt/effect fence, destination endpoint/account/resource scope, canonical query, freshness cursor, response digest/signature, observation time, scoped credential grant, and audit provenance into a versioned receipt. The observer must use a separate service identity, credential-issuance path, configuration authority, and runtime boundary from every runner and effectful connector; it has no write, scheduler, controller database/filesystem, agent, workload-secret, connector-control, or effect authority. Prove valid pre/post/reconciliation reads, stale/missing/malformed/oversized/substituted/replayed responses, timeout/outage/restart, cursor rollback, observer/configuration/credential substitution denial, read-grant expiry and rotation, destination permission-negative behavior, and compromised-runner/connector attempts to control, impersonate, configure, credential, suppress, reorder, or fabricate observations against exact contained destination fixtures. Certify receipt verification and non-collusion before any `DIFF-003` effect-boundary differential, `CANARY-001` production effect grant, `CUTOVER-001` or `RECUTOVER-001` authority transfer, or `ROLLBACK-001` reversal; later aggregate closure cannot satisfy these pre-action gates. Closure: `docs/evidence/OBS-001_SECURITY_REVIEW.md`; exact implementation head `2f3999b8f9f734b93d646100a66dd6ba5c87ba83` passed the 75-test focused gate, all nine protected checks, and a clean exact-head review chain after all seventy-nine review threads were fixed and resolved. PR #39 squash-merged as protected-main commit `aa43e088242bd125422dd4352df071e23ca4f24f`, which passed post-merge Foundation and Windows verification. Mario's sealed denominator contains zero admitted production destination-observer mappings, so production observation, canary, cutover, rollback, and decommission authority remain separately gated. |
| INPUT-001 | DONE | SEC-003, AUDIT-001 | Implement isolated typed read-only adapters for every live external runtime input discovered by MIG-000. Bind tenant/project/build/attempt, exact adapter implementation and protocol/schema, endpoint/data-source identity, scoped short-lived read grant, canonical query, consistency/freshness cursor, response digest/signature/provenance, confidentiality/taint, bounded size/rate/timeout, and audit lineage. The adapter has no write, scheduler, database, agent, controller-filesystem, unrelated-secret, or effect authority. Prove permission-negative behavior plus valid, branch-varying, stale, missing, malformed, oversized, unauthorized, endpoint/schema/identity substitution, replay, outage, retry, secret-marker non-disclosure, adapter restart, cutover, and rollback cases against exact contained fixtures before any dependent canary or cutover. Closure: `docs/evidence/INPUT-001_SECURITY_REVIEW.md`; exact implementation head `b323f61719d91576d3e6c2138876cfaffcc400cb` passed all nine protected checks and independent review after forty-eight actionable implementation findings across thirty-two exact implementation heads were fixed and their threads resolved. Mario's sealed denominator contains zero admitted live external inputs, so production input, canary, cutover, rollback, and decommission authority remain separately gated. |
| PROV-001 | DONE | SEC-003, AGENT-004, OPS-001 | Implement a scoped out-of-process provisioner identity and versioned protocol for every dynamic agent class discovered by MIG-000. Bind tenant/project/build/attempt/fence, provider/account/region, exact provisioner implementation and request, immutable template/image/bootstrap/toolchain, requested platform/capabilities/trust pool, network/volume/workspace/cache policy, short-lived instance identity/IAM grant, quotas, expiry, and audit provenance. The provisioner has no scheduler, controller database/filesystem, unrelated-secret, workload credential, or external-effect authority. Prove template/image/provider/identity substitution denial, least-authority networking and volumes, capacity/exhaustion, duplicate/reordered/stale request fencing, startup failure, timeout/cancel, controller/agent/provisioner crash, partition, orphan detection and cleanup, scale-down, retained evidence, no escaped compute, cutover, and rollback against exact contained provider fixtures before any dynamic-agent canary or cutover. Closure: `docs/evidence/PROV-001_SECURITY_REVIEW.md`; exact implementation head `16ed422d149cb224fbc8fd7652fb8a2d0934ccd0` passed all nine protected checks and independent review after fifty-two actionable implementation findings across twenty-three reviewed implementation heads were fixed and their threads resolved. Mario's sealed denominator contains zero admitted dynamic provisioners, so production provisioning, canary, cutover, rollback, and decommission authority remain separately gated. |
| TRIG-001 | DONE | API-002, AUDIT-001, JOBSTATE-001 | Implement typed authenticated replacement ingress for every trigger class discovered by MIG-000, including SCM webhooks, schedules, upstream jobs, remote-build HTTP/API tokens, and admitted plugin-specific event sources; an unimplemented class remains explicitly ineligible. Bind tenant/project/pipeline, trigger type and implementation digest, event-source or caller identity, configuration/filter digest, delivery/event ID, schedule timezone/calendar, upstream build identity, idempotency key, expiry, and audit provenance; enforce bounded deduplication and replay windows. Prove valid and invalid authentication, branch/path/event and request filtering, duplicate/reordered/delayed delivery, outage retry and dead-letter recovery, schedule skew and restart behavior, upstream success/failure filtering, remote caller revocation, plugin-source substitution, pause/resume, cutover handoff, and rollback restoration before any trigger-dependent canary or cutover. Closure: `docs/evidence/TRIG-001_SECURITY_REVIEW.md`; exact implementation head `2e471342f1d15bbc4448196f9edeb7df9c6b3b7a` passed all nine protected checks and a clean independent exact-head review after forty-five actionable review threads were fixed and resolved. PR #45 squash-merged as protected-main commit `c9e295a5ad61b74af367f9504c5f9071627a7df9`, which passed post-merge Foundation and Windows verification. Mario's sealed denominator contains zero admitted production trigger mappings, so production trigger authority, canary, cutover, rollback, and decommission remain separately gated. |
| JOBSTATE-001 | DONE | CTRL-004, API-002, AUDIT-001 | Add a first-class tenant/project/pipeline operational state, separate from immutable pipeline IR, with `enabled` and `disabled` values, monotonic generation, reviewed reason, actor/source identity, optimistic concurrency, idempotency key, effective time, and audit provenance in PostgreSQL and the public API/CLI/UI. Every manual, API, upstream, webhook, schedule, retry, replay, and administrative trigger path must atomically re-read the current generation and reject a disabled pipeline before queue/build materialization; schedulers must not claim it, and disable races must not mint work, credential grants, approvals, or effects after the disabling fence. Re-enable requires separately authorized generation advancement. Prove migration from existing enabled rows, disabled-state import, duplicate/reordered/stale transitions, concurrent trigger/disable and scheduler/disable races, controller restart and active-active consistency, authorization denial, audit completeness, package/canary freeze, and exact rollback restoration of state/generation/denial behavior before any migrated job receives effect authority. Closure: `docs/evidence/JOBSTATE-001_SECURITY_REVIEW.md`; exact implementation head `4c07ad57f50d694965d2fb6b2e43f7888afda200` passed all nine protected checks and a clean exact-head review after five actionable findings were fixed, one non-blocking refactor suggestion was dispositioned, and all six review threads were resolved. PR #43 squash-merged as protected-main commit `42d9af69590dacf97176b71073a2629213520364`, which passed post-merge Foundation and Windows verification. This closure grants no webhook, schedule, upstream, remote-build, plugin-trigger, production canary, cutover, rollback, or decommission authority. |
| DISC-001 | DONE | TRIG-001, SCM-001, AUTHZ-001 | Implement Multibranch Pipeline and Organization Folder indexing/discovery. Bind the exact deployed discovery implementation binary or image digest and protocol/version, live parent-configuration digest, provider/organization/repository identities, branch/PR discovery and trust/filter strategies, Jenkinsfile path and selection policy, exact discovered revision and provenance, child identity/configuration policy, orphan policy, and audit lineage. Prove new/updated/deleted branch and PR discovery, trusted and untrusted forks, filtering, parent reconfiguration, implementation or configuration substitution denial, duplicate/reordered webhook plus periodic reindex, restart/outage catch-up, child authorization, orphan retirement, and rollback restoration before any parent or child canary or cutover. Closure: `docs/evidence/DISC-001_SECURITY_REVIEW.md`; exact implementation head `f02eddfffbc295dd86eef0a8a000f3f3b6a10554` passed all nine protected checks and a clean independent exact-head review after all seventeen actionable review threads were fixed and resolved. PR #47 squash-merged as protected-main commit `41248d7dd4f1a694494ddec7a22fd51eed1f1987`, which passed post-merge Foundation and Windows verification. Mario's sealed denominator contains zero admitted production discovery mappings, so production discovery, canary, cutover, rollback, and decommission authority remain separately gated. |
| SCM-001 | DONE | SEC-003, AGENT-004 | Implement isolated live source acquisition for checkout, Git, submodule, and credentialed repository steps. Bind provider, repository identity, authenticated ref and exact revision, fork and trust policy, submodule graph, sparse/depth options, checkout implementation, scoped short-lived credential grant, and resulting content/provenance digests. Prove later-commit delivery, ref substitution and untrusted-fork denial, credential non-disclosure, replay resistance, bounded network/filesystem authority, cleanup, and differential checkout truth before any source-dependent canary or cutover. Closure: `docs/evidence/SCM-001_SECURITY_REVIEW.md`; exact implementation head `02f0d09a273abc5bd21039d3a7d0b8de069b0bd6` passed all nine protected checks and clean independent review after forty-seven actionable implementation findings were fixed and every implementation thread resolved. Mario's sealed denominator contains zero admitted live source repositories or credentials, so production source acquisition, canary, cutover, rollback, and decommission authority remain separately gated. |
| SECRET-001 | DONE | SEC-003, AUDIT-001, SCM-001, EXT-001 | Inventory every Jenkins-managed runtime credential reference and classify its exact consumer and taint path without copying secret material into migration packages. `connector-only` and `source-acquisition-only` mappings bind an owner-approved McLoving secret provider and versioned identity, keep credential bytes out of both pipeline runners, and use the exact `EXT-001` outcome-replay or `SCM-001` content/provenance receipt so the deny-authority shadow receives only bounded confidentiality-safe truth. A `workload-visible` credential delivered through `withCredentials`, environment, file, stdin, argument, or equivalent is ineligible for canary and cutover whenever its bytes can affect a branch, condition, process/effect argument, filename, public output, artifact, test, cache key, or other compared behavior; redaction alone cannot waive this boundary. Any future surrogate/replay mapping requires separate owner approval, a bounded typed protocol that reveals no secret-derived discriminator, deterministic equivalence proof for every admitted use, permission-negative tests, and explicit versioned provenance before reclassification. Bind tenant/project/environment/build/attempt/action scope, provider version, rotation generation, expiry, and revocation state to fenced short-lived grants. Prove missing/stale/replayed/cross-tenant/cross-attempt denial, rotation and emergency revocation, consumer/taint misclassification denial, supported-sink redaction, non-disclosure in logs/artifacts/audit, and least-authority integration before any credential-dependent canary or cutover. Closure: `docs/evidence/SECRET-001_SECURITY_REVIEW.md`; exact implementation head `87951abddf174829dc5fe70b22dd6a4a07724f5c` passed fourteen focused tests, strict Clippy, all protected checks, and a clean exact-head review with zero GitHub review threads. PR #51 squash-merged as protected-main commit `f08756fd91810268a0ea18321d9e333895501ab7`, which passed post-merge Foundation and Windows verification. Mario's sealed denominator contains zero credential references, redaction references, or secret consumers, so production provider, credential, grant, canary, cutover, rollback, and decommission authority remain separately gated. |
| IDP-001 | DONE | SEC-002, API-002, AUDIT-001 | Implement production authentication and identity lifecycle before Jenkins principal mapping. For humans, validate issuer-bound OIDC authorization-code/PKCE sessions with exact issuer, audience, nonce/state, signature/JWKS generation, subject, group and claim mapping, expiry, refresh, logout, and session revocation; for automation, use separately revocable scoped service identities with rotation and no shared bearer-token table. Bind external subject/service identity to one immutable McLoving principal and tenant, preserve provider/configuration and group-generation digests, and retain a reviewed provenance edge back to the exact MIG-000 Jenkins security realm plus immutable source user/group identity, alias/rename history, membership generation, and lifecycle state represented by each mapped ACL principal. Audit authentication and lifecycle changes, and deny unknown, disabled, deleted, stale, replayed, cross-issuer, cross-tenant, group-removed, name-colliding, renamed-without-proof, or source-identity-reused actors immediately. Prove key rotation, provider outage, clock skew, session fixation, token/claim/issuer substitution, group membership addition/removal, user rename and same-name collision, deleted-name reuse, user disable/delete, service credential rotation/revocation, privilege-negative API/UI/CLI behavior, active-active consistency, and rollback restoration against real contained source-realm and target identity-provider fixtures before any production canary or cutover. Closure: `docs/evidence/IDP-001_SECURITY_REVIEW.md`. |
| AUTHZ-001 | DONE | IDP-001, SEC-002, API-002 | Map each inventory job's effective Jenkins folder/matrix/job authorization policy and principals into least-authority McLoving organization/project roles without broadening view, trigger, cancel, configure, approval, artifact, test, log, or audit access. Every reviewed mapping binds the MIG-000 source security-realm implementation/configuration digest, immutable source user/group identifier, alias and rename provenance, membership generation, lifecycle state, exact ACL entry and scope, target issuer/subject or service identity, immutable McLoving principal, target group generation, resulting role, reviewer, and policy digest; mutable names alone are never mapping keys. Prove positive and negative decisions, rename and same-name collision, deleted-name reuse, disabled/deleted principal handling, live group-membership changes, service-identity rotation/revocation, source-realm/configuration substitution, cross-issuer and cross-tenant denial, session invalidation, and rollback restoration before any migrated-job canary or cutover. Closure: `docs/evidence/AUTHZ-001_SECURITY_REVIEW.md`; the independent exact-implementation-head security review is clean. Tenant-wide audit and scheduler actions remain explicitly non-mappable rather than broadened. |
| DEP-001 | DONE | SCM-001, SEC-003 | Implement policy-bound workload dependency resolution for Maven/npm/PyPI and other admitted ecosystems. Bind repository identity and trust policy, package coordinate, exact version, lockfile, transitive graph, content and signature/attestation digests, resolver/toolchain, credential grant, and audit provenance; mutable or unresolved coordinates are ineligible. Prove missing, repository/package/graph substitution, compromised mirror, untrusted-source, credential leak, offline/replay, and later-resolution denial before any dependency-resolving canary or cutover. Exact implementation head `075634f6ce6ee6f1ef5e371cbad313dddab4aaf3` passes the 123-test focused gate, including strict resolver all-target Clippy, formatting, `git diff --check`, all 122 ordinary focused tests, and the real exact-capacity contained journey. Documentation head `8d15ca537db6ccaea91fe041514f4b6de76bdbf7` passes workspace-wide strict Clippy, the complete locked non-source workspace, the same contained journey, board verification, and the serialized AppArmor source-acquirer suite. Complete PR head `5e356449cda88cb43c694cbd6f525f24463e3e89` passes all nine protected checks and fresh independent review after 140 actionable findings across 145 important seams were repaired; all sixty-seven fixed threads were resolved. PR #35 squash-merged as protected-main commit `82a5108284d0152b57230995dd53a754b0aae5c4`, which passed post-merge Foundation and Windows verification. Closure evidence: `docs/evidence/DEP-001_SECURITY_REVIEW.md`. Mario's sealed denominator contains zero admitted workload dependencies, so production dependency resolution, canary, cutover, rollback, and decommission authority remain separately gated. |
| CACHE-001 | DONE | DEP-001, SEC-002, OPS-003 | Implement tenant/project/pipeline/trust-class-isolated dependency and build caches with canonical keys, immutable generation/content digests, explicit read/write policy, bounded size/expiry, atomic publication, and auditable provenance. Prove cold and valid-hit behavior, corruption and key/generation substitution rejection, untrusted-write/trusted-read denial, concurrent publication, rotation, eviction, cleanup, and restored-state behavior before any cache-dependent canary or cutover. Closure: `docs/evidence/CACHE-001_SECURITY_REVIEW.md`; exact implementation head `87e3f75936e1d5f153b99167e1340308e92ac9ac` passed all protected checks and two clean independent reviews after all eighteen actionable review threads were fixed and resolved. PR #37 squash-merged as protected-main commit `f58986cd36019588b9731150a663e5dff32773bd`, which passed post-merge Foundation and Windows verification. Mario's sealed denominator contains zero admitted production cache mappings, so production cache, canary, cutover, rollback, and decommission authority remain separately gated. |
| REL-001 | DONE | OPS-002, AUDIT-001 | Produce trusted McLoving release provenance from reviewed protected-branch source through an isolated pinned builder. Closure: `docs/evidence/REL-001_RELEASE_CEREMONY.md`. PR #57's reviewed head `e24fadaea5adce777b49716d25a26d9238b9e24f` passed every exact-head check and clean review after all seven actionable threads were resolved; it squash-merged as protected-main commit `8d2519afcf29a82fa813fcddc8e131ddb7e83935`, whose Foundation, Windows, and isolated release-builder runs passed. The authenticated artifact SHA-256 is `6473174abe701aadf7332aae83744cd599090bfe0bd25c23adeacd1dece9ea94`. HeMan created owner-only `release-key:production:v1`, signed release UUID `3d38cc2c-a88b-4fac-aae2-7d9459c36ee5` as McLoving v0.1.0/profile `private-linux-x86_64` under the one-time genesis policy, published secondary attestation entry `108e9186e8c5677aa038380ec1f5062d282b17affb4457a78f2c3d091b993e9ec199595971f9dc0e` to Rekor, verified the canonical evidence-manifest digest against DigiCert RFC 3161 serial `0xEF41E06E6F4E906BF9CF7FCC31910CA6`, and retained a 47-file self-excluding evidence manifest SHA-256 `094276689d6cec9fbb63b1abd51f5b9a3f9b588c52e32be5e264fb20822af237` under `/sn8100/runs/mcloving/rel001-ceremony-20260814T134056Z/v2`. Private-key marker and hard-link scans are clean. The verification receipt explicitly records `private-release-verification`; no binary placement, production deployment, canary, cutover, or public binary publication is claimed. |
| CONSUMER-001 | DONE | API-002, AUTHZ-001 | Inventory and migrate every external read-side consumer of Jenkins build status, graph, logs, tests, artifacts, queue, and job metadata to a versioned authenticated McLoving API/CLI or bounded compatibility adapter. Bind caller identity, tenant/project scope, endpoint/query and pagination contract, retention/URL semantics, rate limits, and audit provenance. Prove positive/negative authorization, historical and live data equivalence, artifact retrieval, pagination/stream resume, error and outage behavior, caller cutover, rollback restoration, and zero residual Jenkins reads before the corresponding job enters authoritative cutover or its endpoint is retired. Closure: `docs/evidence/CONSUMER-001_SECURITY_REVIEW.md`; exact implementation head `6c3157adbe04e1166bae7ef6753718d5198793dc` passed all nine protected checks and independent review with no major issues. Mario intentionally remains Jenkins-source-authoritative until the real caller supplies a later zero-read cutover receipt. |
| ADMIN-001 | DONE | API-002, AUTHZ-001, AUDIT-001, CONSUMER-001 | Inventory and migrate every authenticated Jenkins administrative/write-side client, including Jenkins Job Builder, JCasC/Terraform automation, seed services, CLI clients, and REST clients that create, reconfigure, disable, delete, or otherwise mutate jobs, folders, nodes, credential references, or controller-global settings. Replace each admitted operation with a versioned authenticated McLoving API/CLI, declarative controller configuration path, or bounded compatibility adapter; bind caller identity, tenant/project or controller scope, exact operation/schema, desired-state and precondition digests, idempotency and optimistic-concurrency contract, authorization decision, and audit provenance. Prove create/update/delete convergence, duplicate/reordered/stale request handling, partial failure and retry, conflict and privilege denial, caller cutover, rollback restoration, and zero residual Jenkins writes before an affected job enters authoritative cutover or the corresponding Jenkins scope or endpoint is retired; unsupported operations require explicit owner-approved retirement before that cutover or decommissioning. Closure: `docs/evidence/ADMIN-001_SECURITY_REVIEW.md`; exact implementation head `8d342d98969d3a3f67282b45f577cdc8e1110f3d` passed all nine protected checks and independent review with no major issues. Mario intentionally remains Jenkins-write-authoritative until the real client supplies a later zero-write cutover receipt. |

Notifications and other non-migration product extensions remain follow-on
backlog. Provisioning, connectors, packaging, upgrades, rollback, retention,
and disaster recovery that are required for migration eligibility are owned by
the explicit tickets above or the proof tickets below; they are not an
unbounded “later Wave 5” escape hatch.

## Wave 8 — Better-and-faster proof

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| PROOF-001 | DEFERRED | MIG-006, MIG-008, MIG-009 | Publish an immutable claim ledger over the exact private and licensed OSS corpus only after authority-transfer closure. Keep parse reach, native runnable coverage, actionable migration, deterministic rejection, certified equivalence, canary eligibility, and successful authority transfer on separate denominators; derive the transfer denominator only from the current signed cutover, rollback, fresh-final-cutover, and decommission receipts verified by `MIG-009`; bind every number to corpus/oracle/package/release/evidence digests and prohibit “Jenkins compatible” or execution-superset claims not earned by the receipts. |
| PERF-001 | PENDING | MIG-006, REL-001, EXEC-004, AGENT-007, SEC-005, EXEC-005, CASE-001, DEPLOY-002, CASE-002 | Establish reproducible controller, PostgreSQL, agent, artifact/log, trigger, queue, and end-to-end capacity/regression envelopes on pinned HeMan, Mario, Luigi, and hosted Windows profiles. Report latency distributions, throughput, saturation/backpressure, storage sensitivity, resource use, recovery time, and explicit safety margin rather than harness timeout alone; compare the exact Jenkins oracle where meaningful and fail CI/release gates on reviewed regressions. **Per eligible platform.** The Linux envelopes are unconditional. The hosted-Windows envelopes are measured if and only if Windows is still eligible when this ticket starts — that is, `REL-003` produced a signed Windows artifact and `SEC-005` delivered Windows containment, so `DEPLOY-002` revalidated a complete Windows topology there is to measure. If either declared Windows ineligible, this ticket closes on the Linux envelopes alone and records that the Windows envelopes were not measured and why: on that branch no contained, signed, deployment-validated Windows topology exists, and envelopes for one would measure a deployment that will never ship. Written this way deliberately: an unconditional Windows requirement would make `PERF-001` unclosable on the very path the release tickets explicitly permit, and `WAR-001` and `REL-002` permanently blocked behind it. Gated on `SEC-005`, `EXEC-005`, `CASE-001`, and `DEPLOY-002`: containment changes how every workload process is launched and isolated, helper integration turns dormant binaries into real subprocess calls, the case adds its own transforms and mappings, and the final deployment installs the complete helper, broker, driver, and verifier topology. Envelopes measured before any of those describe something other than what ships, and nothing downstream regenerates them — `DEPLOY-002` validates the final topology but does not re-measure it, so `REL-002` would join on capacity evidence for an earlier deployment. `CASE-002` is included because its correction path can change the runtime, the mappings, or the deployed case package after `DEPLOY-002` has passed, and regenerating release and deployment receipts does not regenerate capacity evidence. Envelope remediation runs the other way too: a fix to the runtime or deployment made because an envelope came back inadequate is a late correction under the Working rules — the invalidated receipts are regenerated and the affected envelopes re-measured against the corrected deployment before this ticket closes. |
| WAR-001 | DEFERRED | MIG-008, PERF-001, WIN-001, WIN-002, WIN-003 | Run destructive campaigns with exact signed packages: overload, trigger storms, dependency/cache faults, connector ambiguity, controller/agent/database/object-store/network interruption, process and machine crash, reboot, cancellation, rollback, malformed/hostile input, multi-day soak, and no-escaped-work proof. Preserve immutable receipts, database/object integrity, recovery timelines, and post-campaign canary health. **Per eligible platform.** The Linux campaign is unconditional. The persistent-Windows campaign runs if and only if Windows is still eligible when this ticket starts — that is, `REL-003` produced a signed Windows artifact and `SEC-005` delivered Windows containment. If either declared Windows ineligible, this ticket closes on the Linux campaign alone and records that the Windows campaign was not run and why, because `WIN-003`'s package is qualification evidence rather than production provenance and cannot stand in for a signed package. Written this way deliberately: an unconditional Windows requirement would make `WAR-001` unclosable on the very path the release tickets explicitly permit, and `REL-002` permanently blocked behind it. A war-campaign finding fixed through the runtime, deployment configuration, or packaged artifacts is a late correction under the Working rules: the invalidated release, deployment, and downstream evidence is regenerated before this ticket closes. |
| SEC-004 | DEFERRED | MIG-008, IDP-001, AUTHZ-001, SECRET-001, EXT-001, OBS-001, UI-008 | Complete an independent migration/security review and adversarial campaign across identity collision, tenant isolation, authz parity, credential grants, compiler/worker sandbox, trigger spoofing/replay, source/dependency/cache substitution, connector/observer non-collusion, secret disclosure, artifact/log/audit integrity, supply chain, and rollback/decommission authority. Every high/critical finding blocks release until fixed and reverified; accepted residual risk requires explicit owner approval. Fixing is not only reverifying: this ticket completes after `MIG-008`, hence after `REL-003`, `DEPLOY-002`, `CASE-002`, and the production canary, so a finding fixed through the runtime, deployment configuration, mappings, or packaged artifacts invalidates the signed release, deployment proof, case certification, and capacity and war evidence that `REL-002` joins. The late-correction Working rule therefore binds this ticket's closure: every invalidated receipt is regenerated — the `REL-003` re-sign, the `DEPLOY-002` revalidation with the `SEC-005` denial-probe rerun, and whatever case, canary, or capacity evidence the fix invalidated — before this ticket closes and `REL-002` can join. |
| EXEC-005 | ACTIVE | EXT-002, DEPLOY-001, JCOMP-003, PAR-012 | Rescoped 2026-09-10: the cache and input slices merged in PRs #139, #140 and #141 stand; the source slice is delivered by `PAR-012`, and the dependency-resolver and provisioner slices are dropped because their helpers require a McLoving-private attestation that no public registry or cloud provides. Closes when `PAR-012` merges. Original scope follows. Reach the sealed helpers through the product path. Packaging a binary does not put it in the spine: a repository search finds production process spawning only in `crates/execution-spine/src/effect_transport.rs`, which launches the connector, observer, and shadow services, and neither `bins/agent` nor `bins/controller` depends on or invokes `mcloving-source-acquirer`, `mcloving-dependency-resolver`, `mcloving-cache`, `mcloving-input-adapter`, or `mcloving-provisioner`. Each has its own contained test suite and none has a caller, so a submitted job cannot reach any of them and `REL-003` could otherwise close having installed five dormant executables. Acceptance: a submitted pipeline reaches each helper through the product path under its existing contained boundary, with an end-to-end gate per helper proving a job actually invoked it — not a direct test of the helper binary. Until a helper is wired and gated, the job classes that depend on it (SCM acquisition, dependency resolution, cache, live input, dynamic provisioning) are ineligible for `CANARY-001` and `CUTOVER-001`, recorded on the board rather than implied. |
| SECRET-002 | PENDING | SECRET-001, DEPLOY-001, EXEC-005 | Produce the production secret broker and its authority boundary. `SECRET_MAPPING_V1` requires production deployment to bind the broker binary and release, owner-key source, provider adapter identity, network policy, service identity, trusted clock, secret-manager authorization, and the exact SCM or connector launch path before a credential-dependent canary or cutover is eligible; `crates/secret-broker` is a library crate with no binary target, and the contained provider used by tests is explicitly not production authority. This is a secret boundary, so under the Working rules it is one ticket and one pull request rather than a rider on a release ceremony. Acceptance: a production `mcloving-secret-broker` executable exists with each of those bindings implemented and permission-negative tests for each denial; no secret becomes workload-visible, since V1 has no operation that transfers one to a workload. Until it ships, every credential-dependent case is ineligible for `CANARY-001` and `CUTOVER-001`, recorded on the board rather than implied. |
| REL-003 | PENDING | REL-001, DEPLOY-001, SEC-005, SECRET-002, EXEC-005, AGENT-007, CANARY-002, CASE-001, UI-009 | Package and sign every executable the deployment lane installs. `REL-001` produces a signed, digest-pinned artifact containing `mcloving-agent`, `mcloving-cli`, and `mcloving-controller`; `DEPLOY-001` adds `mcloving-identity-admin`, and `mcloving-release-provenance` builds the bundle without being packaged in it. A signed release therefore covers four executables. It does not contain the sealed helper executables the spine spawns — source acquirer, dependency resolver, cache, input adapter, provisioner, external connector, external shadow replay, and destination observer — so a host running the `DEPLOY-001` lane either does not have them or obtained them outside the signed release. `CUTOVER-001` must re-read *every* deployed implementation digest; a helper that is not in the release has no release digest to re-read, and a connector-backed canary effect is dispatched by exactly such a helper. One of them does not exist yet to be packaged. Building it is `SECRET-002`, not part of this ticket: it is a secret boundary, and the Working rules put secret and release boundaries in separate tickets and separate pull requests unless the board classifies them as `BATCH`, so the broker's authority bindings get reviewed and merged on their own before any ceremony packages the result. It runs after `SEC-005` for a reason worth stating: `SEC-005` changes the agent executor that this ticket packages, so a ceremony held first would produce and sign a pre-containment agent, and both tickets could then read `DONE` while the deployed, signed release still lets a workload read its host's credentials. It also waits for `UI-009`: the controller embeds the served UI, and the session, representation and live-delivery changes plus the final browser proof must precede packaging. Otherwise UI work could land after the signed release and its deployment/case/canary receipts, leaving the later security campaign to review a different implementation from the one those receipts certify. `CASE-001` and `SEC-005` are themselves upstream prerequisites of this ticket, so their earlier receipts are not automatically fresh merely because both they and `UI-009` read DONE. Before packaging, identify any earlier case, containment, or ceremony receipt invalidated by UI changes and regenerate the affected evidence; `CASE-002`/`DEPLOY-002` still perform their final deployed-runtime checks. Never join a prior-runtime proof solely on completed dependency status. The existing late-correction and recertification rules also continue to apply after this ordering gate. Acceptance: one release ceremony packages and signs every executable the deployment lane installs, each with a `ComponentRole`; the deployment lane installs all of them from that artifact and nothing from outside it; the deployed-digest re-read covers every one, so the cutover freeze has a signed digest for each executable that can produce an external effect; the `CANARY-002` ceremony driver is included, whether it extends `mcloving-cli` or ships as its own executable, so `CANARY-001` cannot perform a production effect through code outside the signed release; the `mcloving-canary-qualification` verifier is included too, since `CANARY_QUALIFICATION_V1` requires the live session to be verified at the exact reviewed implementation head and `MIG-008` relies on that verification before cutover — an operator running a locally built verifier, or skipping it, is the same gap one step removed; and the `SECRET-002` broker executable is packaged and signed with the rest. Until that broker ships, every credential-dependent case is ineligible for `CANARY-001` and `CUTOVER-001`, and the board records that ineligibility rather than leaving it implied. The same completeness question applies per platform: `REL-001` signed `private-linux-x86_64` only, and the `DEPLOY-001` lane is a Linux systemd/podman lane, so nothing here covers a Windows agent. The `WIN-003` package cannot fill the gap — the board records its short-lived self-signed Authenticode identity as qualification evidence, explicitly not `REL-001` production provenance. `CANARY-001` still admits Windows jobs, so without this the board could authorize a Windows production effect executed by an agent binary that no production-signed release contains. Either this ticket produces a Windows release artifact under the same ceremony, or Windows canaries are ineligible for `CANARY-001` and `CUTOVER-001` until one exists, recorded on the board. |
| DEPLOY-002 | PENDING | DEPLOY-001, DEPLOY-003, DEPLOY-004, REL-003 | Revalidate the deployment lane against the release that actually ships. `DEPLOY-001` proves a clean-host install, health, upgrade, and rollback against a four-component artifact that, by its own bounded acceptance, installs none of the sealed helpers, the secret broker, the ceremony driver, or the qualification verifier. `REL-003` then changes both the artifact and the lane to install all of them, and requires no rerun of that proof, so `CUTOVER-001` could join `DEPLOY-001` and `REL-003` as DONE with nothing establishing that the final signed topology installs, starts, upgrades, or rolls back at all. It additionally gates on `DEPLOY-004`, because that ticket closes a home-ancestor substitution vulnerability that is open on `main`: `CANARY-001` and `CUTOVER-001` gate only on this ticket, so without the edge the graph permits production authority while another local user can still replace a deployment home sitting beneath a writable or foreign-owned parent. It gates on `DEPLOY-003` for the same reason it gates on `REL-003`: that ticket changes how every transition resolves units, enumerates drop-ins, parses `Exec*`, and validates the load path, so revalidation evidence produced before it would describe a lane that no longer exists, while `CANARY-001` and `CUTOVER-001` read this ticket as DONE. Acceptance: the scripted clean-host install, the deployable-runtime gate, the upgrade path with its health and stability gates, and the rollback path all run green against the complete signed release; the deployed-digest re-read covers every executable that release contains; and every `SEC-005` denial probe — filesystem, agent-private state, process, network, and resource bounds — is rerun against that complete installed deployment, because those denials are properties of the deployment configuration and `REL-003` changes both the artifact and the lane after `SEC-005` completes, so the final topology could otherwise regress the containment boundary while both tickets read DONE — **on every platform still eligible at that point**. If `REL-003` takes its option of producing a Windows artifact rather than declaring Windows ineligible, revalidating only the inherited Linux systemd/podman lane would let `CUTOVER-001` see this ticket DONE with nothing having installed, started, upgraded, or rolled back the complete signed Windows topology, while `CANARY-001` still admits Windows jobs. Either every eligible platform is revalidated, or the platforms that are not keep the ineligibility `REL-003` recorded for them. Acceptance also requires a mandatory start-time integrity verifier anchored outside the replaceable service-owned unit and deployment tree; it must detect unit, guard, selected-release, and ancestor permission drift on ordinary and crash restart. Until that external anchor is runtime-proved, this ticket remains PENDING and no production qualification may credit transition-time DEPLOY-003 evidence as restart-time protection. |
| SEC-005 | PENDING | DEPLOY-001, DEPLOY-003, EXEC-005, AGENT-007, SECRET-002, CI-004 | Contain a workload process so it cannot read the credentials of the host that runs it. Measured on the DEPLOY-001 lane: the agent spawns every submitted process step as its own service user, with no user transition and no filesystem sandbox, so a submitted step can read every 0600 file under the deployment config root — controller, API, and database credentials and the agent's mTLS private key — and can write the user-owned current release and helpers. `UMask=` and `StateDirectoryMode=` cannot close this: they are discretionary controls against other users, and the workload runs as this user. Containment belongs to the agent executor rather than to the deployment layer, on the trust boundary `DEPLOY-003` decided and recorded in `docs/architecture/DEPLOYMENT_TRUST_BOUNDARY_V1.md`: the service account keeps ownership of its deployed tree, so a rootless user-level lane has no privilege to transition away from, and the systemd directives that would otherwise enforce a filesystem boundary are measured silently unenforced under a user manager on Ubuntu 24.04+ -- thirteen enforced, thirteen accepted and ignored while the unit still reports success in four classes -- nine needing a mount namespace, one needing a network namespace (`PrivateNetwork=`, which fails for a different reason and must not be remediated as a mount case), one needing BPF, two needing an undelegated cgroup controller -- and three fail closed. The existing `mcloving-source-acquirer` and `mcloving-external-shadow-replay` profiles establish the substrate pattern but not its hardest case: both confine one KNOWN executable named at a unit's `ExecStart=`, whereas this ticket must confine an ARBITRARY submitted executable per attempt, which needs no path attachment, a `change_profile` transition before `exec` under `NoNewPrivileges=`, and a target profile granting no `change_profile` of its own. Note also that this substrate requires root at install to load the profile, so the containment story is not rootless even where the lane is, and any argument that rejects a mechanism for requiring privilege must account for that. The Windows executor has the same shape: it calls `CreateProcessW` in the service's own security context, so a submitted step inherits the agent service account's access to the mTLS and configuration material, and Job Objects bound lifecycle rather than privilege. Acceptance: on **each** platform a canary may be assigned to, a submitted step cannot read, write, or unlink the deployment config root or any of its key material — controller configuration, API and database credentials, CA trust material, and the agent's mTLS private key — cannot write the release or helper directories, **and cannot read, write, or unlink the agent's own private state** — the journal named by `MCLOVING_AGENT_JOURNAL_PATH`, its SQLite sidecars, and the session receipts beside it — with a permission-negative gate proving each denial, write and unlink probes for the config root and key material explicitly included. Read denial there is not sufficient on its own: the step runs under the deployment service identity, so a write-only sandbox or ACL mistake would pass every read gate while a submitted pipeline could still truncate, replace, or unlink the configuration and trust material the services restart on — a persistent outage or a silently changed trust configuration rather than a disclosure. The filesystem boundary also ends at the assigned workspace, not at the workspace root: every attempt's workspace is created beneath the shared `MCLOVING_AGENT_WORKSPACE_ROOT`, and the workload runs as the agent OS user that owns that whole tree, so without their own denials a submitted step can read or corrupt a sibling attempt's workspace and spools, or mutate or rename the workspace root itself and force the agent into recovery while every other gate passes. And the write boundary is an **allowlist, not a deny-list**: the Unix executor merely sets the step's working directory and confines no absolute path, so a step can write any location the service UID can — the service user's home directory and the shared `/tmp` included — filling the host filesystem or corrupting state no enumeration names, past every gate above and past the workspace-storage bound below. Acceptance is therefore stated positively: a submitted step may write only its assigned, quota-backed workspace plus an explicitly bounded private per-attempt temporary area, and every other path is denied by default; the enumerated targets are mandatory canary probes of that single rule rather than its definition — per platform, permission-negative write probes against the deployment config root and its key material, the release and helper directories, the agent's private state, a sibling attempt's workspace and spools, the workspace root itself (mutation, rename, and unlink, including any directory on the path to a workspace the step was not assigned), the service user's home directory, the shared temporary directory, and an arbitrary host-writable path outside the allowlist — plus read-denial probes for sibling attempt workspaces and spools — while the step keeps full access to its own assigned workspace. Stated as an allowlist deliberately: a deny-list is wrong until its last writable target is discovered and has grown by one newly named target per review, while default-deny makes every unenumerated path an instance of the same proven rule. The read boundary carries the same shape, so reads and writes are symmetric default-deny rules differing only in their allowlists — write: the assigned workspace plus the bounded private temporary area; read: the assigned workspace and artifacts explicitly assigned to the current attempt, the step's explicitly provided inputs, and the platform's public execution surface of interpreters, libraries, and system paths. Every **component-private root is read-denied by default**: helper and broker private state, transport roots, and output roots, alongside the already-named deployment config root, key material, and agent-private state, because component-private data is reachable only through its owning component's mediation — that mediation is what makes the helpers' authorization, tenant isolation, and receipt paths meaningful. The helpers enforce private `0o700` roots and tenant-scoped access in their own code paths, but the workload runs as the same UID those checks run under, so a direct read of the cache's tenant-scoped SQLite store, the provisioner's private state directory and its SQLite ledger, or the source acquirer's private output root bypasses the owning helper exactly as a direct connector call bypasses the effect machinery. The read probes are instances of the rule, as on the write side: permission-negative read probes for every helper's and the broker's private-state, transport, and output root at their configured locations, alongside the existing read probes for the config root, key material, agent-private state, and sibling workspaces. Filesystem denial is not sufficient on its own: the step runs under the agent's own UID, and the existing process group bounds the step's descendants without protecting its parent, so a submitted pipeline can signal the agent — `SIGKILL` included — and crash it repeatedly into recovery and reconciliation. It also runs after `DEPLOY-003`, and transitively after `DEPLOY-004`: both change the deployment boundary this ticket's containment is specified against -- `DEPLOY-003` rewrites the lane's manager queries and `deploy/test-deployment.sh`, while this ticket needs deployment-side unit directives such as `Delegate=` for per-attempt cgroups -- and the Working rules require serializing tickets that share a boundary before implementation rather than reconciling them after review. It is also the sequencing `docs/architecture/DEPLOYMENT_TRUST_BOUNDARY_V1.md` asks for, since adopting that boundary decision after this row is written costs more than adopting it before. It runs after `EXEC-005` and `SECRET-002` for the same reason: those tickets create the helper launch paths and the production broker process, so denial gates completed before them would never have exercised the identities they introduce. The process gate follows a pid-targeting principle rather than an interface enumeration: a workload may operate only on processes inside its own containment — itself and the descendants it spawned — and **every kernel interface that takes another process as its target is denied** against any process the workload did not spawn. The current instances of that rule are signal delivery, `ptrace` attachment and process-memory reads, `/proc`-based inspection, and the scheduling, priority, affinity, and resource-limit controls — `setpriority`, `ioprio_set`, `sched_setaffinity`, `prlimit64`, and their equivalents — the complement of the resource bounds below: the workload's own bounds constrain what it consumes, while this rule denies it control over what its peers consume, since deprioritizing or constraining the agent, controller, or helpers starves production without tripping a single consumption bound. The protected set is **every process sharing the deployment service identity** — the agent that spawned it, the controller, the connector, observer, and credential helpers, and any sibling attempt's workload processes — with permission-negative probes per eligible platform covering each interface class against those processes, the four resource-control interfaces included, and the equivalent process-handle-rights denial on Windows wherever accounts are shared. Each such denial binds the WORKLOAD'S OWN containment domain rather than the deployment service identity: a user-wide `hidepid`, `ProtectProc=`, or `ptrace_scope` change would satisfy this requirement's letter while destroying the deployment lane's own manager-query path, which reads `/proc/ExecMainPID/environ` to obtain the effective service environment because `systemctl --user show -p Environment` omits `EnvironmentFile=` contents. Restricting this to the agent parent would leave a submitter able to crash a connector into effect ambiguity, or the controller into production-wide recovery, without touching a file or a secret. Same-user IPC is part of this boundary, not a separate one: System V and POSIX shared memory, semaphores, and message queues, and abstract-namespace Unix sockets are addressable by UID rather than by filesystem path, so neither the write allowlist nor the endpoint denials touch them — the gates must prove a step can neither attach to any IPC object the agent, controller, or helpers own nor reach helper or control-plane RPC over an abstract-namespace socket. Ambient authority is a distinct dimension with its own closure principle: a workload must be denied **every same-UID endpoint whose function is to act on the caller's behalf outside the workload's containment** — the IPC gate above protects objects the agent and helpers own, while this one denies escape through a manager that owns the workload's boundary itself. The named mandatory instance is the user service manager the deployment lane runs under: the `DEPLOY-001` rootless lane manages the controller, agent, database, and bootstrap units through `systemctl --user`, so a same-UID step can otherwise connect to the manager's D-Bus and private API sockets under `$XDG_RUNTIME_DIR`, stop or restart production units, or have `systemd-run` launch a transient unit that executes outside the workload's process, network, filesystem, and resource containment entirely — permission-negative probes must prove the step can neither connect to the manager's sockets, nor control or stop any unit, nor create a transient unit or scope. The instance list closes by sweep rather than by review round: any other ambient-authority launcher present on an eligible platform — session D-Bus activation, cron or at where installed, the Windows service control manager on that platform — is either probed under the same rule or its absence on the deployed host is attested. Filesystem and process denial together are still not the whole boundary: the Unix executor launches the step with a process group and a cleared environment and no network restriction at all, so a native process can open sockets and reach a production destination or a local control or helper endpoint directly — bypassing the typed connector intent, the one-action grant, the fencing, and the observation path, which is exactly the attack `TM-051` names and requires native-process network, credential, and connector-RPC denial against. The gates must therefore also prove, per platform, that a submitted step cannot reach **any network destination that is not explicitly allowlisted for that workload** — not public egress only: private and VPC ranges and the link-local metadata range (`169.254.0.0/16`, the cloud metadata endpoint class) get their own permission-negative probes, because the connector accepts non-loopback HTTPS endpoints without requiring them to be publicly routed, so a canary destination sitting on an RFC1918/VPC network is reachable by exactly the direct traffic a public-egress-only probe never exercises — and cannot reach local control-plane or helper RPC endpoints. The allowlist's contents are constrained by a closure principle, not an enumeration: a workload's allowlist may contain **only destinations that belong to no mediated access class**, and each entry requires explicit owner approval recorded in the deployment contract. Every helper-managed class is mediated — the access classes `EXEC-005` wires through the sealed helpers, with that row as the single authority for the class list — as are the `SECRET-002` broker's secret-provider endpoints, connector destinations, observer endpoints, metadata services, and control-plane or helper endpoints; allowlisting any of them, deliberately or by deployment mistake, hands a native step a direct path around the mediating boundary's scoped grants, provenance, substitution checks, and receipts — the machinery those boundaries exist to enforce. The denial probes are instances of the same rule: unconditional permission-negative probes for **every configured endpoint of every mediated class**, each at its actual configured address rather than a representative range, because a probe aimed at an address class passes while the one allowlisted destination that matters stays reachable. A platform where that is not delivered keeps native-process cases ineligible. Denial is still not the whole boundary either: the Unix executor bounds elapsed time and captured output and creates a process group, and sets no CPU, memory, PID, or storage limit, so a step that can reach neither file nor socket nor process can still fork exhaustively, allocate until the host OOM-kills something, or fill the workspace filesystem — starving the very services the rest of this ticket protects. Resource bounds follow their own closure principle: **every host-shared consumable a workload can draw on carries an explicit per-workload bound with an adverse gate**, so a newly identified consumable is an instance of the standing rule, not a new requirement. The current instance list — CPU, memory, PIDs, file descriptors, workspace-storage bytes, disk-I/O bandwidth and IOPS, and network bandwidth, packet rate, and connection rate — exists because the executor sets no per-step rlimit or I/O control at all; because storage bytes do not bound I/O, a step being able to rewrite one quota-backed file forever to saturate host disk bandwidth without growing its storage, or exhaust shared descriptor capacity across its allowed processes; and because destination filtering does not bound volume, a low-CPU flood of one permitted endpoint being able to saturate the host NIC or connection-tracking capacity and starve the controller and helpers while every reachability probe passes. Each bound carries an adverse gate on each platform or explicit ineligibility there; a platform where that is not delivered is ineligible on the same terms as the rest of this ticket. Two spawn-time surfaces complete the same lattice. The child environment: the Unix executor clears it and repopulates only explicit variables, and the gates must prove, per platform, that the environment a step actually receives contains nothing derived from deployment credentials or key material beyond its explicit per-step allowlist — one inherited variable would hand the workload a secret without touching a file. And crash artifacts: a process holding key material must not leave that memory readable by a workload when it crashes — core dumps for the agent, controller, and helpers are disabled or routed where no workload can read them, and a workload's own crash artifacts land inside its assigned workspace, with a permission-negative gate proving each, per platform, or the same explicit ineligibility. That last one is not a smaller case than the credentials: the workload runs as the service user that owns the journal, so a submitted step can corrupt or delete the record that recovery, fencing, and exactly-once finalization are all read from, and a containment change that stopped at credentials would leave the executor's own truth writable by the thing it executes; if Windows containment is not delivered in this ticket then Windows agents are explicitly ineligible for `CANARY-001` and for the `REL-002` decision until it is, and the board records that ineligibility rather than leaving it implied. The DEPLOY-001 limitation naming this boundary is removed in the same change. Until then the right to submit a pipeline equals the right to read that host's deployment credentials. |
| DR-001 | DEFERRED | MIG-009, OPS-002, WAR-001 | Execute full backup/PITR/object reconciliation, regional-style controller/database loss, agent fleet loss, restore-epoch fencing, legal-hold preservation, credential and identity-provider rotation, canary requalification, rollback, and multi-day recovery soak. Prove documented RPO/RTO, no stale authority, no missing or duplicate logical execution/effect, and independently verified restored API/UI/CLI truth. A drill finding fixed through the runtime, deployment configuration, or packaged artifacts is a late correction under the Working rules: the invalidated release, deployment, and downstream evidence is regenerated before this ticket closes. |
| REL-002 | DEFERRED | PROOF-001, PERF-001, WAR-001, SEC-004, DR-001, MIG-009, SEC-005 | Produce the private release-readiness assessment and owner decision. Require every exact current app-bound merge context, including the `Foundation` and `Windows` aggregates, a fresh protection-rule receipt, independent exact-head review of merge-authority workflows, classifier, verifier, and oracles, signed/SBOM-bound package, supported-platform matrix, migration eligibility/disposition ledger, capacity margins, war/security/DR evidence, rollback target, known limitations, support/runbook ownership, and zero unresolved release blocker. Under the late-correction Working rule, no joined evidence may describe a pre-correction system: any runtime, deployment, mapping, or artifact correction made after the evidence it joins requires that evidence regenerated before this decision. Public publication remains a separate owner authorization. |

## Parity tickets (2026-09-10 re-orientation)

A code-level audit on 2026-09-10 compared shipped behaviour, not board status,
against Jenkins. The durable core is better engineered than Jenkins'
equivalent; the daily-use surface a Jenkins team touches is mostly absent, and
about 45k lines of substrate have no caller. The owner selected daily-workflow
parity as the north star, compile-only Declarative widening for Jenkinsfiles,
and the owner's GitHub repositories plus McLoving itself as first users. The
migration-authority ceremony lanes are `DEFERRED`, not cancelled; they resume
once a real team runs real pipelines. See `docs/adr/0016-product-parity-before-migration-authority.md`.

The target is one concrete pipeline: a GitHub push checks McLoving out inside a
digest-pinned container, runs lint and tests as several steps of one stage,
streams logs while it runs, uploads artifacts, and reports a commit status on
the pull request. Every ticket below makes one line of that file true. The
dependency edges encode the single-implementer dispatch order; where a ticket
does not technically need its predecessor the edge still holds because the
three-mutable-PR cap and shared agent/controller surfaces make the order the
real constraint.

Progress is measured as **distance**: the count of unclosed tickets between
here and `PAR-005`. It is reported every two weeks in `docs/handoffs/CURRENT.md`
and must fall; a ticket added to this chain is reported as a regression, not
filed silently. Each ticket's proof is a command run on HeMan with its output
recorded in the pull request body, plus the unchanged threat-model row.

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| PAR-000 | ACTIVE | — | Re-orient the board, ADRs and handoff to product parity. Mark the ceremony, UI and late-campaign tickets `DEFERRED` and remove them from the remaining topology; file this chain; write ADR 0016; record the GROOVY-001 answer as NO in an amendment to ADR 0006 listing the constructs that stay permanently unsupported (script blocks, dynamic load, arbitrary Groovy in when); raise the ADR count in the Foundation gate; restate the dispatch order and the distance metric in the handoff. Acceptance: both board verifiers and the board test suite pass; Foundation passes on the head. Docs only. Proof: the board verifier, the board test suite, the closure verifier and the closure test suite all exit zero on the merged head. |
| PAR-010 | PENDING | PAR-000 | Multi-step stages. Replace the content-sniffed execution-spec version with an explicit version-5 envelope carrying an ordered tagged step list plus optional image and artifact declarations. One node and one attempt per stage. Per-step output is distinguished by a step ordinal, which needs a schema change this ticket includes: a migration adds a step ordinal to the attempt log chunk key, defaulting to zero for every existing row, and the log publication RPC carries the ordinal under the new feature; stream values stay stdout and stderr. Step outcomes ride the terminal summary. The controller emits version 5 only for stages that need it and requires the new scheduler capability `multi-step-v1`, negotiated under feature `multi-step-execution-v1`, so an agent without it is never offered such a node. The execution spine keeps refusing anything but its current versions; cache and input intents stay single-step. Acceptance: a stage declaring three process steps where the second fails yields two log streams and a failed build, an agent that crashes between a step's process exit and the durable record of that exit cannot tell completion from interruption, so on restart the attempt fails as ambiguous with that reason rather than re-running or skipping the step, and that exact crash point is tested; a crash after the record is durable resumes at the next step; and an old agent binary never receives the node. Proof: `mcloving submit` on a three-step fixture pipeline whose second step is `false`, then `mcloving logs` on the build showing streams for step zero and step one only and `mcloving status` showing failed. |
| PAR-011 | PENDING | PAR-010 | Container stages. A stage may declare a digest-pinned image; each of its steps runs under rootless podman with the attempt workspace bind-mounted and nothing else, keeping the process-group teardown proof and adding proof that the container id is gone. Tag references are refused. Capability `container-podman-v1` is advertised only when the pinned podman path answers. This is the Linux containment answer for container stages and is recorded against `SEC-005` as partial: plain process steps remain uncontained. Acceptance: a step reads its image's os-release, a timed-out step leaves no container behind, and a step cannot read the service account's configuration directory. Proof: `mcloving submit` on a fixture pipeline whose image is a pinned alpine digest and whose step prints its os-release, then `podman ps -a` on the agent host showing no container for the build after a timed-out sibling step. |
| PAR-012 | PENDING | PAR-011 | Checkout step on the product path. A `checkout` step kind in the IR is executed by the agent through the sealed source-acquirer helper using the same private-binding, digest, capability and private-IO pattern the cache and input helpers use; the helper acquires into its own private tree exactly as it does today, and the agent then publishes the tree into the attempt workspace by a confined, descriptor-relative, no-follow rename or copy that checks the destination's identity before and after, so a preceding untrusted step or a retained workspace cannot pre-create or race-replace the destination with a symlink and write through it into agent-owned files; version 1 requires an exact commit from the trigger payload or a parameter. Hosts that restrict unprivileged user namespaces run the helper from a pinned path under its AppArmor profile instead of a sealed memory file. Checkout and build steps share one stage in version 1; cross-stage workspace reuse is `PAR-015`. This delivers the source slice `EXEC-005` still owes. Acceptance: a real GitHub repository is checked out at an exact commit and a following step runs its tests in the checkout; a destination pre-created as a symlink by an earlier step is refused by name with nothing written through it; and a destination swapped between the identity check and the rename is detected and the attempt fails as substituted. Proof: `mcloving submit` on a fixture pipeline that checks out a public GitHub repository at an exact commit and runs its test command as the next step, then `mcloving status` showing succeeded. |
| PAR-001 | PENDING | PAR-012 | GitHub webhook receiver. A public route accepts GitHub push and pull-request deliveries, verifies the body signature in constant time against a per-hook secret derived from a controller key file and never stored, uses the GitHub delivery id for idempotency, maps the payload to the existing normalized trigger event, and admits it through the existing trigger delivery path with the trigger's own event-source identity as caller. Filtered deliveries are recorded and answered so GitHub shows success. A redelivery of an already accepted delivery id with the same authenticated payload is acknowledged with success carrying the previously admitted result, so a lost response or an operator redelivery never reports failure or mints a second build; a reused delivery id whose authenticated payload differs is refused with a conflict. Acceptance: a recorded real delivery admits a build; the same delivery again is acknowledged with the same build id and no second build exists; the same delivery id with a different signed body is refused with a conflict; a tampered body is rejected without a receipt; and the route appears in the OpenAPI document. Proof: `curl` posting a recorded GitHub delivery with its signature header to the hook route twice; both answers succeed and carry the same build id, a third post with the same delivery id but an altered body is refused, and `mcloving builds` lists exactly one build for it. |
| PAR-013 | PENDING | PAR-001 | Live log streaming. The agent publishes output while the step runs from a resumable high-water mark, reserving each chunk's sequence durably in its journal before sending so replay after a crash renumbers identically; the terminal publish verifies the final digest and that reserved chunks cover the whole spool; the per-attempt chunk cap rises under feature `live-log-stream-v1`. The logs route gains a single global follow cursor and a bounded long-poll; the CLI gains a follow flag. Acceptance: output is visible within about a second of being written while the build is running, and killing the agent mid-stream then resuming yields every sequence exactly once. Proof: `mcloving logs --follow` on a running build printing a line within one second of the step writing it; `kill -9` of the agent mid-stream, restart, and `mcloving logs` showing every sequence once. |
| PAR-014 | PENDING | PAR-013 | Artifacts from the agent. A stage may declare named artifact globs; after its steps the agent streams matching files to the controller over a new client-streaming RPC on the existing mTLS agent channel, and the controller commits them through the same store functions the HTTP upload routes use, under the same lease, fence and restore-epoch predicate as log publication, with a per-attempt byte quota. No second agent credential is introduced. Collection is confined: the collector walks the workspace descriptor-relative with no symlink following, uploads regular files only, and re-checks the opened file's identity against the path it matched, so a container step that plants a symlink to a service-account file gets a refusal that names the link, not an upload. Acceptance: a file written by a step is listed and downloadable through the existing artifact routes and CLI; an oversized set is refused with the attempt marked failed for that reason; and a workspace symlink pointing outside the workspace is refused by name and nothing is uploaded for it. Proof: `mcloving artifacts` on the build listing the declared name and `mcloving artifact-download` returning bytes whose digest matches the file the step wrote; the same on a build whose step planted an outward symlink lists nothing and the status names the link. |
| PAR-004 | PENDING | PAR-014 | Notifications. The build outcome derivation emits one terminal outbox event per build; a worker with a delivery ledger and exponential backoff delivers it at least once to notification targets. A pipeline names a target only by mapping id; the mapping itself is deployment-owned, loaded from a private bindings file the way the agent's helper bindings are, and binds the credential to what it may act on: a GitHub commit-status mapping names the exact repository the token may write statuses to, and a generic signed HTTPS mapping names the exact destination host and pins its certificate authority, resolved once per attempt to a numeric address set that is checked against private, link-local, loopback and controller ranges and then bound through connection establishment, so the credential-bearing connection goes only to an address that passed the check, with SNI and the Host header preserved, the resolve-check-bind sequence repeated on every retry, and redirects disabled. A pipeline naming a mapping outside its project, a repository the mapping does not own, or any destination the mapping does not name is refused at validation, so the worker never chooses where a credential acts. The existing outbox publish primitive is untouched. Acceptance: a commit status appears on GitHub for a real build; a sink that fails twice then succeeds shows three attempts and one delivery; two workers deliver once; a pipeline naming a repository the mapping does not own is refused at validation; a mapping whose destination resolves to a private or link-local address is refused before any request is made; and a rebinding test whose name resolves public at validation and private at connect makes no connection. Proof: `gh api` on the commit status of a real commit showing the McLoving context with the build's outcome and a target URL that opens the build. |
| PAR-005 | PENDING | PAR-004 | Dogfood. A pipeline file in this repository runs the Foundation lanes that need no user namespaces or privileged containers (lint, workspace tests, dependencies, secret scan, architecture records, controller PostgreSQL), triggered by the GitHub webhook and reporting a commit status. Acceptance: ten consecutive pushes to protected main where McLoving's verdict equals Foundation's for those lanes, recorded as a table in `docs/evidence/PAR-005_DOGFOOD.md`; any mismatch resets the count. Proof: for each of ten consecutive main pushes, `gh run list` for Foundation and `mcloving builds` for the dogfood pipeline give the same verdict, recorded in the evidence table. |
| PAR-003 | PENDING | PAR-005 | Human role grants. The identity admin tool and a project-scoped API can grant and revoke project roles; the first Owner of a project is grantable only through the admin tool; Owner is required to manage Owner; the last Owner cannot be revoked; revocation fences live sessions by bumping the identity's lifecycle generation; every change is audited. Acceptance: an Owner is bootstrapped, a Viewer is granted through the API, revoked, and the Viewer's bearer is refused. Proof: `mcloving-identity-admin grant-role` bootstrapping an Owner, `curl` granting a Viewer through the memberships route, `curl` revoking it, and the Viewer's bearer answered 401 on a build listing. |
| PAR-002 | PENDING | PAR-003 | Cron schedules. A native schedule calendar with Jenkins-style hashed fields is materialized server-side into a new mutable, generation-bound slot table added by migration in this ticket, keyed by organization, trigger and generation, so the trigger version rows the ingress migration makes immutable stay immutable; the existing schedule watermark check reads the slot from that table; the horizon is extended forward in that table without a generation bump as it empties; and a controller loop fires due slots through the existing delivery path. After downtime only the latest missed slot fires. Acceptance: two controllers sharing one database with a per-minute schedule produce exactly one delivery per minute over ten minutes; and with the horizon set to a handful of slots in test, firing continues past the original horizon without a generation change and the version rows are byte-identical before and after. Proof: two controller processes against one database with a per-minute native schedule, and a `psql` count of schedule deliveries that grows by exactly one per minute over ten minutes. |
| PAR-015 | PENDING | PAR-002 | Build workspace affinity. A build's later stages are offered to the agent that ran its first stage and reuse that build's workspace, so a checkout in one stage is visible in the next without re-acquiring it. The small checkpoint snapshot mechanism keeps its caps. Acceptance: a two-stage pipeline checks out in the first stage and builds from it in the second on the same agent, and a build whose agent is gone is failed with that reason rather than rescheduled blind. Proof: `mcloving submit` on a two-stage fixture pipeline that checks out in stage one and builds from the checkout in stage two, with `mcloving graph` showing both attempts on the same agent. |

The Jenkinsfile compile-only widening lane (expose the compiler from the CLI,
then widen Declarative directives in corpus-frequency order: echo, environment,
post, when, options, parameters, archiveArtifacts, junit, parallel, bat) is
filed as its own tickets once `PAR-010` merges, because each directive must
map onto a native construct that exists first.

## Historical implementation and closure record

The ticket table and batch ledger above are the authoritative status sources;
this section intentionally does not pin the moving protected-main commit.
Protected `main` includes the completed compiler, shared-library,
state-transfer, core differential, identity lifecycle, authorization mapping,
external-client read/write migration gates, isolated external-input adapter,
scoped dynamic-agent provisioner, source-acquisition boundary, dependency
resolver, contained cache, destination-observer, and external-effect connector
boundaries, first-class pipeline operational-state fence, typed trigger-ingress
and versioned multibranch/organization-folder discovery boundaries, and
persistent-Windows work. DIFF-002's exact PR head passed all nine protected
checks and a clean independent exact-head review after all nineteen review
threads were resolved; its squash commit passed post-merge Windows and
unchanged-head Foundation attempt-2 verification. Mario's sealed
inventories contain no admitted dynamic
provisioner, workload dependency, production cache mapping, production
destination-observer mapping, production trigger mapping, or production
discovery, connector, or credential mapping and grant no live SCM, dependency
repository, cache, observer, credential, trigger, discovery, or connector
authority. Production
provisioning, source acquisition, dependency resolution, cache, observation,
trigger ingress, discovery, secrets, effects, canary, cutover, rollback, and
decommission authority remain separately gated. The persistent-Windows,
DEP-001, CACHE-001, OBS-001, JOBSTATE-001, TRIG-001, DISC-001, EXT-001,
SECRET-001, DIFF-002, DIFF-003, MIG-006, and REL-001 campaigns are closed. The signed
v0.1.0 private Linux release is cryptographically verified but not deployed.
The exact-case MIG-005A corrective closure and MIG-007 certification join are
complete. The owner-private package has been generated from those exact objects
and independently verified as deny-authority shadow eligible. SHADOW-001 is
complete for that exact disabled case. ALPHA-001 is accepted and complete at
protected-main commit `db1073c37ff6630ebc4824f138c23b7d82a5a013` with all
post-merge checks green. The owner ended the one-day override and resumed the
board on 2026-08-17. `CANARY-000` completed through PR #70 and verified
protected-main commit `c6a238ae9acdc997d14850d1752cecd54feec8b9` in
Foundation run `32080011592` and Windows run `32080011587`. No production
effect authority has been granted. On 2026-08-18 the board was replanned for
the remaining campaign: the runtime effect-integration gap was implemented and
rehearsed as `EXT-002`; the owner-run bench defects were adopted as `EXEC-001`
through `EXEC-004`; the whole-repository review added `OUTBOX-001`, `HYG-001`,
and `DEPLOY-001`; and the path to a real ceremony was made explicit as
`CASE-001` (owner-designated effectful case with fresh per-case certification)
plus `CANARY-002` (fixture-only ceremony driver). That replanned batch is now
closed except for its deployment lane: `EXT-002` merged as `03a1f5d` (PR #72),
`EXEC-004` as `8fb8ac5` (PR #74), `OUTBOX-001` as `ec1529b` (PR #75),
`EXEC-001` as `5f9aa31` (PR #79), `EXEC-003` as `2c3c266` (PR #80), `EXEC-002`
as `75e618d` (PR #82), and `HYG-001` as `880fb2c` (PR #83); `DEPLOY-001` merged as
`52b2ecb` (PR #84) with its follow-up `586230b` (PR #93), and its
`Deployment lane` job now gates every pull request. That lane reached a
mergeable state only after 162 review findings across 81 rounds, at a flat two
per round whose per-day rate never declined, with 83% of the findings in four
validation scripts rather than in the units and contracts they validate; under
the owner's standing correction-round cap that population is a design property
rather than a defect backlog, and the response is `DEPLOY-003`, which decides
the lane's trust boundary (`TM-050`,
`docs/architecture/DEPLOYMENT_TRUST_BOUNDARY_V1.md`) and bounds the surface
against it. `DEPLOY-001` did not close when it merged: the Working rule
requiring a threat-model review for every affected boundary was unmet, and no
evidence receipt existed, so the board correctly held it `ACTIVE`. Those
receipts were written -- `TM-050` and
`docs/evidence/DEPLOY-001_SECURITY_REVIEW.md` -- and it still did not close, for
a second and independent reason found in the same review: **no gate exercised the
systemd write path.** Install, upgrade and rollback all passed `--no-systemd`,
and postgres started from a quadlet-derived command rather than from systemd, so
unit generation, enablement, ordering and service-managed upgrade/rollback were
unproven and the row's clean-host acceptance was unmet.

**Its original acceptance received a bounded closure on 2026-08-27.**
`deploy/test-deployment-systemd.sh` installs to a
dedicated lingering service account's passwd home without `--no-systemd` and
asserts what the manager did: `daemon-reload`, Quadlet generating
`mcloving-postgres.service`, `Requires=`/`After=` read back from the manager,
`StateDirectory=` creating the agent workspace unaided, the stability window
against real units, health through the manager, and a service-managed upgrade
and rollback. The acceptance's second clause is met too: the deployable-runtime
gate runs against that installed deployment's database and roles -- after being
fixed, because it returned success with no assertions when
`MCLOVING_TEST_DATABASE_URL` was unset. Evidence
`docs/evidence/DEPLOY-001_SYSTEMD_LANE.md`. Running it found three shipped
defects: the runbook's own `enable` step failed on a Quadlet-generated unit,
`mcloving-upgrade` refused `Environment=PODMAN_SYSTEMD_UNIT=%n` and so could not
upgrade the lane it is written for, and the gate's silent skip above.

Wave 3 is merged through PR #12 at protected-main commit
`3756c2f0a15ad2c9ba1a9b96464b852a85f4ae1c`; the original Wave 4 migration
board is merged through PR #13 at protected-main commit
`abb7c91faa13712698fc20fb792882b879837942`. `W4-A` was initially closed
against the owner-designated Mario `jenkins-oracle-228` population. The
controller was
quiesced and copied at offline epoch `2026-07-31T06:44:17Z`; four manifests
cover 230 disabled parse-oracle jobs, one private-realm principal, 230 effective
ACL rows, 230 whole-source opaque CPS runtime surfaces, and 230 build-history
record classes containing 231 build instances. The sealed inventory fingerprint
is `3473f1528e0fa8b1b856ae4941e5a5169d4c2c46389b813d0dd34935fb505198`.
Corpus reconciliation subsequently proved that 220 of 230 inline-source
digests were truncated because the exporter ignored XML `GeneralRef` events.
The original inventory remains immutable as a rejected predecessor. Committed
exporter repairs preserve predefined/numeric references and classify shared
library requirements. Create-new successor
`inventory-20260731T064417Z-r2` reconciles all 230 disabled jobs at fingerprint
`b1c2f81c74ec0ffc36971f358f920b2d0775c6009f474bea924448cd2a1915c1`:
226 sources are byte-exact and four CRLF sources have explicit XML 1.0
LF-normalization receipts. Its manifest and eligibility-ledger SHA-256 values
are `8cf682d06522b050c97c504c1a516f33463bd906e4ee10c3d6a1c38c03c6ec07`
and `436c76718f537ce199e4177e4db9998aad4b661176ff25d5daef17e082e4e636`.
The digest-pinned secret scan passes and `MIG-000` is closed again. No inventory
row grants execution or effect authority.

`W4-B` is complete. `MIG-001` established the isolated compiler
worker binds exact Java, Groovy, Jenkins core, WAR, image, 90-plugin, and
inventory-profile hashes. Its rootless Podman launcher has no network, ignores
inherited image volumes, uses a read-only root/source, drops all capabilities,
clears and allowlists environment, and bounds CPU, memory, PIDs, file
descriptors, temporary storage, time, input, and output. Deterministic,
hostile-input, target-substitution, symlink, mount, secret-marker, and
authority-negative gates pass. `MIG-002` established the corpus at predecessor
manifest
`8c5bb4707303f54ea04e12b95196385cca53a860fe225f322dc324e279989d58`:
228 exact-commit sources, 230 disabled job mappings, 127 declared-license and
101 evidence-only `NOASSERTION` dispositions, six typed redactions across two
files, four XML line-ending receipts, 80 Declarative-valid, 199 compile/CPS
entry, and 119 agent-scheduling oracle outcomes. Native runnable and certified
equivalence remain zero. `MIG-003` admits exactly
`cinqict_jenkinsdev.Jenkinsfile`: one ordered `Build` stage and one literal
shell step, parsed without source evaluation. It emits canonical strict YAML
and a separate disabled state record bound to the exact Mario source,
generation, inventory, profile, compiler, and all-false authority ledger.
Rust independently reparses canonical EDN and both YAML documents, recompiles
and validates canonical IR bytes, and rejects malformed, noncanonical,
authority/profile/provenance/state/host-path/secret substitutions. The
rootless boundary, full workspace tests/clippy, corpus verifier, and
working-tree secret scan pass. The `MIG-003` successor corpus manifest is
`59faf74bb8ebfbd658f85b5224ec15ee7b0db841ad66b2da1326cd83adac4f2a`.
No compiler result grants scheduler, credential, agent, trigger, connector,
effect, canary, or cutover authority.

`MIG-004` seals `mario-jenkins-oracle-228-v1`: one exact
`workflow-durable-task-step` literal `sh` mapping at plugin version
`1479.v56e587f413a_7` and plugin SHA-256
`a0f0f1464ce3592f76d0f0079ce9fc2d4272594f995bf3d1a7ede4cd5031452e`.
The catalog byte digest is
`d383ab8e15593ca5cc2847633a1410b53e676442f60dfcca93606610d1f761c8`
and its independently derived semantic digest is
`1349f2864edb360cf1a954eda0327fe6e2d42549296437690f24168e54f80907`.
It is bound to the exact predecessor corpus and compiler profile, grants no
authority, forbids floating mappings, fallback, network, credentials and host
reads, and makes no certified-equivalence claim. Local-input,
shared-resource, and cache semantics remain explicitly unearned. Rust strict
YAML/schema admission and adversarial substitution gates pass. The catalog is
included in successor corpus manifest
`a28283de801854836887e9bc6cffd43c10bb078dbeff343fdf92d19b470a74c2`.

`W4-C` is deliberately split. `MIG-005A` is complete: deterministic forward
and reverse state-transfer receipts, monotonic PostgreSQL protection truth,
bounded no-follow filesystem materialization, and the disposable exact-profile
Jenkins -> McLoving -> Jenkins rehearsal are documented in
`docs/architecture/STATE_TRANSFER_V1.md`. The accepted successor rehearsal
also removes direct runtime receipt/record/protection writes, derives transferred
changes from bounded sealed Jenkins Git changelog bytes whose head and baseline
bind the exact checkout, and evaluates predicates only from immutable
migration-writer SCM evidence bound to the exact receipt, project, live fenced
agent attempt, and active restore epoch. Approval decisions are constrained to
their owning build windows, and canonical serialization is quota-bounded before
cloning or secondary processing. Jenkins graph history is derived from the
sealed native workflow API rather than fabricated stage names or build-wide
timestamps. McLoving build 3 is a five-node PostgreSQL DAG whose graph,
per-attempt timestamps and terminal outcomes, committed logs, available-artifact
inventory, and fenced checkout are reread from controller truth before export.
Attempt creation and dependency-readiness are distinct durable PostgreSQL
fields, while executing-attempt starts come from durable `attempt.running`
events. Automatic and operator retry paths atomically establish each new
generation's readiness; initially blocked attempts remain unready until their
dependencies are satisfied. Fail-fast skips,
unsatisfied-dependency skips, and queued
pre-execution cancellations are typed terminal-only attempts with no fabricated
start time; terminal timestamps remain monotonic, and logs are exported in the
global controller commit-cursor order.
Graph dependencies retain their exact `succeeded` or `completed` condition,
and imported Jenkins successors after observed non-successful stages use
`completed` rather than fabricated `succeeded` edges. Child attempts cannot
predate the first parent attempt that satisfies their exact condition;
`succeeded` edges require the final parent attempt to be successful, and child
chronology uses the first actually executing attempt rather than an earlier
terminal-only skipped placeholder. `completed` and `succeeded` edges bind to
the latest parent generation admitted at the child attempt's readiness time,
preserving both reopened-parent waits
and children completed before a later retry. Every retry
names its immediately preceding attempt and reason: `failed` for failed
predecessors, `fail_fast_skipped` for fail-fast-aborted predecessors, and
`dependency_not_succeeded` only when an actual active non-successful parent
generation supports the skip.
Missing, reordered, mismatched, and post-success lineage fails closed. Later
failed parent retries on `completed` edges do not invalidate already-admitted
descendants.
The reverse bridge verifies the full canonical build record byte-for-byte and
independently checks Jenkins-native build fields, workflow-stage semantics,
exact per-stage start times and durations, SCM changelog, log payloads,
artifacts, the complete canonical retry sidecar, four exact multi-attempt
histories, and a dedicated persisted
retention/legal-hold boundary. Actual record collection also fails before
cloning any record beyond the one-million-record bound. It
materializes the sealed retained-workspace inventory, makes its exact
`src/first.target` bytes a build-3 input, reverse-exports those bytes as a
build-owned artifact, and independently retrieves and compares that artifact
from Jenkins. Its exact transform binary SHA-256 is
`549ec832edb138cea2895cf02fc39a3e4ec244f8a0aec378473be8f952dfe4c9`.
Its source, transform, and reverse manifest SHA-256 values are
`0304557a39a7c2a58ff9e1f110bc1bd4ca3bb2df16b28d54cc3c94262b7f47c6`,
`e28b47d2aa70ec2ad8cdaa2c48e1100c8862c9a47765d22a355c1660e96cafe7`,
and `2063b41b982f2821d494bfba96d43125382ea39fb12a601fbed3ce0fd8a77e05`;
the forward and reverse bundle SHA-256 values are
`af172be8893e282b72fc20b820382c8236e18c7b981bc3b4acbf57884ead55e4`
and `1a66f2c6354011abd23f45671674291e0b22faeea1043791920fc5ee0123ef52`.
The final readiness repair keeps automatic and operator retries blocked until
their active dependency generation is actually satisfied, and gives legacy
runnable inserts a rolling-upgrade-safe readiness default without falsely
readying blocked DAG attempts. It also fences the pre-v18 retry
insert-then-node-reopen sequence, reclassifies that node from queued to blocked
when its active dependency generation is not terminal, and validates exported
dependency satisfaction against readiness rather than the later process-start
time.
An injected post-install failure restored repository, build, permalink, and
next-build-number truth, removed partial evidence, and passed immediate replay.
The source runtime is retained by default for the dependent phases and removed
only by an explicit cleanup flag. `MIG-005` then proceeded on its own branch
without waiting for unrelated state-transfer work; both lines joined only
through their required differential evidence. The serial persistent-Windows
evidence lane has closed `WIN-001`, `WIN-002`, and `WIN-003`.

`MIG-005` is complete. The strict-YAML
`mario-jenkins-oracle-228-shared-libraries-v1` ledger binds the frozen
inventory, job graph, runtime-dependency inventory, and exact 228-file corpus.
It reconciles 23 live loads plus two comment-only scanner false positives,
including seven runtime calls absent from the frozen naive scanner. A bounded
independent source walk finds the same 23 active load locations. Seven
distinct public references covering eight live occurrences resolve to exact
SCM commits. Their normalized `vars`, `src`, and `resources` inputs are sealed
read-only outside the repository: 518 files and 1,400,368 bytes, with no
symlink, hard-link, special-file, unexpected-namespace, writable-input, digest,
or provenance escape. Certification is Unix-only and rejects platforms where
a directory read-only attribute does not prove effective write denial;
Windows source certification awaits an ACL-aware verifier. Simple-name,
controller-mapped, dynamic, missing-ref,
and host-ambiguous loads remain explicitly unsupported. Source verification
does not grant Groovy, CPS, sandbox, plugin, controller, SCM, or credential
authority; executable cases remain exactly zero. The ledger raw and semantic
SHA-256 values are
`fb6ff37c33aba6288e9632e5d0993adf634d840c5fe21f6345dea5350f28e35b`
and
`f925714595d48efcf29ea9c64696a99cd361b6a4a9b847c2d96b807a63add309`.
Both digests are compiled into the verifier and independently reject a joint
ledger/lock/source substitution.
The authoritative platform-sealing-repaired external evidence is
`/sn8100/runs/mcloving/mig005-shared-libraries-20260801T120106Z-v10`; its
self-excluding manifest SHA-256 is
`6eb13730aa8827e890aeabe2133032eaa3007ce78f427d2936004f8a4151a418`
and covers 522 files. The path-collision predecessor
`971f0d6dc07c04257f54bb9757e1d26e557d62239282caa1b1bb11a5d0dc128f`,
bounded-traversal predecessor
`0f41561942d065d178a86aec82a8bd2db522ee66ac4e591ee531316de913f7e5`,
trust-root predecessor
`81ce26bd0335851b2e7deb7f292caa0a8cf725681afb947f5555a526c36cc44e`,
complete-coverage predecessor
`50bc61768682e225c6536d04db9dc940cf65a9ef164f956e336ca4f624448a5e`,
non-recursive README predecessor
`80032ba8401f0aa8b5ef974b043f5bb4172b887a5078842ee26bb982048a6f24`,
review-repair predecessor
`5387322af011b50fcb3d4200833d7a02b79a287518de4b55e62a412c33892517`,
full-corpus-lock predecessor
`f290fe2090dba32b2af907b8f55e60035fb14a14ce499a21d8560bce93a2daf7`,
README-lock predecessor
`ec598cbc26a39d8f2d69ebd3d8298f89dc5728dd5b91c5f8ea7215b4fd57b9cf`
and pre-README-lock predecessor
`a6671f966e3738e25135b33fc397b5fb21666ac60edb931b49e3b35672f5123b`
remain immutable.
The implementation and verification contract are documented in
`docs/architecture/JENKINS_SHARED_LIBRARY_ADMISSION_V1.md`.

`DIFF-001` is complete at the exact current compiler boundary. The only Rust-
admitted job in the 228-file corpus was executed independently in a pinned,
networkless disposable Jenkins 2.568.1 controller on Mario and through the
shipped McLoving controller/embedded Linux worker against fresh PostgreSQL on
an internal-only Podman network. Both derive the same canonical one-stage,
one-process, success trace with exact semantic stdout and zero user workspace,
artifact, test, approval, credential-grant, or external-effect output. An
independent bounded verifier checks the exact 30-file repository tree,
including the verified 90-plugin profile, exact Jenkins console, three read-only
bind sources, 2 GiB Jenkins-home and `/tmp` tmpfs ceilings, 16 MiB controller-log
ceiling, dropped-capability, memory/swap, ulimit policy, and a 600-second GNU
`timeout` controller watchdog with a 30-second TERM-to-KILL bound, plus two-sided
containment, database integrity, coverage, raw observations, and trace
equality. The raw McLoving admission/build digest, graph/build/node/attempt
identity, fence, graph/status/attempt terminal-result agreement, and ordered log
identity are cross-bound; the embedded worker enforces a 67,108,864-byte aggregate
stdout/stderr ceiling; resealed semantic,
identity, and authority mutations fail closed.
The exact Jenkins initializer digest/body, source path, controller chronology,
job/build identity, complete three-bind set, and bounded Jenkins-home tmpfs are
cross-bound. The exact
Jenkins container ID/name/creation/start identity, timeout/tini/jenkins.sh invocation,
configured image/user, and complete UID/kernel/locale/Java/Jenkins runtime
receipt are cross-bound. Build, workflow, stage, and step timestamps are
exact-bound and cross-checked as nested intervals within the watchdog, and the
hard-pinned 16-file capture-manifest digest closes the remaining raw Jenkins
receipt surface. The exact
McLoving runner container identity, invocation, entrypoint, complete mount set,
and configured capability policy are identical across pre/post receipts and
fail closed under resealed mutation.
Certified equivalence is 1/1 admitted
cases and 1/228 corpus cases. The remaining 227 cases and every unimplemented
family remain non-admitted with zero authority. The exact contract is
`docs/architecture/JENKINS_NATIVE_DIFFERENTIAL_V1.md`; expanding compiler
admission requires a new differential version. The sealed external evidence
is `/sn8100/runs/mcloving/diff001-native-20260801T173419Z-v44`, with a
self-excluding 35-file manifest SHA-256 of
`8cd2c506a7fc7438eae920c83b1089031e9b4fc763d2cb5bb596fe6ddfa00752`.
Immutable v5 is a superseded no-McLoving-containment predecessor; immutable
v10-v14 are rejected/superseded envelope iterations, v15 failed before
execution, v17 is the review-superseded predecessor to v18, and v18 is the
chronology-wording predecessor to v19, v19 is the identity-binding predecessor
to v20, v20 is the runner/source/mount-binding predecessor to v21, and v21 is
the Jenkins invocation/runtime-binding predecessor to v22. V22 is superseded
because its worker output was unbounded; v23-v25 failed before execution, v26
and v28 are exact-contract predecessors, v29/v30 are superseded 1 MiB-quota
evidence, v31 failed on evidence-mount permissions, v32 failed on a host-built
glibc mismatch, and the successful shared-64-MiB v33 capture was first
incorporated into v34. V34 is superseded because its Jenkins controller lacked
an enforced finite lifetime; v35-v37 are failed/provisional Jenkins recapture
predecessors. Time-bounded v38/v39 remained output-unbounded; v40-v41 failed
safely during bounded-home setup, and v42 proved a 1 GiB ceiling operationally
insufficient. Successful time-and-output-bounded Jenkins v43 is combined with
the unchanged McLoving v33 capture in v44; all predecessors
contribute no authority.
`DIFF-002` is complete. Its standalone state/policy
differential and contained exact-profile implementation receipt are complete.
The accepted clean-head run at `f0b3f6dced45f33e9ef6d0ea88af013912cb76bd`
compared live pinned-Jenkins observations with PostgreSQL-backed McLoving
authorization and operational-state observations. Jenkins drives distinct
manual, build-API, completed-upstream, post-commit SCM-hook, and timer-trigger
paths; McLoving drives its five corresponding typed admission paths. Both sides
deny all five while creating zero target builds. The run also proves
authenticated replacement IDs and stable Jenkins user-seed authorization
across distinct authentication objects. All four live observation schemas are
required to match their exact v1 contracts before parity can be true. The
runtime join also binds that scoped observation slice directly to the exact
compiled-digest certificate. The contained runner mounted source read-only,
compiled into a fresh temporary target, and sealed the 19-file evidence
manifest as
`10fbbaed1d819ad9ec6962710de3f557e35c834fb6741f7cb08b085526a81786`.
Exact PR head `c6baebe3ec3a702ee94c8fb1ad211a446fc787c8` passed all nine
protected checks and a clean independent exact-head review after all nineteen
review threads were fixed and resolved. PR #55 squash-merged as protected-main
commit `5e02566ac3f76d8261b6578f71ccb438bd51bda3`; Windows run
`31795542752` passed, and Foundation run `31795542707` passed on unchanged-head
attempt 2 after its first attempt's only failure was an unrelated short-lived
agent-runtime containment timing case. The exact test passed twenty consecutive
times on HeMan before the unchanged rerun passed the complete Foundation gate.
This closure does not inherit authority from the completed DIFF-001 or
MIG-005A receipts and grants no production identity, trigger, scheduler,
credential, effect, canary, cutover, rollback, or decommission authority.

`W2-C` is complete on `codex/wave2-agent-completion`. Production agents
negotiate `work-delivery-v1`, cancel execution on lease-renewal loss, commit
terminal replay authority and complete spool descriptors atomically before
upload, enforce bounded streamed log/result publication, and recover through
the original work or cancellation protocol. Linux reconciliation binds work to
non-reusable boot/process-birth identity and fails closed when the leader is
missing but descendants may remain. Windows process creation now assigns the
kill-on-close Job atomically before any workload code can execute; native
crash-boundary gates prove no escaped process.

After `W2-C`, the Windows tickets still required the full controller-driven
hosted campaign. `WIN-003` has now supplied the signed persistent-host package,
controller-interruption, and physical-reboot proof; cross-compilation and the
hosted test fixture were not used as substitutes.

Wave 3 is complete in three dependency-ordered batches. `W3-A` and `W3-B`
establish the native authoring, durable execution, security, audit, artifact,
and normalized-test contracts. `W3-C` exposes those contracts through one
documented public API used by both the CLI and the static UI; neither product
surface creates a privileged controller path.

`IR-003` is complete. Pipeline IR v1.1 preserves v1.0 canonical bytes for
legacy pipelines and adds typed public/secret parameters, explicit
expression-backed string fields, deterministic checked evaluation, propagated
secret taint, stable failures, independent parse/evaluation budgets, and an
independent canonical-byte validator for the entire new representation.
`IR-004` is complete. Component v1 packages bind their admitted Pipeline IR,
typed outputs, exact digest dependencies, and typed dependency inputs into an
immutable package digest. The pre-scheduling expander rejects floating
references, digest substitution, cycles, secret component parameters, input
type mismatches, and independent depth/count/stage/step/byte limit breaches.
Its canonical expansion binds exact component identities while excluding
presentation-only provenance, and emits a concrete v1.0 scheduling pipeline
plus an ordered provenance receipt ledger.

`CTRL-004` is complete. Deterministic matrices are capped before their stable
Cartesian expansion. PostgreSQL migration v9 persists complete DAG admission,
dependency conditions, node policies, retry history, fail-fast and owner
cancellation truth, and one logical outcome per node. Active-active claims
recheck dependencies and exact normalized platform/trust-pool constraints;
completion-only post nodes survive failure paths. Real-PostgreSQL tests prove
parallel Linux/Windows claims, bounded retry, restart recovery, join/post
ordering, identical-only terminal replay, fail-fast cancellation and
lease-expiry crash recovery, queued skip, owner cancellation, and
deterministic build derivation. W3-A is closed and `SEC-003` begins W3-B.

`SEC-003` is complete. Protected-environment approvals and credential grants
are durably bound to tenant, project, build, IR digest, environment, action,
expiry, attempt fence, restore epoch, agent, and session. The agent waits for
exact grants before process start; response-loss replay is safe before start
and denied after consumption. Redaction precedes every supported durable sink,
feature negotiation fails closed, and real remote execution proves
cross-tenant, cross-attempt, stale, replayed, and substituted authority denial.

`AUDIT-001` is complete. Tenant-prefixed append-only audit rows carry
monotonic sequences and SHA-256 chain links, have an externally verifiable
bounded export, deny update/delete, detect event/head gaps and substitutions,
and integrate monotonic retention plus legal hold. Controller event/outbox
publication automatically records scheduling, credential, approval, artifact,
and administrative categories, with explicit entry points for identity and
authentication actions.

`OPS-003` is complete. The filesystem object store has durable staged upload
tokens, resume, exact digest/size commit, explicit abort, quota enforcement,
no-overwrite CAS semantics, and unavailable-until-commit reads. Public
controller journeys stage, commit, list, inspect, and download artifacts bound
to the exact tenant/build/node/attempt/fence/name/digest/size/media type.
Substitution, partial upload, stale restore epoch, retention, missing/corrupt
reconciliation, controller restart, and remote-agent generated-state
isolation are gated.

`TEST-001` is complete. JUnit-style XML normalization is bounded to 8 MiB,
10,000 suites, 100,000 cases, depth 64, and 16 KiB fields. DTDs, entity
declarations, processing instructions, malformed XML, invalid durations, and
limit breaches fail closed. Schema-v1 suite/case rows retain stable ordinals
and explicit duplicate ordinals, deterministic aggregates, exact raw artifact
provenance, automatic 30-day source retention, immutable history, and a
bounded flaky-outcome query. PostgreSQL mutation denial, idempotent ingestion,
audit publication, and the shipped controller/agent execution journeys pass.
W3-B is closed. `API-002` is complete: the versioned public surface now
documents and serves pipeline validation/planning and optimistic-concurrency
catalogs, immutable components, parameterized DAG submission, resumable build
and log pagination, graph/status/cancel/retry, approvals, credential grants,
artifacts, normalized tests, audit, and scheduler explainability. Stable error
envelopes and unique OpenAPI operation identifiers cover every route. A
database-free contract matrix proves all 26 tenant routes reject both missing
authority and cross-tenant path substitution; real PostgreSQL and shipped
controller/agent gates prove the positive journeys.

`UX-002` is complete. The Rust CLI covers validation, planning, typed
parameter submission, resumable watch and logs, status and graph inspection,
cancel and safe retry, approvals, explainability, artifacts, normalized
tests, and audit. Human output and stable JSON share the same public API
client; bounded watch failures return explicit uncertain-state receipts,
artifact downloads refuse overwrite, shell completions are generated, and a
mock-controller end-to-end gate proves API-only operation.

`UI-001` is complete. The controller serves a static dashboard and pipeline,
build-graph, log, test, artifact, approval, audit, and explainability views
that call only documented public routes. The controller remains the sole
authorization authority and the browser keeps the optional API token in
memory. A restrictive self-only CSP forbids inline script and style.
W3-C and Wave 3 are closed.

**Correction, 2026-09-10 (`UI-002`).** The two sentences this paragraph used to
end with asserted that accessibility contracts covered landmarks, labels,
keyboard-visible focus and live status, and that a browser journey gate proved
the full desktop flow, strict-YAML validation, the audit and explainability
views, a clean console, and a 390-pixel viewport without page overflow. **No such
gate existed.** `crates/controller-api/examples/ui_browser_fixture.rs` was in the
tree unreferenced by any workflow, script or test, and there was no browser
driver in the repository at all. The only executing check,
`static_ui_is_csp_locked_external_only_and_accessibility_structured`, asserts on
the served HTML as text and renders nothing, so "clean console" and "390 pixels
without overflow" were claims nothing here could make. `UI-001` sits in both
exemption sets of the closure-receipt verifier, so it carried no receipt and no
attribution and nothing would have noticed.

`UI-002` built that gate and ran it. **The claims were not all true of the client
`UI-001` shipped.** Against the original source
(`83966def6a24e6bfbcae1354e422784ff09b20f37a6f71524fcfdf078f68826c`, recorded in
`docs/evidence/ui-002-browser-v1/README.md`) fourteen of eighteen assertions
passed and **four failed**: keyboard focus was destroyed on every dashboard
refresh **and** on the build view's own two-second timer, the dashboard and
pipeline views overflowed horizontally at a 390-pixel viewport, and every page
load logged a `favicon.ico` 404 to the console. The landmark, label and
focus-visibility contracts did hold. The fourth failure was invisible to the
first version of this gate, which made sixteen assertions and never rendered an
artifact row at all; review found that gap and the assertion that closes it is
what exposed the defect.

Those three are now repaired, and the repaired client
(`5fe7ee2b3e38219606422ce888dc1ed0c66c23cc84f9f5d745063e0e59f09939`,
`docs/evidence/ui-002-browser-v2/README.md`) passes all eighteen. That digest is
the one `UI-006` and later work must compare against; an earlier revision of this
correction named a superseded repaired client, which would have pointed
successors at the wrong source. **That is a claim about
the repaired source, not about what `UI-001` shipped**; the pre-repair baseline
is retained unchanged so the difference cannot be read away later.

One qualification survives rather than being retired: **assistive-technology
announcement is not checked mechanically.** The gate asserts the rendered
structures a screen reader consumes -- landmark roles, a resolved accessible name
on every control, live-region attributes together with observed text changes, and
a visible focus ring at every keyboard stop -- but it does not observe what any
screen reader says. The manual convention is that a change to a live region,
landmark or control label is exercised once with a screen reader before it
merges; no assertion in this repository is evidence that it was. Cross-engine
rendering is likewise uncovered: one pinned Chromium is the whole population.

`WIN-001` is closed on NucBoxG3 with the exact modified source archive
`6a182420c0274034d0ab7213f037b64a70d2e53974fedb292bbad0da05c2c9a9`
and release binary
`ee0f042e90215095d5873eec709d0560f3595174a9d3d7ef7e6a321f987c4446`.
The native Windows 11 SCM gate proves install, two starts and stops, durable
session epochs `1 -> 2`, WAL integrity, forced-crash reconciliation, complete
Windows tests, deny-warnings clippy, uninstall, and LAN SSH reachability. The
read-only 12-file evidence directory is
`C:\McLoving-Windows-Work\evidence-win001-20260803`; its self-excluding
manifest SHA-256 is
`5975d499b76fade9d0a60654c247bd8fe1cad93188bbb60f169cf3aef48a0101`.
`WIN-002` is closed on the same persistent host. Strict YAML and canonical
Pipeline IR v1.2 bind exactly `direct`, `windows_cmd`, or `powershell`; unknown
or inferred modes fail closed, and controller lowering preserves the explicit
mode through the outbound mTLS work protocol. The exact Windows agent binary
`34d4ddc58cf9d8f8d635fea2d039b6c95baffbcd8049abfe0a2ab6adbfbf7ed9`
and HeMan controller
`58f36b9f4ae0d359dd258386f14a52b540bb46a5d1b80433986c9c697e1d4ccc`
proved all three modes with durable log digests, cancelled a spawned process
tree, and then proved the descendant PID absent in a separate Windows job.
The ACL allowed only `SYSTEM` and Administrators full control, the stopped
journal was WAL/integrity clean with zero active attempts, and the native war
gate also covered timeout and service-crash cleanup under Windows PowerShell
5.1. NucBoxG3's read-only 16-file evidence manifest is
`1f2282bfe22cf91bf9db96be3fb7fea6ef364bbff2e0e3ed0d8923ac63ad4cae`;
HeMan's read-only controller/database evidence manifest is
`272b018f5abbc62ed148d2b3e3e7d90cc8574347d8fd930c603128dbdf5e5460`.
All one-day test private keys were destroyed after sealing.

`WIN-003` is closed on NucBoxG3 with the signed qualification package built
natively for the protected-runtime physical-campaign predecessor at commit
`ee4fffac0b6bcc1b5e901bf2e6dfe3e485fd2e65` and tree
`4c03ae6727af27b2184c3bd639b1af7d7af3f954`. The exact source bundle SHA-256
is `4bb82b92d0dcca2056f5f61866f7920b69ab91339f19c8b45bedd7887e252518`;
the signed binary is
`b7f9899013f88cf4be36c6c801a09f863b012da1cdd0582c17467cb149cf5019`;
and the package archive is
`0da1475c9482d7a51ff7198d85ac18692666275f70affa9ddc21ff761b249f08`.
The short-lived self-signed Authenticode identity is qualification evidence,
not `REL-001` production provenance. The packager binds its exact CNG key
`UniqueName`, requires exactly one `My`-store `-DeleteKey` removal, and emits
PASS only after the bound key file is absent. The external exact-package
qualification harness observed 13 CNG key files before and after with zero
delta; its public trust anchors were removed after the gate. Three historical
qualification containers exposed by this review were deleted by exact name
under receipt SHA-256
`c5f89fe770e1b53eaba5f9380ac55f8eb2210d4cad498f37da301e79f51fc079`.

The outbound mTLS gate proved direct, `cmd.exe`, and PowerShell execution;
durable stream digests; explicit cancellation with a separately verified dead
descendant; and controller interruption with one lease expiration, two fenced
offers, one logical success, and no escaped first child. A physical Windows
reboot advanced the agent journal session epoch `3 -> 14`, returned the SCM
service automatically, rejected a fresh-journal stale session, left zero
active attempts, and killed the pre-reboot PID. Because SCM shutdown allowed
the live agent to publish exit code 1 before power loss, that rebooted attempt
has one `failed` terminal, zero lease expirations, and one offer; it was not
silently retried. A separate post-reboot build succeeded. This exact terminal
distinction is one valid recovery path, not a claim that machine reboot and
controller loss have identical retry behavior. The gate also accepts only the
other observed honest race: one expired lease, exactly two offers, the
`retry-after-reboot` marker, and one terminal success. That alternate path is
preserved under manifest
`beec40cf748645cf48af5bf09e3cb7c65afefd4239392e277e19d42e52fa5284`.
The final reboot request UUID `1620cf3c-9a42-417c-b7f8-a37ae1350895` and build
ID `ba0d5fde-ebc4-4891-814b-bfddc1473807` were echoed by the host completion
and checked by the Rust gate, so a stale completion marker cannot satisfy the
run.

The final NucBoxG3 package/runtime successor has a read-only 24-file manifest
SHA-256 of
`5b952cabe3569deeb9e136ecaf0aea7e21df2f2251ac74b7c1139eafed175c18`.
Its nested package manifest SHA-256 is
`8e9916715c75d667db2ade01a029e4e523a47667eb1a5e4f24065e6976634172`
and verifies directly because the seal includes the exact signed binary and
cargo metadata. HeMan's 37-covered-file outer evidence bundle is sealed at
`/sn8100/runs/mcloving/windows/pr25-ee4fffa-final`; its self-excluding manifest
SHA-256 is
`1cbd6bb5dc24ad51cd749644cf27c2a0324c853854637bcaa816cb40d9d87ac4`.
It binds the exact source and package, native host and controller receipts,
PostgreSQL dump and schema, and cleanup receipts. The separate read-only
verifier supplement is sealed at `pr25-ee4fffa-verifier` with manifest SHA-256
`2e380825e8d5e6abaed4940bb1481510541c8aa26fa013ed1a10efec35413e6c`;
Claude timed out while tool-using and returned no verdict or finding. The
earlier `pr25-f7ae170-final`,
`pr25-cfd7aa2-final`, and
`pr25-9859c7a-final` bundles, plus `pr25-a250c86-final` and
`pr25-38dd5c8-final`, remain immutable predecessor evidence rather than the
current reviewed closure. The Nuc seal
removed the Windows service, installed identity, qualification trust anchors,
gate private key, and test-only recovery-probe shim; manifest-covered cleanup
receipts record that state. HeMan's remaining mTLS private keys and isolated
PostgreSQL fixture were removed after evidence capture and independently
rechecked. W2-B and the persistent Windows evidence lane are closed;
`REL-001` remains the separate production-signing dependency.

The final installer contract requires both the exact binary digest and signer
thumbprint. A native wrong-digest attempt failed before service mutation and
removed its temporary qualification trust; the accepted install reverified
the copied binary, removed temporary trust before service start, and left no
machine-wide qualification certificate after success. Replacement of an
existing service requires a bounded observed stop, protected prior-binary
backup, verified binary replacement, and in-place SCM reconfiguration. The
reviewed installer further creates every new staging, package, and TLS
generation directory with its restricted security descriptor in the atomic
Win32 `CreateDirectoryW` call. It rejects reparse ancestors, untrusted owners,
NULL DACLs, untrusted replacement rights, and raw generic-access grants before
creating any child. Binary, signer, and all three PEM inputs enter a fresh
protected `ProgramData` generation and retain their pre-staging digests. The
service binds to a GUID-named immutable TLS generation whose installed digests
match those captured from the original regular non-reparse files. Before
declaring SCM startup healthy, the installed service must produce schema v2
and a strictly positive session epoch while SCM remains running. Separate
native probes placed `GateRoot` and
`PackageRoot` below a public replaceable ancestor; both were rejected before
service or package mutation. The installer rolls back the whole service
transaction on every post-identity failure and prunes superseded generations
only after the running service points to the retained identity.

The production mTLS loader also parses the presented leaf certificate and
rejects it unless its validity window contains the current time. Generated
valid, expired, and not-yet-valid leaf tests exercise the same loader, and an
exact Windows-binary preflight rejected an expired certificate before creating
a journal or workspace. This closes the review seam where transport startup
could previously advance the journal before a later TLS handshake exposed an
invalid client identity.

The installer refuses every pre-existing `PackageRoot`: replacing a DACL
cannot revoke write/delete handles granted before the elevated run. Upgrades
therefore select a fresh namespace whose protected descriptor is installed in
the atomic directory-creation call. A native writable-root preflight proved
the prior ACL and marker remained byte-for-byte unchanged, with no gate or
service mutation. Failed transactions remove only the fresh package root they
created and only after identity, binary, and service rollback has succeeded.
The exact successor treats caller-writable `GateRoot` as input only. Journal,
workspace, and executable test scripts live under a fresh atomically protected
`PackageRoot\runtime` generation. The physical campaign granted ordinary
Users modify access on `GateRoot`, then proved its ACL and marker unchanged,
proved no runtime children appeared there, and verified the SCM environment
and healthy journal exclusively under the restricted runtime root.

PR #25's final review repair is commit
`eded04319089f182f90278285f6125fc51a34171`, tree
`7c762a15e12e583d8fdced60c76be0e26f5c3d8d`. The production mTLS preflight
now rejects a presented client certificate when an Extended Key Usage
extension excludes TLS client authentication or a Key Usage extension excludes
digital signatures; absent usage extensions retain the RFC-compatible default.
An exact native server-auth-only leaf was rejected before service, registry,
package, journal, or workspace mutation, while the existing service PID,
registration, and environment remained unchanged. Service replacement now
accepts only an existing protected runtime rooted at `runtime/agent.db` and
`runtime/workspaces`, observes it read-only, stops the predecessor, copies the
SQLite database plus WAL and the complete workspace tree into a fresh protected
package generation, re-observes equal stopped state, and only then installs and
starts the new binary. The new service must advance the migrated session epoch;
rollback restores the original registration, environment, binary, and running
state before removing the failed generation.

The full physical precursor campaign at commit `3df4ad0` passed every explicit
Windows mode, cancellation/crash recovery, controller interruption, and a real
reboot in 79.26 seconds, advancing epoch `3 -> 8`, killing the pre-reboot child,
and rejecting stale authority. The exact final repair package has source-bundle
SHA-256 `415a124723bc311a18ac18ee7268e4e28147c9d970b7e8870d101f38973be3c4`,
archive SHA-256
`e1d8fb6215309c16481f404ff4b753eb9846c14d65929cb4d1af24998339bc3f`,
and signed-binary SHA-256
`fb8a8318d2b2afc2064309362cb8ba7e5e5e424b4d938dea8b9931a16ecee901`.
The live replacement preserved predecessor epoch `193`, advanced to epoch
`229`, preserved active attempts `0 -> 0`, and copied two independently created
durable workspace markers byte-for-byte. NucBoxG3's read-only 27-file evidence
manifest is
`80a30bac93ec0ee090b3c2d380305fb71e9609175d1ab477e076ffd0f85f9ab2`;
the nested package manifest is
`9c96eb438f2408471ade25f7bd127e5d15571dec86d3fbed23fdf34c68a34ffa`.
The 41-covered-file cross-host bundle is immutable at
`/sn8100/runs/mcloving/windows/pr25-eded043-final`, manifest SHA-256
`8ecd9e79097f30e2ba2ccbf7160e940f3607f4e288e9bb6e1fb8161fa621a487`.
Cleanup receipts prove no campaign service, install root, gate private key,
temporary signer trust, test database container, or transient package/source
path remains. A bounded read-only Claude plan-mode review consumed 15 turns and
timed out at 180 seconds without a verdict or finding; it made no repository
mutation. Review threads `PRRT_kwDOTmTe486WOZn1` and
`PRRT_kwDOTmTe486WOZn4` are addressed by this exact evidence.

The exact-head authenticated-startup closure supersedes the precursor
attribution above. Commit `11a0e18f860cc6ea39a623e601ad5ff1defb11ee`,
tree `50ffb804978cd457eba92d3d702d7a1c70516fd7`, publishes a protected
session receipt only after the controller accepts the mTLS
`OpenSession` RPC. The installer requires that receipt to match the new
journal epoch, so a locally valid `clientAuth` certificate issued by an
untrusted CA cannot turn a pre-connect epoch reservation into install success.
The native negative gate proved local validation succeeded, controller trust
failed, no authenticated receipt appeared, and service/package rollback was
complete.

NucBoxG3 then ran the complete exact-package campaign in 126.32 seconds:
every explicit Windows mode, cancellation and crash recovery, controller
interruption, physical reboot, stale-authority rejection, and post-reboot LAN
SSH all passed. Reboot advanced session epoch `3 -> 8` with zero active
attempts. A first reboot observation honestly failed because Windows reused
the numeric workload PID for `svchost.exe`; the preserved diagnosis at
`/sn8100/runs/mcloving/windows/pr25-11a0e18-failed-pid-reuse` has manifest
SHA-256
`87d2fcdb0f1101335638a5200e58fcdddf38a0be33bd20720b5e589b65f398bf`.
The corrected gate binds PID plus `Win32_Process` creation time, and the clean
full rerun passed. Same-package live replacement preserved the predecessor
journal and workspace marker, advanced epoch `55 -> 56`, retained active
attempts `0 -> 0`, and matched authenticated receipt epoch `56`.

The final bundle, archive, and signed binary SHA-256 values are respectively
`bf8621cf639dde6183e0ee9f219cfaf6d67516049c24d30afc3c97e5b90f598a`,
`85ab3eb8117727a8f381b460f1545fdac62c88ac24c0f210fcf1be7bf08d0ba6`,
and `68aa3779c1c31e91c917c546cc4d5ae643d7cabe59690ff2b03bc64be066e609`.
NucBoxG3's immutable 28-file manifest is
`750dd34beddfb95349e631e72f4dfdb203d32e91768a0fbd71b16cd8973fadd5`;
its nested package manifest is
`da91469b403c9ea97f5ce9af75da0f47f872d4fdddd80d3d9fc08b6da95b2706`.
HeMan's immutable 21-file cross-host closure is
`/sn8100/runs/mcloving/windows/pr25-11a0e18-final`, manifest SHA-256
`0fe814ce842b6bdd978932f065eed5e8f591c60ad0075706f9ab303e49423e5b`.
Claude's bounded read-only exact-commit review returned `NO_FINDINGS` without
mutation. Review threads `PRRT_kwDOTmTe486WPgc3` and
`PRRT_kwDOTmTe486WPgc9` are addressed by the implementation and final-package
evidence. `WIN-003` therefore remains `DONE` on exact final-package proof.

The final verifier found that a transient post-authentication reconciliation
failure could advance the journal on reconnect while the original write-once
receipt remained pinned to the prior epoch. The follow-up repair makes receipt
publication an authenticated, atomic, monotonic update: equal epochs are
idempotent, newer authenticated epochs replace the receipt, and rollback to an
older epoch is rejected.

The repaired package is bound to commit
`06df6e82dec68e534c559b6fc90ad15cea1488e1`, tree
`c50ddee29b0a3bda637e2f1abc154fee88c2a6df`: bundle, archive, and signed
binary SHA-256 values are respectively
`53c83a6adcf09cff0f7ca95633f59c465657db6b693c289d76574c4bab3069d5`,
`3ae5c215581519ecdde0c96ceeec8243a4b6d0355cc6ed4e1927b2d655895ae2`,
and `596c5646c5a9754e15c6f72e00bd688a013c3dede0f229d01c13e88b4d965ecd`.
The complete physical campaign passed in 118.80 seconds, including every
explicit mode, recovery, controller interruption, and reboot (`3 -> 10`).
After the controller returned, the same protected runtime advanced to journal
epoch `23` and its authenticated receipt also read `23`, directly proving the
retry repair. Live same-package replacement then preserved workspace state and
advanced `23 -> 24` with zero active attempts.

NucBoxG3's immutable 29-file manifest is
`112b96f4144e8d222e0d51195db08a1385d4dd26bf3de6cd83500dd1e8dbc604`;
its nested package manifest is
`0dc85c43c1c08ad24d1e20e1191f37fb3999bf1de1d6ebb2ae2683557bf3abb1`.
HeMan's immutable 46-file cross-host closure is
`/sn8100/runs/mcloving/windows/pr25-06df6e8-final`, manifest SHA-256
`4ec9e0706ddd90c85c96894915994ecfd718384a831f83e3ee112f6098bb3ec4`.
Final bounded Claude review session `d9b4f97a-307f-44da-94f6-9018998ece32`
returned `NO_FINDINGS`; the repository was not mutated. Cleanup removed all
campaign services, install roots, source/package copies, TLS private material,
database container, and controller unit while preserving only sealed evidence.

### Exact final transactional post-start closure

The exact-head review found that superseded-identity cleanup and the final
runtime ACL assertion still ran after the service-install transaction's
`catch`. Commit `99dc9be1912df8b0920e7afc0ce5b496aa6f4ec6`, tree
`716b2e56b21e56e6b17408ea41dcd4ef68ef6f48`, keeps both post-start checks
inside that transaction so any failure restores or deletes the service,
binary, identity, runtime, and fresh package namespace through the established
rollback path. Read-only Claude verifier session
`ffc82179-b954-40f7-9397-67c2ab1bb4c5` returned `NO_FINDINGS` without
repository mutation. An exact-installer gate injected a failure after
authenticated service start and proved the new service and package root were
both absent afterward before the unmodified installer was allowed to run.

The final source bundle, archive, and signed binary SHA-256 values are
respectively
`3ed49c45b444852475b6740a698f01b29bafe358a77137192ecad03329070b08`,
`88d88c7271bdc78a016c932b80367505646157c6ea73a3e3d64e3e29b99c0641`,
and `3a45ee380fe81ef6639f23ed3edee2d45f5cfbd63863823e8b9030317321ee4b`.
The complete physical campaign passed in 138.47 seconds: every explicit mode,
recovery, controller interruption, stale-authority rejection, and physical
reboot passed, advancing epoch `4 -> 15` with zero active attempts. The same
protected runtime then reauthenticated at journal and receipt epoch `30`;
same-package replacement preserved workspace state and advanced `30 -> 31`
with zero active attempts.

NucBoxG3's immutable 30-file manifest is
`8ddb3ee02e9a42cf8adfacaf57fca0f97b0b74940d7cd407e0f44734f1992997`;
its nested package manifest is
`287ff9bf701761023fc094104f5b4274ddfb24362d8b67da7d90c331e1917b86`.
The immutable 46-covered-file cross-host closure is
`/sn8100/runs/mcloving/windows/pr25-99dc9be-final`, whose root manifest
SHA-256 is
`759ecb5016b55bc106874ed3f3bb73f6e9968af47f930242f1317f743d6da5f6`.
Final cleanup removed the campaign service, both install namespaces, caller
input gate and private keys, source/package copies, temporary controller,
database container, and TLS gate while preserving only read-only evidence.
Review thread `PRRT_kwDOTmTe486WRAEH` is addressed by this exact implementation
and physical rollback proof. `WIN-003` remains `DONE`.

### Recovery-ready authenticated-health closure

Exact-head review found that the persistent agent published its authenticated
session receipt after `OpenSession` but before reconciliation and finalization
recovery completed. A replacement installer could therefore accept a service
whose transport authenticated successfully while recovery initialization had
failed. Commit `f12759e2e4ae8ccc1977193864fb1f1ba58bdc4f`, tree
`e6793ea05a0284ec01c939f482532cb97dacdfe7`, moves receipt publication behind
both recovery initializers. The regression fixture seeds an epoch-40 receipt,
injects recovery-initialization failure for epoch 41, and proves the published
health receipt remains at 40.

The exact Windows source bundle, archive, and signed binary SHA-256 values are
respectively
`5efbe13e6807e80cef4538d009ec8e622dff92296d6de87ff62d07bd893a997f`,
`7814bd3717c51b2352bf45d6f9b1658a3916b33785540451f388021a7f26dff5`,
and `ae71f7bfd38b235677b1724c98930449f928a4db32e8758d3da452d334ffa2d2`.
The complete physical campaign passed in 129.68 seconds: every explicit mode,
recovery, controller interruption, stale-authority rejection, and physical
reboot passed, advancing epoch `2 -> 9` with zero active attempts. The same
runtime then completed authenticated recovery at epoch `44`; exact-package
replacement preserved workspace state and advanced `44 -> 45` with zero
active attempts.

NucBoxG3's immutable 30-file evidence manifest is
`ccab9ec5181e958c356dc3b55faca1890cdf84fa759bf1b3a5a588e503d4f51f`;
its nested package manifest is
`65398956aedfde0d6be979522cc42262aee7eccf5fd6b924bcf404cde23691b6`.
The immutable 48-covered-file cross-host closure is
`/sn8100/runs/mcloving/windows/pr25-f12759e-final`, whose root manifest
SHA-256 is
`b7afa4c61fc1aadca566b6cf17a575cae5ac75163fe34b7b15c56c86fb78b295`.
The first seal attempt correctly produced no accepted manifest because its
prepared harness still pinned the predecessor package identity; the harness
was corrected to the exact binary and signer, its unsealed partial directory
was removed, and the clean seal plus independent verification passed. Final
cleanup removed all 20 Windows campaign targets, both install generations,
the service, private gate key, signer trust, temporary controller, database
container, and HeMan gate roots while preserving only read-only evidence.
Review thread `PRRT_kwDOTmTe486WR08q` is addressed by this exact
implementation and native proof. `WIN-003` remains `DONE`.

### Operator-pinned gate identity and predecessor retirement closure

Final exact-head review found two remaining installer seams. A caller who could
write `GateRoot` could replace the controller configuration and TLS identity
before the installer derived their hashes, and successful replacement left the
predecessor package and private identity on disk. Commits
`8b1ad06a6a1f003113e0d2a049b1a648119bac33`,
`dac2111c09c7f03734019a43d5d4189cc5a44f52`, and final commit
`53b0c8abb38f81697769d73f3712c58f07318ae0`, tree
`f2d6d3d8163f32fc711b8cdf955a7723c088104c`, close those seams. The elevated
installer now requires operator-pinned SHA-256 values for the configuration,
controller CA, agent certificate, and agent private key, verifies them before
protected staging, and rechecks the protected configuration copy. A native
negative preflight made `GateRoot` caller-writable, supplied a false pin, and
proved rejection before service, package, or protected-input mutation.

Replacement now captures and validates the predecessor's complete protected
package, runtime, and identity paths before mutation. Rollback retains them
until the new service transaction commits. After commit, normalized
path-boundary checks prove SCM and its environment no longer reference the
predecessor; cleanup revokes the predecessor private key first and then removes
the complete predecessor package. The physical replacement deliberately used
`pr25-53b0c8a` and `pr25-53b0c8a-replacement`, proving a shared filename prefix
is not mistaken for path ancestry. It preserved the journal and workspace
marker, advanced authenticated epoch `15 -> 16`, retained zero active attempts,
and proved both predecessor key and package absent.

The complete 126.51-second physical campaign passed every explicit Windows
mode, cancellation/crash recovery, controller interruption, stale-authority
rejection, and physical reboot, advancing epoch `4 -> 9` with zero active
attempts. The exact bundle, archive, and signed binary SHA-256 values are
respectively
`3567bf664a38580f0c573db41010223802c19def5c7d168fc5bd4ebc11ffebd7`,
`fee0acb00b36db47a9e3c0dac19d37e419e08d4a07a0b4b441e8d1d4bcbfda7f`,
and `79ba8d94bf33d73ae2669ff74eba1923a91bf7eb92590bb41e93319d0ca05f75`.
NucBoxG3's immutable 31-file manifest is
`d4b711b1a30a58c7d3d0205a053690e8e9156d3f325953aae41623f1d6908b31`,
with nested package manifest
`03d39131cda7ca935b086e1638872001544d8c6ae448e396a91f2aaa65d64082`.
The immutable 49-covered-file cross-host closure is
`/sn8100/runs/mcloving/windows/pr25-53b0c8a-final`, root manifest SHA-256
`ee8ace88989f25d059e68fb654dba230b104bf9b7d857ad9704cca111957ac5d`.
Two precursor qualification attempts stopped without accepted manifests when
the gates exposed a prefix-comparison false positive and a PowerShell literal
error; their exact transient namespaces were reset before the clean rerun.
Final cleanup removed all campaign services, install generations, source and
package copies, TLS private material, temporary controller, database container,
and HeMan gate roots while preserving only read-only evidence. Review threads
`PRRT_kwDOTmTe486WSi65` and `PRRT_kwDOTmTe486WSi69` are addressed by this exact
implementation and proof. `WIN-003` remains `DONE`.

## September 10 earned predecessor closure

JCOMP-002B closes on PR #131 merge `49c7e3346529babc131b318a5cf4091e4194db8d` and its verified exact-main receipts. AGENT-007 closes only on response-budget correction merge `44f0498fbdf3a59434176e9d09a52e1260336260` and the successful exact-main evidence identified in its security review. Earlier PR #132 main failure remains retained. After JCOMP-002C earned closure, the board has 125 tickets, 93 DONE and 32 remaining, with 38 earned receipts, 37 attributed closed-ticket reviews and unchanged historical debt 37. JCOMP-003 subsequently earned closure as recorded below; the six unverified original cases and failed tooling captures remain historical evidence, not completed classification or paired certification.

After PR #136 protected merge and exact-main verification, JCOMP-003 is DONE. The board has 125 tickets, 94 DONE and 31 remaining, with 39 earned receipts, 38 attributed closed-ticket reviews and unchanged debt 37. EXEC-005 is selected PENDING; this closure bookkeeping does not claim helper implementation has started. Its EXT-002 and DEPLOY-001 prerequisites were already DONE.
