# McLoving execution board

Updated: 2026-08-21

Status values: `PENDING`, `ACTIVE`, `BLOCKED`, `DONE`, `DEFERRED`.

Execution classes: `SERIAL`, `BATCH`, `PARALLEL`.

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
complete, merged as `03a1f5d` through PR #72; the qualification lane has
advanced to `CASE-001`, and `DEPLOY-001` holds the active implementation slot.
`CANARY-001` remains the production ceremony, and any production effect still requires a separate fresh
one-action owner authorization and every pre-action gate.

## Working rules

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
- If two nominally parallel tickets touch the same schema, protocol, policy,
  generated fixture, migration, package, or threat-model boundary, serialize
  them before implementation instead of resolving integration conflicts after
  review.
- Use one `codex/` branch and pull request per batch or standalone ticket.
- Keep one coherent commit per ticket where practical.
- Address every actionable Copilot review thread before merge.
- Required checks, review threads, exact commit, and clean worktree must be
  verified before protected-main merge.
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
| Library compiler | `MIG-005` | DONE | `MIG-002`, `MIG-003` are done | Separate deny-authority worker/ledger PR; exact 228-file reconciliation and prefetched-source verification are complete |
| State transforms | `MIG-005A` | DONE | Exact admitted-case corrective closure verified | The exact one-build `build-history` denominator now has bounded deterministic forward/reverse transforms, idempotent PostgreSQL import/retrieval proof, a durable imported-cursor/predecessor-bound effect-free McLoving continuation, and pinned Jenkins reverse-import/restart/next-build continuity; private source bytes and seal metadata remain only on HeMan |

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
| Production qualification | `CASE-001` -> `CANARY-001` -> `MIG-008` | SERIAL | `CANARY-000` protected-main verification complete; `EXT-002` merged as `03a1f5d` | Close the runtime effect-integration gap, then the owner designates and fully certifies one real effectful case before the separately authorized one-action ceremony |
| Ceremony driver | `CANARY-002` | PARALLEL | `EXT-002` merged | Producer side of the ceremony: signed gate-receipt assembly against contained fixtures only; the merged `CANARY-000` verifier is the acceptance oracle |
| Authority transfer | `CUTOVER-001` -> `ROLLBACK-001` -> `RECUTOVER-001` -> `DECOM-001` -> `MIG-009` | SERIAL | `MIG-008`, `SEC-005`, `REL-003` | Strict one-at-a-time transition chain with a fresh pre-action threat receipt at every authority change |
| Performance | `PERF-001` | PARALLEL | `MIG-006`, `REL-001`, `EXEC-004` done, `SEC-005`; long-step envelopes measure work rather than a session-epoch collision, and must measure the contained executor rather than one that is about to be replaced | Isolated reproducible capacity lane; may run while later migration gates advance |
| Security review | `SEC-004` | PARALLEL | `MIG-008` and named security substrates | Independent adversarial lane; findings can stop the serial authority chain |
| Helper runtime integration | `EXEC-005` | PARALLEL | `EXT-002` done, `DEPLOY-001` | Wire the sealed helpers into the product path so a submitted job can reach them; packaging a binary nothing calls ships a dormant executable, not a capability |
| Production secret broker | `SECRET-002` | PARALLEL | `SECRET-001` done, `DEPLOY-001` | Build the broker executable and bind its authority: a secret boundary reviewed on its own, before any release ceremony packages it |
| Release completeness | `REL-003` | PARALLEL | `REL-001` done, `DEPLOY-001`, `SEC-005`, `SECRET-002`, `EXEC-005` | Package and sign every executable the deployment lane installs, including the sealed helpers that dispatch external effects, ; `CUTOVER-001` cannot re-read a digest that no release contains. Completeness is per platform as well as per executable: `REL-001` covers `private-linux-x86_64` only, so a Windows canary needs a Windows release artifact or explicit ineligibility. No credential-dependent case is eligible until the broker ships |
| Workload containment | `SEC-005` | PARALLEL | `DEPLOY-001` | Contain the spawned step so submitting a pipeline is not equivalent to reading the host's deployment credentials. It runs in parallel with the qualification lanes, but it is a **gate**, not an unattached lane: `CANARY-001`, `CUTOVER-001`, and `REL-002` all depend on it, because granting a production effect, cutting over, or declaring release readiness while any pipeline submitter can read the deployment credentials and the agent's mTLS private key would carry a known credential escape past the exact decisions those gates exist to make |
| Claim ledger | `PROOF-001` | SERIAL | `MIG-009` | Claims only from final verified authority-transfer receipts |
| War campaign | `WAR-001` | SERIAL | `MIG-008`, `PERF-001`, `WIN-003` | One signed package and one destructive campaign epoch at a time |
| Disaster recovery | `DR-001` | SERIAL | `MIG-009`, `WAR-001` | Runs after final authority truth and war evidence are sealed |
| Release decision | `REL-002` | SERIAL | `PROOF-001`, `PERF-001`, `WAR-001`, `SEC-004`, `DR-001`, `SEC-005` | Final join and private release-readiness decision; no implementation rides along |

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
| Deployment lane | `DEPLOY-001` | PARALLEL | `REL-001` done | One supported install/upgrade/rollback path whose deployed digests the cutover freeze can re-read; `deploy/` README stubs stop counting as a plan |

### Dispatch discipline

The current dependency-ready implementation dispatch order is:

PR #61 is merged at protected-main commit
`2a8f983838b4bd063bd029b3e164f7ac36c20439`; both exact-head workflows,
clean exact-head review, resolution of all twenty-two review threads, and the
complete contained aggregate-evidence ceremony are complete. Exact-head
Foundation run `31912421075` and Windows run `31912421043` passed; protected-main
Foundation run `31914011695` and Windows run `31914011627` passed as the
post-merge verification receipts.

1. `MIG-005A` corrective closure — complete for the exact admitted job's one
   retained `build-history` dependency. Both directions, idempotent PostgreSQL
   persistence, the effect-free McLoving continuation, Jenkins reverse import,
   restart, and next-build continuity are retained under owner-only evidence on
   HeMan.
2. `MIG-007` — complete. The owner-private package
   embeds and verifies those exact bounded objects and receipts under separate
   owner-private manifest, implementation, and package pins: one packaged
   case, 227 deterministic rejections, package complete, and deny-authority
   shadow eligible. The merged public baseline still rejects all 228 cases and
   grants no shadow eligibility. Neither envelope grants production,
   canary, cutover, rollback, credential, trigger, scheduler, or effect
   authority.

The Windows persistent-host campaign is closed. When a slot merges, select the earliest ready successor on the
same critical path before opening a lower-value parallel ticket. Do not exceed
three mutable implementation pull requests merely because more tickets are
dependency-ready.

## Wave 0 — Architecture and foundation

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| FOUND-001 | DONE | — | Private monorepo, ADRs 1–15, board, threat model skeleton, CI, clean protected merge |
| CI-001 | DONE | FOUND-001 | Preserve every protected required check while cancelling superseded PR runs, restoring commit-pinned Rust caches keyed by the lockfile/toolchain, and tiering the full Windows native-service/crash-recovery war gate to Windows-agent-impacting PRs and every push to `main`; a tested Linux router must compare changed source paths, the complete production-and-test package closure, resolved dependency graph, and normalized workspace build policy so an unrelated workspace-member/lockfile addition skips Windows without hiding an agent dependency change; persistent-host `WIN-003` evidence was completed as a separate release gate |
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
polls at 10 ms — cause never isolated; that observation belongs to `PERF-001`
and is recorded here only so it is not lost. These four tickets were first
drafted in PR #41 and are adopted here with their measured evidence unchanged.

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

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| OUTBOX-001 | DONE | CTRL-001, CTRL-003 | The controller writes outbox rows in the same transaction as every durable state change, but no shipped binary drains them: `publish_outbox` is invoked only from `execution-spine` tests, so a deployed controller accumulates `published_at IS NULL` rows without bound. The 2026-08-19 scouted disposition is bounded retention with recorded no-consumer truth: keep the transactional write (the outbox is load-bearing for state-transfer receipt admission through the migration 0017 constraint trigger, and every row is triplicated into `build_events` and tamper-evident `audit_events`), add a fail-closed retention reaper in `bins/controller` that excludes `state_transfer.imported`, expose backlog observability, and amend ADR 0005 to record that no consumer is shipped and any future consumer arrives with its own contract bounded by retention. A publisher without a consumer and a mid-campaign retirement were both rejected with written rationale. Silent accumulation is not a neutral state. **Closure:** merged to protected main as `ec1529b` (PR #75). Bounded retention reaper in `bins/controller` excluding `state_transfer.imported`, backlog observability, and an ADR 0005 amendment recording that no consumer is shipped. |
| HYG-001 | DONE | — | Workspace hygiene with three bounded items. First, retire or absorb the placeholder crates `crates/domain` (14 lines) and `crates/state-machine` (18 lines, a stale second `AttemptPhase` definition diverging from the real phase truth in `controller-store` and `agent-runtime`); `bins/agent` must not depend on a placeholder. Second, give `crates/object-store` — the only core-plane crate with no integration test suite despite owning artifact immutability, quotas, redaction, and gap typing — a real `tests/` gate covering staged publication, quota enforcement, no-overwrite, and gap classification. Third, prove `OidcClientConfig::allow_insecure_loopback_for_tests` cannot be enabled from environment or configuration in the shipped controller binary with a permission-negative test. **Closure:** merged to protected main as `880fb2c` (PR #83). The placeholder `crates/state-machine` and its stale second `AttemptPhase` are gone and `crates/domain` is now the real shared vocabulary rather than a stub `bins/agent` depended on; `crates/object-store` has an integration suite covering staged publication, quota enforcement, no-overwrite, and gap classification; and a permission-negative test proves `OidcClientConfig::allow_insecure_loopback_for_tests` cannot be enabled from environment or configuration in the shipped controller binary. |
| DEPLOY-001 | ACTIVE | REL-001 | `CUTOVER-001` must re-read every deployed implementation digest, yet `deploy/kubernetes`, `deploy/podman`, and `deploy/systemd` are README stubs and only the AppArmor profiles are real. Implement one supported production deployment lane — systemd units or podman quadlets for the controller and agent, with the database bootstrap as its own unit — with digest-pinned release artifacts, split migration/runtime database roles, explicit environment contracts, health checks, and a documented install/upgrade/rollback runbook. Acceptance: a scripted install on a clean host brings up the controller and agent and passes the deployable-runtime gate, and the cutover freeze can read every deployed digest from this lane without hand-assembled state. **Bounded deliberately:** the signed `REL-001` artifact packages `mcloving-agent`, `mcloving-cli`, and `mcloving-controller` only — those are the three installed into `components/bin` and the three recorded in `components.json`. This lane also needs `mcloving-identity-admin` for the database bootstrap, so this change adds it to the release build as a fourth component with role `migration_tool`; `mcloving-release-provenance` builds the bundle and is not packaged in it. The sealed helper executables the spine spawns — `mcloving-source-acquirer`, `mcloving-dependency-resolver`, `mcloving-cache`, `mcloving-input-adapter`, `mcloving-provisioner`, `mcloving-external-connector`, `mcloving-external-shadow-replay`, and `mcloving-destination-observer` — are outside that release, so this lane cannot install them from signed, digest-pinned artifacts and does not claim to. That gap is `REL-003`, which gates cutover. |

## Migration campaign tickets

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
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
| CASE-001 | PENDING | EXT-002, MIG-000, MIG-007, SHADOW-001, MIG-005A, SEC-005 | Owner-designated first effectful production case. The sealed Mario population is a disabled parse-oracle corpus whose 230 jobs are all `unsupported`, so no production ceremony can exist until the owner designates one real enabled Jenkins job with exactly one connector-backed external effect class as the first canary candidate. Then complete, for that exact case and under the existing Working rules: a fresh signed inventory epoch through the `MIG-000` reconciliation protocol covering the job, its enclosing chain, readers/writers, runtime dependencies, and persistent state; a fresh `MIG-002` corpus stratum and scenario-contract revision with the effect and approval families no longer vacuous; `MIG-003` compilation and Rust re-admission; a `MIG-004` mapping-catalog revision binding the case's steps including the effect mapping to a certified `EXT-001` connector action; implemented generalized `MIG-005A` build-history forward and reverse transforms for the case's record classes, replacing the `mcloving/build-history-forward-unimplemented-v1` and `mcloving/build-history-rollback-unimplemented-v1` dispositions; refreshed `DIFF-001`, `DIFF-002`, and `DIFF-003` scenarios, a refreshed `MIG-006` aggregate closure, and a new `MIG-007` package whose packaged-case count includes this job; and fresh `SHADOW-001` qualification, under a v2 receipt schema if the case carries any live input, secret, connector-outcome, semantic-time, or semantic-entropy dependency, because the v1 schema is denial-parity only and a nonempty dependency count cannot be smuggled into it. This ticket grants no execution, credential, trigger, scheduler, connector, effect, canary, cutover, rollback, or decommission authority; the one production action remains a separately owner-authorized `CANARY-001` ceremony. Oversized boundaries discovered during execution split into owner-reviewed sub-tickets rather than sharing one pull request. |
| CANARY-002 | PENDING | CANARY-000, EXT-002 | Implement the producer side of the one-action ceremony so `CANARY-001` has a driver: signed gate-receipt assembly for the eleven pairwise-distinct signing roles, independent pin generation, canonical session assembly, and an owner-driven orchestration CLI that executes the seven pre-action gates, the fenced single connector dispatch under an `EXT-002`-enforced effect grant, pre/post/reconciliation destination observations, the exactly-once shadow outcome replay, and the final authority ledger — against contained fixture destinations only, with every production authority flag false. Acceptance: the merged `CANARY-000` verifier accepts a fixture-produced session end to end; every abort path — gate failure, freeze drift, intent mismatch, quota exhaustion, ambiguity freeze, missing receipt — produces a session the verifier rejects fail-closed; signing keys and pins remain owner-private on HeMan; no production endpoint, credential, connector grant, or destination is reachable from any ceremony component under test. |
| CANARY-001 | PENDING | CANARY-000, EXT-002, CASE-001, CANARY-002, SHADOW-001, REL-001, EXT-001, OBS-001, DISC-001, DEP-001, CACHE-001, PROV-001, SEC-005, REL-003 | Prove graduated per-job effect authority one action at a time under bounded quotas, retention, audit, failure thresholds, and abort rules. Before each grant, satisfy and bind the current pre-action threat-model receipt, live inventory reconciliation, quiescence proof, and complete runtime/input/authority freeze required by the Working rules; post-effect review or drift detection cannot satisfy the gate. Buffer both canonical intents and require exact match before granting the authoritative runner a production connector; the shadow remains effect-free and can never reach a production endpoint. Replay the authoritative bounded outcome into the shadow before downstream control flow, and require an independently observed destination-state/reconciliation receipt binding account/resource, precondition, request, result, freshness, and observer provenance. Ambiguity freezes new effects until reconciliation. Windows jobs require completed persistent-host interruption/reboot proof; unimplemented trigger, discovery, source, secret, dependency, cache, provisioner, observer, connector, or runtime effect-integration classes remain ineligible. This ticket stays `PENDING` until `EXT-002` is merged and verified, `CASE-001` delivers one fully certified effectful case, and `CANARY-002` delivers a fixture-proven ceremony driver. The exact action then requires a fresh explicit one-action owner grant; nothing in this board authorizes it. |
| MIG-008 | PENDING | SHADOW-001, CANARY-001 | Close shadow and graduated-canary readiness by verifying every per-job receipt against the exact MIG-007 package and MIG-006 certified case. Require zero unclassified mismatch, zero duplicate or shadow production effect, stable source/target/package/runtime identities, exact operational-state and authorization parity, complete trigger/input/outcome replay, successful abort/freeze behavior, independently observed effects, and explicit ineligibility for scripted/unsupported or workload-visible secret-dependent jobs. Partial truth or a regression budget can never trigger automatic cutover. |
| CUTOVER-001 | PENDING | MIG-008, MIG-007, REL-001, AUTHZ-001, JOBSTATE-001, DEPLOY-001, SEC-005, REL-003 | Define and prove the per-job cutover freeze and switch. Before the transaction, satisfy and bind the current pre-action threat-model receipt, live inventory reconciliation, quiescence proof, and complete runtime/input/authority freeze required by the Working rules; post-cutover review cannot satisfy the gate. Under owner approval and one signed transaction, atomically re-read every certified source and target identity: Jenkinsfile/library/job/core/plugin/global settings; source/target operational state and authz; trigger/discovery/source/secret/input/dependency/cache/provisioner/connector/observer configurations and generations; platform/agent/toolchain/local-input digests; migration package/YAML/IR/mapping/component/state transforms; McLoving release/SBOM/signature; and authoritative destination-state receipts. Any drift aborts without transferring trigger, scheduler, credential, or effect authority. Disabled, scripted, unsupported, unresolved, or uncertified jobs remain ineligible. |
| ROLLBACK-001 | PENDING | CUTOVER-001, MIG-005A, OPS-002 | Prove bounded per-job rollback after at least one authoritative McLoving build plus denial-only disabled-job probes. Freeze new triggers/effects, reconcile build number/result/SCM baseline/changelog, artifacts, retained workspace/state, retention/legal holds, audit linkage, operational state, agent-local inputs, and external outcomes through the exact MIG-005A reverse transform; restore the pinned Jenkins core/plugin/configuration, trigger/discovery/client authority, identity/authz and dependency/cache/source/secret mappings; then deliver a later revision/event and prove Jenkins resumes without stale lookup, missing evidence, unintended enablement, duplicate mapping, work, or effect. |
| RECUTOVER-001 | PENDING | ROLLBACK-001, MIG-008, MIG-007, REL-001, AUTHZ-001, JOBSTATE-001 | After `ROLLBACK-001` leaves Jenkins authoritative and proves a later Jenkins revision/build, execute the entire `CUTOVER-001` protocol again as a fresh transaction. Reconcile a new live inventory epoch; freeze current source/target/runtime/security/client identities; quiesce both sides; transfer every post-rollback trigger cursor, delivery, build/history/state, retention/hold, reader/writer, scheduler, credential, and effect-authority change through the exact certified transforms; and re-read all pre-action receipts. Prove McLoving becomes the sole current authority, Jenkins is fenced but still rollback-capable, the later Jenkins build and state are queryable on McLoving, and no delivery, work, history, reader/write operation, or effect is skipped or duplicated. A prior cutover receipt, stale snapshot, or closure-only verification cannot satisfy this ticket. |
| DECOM-001 | PENDING | RECUTOVER-001, CONSUMER-001, ADMIN-001 | Prove explicit owner-approved Jenkins scope decommissioning only after the rollback rehearsal, fresh final cutover, and rollback window. Re-read and bind the current `RECUTOVER-001` receipt and prove McLoving—not Jenkins—is authoritative immediately before retirement. Every production job must be cut over or owner-retired, every read-side consumer and administrative writer migrated or owner-retired, and no ineligible dependency may remain. Preserve and verify the final export and legal-hold evidence, then revoke Jenkins triggers, credentials, network, read APIs, administrative write APIs and compute; prove zero production traffic, caller, scheduled work, valid credential, live agent, or remaining Jenkins authority. Decommissioning is separately authorized from cutover. |
| MIG-009 | PENDING | CUTOVER-001, ROLLBACK-001, RECUTOVER-001, DECOM-001 | Close authority transfer by verifying signed rehearsal-cutover, rollback, fresh-final-cutover, and decommission evidence without invoking alternative migration logic. Require per-job eligibility, exact freeze identities, bounded dual-run and rollback windows, successful seeded-history transition, a current receipt proving McLoving holds sole authority immediately before retirement, no residual reader/writer/trigger/credential/compute authority, preserved retention/legal holds and final export, and zero duplicate work or effect. Publish the immutable disposition of every inventoried job, client, state class, and Jenkins scope; an unresolved item blocks closure. |

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
| PROOF-001 | PENDING | MIG-006, MIG-008, MIG-009 | Publish an immutable claim ledger over the exact private and licensed OSS corpus only after authority-transfer closure. Keep parse reach, native runnable coverage, actionable migration, deterministic rejection, certified equivalence, canary eligibility, and successful authority transfer on separate denominators; derive the transfer denominator only from the current signed cutover, rollback, fresh-final-cutover, and decommission receipts verified by `MIG-009`; bind every number to corpus/oracle/package/release/evidence digests and prohibit “Jenkins compatible” or execution-superset claims not earned by the receipts. |
| PERF-001 | PENDING | MIG-006, REL-001, EXEC-004, SEC-005 | Establish reproducible controller, PostgreSQL, agent, artifact/log, trigger, queue, and end-to-end capacity/regression envelopes on pinned HeMan, Mario, Luigi, and hosted Windows profiles. Report latency distributions, throughput, saturation/backpressure, storage sensitivity, resource use, recovery time, and explicit safety margin rather than harness timeout alone; compare the exact Jenkins oracle where meaningful and fail CI/release gates on reviewed regressions. Gated on `SEC-005`: containment changes how every workload process is launched and isolated, so envelopes measured before it describe an executor that no longer exists, and `REL-002` would then join on release-gating numbers nothing is required to regenerate. |
| WAR-001 | PENDING | MIG-008, PERF-001, WIN-001, WIN-002, WIN-003 | Run destructive Linux and persistent-Windows campaigns with exact signed packages: overload, trigger storms, dependency/cache faults, connector ambiguity, controller/agent/database/object-store/network interruption, process and machine crash, reboot, cancellation, rollback, malformed/hostile input, multi-day soak, and no-escaped-work proof. Preserve immutable receipts, database/object integrity, recovery timelines, and post-campaign canary health. |
| SEC-004 | PENDING | MIG-008, IDP-001, AUTHZ-001, SECRET-001, EXT-001, OBS-001 | Complete an independent migration/security review and adversarial campaign across identity collision, tenant isolation, authz parity, credential grants, compiler/worker sandbox, trigger spoofing/replay, source/dependency/cache substitution, connector/observer non-collusion, secret disclosure, artifact/log/audit integrity, supply chain, and rollback/decommission authority. Every high/critical finding blocks release until fixed and reverified; accepted residual risk requires explicit owner approval. |
| EXEC-005 | PENDING | EXT-002, DEPLOY-001 | Reach the sealed helpers through the product path. Packaging a binary does not put it in the spine: a repository search finds production process spawning only in `crates/execution-spine/src/effect_transport.rs`, which launches the connector, observer, and shadow services, and neither `bins/agent` nor `bins/controller` depends on or invokes `mcloving-source-acquirer`, `mcloving-dependency-resolver`, `mcloving-cache`, `mcloving-input-adapter`, or `mcloving-provisioner`. Each has its own contained test suite and none has a caller, so a submitted job cannot reach any of them and `REL-003` could otherwise close having installed five dormant executables. Acceptance: a submitted pipeline reaches each helper through the product path under its existing contained boundary, with an end-to-end gate per helper proving a job actually invoked it — not a direct test of the helper binary. Until a helper is wired and gated, the job classes that depend on it (SCM acquisition, dependency resolution, cache, live input, dynamic provisioning) are ineligible for `CANARY-001` and `CUTOVER-001`, recorded on the board rather than implied. |
| SECRET-002 | PENDING | SECRET-001, DEPLOY-001 | Produce the production secret broker and its authority boundary. `SECRET_MAPPING_V1` requires production deployment to bind the broker binary and release, owner-key source, provider adapter identity, network policy, service identity, trusted clock, secret-manager authorization, and the exact SCM or connector launch path before a credential-dependent canary or cutover is eligible; `crates/secret-broker` is a library crate with no binary target, and the contained provider used by tests is explicitly not production authority. This is a secret boundary, so under the Working rules it is one ticket and one pull request rather than a rider on a release ceremony. Acceptance: a production `mcloving-secret-broker` executable exists with each of those bindings implemented and permission-negative tests for each denial; no secret becomes workload-visible, since V1 has no operation that transfers one to a workload. Until it ships, every credential-dependent case is ineligible for `CANARY-001` and `CUTOVER-001`, recorded on the board rather than implied. |
| REL-003 | PENDING | REL-001, DEPLOY-001, SEC-005, SECRET-002, EXEC-005 | Package and sign every executable the deployment lane installs. `REL-001` produces a signed, digest-pinned artifact containing `mcloving-agent`, `mcloving-cli`, and `mcloving-controller`; `DEPLOY-001` adds `mcloving-identity-admin`, and `mcloving-release-provenance` builds the bundle without being packaged in it. A signed release therefore covers four executables. It does not contain the sealed helper executables the spine spawns — source acquirer, dependency resolver, cache, input adapter, provisioner, external connector, external shadow replay, and destination observer — so a host running the `DEPLOY-001` lane either does not have them or obtained them outside the signed release. `CUTOVER-001` must re-read *every* deployed implementation digest; a helper that is not in the release has no release digest to re-read, and a connector-backed canary effect is dispatched by exactly such a helper. One of them does not exist yet to be packaged. Building it is `SECRET-002`, not part of this ticket: it is a secret boundary, and the Working rules put secret and release boundaries in separate tickets and separate pull requests unless the board classifies them as `BATCH`, so the broker's authority bindings get reviewed and merged on their own before any ceremony packages the result. It runs after `SEC-005` for a reason worth stating: `SEC-005` changes the agent executor that this ticket packages, so a ceremony held first would produce and sign a pre-containment agent, and both tickets could then read `DONE` while the deployed, signed release still lets a workload read its host's credentials. Acceptance: one release ceremony packages and signs every executable the deployment lane installs, each with a `ComponentRole`; the deployment lane installs all of them from that artifact and nothing from outside it; the deployed-digest re-read covers every one, so the cutover freeze has a signed digest for each executable that can produce an external effect; and the `SECRET-002` broker executable is packaged and signed with the rest. Until that broker ships, every credential-dependent case is ineligible for `CANARY-001` and `CUTOVER-001`, and the board records that ineligibility rather than leaving it implied. The same completeness question applies per platform: `REL-001` signed `private-linux-x86_64` only, and the `DEPLOY-001` lane is a Linux systemd/podman lane, so nothing here covers a Windows agent. The `WIN-003` package cannot fill the gap — the board records its short-lived self-signed Authenticode identity as qualification evidence, explicitly not `REL-001` production provenance. `CANARY-001` still admits Windows jobs, so without this the board could authorize a Windows production effect executed by an agent binary that no production-signed release contains. Either this ticket produces a Windows release artifact under the same ceremony, or Windows canaries are ineligible for `CANARY-001` and `CUTOVER-001` until one exists, recorded on the board. |
| SEC-005 | PENDING | DEPLOY-001 | Contain a workload process so it cannot read the credentials of the host that runs it. Measured on the DEPLOY-001 lane: the agent spawns every submitted process step as its own service user, with no user transition and no filesystem sandbox, so a submitted step can read every 0600 file under the deployment config root — controller, API, and database credentials and the agent's mTLS private key — and can write the user-owned current release and helpers. `UMask=` and `StateDirectoryMode=` cannot close this: they are discretionary controls against other users, and the workload runs as this user. The deployment layer has no privilege to transition away from in a rootless user-level lane, so containment belongs to the agent executor, alongside the existing `mcloving-source-acquirer` and `mcloving-external-shadow-replay` profiles which already establish the pattern. The Windows executor has the same shape: it calls `CreateProcessW` in the service's own security context, so a submitted step inherits the agent service account's access to the mTLS and configuration material, and Job Objects bound lifecycle rather than privilege. Acceptance: on **each** platform a canary may be assigned to, a submitted step cannot read the deployment config root or the agent's key material, cannot write the release or helper directories, and a gate proves each denial; if Windows containment is not delivered in this ticket then Windows agents are explicitly ineligible for `CANARY-001` and for the `REL-002` decision until it is, and the board records that ineligibility rather than leaving it implied. The DEPLOY-001 limitation naming this boundary is removed in the same change. Until then the right to submit a pipeline equals the right to read that host's deployment credentials. |
| DR-001 | PENDING | MIG-009, OPS-002, WAR-001 | Execute full backup/PITR/object reconciliation, regional-style controller/database loss, agent fleet loss, restore-epoch fencing, legal-hold preservation, credential and identity-provider rotation, canary requalification, rollback, and multi-day recovery soak. Prove documented RPO/RTO, no stale authority, no missing or duplicate logical execution/effect, and independently verified restored API/UI/CLI truth. |
| REL-002 | PENDING | PROOF-001, PERF-001, WAR-001, SEC-004, DR-001, MIG-009, SEC-005 | Produce the private release-readiness assessment and owner decision. Require all protected checks, exact-head review, signed/SBOM-bound package, supported-platform matrix, migration eligibility/disposition ledger, capacity margins, war/security/DR evidence, rollback target, known limitations, support/runbook ownership, and zero unresolved release blocker. Public publication remains a separate owner authorization. |

## Current state and dispatch queue

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
as `75e618d` (PR #82), and `HYG-001` as `880fb2c` (PR #83); `DEPLOY-001` is in
review as PR #84. Reviewing `DEPLOY-001` measured a containment gap on its own
lane and produced `SEC-005`: the agent spawns every submitted step as its own
service user with no transition and no sandbox, so a submitted pipeline can
read the deployment credentials and the agent's mTLS private key. `SEC-005` is
therefore a dependency of `CANARY-001`, `CUTOVER-001`, and `REL-002`, not an
unattached parallel lane. The `EXEC-004` premise did not survive review:
renewal always ran during steps, and the wedge was a shared-agent-identity
session-epoch war. `PERF-001` is no longer gated on that disproven defect,
but it is gated on `SEC-005`: containment changes how every workload process
is launched, so envelopes measured before it would describe an executor that
no longer exists. `REL-003` is gated on `SEC-005` for the matching reason —
a ceremony held first would sign a pre-containment agent. The
current Mario inventory still has zero eligible production canaries, and any
real one-action effect requires separate fresh owner authorization after
`CASE-001` and `CANARY-002` are complete.

| Slot | Current ticket | Status | Dependency-critical successors |
|---:|---|---|---|
| 1 | `DEPLOY-001` | ACTIVE | PR #84; `CUTOVER-001` cannot re-read deployed digests until one supported install/upgrade/rollback lane exists, and `SEC-005` is measured on this lane |
| 2 | `CANARY-002` | PENDING | Producer side of the one-action ceremony against contained fixtures; `CANARY-001` has no driver without it |

Only two slots are filled, and that is the honest state rather than a gap to
be padded. Every other remaining ticket depends on `DEPLOY-001`, or on
`SEC-005` which depends on it in turn: the campaign is genuinely serialized
behind the deployment lane right now. Dispatching a third ticket would mean
starting work whose evidence the containment change is about to invalidate.

A slot advances to its earliest ready successor after protected-main merge and
exact-head verification; it does not wait for the other independent slots.

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
memory. A restrictive self-only CSP forbids inline script and style,
accessibility contracts cover landmarks, labels, keyboard-visible focus, and
live status, and the browser journey gate proves the full desktop flow,
strict-YAML validation, audit/explainability views, clean console, and a
390-pixel viewport without page overflow. W3-C and Wave 3 are closed.

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
