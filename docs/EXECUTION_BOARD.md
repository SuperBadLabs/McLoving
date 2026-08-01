# McLoving execution board

Updated: 2026-07-31

Status values: `PENDING`, `ACTIVE`, `BLOCKED`, `DONE`, `DEFERRED`.

Execution classes: `SERIAL`, `BATCH`, `PARALLEL`.

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
| W2-B | WIN-001, WIN-002, WIN-003 | DONE | PR #8 merged the Windows service/runtime foundation and hosted destructive fixture; the three product tickets remain active until their production work, recovery, atomic Job, and persistent-host gates close |
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
| Windows evidence | `WIN-001` -> `WIN-002` -> `WIN-003` | SERIAL | Active | One persistent-Windows evidence generation at a time; the lane may run beside Linux/repository work |
| Library compiler | `MIG-005` | PARALLEL | `MIG-002`, `MIG-003` are done | Separate worker/library PR; it no longer waits for unrelated state-transfer work |

### Parity substrate lanes

| Lane | Ticket or ordered chain | Class | Start gate | Streamlined execution rule |
|---|---|---|---|---|
| Identity | `IDP-001` -> `AUTHZ-001` | SERIAL | Ready | Separate security-reviewed PRs; authorization starts from the merged identity model |
| Operational ingress | `JOBSTATE-001` -> `TRIG-001` | SERIAL | Ready | Separate PRs; merge and verify the operational-state fence before trigger ingress consumes it |
| Source acquisition | `SCM-001` | PARALLEL | Ready | Standalone contained-source boundary PR |
| Live inputs | `INPUT-001` | PARALLEL | Ready | Standalone read-only adapter and receipt boundary PR |
| Dynamic agents | `PROV-001` | PARALLEL | Ready | Standalone provisioner identity, lifecycle, and cleanup PR |
| Effects | `EXT-001` | PARALLEL | Ready | Standalone effect-authority connector PR |
| Observation | `OBS-001` | PARALLEL | Ready | Must remain a separate deployment, identity, credential path, branch, PR, and evidence set from `EXT-001` |
| Release provenance | `REL-001` | PARALLEL | Ready | Standalone builder, SBOM, signing, and verification PR |
| Cache | `CACHE-001` | PARALLEL | Ready | Standalone tenant/trust-class cache boundary PR |
| Secret mapping | `SECRET-001` | SERIAL | `SCM-001`, `EXT-001` | Starts only after both consumer receipt protocols are merged; no speculative adapter contract |
| Discovery | `DISC-001` | SERIAL | `TRIG-001`, `SCM-001`, `AUTHZ-001` | Integrates only the exact merged ingress, source, and policy contracts |
| Dependencies | `DEP-001` | SERIAL | `SCM-001` | Builds on the merged source-acquisition trust policy |
| External clients | `CONSUMER-001` -> `ADMIN-001` | SERIAL | `AUTHZ-001` | Separate PRs; close read compatibility before adding the higher-authority administrative write surface |

### Certification, authority, and proof lanes

| Lane | Ticket or ordered chain | Class | Start gate | Streamlined execution rule |
|---|---|---|---|---|
| Native differential | `DIFF-001` | PARALLEL | `MIG-005` | Standalone execution-semantic evidence PR |
| State/policy differential | `DIFF-002` | PARALLEL | `MIG-005A`, `IDP-001`, `AUTHZ-001`, `JOBSTATE-001` | Standalone state, identity, policy, and operational-state evidence PR |
| Boundary differential | `DIFF-003` | SERIAL | All parity-substrate tickets | Final external-boundary differential after exact implementations are frozen |
| Certification join | `MIG-006` -> `MIG-007` | SERIAL | `DIFF-001`, `DIFF-002`, `DIFF-003` | Aggregate closure first, reproducible migration package second; separate PRs |
| Production qualification | `SHADOW-001` -> `CANARY-001` -> `MIG-008` | SERIAL | `MIG-007` and named production substrates | Effect-free shadow, then narrowly granted canary, then receipt-only closure; never overlap authority states |
| Authority transfer | `CUTOVER-001` -> `ROLLBACK-001` -> `RECUTOVER-001` -> `DECOM-001` -> `MIG-009` | SERIAL | `MIG-008` | Strict one-at-a-time transition chain with a fresh pre-action threat receipt at every authority change |
| Performance | `PERF-001` | PARALLEL | `MIG-006`, `REL-001` | Isolated reproducible capacity lane; may run while later migration gates advance |
| Security review | `SEC-004` | PARALLEL | `MIG-008` and named security substrates | Independent adversarial lane; findings can stop the serial authority chain |
| Claim ledger | `PROOF-001` | SERIAL | `MIG-009` | Claims only from final verified authority-transfer receipts |
| War campaign | `WAR-001` | SERIAL | `MIG-008`, `PERF-001`, `WIN-003` | One signed package and one destructive campaign epoch at a time |
| Disaster recovery | `DR-001` | SERIAL | `MIG-009`, `WAR-001` | Runs after final authority truth and war evidence are sealed |
| Release decision | `REL-002` | SERIAL | `PROOF-001`, `PERF-001`, `WAR-001`, `SEC-004`, `DR-001` | Final join and private release-readiness decision; no implementation rides along |

### Dispatch discipline

After `MIG-005A` closure, the current three implementation slots are:

1. `MIG-005` — next shared-library/compiler lane.
2. `IDP-001` — longest remaining security critical path; `AUTHZ-001`,
   `DISC-001`, `CONSUMER-001`, and `ADMIN-001` all wait behind it.
3. `SCM-001` — independent contained-source boundary and prerequisite for
   `SECRET-001`, `DISC-001`, and `DEP-001`.

The Windows persistent-host campaign continues independently as an isolated
evidence lane. When a slot merges, select the earliest ready successor on the
same critical path before opening a lower-value parallel ticket. Do not exceed
three mutable implementation pull requests merely because more tickets are
dependency-ready.

## Wave 0 — Architecture and foundation

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| FOUND-001 | DONE | — | Private monorepo, ADRs 1–15, board, threat model skeleton, CI, clean protected merge |
| CI-001 | DONE | FOUND-001 | Preserve every protected required check while cancelling superseded PR runs, restoring commit-pinned Rust caches keyed by the lockfile/toolchain, and tiering the full Windows native-service/crash-recovery war gate to Windows-agent-impacting PRs and every push to `main`; a tested Linux router must compare changed source paths, the complete production-and-test package closure, resolved dependency graph, and normalized workspace build policy so an unrelated workspace-member/lockfile addition skips Windows without hiding an agent dependency change; persistent-host `WIN-003` evidence remains a separate release gate |
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
| WIN-001 | ACTIVE | AGENT-003, AGENT-004, AGENT-005 | Build a native Windows service agent with the existing outbound enrollment/session protocol and SQLite WAL journal; prove hosted Windows install/start/stop/uninstall, monotonic session epochs, process restart, and journal reconciliation |
| WIN-002 | ACTIVE | WIN-001, WIN-004 | Add explicit direct-process, `cmd.exe`, and PowerShell execution modes; isolate each attempt in a race-free Job Object and ACL-owned workspace; prove timeout/cancel/service-crash kills every descendant and preserves durable stdout/stderr/result evidence |
| WIN-003 | ACTIVE | WIN-002, E2E-003 | Maintain one versioned Linux/Windows semantic-parity matrix and run destructive hosted-Windows proof; then close with a signed package on a persistent Windows host through controller/network interruption and machine reboot, requiring matching terminal outcomes, logs, artifacts, cancellation, stale-authority rejection, and zero escaped descendants |

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
| MIG-005A | DONE | MIG-002, MIG-003, OPS-003, AUDIT-001 | Implement versioned, deterministic, idempotent forward and reverse state transforms for every admitted build-number, previous-result, per-build SCM provider/repository/ref/revision, previous-revision and canonical changelog/change-entry baseline, cross-build artifact, retained workspace, persistent-state dependency, retention policy/deadline, and active legal hold with its identity/scope/reason/provenance/generation/release authority. Bind immutable source export, transform implementation/configuration, destination state, record-level provenance, conflict policy, and verification digests; reject gaps, duplicate mappings, divergent replays, provenance substitution, unclassified state, deadline shortening, hold omission, and unauthorized release. Before `DONE`, execute both directions against disposable exact-profile Jenkins and McLoving instances with seeded history: include jobs whose `when { changeset ... }`, `when { changelog ... }`, or equivalent step consumes the prior SCM/change-set record plus records under shorter/longer/expired retention, multiple overlapping holds, and attempted unauthorized hold release; import state, prove equivalent-or-stronger retention and the union of active holds before reader or execution authority, deliver a pinned next revision with known canonical changes, prove the first destination build selects the same branches and effect intents from the transferred baseline, run a McLoving state-authoritative but externally effect-free build, freeze new work, reverse-reconcile its number, result, SCM revision/baseline/change entries, retention/holds, artifacts, retained workspace/state, and audit linkage, then deliver another pinned revision and prove Jenkins resumes with the same predicate decisions and without stale lookups, missing changes, missing artifacts, premature deletion, missing holds, duplicate mappings, or duplicate effects. Every stateful, SCM-baseline-dependent, retained, or held job requires a successful case-specific rehearsal before `CANARY-001` may grant production effect authority; the later receipt-only `MIG-008` closure cannot satisfy this pre-effect gate. |
| MIG-005 | PENDING | MIG-002, MIG-003 | Inventory and resolve Jenkins shared libraries by pinned SCM reference and content digest, including `vars`, `src`, and `resources`, while classifying load-time, runtime, sandbox, CPS, plugin, and credential dependencies. The worker ingests only owner-approved, prefetched, digest-verified read-only source and never receives direct SCM or credential authority. Arbitrary Groovy never runs in the controller; any future bounded isolated evaluation is owner-approved, meets the MIG-001 deny-authority boundary, and produces explicit unsupported receipts outside its admitted subset. |
| DIFF-001 | PENDING | MIG-002, MIG-003, MIG-004, MIG-005 | Certify core execution semantics in separate independently tested deny-authority Jenkins and McLoving sandboxes with exact platform/image/locale/toolchain/input-fixture receipts and bounded CPU/memory/time/output. Run every admitted parameter, condition, matrix, timeout, retry, caught-error, unstable-result, cancellation, post, parallel, join, fail-fast, multi-build, shared-resource, agent-selection, approval, dependency, cache, artifact, test, stdout/stderr, and success/failure scenario. Compare canonical stage/step arguments, normalized node/stage/build outcomes, attempt lineage, concurrency/order, cancellation, workspace and published artifact digests/metadata/API retrieval, normalized tests, logs/gaps, and deterministic classification. Scripted/unsupported cases must remain non-executable with zero work, grant, or effect. |
| DIFF-002 | PENDING | MIG-005A, IDP-001, AUTHZ-001, JOBSTATE-001, AUDIT-001 | Certify identity, authorization, operational state, and persistent-history semantics. Compare immutable source-to-target principal mappings and positive/negative view/trigger/cancel/configure decisions; enabled/disabled generations and pre-queue denial; build-number/previous-result/SCM-changelog baselines; cross-build artifacts; retained workspace/state; retention and legal holds; approval identity/value/expiry behavior; retry/result history; first-authoritative-run decisions; and forward/reverse reconciliation. Include rename/collision/deleted-identity reuse, group changes, disable races, stale generations, history gaps, hold omission/release denial, restart, and rollback fixtures. |
| DIFF-003 | PENDING | TRIG-001, SCM-001, SECRET-001, INPUT-001, PROV-001, EXT-001, OBS-001, DISC-001, DEP-001, CACHE-001, CONSUMER-001, ADMIN-001, REL-001 | Certify every live boundary through exact typed receipts and permission-negative fixtures: canonical trigger capture/replay, source acquisition and later revisions, secret consumer/taint eligibility, external runtime reads, dynamic provisioning, dependency/cache resolution, multibranch discovery, external read/write client migration, trusted release provenance, authoritative connector outcomes, and independently observed destination state. Compare implementation/configuration/account/resource/content/generation identities, downstream control flow, effect intents/outcomes, retry/ambiguity truth, observation freshness, and rollback restoration. Prove runner/connector/observer non-collusion, zero secret-marker disclosure, no residual Jenkins read/write client, no shadow production endpoint, substitution/replay/stale/outage denial, and zero duplicate effect. |
| MIG-006 | PENDING | DIFF-001, DIFF-002, DIFF-003 | Close the exact committed-corpus differential gate by verifying and aggregating all three immutable evidence sets without rerunning alternative logic. Require complete per-case coverage, matching source/oracle/profile/compiler/mapping/component/release identities across the evidence sets, zero unclassified jobs or mismatches for certified cases, deterministic fail-closed receipts for scripted/unsupported cases, and stable mismatch/regression taxonomies. The migration package does not exist yet and is neither an input nor an acceptance condition here; `MIG-007` creates it and binds it to this exact closure. Report production-population coverage, parse reach, native runnable coverage, actionable migration, deterministic rejection coverage, and certified equivalence separately; no metric can borrow another metric's denominator or imply production authority. |
| MIG-007 | PENDING | MIG-005A, MIG-006 | Generate a reviewable migration package containing canonical strict YAML, the exact reviewed `JOBSTATE-001` operational-state record, provenance, diagnostics, a mapping lock, exact source/oracle/profile/compiler digests, and the exact already-certified `MIG-005A` bidirectional state transforms plus `MIG-006` seeded-history differential and rehearsal receipts for every admitted state dependency. The package must round-trip to identical IR and operational state, contain no credential material, expose every substitution and unsupported boundary explicitly, bind immutable source export, forward/reverse transform, destination state, and verification digests for cutover and rollback, and reproduce the packaged receipt verification without invoking alternative transform logic. |
| SHADOW-001 | PENDING | MIG-007, JOBSTATE-001, AUTHZ-001, TRIG-001, SCM-001, SECRET-001, INPUT-001 | Prove deny-authority shadow execution before any production effect. Atomically freeze source/target enabled state, package/release/runtime identities, source revision, authz generation, agent-local inputs, clock/elapsed-time and non-security entropy streams. Capture each authenticated trigger, external read, approval/input/cancel/retry action, connector outcome, and other behavior-changing event once as a bounded receipt and replay it at the same state-machine point to both runners. The shadow has no production credentials, connector/deployment grants, scheduler/database/controller authority, host mounts, or write-capable network path; secret-dependent logic is admitted only through confidentiality-safe source/outcome receipts. Require exact MIG-006 trace comparison, isolated outputs, zero production request, and quarantine on drift, missing receipt, mismatch, or ambiguous authority. |
| CANARY-001 | PENDING | SHADOW-001, REL-001, EXT-001, OBS-001, DISC-001, DEP-001, CACHE-001, PROV-001 | Prove graduated per-job effect authority one action at a time under bounded quotas, retention, audit, failure thresholds, and abort rules. Before each grant, satisfy and bind the current pre-action threat-model receipt, live inventory reconciliation, quiescence proof, and complete runtime/input/authority freeze required by the Working rules; post-effect review or drift detection cannot satisfy the gate. Buffer both canonical intents and require exact match before granting the authoritative runner a production connector; the shadow remains effect-free and can never reach a production endpoint. Replay the authoritative bounded outcome into the shadow before downstream control flow, and require an independently observed destination-state/reconciliation receipt binding account/resource, precondition, request, result, freshness, and observer provenance. Ambiguity freezes new effects until reconciliation. Windows jobs require completed persistent-host interruption/reboot proof; unimplemented trigger, discovery, source, secret, dependency, cache, provisioner, observer, or connector classes remain ineligible. |
| MIG-008 | PENDING | SHADOW-001, CANARY-001 | Close shadow and graduated-canary readiness by verifying every per-job receipt against the exact MIG-007 package and MIG-006 certified case. Require zero unclassified mismatch, zero duplicate or shadow production effect, stable source/target/package/runtime identities, exact operational-state and authorization parity, complete trigger/input/outcome replay, successful abort/freeze behavior, independently observed effects, and explicit ineligibility for scripted/unsupported or workload-visible secret-dependent jobs. Partial truth or a regression budget can never trigger automatic cutover. |
| CUTOVER-001 | PENDING | MIG-008, MIG-007, REL-001, AUTHZ-001, JOBSTATE-001 | Define and prove the per-job cutover freeze and switch. Before the transaction, satisfy and bind the current pre-action threat-model receipt, live inventory reconciliation, quiescence proof, and complete runtime/input/authority freeze required by the Working rules; post-cutover review cannot satisfy the gate. Under owner approval and one signed transaction, atomically re-read every certified source and target identity: Jenkinsfile/library/job/core/plugin/global settings; source/target operational state and authz; trigger/discovery/source/secret/input/dependency/cache/provisioner/connector/observer configurations and generations; platform/agent/toolchain/local-input digests; migration package/YAML/IR/mapping/component/state transforms; McLoving release/SBOM/signature; and authoritative destination-state receipts. Any drift aborts without transferring trigger, scheduler, credential, or effect authority. Disabled, scripted, unsupported, unresolved, or uncertified jobs remain ineligible. |
| ROLLBACK-001 | PENDING | CUTOVER-001, MIG-005A, OPS-002 | Prove bounded per-job rollback after at least one authoritative McLoving build plus denial-only disabled-job probes. Freeze new triggers/effects, reconcile build number/result/SCM baseline/changelog, artifacts, retained workspace/state, retention/legal holds, audit linkage, operational state, agent-local inputs, and external outcomes through the exact MIG-005A reverse transform; restore the pinned Jenkins core/plugin/configuration, trigger/discovery/client authority, identity/authz and dependency/cache/source/secret mappings; then deliver a later revision/event and prove Jenkins resumes without stale lookup, missing evidence, unintended enablement, duplicate mapping, work, or effect. |
| RECUTOVER-001 | PENDING | ROLLBACK-001, MIG-008, MIG-007, REL-001, AUTHZ-001, JOBSTATE-001 | After `ROLLBACK-001` leaves Jenkins authoritative and proves a later Jenkins revision/build, execute the entire `CUTOVER-001` protocol again as a fresh transaction. Reconcile a new live inventory epoch; freeze current source/target/runtime/security/client identities; quiesce both sides; transfer every post-rollback trigger cursor, delivery, build/history/state, retention/hold, reader/writer, scheduler, credential, and effect-authority change through the exact certified transforms; and re-read all pre-action receipts. Prove McLoving becomes the sole current authority, Jenkins is fenced but still rollback-capable, the later Jenkins build and state are queryable on McLoving, and no delivery, work, history, reader/write operation, or effect is skipped or duplicated. A prior cutover receipt, stale snapshot, or closure-only verification cannot satisfy this ticket. |
| DECOM-001 | PENDING | RECUTOVER-001, CONSUMER-001, ADMIN-001 | Prove explicit owner-approved Jenkins scope decommissioning only after the rollback rehearsal, fresh final cutover, and rollback window. Re-read and bind the current `RECUTOVER-001` receipt and prove McLoving—not Jenkins—is authoritative immediately before retirement. Every production job must be cut over or owner-retired, every read-side consumer and administrative writer migrated or owner-retired, and no ineligible dependency may remain. Preserve and verify the final export and legal-hold evidence, then revoke Jenkins triggers, credentials, network, read APIs, administrative write APIs and compute; prove zero production traffic, caller, scheduled work, valid credential, live agent, or remaining Jenkins authority. Decommissioning is separately authorized from cutover. |
| MIG-009 | PENDING | CUTOVER-001, ROLLBACK-001, RECUTOVER-001, DECOM-001 | Close authority transfer by verifying signed rehearsal-cutover, rollback, fresh-final-cutover, and decommission evidence without invoking alternative migration logic. Require per-job eligibility, exact freeze identities, bounded dual-run and rollback windows, successful seeded-history transition, a current receipt proving McLoving holds sole authority immediately before retirement, no residual reader/writer/trigger/credential/compute authority, preserved retention/legal holds and final export, and zero duplicate work or effect. Publish the immutable disposition of every inventoried job, client, state class, and Jenkins scope; an unresolved item blocks closure. |

## Migration parity substrate tickets

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| EXT-001 | PENDING | SEC-003, CTRL-003 | Define the scoped out-of-process connector identity and versioned protocol for external effects. A connector has no scheduler, database, agent, controller-filesystem, or unrelated-secret authority; each action binds tenant/project/build/attempt/fence, exact connector and request digests, idempotency class, expiry, and audit provenance. Define a bounded signed authoritative-outcome receipt with typed response schema/status, canonical public values, protected secret references/taint, external identifiers, retry/ambiguity truth, and `OBS-001` destination-state linkage plus a deny-authority exactly-once shadow replay protocol that cannot reach the production endpoint. Prove downstream control-flow and later-intent equivalence after success, failure, retry, timeout, ambiguous completion, public/secret-bearing result, malformed/substituted/replayed outcome, and replay-adapter restart. Permission-negative integration, stale/replay denial, bounded retry, exact deduplication, and ambiguous-effect reconciliation gates are required before any connector-backed canary or cutover. |
| OBS-001 | PENDING | SEC-003, AUDIT-001 | Implement typed independently deployed read-only destination observers for every authoritative effect class discovered by MIG-000. Bind the exact observer implementation/image, protocol, deployment and operator trust identity, tenant/project/build/attempt/effect fence, destination endpoint/account/resource scope, canonical query, freshness cursor, response digest/signature, observation time, scoped credential grant, and audit provenance into a versioned receipt. The observer must use a separate service identity, credential-issuance path, configuration authority, and runtime boundary from every runner and effectful connector; it has no write, scheduler, controller database/filesystem, agent, workload-secret, connector-control, or effect authority. Prove valid pre/post/reconciliation reads, stale/missing/malformed/oversized/substituted/replayed responses, timeout/outage/restart, cursor rollback, observer/configuration/credential substitution denial, read-grant expiry and rotation, destination permission-negative behavior, and compromised-runner/connector attempts to control, impersonate, configure, credential, suppress, reorder, or fabricate observations against exact contained destination fixtures. Certify receipt verification and non-collusion before any `DIFF-003` effect-boundary differential, `CANARY-001` production effect grant, `CUTOVER-001` or `RECUTOVER-001` authority transfer, or `ROLLBACK-001` reversal; later aggregate closure cannot satisfy these pre-action gates. |
| INPUT-001 | PENDING | SEC-003, AUDIT-001 | Implement isolated typed read-only adapters for every live external runtime input discovered by MIG-000. Bind tenant/project/build/attempt, exact adapter implementation and protocol/schema, endpoint/data-source identity, scoped short-lived read grant, canonical query, consistency/freshness cursor, response digest/signature/provenance, confidentiality/taint, bounded size/rate/timeout, and audit lineage. The adapter has no write, scheduler, database, agent, controller-filesystem, unrelated-secret, or effect authority. Prove permission-negative behavior plus valid, branch-varying, stale, missing, malformed, oversized, unauthorized, endpoint/schema/identity substitution, replay, outage, retry, secret-marker non-disclosure, adapter restart, cutover, and rollback cases against exact contained fixtures before any dependent canary or cutover. |
| PROV-001 | PENDING | SEC-003, AGENT-004, OPS-001 | Implement a scoped out-of-process provisioner identity and versioned protocol for every dynamic agent class discovered by MIG-000. Bind tenant/project/build/attempt/fence, provider/account/region, exact provisioner implementation and request, immutable template/image/bootstrap/toolchain, requested platform/capabilities/trust pool, network/volume/workspace/cache policy, short-lived instance identity/IAM grant, quotas, expiry, and audit provenance. The provisioner has no scheduler, controller database/filesystem, unrelated-secret, workload credential, or external-effect authority. Prove template/image/provider/identity substitution denial, least-authority networking and volumes, capacity/exhaustion, duplicate/reordered/stale request fencing, startup failure, timeout/cancel, controller/agent/provisioner crash, partition, orphan detection and cleanup, scale-down, retained evidence, no escaped compute, cutover, and rollback against exact contained provider fixtures before any dynamic-agent canary or cutover. |
| TRIG-001 | PENDING | API-002, AUDIT-001, JOBSTATE-001 | Implement typed authenticated replacement ingress for every trigger class discovered by MIG-000, including SCM webhooks, schedules, upstream jobs, remote-build HTTP/API tokens, and admitted plugin-specific event sources; an unimplemented class remains explicitly ineligible. Bind tenant/project/pipeline, trigger type and implementation digest, event-source or caller identity, configuration/filter digest, delivery/event ID, schedule timezone/calendar, upstream build identity, idempotency key, expiry, and audit provenance; enforce bounded deduplication and replay windows. Prove valid and invalid authentication, branch/path/event and request filtering, duplicate/reordered/delayed delivery, outage retry and dead-letter recovery, schedule skew and restart behavior, upstream success/failure filtering, remote caller revocation, plugin-source substitution, pause/resume, cutover handoff, and rollback restoration before any trigger-dependent canary or cutover. |
| JOBSTATE-001 | PENDING | CTRL-004, API-002, AUDIT-001 | Add a first-class tenant/project/pipeline operational state, separate from immutable pipeline IR, with `enabled` and `disabled` values, monotonic generation, reviewed reason, actor/source identity, optimistic concurrency, idempotency key, effective time, and audit provenance in PostgreSQL and the public API/CLI/UI. Every manual, API, upstream, webhook, schedule, retry, replay, and administrative trigger path must atomically re-read the current generation and reject a disabled pipeline before queue/build materialization; schedulers must not claim it, and disable races must not mint work, credential grants, approvals, or effects after the disabling fence. Re-enable requires separately authorized generation advancement. Prove migration from existing enabled rows, disabled-state import, duplicate/reordered/stale transitions, concurrent trigger/disable and scheduler/disable races, controller restart and active-active consistency, authorization denial, audit completeness, package/canary freeze, and exact rollback restoration of state/generation/denial behavior before any migrated job receives effect authority. |
| DISC-001 | PENDING | TRIG-001, SCM-001, AUTHZ-001 | Implement Multibranch Pipeline and Organization Folder indexing/discovery. Bind the exact deployed discovery implementation binary or image digest and protocol/version, live parent-configuration digest, provider/organization/repository identities, branch/PR discovery and trust/filter strategies, Jenkinsfile path and selection policy, exact discovered revision and provenance, child identity/configuration policy, orphan policy, and audit lineage. Prove new/updated/deleted branch and PR discovery, trusted and untrusted forks, filtering, parent reconfiguration, implementation or configuration substitution denial, duplicate/reordered webhook plus periodic reindex, restart/outage catch-up, child authorization, orphan retirement, and rollback restoration before any parent or child canary or cutover. |
| SCM-001 | PENDING | SEC-003, AGENT-004 | Implement isolated live source acquisition for checkout, Git, submodule, and credentialed repository steps. Bind provider, repository identity, authenticated ref and exact revision, fork and trust policy, submodule graph, sparse/depth options, checkout implementation, scoped short-lived credential grant, and resulting content/provenance digests. Prove later-commit delivery, ref substitution and untrusted-fork denial, credential non-disclosure, replay resistance, bounded network/filesystem authority, cleanup, and differential checkout truth before any source-dependent canary or cutover. |
| SECRET-001 | PENDING | SEC-003, AUDIT-001, SCM-001, EXT-001 | Inventory every Jenkins-managed runtime credential reference and classify its exact consumer and taint path without copying secret material into migration packages. `connector-only` and `source-acquisition-only` mappings bind an owner-approved McLoving secret provider and versioned identity, keep credential bytes out of both pipeline runners, and use the exact `EXT-001` outcome-replay or `SCM-001` content/provenance receipt so the deny-authority shadow receives only bounded confidentiality-safe truth. A `workload-visible` credential delivered through `withCredentials`, environment, file, stdin, argument, or equivalent is ineligible for canary and cutover whenever its bytes can affect a branch, condition, process/effect argument, filename, public output, artifact, test, cache key, or other compared behavior; redaction alone cannot waive this boundary. Any future surrogate/replay mapping requires separate owner approval, a bounded typed protocol that reveals no secret-derived discriminator, deterministic equivalence proof for every admitted use, permission-negative tests, and explicit versioned provenance before reclassification. Bind tenant/project/environment/build/attempt/action scope, provider version, rotation generation, expiry, and revocation state to fenced short-lived grants. Prove missing/stale/replayed/cross-tenant/cross-attempt denial, rotation and emergency revocation, consumer/taint misclassification denial, supported-sink redaction, non-disclosure in logs/artifacts/audit, and least-authority integration before any credential-dependent canary or cutover. |
| IDP-001 | PENDING | SEC-002, API-002, AUDIT-001 | Implement production authentication and identity lifecycle before Jenkins principal mapping. For humans, validate issuer-bound OIDC authorization-code/PKCE sessions with exact issuer, audience, nonce/state, signature/JWKS generation, subject, group and claim mapping, expiry, refresh, logout, and session revocation; for automation, use separately revocable scoped service identities with rotation and no shared bearer-token table. Bind external subject/service identity to one immutable McLoving principal and tenant, preserve provider/configuration and group-generation digests, and retain a reviewed provenance edge back to the exact MIG-000 Jenkins security realm plus immutable source user/group identity, alias/rename history, membership generation, and lifecycle state represented by each mapped ACL principal. Audit authentication and lifecycle changes, and deny unknown, disabled, deleted, stale, replayed, cross-issuer, cross-tenant, group-removed, name-colliding, renamed-without-proof, or source-identity-reused actors immediately. Prove key rotation, provider outage, clock skew, session fixation, token/claim/issuer substitution, group membership addition/removal, user rename and same-name collision, deleted-name reuse, user disable/delete, service credential rotation/revocation, privilege-negative API/UI/CLI behavior, active-active consistency, and rollback restoration against real contained source-realm and target identity-provider fixtures before any production canary or cutover. |
| AUTHZ-001 | PENDING | IDP-001, SEC-002, API-002 | Map each inventory job's effective Jenkins folder/matrix/job authorization policy and principals into least-authority McLoving organization/project roles without broadening view, trigger, cancel, configure, approval, artifact, test, log, or audit access. Every reviewed mapping binds the MIG-000 source security-realm implementation/configuration digest, immutable source user/group identifier, alias and rename provenance, membership generation, lifecycle state, exact ACL entry and scope, target issuer/subject or service identity, immutable McLoving principal, target group generation, resulting role, reviewer, and policy digest; mutable names alone are never mapping keys. Prove positive and negative decisions, rename and same-name collision, deleted-name reuse, disabled/deleted principal handling, live group-membership changes, service-identity rotation/revocation, source-realm/configuration substitution, cross-issuer and cross-tenant denial, session invalidation, and rollback restoration before any migrated-job canary or cutover. |
| DEP-001 | PENDING | SCM-001, SEC-003 | Implement policy-bound workload dependency resolution for Maven/npm/PyPI and other admitted ecosystems. Bind repository identity and trust policy, package coordinate, exact version, lockfile, transitive graph, content and signature/attestation digests, resolver/toolchain, credential grant, and audit provenance; mutable or unresolved coordinates are ineligible. Prove missing, repository/package/graph substitution, compromised mirror, untrusted-source, credential leak, offline/replay, and later-resolution denial before any dependency-resolving canary or cutover. |
| CACHE-001 | PENDING | SEC-002, OPS-003 | Implement tenant/project/pipeline/trust-class-isolated dependency and build caches with canonical keys, immutable generation/content digests, explicit read/write policy, bounded size/expiry, atomic publication, and auditable provenance. Prove cold and valid-hit behavior, corruption and key/generation substitution rejection, untrusted-write/trusted-read denial, concurrent publication, rotation, eviction, cleanup, and restored-state behavior before any cache-dependent canary or cutover. |
| REL-001 | PENDING | OPS-002, AUDIT-001 | Produce trusted McLoving release provenance from reviewed protected-branch source through an isolated pinned builder. Bind source/tree, toolchain and builder image, dependency lock and SBOM, tests and policy gates, archive/component digests, version/profile, signer identity, and transparency/audit evidence; sign the immutable release and verify it before deployment. Prove source, dependency, builder, artifact, signature, and rollback-target substitution denial before any production canary or cutover. |
| CONSUMER-001 | PENDING | API-002, AUTHZ-001 | Inventory and migrate every external read-side consumer of Jenkins build status, graph, logs, tests, artifacts, queue, and job metadata to a versioned authenticated McLoving API/CLI or bounded compatibility adapter. Bind caller identity, tenant/project scope, endpoint/query and pagination contract, retention/URL semantics, rate limits, and audit provenance. Prove positive/negative authorization, historical and live data equivalence, artifact retrieval, pagination/stream resume, error and outage behavior, caller cutover, rollback restoration, and zero residual Jenkins reads before the corresponding job enters authoritative cutover or its endpoint is retired. |
| ADMIN-001 | PENDING | API-002, AUTHZ-001, AUDIT-001, CONSUMER-001 | Inventory and migrate every authenticated Jenkins administrative/write-side client, including Jenkins Job Builder, JCasC/Terraform automation, seed services, CLI clients, and REST clients that create, reconfigure, disable, delete, or otherwise mutate jobs, folders, nodes, credential references, or controller-global settings. Replace each admitted operation with a versioned authenticated McLoving API/CLI, declarative controller configuration path, or bounded compatibility adapter; bind caller identity, tenant/project or controller scope, exact operation/schema, desired-state and precondition digests, idempotency and optimistic-concurrency contract, authorization decision, and audit provenance. Prove create/update/delete convergence, duplicate/reordered/stale request handling, partial failure and retry, conflict and privilege denial, caller cutover, rollback restoration, and zero residual Jenkins writes before an affected job enters authoritative cutover or the corresponding Jenkins scope or endpoint is retired; unsupported operations require explicit owner-approved retirement before that cutover or decommissioning. |

Notifications and other non-migration product extensions remain follow-on
backlog. Provisioning, connectors, packaging, upgrades, rollback, retention,
and disaster recovery that are required for migration eligibility are owned by
the explicit tickets above or the proof tickets below; they are not an
unbounded “later Wave 5” escape hatch.

## Wave 8 — Better-and-faster proof

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| PROOF-001 | PENDING | MIG-006, MIG-008, MIG-009 | Publish an immutable claim ledger over the exact private and licensed OSS corpus only after authority-transfer closure. Keep parse reach, native runnable coverage, actionable migration, deterministic rejection, certified equivalence, canary eligibility, and successful authority transfer on separate denominators; derive the transfer denominator only from the current signed cutover, rollback, fresh-final-cutover, and decommission receipts verified by `MIG-009`; bind every number to corpus/oracle/package/release/evidence digests and prohibit “Jenkins compatible” or execution-superset claims not earned by the receipts. |
| PERF-001 | PENDING | MIG-006, REL-001 | Establish reproducible controller, PostgreSQL, agent, artifact/log, trigger, queue, and end-to-end capacity/regression envelopes on pinned HeMan, Mario, Luigi, and hosted Windows profiles. Report latency distributions, throughput, saturation/backpressure, storage sensitivity, resource use, recovery time, and explicit safety margin rather than harness timeout alone; compare the exact Jenkins oracle where meaningful and fail CI/release gates on reviewed regressions. |
| WAR-001 | PENDING | MIG-008, PERF-001, WIN-001, WIN-002, WIN-003 | Run destructive Linux and persistent-Windows campaigns with exact signed packages: overload, trigger storms, dependency/cache faults, connector ambiguity, controller/agent/database/object-store/network interruption, process and machine crash, reboot, cancellation, rollback, malformed/hostile input, multi-day soak, and no-escaped-work proof. Preserve immutable receipts, database/object integrity, recovery timelines, and post-campaign canary health. |
| SEC-004 | PENDING | MIG-008, IDP-001, AUTHZ-001, SECRET-001, EXT-001, OBS-001 | Complete an independent migration/security review and adversarial campaign across identity collision, tenant isolation, authz parity, credential grants, compiler/worker sandbox, trigger spoofing/replay, source/dependency/cache substitution, connector/observer non-collusion, secret disclosure, artifact/log/audit integrity, supply chain, and rollback/decommission authority. Every high/critical finding blocks release until fixed and reverified; accepted residual risk requires explicit owner approval. |
| DR-001 | PENDING | MIG-009, OPS-002, WAR-001 | Execute full backup/PITR/object reconciliation, regional-style controller/database loss, agent fleet loss, restore-epoch fencing, legal-hold preservation, credential and identity-provider rotation, canary requalification, rollback, and multi-day recovery soak. Prove documented RPO/RTO, no stale authority, no missing or duplicate logical execution/effect, and independently verified restored API/UI/CLI truth. |
| REL-002 | PENDING | PROOF-001, PERF-001, WAR-001, SEC-004, DR-001, MIG-009 | Produce the private release-readiness assessment and owner decision. Require all protected checks, exact-head review, signed/SBOM-bound package, supported-platform matrix, migration eligibility/disposition ledger, capacity margins, war/security/DR evidence, rollback target, known limitations, support/runbook ownership, and zero unresolved release blocker. Public publication remains a separate owner authorization. |

## Current state and dispatch queue

Protected `main` is `4980247824eae70c8ecc42f3305274811534ff14` after
PR #20 streamlined the execution topology. Dispatch follows the three-slot
topology above: `MIG-005`, `IDP-001`, and `SCM-001`. The persistent-Windows campaign remains
an isolated evidence lane. A slot advances to its earliest dependency-critical
successor after protected-main merge and exact-head verification; it does not
wait for the other independent slots.

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
materializes the sealed retained-workspace inventory, makes its exact
`src/first.target` bytes a build-3 input, reverse-exports those bytes as a
build-owned artifact, and independently retrieves and compares that artifact
from Jenkins. Its source, transform, and reverse manifest SHA-256 values are
`26176f86b6c5fadd935b26df9bb3db4aff57f3ba60122510042a0e1880baa83c`,
`f5c92cbe53316e960faa67ad35502d1ebda1f227b238f8e50432ff9a603dc964`,
and `d04806bb0e7a41ce1c8c0a893c2a6764b010065000a4b1ec17941c68fa651c17`.
The source runtime is retained by default for the dependent phases and removed
only by an explicit cleanup flag. `MIG-005` is next on its own branch
and no longer waits for unrelated state-transfer work; both join only through
their required differential evidence. `WIN-001`, `WIN-002`, and `WIN-003`
remain a separate serial persistent-Windows evidence lane that may run in
parallel with repository implementation.

`W2-C` is complete on `codex/wave2-agent-completion`. Production agents
negotiate `work-delivery-v1`, cancel execution on lease-renewal loss, commit
terminal replay authority and complete spool descriptors atomically before
upload, enforce bounded streamed log/result publication, and recover through
the original work or cancellation protocol. Linux reconciliation binds work to
non-reusable boot/process-birth identity and fails closed when the leader is
missing but descendants may remain. Windows process creation now assigns the
kill-on-close Job atomically before any workload code can execute; native
crash-boundary gates prove no escaped process.

After `W2-C`, the Windows tickets still require the full controller-driven
hosted campaign. `WIN-003` additionally requires a signed package on a
persistent Windows host through controller/network interruption and machine
reboot. Cross-compilation, a test-only service fixture, or hosted CI alone
cannot waive either boundary.

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

The still-active `WIN-001`, `WIN-002`, and `WIN-003` persistent-host closure is
tracked independently and remains a release gate for Windows parity; it does
not block platform-neutral Wave 3 implementation, and Wave 3 cannot mark those
tickets done by implication.
