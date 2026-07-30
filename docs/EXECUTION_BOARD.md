# McLoving execution board

Updated: 2026-07-30

Status values: `PENDING`, `ACTIVE`, `BLOCKED`, `DONE`, `DEFERRED`.

## Working rules

- Select a coherent batch of three to six logically coupled tickets.
- Use one `codex/` branch and pull request per batch.
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
- After merge, select the next unblocked batch without waiting for ceremony.
- No job may enter `MIG-008` effect-authoritative canary or `MIG-009`
  authoritative cutover while an inventoried external reader still consumes
  that job's effect-free or stale Jenkins-side truth or an inventoried
  administrative writer still targets only that job's Jenkins definition or
  enclosing folder/controller configuration. Each affected caller must first pass
  `CONSUMER-001` or `ADMIN-001`, respectively, or have explicit owner-approved
  retirement, with tested caller cutover and rollback evidence.
- The `MIG-009` atomic cutover freeze must re-read and match each deployed
  replacement trigger's implementation digest in addition to its class and
  configuration, and each deployed Multibranch Pipeline or Organization Folder
  discovery implementation's binary or image digest, protocol/version, live
  configuration digest, provider/organization/repository scope, branch and PR
  trust/filter strategy, Jenkinsfile selection policy, child identity policy,
  and orphan policy. Any change invalidates prior proof and requires
  recertification before authoritative cutover.
- The `MIG-008` pre-effect and `MIG-009` cutover freezes must also re-read and
  match every separately deployed runtime implementation used by the job,
  including SCM acquisition, dependency resolver, cache service, secret
  provider adapter, connector, and agent components: exact binary/image or
  release-component digest, protocol/version, deployment/service identity,
  endpoint, live configuration digest, and policy digest. Matching logical
  requests, resolved outputs, or cache contents without the certified
  implementation identities is insufficient and forces recertification.
- Jenkins decommissioning must quiesce before the final export: pause and
  verify all trigger ingress and administrative writes, freeze new scheduling
  and external-effect authority, drain or explicitly reconcile every queued or
  running build, lease, lock, retry, and uncertain effect, and prove zero active
  work or ambiguous destination state. Only then capture and verify the final
  configuration/build/artifact/audit export, revoke remaining read and write
  authority, credentials, and network paths, and retire compute and secrets.
- `MIG-000` must inventory every Jenkins retention schedule and active legal
  hold covering configuration, build history, console logs, tests, artifacts,
  workspaces/state, and audit evidence, including record scope, policy digest,
  owner/custodian, expiry, and hold/release authority. Before `MIG-009` retires
  any affected scope, reconcile every protected record against the final
  export, import it with equivalent or stronger `OPS-002` retention and hold
  metadata plus immutable provenance, prove deletion remains blocked, and
  verify indexed retrieval and backup restore. Missing records, weaker policy,
  untested restore, or an unapproved hold release blocks retirement.
- Every effectful or stateful `MIG-009` per-job cutover must quiesce first:
  pause and verify scheduled, webhook, upstream, remote, manual, and API build
  ingress plus administrative writers for the job and affected enclosing scope;
  freeze new scheduling and effect-authority transfers; drain or reconcile all
  queued/running builds, retries, issued grants, leases, locks, and uncertain
  effects; and prove zero active source work or authority. For stateful jobs,
  only then re-export, transform, import, and verify state. Atomically switch
  trigger, reader, writer, and effect authority afterward; failure restores the
  frozen Jenkins authorities without skipped/duplicated state or effects.
- A job using a shared lock, throttle, or resource cohort cannot enter
  `MIG-008` effect-authoritative canary or `MIG-009` cutover while any cohort
  member can execute under an independent platform-local lock. During dual-run
  and rollback, both Jenkins and McLoving must acquire the same external
  lease/fence identity through one tested coordinator with atomic ownership,
  expiry, cancellation, restart, partition, stale-holder, and rollback proof;
  otherwise quiesce and migrate the entire cohort atomically. Reconciliation
  must prove one holder and one effect authority for every transition.
- Jobs connected by previous/last-result, upstream/downstream build identity,
  cross-job artifact, retained-workspace, or other cross-job state edges cannot
  enter `MIG-008` effect-authoritative canary or `MIG-009` cutover independently
  while producers and consumers would read different platform-local truth.
  Either provide one receipt-bound continuous bridge with a single authoritative
  source, monotonic sequence/build mapping, immutable content/provenance
  digests, exact deduplication, bounded lag, restart/replay, partition and
  failure-freeze, and bidirectional rollback proof, or quiesce, snapshot,
  transform, import, verify, and switch the entire dependency cohort atomically.
  Any stale, missing, divergent, or ambiguous edge blocks effects and cutover.
- A Multibranch Pipeline or Organization Folder cannot transfer parent
  `MIG-008` or `MIG-009` authority until the relinquishing discovery/indexing
  owner has paused webhook, periodic, and manual indexing ingress; drained or
  reconciled in-flight scans/events; exported the content-hashed discovery
  cursor, repository/branch/PR set, child identities/configurations, and orphan
  timers; and imported and verified them on the gaining side. Atomically fence
  exactly one discovery generation/owner before resuming ingress. Apply the
  same protocol in reverse and prove duplicate/reordered event, restart,
  partition, rollback, missing-child, duplicate-child, and orphan outcomes.
- Before every `MIG-008` effect-authoritative canary action, atomically re-read
  and match the complete live input and deployment set required by the
  `MIG-009` cutover freeze against its certified receipt, including source and
  shared libraries, Jenkins/controller inputs, compiler/mapping/components,
  state transforms, release, platform/agent/toolchain, authorization, trigger
  and discovery, connector and SCM acquisition, credential mapping and
  rotation/revocation state, dependencies, cache, and destination identity.
  Issue the fenced effect grant only after that match succeeds. Any drift,
  missing identity, or partial comparison keeps the canary effect-free until
  recertification; post-effect detection cannot satisfy this gate.
- Before the first `MIG-008` production effect grant and every later transfer
  or rollback of effect authority, quiesce the runner relinquishing authority:
  pause and verify its ingress, freeze its new scheduling and grants, then drain,
  revoke, or explicitly reconcile all queued/running work, issued
  credentials/grants, connector authority, leases, locks, retries, and uncertain
  effects. Prove no execution from the relinquishing runner retains effect
  authority before issuing the gaining runner's fenced grant; this applies
  Jenkins-to-McLoving and McLoving-to-Jenkins, and input receipt matching alone
  cannot replace quiescence.
- For every stateful `MIG-008` authority transfer or rollback, after quiescing
  the relinquishing runner and before granting the gaining runner, take a fresh
  content-hashed live export from the relinquishing side, apply the exact
  certified direction-specific `MIG-005A` transform, import it into the gaining
  side, and verify record-level provenance, build-number/previous-result
  mappings, cross-build artifacts, retained workspace/state, audit linkage, and
  destination digests. Empty, stale, partial, conflicting, or unverifiable
  state keeps the gaining runner effect-free; the prior runner resumes only
  after its authority and state remain or are restored consistently. A rehearsal
  receipt alone is insufficient.
- In `MIG-006`, "no network or host mounts" means no external, host,
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
  `MIG-006` transition case must use those exact content-hashed transforms and
  receipts; ad hoc import/export logic cannot earn equivalence. `MIG-007`
  packages the already-certified mapping and receipts rather than defining a
  downstream replacement.
- Every `MIG-005A`, `MIG-007`, `MIG-008`, and `MIG-009` workspace/state export,
  transform, backup, receipt, and reverse import is secret-aware. Classify and
  scan every record before and after transformation; omit credential files,
  tokens, keys, encrypted Jenkins secrets, and other secret material from
  portable state, retaining only reviewed typed redaction references and keyed
  digests in protected evidence. Required credentials must be freshly
  rebrokered through the mapped `SECRET-001` provider and scoped grant; stale,
  revoked, unclassified, or undecipherable secret-bearing state fails closed.
  Prove injected markers never enter destination state, logs, artifacts,
  backups, receipts, APIs, or the reverse transform.
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
  complete at its first `MIG-006` run—including `DEP-001` dependency resolution
  or `CACHE-001` cache behavior—cannot count as native, mappable, runnable, or
  certified through fixture/ad hoc behavior. After the required implementation
  is complete, rerun every affected `MIG-006` scenario against its exact
  deployed binary/image, configuration, policy, and provenance identities,
  regenerate the `MIG-007` package and receipts, and pass exact-head review
  before `MIG-008` effect authority. This recertification rule applies to any
  later trigger, discovery, connector, SCM, secret, dependency, cache, agent,
  or other runtime implementation that changes certified behavior.
- `MIG-000` must inventory every Jenkins Pipeline durability/resume setting and
  dependency, including durability hints, disabled resume, durable tasks,
  preserved stashes, controller checkpoints, and agent reconnect/loss behavior.
  `MIG-002` defines bounded controller restart/crash, agent disconnect/reconnect
  and loss, executor/container kill, network partition, checkpoint replay,
  preserved-stash recovery, retry, cancellation, and duplicate-effect scenarios;
  `MIG-006` runs them through both exact-profile systems and compares resumed
  node/attempt lineage, state, logs, artifacts, results, effects, and audit.
  Unimplemented or uncertified durability semantics are explicit unsupported
  classifications and make affected jobs ineligible for canary or cutover.
- Stop only for an owner-level decision, new authority, or genuine blocker.

## Batch ledger

| Batch | Tickets | Status | Outcome |
|---|---|---|---|
| W0-A | FOUND-001 | DONE | PR #1 established private repository and architecture baseline |
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
| W4-A | MIG-000, MIG-001, MIG-002, MIG-003 | ACTIVE | Owner-scoped production inventory, isolated compiler boundary, pinned Jenkins corpus/oracle, and deterministic Declarative translation |
| W4-B | MIG-004, MIG-005A, MIG-005, AUTHZ-001, MIG-006 | PENDING | Versioned step and state mappings, shared-library/scripted boundaries, migrated-job authorization parity, and differential certification |
| W4-C | MIG-007, REL-001, MIG-008, MIG-009 | PENDING | Generated migration packages, trusted release provenance, shadow/canary proof, and cutover/rollback readiness |

## Wave 0 — Architecture and foundation

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| FOUND-001 | DONE | — | Private monorepo, ADRs 1–15, board, threat model skeleton, CI, clean protected merge |
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

## Wave 4 — Jenkins migration

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| MIG-000 | ACTIVE | API-002, AUDIT-001 | Establish the owner-scoped production Jenkins inventory before corpus design. Export and content-hash every in-scope job definition and configuration, Multibranch Pipeline/Organization Folder parent and discovery strategy, Jenkinsfile or inline script, plugin/core profile, shared library, every referenced controller-global environment/tool/managed-file/plugin setting, every trigger class, effective folder/matrix/job authorization policy, build-parameter type and confidentiality classification without secret default/value material, credential reference without secret material, source checkout, workload dependency repository/lock policy, approval/input policy, platform/agent label/toolchain requirement and effective node authority, artifact/test publication, dependency/build cache, external effect, shared lock/throttle, build-number and previous-build dependency, cross-build artifact lookup, retained workspace/state dependency, every external read-side consumer and endpoint it uses, and every authenticated administrative writer—including Jenkins Job Builder, JCasC/Terraform automation, seed services, CLI clients, and REST clients—that creates, reconfigures, disables, deletes, or otherwise mutates jobs, folders, nodes, credentials references, or controller-global configuration, together with each writer's endpoint/action contract, caller identity, authorization scope, owner, and observed use. Secret-scan every source and export before persistence; replace embedded or encrypted credential values with reviewed typed redaction references that retain the original value's keyed digest and location only in protected evidence, never in the repository. Reconcile the export against live Jenkins so every production parent/child job, read-side consumer, and write-side automation client is accounted for, explicitly mark retired/out-of-scope items with owner approval, preserve immutable provenance, and use the resulting population to define MIG-002 corpus strata, coverage denominators, state-import demand, and Wave 5 dependency demand. |
| MIG-001 | PENDING | MIG-000, API-002, SEC-003 | Build an isolated Jenkins import/compiler worker for the exact inventory-derived JDK, Groovy, Jenkins core, and plugin-profile versions plus content hashes. It receives read-only corpus input, has no network, bounded CPU/memory/time/output, a versioned protocol, complete provenance, an explicit target profile, and fail-closed results. Launch clears and allowlists its environment, mounts, files, and local sockets; the worker receives no execution secrets, database credentials or reachability, agent credentials or protocol authority, scheduler identity, or controller filesystem access. Reproducibility, hostile-input containment, sandbox escape attempts, and authority-negative secrets/database/agent tests must be proven independently. |
| MIG-002 | PENDING | MIG-000, MIG-001 | Commit the exact secret-scanned Jenkins migration corpus and oracle manifest, stratified from the reconciled production inventory plus pinned OSS fixtures, with source hashes, licenses, provenance, reviewed typed redaction references and protected-evidence digests instead of embedded values, Jenkins/plugin target profile, every referenced effective controller-global setting and value/configuration digest, both execution platforms, agent label/image/capability/trust-pool mappings, and toolchain identities, plus expected parse, validation, and execution traces. For every behavior-changing public or secret parameter, condition, matrix, timeout, retry, cancellation, `catchError`, unstable-stage/result, post path, parallel branch, join, fail-fast sibling-cancellation path, job-level concurrency/supersession option, interactive approval/input path, cross-job shared-resource mapping, agent selection, cache mapping, authorization policy, workload dependency resolution, and persistent cross-build state/history dependency, define bounded equivalence classes and success/failure scenarios rather than one default execution. Secret-parameter cases require an explicit invocation-only tainted secret mapping or deterministic fail-closed classification, never a stored default/value, and inject unique markers whose absence is scanned across corpus/canonical bytes, diagnostics, logs, artifacts, tests, audit, and every API/UI/CLI response. Multi-build cases must cover simultaneous triggers, queue/start order, serialization, abort-previous behavior, cancellation propagation, and effect authority; retry/result cases must cover each failed/successful attempt, retry lineage, caught errors, node/stage/build result divergence, and eventual success or exhaustion; multi-job cases must cover contention, release, cancellation, restart, and effect authority; agent cases must cover label matches/misses, required capabilities, trust-pool selection, and denial of under- or over-privileged pools; approval cases must cover allowed and denied identities, submitter restrictions, submitted values, rejection, expiry, timeout, and cancellation; authorization cases must cover positive and negative view/trigger/cancel/configure decisions for effective principals; dependency cases must cover locked resolution, repository or artifact substitution, missing content, and mutable-resolution rejection; cache cases must cover cold, valid-hit, corrupt, key-substitution, untrusted-write/trusted-read, generation rotation, and cleanup paths; transition cases must seed Jenkins history and prove build-number mapping, previous-result lookup, cross-build artifact retrieval, retained-workspace handling, and the first authoritative McLoving execution. Classify every case as native, mappable, scripted, or unsupported; preserve immutable result deltas; and report production-population coverage, parse reach, native runnable coverage, actionable migration, and certified equivalence separately. |
| MIG-003 | PENDING | MIG-001, MIG-002, IR-004 | Compile the admitted Jenkins Declarative subset into versioned McLoving IR and canonical strict YAML. Preserve stage order, conditions, environment, public parameter schemas, invocation-only tainted secret-parameter references with no default/value persistence, matrices, post behavior, agent selection through an explicit normalized Jenkins-label-to-platform/capability/trust-pool mapping, admitted options including job-level concurrency and supersession, the parallel branch DAG and join semantics, fail-fast sibling cancellation, per-node/stage/build result semantics including caught errors and unstable outcomes, retry attempt identity and lineage, and interactive approval policy including allowed approvers, submitter restrictions, values, expiry, rejection, and cancellation; emit stable diagnostics for everything else; bind exact source/profile/compiler digests; and prove deterministic output with differential compiler fixtures. Rust independently reparses and validates every worker result before admission; adversarial worker-output gates reject malformed, unsupported, noncanonical, provenance- or profile-substituted IR/YAML, and any secret default, literal, or taint downgrade. |
| MIG-004 | PENDING | MIG-003 | Ship a versioned step and plugin mapping catalog to native processes, reusable components, and connectors. Every mapping declares schema, types, effects, trust requirements, supported target profiles, and provenance; mappings with lock, throttle, or shared-resource semantics additionally bind the canonical resource identity, coordination scope across jobs, queue and fairness policy, lease/release behavior, cancellation/restart recovery, and effect fencing; cache mappings bind key derivation, immutable generation/content digests, trust class, read/write policy, expiry, and cleanup. Floating mappings and silent fallback are forbidden; substitution resistance and corpus-earned coverage are gated. |
| MIG-005A | PENDING | MIG-002, MIG-003, OPS-003, AUDIT-001 | Implement versioned, deterministic, idempotent forward and reverse state transforms for every admitted build-number, previous-result, cross-build artifact, retained workspace, and persistent-state dependency. Bind immutable source export, transform implementation/configuration, destination state, record-level provenance, conflict policy, and verification digests; reject gaps, duplicate mappings, divergent replays, provenance substitution, and unclassified state. Before `DONE`, execute both directions against disposable exact-profile Jenkins and McLoving instances with seeded history: import state, run a McLoving state-authoritative but externally effect-free build, freeze new work, reverse-reconcile its number, result, artifacts, retained workspace/state, and audit linkage, then prove Jenkins resumes without stale lookups, missing artifacts, duplicate mappings, or duplicate effects. Every stateful job requires a successful case-specific rehearsal before `MIG-008` may grant production effect authority. |
| MIG-005 | PENDING | MIG-002, MIG-003, MIG-005A | Inventory and resolve Jenkins shared libraries by pinned SCM reference and content digest, including `vars`, `src`, and `resources`, while classifying load-time, runtime, sandbox, CPS, plugin, and credential dependencies. The worker ingests only owner-approved, prefetched, digest-verified read-only source and never receives direct SCM or credential authority. Arbitrary Groovy never runs in the controller; any future bounded isolated evaluation is owner-approved, meets the MIG-001 deny-authority boundary, and produces explicit unsupported receipts outside its admitted subset. |
| MIG-006 | PENDING | MIG-003, MIG-004, MIG-005, AUTHZ-001 | Process the same committed corpus through the pinned Jenkins oracle and McLoving in separate, independently tested deny-authority sandboxes whose exact platform, execution-image digest, locale, and toolchain identity match the receipt, with bounded CPU/memory/time/output, no network or host mounts, and no secrets, database, agent, scheduler, or controller authority. For `native` and `mappable` cases only, execute every bounded input equivalence class and success/failure scenario declared by MIG-002, including public/secret-parameter, condition and matrix branches plus timeout, retry, caught-error/unstable-result, cancellation, post, parallel-success, parallel-failure, fail-fast, overlapping multi-build, multi-job shared-resource, agent-selection, interactive-approval, authorization, dependency-resolution, cache, and seeded-history transition paths; compare parameter confidentiality and taint, referenced effective controller-global settings, stage order, step/effect arguments, post behavior, terminal build outcome, normalized node/stage outcomes, complete attempt count and retry parent/child lineage, caught-error and unstable-result truth, parallel branch concurrency and overlap, join completion, fail-fast sibling cancellation, multi-build queue/start order, serialization, supersession and cancellation propagation, shared-resource exclusion/ordering/release/recovery, normalized Jenkins label mapping and requested platform/capabilities/trust pool plus scheduling denial, approval policy and identity, submitted values, rejection/expiry/timeout/cancellation behavior, positive and negative view/trigger/cancel/configure authorization decisions, SEC-003 grant and AUDIT-001 event truth, resolved dependency coordinates/repository/version/content/provenance, cache hit/miss/corruption outcome plus exact key/generation/content/trust identity and cross-trust denial, build-number/previous-result mapping, cross-build artifact retrieval, retained-workspace/state behavior, first-authoritative-run behavior, workspace artifact digests, bounded normalized stdout/stderr with stream identity and explicit gaps, and TEST-001 normalized suite/case/retry/flaky outcomes with exact retained-source provenance. Scan every retained and exposed surface for injected secret markers and require zero disclosure. For every archived or published artifact, also compare the committed OPS-003 artifact record, logical name, media type, content digest, retention/provenance metadata, and successful API retrieval; workspace-byte equality alone cannot certify publication behavior. For every `scripted` or `unsupported` case, prohibit McLoving execution and instead prove deterministic fail-closed classification, stable actionable diagnostics, exact unsupported-boundary/provenance receipts, and zero admitted pipeline, scheduled work, credential grant, or external effect; these rejection cases never count as runnable or certified equivalence. Publish a stable mismatch taxonomy and regression budget while keeping production-population coverage, parse reach, native runnable coverage, actionable migration, deterministic rejection coverage, and certified equivalence as distinct metrics. |
| MIG-007 | PENDING | MIG-005A, MIG-006 | Generate a reviewable migration package containing canonical strict YAML, provenance, diagnostics, a mapping lock, exact source/oracle/profile/compiler digests, and the exact already-certified `MIG-005A` bidirectional state transforms plus `MIG-006` seeded-history differential and rehearsal receipts for every admitted state dependency. The package must round-trip to identical IR, contain no credential material, expose every substitution and unsupported boundary explicitly, bind immutable source export, forward/reverse transform, destination state, and verification digests for cutover and rollback, and reproduce the packaged receipt verification without invoking alternative transform logic. |
| MIG-008 | PENDING | MIG-007, REL-001, AUTHZ-001, OPS-003, AUDIT-001 | Prove shadow and graduated canary migration. Begin with mirrored triggers that cannot perform external effects and receive no production credentials, connector authority, deployment grants, or write-capable network path; contain all outputs in an isolated shadow namespace and apply every MIG-006 comparison dimension to every shadow and canary run. Transfer effect authority one action at a time under bounded quotas, retention, audit, and abort rules: exactly one runner is effect-authoritative, the other remains effect-free, and every ambiguous authority transition freezes new effects until reconciled. Every authoritative external effect must also produce a bounded independently observed destination-state or reconciliation receipt that binds account/resource identity, precondition, requested change, resulting state, and observer provenance and is compared with the certified Jenkins contract; request acceptance or pipeline success alone is insufficient. If an external system requires both runners, they must share a verified idempotency key and prove exact deduplication plus ambiguous-effect reconciliation before admission. Production canaries require `REL-001` trusted release provenance and `AUTHZ-001` migrated-job authorization parity; Windows-targeting jobs are ineligible until `WIN-001`, `WIN-002`, and `WIN-003` are `DONE` with their persistent-host interruption and reboot proof; every job with a non-manual trigger inventoried by MIG-000 is ineligible until that exact trigger class has a typed `TRIG-001` replacement and proof; Multibranch Pipeline or Organization Folder scopes and their children are ineligible until `DISC-001` is `DONE`; connector-backed effects are ineligible until `EXT-001` is `DONE`, jobs requiring live source acquisition are ineligible until `SCM-001` is `DONE`, jobs requiring Jenkins-managed runtime credentials are ineligible until `SECRET-001` is `DONE`, jobs with workload dependency resolution are ineligible until `DEP-001` is `DONE`, and jobs reading or publishing dependency/build caches are ineligible until `CACHE-001` is `DONE`; Wave 4 grants none of these authorities implicitly. Partial truth or an unclassified mismatch can never trigger automatic cutover. |
| MIG-009 | PENDING | MIG-008, OPS-002 | Define and prove per-job cutover, rollback, and explicit Jenkins decommissioning: owner approval, eligibility evidence, a bounded dual-run and rollback window, state/artifact retention, an exact Jenkins configuration and plugin rollback target, failure thresholds, and signed receipts. At cutover, atomically re-read and match both sides of the certified MIG-007/MIG-008 receipt: the live Jenkinsfile, shared-library, job-configuration, Jenkins-core, plugin-profile, every referenced effective controller-global setting, platform, agent-image, locale, and toolchain digests plus the normalized Jenkins-label-to-platform/capability/trust-pool mapping and deployed migration-package, canonical YAML/IR, mapping-lock/component, McLoving release/profile, platform, agent-image, requested capabilities, required trust pool, locale, and toolchain digests, together with `REL-001` reviewed-source, trusted-builder, dependency/SBOM, signature, and provenance identities; the effective principal-to-project role mapping and authorization-policy digest; each replacement trigger's typed class, live configuration digest, authenticated event-source or caller identity, filtering policy, and deduplication/replay contract; each live connector's binary/image digest, protocol version, configuration digest, target endpoint/account/resource identity, permission scope, deployment identity, and health/version receipt; each live source acquisition's provider/repository/ref/revision/submodule policy, credential-grant identity, checkout implementation, and resulting content/provenance digests; every runtime credential reference's mapping, provider/version, scoped grant policy, rotation generation, and revocation state; every resolved workload dependency's repository, coordinate, version, content, and provenance digests; every cache mapping's key, generation/content digests, trust class, read/write policy, and expiry; every authoritative external effect's destination-state/reconciliation receipt; and every required state transfer's source export, forward or reverse transform, destination, build-number mapping, and verification digests. Any change breaks the freeze and requires recertification. Cutover requires every job to have certified equivalence or an explicitly approved bounded-migration delta, zero unclassified jobs, successful rollback rehearsal, and successful seeded-history transition proof for every persistent cross-build dependency; scripted or unsupported classifications, mutable or unresolved workload dependencies, and unresolved differential mismatches are ineligible regardless of the regression budget. The rollback rehearsal must execute at least one authoritative McLoving build, freeze new effects, reconcile its build number, result, artifacts, retained workspace/state, and audit linkage back into Jenkins using the receipt-bound reverse transform, then prove Jenkins resumes without stale lookups, duplicate mappings, missing artifacts, or duplicate effects. Every migrated job must pass `AUTHZ-001` positive and negative view/trigger/cancel/configure equivalence. Every trigger class inventoried by MIG-000—including SCM webhooks, schedules, upstream jobs, remote-build HTTP/API tokens, and plugin-specific event sources—must pass its typed `TRIG-001` authenticated replacement, equivalent filtering, delivery, bounded deduplication, replay, failure, pause/resume, and rollback-restoration proof before its job is eligible; an absent implementation is an explicit blocker. Every Multibranch Pipeline or Organization Folder scope must pass `DISC-001` repository/branch/PR discovery, trust/filter policy, Jenkinsfile/revision selection, child lifecycle, orphan retirement, reindex/restart, and rollback proof before any parent or child cutover. Every job using checkout, Git, submodules, or credentialed repository access must also pass `SCM-001` live acquisition, fork-policy, exact-revision, later-commit delivery, and provenance gates; staged source alone is ineligible. Every job using `withCredentials`, credential-backed environment, deployment tokens, or other Jenkins-managed runtime secrets must pass `SECRET-001` provider, grant, rotation, revocation, redaction, and permission-negative gates. Every job resolving Maven/npm/PyPI or other workload dependencies must pass `DEP-001` repository-policy, exact-resolution, substitution, and provenance gates. Every job reading or publishing dependency/build caches must pass `CACHE-001` cold/hit/corrupt/substitution/cross-trust/rotation/cleanup gates. A Windows-targeting job is additionally ineligible until `WIN-001`, `WIN-002`, and `WIN-003` are `DONE`, including their persistent-host interruption and reboot evidence. Before decommissioning any Jenkins scope or endpoint, the inventory must prove every production job in that scope either completed eligible cutover or was explicitly retired by its owner, every external read-side consumer passed `CONSUMER-001` replacement or owner-approved retirement, and every authenticated administrative/write-side client passed `ADMIN-001` replacement or owner-approved retirement; no ineligible job, reader, or writer may remain dependent on Jenkins. After the rollback window and a separate owner-approved decommission gate, preserve and verify the final export, revoke Jenkins triggers, credentials, network, read-side API, and administrative write API authority, retire its compute and secrets, and prove no production traffic or active Jenkins authority remains. |

## Wave 5 — Extensions and operations

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| EXT-001 | PENDING | SEC-003, CTRL-003 | Define the scoped out-of-process connector identity and versioned protocol for external effects. A connector has no scheduler, database, agent, controller-filesystem, or unrelated-secret authority; each action binds tenant/project/build/attempt/fence, exact connector and request digests, idempotency class, expiry, and audit provenance. Permission-negative integration, stale/replay denial, bounded retry, exact deduplication, and ambiguous-effect reconciliation gates are required before any connector-backed canary or cutover. |
| TRIG-001 | PENDING | API-002, AUDIT-001 | Implement typed authenticated replacement ingress for every trigger class discovered by MIG-000, including SCM webhooks, schedules, upstream jobs, remote-build HTTP/API tokens, and admitted plugin-specific event sources; an unimplemented class remains explicitly ineligible. Bind tenant/project/pipeline, trigger type and implementation digest, event-source or caller identity, configuration/filter digest, delivery/event ID, schedule timezone/calendar, upstream build identity, idempotency key, expiry, and audit provenance; enforce bounded deduplication and replay windows. Prove valid and invalid authentication, branch/path/event and request filtering, duplicate/reordered/delayed delivery, outage retry and dead-letter recovery, schedule skew and restart behavior, upstream success/failure filtering, remote caller revocation, plugin-source substitution, pause/resume, cutover handoff, and rollback restoration before any trigger-dependent canary or cutover. |
| DISC-001 | PENDING | TRIG-001, SCM-001, AUTHZ-001 | Implement Multibranch Pipeline and Organization Folder indexing/discovery. Bind the exact deployed discovery implementation binary or image digest and protocol/version, live parent-configuration digest, provider/organization/repository identities, branch/PR discovery and trust/filter strategies, Jenkinsfile path and selection policy, exact discovered revision and provenance, child identity/configuration policy, orphan policy, and audit lineage. Prove new/updated/deleted branch and PR discovery, trusted and untrusted forks, filtering, parent reconfiguration, implementation or configuration substitution denial, duplicate/reordered webhook plus periodic reindex, restart/outage catch-up, child authorization, orphan retirement, and rollback restoration before any parent or child canary or cutover. |
| SCM-001 | PENDING | SEC-003, AGENT-004 | Implement isolated live source acquisition for checkout, Git, submodule, and credentialed repository steps. Bind provider, repository identity, authenticated ref and exact revision, fork and trust policy, submodule graph, sparse/depth options, checkout implementation, scoped short-lived credential grant, and resulting content/provenance digests. Prove later-commit delivery, ref substitution and untrusted-fork denial, credential non-disclosure, replay resistance, bounded network/filesystem authority, cleanup, and differential checkout truth before any source-dependent canary or cutover. |
| SECRET-001 | PENDING | SEC-003, AUDIT-001 | Inventory every Jenkins-managed runtime credential reference and map it to an owner-approved McLoving secret provider and versioned identity without copying secret material into migration packages. Bind tenant/project/environment/build/attempt/action scope, provider version, rotation generation, expiry, and revocation state to fenced short-lived grants. Prove missing/stale/replayed/cross-tenant/cross-attempt denial, rotation and emergency revocation, supported-sink redaction, non-disclosure in logs/artifacts/audit, and least-authority integration before any credential-dependent canary or cutover. |
| AUTHZ-001 | PENDING | SEC-002, API-002 | Map each inventory job's effective Jenkins folder/matrix/job authorization policy and principals into least-authority McLoving organization/project roles without broadening view, trigger, cancel, configure, approval, artifact, test, log, or audit access. Preserve reviewed identity mappings and policy digests; prove positive and negative decisions, disabled/deleted principal handling, group-membership changes, cross-tenant denial, and rollback restoration before any migrated-job canary or cutover. |
| DEP-001 | PENDING | SCM-001, SEC-003 | Implement policy-bound workload dependency resolution for Maven/npm/PyPI and other admitted ecosystems. Bind repository identity and trust policy, package coordinate, exact version, lockfile, transitive graph, content and signature/attestation digests, resolver/toolchain, credential grant, and audit provenance; mutable or unresolved coordinates are ineligible. Prove missing, repository/package/graph substitution, compromised mirror, untrusted-source, credential leak, offline/replay, and later-resolution denial before any dependency-resolving canary or cutover. |
| CACHE-001 | PENDING | SEC-002, OPS-003 | Implement tenant/project/pipeline/trust-class-isolated dependency and build caches with canonical keys, immutable generation/content digests, explicit read/write policy, bounded size/expiry, atomic publication, and auditable provenance. Prove cold and valid-hit behavior, corruption and key/generation substitution rejection, untrusted-write/trusted-read denial, concurrent publication, rotation, eviction, cleanup, and restored-state behavior before any cache-dependent canary or cutover. |
| REL-001 | PENDING | OPS-002, AUDIT-001 | Produce trusted McLoving release provenance from reviewed protected-branch source through an isolated pinned builder. Bind source/tree, toolchain and builder image, dependency lock and SBOM, tests and policy gates, archive/component digests, version/profile, signer identity, and transparency/audit evidence; sign the immutable release and verify it before deployment. Prove source, dependency, builder, artifact, signature, and rollback-target substitution denial before any production canary or cutover. |
| CONSUMER-001 | PENDING | API-002, AUTHZ-001 | Inventory and migrate every external read-side consumer of Jenkins build status, graph, logs, tests, artifacts, queue, and job metadata to a versioned authenticated McLoving API/CLI or bounded compatibility adapter. Bind caller identity, tenant/project scope, endpoint/query and pagination contract, retention/URL semantics, rate limits, and audit provenance. Prove positive/negative authorization, historical and live data equivalence, artifact retrieval, pagination/stream resume, error and outage behavior, caller cutover, rollback restoration, and zero residual Jenkins reads before the corresponding job enters authoritative cutover or its endpoint is retired. |
| ADMIN-001 | PENDING | API-002, AUTHZ-001, AUDIT-001 | Inventory and migrate every authenticated Jenkins administrative/write-side client, including Jenkins Job Builder, JCasC/Terraform automation, seed services, CLI clients, and REST clients that create, reconfigure, disable, delete, or otherwise mutate jobs, folders, nodes, credential references, or controller-global settings. Replace each admitted operation with a versioned authenticated McLoving API/CLI, declarative controller configuration path, or bounded compatibility adapter; bind caller identity, tenant/project or controller scope, exact operation/schema, desired-state and precondition digests, idempotency and optimistic-concurrency contract, authorization decision, and audit provenance. Prove create/update/delete convergence, duplicate/reordered/stale request handling, partial failure and retry, conflict and privilege denial, caller cutover, rollback restoration, and zero residual Jenkins writes before an affected job enters authoritative cutover or the corresponding Jenkins scope or endpoint is retired; unsupported operations require explicit owner-approved retirement before that cutover or decommissioning. |

Subsequent Wave 5 batches add notifications, provisioners,
deployment connectors, compact and HA packaging, upgrades, rollback,
retention, and disaster recovery.

## Wave 6 — Better-and-faster proof

OSS/private corpus, Linux/Windows war hosts, Jenkins comparison, capacity
envelope, multi-day soak, security review, disaster campaign, private alpha
canary, and release-readiness assessment.

## Current next batch

Wave 3 is merged through PR #12 at protected-main commit
`3756c2f0a15ad2c9ba1a9b96464b852a85f4ae1c` after exact-head review,
complete foundation validation, real-PostgreSQL execution, deployable
embedded/remote-agent proof, backup/restore verification, and all required
checks. `W4-A` is the current next batch and `MIG-000` is the first active
implementation target once this board change lands. W4-A must establish the
owner-scoped production inventory first, the pinned compiler/profile boundary
second, the committed corpus/oracle third, and Declarative translation fourth.
It does not authorize general Groovy
execution, production cutover, or an undifferentiated "Jenkins compatible"
claim. `WIN-001`, `WIN-002`, and `WIN-003` remain independently active for
their explicit production and persistent-Windows-host gates; Wave 3 closure
does not waive those gates.

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
