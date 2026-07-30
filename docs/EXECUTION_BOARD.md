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
- After merge, select the next unblocked batch without waiting for ceremony.
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
| W4-B | MIG-004, MIG-005, MIG-006 | PENDING | Versioned mappings, shared-library/scripted boundaries, and differential certification |
| W4-C | MIG-007, REL-001, AUTHZ-001, MIG-008, MIG-009 | PENDING | Generated migration packages, trusted release provenance, migrated-job authorization parity, shadow/canary proof, and cutover/rollback readiness |

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
| MIG-000 | ACTIVE | API-002, AUDIT-001 | Establish the owner-scoped production Jenkins inventory before corpus design. Export and content-hash every in-scope job definition and configuration, Jenkinsfile or inline script, plugin/core profile, shared library, trigger, effective folder/matrix/job authorization policy, credential reference without secret material, source checkout, workload dependency repository/lock policy, approval/input policy, platform/agent/toolchain requirement, artifact/test publication, dependency/build cache, external effect, shared lock/throttle, build-number and previous-build dependency, cross-build artifact lookup, retained workspace/state dependency, owner, and observed use. Secret-scan every source and export before persistence; replace embedded or encrypted credential values with reviewed typed redaction references that retain the original value's keyed digest and location only in protected evidence, never in the repository. Reconcile the export against live Jenkins so every production job is accounted for, explicitly mark retired/out-of-scope jobs with owner approval, preserve immutable provenance, and use the resulting population to define MIG-002 corpus strata, coverage denominators, state-import demand, and Wave 5 dependency demand. |
| MIG-001 | ACTIVE | API-002, SEC-003 | Build an isolated Jenkins import/compiler worker with exact JDK, Groovy, Jenkins core, and plugin-profile versions plus content hashes. It receives read-only corpus input, has no network, bounded CPU/memory/time/output, a versioned protocol, complete provenance, an explicit target profile, and fail-closed results. Launch clears and allowlists its environment, mounts, files, and local sockets; the worker receives no execution secrets, database credentials or reachability, agent credentials or protocol authority, scheduler identity, or controller filesystem access. Reproducibility, hostile-input containment, sandbox escape attempts, and authority-negative secrets/database/agent tests must be proven independently. |
| MIG-002 | PENDING | MIG-000, MIG-001 | Commit the exact secret-scanned Jenkins migration corpus and oracle manifest, stratified from the reconciled production inventory plus pinned OSS fixtures, with source hashes, licenses, provenance, reviewed typed redaction references and protected-evidence digests instead of embedded values, Jenkins/plugin target profile, both execution platforms, agent image digests, and toolchain identities, plus expected parse, validation, and execution traces. For every behavior-changing parameter, condition, matrix, timeout, retry, cancellation, post path, parallel branch, join, fail-fast sibling-cancellation path, job-level concurrency/supersession option, interactive approval/input path, cross-job shared-resource mapping, cache mapping, authorization policy, workload dependency resolution, and persistent cross-build state/history dependency, define bounded equivalence classes and success/failure scenarios rather than one default execution. Multi-build cases must cover simultaneous triggers, queue/start order, serialization, abort-previous behavior, cancellation propagation, and effect authority; multi-job cases must cover contention, release, cancellation, restart, and effect authority; approval cases must cover allowed and denied identities, submitter restrictions, submitted values, rejection, expiry, timeout, and cancellation; authorization cases must cover positive and negative view/trigger/cancel/configure decisions for effective principals; dependency cases must cover locked resolution, repository or artifact substitution, missing content, and mutable-resolution rejection; cache cases must cover cold, valid-hit, corrupt, key-substitution, untrusted-write/trusted-read, generation rotation, and cleanup paths; transition cases must seed Jenkins history and prove build-number mapping, previous-result lookup, cross-build artifact retrieval, retained-workspace handling, and the first authoritative McLoving execution. Classify every case as native, mappable, scripted, or unsupported; preserve immutable result deltas; and report production-population coverage, parse reach, native runnable coverage, actionable migration, and certified equivalence separately. |
| MIG-003 | PENDING | MIG-001, MIG-002, IR-004 | Compile the admitted Jenkins Declarative subset into versioned McLoving IR and canonical strict YAML. Preserve stage order, conditions, environment, parameters, matrices, post behavior, agent selection, admitted options including job-level concurrency and supersession, the parallel branch DAG and join semantics, fail-fast sibling cancellation, and interactive approval policy including allowed approvers, submitter restrictions, values, expiry, rejection, and cancellation; emit stable diagnostics for everything else; bind exact source/profile/compiler digests; and prove deterministic output with differential compiler fixtures. Rust independently reparses and validates every worker result before admission; adversarial worker-output gates reject malformed, unsupported, noncanonical, and provenance- or profile-substituted IR/YAML. |
| MIG-004 | PENDING | MIG-003 | Ship a versioned step and plugin mapping catalog to native processes, reusable components, and connectors. Every mapping declares schema, types, effects, trust requirements, supported target profiles, and provenance; mappings with lock, throttle, or shared-resource semantics additionally bind the canonical resource identity, coordination scope across jobs, queue and fairness policy, lease/release behavior, cancellation/restart recovery, and effect fencing; cache mappings bind key derivation, immutable generation/content digests, trust class, read/write policy, expiry, and cleanup. Floating mappings and silent fallback are forbidden; substitution resistance and corpus-earned coverage are gated. |
| MIG-005 | PENDING | MIG-002, MIG-003 | Inventory and resolve Jenkins shared libraries by pinned SCM reference and content digest, including `vars`, `src`, and `resources`, while classifying load-time, runtime, sandbox, CPS, plugin, and credential dependencies. The worker ingests only owner-approved, prefetched, digest-verified read-only source and never receives direct SCM or credential authority. Arbitrary Groovy never runs in the controller; any future bounded isolated evaluation is owner-approved, meets the MIG-001 deny-authority boundary, and produces explicit unsupported receipts outside its admitted subset. |
| MIG-006 | PENDING | MIG-003, MIG-004, MIG-005 | Run the same committed corpus through the pinned Jenkins oracle and McLoving in separate, independently tested deny-authority sandboxes whose exact platform, execution-image digest, locale, and toolchain identity match the receipt, with bounded CPU/memory/time/output, no network or host mounts, and no secrets, database, agent, scheduler, or controller authority. Execute every bounded input equivalence class and success/failure scenario declared by MIG-002, including condition and matrix branches plus timeout, retry, cancellation, post, parallel-success, parallel-failure, fail-fast, overlapping multi-build, multi-job shared-resource, interactive-approval, authorization, dependency-resolution, cache, and seeded-history transition paths; compare stage order, step/effect arguments, post behavior, terminal outcome, parallel branch concurrency and overlap, join completion, fail-fast sibling cancellation, multi-build queue/start order, serialization, supersession and cancellation propagation, shared-resource exclusion/ordering/release/recovery, approval policy and identity, submitted values, rejection/expiry/timeout/cancellation behavior, positive and negative view/trigger/cancel/configure authorization decisions, SEC-003 grant and AUDIT-001 event truth, resolved dependency coordinates/repository/version/content/provenance, cache hit/miss/corruption outcome plus exact key/generation/content/trust identity and cross-trust denial, build-number/previous-result mapping, cross-build artifact retrieval, retained-workspace/state behavior, first-authoritative-run behavior, workspace artifact digests, bounded normalized stdout/stderr with stream identity and explicit gaps, and TEST-001 normalized suite/case/retry/flaky outcomes with exact retained-source provenance. For every archived or published artifact, also compare the committed OPS-003 artifact record, logical name, media type, content digest, retention/provenance metadata, and successful API retrieval; workspace-byte equality alone cannot certify publication behavior. Publish a stable mismatch taxonomy and regression budget while keeping production-population coverage, parse reach, native runnable coverage, actionable migration, and certified equivalence as distinct metrics. |
| MIG-007 | PENDING | MIG-006 | Generate a reviewable migration package containing canonical strict YAML, provenance, diagnostics, a mapping lock, exact source/oracle/profile/compiler digests, and a bounded bidirectional state mapping/import plan for every admitted build-number, previous-result, cross-build artifact, retained workspace, or persistent-state dependency. The package must round-trip to identical IR, contain no credential material, expose every substitution and unsupported boundary explicitly, and bind immutable source-state/export, forward and reverse transform, destination-state, and verification digests for both cutover import and rollback reconciliation. |
| MIG-008 | PENDING | MIG-007, REL-001, AUTHZ-001, OPS-003, AUDIT-001 | Prove shadow and graduated canary migration. Begin with mirrored triggers that cannot perform external effects and receive no production credentials, connector authority, deployment grants, or write-capable network path; contain all outputs in an isolated shadow namespace and apply every MIG-006 comparison dimension to every shadow and canary run. Transfer effect authority one action at a time under bounded quotas, retention, audit, and abort rules: exactly one runner is effect-authoritative, the other remains effect-free, and every ambiguous authority transition freezes new effects until reconciled. Every authoritative external effect must also produce a bounded independently observed destination-state or reconciliation receipt that binds account/resource identity, precondition, requested change, resulting state, and observer provenance and is compared with the certified Jenkins contract; request acceptance or pipeline success alone is insufficient. If an external system requires both runners, they must share a verified idempotency key and prove exact deduplication plus ambiguous-effect reconciliation before admission. Production canaries require `REL-001` trusted release provenance and `AUTHZ-001` migrated-job authorization parity; webhook-, schedule-, or upstream-triggered jobs are ineligible until `TRIG-001` is `DONE`, connector-backed effects are ineligible until `EXT-001` is `DONE`, jobs requiring live source acquisition are ineligible until `SCM-001` is `DONE`, jobs requiring Jenkins-managed runtime credentials are ineligible until `SECRET-001` is `DONE`, jobs with workload dependency resolution are ineligible until `DEP-001` is `DONE`, and jobs reading or publishing dependency/build caches are ineligible until `CACHE-001` is `DONE`; Wave 4 grants none of these authorities implicitly. Partial truth or an unclassified mismatch can never trigger automatic cutover. |
| MIG-009 | PENDING | MIG-008, OPS-002 | Define and prove per-job cutover, rollback, and explicit Jenkins decommissioning: owner approval, eligibility evidence, a bounded dual-run and rollback window, state/artifact retention, an exact Jenkins configuration and plugin rollback target, failure thresholds, and signed receipts. At cutover, atomically re-read and match both sides of the certified MIG-007/MIG-008 receipt: the live Jenkinsfile, shared-library, job-configuration, Jenkins-core, plugin-profile, platform, agent-image, locale, and toolchain digests plus the deployed migration-package, canonical YAML/IR, mapping-lock/component, McLoving release/profile, platform, agent-image, locale, and toolchain digests, together with `REL-001` reviewed-source, trusted-builder, dependency/SBOM, signature, and provenance identities; the effective principal-to-project role mapping and authorization-policy digest; each replacement trigger's live configuration digest, authenticated event-source identity, filtering policy, and deduplication/replay contract; each live source acquisition's provider/repository/ref/revision/submodule policy, credential-grant identity, checkout implementation, and resulting content/provenance digests; every runtime credential reference's mapping, provider/version, scoped grant policy, rotation generation, and revocation state; every resolved workload dependency's repository, coordinate, version, content, and provenance digests; every cache mapping's key, generation/content digests, trust class, read/write policy, and expiry; every authoritative external effect's destination-state/reconciliation receipt; and every required state transfer's source export, forward or reverse transform, destination, build-number mapping, and verification digests. Any change breaks the freeze and requires recertification. Cutover requires every job to have certified equivalence or an explicitly approved bounded-migration delta, zero unclassified jobs, successful rollback rehearsal, and successful seeded-history transition proof for every persistent cross-build dependency; scripted or unsupported classifications, mutable or unresolved workload dependencies, and unresolved differential mismatches are ineligible regardless of the regression budget. The rollback rehearsal must execute at least one authoritative McLoving build, freeze new effects, reconcile its build number, result, artifacts, retained workspace/state, and audit linkage back into Jenkins using the receipt-bound reverse transform, then prove Jenkins resumes without stale lookups, duplicate mappings, missing artifacts, or duplicate effects. Every migrated job must pass `AUTHZ-001` positive and negative view/trigger/cancel/configure equivalence. Every SCM webhook, schedule, and upstream-job trigger must pass `TRIG-001` authenticated replacement, equivalent filtering, delivery, bounded deduplication, replay, failure, pause/resume, and rollback-restoration proof before its job is eligible; an absent implementation is an explicit blocker. Every job using checkout, Git, submodules, or credentialed repository access must also pass `SCM-001` live acquisition, fork-policy, exact-revision, later-commit delivery, and provenance gates; staged source alone is ineligible. Every job using `withCredentials`, credential-backed environment, deployment tokens, or other Jenkins-managed runtime secrets must pass `SECRET-001` provider, grant, rotation, revocation, redaction, and permission-negative gates. Every job resolving Maven/npm/PyPI or other workload dependencies must pass `DEP-001` repository-policy, exact-resolution, substitution, and provenance gates. Every job reading or publishing dependency/build caches must pass `CACHE-001` cold/hit/corrupt/substitution/cross-trust/rotation/cleanup gates. A Windows-targeting job is additionally ineligible until `WIN-001`, `WIN-002`, and `WIN-003` are `DONE`, including their persistent-host interruption and reboot evidence. Before decommissioning any Jenkins scope, the inventory must prove every production job in that scope either completed eligible cutover or was explicitly retired by its owner; no ineligible job may remain dependent on Jenkins. After the rollback window and a separate owner-approved decommission gate, preserve and verify the final export, revoke Jenkins triggers, credentials, and network authority, retire its compute and secrets, and prove no production traffic or active Jenkins authority remains. |

## Wave 5 — Extensions and operations

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| EXT-001 | PENDING | SEC-003, CTRL-003 | Define the scoped out-of-process connector identity and versioned protocol for external effects. A connector has no scheduler, database, agent, controller-filesystem, or unrelated-secret authority; each action binds tenant/project/build/attempt/fence, exact connector and request digests, idempotency class, expiry, and audit provenance. Permission-negative integration, stale/replay denial, bounded retry, exact deduplication, and ambiguous-effect reconciliation gates are required before any connector-backed canary or cutover. |
| TRIG-001 | PENDING | API-002, AUDIT-001 | Implement authenticated replacement ingress for SCM webhooks, schedules, and upstream-job triggers. Bind tenant/project/pipeline, event-source identity, configuration/filter digest, delivery/event ID, schedule timezone/calendar, upstream build identity, idempotency key, expiry, and audit provenance; enforce bounded deduplication and replay windows. Prove valid and invalid authentication, branch/path/event filtering, duplicate/reordered/delayed delivery, outage retry and dead-letter recovery, schedule skew and restart behavior, upstream success/failure filtering, pause/resume, cutover handoff, and rollback restoration before any trigger-dependent canary or cutover. |
| SCM-001 | PENDING | SEC-003, AGENT-004 | Implement isolated live source acquisition for checkout, Git, submodule, and credentialed repository steps. Bind provider, repository identity, authenticated ref and exact revision, fork and trust policy, submodule graph, sparse/depth options, checkout implementation, scoped short-lived credential grant, and resulting content/provenance digests. Prove later-commit delivery, ref substitution and untrusted-fork denial, credential non-disclosure, replay resistance, bounded network/filesystem authority, cleanup, and differential checkout truth before any source-dependent canary or cutover. |
| SECRET-001 | PENDING | SEC-003, AUDIT-001 | Inventory every Jenkins-managed runtime credential reference and map it to an owner-approved McLoving secret provider and versioned identity without copying secret material into migration packages. Bind tenant/project/environment/build/attempt/action scope, provider version, rotation generation, expiry, and revocation state to fenced short-lived grants. Prove missing/stale/replayed/cross-tenant/cross-attempt denial, rotation and emergency revocation, supported-sink redaction, non-disclosure in logs/artifacts/audit, and least-authority integration before any credential-dependent canary or cutover. |
| AUTHZ-001 | PENDING | SEC-002, API-002 | Map each inventory job's effective Jenkins folder/matrix/job authorization policy and principals into least-authority McLoving organization/project roles without broadening view, trigger, cancel, configure, approval, artifact, test, log, or audit access. Preserve reviewed identity mappings and policy digests; prove positive and negative decisions, disabled/deleted principal handling, group-membership changes, cross-tenant denial, and rollback restoration before any migrated-job canary or cutover. |
| DEP-001 | PENDING | SCM-001, SEC-003 | Implement policy-bound workload dependency resolution for Maven/npm/PyPI and other admitted ecosystems. Bind repository identity and trust policy, package coordinate, exact version, lockfile, transitive graph, content and signature/attestation digests, resolver/toolchain, credential grant, and audit provenance; mutable or unresolved coordinates are ineligible. Prove missing, repository/package/graph substitution, compromised mirror, untrusted-source, credential leak, offline/replay, and later-resolution denial before any dependency-resolving canary or cutover. |
| CACHE-001 | PENDING | SEC-002, OPS-003 | Implement tenant/project/pipeline/trust-class-isolated dependency and build caches with canonical keys, immutable generation/content digests, explicit read/write policy, bounded size/expiry, atomic publication, and auditable provenance. Prove cold and valid-hit behavior, corruption and key/generation substitution rejection, untrusted-write/trusted-read denial, concurrent publication, rotation, eviction, cleanup, and restored-state behavior before any cache-dependent canary or cutover. |
| REL-001 | PENDING | OPS-002, AUDIT-001 | Produce trusted McLoving release provenance from reviewed protected-branch source through an isolated pinned builder. Bind source/tree, toolchain and builder image, dependency lock and SBOM, tests and policy gates, archive/component digests, version/profile, signer identity, and transparency/audit evidence; sign the immutable release and verify it before deployment. Prove source, dependency, builder, artifact, signature, and rollback-target substitution denial before any production canary or cutover. |

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
