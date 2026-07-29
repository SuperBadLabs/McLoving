# McLoving execution board

Updated: 2026-07-29

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
| W3-A | IR-003, IR-004, CTRL-004 | ACTIVE | Native pipeline semantics: typed parameters and bounded expressions, digest-pinned reusable components, deterministic matrix expansion, and durable parallel DAG execution |
| W3-B | SEC-003, AUDIT-001, OPS-003, TEST-001 | PENDING | Grants and protected environments, append-only audit, artifact product journeys, and normalized test truth |
| W3-C | API-002, UX-002, UI-001 | PENDING | Complete documented REST surface, end-to-end CLI journeys, and an API-only initial static UI |

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
| IR-003 | ACTIVE | IR-002, ARCH-002 | Add typed pipeline parameters and a non-Turing-complete expression language with explicit contexts, stable diagnostics, canonical encoding, deterministic evaluation, secret-taint propagation, and independently enforced depth/node/string/operation limits; arbitrary-input and boundary properties must remain panic-free and bounded |
| IR-004 | PENDING | IR-003 | Add versioned reusable components resolved by immutable digest; bind input/output types and provenance, reject cycles and floating references, cap expansion depth/count/bytes before scheduling, and prove presentation-independent canonical expansion plus component-substitution resistance |
| CTRL-004 | PENDING | IR-004, CTRL-003 | Compile matrix axes deterministically into a bounded DAG; persist dependency, fan-out, join, fail-fast, retry, post, and cancellation truth transactionally; schedule ready nodes fairly across exact platform/trust-pool constraints and prove parallel races, restart recovery, terminal monotonicity, and one logical outcome per node in real PostgreSQL |
| SEC-003 | PENDING | SEC-002, CTRL-004 | Issue attempt-scoped credential grants and protected-environment approvals bound to organization, project, build, IR digest, environment, action, and expiry; deliver secrets only to the exact fenced attempt, redact every supported sink, reject stale/replayed approvals, and prove cross-tenant and cross-attempt denial |
| AUDIT-001 | PENDING | SEC-003, OPS-002 | Persist an append-only tenant-keyed audit stream for identity, authorization, scheduling, grant, approval, artifact, and administrative actions; hash chained segments, externally verifiable export, retention/legal-hold integration, mutation denial, and gap/tamper detection are required |
| OPS-003 | PENDING | OPS-001, CTRL-004 | Expose artifact upload, commit, list, metadata, and download journeys over staged immutable object truth; bind every artifact to tenant/build/node/attempt/name/digest/size/media type, enforce quotas and no-overwrite semantics, and prove partial upload, substitution, restore, and retention behavior |
| TEST-001 | PENDING | OPS-003 | Normalize bounded JUnit-style test reports into versioned suite/case outcomes with provenance and raw immutable source retention; reject entity expansion and malformed/oversized input, preserve duplicate-name identity explicitly, aggregate deterministically, and expose flaky/retry history without rewriting prior outcomes |
| API-002 | PENDING | CTRL-004, SEC-003, AUDIT-001, OPS-003, TEST-001 | Complete the documented REST API for pipelines/components, parameters, builds/nodes/attempts, approvals/grants, logs/artifacts/tests/audit, pagination/filtering, idempotency, optimistic concurrency, stable errors, OpenAPI, and tenant-scoped authorization; contract and real-PostgreSQL tests must cover every route and deny path |
| UX-002 | PENDING | API-002 | Complete Rust CLI journeys for validate/plan/submit/watch/explain/cancel/retry/approve, logs, artifacts, tests, and audit; support machine-stable JSON plus human output, resumable watch, explicit uncertain states, shell completion, and API-only end-to-end tests |
| UI-001 | PENDING | API-002 | Ship a content-security-policy-locked static web UI that uses only the public API for dashboard, pipeline/build graph, live logs, approvals, artifacts, tests, audit, and explainability; no privileged backend path, embedded secret, or client-side authorization claim is allowed, with accessibility and browser journey gates |

## Wave 4 — Jenkins migration

Pinned isolated compiler, exact target profiles, Declarative compilation,
Scripted classification, mapping catalog, shared-library inventory,
differential traces, generated strict YAML, shadow, canary, and cutover.

## Wave 5 — Extensions and operations

SCM, secrets, notifications, provisioners, deployment connectors, compact and
HA packaging, upgrades, rollback, retention, and disaster recovery.

## Wave 6 — Better-and-faster proof

OSS/private corpus, Linux/Windows war hosts, Jenkins comparison, capacity
envelope, multi-day soak, security review, disaster campaign, private alpha
canary, and release-readiness assessment.

## Current next batch

`W2-B` merged through PR #8 at protected-main commit `776d842`. It is a
completed foundation batch, not closure of `WIN-001`, `WIN-002`, or `WIN-003`;
those tickets remain active for the explicit production and persistent-host
gates above.

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

Wave 3 is loaded as three dependency-ordered batches. `W3-A` is active on
`codex/wave3-native-pipeline`; it establishes the native authoring and durable
execution semantics that every later security, artifact, API, CLI, and UI
surface consumes. `W3-B` owns product security and operational truth. `W3-C`
exposes those completed contracts without creating a privileged product path.

The still-active `WIN-001`, `WIN-002`, and `WIN-003` persistent-host closure is
tracked independently and remains a release gate for Windows parity; it does
not block platform-neutral Wave 3 implementation, and Wave 3 cannot mark those
tickets done by implication.
