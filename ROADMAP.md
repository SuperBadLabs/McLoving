# McLoving roadmap and milestones

Planning snapshot observed 2026-10-05 from the execution board at commit
`8f2b625b`. This records that observation, not the current head of `main`.
The board contained 147 tickets: 107 `DONE`, 15 `PENDING`, two `ACTIVE`, and
23 `DEFERRED`. Run `python3 scripts/verify-execution-board.py` for live totals.

This roadmap groups every unclosed ticket by category and assigns it to one
proposed milestone. The [execution board](docs/EXECUTION_BOARD.md) remains
authoritative for status, dependencies, dispatch and acceptance. These
milestones do not change those fields or resume deferred work. Milestone
numbers describe the planning sequence; only board dependencies determine
which tickets must wait. Tracks can overlap under the board's working rules.

The [2026-10-05 execution observation](docs/handoffs/MILESTONE_EXECUTION_2026-10-05.md)
records the initial agent waves, verified evidence, local candidates and
remaining execution gates.

## Subsequent execution observation

At 2026-10-05T19:22:09.804839+00:00, `PAR-005` had earned its reviewed protected closure
through PR #172 after implementation PR #170 and successful exact-merge
Foundation and native Windows runs. Local main was synced to closure merge
`4bdcbcf78cd040390a6f1afb689f8535fb415b60`, preserving the owner edits.
`CTRL-006` had passed its implementation merge and exact-main checks; its
subsequent closure draft #173 and HYG-003 implementation draft #157 still
awaited fresh protected gates. CTRL-005 accounting and legacy-writer
concurrency work remained in progress. The categories and milestone
assignments below retain the original planning population; consult the board
and dated execution observations for earned status changes.

## Product objective and delivered baseline

[ADR 0016](docs/adr/0016-product-parity-before-migration-authority.md) makes
daily-workflow parity the priority: a GitHub push checks out a repository,
runs multiple steps in a digest-pinned container, streams logs, uploads
artifacts and reports a commit status. McLoving uses that pipeline itself.
Native YAML is the product; Jenkinsfile support remains compile-only.

The 107 closed tickets form the delivered baseline: the durable controller,
fenced Linux and Windows agents, API/CLI/static UI, identity and roles, audit,
object storage, recovery foundations, and bounded Jenkins compatibility.
The closed parity work includes checkout, containers, webhook triggers,
multi-step execution, live logs, artifacts, notifications, human role grants
(`PAR-003`), cron schedules (`PAR-002`) and workspace affinity (`PAR-015`).
Closed implementation does not grant production or migration authority.

## Tickets grouped by category

Only unclosed tickets appear below. Each belongs to exactly one category.
Counts and states are observations from the snapshot above.

| Category | Tickets | Observed state | Milestone |
|---|---|---|---|
| Self-hosting and dogfood | `PAR-005`, `AGENT-013`, `DOGFOOD-001` | 2 active, 1 pending | M1 |
| Checkout and container execution | `AGENT-009`, `AGENT-010` | 2 pending | M2 |
| Logs, artifacts and notifications | `AGENT-008`, `AGENT-011`, `AGENT-012`, `CTRL-005`, `CTRL-006`, `CTRL-007` | 6 pending | M2 |
| Documentation and governance hygiene | `HYG-003` | 1 pending | M2 |
| Compile-only compatibility decision | `GROOVY-001` | 1 deferred | M2 |
| Secrets and workload isolation | `SECRET-002`, `SEC-005` | 2 pending | M3 |
| Web interface and usability | `UI-003`, `UI-004`, `UI-005`, `UI-006`, `UI-007`, `UI-008`, `UI-009` | 7 deferred | M4 |
| First-team qualification | `CASE-001`, `CANARY-002`, `CASE-002` | 3 deferred | M4, M5 |
| Release, deployment and capacity | `REL-003`, `DEPLOY-002`, `PERF-001` | 3 pending, gated by deferred work | M5 |
| Migration and authority transitions | `CANARY-001`, `MIG-008`, `CUTOVER-001`, `ROLLBACK-001`, `RECUTOVER-001`, `DECOM-001`, `MIG-009` | 7 deferred | M6 |
| Release validation and decision | `PROOF-001`, `WAR-001`, `SEC-004`, `DR-001`, `REL-002` | 5 deferred | M7 |

## Milestones at a glance

Every unclosed ticket is assigned once in this table. The detailed exit
criteria below summarize the board; a milestone completes only when all its
assigned tickets earn their board closures.

| Milestone | User outcome | Assigned tickets | Entry gate |
|---|---|---|---|
| M1 — Reliable self-hosting | McLoving builds itself reliably for each push | `PAR-005`, `AGENT-013`, `DOGFOOD-001` | Dogfood is active; its follow-ups retain the `PAR-005` dependency |
| M2 — Runtime hardening and compatibility closure | Builds retain their logs and artifacts, recover safely and report the right result | `AGENT-008`, `AGENT-009`, `AGENT-010`, `AGENT-011`, `AGENT-012`, `CTRL-005`, `CTRL-006`, `CTRL-007`, `HYG-003`, `GROOVY-001` | Nine pending tickets have completed dependencies; the compiler residual stays deferred |
| M3 — Safe workload and secret boundary | Submitted workloads cannot access host credentials or bypass mediated capabilities | `SECRET-002`, `SEC-005` | Broker dependencies are complete; isolation follows the broker |
| M4 — First-team and UI qualification | A named team can use real pipelines through the supported interface | `CASE-001`, `CANARY-002`, `UI-003`, `UI-004`, `UI-005`, `UI-006`, `UI-007`, `UI-008`, `UI-009` | ADR 0016's real-team condition and resumed board lanes; case qualification also waits for M3 |
| M5 — Deployable release and measured capacity | The signed release installs, upgrades and rolls back with qualified cases and measured limits | `REL-003`, `DEPLOY-002`, `CASE-002`, `PERF-001` | Release dependencies include M3, `CASE-001`, `CANARY-002` and `UI-009` |
| M6 — Controlled migration lifecycle | Production migration can advance, reverse and retire Jenkins under explicit authority | `CANARY-001`, `MIG-008`, `CUTOVER-001`, `ROLLBACK-001`, `RECUTOVER-001`, `DECOM-001`, `MIG-009` | Resumed lanes; production canary waits for the qualified release and deployment |
| M7 — Release readiness decision | Owners have joined security, resilience, recovery and migration evidence for a release decision | `PROOF-001`, `WAR-001`, `SEC-004`, `DR-001`, `REL-002` | Per-ticket migration, capacity and UI gates; final decision joins all required evidence |

## M1: reliable self-hosting

**Tickets:** `PAR-005`, `AGENT-013`, `DOGFOOD-001`.

- `PAR-005`: retain ten consecutive matching dogfood/Foundation verdicts and
  earn the reviewed closure with exact-main Foundation and native Windows
  evidence and the required security-review receipt.
- `AGENT-013`: materialize checkout in under one minute on the owner's host,
  recover interrupted retained state without manual cleanup, and fetch the
  requested commit even after its branch advances.
- `DOGFOOD-001`: persist and update the public webhook, disable it when
  switching to bridge mode, and compare normalized lane commands in both
  directions so duplicate ingress and lane drift are caught.

The [dogfood evidence](docs/evidence/PAR-005_DOGFOOD.md) recorded a 10/10
sequence by 2026-09-28 and landed source-throughput improvements. Nevertheless,
the board observed `PAR-005` and `AGENT-013` as `ACTIVE`; the required
`docs/evidence/PAR-005_SECURITY_REVIEW.md` was absent at this snapshot.
Implementation and a verdict table alone do not close either ticket.

The formal order remains `PAR-005` closure, then its two follow-ups. The
`AGENT-013` active state alongside its unclosed dependency needs reconciliation
with the board's dispatch rules; this roadmap does not rewrite that edge.

## M2: runtime hardening and compatibility closure

**Tickets:** `AGENT-008`, `AGENT-009`, `AGENT-010`, `AGENT-011`, `AGENT-012`,
`CTRL-005`, `CTRL-006`, `CTRL-007`, `HYG-003`, `GROOVY-001`.

The nine pending tickets have completed dependencies and can be planned
alongside M1 and M3, subject to shared-boundary coordination:

- **Crash recovery and live logs:** `AGENT-008` uploads journaled logs before
  cancellation completes; `AGENT-011` retains private copies of reserved
  chunks until receipt; `CTRL-005` maintains transactional byte accounting
  without rescanning every prior chunk.
- **Container and checkout custody:** `AGENT-009` pins effective podman
  storage and agent-owned configuration; `AGENT-010` verifies retained
  checkout through held descriptors with explicit bounds and deadlines.
- **Artifact integrity:** `AGENT-012` bounds matching and I/O, handles
  cancellation, and makes publication atomic and recoverable; `CTRL-006`
  refuses artifact declarations the sequential planner cannot honor.
- **Notification correctness:** `CTRL-007` reconciles delayed GitHub status
  writes and validates configured NAT64 address prefixes.
- **Hygiene:** `HYG-003` distinguishes recorded observations from assertions
  of current state and proves its checks against historical failures and
  valid receipts. Coordinate edits with board and handoff closures.

`GROOVY-001` is an independent deferred residual: the architecture decision
is **no Groovy evaluation**. Its remaining malformed-quoting negative fixture
and closure receipt need an assigned compiler-exposure ticket. It is not
conditioned on a real team and does not authorize an interpreter. Its deferred
state does not prevent dispatch of the other M2 tickets.

Exit: each named adverse case passes through the shipped path or its required
gate, and the closures preserve the compile-only boundary.

## M3: safe workload and secret boundary

**Tickets:** `SECRET-002` → `SEC-005`.

`SECRET-002` can start after dispatch checks; its board dependencies are
complete. Deliver the production secret broker and scoped authority boundary.
Then `SEC-005` closes the hostile-workload boundary for eligible platforms:
filesystem and process separation, denial of unmediated network/helper access,
resource limits, explicit child environments, and protected crash artifacts.

Exit: workloads cannot read deployment credentials, alter agent truth, escape
through host launchers, bypass mediated capabilities or exhaust unbounded
host resources. Each platform earns the required adverse probes or remains
explicitly ineligible. Container execution alone does not close this boundary.

M3 can overlap M1/M2 according to the board. Before qualification, re-derive
dependencies for runtime-changing hardening so the security and downstream
evidence describe the shipped runtime, as the working rules require.

## M4: first-team and UI qualification

**Tickets:** `CASE-001`, `CANARY-002`, `UI-003` through `UI-009`.

These lanes remain deferred until ADR 0016's real-team condition is met and
the board resumes them. Identify the team, pipeline, job owner and intended
case before scheduling the campaign.

Two tracks can progress under their own dependencies:

1. **Case qualification:** after M3, `CASE-001` qualifies the owner-designated
   enabled effectful Jenkins job; `CANARY-002` follows it to provide the
   controlled ceremony driver. This is not a production effect grant.
2. **Interface:** `UI-003` → `UI-004` → `UI-005` → `UI-006` → `UI-007` →
   `UI-008` → `UI-009`: browser trust/session auth, pinned htmx, authenticated
   server-rendered representations, migrated views, missing operations,
   live updates, then accessibility and viewport evidence.

Exit: the selected case and its driver are qualified and the UI chain has
earned its usability evidence. The existing `UI-009` dependency means release
packaging waits for this interface chain unless the board is formally changed.

## M5: deployable release and measured capacity

**Tickets:** `REL-003`, `DEPLOY-002`, `CASE-002`, `PERF-001`.

Follow the existing order:

1. `REL-003`: package and sign all installed executables after security,
   first-case, ceremony-driver and `UI-009` dependencies close.
2. `DEPLOY-002`: revalidate installation, upgrade, rollback and workload-denial
   probes against that signed release.
3. `CASE-002`: recertify the case against the final deployed system.
4. `PERF-001`: measure pinned capacity, resource margins and recovery latency
   for eligible platforms after deployment and recertification.

Exit: package, deployment, case and capacity evidence describe the same
qualified system. These release/deployment/performance rows remain pending
with deferred dependencies. ADR 0016 calls for re-deriving their edges after
parity closure; grouping them here does not clear those gates.

## M6: controlled migration lifecycle

**Tickets:** `CANARY-001`, `MIG-008`, `CUTOVER-001`, `ROLLBACK-001`,
`RECUTOVER-001`, `DECOM-001`, `MIG-009`.

After the required case, security, release and deployment gates:

`CANARY-001` → `MIG-008` → `CUTOVER-001` → `ROLLBACK-001` →
`RECUTOVER-001` → `DECOM-001` → `MIG-009`.

This covers graduated production effects, shadow/canary readiness, authority
cutover, reversal, re-cutover, Jenkins decommissioning, and the joined migration
record. The arrows show the remaining-ticket chain; all other board
dependencies still apply. `PERF-001` is not an existing entry dependency of
`CANARY-001`; it separately gates the M7 war campaign and release decision.

Exit: the lifecycle has earned its receipts and eligibility/disposition
record. Each authority transition retains its explicit owner authorization
and current threat-review requirements; this plan grants no effects or
decommissioning authority.

## M7: release readiness decision

**Tickets:** `PROOF-001`, `WAR-001`, `SEC-004`, `DR-001`, `REL-002`.

The campaigns overlap M6 when their own gates are met:

- `WAR-001` follows `MIG-008` and `PERF-001` plus its closed platform gates.
- `SEC-004` follows `MIG-008` and `UI-008` plus its closed security gates.
- `PROOF-001` follows the completed migration record (`MIG-009`).
- `DR-001` follows `MIG-009` and the war campaign, proving recovery and
  requalification through the required drills.
- `REL-002` joins proof, capacity, war, security, disaster recovery, migration
  and workload-isolation evidence for the private owner release decision.

Exit: evidence agrees on the shipped system, supported platforms, recovery
and rollback targets, ownership and remaining limitations. Any late runtime,
deployment or artifact correction regenerates the affected signed release,
deployment and downstream receipts before closure. Public publication remains
a separate owner authorization.

## Next planning decisions

- Close the remaining M1 evidence/review gaps and reconcile `AGENT-013`'s
  dependency and active state before dispatching its residual work.
- Coordinate the eligible M2 hardening lanes and the M3 broker work within
  the board's three-mutable-PR limit; shared schemas and boundaries serialize.
- Assign the `GROOVY-001` negative fixture and receipt to a concrete compiler
  ticket without widening the compile-only architecture.
- Identify the first real team and pipeline so deferred work has a concrete
  resumption condition. Re-derive release and qualification dependencies
  after parity closure, including runtime-changing hardening.
- Audit existing support before filing the next parity tickets: credentials
  in steps, manual runs/parameters, parallel/matrix execution, retry/timeout
  policy and approval gates. These are candidate requirements, not assigned
  tickets or milestone commitments.
- Refresh the fortnightly handoff's distance to `PAR-005` and user-visible
  capability report; the milestone grouping introduces no due dates or effort
  estimates without that planning evidence.

## GitHub milestone publication observation

At 2026-10-05T20:02:25.175837+00:00, the seven definitions above were independently reviewed and published
as open GitHub milestones. All 40 original board tickets occur exactly once in
their descriptions; these are board references, and no GitHub issues were created.
The execution board remains authoritative for acceptance, dependencies and status.

- [M1: Reliable self-hosting](https://github.com/SuperBadLabs/McLoving/milestone/1)
- [M2: Runtime hardening and compatibility closure](https://github.com/SuperBadLabs/McLoving/milestone/2)
- [M3: Safe workload and secret boundary](https://github.com/SuperBadLabs/McLoving/milestone/3)
- [M4: First-team and UI qualification](https://github.com/SuperBadLabs/McLoving/milestone/4)
- [M5: Deployable release and measured capacity](https://github.com/SuperBadLabs/McLoving/milestone/5)
- [M6: Controlled migration lifecycle](https://github.com/SuperBadLabs/McLoving/milestone/6)
- [M7: Release readiness decision](https://github.com/SuperBadLabs/McLoving/milestone/7)

At the same observation, HYG-003 implementation PR #157 had completed protected
merge `7379d8a416435f871b265d59f2d1b09b82dead4a` and local main had been
fast-forwarded with owner edits preserved. PAR-005 was the one earned closure
in this original 40-ticket population. CTRL-006 closure draft #173 and CTRL-005
implementation draft #174 still awaited fresh checks after composition onto
that merge. No milestone completion was claimed.
