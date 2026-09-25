# McLoving roadmap

Written 2026-09-25 from a snapshot of the execution board and ADRs at commit
`1b0da107`. That is the snapshot this file was derived from, not a claim about
the current head of `main`; later commits may have moved the board.

This roadmap is a reading aid. It lines up the objectives recorded in
[ADR 0016](docs/adr/0016-product-parity-before-migration-authority.md) and the
[execution board](docs/EXECUTION_BOARD.md) into phases. The board stays
authoritative for ticket status, dependencies and acceptance; where the two
disagree, the board wins and this file is stale. The section "Gaps" at the end
is a proposal, not a board decision.

## North star

Daily-workflow parity with Jenkins, measured by one pipeline: a GitHub push
checks a repository out inside a digest-pinned container, runs several steps in
one stage, streams logs while running, uploads artifacts and reports a commit
status. McLoving builds McLoving with it.

ADR 0016 binds three rules to every ticket:

1. A ticket names a user-visible verb (check out, run, stream, upload, notify,
   log in).
2. Done means used: the dogfood pipeline is the phase's definition of done.
3. Process may not grow faster than product.

Progress is reported as **distance**: the count of unclosed tickets up to
`PAR-005`, stated every two weeks in `docs/handoffs/CURRENT.md`. It must fall.

## Phases at a glance

| Phase | Objective | State |
|---|---|---|
| 0 | Durable core and the first parity tickets | Done |
| 1 | McLoving builds itself (`PAR-005`) | Active |
| 2 | Finish the parity chain (`PAR-003`, `PAR-002`, `PAR-015`) | Next, serial |
| 2b | Hardening follow-ups from parity review | Parallel, any time |
| 3 | Production readiness | `SECRET-002` can start now, `SEC-005` after it; release rows wait on re-derivation |
| 4 | Migration authority, new web UI, release campaigns | Deferred |

## Phase 0: durable core (done)

Every ticket outside the phases below is `DONE`; run
`python3 scripts/verify-execution-board.py` for live totals rather than
copying counts from this file. `main` has a PostgreSQL-backed controller and
scheduler, outbound fenced mTLS agents for Linux and Windows, a public API, CLI
and static UI, artifact and test-result storage, a hash-chained audit, backup
and restore drills, identity and action-scoped authorization, and the isolated
Jenkins compiler with its M1 evidence (`JCOMP-001` to `JCOMP-003`).

The parity chain so far:

| Ticket | Delivered | Pull request |
|---|---|---|
| `PAR-000` | Board and ADRs re-oriented to product parity | #143 |
| `PAR-010` | Several process steps in one stage, one attempt | #145 |
| `PAR-011` | Steps run inside a digest-pinned rootless podman container | #146 |
| `PAR-012` | Checkout at an exact commit through the sealed source acquirer | #147 |
| `PAR-001` | Signed GitHub push and pull-request webhooks admit builds | #148 |
| `PAR-013` | Live log streaming with `mcloving logs --follow` | #149 |
| `PAR-014` | Agent-side artifact upload over the mTLS channel | #150 |
| `PAR-004` | Build outcome delivered as a GitHub commit status or signed webhook | #151 |

## Phase 1: McLoving builds itself (active)

Close `PAR-005`: ten consecutive pushes to protected `main` where the dogfood
build's verdict equals Foundation's, recorded in
[`docs/evidence/PAR-005_DOGFOOD.md`](docs/evidence/PAR-005_DOGFOOD.md). The
pipeline and deployment merged in #152; the verdict table is empty.

What stands in the way:

1. **Collect ten matching verdicts** with `scripts/dogfood/verdicts.sh`. This
   is the remaining acceptance evidence. Closing `PAR-005` also needs what
   every ticket needs under the board's working rules (the reviewed merge,
   exact-main Foundation and native Windows runs, and a closure update
   recording them) plus the receipt in
   `docs/evidence/PAR-005_SECURITY_REVIEW.md` the threat model names.
2. **The checkout is too slow and fragile for a reliable count.** Checking this
   repository out took the source acquirer past a fifteen-minute step timeout
   because it reads blobs one process per file. A killed acquisition leaves
   state that blocks the next one until an operator cleans it up, and a push
   the branch has moved past fails as `revision_mismatch`, which counts as a
   mismatch. `AGENT-013` fixes all three.
3. **The board orders these the other way round.** `AGENT-013` and
   `DOGFOOD-001` both list `PAR-005` as a dependency, and the board verifier
   refuses to dispatch a ticket whose dependencies are not `DONE`, so neither
   can take a slot until the ten-push count completes. As written, the count
   has to be collected with the current acquirer (operator cleanup included),
   or the owner changes those two rows so the fixes can land first (see
   Gaps). That is a board decision; this file does not make it.

`DOGFOOD-001` stops a push being delivered twice when the deployment switches
between public hook and bridge mode, and makes `verify-lanes.py` compare
wrapped test commands in both directions.

## Phase 2: finish the parity chain (serial)

Each ticket starts after its predecessor is merged and verified on `main`.

| Order | Ticket | What users get | State |
|---:|---|---|---|
| 1 | `PAR-003` | Grant and revoke human project roles; the last Owner cannot be revoked; revocation fences live sessions | Pull request #153 open ahead of its gate |
| 2 | `PAR-002` | Native cron schedules with Jenkins-style hashed fields, firing exactly once across controllers | Pending |
| 3 | `PAR-015` | Later stages run on the first stage's agent and reuse its workspace and checkout | Pending |

`PAR-003` is `SERIAL` behind `PAR-005`, and a serial ticket begins only after
its predecessor is merged and verified, which for `PAR-005` means the ten-push
count is recorded and the row reads `DONE`. #153 was opened before that gate
cleared; by the board's rule it pauses, implementation and review included,
until `PAR-005` closes, rather than continuing and merging later.

## Phase 2b: hardening follow-ups (parallel)

The `AGENT-` and `CTRL-` rows were filed from parity reviews past the
correction cap; they touch disjoint code and can land in any order alongside
Phase 1 and 2. `HYG-003` is different: it edits the board, the handoff and the
board verifier, which every phase closure also edits, so the board asks for
hygiene work to be coordinated before concurrent edits to those files rather
than run in parallel with a closure.

| Ticket | Area | Objective |
|---|---|---|
| `AGENT-008` | Agent recovery | Upload a crashed attempt's journaled logs before recovery completes its cancellation |
| `AGENT-009` | Containers | Bind podman's effective storage identity into launch and reap |
| `AGENT-010` | Checkout | Make pre-publication verification of a retained checkout descriptor-relative |
| `AGENT-011` | Live logs | Keep reserved log chunks in agent custody until receipted |
| `AGENT-012` | Artifacts | Bound the collector's aggregate pattern-matching work |
| `CTRL-005` | Logs | Account committed log bytes incrementally instead of summing every append |
| `CTRL-006` | Planner | Refuse artifact-bearing stages in the sequential Jenkins planner |
| `CTRL-007` | Notifications | Reconcile commit statuses against GitHub after the quiet interval |
| `HYG-003` | Process | Refuse board claims that are true when written and false when read |

## Phase 3: production readiness

Two tracks. The secret broker and workload containment have no deferred
dependencies: every dependency of `SECRET-002` is `DONE`, and `SEC-005` waits
only on `SECRET-002`, so this chain can be dispatched today. The release,
deployment and performance rows still carry edges to deferred tickets; ADR
0016 says those are re-derived when the parity phase closes, and that
re-derivation gates them.

| Ticket | Track | Objective |
|---|---|---|
| `SECRET-002` | Runnable now | Production secret broker and its authority boundary |
| `SEC-005` | After `SECRET-002` | Contain workload processes so they cannot read the host's credentials (containers are a partial answer; plain process steps are uncontained) |
| `REL-003` | After re-derivation | Package and sign every executable the deployment lane installs |
| `DEPLOY-002` | After re-derivation | Revalidate the deployment lane against the release that ships |
| `PERF-001` | After re-derivation | Reproducible capacity and regression envelopes |

## Phase 4: deferred

Deferred, not cancelled. The migration-authority, web UI and release lanes
resume when a real team runs real pipelines (ADR 0016). `GROOVY-001` is
different; see below.

- **Migration authority:** `CASE-001`, `CASE-002`, `CANARY-001`, `CANARY-002`,
  `MIG-008`, `CUTOVER-001`, `ROLLBACK-001`, `RECUTOVER-001`, `DECOM-001`,
  `MIG-009`, `PROOF-001`.
- **Web UI rewrite (server-rendered, htmx 4):** `UI-003` to `UI-009`.
- **Release campaigns:** `WAR-001`, `SEC-004`, `DR-001`, `REL-002`.
- **Groovy evaluation:** `GROOVY-001` is decided: NO, Jenkinsfile support
  stays compile-only (ADR 0006 amendment). It is not waiting on a real team.
  The row stays `DEFERRED` only until a negative fixture for malformed quoting
  and its closure receipt are earned; the board assigns that fixture to "the
  compiler-exposure ticket of the parity phase" (see Gaps).

## Gaps (proposal, not on the board)

- **Nothing is planned after `PAR-015`.** Common Jenkins features have no
  ticket: credentials bound into pipeline steps, build parameters and manual
  runs, parallel and matrix stages, retry and timeout policy, and manual
  approval gates. Some may already exist in part; each needs a code check
  before filing. A `PAR-016`+ batch should be filed before `PAR-015` closes so
  the dispatch queue does not run dry.
- **The first real team is unnamed.** The migration-authority, web UI and
  release lanes wait on it; naming
  it, and the pipeline it would move first, would give Phase 3 a target.
- **`AGENT-013` and `DOGFOOD-001` are gated on the ticket they unblock.** See
  Phase 1. The board verifier reads dependencies only as ticket IDs in the
  "Depends on" cell, so a pull request cannot stand in for `PAR-005` there:
  writing #152 alone silently drops the edge, and leaving `PAR-005` anywhere
  in the cell keeps blocking dispatch. A representable change is to replace
  `PAR-005` in both rows with the `DONE` ticket whose code each one hardens
  (`PAR-012` for the acquirer, `PAR-001` for the webhook ingress), keep the
  already-merged implementation as the lane's start gate ("`PAR-005` merged as
  `1b0da107`" in the parallel-lanes table, where it already reads "`PAR-005`
  merged"). Applied to a scratch copy of the board at `1b0da107`, that
  two-cell change passes `scripts/verify-execution-board.py` unchanged.
- **`GROOVY-001`'s residual points at a ticket that is not filed.** Its board
  row hands the malformed-quoting negative fixture to "the compiler-exposure
  ticket of the parity phase", but no parity ticket covers compiler exposure.
  Filing one, or naming an existing ticket, would give that work an owner.
- **The fortnightly distance report is due.** The last one is from
  2026-09-10.
