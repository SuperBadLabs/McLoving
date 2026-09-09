# JCOMP-002A contained sequential runtime review

## Status and boundary

JCOMP-002A is DONE after protected merge, independent review and successful
exact-main verification. This subsequent bookkeeping update records earned
bounded closure. The architecture is
`docs/architecture/SEQUENTIAL_STEP_EXECUTION_V1.md`; the original settled design
and threat plan remain in the dated September 9 handoff.

The pure planner lowers each literal shell to one existing version-1 process
node. Its owned validated store wrapper freezes ordered stage/step identity
inside the admission transaction. The internal result projection reads coherent
current logical outcomes and complete bounded attempt/log lineage. No public
route, imported-job enablement, agent protocol, schema table, production pool,
credential source or connector authority is added.

## Reviewed invariants

- TM-001/TM-038: every new admission resolves the saved enabled revision and
  generation; the parameter-free semantic digest equals the saved digest.
  Scoped replay checks original revision/generation, both digests and full
  contract before current enabled state. Projection binds organization,
  project and build. The store uses its existing tenant transaction boundary.
- TM-005/TM-009/TM-026: the owned constructor rejects malformed identity,
  noncontiguous order, missing/extra node mappings, unsupported payloads and
  non-linear or non-Succeeded edges. Its fields are private and it has no
  unchecked deserializer. Legacy normalized contracts remain unchanged.
- TM-003/TM-005/TM-006/TM-007/TM-011/TM-017: one process per existing attempt,
  session/restore/fence checks, terminal replay, cancellation and journals
  remain load-bearing. Sequential StartWork followed by lease loss requires
  reconciliation; it cannot silently rerun ordinal one under another fence.
- TM-005/TM-024: authorized retries alter current budget, state and lineage,
  while the original immutable contract and original admission IDs persist.
  Projection aggregates logical outcomes rather than old failed attempts.
- TM-009/TM-018/TM-022/TM-024: repeatable-read projection validates original
  payload, normalized capabilities, placement, priority and edges in the same
  snapshot as mutable status and attempts. Operational read limits return an
  explicit incomplete-read error. Start/terminal times mean controller
  accounting; actual private shell markers and output establish execution.
- TM-008/TM-016/TM-023/TM-052: fixed bounds, exact test populations, scoped
  disposable tests and observed executable/image identities support bounded
  claims. Mocked gate controls are kept distinct from runtime evidence.

## Development verification and correction

The initial five planner tests passed; they cover retained literals and Unicode
labels, exact stage/step/script byte bounds, process/parameter refusal, forged
layout/policy and normalization collisions. Strict all-target Clippy passed for
controller-api, controller-store and agent. These are focused candidate checks,
not a protected-head receipt.

The initial real campaign passed shell freshness/order, first/middle/last
failure, prestart/active cancellation with stale fence/restore/session refusals,
and terminal-commit crash replay. Its lease-loss case failed: after the agent
cancelled on renewal transport failure, generic lease expiry requeued the same
ordinal-one attempt at fence 2, and a fresh shell eventually succeeded. The
disposable database event sequence confirmed a second StartWork; this was not
stale completion acceptance or a passing containment result.

The candidate corrects this for sequential layout mode: an expired lease with
a matching StartWork event requires reconciliation even without a protected
connector effect. Pre-start offers still requeue; legacy generic DAG policy
is unchanged. StartWork is a conservative may-have-spawned boundary, not proof
of process birth. The corrected real campaign passed all five then-current
runtime tests: the lease case remained reconciliation_required, no successor
process started, and the first step stayed at fence 1. Four then-current
PostgreSQL tests passed, including deterministic prestart/running expiry
distinction. Subsequent additions (late transactional write rollback and an
actual-agent authorized retry case) require the final campaign again.

Host-built controller binaries needed glibc 2.39, which the pinned Debian
runner's glibc 2.36 could not supply. Those binaries were not executed as
contained evidence. Building inside the pinned Rust image produced controller
binaries needing at most glibc 2.34. The final local driver builds from a clean
committed archive before running copied binaries in the private test namespace.

## Final focused campaign

The [retained campaign](jcomp-002a-runtime-v1/campaign.json) binds source
`68a7487d2ef177a3ccbd0bffe98a5c846fa76020`, tree
`8124410e459d19c5997a1c839aa999943177a178`. It passed four PostgreSQL tests and
six real shipped-controller/agent tests with zero failures, ignored or skipped
cases. The refined session test first opens a valid probe session, then proves
that epoch is rejected after the actual worker enrolls again; the store test
also refuses the previously offered fence after a valid pre-start requeue.
The rollback test faults the second node insert and verifies no build, node or
attempt remains. Snapshot readers run concurrently with cancellation, retry
and finalization. The actual-agent retry test reruns only the failed step,
preserving earlier successes, original admission IDs and skipped placeholders.

| Executed artifact | SHA-256 |
|---|---|
| Controller | `5bcdb9017edf6aa8f837346a6993b1985056fd959ee92610693d325a3dc70883` |
| Remote agent | `cefc50979bb2ac39f506f2cd33c79737af9533ca324fef2df1b566f9d5b83670` |
| Store test executable | `d11be54192aba8981cf3405bd44515e7531818cd214d64737b534f627f85a494` |
| Remote test executable | `f5c87d69e4d2c8f4f8013198fe7c93a16fc353f23dcfe98acd8e8a82b2e616b1` |

The complete local Foundation gate passed on `7630600` using the documented
CI split, including all boundary suites and the final validation sentinel;
the source-acquirer package passed separately under its required AppArmor
profile. Five planner tests, the projection aggregation unit test, strict
all-target Clippy for affected packages, four mocked gate controls, all 11
workflow aggregate tests, and the 49/78 board/closure suites passed. The later
stale-session/fence refinement changed tests only, passed focused Clippy, and
regenerated the complete contained campaign above. Protected PR and exact-main
checks remain separate obligations.

## Independent review disposition

Copilot reviewed PR #130 at `f22226468ce26ae0824072503d31d46d165abe2b`
on 2026-09-09 (review `PRR_kwDOTmTe488AAAABMzN6fQ`), including the
Foundation workflow, aggregate verifier, gate controls and runtime driver.
Its sole comment, `3968118329`, asserted that SET LOCAL before SET TRANSACTION
would reject the projection at runtime. This is a false positive: PostgreSQL
requires the isolation change before a data query, not before SET LOCAL.

A separate disposable PostgreSQL 17.6 instance from the pinned image
`sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`
was run with no network, no published ports and tmpfs data, then removed.
The exact sequence `BEGIN; SET LOCAL "mcloving.organization_id" =
'00000000-0000-0000-0000-000000000001'; SET TRANSACTION ISOLATION LEVEL
REPEATABLE READ, READ ONLY;` succeeded. SHOW reported `repeatable read`,
`on`, and the exact tenant UUID. The negative control `BEGIN; SELECT 1;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;` failed with
`SET TRANSACTION ISOLATION LEVEL must be called before any query`.
The protected PostgreSQL job `102456048603` also passed the projection's
actual concurrent-reader and shipped-runtime cases. No implementation change
is warranted by this finding; future changes that query inside
`tenant_transaction` must preserve the projection's pre-snapshot setup.

## Protected merge and exact-main closure

PR #130's final head `d7be0f777a5f68c528717d17f0238ced2f62cb03`
passed all eight required GitHub Actions contexts (app `15368`): Rust,
Dependencies and licenses, Secret scan, Architecture records, Formal model,
Controller PostgreSQL, Foundation, and Windows. Final-head Foundation run
`34349462276` and Windows run `34349462367` succeeded. The final change after
Copilot's reviewed implementation head `f222264` was a 23-line documentation-only
review disposition; it changed no implementation or gate behavior. The sole
review thread was resolved with the positive and negative PostgreSQL controls
above; no actionable finding remained.

The protected squash merge is `c2aaa0da6aaf5f5a5800bca252fd0514584f56fa`,
with GitHub signature verification `valid`. Its tree
`77bc88fa006123ab72ae497334c1733dc0ac749b` exactly matches the final PR head.
On that exact merged-main commit, Foundation run `34351767851` and Windows
Agent run `34351767843` succeeded, including the actual native Windows job.
Protection remained enabled with all eight app-bound contexts; no bypass was used.
These exact-main observations were supplied by the integrating custodian after
live verification, separately from the read-only audit below.

An independent read-only subagent audit inspected the pure planner, owned
sequential contract, atomic admission/replay, coherent projection, StartWork
lease-expiry reconciliation, runtime fixtures, contained driver, hosted gates,
and workflow aggregate changes. It found no actionable blocker, independently
passed all four gate-control and 11 workflow-aggregate tests, and verified all
11 retained artifact checksums. It also confirmed the candidate/merge tree
identity and that only documentation/evidence changed after campaign source
`68a7487`. The audit did not rerun PostgreSQL or native runtime tests or inspect
live GitHub gates; those observations remain the separate campaign and hosted
receipts recorded here.

The retained inventory identifies the source commit/tree, image identities,
executed controller/agent/test hashes, full non-skipped output and successful
cleanup. The source archive is not retained: reconstruct it with
`git archive 68a7487d2ef177a3ccbd0bffe98a5c846fa76020`. The independent audit
reconstructed its SHA-256 as
`f4606f2f43aa4157a10650913370e943d98467603d844c3897087bf165bc7700`, exactly
matching `campaign.json`. Historical evidence-directory bytes remain unchanged.
JCOMP-002B is selected next; this receipt grants no workspace continuity claim.

## Residuals and nonclaims

Fresh shells use separate attempt workspaces. File continuity, build workspace
lifecycle and namespace non-collision remain JCOMP-002B. Hostile same-UID
workload, filesystem, process and credential isolation remain SEC-005.
The public one-step guard remains. S03/S06/S07 are excluded from the new runtime
campaign; S07's legacy generic YAML acceptance has no continuity implication.
Imported definitions remain disabled; no Jenkins workload ran in this ticket.
Paired Jenkins/product compatibility and 228-source reclassification remain
JCOMP-003, with authored and historical populations separate.

Focused lease/session/restore tests do not recertify full catastrophic restore
or every platform. Long sequential history beyond the explicit read limit is
incomplete-read, not evidence of corruption. None of this grants deployment,
production credentials/effects, canary, cutover or release authority.
