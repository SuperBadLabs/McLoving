# JCOMP-002A contained sequential runtime review

## Status and boundary

JCOMP-002A is ACTIVE. This implementation candidate has not earned protected
merge, exact-main verification or closure attribution. The architecture is
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

## Evidence required for closure

Retain the final committed source/tree, source archive, runner/database image
identities, executed controller/agent/test hashes, full non-skipped test output
and cleanup result. Run the complete protected checks and independent review
against the final PR head, resolve actionable findings, then verify the exact
merged-main Foundation and actual native Windows jobs. No result for an earlier
candidate can replace those observations.

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
