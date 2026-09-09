# Future deployment merge-gate optimization follow-up

Read-only planning, not a ticket, implementation, benchmark claim or gate waiver. Completed Foundation run34312321450 at b58d752e186c639e568e4d3ff4ae037999f86b38; Deployment lane job102341424544 succeeded. GitHub job/step metadata and filtered public log timestamps were inspected. No workloads were run; no raw log or credential material was retained.

## Measured baseline

| Interval | Observed time |
| --- | ---: |
| Deployment job04:47:43–05:06:38 UTC | 18m55s |
| Toolchain/cache setup | 8s +10s |
| Disk reclamation |31s |
| Smoke04:48:35–05:03:11 |14m36s |
| Smoke Rust build, log-reported |35.40s |
| Smoke marker [9/9]04:50:13.172 to passed05:03:11.734 |12m58.562s |
| Build exact service-managed test/release |21s (Cargo20.19s) |
| Controlled real user manager test |3m04s |

The final [9/9] marker covers upgrade/rollback AND the long subsequent refusal/race matrix (deploy/test-deployment.sh:2346 onward), not merely two transitions. It consumes about89% of this smoke interval and69% of the whole job. The current coarse marker cannot attribute that interval among individual refusal families. Rust caching or initial startup alone cannot remove most of this run's cost. This is one historical runner observation, not a stable percentile or a forecast for current PR/main.

CI-004 is already closed: strip only disposable smoke fixture copies before checksums; preserve build outputs, code/symbol/unwind behavior and exact service-manager binary identity. That improvement is in this baseline (script:607–615). The earlier attempted systemd stripping failed the exact-binary gate correctly; it is not a candidate to repeat.

## Candidate1: measure and isolate the long refusal matrix before bounded parallelism

Add per-family elapsed markers around existing [9/9] subgroups, retaining the full named acceptance population and offender/reason assertions. Then consider isolated shards for independently initialized homes/release copies whose cases do not share transition state. Keep real install→bootstrap→CLI submission→digest reread→upgrade/rollback journey intact. The observed12m59s makes this the highest-value place to investigate; no per-case profile exists yet, so neither a shard count nor a speedup is earned.

Stateful cases are not trivially parallel: script has shared home/release2 state, controlled environment overrides, unrelated-process lock holders, background-PID cleanup and race barriers (for example:7496 onward). Preserve ownership/mode/ancestor checks, mutation order, exact refusal reasons, lock contention, cleanup and failure artifacts. Never replace real production helper invocations with stubs to make the measured gate cheaper, weaken race waits, remove repetitions, or classify a missing shard as success. Measurement itself should expose durations only, not environment/secret dumps.

Ownership: deployment harness maintainers own subgroup/state extraction and coverage mapping; CI maintainers own any shard orchestration/aggregation. Independent review must cover TM-050 trust and negative evidence plus TM-052 all-required-results semantics. Begin with telemetry and acceptance inventory, not immediate wholesale splitting.

## Candidate2: overlap independent smoke and controlled-manager execution after one exact build

Today the workflow runs smoke, builds its service-managed gate, then runs the real manager serially (.github/workflows/foundation.yml:566,583,608). After prerequisites and all required binaries/test executables are built once, the two suites might run in separate isolated execution contexts. At this observation, the serial service-manager segment is3m04s plus21s build, so roughly3m25s is an optimistic upper bound on removable serial tail—not a promised saving; extra setup, contention or transport can erase it.

Keep the exact unstripped controller/release identity assertion. The runtime test embeds CARGO_BIN_EXE_mcloving-controller (bins/controller/tests/deployable_runtime.rs:80,780), so copying a test executable to another runner does not automatically relocate its referenced controller. A separate-job artifact design must preserve/verify executable path and exact source/toolchain/test/controller digests, or rebuild with equally pinned provenance and measure that cost. The workflow deliberately waits until builds finish before changing runner-home search permissions for the disposable service account; do not background current steps blindly and race chmod/restore, Cargo writes or shared host paths. Compare a same-runner isolated parallel design against separate jobs only after proving those boundaries.

Ownership: CI orchestration plus deployment controlled-manager harness; controller test owner reviews exact-path/binary assertions. Aggregate tests must add every new job literally, preserve always()/failure/cancel semantics, retain actual real-manager execution, and prove missing/zero/skipped child/test failures locally and hosted. This is not a path-based waiver or a proposal to reuse stale successful checks.

No new board ticket or repository change was made. Any eventual implementation needs scoped ownership, independent review and fresh exact-head/protected-main evidence; current merge gates remain unchanged.


Source references in this planning note describe repository commit `904fd1fed083cd17a6fc371e0a300c3696d93483` (tree `26240208f51f6028bf6bb6e619a2dcd5d19555f0`). Re-resolve paths and line numbers on the successor head. Planning and historical tool observations are not new runtime evidence.
