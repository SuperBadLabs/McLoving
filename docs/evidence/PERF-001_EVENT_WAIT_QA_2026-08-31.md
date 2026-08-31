# PERF-001 event-wait QA evidence — 2026-08-31

## Verdict

The fixed-interval work-acquisition regime and its residual
reconciliation-only controller loop are replaced by event-driven waits. The
bounded event-wait dimension is closed by PRs #109 and #110. `PERF-001` remains
`PENDING`: these receipts do not establish its full capacity, saturation,
backpressure, storage-sensitivity, recovery, regression-margin, or eligible
platform envelopes.

## Identity map

| Item | Identity |
|---|---|
| PR #109 protected-main merge | `4f77485d9ac3ee3506779d318d56c133bcf72a64` |
| PR #110 signed reviewed source | `e57f7c9c6dcd8a1f45bc41393780d90fdbf7c13a` |
| PR #110 reviewed/evidenced tree | `b4d4b86b06666fd9bae9f85b8e44f426a9b227dd` |
| PR #110 protected-main squash | `0f6499ff082f7d7dd7c85831ed4659bc3923dce6` |
| PR #110 squash tree | `b4d4b86b06666fd9bae9f85b8e44f426a9b227dd` |
| Squash verification | GitHub `verified=true`, `reason=valid`, verified 2026-08-31T21:09:38Z |

The squash commit and reviewed source have the same tree. Performance receipts
name the source commit compiled into the binaries; the protected-main mapping
above records where that exact tree shipped.

## Accepted receipts

The exact signed source was transferred as a Git bundle to a clean checkout on
Mario. Controller and agent were rebuilt in the pinned Rust image with source
head/tree embedded at link time. The split-stack proof then executed each live
binary's `build-provenance` command, compared executable hashes, resolved the
PostgreSQL container init PID and image ID, and sampled the complete process
trees plus the SSH forwarder.

| Receipt | SHA-256 | Result |
|---|---|---|
| `PERF-001_EVENT_WAIT_QA_2026-08-31.json` | `c909d227d1cffc6df3ac19d155454637e3137ab078356e62679665e2d65a7a35` | five heats; 71.2018 ms/stage median, 61.0326 minimum; 14.3% estimator gap; 7.06 median transactions/stage; 183 ms target met |
| `PERF-001_EVENT_WAIT_QA_2026-08-31_IDLE.tsv` | `043c5e485f92a310e81c4e59556b4fd8ee238fa7cc6dd417d7a822bc70e3bf77` | 1.099% complete-stack idle CPU across 14 processes; fixed 5% target met |

The idle-CPU result reported for this evidence bundle is the value from
`PERF-001_EVENT_WAIT_QA_2026-08-31_IDLE.tsv`; the JSON receipt includes
`combined_idle_cpu_percent` and `idle_cpu_target_met` fields only as metadata
for the stage-latency run and they are not the reported idle-CPU measurement in
this bundle.

Runtime identities in the strict receipt:

- controller SHA-256: `1437efacb2a010ea8246a6aed0a042bdd5aa4ad2eaddaf1d1535631d3085d27f`
- agent SHA-256: `392cef655b572fea3eec47e7cf277cc7f584371ecade2871c6e6d012f3b92de4`
- forwarder SHA-256: `27a7f5e86ed31efa1e758c7f955bdc016adf58bb3266c68e217ab5bee311b46b`
- PostgreSQL: `docker.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`, runtime image ID `d741b376874687de90374fd34f55c6b2760e8f7bd7e4ae5cd47f50757fc08cf8`

## Correctness and review

- The focused exact-head PostgreSQL test passed queued admission, no-op
  suppression, first-active-lease wake, shorter-active-lease wake, and quiet
  lease extension.
- The exact-head hosted Controller PostgreSQL lane passed its 55 active truth
  tests with 2 purposefully ignored, plus all other migration, ingress,
  discovery, authorization, consumer, identity, OIDC, and credential-rollout
  groups.
- Every hosted check completed successfully, including Deployment lane, Rust
  workspace/lint/boundary suites, Windows agent, formal model, dependencies,
  backup/restore, architecture, and secret scan.
- Codex reviewed exact `e57f7c9` and reported no major issues. Copilot reviewed
  exact `e57f7c9` and verified the shorter-deadline semantics and regression.
  No review thread remained unresolved at merge.

## Rejected and superseded measurements

Evidence selection was not post-hoc. Earlier raw-minimum runs on review heads
were rejected when their median/minimum estimator gaps exceeded the fixed 15%
admissibility bound, including 78.48/42.30 ms per stage on `8724a85` and
70.91/30.47 ms per stage on `2cea400`. They are disclosed here and are not
substituted for the final receipt.

An admissible exact `66a04d8` receipt (79.7523 ms/stage median, 75.9757
minimum; SHA-256 `1e4624fb7f8e15b0733363dae7070dcae1355a3ed6b2d9500dc3da060719c63a`)
was superseded when exact-head review found the legal shorter-lease edge case.
The implementation changed, binaries were rebuilt, and both receipts were
rerun at `e57f7c9` rather than relabeling the earlier proof.

## Bounded non-claims

This evidence proves the event-wait implementation, its authoritative timeout
fallbacks, and the measured Mario latency/idle-CPU slice. It does not close
`PERF-001`; it does not claim saturation, overload/backpressure, storage
sensitivity, recovery-time, full multi-host regression margins, or eligible
Windows performance envelopes. Those remain on the existing `PERF-001` row.
