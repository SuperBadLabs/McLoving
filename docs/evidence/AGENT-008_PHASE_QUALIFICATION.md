# AGENT-008 every-descriptor phase qualification

Observed on 2026-10-06 in the same isolated candidate allocated from
`7ff63e54f70ea5d1110b72037e84fe6011f50d01`. This supplements
`docs/evidence/AGENT-008_SECURITY_REVIEW.md` and preserves that original
130-test campaign as historical evidence. It earns no ticket closure,
independent review, protected merge, hosted candidate check or post-merge
Foundation/native Windows claim.

## Correction to observation scope

The initial scenario directly inspected `cancelling` through the held first
upload and identical retry. Later descriptors then forwarded without the same
direct journal/controller observation at each publication and accepted receipt.
That evidence was insufficient for the original acceptance's **every descriptor**
requirement. The test-only continuation adds those observations; acceptance,
production agent/controller code, protocol, journal schema, authority rules and
the workflow wiring remain unchanged.

The authenticated fixture peer now reads the actual local active journal row
and real PostgreSQL ledger before forwarding each recovery upload and after
its actual accepted commit, before releasing the response. Every snapshot
requires the row still present in `cancelling`, zero cancellation requests,
controller status `cancelling`, and zero terminal events. A test-owned failure
notification exposes a named invariant rather than masking an observer refusal
as a transport timeout. An independent local-phase watcher also detects
retirement when a defective publisher fails locally before its next RPC.

The complete positive contains eight direct snapshots: before/after the first
step-zero stdout upload, before/after its genuine committed-but-unreceipted
fresh-session retry, before/after step-zero stderr, and before/after interrupted
step-one stdout. Each is bound to its sequence, stream, ordinal, content digest,
attempt, fence and session. All eight observe `cancelling` locally and remotely
with no cancellation request or terminal event. The lost positive response,
new session, identical ledger/counter retry, three dense final chunks, 55-byte
counter and actual CLI output remain proved.

Portable actual snapshots, exact source hashes, commands, control results and
fixture identity are in `docs/evidence/AGENT-008_PHASE_QUALIFICATION.json`.

## New semantic control and fresh execution

A temporary isolated worker mutation transitions the local journal to `aborted`
after the first acknowledged recovery chunk, before later descriptors publish.
The observer fails with
`local journal left cancelling before all descriptor receipts`. Its actual
failure snapshot has no active local row, only two accepted receipt observations
(the lost response and its retry), and a controller still `cancelling` with
17 bytes, one chunk and zero terminal events. This is a direct ordering refusal,
not a timeout or fixture/setup failure. Exact runtime restoration then passes
the complete scenario.

All three original semantic controls were rerun against the revised observer:
premature controller cancellation, omitted completed descriptors and premature
journal acknowledgement. Each yields its named semantic red, followed by
byte-restored green. The fresh controls report has nine stages: one baseline
positive and four red/restored-green pairs.

The fresh full long-step campaign executes and passes all nine tests, with
zero failures, ignores or filtered tests, including the unchanged negotiated-live
single-step crash and lease/outage regressions. Test execution takes 70.15 seconds;
the encompassing verified command takes 71.244 seconds. Targeted agent Clippy
with warnings denied passes in 1.248 seconds. The earlier 115 agent unit tests
and six focused mTLS/containment/identity/store tests were **not rerun** in this
continuation; their original results remain historical with unchanged production
runtime bytes. They are not added to the fresh nine-test denominator.

Raw followup logs, exact source freezes, controls and fixture custody are under
`/tmp/mcloving-milestones/M2/AGENT-008/phase-qualification/`. The original
`candidate-freeze.json`, `final-native.json` and `controls.json` in its parent
directory retain their original bytes. The final phase freeze separately binds
the revised candidate. No production fault switch or authority bypass is added.

The canonical assessment's residual boundaries remain: AGENT-011 owns missing
or rewritten reserved-spool custody, SEC-005 owns hostile same-UID isolation,
and host/disk failure, definitive fence retirement and native Windows
qualification are not discharged by this contained Linux proof.
