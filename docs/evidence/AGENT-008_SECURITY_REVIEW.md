# AGENT-008 recovery publication candidate review

Observed on 2026-10-06 in isolated branch `codex/agent-008-recovery-20261005`,
allocated from `7ff63e54f70ea5d1110b72037e84fe6011f50d01`. This records local
implementation evidence and an agent-authored boundary assessment. Independent
review, exact candidate checks, protected merge and post-merge Foundation/native
Windows receipts remain required. The ticket remains open; this document grants
no production, release, credential or migration authority.

## Implementation and acceptance

The original board acceptance describes cancellation completing before crashed
attempt logs replay. PAR-013 subsequently introduced the necessary recovery
ordering. This candidate changes no production agent/controller code, journal
schema, authority predicates or protocol. It supplies the missing exact
shipped-binary evidence rather than speculatively reordering session transfer.

The test
`crashed_second_step_publishes_all_descriptors_before_cancellation_and_replays_lost_response`
in `bins/agent/tests/long_step_lease.rs` observes the actual journal while the
second of two process steps is running, with both nonempty step-zero stdout and
stderr descriptors already durable and no published chunks. It SIGKILLs the
shipped agent, restarts it, and gates recovery publication through a test-owned
mTLS forwarding peer. The peer forwards authority and lease RPCs to the shipped
controller normally; the actual server remains responsible for fencing,
session transfer and commit. It negotiates terminal-only logs on both sides so
the test cannot pass merely because a live tail uploaded step zero before the
crash. The separate existing single-step live-stream crash test covers that
negotiated mode.

Before the first upload, both descriptor identities remain in the journal and
the phase is `cancelling`; the controller ledger is empty and no cancellation
request has occurred. The peer then forwards the actual first chunk and holds
its positive controller receipt. PostgreSQL contains one 17-byte chunk at
position 1, while the local reservation is unacknowledged, cancellation has not
been sent, and neither controller nor journal is terminal. The forwarding peer
discards that accepted response and returns `Unavailable`. The journal stays
`cancelling`. A newly started agent session sends the identical sequence,
stream, step ordinal and content under the same fence and a fresh session epoch.
Its accepted retry leaves the controller ledger, byte quota counter and build
position unchanged. After release of that receipt, all journaled descriptors
and interrupted step-one output publish before the sole cancellation outcome.

The complete ledger contains exactly three dense sequences and positions,
55 committed bytes, both exact step-zero descriptor digests and one terminal
event. The real public logs API and shipped `mcloving-cli logs` both return the
step-zero stdout/stderr markers. Local terminal acknowledgement finally retires
the journal row. These are actual local contained observations, not a claim
about arbitrary missing, rewritten or maliciously unlinked spool files.

Foundation now builds the CLI alongside the existing controller/helper fixtures,
supplies its binary path and raises the verified long-step executed minimum
from eight to nine. `scripts/test-controller-postgres.sh` mirrors that build and
minimum. No old gate, aggregate context, application identity, protection rule,
classifier or supported production authority is removed or broadened.

## Fault controls

Three temporary isolated source mutations demonstrate specific semantic reds:

1. Re-admitting retained `cancelling` attempts to startup cancellation reporting
   produces an actual controller terminal event before the first log upload.
   The test fails with `cancellation completed before first recovery publication`,
   with the real ledger/status snapshot, rather than earning a generic timeout.
2. Omitting the journaled-descriptor replay loop publishes only interrupted
   step-one output and fails the named assertion requiring both step-zero streams.
3. Recording a journal acknowledgement before a positive response reaches the
   agent fails `upstream commit is not a client receipt` at the held response.

Every credited control has a byte-for-byte runtime restoration followed by a
successful complete acceptance scenario. Production runtime files match the
allocated baseline. An exploratory omission of reservation replay instead hit
the journal's existing spool-sequence conflict guard and timed out awaiting the
intended retry; it is retained as diagnostic evidence and is not credited as a
semantic mutation proof.

## Boundary assessment

TM-006 durable agent recovery is directly exercised: descriptor persistence,
sequence/digest reservation custody, acknowledgement semantics and the order
of publication, cancellation completion, terminal transition and reclamation.
TM-003 and TM-011 retain the exact attempt/fence/restore-epoch/session authority;
the recovered upload and duplicate carry fresh session epochs, not a stale
session bypass. TM-005 PostgreSQL truth and TM-018 quota/counter semantics retain
the real transactional append and unchanged counters for an identical retry.
TM-007 containment is unchanged: the second-step process is quiesced under its
journaled process identity before logs replay; missing/unverifiable process
identity must still park, not self-discharge. TM-052 gains an executing gate
with its CLI fixture and count mirrored; merge-authority review is still owed.

Reviewed with no production-control change: TM-001 tenant scoping and RLS,
TM-002 trust-pool admission, TM-013 credential redaction, TM-014 artifact
provenance, TM-016 immutable dependency/action pins, TM-017 restore authority, TM-019
approvals, TM-020/TM-026 compile-only admission, TM-021 protocol validation, TM-022 audit, TM-023 validated tool versions,
TM-024 CLI state rendering, TM-027/TM-028 identity/grants, TM-031 external readers, TM-032 external administrative writers,
TM-033 external input, TM-036 cache, TM-041 secret broker, TM-034 provisioner, TM-035 dependency resolution and deployment,
supply-chain, migration and release boundaries. No production code, credential
grant, source/artifact/helper execution, package or policy changes enter this
candidate. The fixture CA/private keys and service-account test token belong
only to the contained test; the peer forwards using that fixture identity and
does not install a trust root or fault switch in shipped code.

Residual risks remain spool disappearance or rewrite under the service UID
(AGENT-011 custody), hostile same-UID workload isolation (SEC-005), host/disk
failure, stale authority definitively refused by the controller, and native
Windows recovery qualification. A definitive fence retirement never authorizes
log publication. This Linux shell/SQLite/PostgreSQL proof does not replace
native Windows or independently reviewed closure evidence.

## Verification custody

Local raw results, scenario ledger/journal/CLI JSON, source hashes and private
fixture readbacks are retained under
`/tmp/mcloving-milestones/M2/AGENT-008/`. `controls.json` records the credited
semantic reds, restored greens and exact runtime restoration. The frozen native
regression report is `final-native.json`. The portable scenario, tested source
hashes, commands and actual denominators are in
`docs/evidence/AGENT-008_RECOVERY_EVIDENCE.json`. Final native execution passed
all nine long-step gates, 115 agent unit tests, one shipped mTLS execution gate,
one ambiguity-window containment gate, one identity-collision gate, and three
real PostgreSQL fencing/discharge/quota tests. Clippy passed with warnings
denied. Workflow-aggregate tests passed 13 cases, test-execution verifier tests
passed nine, and dogfood lane coverage passed six lanes with 67 commands checked
and its existing one documented omission unchanged. No unexecuted or
environment-skipped gate earns acceptance.

## 2026-10-06 every-descriptor phase continuation

The 130-test campaign above is historical. Its direct local/controller phase
snapshots extended through the held first upload and identical retry; later
descriptors needed their own publication and committed-receipt observations to
prove the original acceptance at its full scope. The revised test-only observer
now directly records all eight moments, including step-zero stderr and
interrupted step-one stdout, with the active local row still `cancelling`, no
cancellation request, and a nonterminal controller before each response is
released. A new early-local-retirement mutation fails that specific invariant;
all four semantic controls pass after exact runtime restoration.

The fresh continuation reruns all nine long-step tests and targeted Clippy.
The earlier 115 unit and six focused regressions remain historical and are not
claimed as newly executed. Exact phase snapshots, current tested source hashes,
commands and the fresh owned fixture binding are recorded in
`docs/evidence/AGENT-008_PHASE_QUALIFICATION.json`; the observation gap,
meaningful mutation and qualification scope are explained in
`docs/evidence/AGENT-008_PHASE_QUALIFICATION.md`. The original canonical body is
retained as this file's exact prefix and as an initial-body copy beside the new
local phase freeze. Original native/control/freeze JSON bytes are unchanged.
The four named red/restored-green controls are premature controller cancellation,
omitted journaled descriptors, acknowledgement before a receipt, and local
retirement before later descriptor receipts. The last fails
`local journal left cancelling before all descriptor receipts` with the real
local/controller snapshot. The fresh full-nine gate and targeted Clippy pass;
their actual commands and results remain separately bound from the initial
130-test campaign. The whole revised candidate, untouched historical reports,
initial canonical-prefix digest and exact new fixture cleanup are bound by
`/tmp/mcloving-milestones/M2/AGENT-008/phase-qualification/candidate-phase-freeze.json`.

Independent review, protected publication and exact hosted/post-merge gates
remain open; no closure attribution or authority is earned by this continuation.
