# AGENT-013 source throughput and retained-state review candidate

Observed 2026-10-07 UTC. Status: **ACTIVE**. Candidate base
`36221c44d793538dad8565dfb0cabc236c286348`; this receipt records earned proof and pending protected
completion gates. It does not close the execution board or change its DONE ratchet.

## Original acceptance and final candidate scope

The original board requires batched blob materialization with per-blob bounds,
next-attempt recovery or named refusal of killed retained state without operator
cleanup, exact requested-object acquisition after its branch advances, an actual
owner-host dogfood checkout under one minute, and a genuine mid-materialization
kill/retry integration proof. All obligations remain in scope.

Throughput, bulk prefetch, exact-revision and retained-state behavior already
ship in `crates/source-acquirer/src/lib.rs`. This candidate strengthens only
`sealed_helper_killed_mid_materialization_is_reclaimed` in
`crates/source-acquirer/tests/contained_source.rs`, then adds this receipt,
[`AGENT-013_PROOF.json`](AGENT-013_PROOF.json) and append-only observations in
`PAR-005_DOGFOOD.md` and `docs/threat-model/README.md`. No production source,
protocol, schema, workflow, credential grant, source profile, container launcher,
checkout policy, or controller/agent runtime behavior is changed.
Root observed the entire source-acquirer subtree unchanged between native-qualified
`cbfb41c9ce1374c7bc2cd757dbf4d60b78f744f5` and the new protected base, before
carrying this same modified test. Its exact current SHA256 is
`fb3dc513cfe4fcb1c233c2d354965f9ed6eb0bb15cd33661a255b061c0f3b404`.
Retained independent source hashes also match the current candidate bytes.

## Earned proof

| Original obligation | Actual evidence and limits |
|---|---|
| Batched throughput with bounded blobs | Existing one `git cat-file --batch` per repository tree after bulk object prefetch; `many_unique_blobs_materialize_through_bulk_prefetch_and_batch` passes. Each blob still passes declared-size/byte/secret limits; no global deadline, file/total/transport quota or object authorization is loosened. |
| Genuine killed acquisition and ordinary next retry | Native standalone helper stopped after **2/256** distinct bulk blobs existed, including at least one exact expected body; full-suite run separately observed **1/256**. `waitpid` acknowledges SIGSTOP within 5s; actual SIGKILL exit and bounded 5s reap are asserted. Same native executable, config bytes/digest, credential/signing/marker paths, acquisition ID and byte-identical request retry without claim rewriting or operator cleanup. Only the fixture readiness indicator uses a fresh path. Original signing binding authenticates the receipt/full retained tree; all **257 files / 1,516,557 bytes** and reclaimed owned stage/runtime/git-exec/transport/claim state are checked. |
| Exact older commit after branch advance | `exact_revision_replay_later_commit_and_sparse_truth` requests the original reachable commit after main advances, and binds its original tree/content digest. `exact_commit_only_reachable_from_other_ref_is_refused` retains the negative authorization boundary. Branch head never substitutes for the requested object. |
| Actual owner's dogfood checkout under60s | Fresh shipped controller, remote mTLS agent, sealed source renderer/helper and actual GitHub HTTPS checkout on HeMan at protected **dc5c58e85f0835d9761beffa330d46d960139e10**. The complete successful two-step attempt lasts **9,314ms**, including acquisition, normal agent tree verification/publication and harmless project-readiness process. Exact attempt/fence/remote identity, signed receipt and all **2,191 files / 28,074,111 bytes** are independently reconciled. This target-specific measurement is historical after base 362 advances; it is not a fresh checkout of this candidate base. |

Native recovery phase: **5.477213s**, test 2.94s. The affected source suite
passed **62 unique tests** (18 library  + 4 binary  + 38 contained  + 2 inventory),
zero failures/ignored, in **96.252236s**. Warnings-denied all-targets/all-features
Clippy exited 0 in **4.848940s**. These are qualified cbfb native observations,
not source tests rerun by this documentation author on base 362. The native proof
helper SHA256 was `a31d8e4d38def90fd0953001377b43e9ad6cd5a81d740382e195e0e60834f3d4`;
the separately clean-built dc5 benchmark helper was
`f4417f240aa0816efd43f8effcc45de83d5d075c5eecfd2d87d95fb0d8ee97c5`.
Their source/provenance bindings are retained; different binaries are not equated.

The benchmark's start/acquired/completed integer times are respectively
`1791340296545`, `1791340305657`, `1791340305859`. Acquisition-only
**9,112ms** is diagnostic; whole-wrapper **13.521s** includes setup/cleanup and
is not checkout timing. The signed resolved tree is
`ade4d1eea0649b8d71d204dde5861fde5989e3d9`. Independent review reproduced the
original HMAC-SHA256/base64url signature before retiring the fixture key,
rejected a signed-bytecount substitution, verified the full manifest digest,
and checked every path/mode/blob/content hash against the clean protected
expected tree. It reconstructed that exact tree without a Git command.
The materialized runtime tree had already been cleaned; this static review
never pretends that tree is still live. Normal product verification/publication
is supported by the actual successful checkout and subsequent readiness step.

The benchmark retained max-depth 8, 20,000 files, 256MiB total, 32MiB per file,
512MiB transport, 512-byte paths, no submodules, 120-second command deadline,
heads-only refs, full tree, no untrusted forks and no file/loopback source mode.
The full protected checkout block is byte-identical except the deployment mapping
digest; its original 3600s step timeout remains. The pipeline omits notifications
and costly Foundation lanes, so this proof is checkout throughput, not a new
whole-Foundation dogfood verdict.

## Threat and boundary determinations

| Boundary | Determination and verification |
|---|---|
| Source substitution, batching and bounded materialization; TM-016/TM-023 supply-chain controls and PAR-012 checkout | Existing exact implementation/config/Git/helper/CA/runtime-closure/mapping/commit/tree bindings remain. Current complete source hashes and all five benchmark product binaries/build receipts match. Per-blob, total, file/path, batch, transport, deadline and secret bounds retain existing positive/negative controls. No protocol or production source edit. |
| Retained state, durability and recovery; TM-005/TM-006 | Kernel-confirmed actual helper death precedes unchanged-binding retry. Original incomplete claim bytes are observed and left untouched; live unrelated helper preservation, named ambiguity refusal and normal coordination locks remain tested. Owner host/disk corruption and unknown identity still require fail-closed diagnosis. |
| Cancellation/process lifetime; TM-007 | Bounded kernel SIGSTOP acknowledgement and real SIGKILL/reap make the crash oracle meaningful. No change to process-group/Windows Job/VM containment or agent cancellation. SIGKILL/power loss cannot execute benchmark cleanup traps; owned-custody markers remain mandatory on failure. |
| Secrets and provenance; TM-013/TM-014 | Real gh read token is acquired only inside the reviewed root execution path into private0400 files and a private0600 intent, never host argv/token environment/public output. Source marker/refusal controls remain. Independent receipt/config/request/tree authentication occurred before exact fixture key/journal retirement. Same-UID owner environment/debug inspection and transformed-secret residuals remain SEC-005 scope. |
| Work admission, tenant/pool and authority; TM-009/TM-011/TM-038 | Existing saved-pipeline authenticated API, distinct fixture tenant/project, actual remote mTLS identity/pool, exact attempt/fence/status and normal tree publication are used. Embedded agent is disabled for this fixture. No controller, scheduler, tenant, RLS, session, retry, schema or real workload authority changes. |
| Isolation and runtime custody | Fresh immutable PostgreSQL17.6 fixture: network none/no published ports, keep-id owner, private host Unix socket bound at container standard path, empty TCP listen addresses, host-auth reject, final PID1 plus real SQL readiness. Fresh random0400 password file is bound read-only and removed; values never enter host argv/environment/logs. Existing source profile is explicitly **(unconfined)**: a named userns permission profile, not a MAC-confinement assertion. |
| Audit/restore/quota/rendering/release and protected checks; TM-052 | This test/evidence candidate changes none of those production contracts or merge-authority workflows/oracles. Actual dc5 Foundation37558694848 and Windows37558694803 include all eight app 15368-required contexts and 23 executed native Windows steps. They qualify the benchmark target, not this later uncommitted candidate or universal latest-head checks. |

## Failed setup, cleanup and limits

The first actual benchmark invocation failed at PostgreSQL setup after 121.677s,
before product startup or the real GitHub credential read. That elapsed time is
not checkout evidence. Immutable password-only bootstrap/default-socket and
standard-socket temporary-server early-readiness negatives remain separately
recorded. The corrected final PID1/real SQL preflight passed actual 170006,
listen-empty/socket0700/network-none/no-port readbacks and exact owned cleanup.
The earlier mutable preflight JSON and its later immutable negative differ in
hashes; the dated prior freeze is preserved, with no invented byte equality.

Tool cleanup records five credential-copy removals and ten runtime directory
removals, exact owned-container label/ID removal, child reap and transport unmount.
Independent review observed exact container ID absence (read-only exists exit1),
all owned credential/runtime paths and mount absent and both direct-child PIDs
absent. Cleanup-time 98 same-real-UID executable/cwd readbacks were outside the
fresh prefix with matching UID/starttime before/after; unknown/denied or changed
identities would refuse custody. That is not a universal other-UID, anonymous
memory image or host-quiescence assertion. No unrelated owner process is killed.
Root then retired only the fixture verification key, agent/embedded journals and
empty lock after consuming actual independent HMAC review; signed receipt,
manifest, graph/timing/config and cleanup evidence remain. No GitHub token
revocation or production credential action is claimed.

The real credential's signed binding does not prove GitHub challenged/used it
for this public origin. Generated fixture mTLS/receipt keys and database password
do not grant broker/production/canary authority. The live NDJSON request was not
persisted; only its signed request_sha256 and acquisition/build/attempt linkage
are retained. Historical HeMan 13.0s/2,138 files at 0220759a and Luigi 64.6s remain
historical observations; neither is rewritten as the current measurement.

## Review roles and remaining gates

Original test author/native executor: `/root/milestone_m1/agent013`; actual
FINAL consumed. Independent full corrected-test/native proof reviewer:
`/root/milestone_m1`. Benchmark tool author: `/root/milestone_m1`;
independent whole-tool/delta reviewer and executor: `/root`. Benchmark result
reviewer: `/root/milestone_m1`, review SHA256
`a265906ee5797b636168b3eab68142ac83bd709974fd20b0aa53f9b2c19b83db`.
Those are observed agent roles, not invented human or production-owner approvals.
All raw nonsecret identity/digest references are bound in `AGENT-013_PROOF.json`;
private credentials, keys, journals, process inventories and logs are not copied
into the repository. The raw manifest remains in controlled local evidence.

This new complete candidate/security/threat documentation still requires root's
independent whole-candidate and exact committed-head review, resolution of any
actionable findings, required app-bound candidate checks/live protection, normal
protected merge, exact resulting-main Foundation and actual native Windows, then
subsequent reviewed closure bookkeeping. No DONE transition or ratchet edit is
made here. DOGFOOD-001 public ingress/normalization and SEC-005 hostile same-UID
isolation remain separate full-scope tickets; no production/migration/release
permission is inferred from these bounded proofs.

## Public receipt metadata projection (2026-10-07 UTC)

PR #182's exact head `f1a398a4a03fffdd989a4805c8e805597b8e3365` failed
Foundation Secret scan job112608173756 in run37564228534: `generic-api-key`
reported `AGENT-013_PROOF.json` line121, `secret_marker_set_sha256`. Private
comparison confirms that field exactly matches the original authenticated
receipt and retained config. The shipped `marker_set_digest` hashes sorted
marker bytes with unsigned64-bit big-endian length prefixes. The published
value is that SHA256 commitment, not the credential or signing key; no raw
secret leak is inferred from this entropy finding. The matched value is not
repeated in this correction. The exact negative log SHA256 is
`1ea5e9518be6959016c2da08e1849c50a48619842dfd10dde339d1b8cf0d4c17`.

The public JSON now contains an explicitly unsigned receipt metadata projection.
It omits the original `secret_marker_set_sha256` and `signature` fields; all
remaining receipt metadata is identical to the original. No matched value is
renamed or reencoded, no signature is presented as authenticating the reduced
projection, and no scanner rule/allowlist/exemption is changed. The complete
original signed receipt is untouched in controlled local evidence; its raw
SHA256 remains `c182f0c0666944d503e7b320d45bbf8bffe492fffe40b64e91e08403d7247386`.
Actual original-key HMAC verification, exact manifest/tree/timing review and
post-review key retirement remain the previously observed proofs. No key or
credential is regenerated/reacquired, and all original AGENT-013 scope stays.

The prior full public receipt and this exact negative remain dated history.
Root must independently review the whole corrected candidate and run the
unchanged scanner over its actual candidate tree and required CI history range;
this source-only correction has not run a scanner or restarted/cancelled the
live workflow. Exact candidate checks, protected merge/post-merge gates and
closure bookkeeping remain unearned. AGENT-013 stays ACTIVE.

## Current-main composition provenance (2026-10-07 UTC)

The original header's “Candidate base”
`36221c44d793538dad8565dfb0cabc236c286348` records the **initial published
candidate's provenance**. That dated original text remains preserved. The
current source/evidence composition is based on protected main
`3fb819f53116f039159e9d0055eadcf539f1243c`. In `AGENT-013_PROOF.json`,
`initial_published_candidate_base` retains 362, while `candidate_base` now names
this actual 3fb composition. This metadata clarification does not change any
test, signed receipt, projected receipt field, native observation, benchmark
measurement, authority boundary or protected historical prefix.

No new native suite or owner-host benchmark was run for 3fb. The qualified
cbfb native recovery and exact dc5 owner checkout remain target-specific earlier
observations, not fresh 3fb qualification. The previously reviewed 9b301b composition
passed root's unchanged pinned full-history scan in 3.770s; that result belongs
to those prior exact bytes. This later metadata correction still requires root's
independent whole-candidate/exact committed review and fresh unchanged scanner
and candidate checks before publication/merge. No future candidate SHA is
invented or bound circularly inside this receipt. AGENT-013 remains ACTIVE.


## 2026-10-07 subsequent reviewed closure observation

Observed at 2026-10-07T04:09:24.394197+00:00: the full original AGENT-013 acceptance had independently
reviewed proof, normal protected implementation merge and successful exact-
implementation-result Foundation and actual native Windows verification.
The entire earlier receipt remains an exact historical prefix, including the
initial 362 provenance, later 3fb composition and earlier pending-gate language.

All three original behavior obligations and both proof requirements remain
earned at their recorded scope. Batched blob materialization retains per-blob,
file/total/path/transport/deadline/secret bounds. The kernel-acknowledged partial-
materialization SIGSTOP/SIGKILL proof retries the same actual native executable,
config, private bindings, acquisition identity and byte-identical request,
without operator cleanup or retained-claim rewriting; the full signed tree
and owned-state reclamation are checked. Exact older reachable-object acquisition
after its branch advances passes, while another-ref-only authorization remains
refused. The native proof's 62 unique source tests and strict Clippy retain their
qualified cbfb source/binary identities and measured phases.

The actual HeMan dogfood checkout proof is the historical protected
`dc5c58e85f0835d9761beffa330d46d960139e10` target: a complete successful
two-step attempt took **9,314 ms** for **2,191 files / 28,074,111 bytes** through
the shipped authenticated controller, remote mTLS agent and sealed checkout.
That conservative interval includes ordinary tree verification/publication and
the harmless readiness process. Acquisition-only 9,112 ms is diagnostic and the
13.521 s wrapper duration is not checkout timing. No new d7 checkout or native
benchmark is claimed by this closure.

Original leaf `/root/milestone_m1/agent013` authored/executed the crash proof;
its actual FINAL was consumed. Independent corrected-source/native review by
`/root/milestone_m1` is
`/tmp/mcloving-milestones/M1/AGENT-013/native/independent-native-review.json`,
SHA-256 `ba2ac1423190b8bcc84969da3fd3e4cd230c4fb4eab85bfc32590ba5909ef34d`.
Root independently reviewed and executed the benchmark tool; independent full
result/HMAC/tree/manifest/timing/cleanup review by `/root/milestone_m1` is
`benchmark/root-owner-benchmark-dc5-retry2-independent-review.json`,
SHA-256 `a265906ee5797b636168b3eab68142ac83bd709974fd20b0aa53f9b2c19b83db`.
Root's exact whole-five-file implementation/projection/provenance review in
`root-final-current-main-projection-review.json` binds
`c5bf441fa5c9b5ec29ec45949375513f81bbbbbb` on protected 3fb, SHA-256
`5a8ecd74692d652dbbf89e7ac9ca08b2adc74f90b374813fd552703a6787835a`.

The public receipt is explicitly an **unsigned metadata projection**, omitting
the original marker commitment and signature while retaining the original raw
receipt SHA-256. It does not authenticate the reduced projection. The complete
original signed receipt, exact manifest/tree and config/request/execution
bindings were privately HMAC-reviewed before root retired the exact fixture
verification key and private journals. The retirement record
`benchmark/root-benchmark-post-review-private-custody-retirement.json`,
SHA-256 `572c7474d867102c3fd0bcb75187c9f4740c8ee6d2996b7b205479e36073a810`,
retains that sequence. No key recovery/regeneration or provider-token revocation
is claimed. The original entropy-scan negative and unchanged-scanner correction
remain historical evidence without a rule exemption.

PR [#182](https://github.com/SuperBadLabs/McLoving/pull/182) normally protected
squash-merged as `d7bba542dfa67306a3128908c3ccd37e84fbb8d5` at
2026-10-07T03:42:05Z, after the exact reviewed candidate's eight required
GitHub Actions App 15368 contexts and protected review policy; no administrator
override or direct main push was used. The protected premerge/merge records
remain under `/tmp/mcloving-milestones/M1/AGENT-013/`.

Exact-merge push Foundation
[37567968905](https://github.com/SuperBadLabs/McLoving/actions/runs/37567968905)
and Windows Agent
[37567968977](https://github.com/SuperBadLabs/McLoving/actions/runs/37567968977)
completed successfully on attempt 1. Foundation's fifteen recorded jobs were
terminal: fourteen succeeded and the UI browser job was legitimately skipped
under the successful impact classifier. No skipped browser execution is credited.
Actual native Windows job
[112619980593](https://github.com/SuperBadLabs/McLoving/actions/runs/37567968977/job/112619980593)
executed all 23 steps successfully; raw log SHA-256 is
`8067e5b437948b2059b8eb35bd6fd7fe824d893b9947e5561cb5f7be4004caed`.
`implementation-current-main-joint-gate-success.json`, SHA-256
`cfef9319a7d4bb581f31a083d4ee3306a245a7d0c038ddf56f89adf957da33f5`,
records the exact d7 implementation-result gate. The Linux kill/retry and dc5
owner checkout are distinct proofs, not claims those scenarios ran on Windows.

All affected source/provenance, retained-state, cancellation, secret and
admission boundary determinations above remain. The named source profile is
explicitly unconfined and grants user-namespace permission, not MAC containment.
A real credential binding for a public GitHub origin does not prove the provider
challenged/used that credential; raw live NDJSON was not retained. Same-UID owner
inspection/transformed secrets, SIGKILL/power-loss cleanup, bounded process
visibility and host/disk corruption remain residuals. The first 121.677 s
PostgreSQL setup failure and subsequent bootstrap/readiness negatives remain
historical failures, not checkout metrics. Older HeMan 13.0 s and Luigi 64.6 s
are not relabeled. DOGFOOD-001 ingress and SEC-005 hostile same-UID isolation
remain separate full-scope tickets.

This private closure bookkeeping preserves the literal acceptance and PAR-005
dependency. It changes no product source, protocol, schema, checkout policy,
credential grant or operational authority. Root owns independent whole-five-file
review, validation, composition on the qualified result of the in-flight combined
implementation, protected checks and normal closure merge. No production,
canary, migration, deployment or release authority is granted, and no later
head's gates or already published closure are asserted.
