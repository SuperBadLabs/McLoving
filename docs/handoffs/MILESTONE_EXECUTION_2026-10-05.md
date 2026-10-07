# Milestone execution observation: 2026-10-05

This records an execution wave observed on 2026-10-05. It does not assert the
current head, current ticket status, or completion of the roadmap. The
execution board remains authoritative. The requested objective is to work
through every roadmap milestone and ticket using a milestone coordinator
which spawns a separate agent for each ticket.

## Scope and custody

The roadmap snapshot groups 40 unclosed tickets into seven milestones;
107 tickets were already DONE. Complete ticket acceptance and dependency
records are retained locally in `/tmp/mcloving-milestones/manifest.json`.
Ticket implementations use isolated `codex/` worktrees below
`/tmp/mcloving-milestones/worktrees`. The original main checkout's roadmap
edit, dogfood script edit and unrelated untracked work were preserved.

The open-ticket dependency audit assigned all 40 tickets exactly once and
found no cycle. Its snapshot is `/tmp/mcloving-milestones/dependency-audit.json`.
An absent open predecessor does not resume a deferred lane or grant authority.

Seven milestone coordinators and forty distinct ticket agents completed their
initial acceptance/source review waves. Each agent maps to exactly one ticket
under its milestone coordinator in the manifest. All original acceptance and
dependency sets were retained. These initial reviews did not complete the
implementation goal or earn any ticket closure.

Observed baseline: `8f2b625b7623aae7734576b85fa15424b86a7170`.
Foundation run `36652376712`, attempt 2, completed successfully after rerunning
the canceled browser job. Windows Agent run `36652376373` completed
successfully, including native debug and release service/recovery gates.
Pinned local formatting, workspace Clippy with warnings denied, and the
selected board, closure, workflow aggregate and classifier checks passed.
These baseline observations do not verify any later candidate commit.

## M1: reliable self-hosting

Coordinator `/root/milestone_m1` spawned `/root/milestone_m1/par005`,
`/root/milestone_m1/agent013` and `/root/milestone_m1/dogfood001`.

PAR-005 has a local candidate commit
`c8cdf61169fdd84ff4febc5fdcc8c446d42f2298`. The recorder fix preserves three
millisecond digits. Its full-script regression checks seven fractions,
including the actual historical 040 and 087 ms cases, plus refusal of a
truly older build. The regression runs in Foundation's architecture job and
its dogfood mirror. Local regression, 13 workflow aggregate tests, lane
alignment and board/closure verifiers passed.

Independent readbacks confirmed the ten Foundation push runs and their exact
head SHAs, the corresponding successful GitHub statuses, and ten succeeded
controller builds. The database evidence came from an isolated copy of the
stopped original volume with no network and read-only transactions; the
original deployment was not started. Each stored checkout commit matched
its recorded Foundation head. The task-created readback container was
removed; the snapshot and selected nonsecret evidence remain available.

The original evidence table was preserved. Dated errata explain row 7's
`.870` versus actual API `.087`, and row 10's `.400` versus actual API `.040`.
All verdicts and the consecutive-push ordering still match.

Full security review also identified credentials in process arguments:
bridge HMAC signing, controller bearer headers, and public-hook configuration.
Untested prototypes for removing this exposure were preserved separately as
uncommitted edits to bridge.sh/heman-up.sh plus sign-hook.py in the isolated
PAR-005 worktree. They have not earned regression or exact-head approval.

AGENT-013's existing implementation needs a stronger real interrupted-helper
recovery test and appropriately bound owner-host checkout evidence.
DOGFOOD-001 needs persistent webhook ownership/mode transitions and
bidirectional comparison of normalized wrapped lane commands. Their formal
PAR-005 dependency remains unclosed. No M1 ticket earned closure in this wave.

## M2: runtime hardening and compatibility

Coordinator `/root/milestone_m2` spawned ten distinct ticket agents and
consumed all ten actual FINALs. `/tmp/mcloving-milestones/M2/coverage.json`
records their names, source findings and twenty audit/design artifacts.

CTRL-006's missing artifact-stage refusal was confirmed; valid-IR first/later
stage regressions and an artifact-free positive case are designed.
CTRL-005 needs exact organization/attempt/fence byte accounting, safe backfill,
legacy-writer compatibility, and full query-plan proof. Its schema work must
serialize with AGENT-012. AGENT-008's recovery ordering appears incidentally
corrected already; shipped crash and lost-response evidence remain missing.

AGENT-009 lacks effective store/configuration pinning and leading-`#`
environment-name refusal. AGENT-010 retains all five publication/recovery
gaps. AGENT-011 lacks private reserved-log copies and reservation-only replay;
its diagnostic carrier needs resolution while preserving the current fresh
cancelling-fence transfer. AGENT-012's nineteen-row matrix has fifteen missing
items and three unresolved proofs. CTRL-007 lacks delivered-status target
reconciliation and configured NAT64 policy/proof.

The existing HYG-003 draft PR is #157. Its static audit found a date-dependent
historical test, permissive observation exemption and incomplete adjacent-count
coverage. Continuation must preserve subsequent main receipts and changes.
GROOVY-001's authored `E_SOURCE_PARSE` fixture does not establish the measured
`E_SOURCE_LEXICAL` input required by the ADR; ownership, provenance and closure
evidence remain open. Separate M2 worktrees are allocated. These audits are
not implementations or earned closures; all ten tickets retain their statuses.

## M3: secret broker and workload isolation

Coordinator `/root/milestone_m3` spawned SECRET-002 agent
`/root/milestone_m3/secret_002`. An initial unverified anonymous sealed
credential transport module is preserved in its isolated worktree. The
production executable, authenticated IPC, provider/release/network/clock
bindings, exact helper handoff and adverse integration tests remain required.
A temporary plaintext credential file or fixture provider cannot stand in
for those requirements. Read-only candidate review also found missing
full-grant scope matching and unresolved descriptor/askpass lifetime checks.

SEC-005's separate agent `/root/milestone_m3/sec_005` completed a 57-row
requirement audit. The baseline native Linux process group and Windows Job
Object provide lifecycle controls without the required hostile-workload
authority separation. Default-deny filesystem access, peer-process and IPC
controls, ambient launchers, mediated endpoints, every resource class, child
environment and crash artifacts remain in scope. Actual deployed paths,
endpoints and policy probes were unavailable, not assumed safe or absent.
Both child FINALs were consumed by M3 before the coordinator returned.
Neither ticket earned closure.

## M4: first-team and UI qualification

Coordinator `/root/milestone_m4` spawned nine separate ticket agents and
reported all nine actual FINALs consumed. Their acceptance matrices and
canonical names are in `/tmp/mcloving-milestones/M4/coordination.json`.

CASE-001 lacks the designated enabled effectful job, case-specific history
transforms and fresh qualification. The existing disabled corpus and v1
denial-only shadow receipts do not satisfy its requirements. CANARY-002's
producer/orchestration path and adverse end-to-end fixture proof are absent.

The UI chain retains decisions for both access and refresh credentials,
unchanged CSP, exact library digest pinning, shared authorization and public
field disclosure, hostile output encoding, view-by-view migration, and
method-level operation coverage. UI-007's audit records 46 method rows but
explicitly leaves full reconciliation unearned. The original browser
baselines stay historical; later views require their own source-bound baseline.
Live delivery needs preregistered cost/correctness/freshness comparison and
degradation proof. Successor accessibility includes focus, announcements and
390-pixel viewport behavior across every view. No M4 ticket earned closure
or resumption of its deferred lane.

## M5: deployable release and measured capacity

Coordinator `/root/milestone_m5` consumed four distinct ticket-agent FINALs.
`/tmp/mcloving-milestones/M5/coordination.json` preserves full acceptance,
source observations and remaining evidence for all four tickets.

The release builder packages four executables. REL-003 still needs the complete
signed helper/broker/driver/verifier topology, fresh affected UI/case/containment
evidence, and the permitted explicit Windows release disposition. DEPLOY-002
needs complete final-topology installation, upgrade, rollback and denial probes,
plus outside-tree mandatory integrity enforcement on ordinary and crash restart.
CASE-002 needs the actual final deployed case recertified after corrections.
PERF-001 needs reproducible final-platform capacity and recovery envelopes;
historical Mario stage/idle measurements remain bounded predecessor evidence.
All required joins and late-correction regeneration remain open. None of the
four tickets earned closure.

## M6: controlled migration lifecycle

Coordinator `/root/milestone_m6` consumed seven distinct ticket-agent FINALs.
`/tmp/mcloving-milestones/M6/coordination.json` verifies all seven original
acceptance records and dependency sets were preserved.

No enabled-job campaign, final signed deployment or production authority
transition was proved. CANARY-001/MIG-008 still need fresh exact-case campaign
evidence. Cutover retains atomic source/target/runtime/input/authority re-read,
quiescence and drift refusal. Rollback must transfer history/state/outcomes and
prove a later Jenkins revision. Re-cutover must repeat the complete protocol
against post-rollback changes. Decommission requires separate owner approval,
rollback-window completion, current sole McLoving authority, verified final
export/legal holds and no Jenkins reader/writer/trigger/credential/compute
authority. MIG-009 must join the complete signed lifecycle and every inventory
disposition without alternative transfer logic. All seven remain deferred;
no authority or closure was earned.

## M7: release readiness decision

Coordinator `/root/milestone_m7` consumed five distinct ticket-agent FINALs.
`/tmp/mcloving-milestones/M7/coordination.json` retains the five original
acceptance/dependency records and ten report paths.

PROOF-001 lacks current joined corpus/package/campaign/transfer ledger evidence.
WAR-001 retains the complete destructive/soak/crash/no-escape campaign and
unconditional Linux requirement; its Windows condition must follow actual
signed-release/containment eligibility. No such campaign ran in this wave.
SEC-004 retains independent adversarial review, all high/critical blockers,
explicit owner residual acceptance and regeneration after corrections.
DR-001 retains backup/PITR, regional/fleet loss, restore fencing, legal holds,
rotation, requalification, soak, RPO/RTO and restored interface truth; the final
deployed drill proof was not available. REL-002 still needs all exact-current
app-bound/protection/review, provenance/platform/migration, capacity/campaign,
rollback/support and owner decision joins. All five remained deferred and
earned no closure. Public publication was not authorized by these audits.

## Remaining execution inputs

All seven milestones retained their full implementation scope and dependency
gates. The first-team qualification campaign needs an owner-designated enabled,
effectful Jenkins job and its test environment; that information was requested
asynchronously. The initial forty-ticket review wave finished while that input
and direct scope approval were unanswered.
No production effect, cutover, rollback or decommissioning authority was granted.

The PAR-005 local publication preview is
`/tmp/mcloving-milestones/PAR-005-pr-body.md`, targeting its already committed
`c8cdf611` timestamp candidate. It states the remaining security, hosted-check
and closure gaps. No branch push or draft PR was created for this candidate.
Untested prototype hashes are recorded separately in
`/tmp/mcloving-milestones/custody/untested-prototype-hashes.json`.

Automatic approval review rejected pushing the PAR-005 branch/creating a draft
PR and twice rejected a bounded SECRET-002 native test. Its stated reason was
that only the earlier planning request was recognized and the implementation
authorization came from untrusted agent context. No rejected command executed.
Direct user approval for implementation, tests and draft PR publication was
requested. At this observation its answer had not arrived; dependent
implementation/testing/publication was held while read-only audits continued.
This records the session gate at that time. A later custodian must inspect
the user's subsequent answer and refreshed execution records before deciding
dispatch; this historical handoff cannot revoke later authorization. The
overall goal was active and incomplete, with no request to pause it.

## Subsequent direct execution authorization

At 2026-10-05T17:10:42.421914+00:00, the user answered the pending implementation/testing/reviewed draft-publication request: “I authorize you to proceed”. This supersedes the earlier read-only execution hold described above. M1 resumed the existing PAR-005 child to complete the credential process-argument fixes and their isolated regressions; M2 prepared CTRL-006 implementation dispatch under the four-agent capacity limit. No ticket closure, hosted candidate success, production authority, or missing qualified job is conferred by this approval. Subsequent execution receipts must record what actually ran.

At 2026-10-05T18:12:16.458600+00:00, PAR-005 fix PR #170 had completed its normal protected squash merge as `178693dbb59b062739e6404c72017ebbf73727e4`, after independent review, eight successful required GitHub Actions app-bound checks and zero unresolved review threads. Local `main` was fast-forwarded to that same commit. The pre-existing `ROADMAP.md` work and owner script chmod edit were restored; both tracked-edit backup stashes and all unrelated untracked archives were preserved. Exact-main Foundation `37353894530` and native Windows `37353894444` were running; PAR-005 therefore remained ACTIVE with no closure earned. CTRL-006 draft #171 retained its passing planner/lint/native-Windows results and a failing unchanged source-acquirer fixture timeout pending run completion/retry. CTRL-005 earned actual PostgreSQL semantic RED (3,000 prior chunk rows read per quota check), then five of six first candidate tests passed; a missing required node field in the migration-backfill test fixture was being corrected. HYG-003 remained under independent parser/mutation review. These observations grant no production authority.

At 2026-10-05T18:41:32.048932+00:00, PAR-005 protected merge `178693dbb59b062739e6404c72017ebbf73727e4` had successful exact-main Foundation `37353894530` attempt 1 (completed 18:32:35Z) and actual native Windows `37353894444` attempt 1. The independently reviewed subsequent closure update was published as draft PR #172; its protected gates and publication remained pending. HYG-003 existing draft #157 was updated to independently reviewed `09e47bdb23a46cf39b589db09c705bf7b22a7900` after 83 board tests, 85 closure tests, 25 mutation controls, eight historical comparisons and current-base workflow/lane checks. CTRL-006 draft #171 was rebased as `dea09f0473cee87a813441ee616b19c56aa9eda6`; fresh source-acquirer/native Windows/Rust/PostgreSQL checks passed and its deployment job was still running. CTRL-005 fresh migration44 candidate passed all eight focused tests; 17 actual tenant append/nested SQL plans contained two complete primary-key point probes, zero prior chunk rows and two hit blocks apiece. The full store suite passed 67 tests, with its two ignored backup canaries separately passed through actual pg_dump/pg_restore. A test-only Clippy style correction was followed by final store/Clippy/controller-preflight validation. Zero ticket closures were yet recorded on protected main.

At 2026-10-05T19:04:44.189365+00:00, CTRL-006 implementation PR #171 had completed normal protected merge `663124621e37dd2a5387cec3aedbfa452f20c2c4`, and local main had been fast-forwarded with the owner edits preserved. Exact-main Windows Agent `37358396922` succeeded, including actual native Windows job `111926589336`; Foundation `37358396885` still had its deployment job running. Subsequent CTRL-006 closure therefore remained unearned. PAR-005 closure draft #172 was reviewed after rebase to that main, as `302ad4750af36ce3490ddb14c10ac41e44d58f48`; HYG-003 draft #157 was reviewed after rebase as `405cad3c23d28854055af82a61e8f3ab785f29b1`. Both fresh candidate Foundation aggregates were still pending. CTRL-005 corrected the schema validator to derive both RLS/policy counts from its declared table inventory; 67 store tests and both actual controller startup/preflight tests passed, including weakened accounting-table FORCE/policy refusals. However, the final restored cost test on a grown fixture failed: an own-key probe filtered 3,000 prior chunks. Three of four targeted mutation controls earned their intended diagnostic; the old-MAX control failed at that earlier lookup and earned no specific position-control claim. All mutated sources were restored byte-exactly. A later rollback-only SQL comparison no longer reproduced the original bad plan, so no query candidate was adopted from that comparison. The earlier fresh 17-plan result remains bounded to its measured fixture; CTRL-005 cost acceptance is withheld pending a reproducible grown-statistics regression and correction. Zero new ticket closures were recorded on protected main at this observation.

At 2026-10-05T19:22:09.804839+00:00, PAR-005 subsequent closure PR #172 had completed normal protected merge `4bdcbcf78cd040390a6f1afb689f8535fb415b60` after independent exact-delta review, all eight required app-bound checks and zero unresolved threads. Local main was fast-forwarded with both tracked owner edits preserved; PAR-005 was DONE on the published board. Its next-head Foundation `37361766638` remained running and Windows Agent `37361766689` had succeeded; new successor implementation therefore still awaited the complete gate. CTRL-006 actual implementation post-merge Foundation `37358396885` and native Windows `37358396922`, including native job `111926589336`, succeeded on attempt 1. Its independently reviewed standalone closure update was published and attached as draft #173 at `dde9bb50633db7ae38bd2bcb8c488a11aad79ce5`; fresh required gates remained pending. HYG-003 draft #157 was rebased as `b5e4bdb2aeb940c6d57219869e3e41fec05d6956` onto the PAR closure, preserving every reviewed topic added/removed line; 83 board tests, 85 closure tests and 25 mutations passed on that composition.

At the same observation, the controlled two-tenant stale-statistics test passed with unmodified CTRL-005 production source; it did not reproduce or explain the retained grown-fixture failure. Root and independent M2 review re-read the original acceptance, which expressly allows each append its own conflict check. The measured slow scans belonged to those exact full-key duplicate checks, rather than quota or position allocation. The original counter/quota/allocation acceptance remains required; an unqualified constant-cost whole-append claim is withdrawn, and the remaining physical conflict-check cost must be stated as a residual. A speculative covering-primary-key rebuild was being removed to reduce migration/index risk. Removing FOR UPDATE from the modern duplicate lookup was retained for a separate correctness reason: with the new legacy mutation triggers, restoring it can create row-lock/advisory-lock inversion. A genuine concurrent same-key test and an exact FOR UPDATE mutant were being prepared; neither outcome was yet earned. Earlier failures and scope-limited successful traces remain retained. M1 and M3 readiness plans preserved complete AGENT-013 and SECRET-002 acceptance and coordinated the source seams; no new child implementation started before the next-main gate. Production inputs/authority were still unavailable.

At 2026-10-05T20:02:25.175837+00:00, all seven independently reviewed GitHub milestone definitions were published and fresh-read verified, with exactly-once coverage of the original 40 board IDs and no fabricated GitHub issues or due dates. The publication record is `/tmp/mcloving-milestones/github-milestones-publication.json`; their descriptions preserve the original acceptance/dependency authority. GROOVY-001 remains NO-evaluation; its assigned malformed-quoting negative fixture is not a real-team resumption gate.

At the same observation, CTRL-005 full local acceptance had been independently reviewed and published as implementation draft #174 at `050ebec1434b9bf5d7f946e0c356b00ccce3f686`. Its frozen executable/schema/test bytes passed nine focused tests, 68 full-store tests (two ignored backup canaries separately passed through actual pg_dump/pg_restore), store/controller all-targets Clippy and two actual controller startup/preflight tests. Five baseline-green mutation controls earned their specific red diagnostics, including the exact restored-FOR-UPDATE PostgreSQL 40P01 lock cycle; bytes were restored and all nine focused tests passed again. The qualified classifier excepts only canonical full-key own conflict checks, as original acceptance requires. Actual stale-statistics own conflict scans still filtered 3,000 rows; universal constant-cost append is explicitly not claimed. The private owned PostgreSQL fixture and anonymous volumes were removed after retaining logs, with deployment volumes untouched. Native/mutation/backup/cleanup evidence remains under `/tmp/mcloving-milestones/M2/CTRL-005/`.

At the same observation, GitHub reported an Actions incident. Foundation run `37361766638` on PAR closure `4bdcbcf78cd040390a6f1afb689f8535fb415b60` completed as failure: every non-skipped test job succeeded, but the final Foundation aggregate was cancelled. This was not accepted as a successful main gate. HYG-003 candidate `b5e4bdb2aeb940c6d57219869e3e41fec05d6956` separately passed all eight required app-bound checks with zero unresolved threads and completed normal protected merge #157 as `7379d8a416435f871b265d59f2d1b09b82dead4a`. Local main was fast-forwarded, preserving tracked owner edits byte-exactly and all historical untracked archives. New implementation dispatch awaits actual exact-merge Foundation and native Windows receipts. HYG-003 closure remains unearned. CTRL-006 closure #173 and CTRL-005 implementation #174 were rebased onto that merge; threat-document conflict resolution preserved both protected HYG assessment and ticket-specific evidence. Fresh independent composition review and fresh exact-head checks remain required before publication/merge. One original ticket, PAR-005, was DONE on protected main; 39 original tickets remained unclosed.

At 2026-10-05T20:05:52.551813+00:00, fresh independent composition reviews had approved CTRL-006 closure candidate `77e0fffb0f3637a8dfb66ad4e3ad528eec708b51` and CTRL-005 implementation candidate `588417516e8e9f2de6bee6ae763206220719124e`, both based on the protected HYG merge `7379d8a416435f871b265d59f2d1b09b82dead4a`. Root published and fresh-read verified both existing draft PRs #173 and #174 under exact prior-head push leases. All reviewed runtime bytes remained identical; fresh exact-head required checks still awaited completion. This paragraph supplies the completed review and publication observations omitted from the preceding summary. Root local board verification also refused four existing untracked owner archive assertions; those archive files were preserved byte-exactly and classification under HYG-003’s sealed-evidence exclusion was assigned for read-only review. This local failure does not contradict the recorded clean candidate-tree gate successes or discharge the next-main Foundation/native Windows gate.
