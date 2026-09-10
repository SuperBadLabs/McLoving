# Current custodian handoff

The current dated handoff is the
[September 9 Master Chief bundle](2026-09-09-master-chief/README.md), including a
[next-chief briefing](2026-09-09-master-chief/NEXT_CHIEF.md), verified checkpoint,
durable compiler supplement and reviewed runtime design. The earlier
[September 6 thaw](2026-09-06-freeze-thaw.md) and
[September 1 freeze](2026-09-01-september-freeze.md) remain historical records.

On September 9, PR #128 merged as `904fd1f`; exact-main Foundation
`34317917356` and actual native Windows `34317917395` succeeded. JCOMP-002
closed in the subsequent JCOMP-002A bookkeeping commit after receipt review
and live verification. EXEC-005 is the next selected PENDING dispatch after JCOMP-003 earned closure; JCOMP-002B and AGENT-007 earned closure as recorded below. The original dated
handoff remains an immutable historical observation. Fresh custody on `09b6c53`
observed successful Foundation `34342349617` and native Windows `34342349592`;
those observations verify only that head.

**The September code freeze is LIFTED.** The owner lifted it on 2026-09-06,
ahead of its 2026-09-30 expiry, and the six-step thaw procedure was executed in
full. The
[`September 2026 code-freeze contract`](SEPTEMBER_2026_CODE_FREEZE.md) is now
history rather than a live prohibition; its receipts are in the thaw handoff.
Ordinary board custody applies.

The lift is a repository-custody decision only. It grants no product,
deployment, credential, connector, canary, cutover, rollback, or production
authority, closes no ticket, and does not relax
[`docs/related-work/FOGELL.md`](../related-work/FOGELL.md).

## September 8 priority: Jenkins compatibility M1

The owner selected broader pipeline support with Linux sequential Declarative
pipelines and literal shell steps as the first milestone. The selected slot is
now `EXEC-005` (`PENDING`) after the Jenkins milestone earned closure; JCOMP-002C is DONE on its corrected protected merge and exact-main receipts. The serialized dispatch is `JCOMP-001` ->
`JCOMP-002` -> `JCOMP-002A` -> `JCOMP-002B` -> `JCOMP-002C` -> `JCOMP-003`, with one standalone
PR per ticket. The [board](../EXECUTION_BOARD.md) holds their complete acceptance
criteria; no successor starts before its predecessor is protected-main merged
and verified. Once started, a ticket remains `ACTIVE` until its required review,
closure evidence, protected merge, and post-merge verification are complete.
A passing implementation check or draft artifact alone cannot close it.

JCOMP-001 closed after PR #127 merged as
`533dbff671b5a2d58e4d92339708375601d5b7d2` and exact-main Foundation
`34306662841` and native Windows `34306662842` succeeded. The contract
preregisters expectations only; it did not itself earn generalized compilation
or paired execution. That earlier closure update started the separate JCOMP-002 PR.
The [syntax contract](../architecture/JENKINS_SEQUENTIAL_DECLARATIVE_V1.md)
and fixture expectations now have a shared Foundation authoring gate. The
[review record](../evidence/JCOMP-001_SECURITY_REVIEW.md) records the completed
contract merge and exact post-merge verification. JCOMP-002 retains its own
review, merge and post-merge gates; the contract receipt claims no broader
compiler admission or paired execution evidence.
The legacy exact-source compiler admission is not general syntax support;
M1 must earn a new versioned differential claim through contained submitted
jobs, with authored fixtures and original-corpus coverage reported separately.

`JCOMP-002` generalizes compile-only translation and independent admission. Its explicit
protocol-v2 implementation is merged, post-main verified and closed, with a separate disabled logical
document artifact and immutable worker/admission bindings. The
[compiler review](../evidence/JCOMP-002_SECURITY_REVIEW.md) records focused and
contained compilation checks; these do not establish runnable support.
`JCOMP-002A` earned real sequential step execution with distinct step/stage
results and downstream skipping. `JCOMP-002B` earned bounded build-workspace
continuity through checkpoint transfer between fresh attempt workspaces and
controller-assigned namespace non-collision in contained fixtures. Hostile
same-UID sibling-workspace read/write isolation remains `SEC-005`.
JCOMP-003 must retain the bounded admission contract and earns its separate
paired execution evidence only against the reviewed, frozen corrected runtime.


JCOMP-002A closed after PR #130 merged as
`c2aaa0da6aaf5f5a5800bca252fd0514584f56fa`, tree
`77bc88fa006123ab72ae497334c1733dc0ac749b`, matching final head `d7be0f7`.
All eight final-head protected checks and independent review passed, followed
by exact-main Foundation `34351767851` and actual native Windows
`34351767843`. The [closure review](../evidence/JCOMP-002A_SECURITY_REVIEW.md)
records the pure planner, immutable sequential admission, coherent projection,
and contained controller/agent evidence, including reconciliation after lease
loss following StartWork. JCOMP-002B implementation is closed on its exact-main
receipts; paired Jenkins execution remains the separate JCOMP-003 claim.

`CI-004` is closed on observed protected-merge and post-merge evidence: PR #125
merged as `1d81127`, whose Foundation run `34293282546` and native Windows run
`34293282632` both succeeded. Its [security review](../evidence/CI-004_SECURITY_REVIEW.md)
retains the corrected implementation and closure evidence. These receipts verify
that exact merged head; they do not discharge the standing successor-head gate
below for the current or any future head.

The subsequent production-readiness track is `EXEC-005` -> `SECRET-002` ->
`SEC-005` -> `CASE-001`; `EXEC-005` additionally waits for `JCOMP-003`.
`GROOVY-001` and `HYG-003` retain their pending parallel lanes; `AGENT-007`
is DONE in its lease-survival lane on the corrected runtime and exact-main evidence
recorded in its security review, and the new `UI-002` through
`UI-009` web-interface lane is serial beside them. `REL-003` waits for `UI-009`,
so the complete UI chain and final browser proof precede packaging and subsequent
deployment/canary receipts. Before packaging, identify earlier case, containment
or ceremony receipts invalidated by those UI changes and regenerate the affected
evidence; completed dependency statuses alone do not establish fresh evidence.
`CASE-002`/`DEPLOY-002` retain their final deployed-runtime checks. M1 keeps the current
compile-only architecture; an interpreter port requires a separate decision and
ticket. Shared contract or documentation boundaries serialize.

Use independent subagents for compiler/admission inspection and differential
fixture design. Verify HeMan's Qwen model and connectivity before assigning
cited corpus analysis or fixture drafts. Agent review is required, and model
output cannot serve as Jenkins oracle evidence. Qwen is optional support.

## Read this first

- September 1 authoring baseline: protected `main`
  `c17bbafafe4f983b6e936cd2f57245edabfb1ffd`, tree
  `dddf3c31edd2aa6f41d1614e119367beaa8dca5b`, GitHub-verified with reason
  `valid`.
- At the September 1 authoring time there were no open pull requests, and the
  freeze publication was the final planned September mutation. The September 6
  thaw superseded that plan; inspect GitHub for current open pull requests.
- Board and closure totals are **not restated here**. Run
  `scripts/verify-execution-board.py` and
  `scripts/verify-ticket-closure-receipts.py`; they are the live source, and a
  count copied into this file is stale on the next ticket. As an observation
  rather than a current-state claim: on 2026-09-08 the reorganized local board
  reported 112 tickets with 26 remaining, and 86 done with the admitted, ratcheted 37-item debt.
- `EXEC-005` is the selected dispatch ticket and remains `PENDING`; `JCOMP-002C` has earned closure. Before
  continuing on a successor head, evaluate the standing successor-head verification gate against
  the current protected-main head -- see "Safe next action". That gate is not
  dischargeable by this file.
- `GROOVY-001` and `HYG-003` are also `PENDING`. Each is a standalone
  `PARALLEL` lane and neither occupies the dispatch slot. `UI-002` through
  `UI-009` are `PENDING` too, as one serial web-interface lane; `UI-002`
  earns the unsupported browser-journey claim with only necessary minimal
  served-client repairs, retaining initial failures separately from the accepted
  repaired baseline; both remain unchanged when `UI-007` adds a separate
  source-bound baseline for its new views. `UI-002` adds no redesign, route,
  CSP or authorization change.
  `UI-003` decides a threat boundary rather than implementing one, and the
  six after it are implementation behind that decision. Read the board
  rather than this list for the full set; that is the point of the bullet
  above.
- Protected-main Foundation, native Windows, and Release Builder runs are green
  at the authoring baseline. All eight required contexts remain bound to GitHub
  Actions app id `15368`.
- McLoving is not release-ready and has no production authority.
- Two open Dependabot records represent one moderate `jsonwebtoken` advisory.
  They are deferred for reassessment, not resolved or accepted.

## During September (superseded by the 2026-09-06 thaw)

While the freeze was in force this section read: do not start a board ticket,
resume an old branch, open an implementation pull request, change dependencies
or workflows, publish a release, or grant operational authority.

Those restrictions ended with the lift. Two of them were never freeze-specific
and still hold: do not resume a pre-freeze remote branch, and do not grant
operational authority. Keep CI, branch protection, alerts, and monitoring
enabled. Every normal protected-merge obligation still applies -- exact-head
review, zero unresolved threads, all eight protected contexts, and post-merge
Foundation and Windows verification.

## Safe next action

The thaw procedure is complete; its receipts are in
[`2026-09-06-freeze-thaw.md`](2026-09-06-freeze-thaw.md). Protection was
re-read, September drift and alerts were audited, the board and closure
verifiers reproduce the baseline numbers, and the Foundation gate is green on
HeMan when it is run the way CI runs it: the script's `set -e` abort inside the
first container must be prevented from masking the remainder, and the
source-acquirer package must run under `aa-exec -p mcloving-source-acquirer`.

The September 8 priority selected the Jenkins compatibility chain ahead of
`EXEC-005`. That chain has now earned its bounded milestone closure through
`JCOMP-003`, including the JCOMP-002C diagnostic correction, reviewed execution
freeze and fresh paired and original-corpus evidence. `EXEC-005` is again the
selected PENDING ticket.
Before starting, refresh protected main, open PRs, alerts and protection,
run the board/closure and full Foundation gates, and observe the condition
below against the head that is current when you read this. Use a fresh
`codex/` branch; do not resume a pre-freeze implementation branch.

**The condition is a standing gate, not a box this file can tick.** It is
evaluated against whatever protected-main head is current, so no document can
discharge it in advance: the moment a change like this one merges, the head it
named becomes the parent and its receipts verify the parent only. A previous
revision of this section declared the gate discharged at `a5ffdb5` and was
already wrong about its own successor before it merged.

Before starting work on the current protected-main head, confirm by observation
that it produced a successful `Foundation` run and a successful `Windows Agent`
run. Those are the workflow names the query below prints; the branch-protection
contexts they report are named `Foundation` and `Windows`. Do not infer either
from the merge having happened. Query the head directly:

```text
gh api "repos/SuperBadLabs/McLoving/actions/runs?head_sha=<successor head>" \
  -q '.workflow_runs[] | "\(.name) \(.status) \(.conclusion)"'
```

If either run is absent, or either concludes anything other than `success`, that
head is in the same unverified state this thaw was published to correct. Work
does not start on it until both are observed green; re-run or repair the
verification first and record the outcome.

**One observation is recorded, as evidence about the mechanism rather than as a
discharge.** The thaw merged as `a5ffdb5`, and that head produced push-triggered
`Foundation` `34060521970`, `Windows Agent` `34060521979`, and `Release Builder`
`34061427450`, all `success`. Two things follow, neither of which is permission
to skip the check above. The push trigger works normally, so `d534a1b` having
produced no runs at all is an anomaly rather than a systemic defect -- worth a
ticket if it recurs, and not one yet. And `Release Builder` concluded `success`
there rather than the `skipped` seen on pull-request branches, which is the gate
reading `workflow_run.conclusion == 'success' && workflow_run.head_branch ==
'main'` behaving as documented.

Two items the freeze deferred are now due and are not closed by the thaw: the
two open `jsonwebtoken` Dependabot records (one moderate advisory,
`GHSA-h395-gr6q-cpjc`), and the ratcheted 37-item historical closure debt.

## September 10 custody and earned closures

PR #131 protected merge `49c7e3346529babc131b318a5cf4091e4194db8d` earned JCOMP-002B closure after exact-main Foundation `34411625710` attempt 2 and actual native Windows `34411625740` succeeded. AGENT-007 closes on corrected runtime `44f0498fbdf3a59434176e9d09a52e1260336260`, reviewed head `6cdf3fe038c74ac22dd304a77650c37b79d985a5`, exact-main Foundation `34440051467` and actual native Windows `34440051470`. The corresponding security reviews retain the prior failed runs and exact-source qualifications. JCOMP-003 tooling must be reconciled to this runtime and independently reviewed before an execution freeze; its 11 positive paired executions, 12 compile-negative inputs and separate 228 original-source classifications remain unearned claims until their actual campaigns pass.

## September 10 compiler correction prerequisite

The contained JCOMP-003 original-corpus capture at source `2eadf80ec99f362d901a01a074b79e669a7fe3a9` retained six cases as `unverified` under `E_SOURCE_CLASSIFICATION`: 018, 019, 023, 065, 160 and 162. They are not rejection or unsupported evidence. `JCOMP-002C` owns the bounded independent negative-diagnostic correction described on the board. No admitted grammar or runtime expansion is authorized by this ticket. Preserve the original 228 identities and separate authored-fixture evidence.

Exact candidate `2326a63b6c52a5354a82d58aee9879db046613c9` now has independent source/build/evidence review: 34 Rust tests, strict Clippy, 13 Clojure tests with 257 assertions, two meaningful failing mutations and independent replay of all 46 preregistered fixture responses. The separate original corpus has 1 admitted, 216 unsupported, 11 rejected and zero unverified across 226 exact originals and two previously retained redacted representations. Only the six prior disagreements changed classification; these are compile-only observations. The [security review and bounded retained evidence](../evidence/JCOMP-002C_SECURITY_REVIEW.md) qualify the exact tested source and omitted raw inventory. The corrected final c94 source subsequently earned protected merge and exact-main verification as recorded below. At that correction-stage observation, JCOMP-003 remained ACTIVE and owed a refreshed compiler/runtime freeze and regenerated captures; the later earned result is recorded below. Earlier successful components and failed cleanup/startup observations retain their original source identities. The compiler-only corpus result does not establish a sealed paired execution claim.

PR #135 review subsequently found a malformed first-dollar interpolation prefix that source `2326a63` classified inconsistently before a later lexical exclusion. The bounded follow-up mirrors the already trusted Rust prefix predicates in Clojure before the dynamic flag changes. The sealed `jcomp-002c-v1` receipts remain historical baseline evidence, not verification of the new compiler source. Final c94 validation independently replayed all 17 reduced cases, 46 preregistered responses and 228 originals with 1 admitted / 216 unsupported / 11 rejected / 0 unverified. See the updated JCOMP-002C security review for source-qualified receipts.

JCOMP-002C earned closure on signed PR #135 merge `01137b54b8fbefdc0deb0214a5d4d8979a773575`, tree `b5f50381ad6af2183bb6d6ef56c8daee2e371723`, with exact-main Foundation `34450761533` and native Windows `34450761576`, both successful attempt 1. The [retained post-merge audit](../evidence/JCOMP-002C_CLOSURE.json) has SHA-256 `d10d2965828e40d17673a711cf181a6033aa0a61c2ccc20c920ff9a6605487e6`. JCOMP-003 subsequently earned its separately reviewed fresh freeze and campaigns as recorded below.

## September 10 fresh paired observations before protected publication

Execution freeze `f263ad4ae2871e8bb06fe3b5bceef534179a0a88` produced independently reviewed fresh Jenkins/product captures: 11 positive cases, 19 shell invocations per runtime, 12 compile denials scheduling no product work, verified cleanup and zero unexplained differences. The separate 228-source corpus has 1 admitted, 216 unsupported, 11 rejected and zero unverified across 226 exact originals and two retained redacted representations. The [JCOMP-003 security review](../evidence/JCOMP-003_SECURITY_REVIEW.md) binds source, inventories, report and retention limitations. JCOMP-003 subsequently earned protected publication merge and exact-main gates as recorded below; no production authority is granted.

## Earned JCOMP-003 closure and next dispatch

PR #136 merge `ca79f7b4c5573c17f9bd7607f47c65f13f683840` passed exact-main Foundation `34456846575` and actual native Windows `34456846592`; the [byte-preserved audit](../evidence/JCOMP-003_CLOSURE.json) is SHA-256 `e68f7efb4f75262fbf0b6e6bd41d87aa0b479ae5835e0ebd0a841abe462ea6a9`. JCOMP-003 is DONE for its exact contained runtime and fixture population. EXEC-005 is the next selected PENDING ticket in the existing EXEC-005 -> SECRET-002 -> SEC-005 -> CASE-001 sequence. This handoff does not claim implementation has begun or grant production authority.
