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
and live verification. JCOMP-002B is now the sole ACTIVE dispatch. The original dated
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
now solely `JCOMP-002B` (`ACTIVE`). The serialized dispatch is `JCOMP-001` ->
`JCOMP-002` -> `JCOMP-002A` -> `JCOMP-002B` -> `JCOMP-003`, with one standalone
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
`JCOMP-002A` then owns real sequential step execution with distinct step/stage
results and downstream skipping; current product admission rejects more than
one step per stage. `JCOMP-002B` owns build-workspace lifecycle, continuity, and namespace
non-collision in contained fixtures; current workspaces are scoped to each
attempt and removed after finalization. Hostile same-UID sibling-workspace
read/write isolation remains `SEC-005`, not an M1 acceptance claim.
Keep runtime admission guards until runnable support exists. Removing a guard,
concatenating commands into one shell, or sharing an attempt path cannot satisfy
these runtime tickets. `JCOMP-003` waits for both and earns the final paired
execution evidence against their corrected exact runtime.


JCOMP-002A closed after PR #130 merged as
`c2aaa0da6aaf5f5a5800bca252fd0514584f56fa`, tree
`77bc88fa006123ab72ae497334c1733dc0ac749b`, matching final head `d7be0f7`.
All eight final-head protected checks and independent review passed, followed
by exact-main Foundation `34351767851` and actual native Windows
`34351767843`. The [closure review](../evidence/JCOMP-002A_SECURITY_REVIEW.md)
records the pure planner, immutable sequential admission, coherent projection,
and contained controller/agent evidence, including reconciliation after lease
loss following StartWork. JCOMP-002B is selected for implementation; no workspace
continuity or paired Jenkins execution claim is earned by JCOMP-002A.

`CI-004` is closed on observed protected-merge and post-merge evidence: PR #125
merged as `1d81127`, whose Foundation run `34293282546` and native Windows run
`34293282632` both succeeded. Its [security review](../evidence/CI-004_SECURITY_REVIEW.md)
retains the corrected implementation and closure evidence. These receipts verify
that exact merged head; they do not discharge the standing successor-head gate
below for the current or any future head.

The subsequent production-readiness track is `EXEC-005` -> `SECRET-002` ->
`SEC-005` -> `CASE-001`; `EXEC-005` additionally waits for `JCOMP-003`.
`GROOVY-001` and `HYG-003` retain their pending parallel lanes; `AGENT-007`
closed its lease-survival lane. M1 keeps the current compile-only
architecture; an interpreter port requires a separate decision and ticket.
Shared contract or documentation boundaries serialize.

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
- `JCOMP-002B` is the selected dispatch ticket and is `ACTIVE`. Before
  continuing on a successor head, evaluate the standing successor-head verification gate against
  the current protected-main head -- see "Safe next action". That gate is not
  dischargeable by this file.
- `GROOVY-001` and `HYG-003` are also `PENDING`. Each is a standalone
  `PARALLEL` lane and neither occupies the dispatch slot. Read the board
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

The September 8 priority replaces the thaw's `EXEC-005` selection with
the Jenkins compatibility chain. `JCOMP-001`, `JCOMP-002` and `JCOMP-002A` are now verified complete and
`JCOMP-002B` is selected; its dependency is earned sequential-runtime closure.
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
