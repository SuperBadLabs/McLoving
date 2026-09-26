# HYG-003 candidate review: claims that expire

Status: `ACTIVE`. This is implementation evidence for review, not a closure or
protected-main receipt. The ticket stays active until exact-head review,
protected merge, and post-merge Foundation and Windows verification.

## Historical population and correction

| Failure | Historical source | Correction or retained observation |
|---|---|---|
| The live handoff said the September freeze governed through September 30 after the owner lifted it on September 6. | `d534a1b5:docs/handoffs/CURRENT.md`, opening paragraph | `a5ffdb52:docs/handoffs/CURRENT.md` records the lift; `docs/handoffs/2026-09-06-freeze-thaw.md` dates the decision. The new governance check refuses the original wording against that thaw record. |
| The first thaw draft called EXEC-005 "now startable" using a preceding head's receipt. | `1b88a885:docs/handoffs/CURRENT.md`, Read this first | `f843bc8c` restored an explicit successor-head condition. The new handoff check refuses the draft's live readiness assertion. |
| The second draft said the successor-head condition "is now discharged" and tied it to `a5ffdb5`, the parent its own merge would replace. | `f039d414:docs/handoffs/CURRENT.md`, Read this first and Safe next action | `2155a4ea` made the gate standing. The new check refuses both statements and permits the merged historical observation that `a5ffdb5` produced named successful runs. |
| The closure verifier's comment repeated the table counts beside `EXPECTED_TABLES`; its count went stale at the next ratchet raise. | `d534a1b5:scripts/verify-ticket-closure-receipts.py`, comment before `TICKET_TABLE_HEADER` | `187bf0c6` removed the duplicate table counts. The new check refuses the original comment; the remaining format count is removed from the live comment as well. |
| A Release Builder ledger said three further runs while naming two IDs and two more runs, and included PR-triggered runs whose number rose with each push. | `baf3b5c1:docs/handoffs/2026-09-06-freeze-thaw.md`, Step 4 | `51cef3ee` defined a closed audit window and enumerated its three runs. This is an external, changing denominator; the repository-only verifier cannot prove the GitHub set. The convention in `CONTRIBUTING.md` requires a closed window and a live query. |
| The freeze published evidence at `c17bbaf` while naming its own PR the final planned September change; its merge `d534a1b` had no Foundation or Windows run. | `d534a1b5:docs/handoffs/2026-09-01-september-freeze.md`, Executive state and closure receipt; `2026-09-06-freeze-thaw.md`, Step 4 | The thaw recorded the missing post-publication verification. A local text gate cannot know whether a future push will run. The convention requires a new exact-main observation after publication. |

## Checks and limits

`scripts/stale_claims.py` is used by the board and closure verifiers. It scans
the board and every tracked Markdown handoff for explicit live-head and
head-gate assertions. Dated audit findings and statements that name their
observed head and run IDs remain valid. It checks the live `CURRENT.md` against
the recorded early lift, and rejects expired governance windows. It also
refuses table/format counts in the comment next to the closure verifier's
`EXPECTED_TABLES` constant. The tests use the pre-fix text above, not invented
sentences, and the current tree is the false-alarm control.

The text checks are bounded patterns. They do not prove the truth of arbitrary
English, discover an unrecorded owner decision, count GitHub runs, or certify
future CI. Residual risk is a differently phrased stale claim and any external
state change after verification. The live custody checks and dated receipt
convention remain required. No product, deployment, migration, release, or
production authority changes here.

## Candidate verification

On the candidate worktree:

- `python3 scripts/test-execution-board.py`: 63 passed. The historical
  discharge drafts and pre-thaw governance claim are red; the current board
  and all tracked handoffs are green, including the dated thaw audit.
- `python3 scripts/verify-execution-board.py`: `execution-board-ok tickets=147
  remaining=20 current_slots=1 batch=0 parallel=11 serial=9`.
- `python3 scripts/test-ticket-closure-receipts.py`: 80 passed.
- `python3 scripts/verify-ticket-closure-receipts.py`: `closure-receipts-ok
  done=104 receipted=49 reviewed=48 receipt_exempt=50
  threat_model_exempt=24 debt=37`.
- `python3 scripts/test-verify-rust-test-execution.py`: 9 passed;
  `python3 scripts/verify-ui-browser-gate.py`: 18 assertions passed;
  `bash -n scripts/validate-foundation.sh` and `git diff --check`: passed.

Five isolated mutations replaced `HEAD_ASSERTIONS`, `LIVE_GATE`, `STARTABLE`,
`GOVERNED_THROUGH`, and `COMMENT_COUNT` with no-match rules. Each made its named
negative test fail with one assertion failure and no test error, respectively:
`test_pinned_protected_main_fails`, `test_second_discharge_draft_fails`,
`test_first_discharge_draft_fails`,
`test_pre_thaw_governance_claim_fails_after_recorded_lift`, and
`test_pre_hyg003_comment_is_refused`. The live-tree test is a green control;
the dated thaw audit is a green control for a real observed past head.

`./scripts/validate-foundation.sh` was attempted on 2026-09-24. The default
sandbox could not create Podman's runtime directory. With host Podman access,
the pinned Rust image passed formatting, metadata, and strict workspace
Clippy, then ran workspace tests until the source-acquirer suite: 28 tests
there failed because `aa-exec` was absent inside the image (many reported
`InvalidConfig`), so the script exited 101. The workflow runs that suite
separately under a host AppArmor profile; this attempt is not a full
Foundation pass. The unrelated source-acquirer failure is retained here, not
counted as HYG-003 verification.

Pending: independent exact-head review, a protected pull request and merge,
and post-merge Foundation and Windows run IDs. The threat-model no-change
assessment remains a candidate until independently reviewed.
