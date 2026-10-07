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

The measured population is the nine documentation-review rounds recorded in
HYG-003's acceptance for [PR #120](https://github.com/SuperBadLabs/McLoving/pull/120)
and [PR #121](https://github.com/SuperBadLabs/McLoving/pull/121). Their findings
share the stale-claim shape above; the acceptance records no code defects in
those rounds. This implementation does not claim a new audit of closed tickets.

## Checks and limits

`scripts/stale_claims.py` checks `docs/EXECUTION_BOARD.md` and Markdown handoffs.
It refuses explicit present-tense named-head/current/verified assertions,
head-dependent discharged-gate declarations, and CURRENT.md's live startability
claim. Table-cell gates are checked without combining unrelated adjacent cells.
Valid paired Markdown asterisk/underscore emphasis is normalized before the
checks, without removing underscores inside identifiers. The general timed-head
observation form requires a valid ISO date or UTC
timestamp and the past-tense predicate `was observed/audited/found` with its
condition. The retained thaw's dated, negative workflow audit is recognized
narrowly; its filename date must be valid. Both exceptions cover only the head
mention's character span. An added live assertion in the same sentence or
paragraph is still refused. Invalid dates/times cannot purchase an exception.
Time syntax validation does not establish an observation's truth.

Present-tense governance windows in the board and handoffs are checked for
expiry, invalid end dates, and the recorded September early lift. Every matched
window in a paragraph is checked, so a future window cannot hide a later
expired assertion. The September early-lift marker must occur in the matched
governance declaration; an unrelated historical reference elsewhere in the
paragraph cannot invalidate a future window. Historical past-tense records
remain readable. The printed end date is inclusive; owner
extensions/lifts that have no repository record require a live decision check.
The verifier entry point passes an injectable observation date through the
production calls. The historical early-lift test fixes September 24 and forces
an opposing October 5 ambient date, proving that this clock is propagated rather
than accidentally using the date on which a test runs.

The closure verifier rejects repeated counts in comments before, between,
inside, inline with, and after the header/count declarations. AST statement
bounds and comment tokens distinguish prose from actual numeric constants and
strings. A missing declaration or unparsable source fails closed. The actual
pre-fix count comment is red, while current numeric constants and dated ratchet
history are green.

These are mechanically checked text forms, rather than a claim to understand
all English. CONTRIBUTING requires dated observations and names the convention
cases: external GitHub run-set completeness, prose ledger arithmetic with no
canonical machine-readable schema, evolving PR-triggered denominators,
unrecorded owner decisions, and post-publication successor workflows. A local
verifier does not query those states, validate arbitrary phrasing, certify
future CI, or independently establish a receipt's truth. Those limits do not
waive the recognized assertion checks. No product, deployment, migration,
release, or production authority changes here.

## Historical controls and provenance

`scripts/fixtures/stale-claims.json` retains full commit/path identities and
SHA-256 values. Seven entries are byte-exact complete historical files. The
`pre_count` entry is an exact historical comment-and-declarations excerpt, whose
hash identifies that excerpt. It is byte-contained in the cited original source;
it is not represented as the complete verifier. The first and second discharge
drafts and pre-thaw handoff are read directly from these historical fixtures by
the red tests. Real merged CURRENT.md and thaw receipts from `2155a4ea` pass
through the production board entry point as green controls. The local history
replay compares the seven complete texts for equality and the excerpt for exact
containment against `git show <full-commit>:<path>`.

## Original implementation verification (historical)

Current source and exact command outputs are retained in
[`hyg-003/validation.json`](hyg-003/validation.json); source SHA-256 values bind
the tested Python checks and their workflow/local-script hooks. The isolated
candidate retains recent main's board and closure ratchets rather than the old
September 24 topic-tree counts. This is candidate-source evidence, not a claim
that current protected main or a future merge has passed.

- `python3 -B scripts/test-execution-board.py`: 83 tests passed.
- `python3 -B scripts/test-ticket-closure-receipts.py`: 85 tests passed.
- `python3 -B scripts/verify-execution-board.py`: 147 tickets, 17 remaining,
  one current slot; no stale-claim false alarms in the current candidate tree.
- `python3 -B scripts/verify-ticket-closure-receipts.py`: 107 done, 52 receipted,
  51 reviewed, and the unchanged 37-item admitted historical debt.
- `python3 -I scripts/test-workflow-aggregate.py`: 13 tests passed;
  `python3 -I scripts/test-windows-agent-impact.py`: 15 tests passed.
- `bash -n scripts/validate-foundation.sh`: passed.

`python3 -B scripts/test-stale-claims-mutations.py --verify-history --output
 docs/evidence/hyg-003/mutations.json` passes 25 isolated mutation controls and
all eight historical-source comparisons. Each control first passes unchanged,
then fails with one assertion failure and no test error after its production
check is removed or weakened. The raw outputs, named controls, and source hashes
are retained in [`hyg-003/mutations.json`](hyg-003/mutations.json). Mutations cover
head/gate/startable recognition and Markdown emphasis; governance wording,
every window, matched governance identity, expiry, early lift and
invalid dates; observation time validation and narrow exemptions; count,
adjacency and parser fail-closed checks; symlink refusal; root clock propagation;
and both verifier entry points plus the board/handoff production calls. Removing
the observation exemptions also makes their real-history or timed green
controls red. Re-admitting the old paragraph-wide exemption makes the mixed
observation/assertion control red. Architecture records and local Foundation
validation and the required dogfood architecture mirror now invoke the
reproducible mutation replay without requiring old Git objects; history
comparison remains an explicit local review option. Independent lane review
found the initially missing mirror command. After adding that exact required
command, `python3 -B scripts/dogfood/verify-lanes.py` passes with six lanes,
65 checked commands, and one pre-existing declared unmirrored command. An
isolated copy also passes, then exits 1 with the specific architecture-lane
missing-command denial when only the new mutation invocation is removed.
`bash -n scripts/dogfood/architecture.sh` passes. Raw green/red results and
hook/gate hashes are retained in [`hyg-003/lane-mirror.json`](hyg-003/lane-mirror.json).
This added hook is required; it receives no exemption. The mirror script itself
was not executed, so this verification runs no native or database workload.

A default-sandbox launch failed before Python ran with a bwrap mount error at
`/newroot/srv/data`. The focused Python/governance checks were then executed
outside that failed sandbox. This is recorded as a launch failure, not a test
failure or a skipped passing result. No Cargo/native/source-transport or
database suite was run for this implementation refresh.

## Historical Foundation attempt

`./scripts/validate-foundation.sh` was attempted on 2026-09-24. The default
sandbox could not create Podman's runtime directory. With host Podman access,
the pinned Rust image passed formatting, metadata, and strict workspace
Clippy, then ran workspace tests until the source-acquirer suite: 28 tests
there failed because `aa-exec` was absent inside the image (many reported
`InvalidConfig`), so the script exited 101. The workflow runs that suite
separately under a host AppArmor profile; this attempt is not a full
Foundation pass. The unrelated source-acquirer failure is retained here, not
counted as HYG-003 verification.

At that original implementation observation, independent review, protected
checks, publication and merge were pending. PR #157 subsequently merged while
HYG-003 remained ACTIVE: four owner-local archival false alarms still required
a follow-up. The archive continuation below supplies candidate evidence for
that follow-up; root owns publication, hosted checks, merge and closure.

## Current-base revalidation observation

On 2026-10-05T18:27:15.917349+00:00, root rebased the complete independently reviewed HYG topic onto protected merge `178693dbb59b062739e6404c72017ebbf73727e4`. All non-overlapping reviewed source/test bytes remained identical. The composition retains the complete protected-main threat text, its jq/ripgrep runner dependency, both dogfood regression commands, and the HYG mutation command. Fresh candidate checks passed: 83 board tests, 85 closure tests, 25 mutation controls, eight Git-history comparisons, 13 workflow tests, both verifiers, shell syntax and diff checking. The lane verifier observed six lanes and 67 commands with the same one pre-existing declared omission. This supplements the earlier 65-command topic observation above; it does not replace it with a claim about a future main head. The validation JSON retains the earlier candidate hashes and outputs separately from this rebase observation. Exact-head hosted checks, protected merge and post-merge verification remained unearned at this observation.


## Archive scope continuation on the 7ff63e54 base

This follow-up preserves the seven acceptance clauses and the historical
population/citations above. Its clean isolated base is
`7ff63e54f70ea5d1110b72037e84fe6011f50d01`; earlier metrics and reports remain
historical observations. Before editing production code, the new real-manifest
integration test reproduced four actual owner-file refusals from the old
checker. [`hyg-003/archive-scope-before.json`](hyg-003/archive-scope-before.json)
retains that RED output and source identity. Two READINESS files said
`recovered-main`, whose suffix is a recovery branch name rather than the live
main subject. The other two START_HERE files retained historical current-head
or standing-gate wording. Owner archive files are preserved byte for byte.

`MAIN_SUBJECT` now requires a complete main/protected-main token rather than a
hyphenated or identifier suffix. Bare main and protected-main assertions remain
refused. A separately reviewed registry pins precisely three original seals:

| Reviewed root below docs/handoffs | Seal | Manifest SHA-256 | Listed Markdown |
|---|---|---|---:|
| `2026-09-10-master-chief-mission/campaign-complete-v4` | `ARTIFACTS.sha256` | `bbba8731110c0adf2dc829bbde0541856ac26ba9417b135399f35df90998f143` | 6 |
| `2026-09-10-next-master-chief-post-mission` | `SHA256SUMS` | `a4940f7721b356a3bc2a4bdbbdfc6da3a58f2b99387c5f6a07d074f4d86fa273` | 42 |
| `2026-09-11-source-prerequisite-verified` | `SHA256SUMS` | `72e758c7ecdd546ca830b734d5b7953a0fdb1fcfeb817fcaf45f7da8abc0bd74` | 59 |

The production eligible set is **107 listed Markdown files**, subject to each
existing file matching its exact sealed digest. Root independently read all
107 owner-local Markdown files and verified the original seals and digests;
that readback is distinct from the focused fixture replay. The registry trusts
these reviewed historical content commitments; it asserts no authorship,
owner endorsement, current authority, or complete recovery of non-Markdown
payloads. There is no whole-directory or archive-name exception. Unlisted,
new, nested, untracked and live prose remains checked; a changed listed file
adds an explicit digest denial and also receives ordinary prose checks.

Descriptor traversal refuses symlink leaves and ancestors. Present registered
units require regular, exact, well-formed seals. Duplicate paths/JSON keys,
escaping or aliased paths, invalid commitments and overlapping roots are
refused. Directory symlinks are diagnosed even when directory enumeration would
not descend into them. Optional units may be absent on clean CI. Missing or
invalid policy itself fails closed. Eligibility hashes and historical skipping
use the **same opened Markdown bytes**; checking ordinary prose also consumes
that same byte snapshot. This bounds one observation, not later file changes.

`scripts/fixtures/hyg-003-owner-archives` retains three byte-exact complete
original seals as losslessly compressed fixtures and four complete original
Markdown files. The index binds decompressed bytes to original paths, lengths
and SHA-256 values. This partial seven-file mirror uses the actual production
registry and pins without override. It is a meaningful replay of the four
false alarms, not a full archive-tree or owner-tree proof. Separate negative
parser controls are expressly not evidence that a synthetic seal is trusted.
The eight original history fixtures remain unchanged: seven full historical
files and one byte-contained verifier excerpt, as described above. This
continuation reruns their semantic RED/GREEN controls without running Git;
the earlier independently verified Git provenance remains historical evidence.

Fresh Python validation and exact source/hook hashes are in
[`hyg-003/archive-scope-validation.json`](hyg-003/archive-scope-validation.json).
The 33 archive tests exercise the real board entry point, restored historical
scope, tampering, live prose, path/registry failures and snapshot identity.
[`hyg-003/archive-scope-mutations.json`](hyg-003/archive-scope-mutations.json)
retains all 43 named controls: the 25 original semantic mutations and 18 new
archive/boundary controls. Each control actually passes unchanged, fails with
one assertion failure and no test error after removing/weakening its guard,
and passes again after restoration. Removal of the historical scope makes the
real positive integration test RED. Actual dated and merged historical GREEN
controls remain preserved.

Foundation architecture, local validation and the dogfood architecture mirror
add exactly one required command: `python3 scripts/test-stale-claims-archives.py`.
Existing required commands and floors remain intact. The mirror verifier is
GREEN; removal of this exact command from an isolated architecture mirror
produces its specific required-command denial and restoration is GREEN.
[`hyg-003/archive-scope-lane-mirror.json`](hyg-003/archive-scope-lane-mirror.json)
retains those observations. The architecture shell and full Foundation script
are not executed here: no native, database, source-transport or Git workloads
are credited to this continuation.

Independent final source/threat/evidence review, hosted exact-head checks,
protected publication/merge, post-merge observations and closure remain
root-owned. HYG-003 stays ACTIVE. The local fixture GREEN remains distinct
from the actual owner-tree clause-seven proof below.


## Actual owner-tree observation

At 2026-10-07T00:07:42.596115+00:00, root independently ran the frozen candidate
against the actual `/sn8100/work/forge/McLoving` owner tree observed at
`4fa136de9515cf0ac6c423bfc9bd19d0ebc5c45a`. The source-bound wrapper verified all
four frozen production hashes and ran the real board main entry point with the
explicit local observation date 2026-10-06. It exited 0: 147 tickets, 15 remaining,
one current slot, 10 parallel and five serial tickets. This resolves the four
owner-archive false alarms on the actual tree while retaining the independently
reviewed content boundary of 107 registered Markdown files and three seals.
Root's before/after comparison found all 113 observed files unchanged in bytes
and modes: those 110 archive files plus ROADMAP, Heman and the root planning
handoff. Python used `-B`; no cache writes were credited.

The full source-bound observation and preservation inventories are in
[`hyg-003/archive-scope-root-owner-tree.json`](hyg-003/archive-scope-root-owner-tree.json),
with its [raw log](hyg-003/archive-scope-root-owner-tree.log), SHA-256
`75ff348166f359f22a20cb8ac613e9ec3c135ec55e74c6029dc996a4c53470e7`.
This is a dated candidate-source readback against that owner-tree snapshot;
it establishes no future head's result, hosted workflow success, publication,
merge, authorship, operational authority or ticket closure. HYG-003 remains ACTIVE.
