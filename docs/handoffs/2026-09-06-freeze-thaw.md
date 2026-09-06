# September 2026 freeze thaw receipt

Thaw date: 2026-09-06. Authority: explicit owner decision to lift the freeze
ahead of its 2026-09-30 expiry, recorded in the custody session that produced
this receipt. The freeze document's own term governs: it expires "unless the
owner explicitly extends or lifts it."

This receipt discharges the six-step thaw procedure in
`docs/handoffs/SEPTEMBER_2026_CODE_FREEZE.md`. It records repository custody
only. It grants no product, deployment, credential, connector, canary,
cutover, rollback, or production authority, and it closes no ticket.

## Why the freeze was lifted early

The freeze's stated purpose was to "preserve the verified McLoving baseline
while engineering effort moves to Fogell." A measurement campaign run on
2026-09-05 and 2026-09-06 reversed that premise's direction. The owner
therefore lifted the freeze rather than let it run to term.

The campaign is Fogell-side evidence. Under
`docs/related-work/FOGELL.md` boundary rules 1 and 2 it informs design and
licenses no McLoving claim, tier assignment, or board status. Nothing in this
receipt records a Fogell measurement as a McLoving result.

## Step 1 — no extension, no emergency, no external change

The owner did not extend the freeze. No emergency exception was declared and
no emergency change was made. Live branch protection is unchanged from the
recorded baseline (step 3). No external repository-setting change is visible
in protection readback, alerts, releases, or workflow history.

## Step 2 — clean checkout of protected main

Fetched protected `main` at `d534a1b54b7832e1b4a77e1715506256fa404dec`. The
freeze recorded the authoring baseline as
`c17bbafafe4f983b6e936cd2f57245edabfb1ffd`; the single commit between them is
the freeze's own publication pull request #119, which the document names as
"the final planned September repository change." No local or untracked user
file was discarded.

## Step 3 — protection readback

Live protection requires exactly the eight recorded contexts, each bound to
GitHub Actions app id `15368`:

`Rust`, `Dependencies and licenses`, `Secret scan`, `Architecture records`,
`Formal model`, `Controller PostgreSQL`, `Foundation`, `Windows`.

Strict synchronization, admin enforcement, linear history, and conversation
resolution are enabled; force pushes and deletion are disabled. This matches
`docs/handoffs/2026-09-01-september-freeze.md` exactly.

## Step 4 — changes since the baseline

- Default-branch commits: one, `d534a1b` (#119), the freeze publication.
- Open pull requests: none.
- Releases: none.
- Workflow outcomes, including `Release Builder`, which is `workflow_run`
  triggered on every `Foundation` completion and therefore produces an outcome
  the other two do not:
  - Protected-main `Foundation` `33556596622` and `Windows Agent` `33556596621`
    both succeeded at the baseline `c17bbaf`.
  - `Release Builder` `33558663955` succeeded at `c17bbaf`, driven by that
    protected-main Foundation. This is the run the freeze handoff recorded.
  - Three further `Release Builder` runs report `skipped`: `33562371951`,
    `33564215818`, and the two triggered today by this pull request's own
    Foundation runs. `skipped` is the designed outcome, not a missing result:
    the job is gated on
    `workflow_run.conclusion == 'success' && workflow_run.head_branch == 'main'`
    within the same repository, so a completion on a pull-request branch, or a
    cancelled Foundation, correctly builds nothing.
  - The one `cancelled` Foundation run on the #119 branch was superseded by a
    later successful run on the same branch -- `CI-001`'s designed supersession
    behavior, not a failure.

- **Gap found, and it predates the thaw.** The current protected-main head
  `d534a1b` has **no `Foundation` run, no `Windows` run, and consequently no
  `Release Builder` run at all.** Querying every workflow run at that head
  returns exactly two, both `Release Builder` completions triggered by this
  pull request today. `foundation.yml` triggers on `push` to `main` with no
  path filter, and the preceding head `c17bbaf` did receive its push-triggered
  Foundation and Windows Agent runs, so this is specific to the #119 merge
  rather than a configuration exclusion.

  The freeze document's recorded evidence is all at `c17bbaf`, and it described
  its own publication pull request as "the final planned September repository
  change". The merge that produced `d534a1b` therefore never received the
  post-merge Foundation and Windows verification the repository's protocol
  requires, and the freeze then held the repository still for five days with
  that gap unrecorded.

  Nothing is known to be broken: `d534a1b` is documentation-only, its
  pull-request head passed both workflows before merging, and both verifiers
  reproduce its expected numbers. What is missing is the protected-main
  receipt, not a passing result. Merging this thaw pull request closes the gap
  going forward, because its own post-merge Foundation and Windows runs verify
  the successor head.
- Dependabot: exactly the two recorded open alerts, numbers 1 and 2, both the
  moderate `jsonwebtoken` advisory `GHSA-h395-gr6q-cpjc`, in
  `crates/controller-api/Cargo.toml` and `Cargo.lock`. The freeze deferred
  them; the thaw does not close them. They remain open and unremediated, and
  are now eligible for a bounded reassessment ticket.
- Pre-freeze remote branches: five `codex/*` branches survive as stale
  post-squash refs. None is resumed; the thaw procedure forbids it.

## Step 5 — verifiers and the Foundation gate

- `scripts/verify-execution-board.py`:
  `execution-board-ok tickets=107 remaining=21 current_slots=1 batch=0 parallel=2 serial=19`
- `scripts/verify-ticket-closure-receipts.py`:
  `closure-receipts-ok done=86 receipted=31 reviewed=30 receipt_exempt=50 threat_model_exempt=24 debt=37`

Both reproduce the numbers the freeze document recorded at authoring time. The
37 admitted historical debt items are unchanged and remain admitted; the thaw
neither closes nor re-opens them.

### Foundation gate

Discharging this step took two runs, and the first one's failure was not what
it looked like.

`bash scripts/validate-foundation.sh` exits `101` on HeMan. The failing suite is
`-p mcloving-source-acquirer --test contained_source`: 5 passed, 15 failed,
every failure a `sealed helper source acquirer readiness: Elapsed(())` timeout
rather than an assertion. HeMan sets
`kernel.apparmor_restrict_unprivileged_userns=1`, so the sealed helper cannot
execute, and the script runs the suite inside a podman container where the
`mcloving-source-acquirer` profile is not applied.

**That failure aborts the gate rather than merely reddening one suite.** The
script runs under `set -e` and the failing test sits inside the first
`podman run`. Everything after it was therefore never executed: the
`--all-features` destination-observer and external-connector clippy and test
steps in that same container, `cargo-deny`, all seven Python board/closure/
workflow verifiers, the two `bash -n` checks, `actionlint`, TLA+ `SANY` and
`TLC`, the Jenkins Clojure compatibility suite and plugin-directory contract,
`gitleaks`, and the ADR/charter/threat-model/board file assertions. A first
draft of this receipt claimed thirty green suites established a green gate.
It did not: thirty suites is what ran before the abort, and the untested
remainder was the majority of the gate's distinct checks.

The step was therefore re-run in two parts that together cover the whole gate:

1. The complete script with the single change
   `cargo test --locked --workspace --exclude mcloving-source-acquirer`, so the
   abort cannot mask the remainder. It ran to completion and printed
   `McLoving foundation validation passed.`, exit `0` — cargo-deny, every
   verifier, actionlint, TLA+, the Clojure suite (6 tests, 20 assertions, 0
   failures), the plugin-directory contract, and gitleaks (`no leaks found`)
   all executed and passed.
2. The excluded package under the profile the gate requires, as
   `CONTRIBUTING.md` and `.github/workflows/foundation.yml` prescribe:

```text
aa-exec -p mcloving-source-acquirer -- \
  cargo test --locked -p mcloving-source-acquirer -- --test-threads=1
```

   Exit `0`, with the 20 `contained_source` tests passing in 48.48s.

The same tests fail bare and pass under the profile on the same commit and in
the same worktree, which isolates the cause to the missing `userns create`
grant rather than the tree. Two competing explanations were checked and
rejected: the host-global transport roots
`/tmp/mcloving-source-transport-16m` and `-512k` were present and intact and
are fixtures the suite requires rather than stale corruption, and no second
suite ran concurrently, which is the other known way those roots produce false
failures.

This split is not a local workaround. It is the shape the authoritative gate
already has: CI runs `Rust workspace tests`, `Rust boundary suites`,
`Rust lint`, and a dedicated aa-exec `Rust source-acquirer suite` as separate
jobs. `scripts/validate-foundation.sh` is the monolithic local approximation,
and its `set -e` coupling is why one environmental failure reads as a total
gate failure here.

The authoritative signal is the app-bound `Foundation` context on this thaw's
own pull request head, together with the seven other required contexts.

## Step 6 — dispatch slot

`EXEC-005` is re-read from its formal board row and remains `PENDING` with both
start gates satisfied: `EXT-002` merged as `03a1f5d` and `DEPLOY-001` merged as
`52b2ecb` with follow-up `586230b`. The board verifier independently reports one
current slot. `EXEC-005` is therefore still the selected earliest-ready work,
and it keeps that position on thaw.

No pre-freeze implementation branch is resumed. Any implementation starts from
a fresh `codex/` branch off protected `main`.

## What this receipt does not do

It does not start `EXEC-005` or mark any ticket `ACTIVE`. It does not import
Fogell code or evidence. It does not remediate the two open Dependabot alerts.
It does not reduce the 37 admitted closure-debt items. Each of those is a
separate bounded decision.
