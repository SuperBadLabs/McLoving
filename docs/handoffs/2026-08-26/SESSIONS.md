# Sister-session ledger — 2026-08-26 custodianship

*Part of `docs/handoffs/2026-08-26/`.*

Four Claude sessions were live on McLoving during this shift, including mine.
This records what each was for, where it ended, and what it left behind, so the
next custodian inherits dispositions rather than orphans.

**Read `HANDOFF.md` first.** This file is only the session bookkeeping.

---

## 1. `mcloving-78` — custodian (mine)

Drove the shift's single dimension: **closure integrity — make absence loud.**
Merged PR #94 (`4bf882b`) and PR #96 (`2c2cc73`), filed `HYG-002`, reviewed
PR #95. Worktree `/sn8100/work/forge/McLoving-closure-integrity`
(branch `codex/closure-integrity`, merged — safe to reclaim).

## 2. `priceless-poincare-341541` — ARCHIVED ✅

*"Add CI gate for ticket closure receipts."* Stopped since 2026-08-25.

**Its work landed.** It authored `122e5cd`, the first version of the
ticket-closure receipt gate, and left it unpushed; the previous custodian
backed it up at `refs/keep/closure-gate-122e5cd`. I cherry-picked it onto
`codex/closure-integrity` with authorship preserved, hardened it, and it merged
to protected `main` inside `2c2cc73`. Both
`scripts/verify-ticket-closure-receipts.py` and
`scripts/test-ticket-closure-receipts.py` are live in the required
**Architecture records** check.

Archived safely: its worktree held only `claude/priceless-poincare-341541` at
`7207852`, which is reachable from `origin/codex/wave4b-jenkins-compiler`, so
nothing unique went with the worktree. **`refs/keep/closure-gate-122e5cd` is now
redundant** — its content is on `main` — and can be released.

## 3. `eloquent-cray-6218d1` — PR #95

*"Check if the deploy smoke test leaks daemons."*

Found and fixed a real defect: `run_with_env … &` backgrounds a shell
*function* whose body is a `( … exec "$@" )` subshell, so `$!` named an
intermediate `bash`. The trap killed the wrapper and the daemon reparented to
init — **on every clean pass**, which is why it survived ~45 runs over two days
without one going red.

I reviewed it and reproduced the diagnosis standalone:

```
OLD  (run_with_env … &):   $! = 1869500  comm = bash    → after kill: sleep survives at ppid=1
NEW  (spawn_with_env … &): $! = 1869501  comm = sleep   → after kill: gone
```

Verdict: **approve in substance.** No `run_with_env … &` call sites remain;
`require_service_pid`'s `[[ … ]] && return 0` is `set -e`-safe; the
`BASHPID`/`$$` guard refuses rather than exec'ing over the suite; `bash -n`
clean; shellcheck output **byte-identical to `main`**.

Its `require_service_pid` is the best example on this project of the *second*
shape of the absence bug: an invariant the **success** path depends on and
never states. The source-acquirer idiom covers the error path; this covers the
other one.

**Disposition: ARCHIVED ✅.** PR #95 squash-merged to protected `main` as
**`d002e0c`**. Worktree clean at `7396f86`, nothing unpushed, confirmed by the
session before archiving.

**It also corrected me twice, and both corrections improved the outcome.** It
told me my credit of "real-suite evidence" to it was wrong — its own first
harness was synthetic too, and weaker than mine on the axis in dispute. It gave
up the stronger-looking position voluntarily. And it pushed back on my
refutation of the signal-during-`cleanup` finding rather than co-signing it.
Both are on the PR record.

## 4. `strange-franklin-a8e34d` — follow-up ticket

*"Trap-manage the smoke suite's inline-killed pids."* Spawned by me from a
finding in the #95 review. Branch `codex/deploy-harness-spawn-registry`.

The suite kills three backgrounded processes inline rather than from its trap —
the health server (`deploy/test-deployment.sh:1229`, killed at `:1262`),
`lock_holder`, and `shared_holder`. A death in between leaks them. Same class as
#95, **pre-existing**, deliberately excluded from that PR.

I corrected my own first write-up here: I claimed #95's signal traps *widened*
the window; the peer session pointed out that before the change a SIGINT killed
the suite with no cleanup at all, so the outcome in that window is unchanged.
They were right.

Time-boxed against the end of my tenure to: reproduce the leak first, then write
the design call (what a stale pid means once the inline kill has run; registry
vs self-registration), and open a PR **only** if both are done.

**Disposition: ARCHIVED ✅.** PR #97 squash-merged as **`96ef05f`**. See
`HANDOFF.md` §6b.

It went well beyond the ticket:
- **Proved the leak twice** — the real suite SIGTERM'd inside the `lock_holder`
  window, leaving an orphan at `ppid=1` **still holding the flock** on
  `.transition-lock`; and a standalone `exit 1` path with no signal at all.
- **Found a second defect I had not ticketed:** the held-lock refusal gate at
  `:6466` exits **without** killing its holder, while all five sibling gates
  kill first. So this leaks *today*, on a plain gate failure, no signal needed.
- Established that on SIGTERM **the EXIT trap does run** — it is reached and
  still cannot see these processes. The fix is a registry, not a signal trap.
