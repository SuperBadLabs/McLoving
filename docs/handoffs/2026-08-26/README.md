# Custodian handoff pack — 2026-08-26

**Canonical location:** `docs/handoffs/2026-08-26/` in this repository. The
current pack, superseding every earlier `McLoving-handoff-*` directory.

**Start with [`HANDOFF.md`](HANDOFF.md).** Its §0 is the three things to do first.

One shift, one dimension: **closure integrity — make absence loud.** The
project's defining failure is that absence and success look identical; this
shift turned two instances of it into mechanisms and merged the pull request
that had been blocking the board.

## What landed

| | |
|---|---|
| `4bf882b` (PR #94) | `DEPLOY-001`'s receipts and the deployment trust boundary. Open since 2026-08-25, blocked on a rule nobody had read. Seven correction rounds on the way in, including one P1 that had a live vulnerability understated as arbitrary execution when it is credential compromise. |
| `2c2cc73` (PR #96) | Two gates in the required **Architecture records** check: a `DONE` ticket must carry a receipt and an *attributed* threat-model review, and the board must declare an edge between tickets that share a boundary. |
| `d002e0c` (PR #95) | The smoke suite leaked a controller/agent pair on **every clean pass** — `run_with_env … &` backgrounds a shell *function*, so `$!` named an intermediate `bash` and the trap killed the wrapper. Reviewed and merged. |
| `HYG-002` | Filed. Replaces the gates' prose inference with a machine-readable attribution field, and carries the parser debt PR #96 left. |
| `96ef05f` (PR #97) | Three more backgrounded processes outside the EXIT trap, one leaking a *held flock* on `.transition-lock`. Reviewed and merged. |

## Sister sessions

Three ran alongside mine; **all three are archived with their work merged**, and
nothing was left unpushed. Ledger in [`SESSIONS.md`](SESSIONS.md).

**Zero open pull requests, zero live sessions, zero orphaned processes.** The
board starts clean.

## Two things to read even if you read nothing else

**The gate inherited from `122e5cd` could be satisfied by nothing.** An empty
file at the receipt path plus a threat-model line reading
`TODO: <TICKET> has not been reviewed yet` printed `closure-receipts-ok`.
Existence was the receipt test and a substring search was the review test. The
mechanism built to stop this project's defining bug was an instance of it.

**Five of PR #96's ~45 findings were the gate refusing correct work**, not
passing on absence. That direction is easier to miss and more damaging: a gate
that goes red on a correct change is the one people delete. Watch both.

## Trust this pack for

- §1 — the branch-protection facts, which cost the previous shift its top item
- §3 — the gates' behaviour and the constants that must be maintained by hand
- §5 — what I got wrong, including overrunning the correction-round cap by
  seven rounds
- §6 — corrections to the 2026-08-25b pack, whose receipt-gap figure is inverted

**This pack supersedes `McLoving-handoff-2026-08-25b/`** — say so explicitly
wherever you leave a pointer, because a stale pointer to a dated directory is
indistinguishable from a current one, and two people walked into that this week.
The `-25b` pack remains accurate for project rules, host state and worktree
inventory; where they conflict, this one is later and wins.
