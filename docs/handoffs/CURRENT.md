# Current custodian handoff

The current dated handoff is
[`2026-09-06-freeze-thaw.md`](2026-09-06-freeze-thaw.md). The preceding handoff
is [`2026-09-01-september-freeze.md`](2026-09-01-september-freeze.md), whose
snapshot below remains accurate for the September baseline.

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

## Read this first

- Authoring baseline: protected `main`
  `c17bbafafe4f983b6e936cd2f57245edabfb1ffd`, tree
  `dddf3c31edd2aa6f41d1614e119367beaa8dca5b`, GitHub-verified with reason
  `valid`.
- There were no open pull requests at authoring time. This handoff publication
  pull request is the final planned September repository mutation.
- The board verifier reports 107 tickets and 21 remaining. `EXEC-005` is the
  selected next ticket and remains `PENDING`; it was re-read at thaw and is
  still the earliest-ready work. It is now startable on a fresh `codex/` branch.
- The closure verifier reports 86 done, 31 receipted, 30 threat-model reviewed,
  and the admitted, ratcheted 37-item historical debt.
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
HeMan when the source-acquirer suite is run under `aa-exec` the way CI runs it.

`EXEC-005` was re-read at thaw and is still the earliest ready ticket, with
both start gates (`EXT-002`, `DEPLOY-001`) satisfied. It is the safe next
action. Start it on a fresh `codex/` branch; do not resume a pre-freeze one.

Two items the freeze deferred are now due and are not closed by the thaw: the
two open `jsonwebtoken` Dependabot records (one moderate advisory,
`GHSA-h395-gr6q-cpjc`), and the ratcheted 37-item historical closure debt.
