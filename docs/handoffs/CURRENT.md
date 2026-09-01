# Current custodian handoff

The current dated handoff is
[`2026-09-01-september-freeze.md`](2026-09-01-september-freeze.md).

McLoving is governed by the
[`September 2026 code-freeze contract`](SEPTEMBER_2026_CODE_FREEZE.md) through
2026-09-30 23:59:59 America/Chicago, unless the owner explicitly changes that
decision.

## Read this first

- Authoring baseline: protected `main`
  `c17bbafafe4f983b6e936cd2f57245edabfb1ffd`, tree
  `dddf3c31edd2aa6f41d1614e119367beaa8dca5b`, GitHub-verified with reason
  `valid`.
- There were no open pull requests at authoring time. This handoff publication
  pull request is the final planned September repository mutation.
- The board verifier reports 107 tickets and 21 remaining. `EXEC-005` is the
  selected next ticket but must remain `PENDING` during the freeze.
- The closure verifier reports 86 done, 31 receipted, 30 reviewed, and the
  admitted, ratcheted 37-item historical debt.
- Protected-main Foundation, native Windows, and Release Builder runs are green
  at the authoring baseline. All eight required contexts remain bound to GitHub
  Actions app id `15368`.
- McLoving is not release-ready and has no production authority.
- Two open Dependabot records represent one moderate `jsonwebtoken` advisory.
  They are deferred for reassessment, not resolved or accepted.

## During September

Do not start a board ticket, resume an old branch, open an implementation pull
request, change dependencies or workflows, publish a release, or grant
operational authority. Keep CI, branch protection, alerts, and monitoring
enabled. Only an explicit written owner emergency decision may authorize a
bounded exception, and every normal protected-merge obligation still applies.

## Safe next action

Until the freeze expires or is explicitly lifted, the safe action is read-only
observation. On thaw, follow the ordered procedure in the dated handoff:
re-fetch protected main, audit September drift and alerts, re-read protection,
run all board/closure/aggregate/Foundation gates, and only then decide whether
`EXEC-005` is still the earliest ready ticket. Create a fresh branch rather
than resuming a pre-freeze one.
