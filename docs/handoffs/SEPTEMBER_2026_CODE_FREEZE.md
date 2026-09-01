# September 2026 code freeze

## Effective window

McLoving is frozen from publication of this document through
**2026-09-30 23:59:59 America/Chicago**. The freeze expires at
**2026-10-01 00:00:00 America/Chicago** unless the owner explicitly extends or
lifts it. The publication pull request for this handoff is the final planned
September repository change.

The purpose is to preserve the verified McLoving baseline while engineering
effort moves to Fogell. A freeze is a refusal of new mutation, not permission to
weaken verification.

## Frozen actions

During the window, do not:

- start or mark a board ticket `ACTIVE`, open or merge an implementation pull
  request, resume an old remote branch, or advance the dispatch slot;
- change source, dependencies, lockfiles, schemas, migrations, workflows,
  branch protection, release material, deployment configuration, fixtures,
  sealed evidence, or ticket status;
- publish a release or grant deployment, credential, connector, canary,
  cutover, rollback, recutover, decommission, or other production authority;
- suppress, cancel permanently, unrequire, rename, or bypass a protected check
  merely to keep the frozen repository quiet; or
- import Fogell code or evidence. The boundary in
  `docs/related-work/FOGELL.md` remains unchanged: measurements may inform
  design, but receipts and authority do not transfer.

Normal read-only observation may continue. GitHub Actions, dependency alerts,
security alerts, retention, and repository monitoring should remain enabled.
An alert being deferred by the freeze is not an accepted fix or a closed risk.

## Emergency exception

There is no implicit exception. Work during the freeze requires an explicit,
written owner decision naming the emergency, scope, and authority. An emergency
should be limited to an actively exploitable security issue, imminent data or
evidence loss, repository-control failure, or an equivalent event that cannot
safely wait until October.

An authorized emergency still uses a fresh branch from protected `main`, one
bounded pull request, exact-head independent review, zero unresolved threads,
all eight protected contexts, a live protection readback, guarded merge, and
post-merge Foundation and Windows verification. It must record why waiting was
unsafe and what evidence or certification it invalidates. The exception does
not grant production authority that McLoving does not already possess.

## State held by the freeze

The canonical authoring baseline is protected `main`
`c17bbafafe4f983b6e936cd2f57245edabfb1ffd`, tree
`dddf3c31edd2aa6f41d1614e119367beaa8dca5b`. GitHub reports the commit signature
as verified with reason `valid`.

At authoring time:

- there are no open pull requests;
- the execution-board verifier reports 107 tickets, 21 remaining, one current
  slot, no remaining batch, two parallel tickets, and nineteen serial tickets;
- `EXEC-005` is the selected next ticket but remains `PENDING`;
- the closure verifier reports 86 done, 31 receipted, 30 threat-model reviewed,
  and 37 admitted historical debt items;
- McLoving is not release-ready and has no production authority; and
- two open Dependabot alerts, numbers 1 and 2, describe the same moderate
  `jsonwebtoken` advisory `GHSA-h395-gr6q-cpjc` in
  `crates/controller-api/Cargo.toml` and `Cargo.lock`. They are queued for
  reassessment on thaw unless the owner declares an emergency first.

The complete custody snapshot and restart instructions are in
`docs/handoffs/2026-09-01-september-freeze.md`.

## Thaw procedure

On or after the expiry time, the next custodian must not assume that elapsed
time alone makes the checkout current. Before mutation:

1. Confirm that the owner has not extended the freeze and that no emergency
   change or external repository-setting change occurred.
2. Fetch protected `main` into a clean checkout and discard no local or
   untracked user files.
3. Re-read branch protection and require the exact eight GitHub-Actions-bound
   contexts recorded in the handoff.
4. Review all alerts, open pull requests, default-branch commits, workflow
   outcomes, releases, and protection changes since this baseline.
5. Run the board and closure verifiers and the complete Foundation gate.
6. Re-read the formal `EXEC-005` row and its dependencies. If it is still the
   selected earliest-ready work, create a fresh `codex/` branch; do not resume
   a pre-freeze implementation branch.

The thaw is a new custody decision. This document preserves the September
baseline; it does not pre-approve October work.
