# Current custodian handoff

The current dated handoff is
[`2026-08-31-custodian.md`](2026-08-31-custodian.md).

## Read this first

- Authoring baseline: protected `main`
  `e7eefb6d66cf0886f4c9198fc88cbec757e80fd2`, tree
  `65b2d78d099bd209e9a4ff247181f0be21da9009`.
- The execution board is authoritative. Its selected pending implementation
  slot is `DEPLOY-003`; do not mark it `ACTIVE` until an implementation branch
  and pull request actually exist.
- The board verifier reports 106 tickets and 22 remaining. No remaining ticket
  is a batch. The closure-receipt verifier intentionally reports the admitted,
  ratcheted 37-item historical debt.
- There were no open pull requests at authoring time. The handoff publication
  pull request is accounting only.
- McLoving is not release-ready. No production effect, canary, cutover,
  rollback, recutover, or decommission authority has been granted.
- `PERF-001` is still `PENDING`. PRs #109 and #110 close only the bounded
  event-wait dimension; the capacity, saturation, storage, recovery,
  regression-margin, and eligible-platform envelopes remain open.

## Safe next action

Start with `DEPLOY-003` and read, in order:

1. `docs/EXECUTION_BOARD.md`, especially the `DEPLOY-003` row and current
   dispatch queue.
2. `docs/architecture/DEPLOYMENT_TRUST_BOUNDARY_V1.md`.
3. `docs/evidence/DEPLOY-001_SYSTEMD_LANE.md`.
4. `docs/evidence/DEPLOY-001_SECURITY_REVIEW.md`.
5. `docs/evidence/CI-002_SECURITY_REVIEW.md`.

The preferred closure is an ephemeral systemd-capable host with controlled
global unit paths. A fresh lingering account on a shared host is not a clean
host: root-owned global `UnitPath` entries remain shared. Preserve the board's
manager-query, union-validation, retained-obligation, threat-model, exact-head
review, and post-merge verification requirements.

Before opening work, fetch protected main, verify the selected ticket is still
current, and run:

```text
python3 scripts/verify-execution-board.py
python3 scripts/verify-ticket-closure-receipts.py
git status --short
```

The second command succeeds while printing the admitted debt. `--strict` is
reserved for a zero-debt ceremony and is expected to fail until that debt is
retired.
