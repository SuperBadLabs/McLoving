# CACHE-001 security and closure review

Status: closed against protected `main` commit
`f58986cd36019588b9731150a663e5dff32773bd`.

## Scope

CACHE-001 adds the contained `mcloving-cache` process and the
`CACHE_SERVICE_V1` contract. The boundary is tenant, project, pipeline,
trust-class, policy, generation, restore-epoch, toolchain, platform, and
content bound. It has no listener, network client, scheduler, runner,
controller-database, repository-credential, connector, observer, or production
effect authority. Mario's sealed inventory still admits zero production cache
mappings.

Every admitted cache outcome is committed with an HMAC-signed, hash-chained
receipt. Every stored-row removal requires an HMAC-authenticated historical
`Published` event for the exact canonical subject and generation before the row
can be deleted or a removal receipt can be signed. Entry-pointer, content,
expiry, policy, generation, canonical-key, and historical-record substitution
are independently rejected. Authenticated-subject blob corruption remains
purgeable only through a content-free `corrupt_rejected` receipt.

## Exact evidence

- Pull request: `#37` (`CACHE-001: add isolated transactional cache boundary`).
- Exact reviewed implementation head:
  `87e3f75936e1d5f153b99167e1340308e92ac9ac`.
- Focused gate: 28 cache tests, comprising 22 contained store tests, one sealed
  Mario inventory assertion, and five strict standalone-process tests.
- Workspace gates: strict Clippy, the complete locked non-source-acquirer
  workspace, nine execution-board tests, board verification, formatting, and
  diff hygiene passed.
- Source-acquirer isolation remained independently green under the repository
  AppArmor profile: 30 tests, including all 19 contained source tests.
- Exact-head protected checks: Foundation run `31386942233` and Windows Agent
  run `31386942427` passed.
- Independent Codex review reported no major issues twice on exact head
  `87e3f75936`; all 18 actionable review threads were fixed, replied to, and
  resolved before merge.
- Squash merge: `f58986cd36019588b9731150a663e5dff32773bd`, with protected-main
  parent `8ddf6153552e14781d12705758bdbaa29fd18f5a`.
- Post-merge verification: Foundation run `31389728915` and Windows Agent run
  `31389728894` passed on that exact protected-main commit.

## Residual boundary

This closure proves the contained cache implementation and its evidence path;
it does not grant production cache, dependency, scheduler, runner, credential,
connector, observer, canary, cutover, rollback, or decommission authority.
Those claims remain gated by the execution board and their own live receipts.
