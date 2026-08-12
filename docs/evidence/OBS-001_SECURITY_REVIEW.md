# OBS-001 security and closure review

Date: 2026-08-12

Verdict: PASS. The contained destination-observer implementation is bound to
exact reviewed head `2f3999b8f9f734b93d646100a66dd6ba5c87ba83` and closed
against protected `main` commit `aa43e088242bd125422dd4352df071e23ca4f24f`
after exact-head and post-merge Foundation and Windows verification.

## Scope

OBS-001 adds the independently deployed `mcloving-destination-observer`
process and the `DESTINATION_OBSERVER_V1` contract. The observer is GET-only
and binds exact implementation, image, configuration, generation, deployment,
operator, runtime, service, credential-issuance, request-authority, destination
attestation, endpoint, account, resource, query, tenant, project, build,
attempt, effect-fence, phase, cursor, freshness, read-grant, and audit
identities into a signed receipt.

The durable private ledger serializes destination scope, retains phase-chain
heads and physical cursor high-water independently of receipt pruning, bounds
observations, heads, receipts, evidence bytes, requests, and runtime history,
and distinguishes abandoned pre-reservation claims from retries that consumed
transport authority. Transport-boundary time resampling, pinned trust material,
closed typed state, complete reversible-encoding marker scanning, terminal
permission behavior, and exact raw request/response frame limits fail closed.

The process has no write, scheduler, runner, controller database/filesystem,
agent, workload-secret, connector-control, or effect authority. Mario's sealed
inventory still admits zero production destination-observer mappings.

## Exact evidence

- Pull request: `#39` (`OBS-001: independent destination observer`).
- Exact reviewed implementation head:
  `2f3999b8f9f734b93d646100a66dd6ba5c87ba83`.
- Focused gate: 75 observer tests, comprising 17 unit tests, one sealed Mario
  inventory assertion, 55 contained contract tests, and two strict
  standalone-protocol tests.
- Focused build gates: formatting, diff hygiene, no-default-feature
  compilation, and all-target/all-feature Clippy with warnings denied passed.
- Exact-head protected checks: Foundation run `31568744882` and Windows Agent
  run `31568744895` passed all nine required checks.
- The independent exact-head review chain reported no discrete actionable
  defect after every discovered issue was repaired. All 79 review threads were
  replied to where applicable and resolved before merge.
- Squash merge: `aa43e088242bd125422dd4352df071e23ca4f24f`, with
  protected-main parent `3787b42fa72b143eb0d1a1c643a15f05e259fdfc`.
- Post-merge verification: Foundation run `31570215577` and Windows Agent run
  `31570215548` passed on that exact protected-main commit.

## Residual boundary

This closure proves the contained observer implementation and its evidence
path; it does not grant production destination-read credentials, a production
mapping, connector or runner authority, canary, cutover, rollback, recutover,
or decommission authority. Those claims remain gated by the execution board
and their own pre-action and live receipts.
