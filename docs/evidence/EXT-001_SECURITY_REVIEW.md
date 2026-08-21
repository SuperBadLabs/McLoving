# EXT-001 security and closure review

Date: 2026-08-13

Verdict: PASS. The contained external-effect connector and deny-authority
shadow-replay implementation are bound to exact reviewed head
`186f48df1ac83c78f4c9dc9e085f2a8fb757b9da` and closed against protected
`main` commit `dae140e038c52a655489ab99f112ecfa4252aede` after exact-head
and post-merge Foundation and Windows verification.

## Scope

EXT-001 adds the standalone `mcloving-external-connector` one-action boundary,
the signed versioned request and authoritative-outcome protocols, a private
durable exactly-once ledger, and the separate no-network
`mcloving-external-shadow-replay` process. Requests and receipts bind the exact
tenant, project, pipeline, build, attempt, effect fence and key, connector,
implementation, image, configuration, deployment, runtime, endpoint, account,
resource, action, credential grant, authority keys, idempotency class, expiry,
audit provenance, retry/ambiguity truth, and independently observed destination
state.

The connector permanently deduplicates a physical effect scope across certified
generation rotation, reserves ambiguity-reconciliation capacity before
dispatch, persists dispatch truth and timing, and admits only exact HTTP 200
signed destination outcomes. Quiescent cutover and rollback retain bounded
generation ancestry. Ambiguous completion remains frozen until a fresh signed
OBS-001 reconciliation receipt resolves it.

Raw and encoded secret representations are denied before transport, signing,
or persistence. Bounded credentials are screened for authority seed material
across every raw 32-byte window and every complete or segmented standard
Base64, Base64URL, and hexadecimal decoding. Public output and shadow audit
provenance use the same raw, hexadecimal, fixed-point percent-decoded, and
normalized Base64 detector, including markers at nonzero decoded offsets.
Shadow replay secret material cannot reuse public connector-receipt or
runtime-attestation authority-key bytes.

Production construction verifies short-lived runtime evidence bound to the
executing inode, image, configuration, boot ID, mount namespace, cgroup,
deployment, and runtime identities before secrets or state open. The shadow
process has no endpoint configuration or credential, must run under the exact
enforcing AppArmor label, and proves live kernel denial of all network access.
Mario's sealed denominator still admits zero production connector or credential
authority.

## Exact evidence

- Pull request: `#49` (`feat: implement EXT-001 external connector boundary`).
- Exact reviewed implementation head:
  `186f48df1ac83c78f4c9dc9e085f2a8fb757b9da`.
- Protected Linux focused gate: 20 connector tests, comprising ten unit tests,
  nine contained connector/shadow contract tests, and one sealed Mario
  inventory assertion. The tenth unit test exercises Linux `/proc` executable
  hashing and is correctly absent on the local macOS host.
- Focused build gates: pinned Rust 1.97.1 formatting, strict all-target
  loopback-feature Clippy with warnings denied, diff hygiene, locked metadata,
  execution-board tests, and execution-board verification passed.
- Protected exact-head checks: Foundation run `31745305137` and Windows Agent
  run `31745305193` passed. The Linux Foundation gate exercised live `/proc`
  runtime evidence, the enforcing shadow AppArmor profile, the all-network
  denial probe, and the serialized source-acquirer policy suite.
- The independent exact-head review reported no major issue after every
  discovered defect was repaired. All 61 actionable review threads were
  replied to where applicable and resolved before merge.
- Squash merge: `dae140e038c52a655489ab99f112ecfa4252aede`, with
  protected-main parent `64ad5fb38ca4d348a57b2e1d07663ee21c7ff3a8`.
- Post-merge verification: Foundation run `31748017628` and Windows Agent run
  `31748017610` passed on that exact protected-main commit.

## Residual boundary

This closure proves the contained one-action connector, outcome receipt,
independent-observer linkage, and deny-authority replay implementation. It does
not grant a production connector mapping, destination credential, secret
provider mapping, credential grant, production endpoint, canary, cutover,
rollback, recutover, or decommission authority. SECRET-001 must inventory and
classify every Jenkins-managed credential reference and prove its own provider,
grant, rotation, revocation, taint, and non-disclosure boundary before any
credential-dependent qualification may proceed.
