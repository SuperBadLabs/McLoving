# PROV-001 security and implementation closure

Date: 2026-08-05

Verdict: PASS for the implementation gate at exact implementation head
`16ed422d149cb224fbc8fd7652fb8a2d0934ccd0`. All nine protected checks passed,
and the focused gate passed with fifty-five contained end-to-end tests plus the
sealed Mario inventory test. Independent exact-head review found no further
actionable issue after fifty-two implementation findings were fixed and their
threads resolved.

The later PR #33 closure candidate adds only this receipt and the execution-board
transition from PROV-001 to SCM-001. Its exact head must independently pass the
protected checks and review before merge. The final squash-merge commit is
necessarily unknowable from inside its own pre-merge contents; the immutable PR
#33 exact-head checks plus post-merge protected-main verification are the final
closure attestation.

This receipt does not claim a Mario production provisioner, dynamic-agent
canary, cutover, rollback, or Jenkins decommissioning event.

## Inventory denominator

The accepted MIG-000 provider inventory contains zero admitted Mario dynamic
provisioners. The executable inventory test preserves that zero denominator and
does not substitute the contained provider fixture for production truth.

## Implemented boundary

- standalone NDJSON provisioner with a self-hashed executable, canonical
  immutable configuration, generation admission, and retained SQLite ledger;
- one pinned provider/account/region/grant and immutable agent class binding the
  template, image, bootstrap, toolchain, platform, capabilities, trust pool,
  network, volume, workspace, cache, instance identity, and IAM policy;
- tenant/project/build/attempt/fence binding, request idempotency, global and
  scoped quotas, bounded command and instance lifetimes, and audit lineage;
- HTTPS/private-CA production policy, no redirects, ambient proxies, or client
  retries, bounded provider responses, signed provider attestations, and
  substitution/staleness/duplicate-identity denial;
- effective-user-owned private state, no-follow bounded authority-file reads,
  durable intent before provider access, first-writer cleanup intents, and
  HMAC-signed lifecycle and reconciliation receipts;
- create, startup polling, cancellation, scale-down, agent-loss, expiry,
  reconciliation, orphan cleanup, generation cutover, and rollback behavior;
- CAS-protected lifecycle transitions, retained cleanup truth across concurrent
  create/cancel/reconcile races, immutable admission-time startup deadlines,
  monotonic state revisions across current and legacy writers, atomic
  cleanup-intent/absence transitions, revision- and identity-fenced signed
  absence and cleanup confirmation, and terminal receipt precedence bound to
  the same concrete instance;
- retained ledger scope bound to provider and agent identity plus both the
  receipt-signing key identifier and key-material digest; and
- final inventory reconciliation and explicit escaped-compute reporting.

The governing contract is `docs/architecture/DYNAMIC_PROVISIONER_V1.md`.

## Review and executable evidence

The independent review produced fifty-two actionable implementation findings
across twenty-three reviewed implementation heads. The fixes covered final-inventory
revalidation, retained-ledger scope, lifecycle deadlines, create/reconcile and
cancel races, recovery identity validation, concrete-instance anchoring,
instance-less receipt precedence, durable cleanup intent, CAS-protected lookup
and startup transitions, retained cancellation through CAS loss, stale
ambiguity recovery, post-lookup timeout convergence, receipt-key scope,
receipt/state crash convergence, admission-fenced reconciliation evidence,
initial and final inventory snapshot races, final ready-ledger absence,
ambiguity convergence, and concurrent schema migration.
Later exact-head findings additionally hardened post-snapshot Ready retention,
pre-inventory concrete revision fences, same-instance observation races,
provider-signed observation time and clock-skew bounds, concrete Pending
refreshes, legacy-writer revision triggers, transactional cleanup-intent CAS
rollback, startup signed absence, and post-delete cleanup confirmation.

Every finding was resolved only after its fix was pushed on the reviewed head
and backed by a focused regression or an explicit fail-closed admission rule.
The final implementation head passed `git diff --check`, Rust formatting,
`clippy -D warnings`, fifty-five contained tests, the sealed Mario inventory
test, all nine protected checks, and independent exact-head review.

## Residual risk and authority boundary

The provider, grant issuer, provisioner operator, host, private CA, provider
attestation key, and receipt-signing key remain trusted within their declared
scopes. The provisioner and receipt verifier share signing authority, so their
collusion can forge lifecycle evidence. No real Mario provider class is
admitted by this ticket. DIFF-003, SHADOW-001, and CANARY-001 remain mandatory
before any production dynamic-agent authority grant. CUTOVER-001, ROLLBACK-001,
RECUTOVER-001, DECOM-001, and MIG-009 remain mandatory for the subsequent
authority-transfer, reversal, final-transfer, decommission, and closure chain.
SEC-004 and WAR-001 remain release-readiness gates at their board-defined
points; DR-001 follows MIG-009 and is a final-release gate, not a prerequisite
for the authority transition. This receipt waives none of those gates.
