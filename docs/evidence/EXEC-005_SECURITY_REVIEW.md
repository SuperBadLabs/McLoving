# EXEC-005 security review — ACTIVE cache product slice

EXEC-005 is ACTIVE. This receipt records review of a bounded Linux cache
publish/read integration; it does not close the ticket. SCM acquisition,
dependency resolution, live-input capture and dynamic provisioning remain
unwired. General cache-to-workspace restoration is also unimplemented. All five
actual helper product gates and normal protected-main verification remain
closure requirements; no canary, cutover or production authority is granted.

## Boundary and independent review

The contract is `docs/architecture/CACHE_PRODUCT_PATH_V1.md`. Independent design
review required authoritative scope, immutable command/configuration custody,
bounded concurrent private IO, full receipt/content validation and an actual
submitted-job gate. Implementation review identified and corrected a test crash
hook that was initially present in release builds; it is now debug-only. Root
review identified blocking FIFO opens before metadata checks; agent binding,
executable and helper configuration opens now use nonblocking no-follow access
and reject nonregular files. Neither finding was treated as an acceptable
limitation. The cache verifier reuses pure store admission instead of opening
cache state in the product caller. The existing context-bound durable journal
commitment supplies the deterministic invocation identity without a new sidecar
ledger or a false claim that native cache receipts carry attempt identity.

## Verification scope

Focused verification covers agent scope/payload mutations, sealed original-path
substitution, bounded special-file refusal, real memfd cache execution and
configuration substitution before state creation, exact signed receipt/content
and multi-receipt chain mutations, concurrent pipe pressure, blocked stdin under
timeout/cancellation, withheld request bytes on failed spawn journaling, and
nonzero/oversized output refusal with no raw spool. The full agent unit suite
also retains the earned lease-renewal behavior. An initial sandbox run could not
bind eight loopback test listeners; the unchanged host run passed all 75 tests.
That environmental refusal is not a product failure and was not counted as a
passing test.

The actual positive gate passed one comprehensive test in 8.95 seconds against
the shipped controller/cache and same-source remote agent. It covers actual
miss/publish/hit, prequeue scope refusals, conflict/downstream skipping, the
post-helper parked-recovery window without redispatch, and terminal-commit
replay in a fresh fixture. Earlier harness expectations that the post-helper
window would automatically terminalize were corrected to assert the observed
named parked refusal; product recovery behavior was not relaxed.

The gate is `bins/agent/tests/cache_work.rs`, driven by
`scripts/test-cache-product.sh`: API put/submit, shipped controller, remote mTLS
agent and real sealed cache, followed by independent read-only audit and
journal/context verification. Fake helpers and direct library tests contribute
only focused negative or boundary evidence, not actual product invocation
coverage. Final candidate, protected PR and exact-main results must be recorded
from observed receipts before any future closure; this ACTIVE review makes no
claim that those publication gates have already completed.

## Residual risks and unchanged authority

Reviewed threats and mitigations are attributed under EXEC-005 in
`docs/threat-model/README.md`. Deployment catalog decisions, the controller and
agent, kernel, cache producer and shared HMAC verifier remain trusted. Catalogs
are startup-frozen, not hot-revoked. A post-helper/pre-result crash can park the
agent with an unresolved recovered attempt until operator recovery; this slice
does not promise automatic terminal completion. SEC-005 still owes hostile same-UID workload
isolation. The new versioned runtime requires the existing later case
recertification gates; it does not extend the frozen JCOMP-003 equivalence claim.
The dependency full-request provenance producer and provisioner lifecycle are
separate unresolved integration obligations, not reasons to weaken their
standalone contracts.
