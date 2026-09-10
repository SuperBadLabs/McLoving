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

Protected PR verification exposed two additional integration gaps: Windows
agent Clippy now compiles the cache dependency and rejected its unconditional
Unix-only import, and the deployment environment classifier did not recognize
the new cache catalog/binding paths. The import is now Unix-gated. Deployment
classification explicitly treats the controller catalog as no-follow trust
material and agent bindings as no-follow secret material, with private mode,
service ownership, single-link and canonical-path checks. Regression fixtures
cover valid deployment paths and mode, symlink, FIFO and hardlink refusals.
An external review also found that CLI validate/plan could not supply the
required pipeline scope; both now expose optional `--pipeline-id`, with actual
HTTP request coverage for scoped and legacy unscoped use. These findings are
retained as failed-candidate evidence, not relabeled as passing gates.

A subsequent full Foundation run failed the private-stdin test's two-second
whole-execution assertion. That bound omitted the executor's existing separate
five-second leader and descendant containment waits and final spool durability.
A controlled unchanged syscall-traced diagnostic completed both modes with
TERM/KILL, reaping and descendant absence; it did not reproduce or explain the
earlier delay and does not replace the failed gate. The test now derives its
12.35-second bound from the existing lifecycle budgets, including explicit
setup/durability allowance, and checks exact termination, descendant absence,
private-response refusal and empty output before timing. Runtime timeouts and
containment behavior are unchanged; the hostile helper still has a 30-second
lifetime. Final candidate Foundation verification must pass independently.

A further external review found that a generic cache capability let an agent
with different configured mappings in the same pool claim and terminally refuse
an otherwise authorized one-attempt job. Scheduling now requires an additional
domain-separated capability binding the exact mapping id, full mapping digest
and operation; agents advertise only their configured operation/pool bindings.
This prevents incompatible assignment before the unchanged agent authority
checks. The revised actual product gate passed one comprehensive test in 9.58
seconds: a same-pool agent with a disjoint mapping completed a process barrier
while leaving the original cache attempt unclaimed, with no cache audit or
ineligible journal entry. The matching agent then completed that same attempt
while the other agent remained live. Focused capability tests additionally
cover mapping-digest and operation mismatches.

The client-context audit then found that CLI validate, plan and apply could
not select a nondefault trust pool. All three now expose the same trust-pool
and platform options as submit, and scoped Rust client methods transmit both
existing admission headers while preserving legacy method signatures/defaults.
Actual HTTP tests cover default Linux, custom-pool Linux, explicit Windows
transport, pipeline scope, apply revision/slug/parameters and malformed platform
refusal. Windows transport coverage does not grant Windows cache admission.

Native Windows verification later returned the expected cancellation outcome
but failed a separate PowerShell numeric-PID disappearance probe. Its output
did not distinguish an original surviving process from PID reuse or observer
failure; this differs from the earlier pre-PID startup timeout and its cause
remains unproven. Three equivalent probes now hold a read-only native process
handle obtained while the original process is alive, then require that same
handle to be signaled with the termination exit code after execution. The
observer is feature-gated test support in the existing Win32 FFI capsule,
enabled by a Windows-only development dependency. It cannot terminate or
modify a process. Production Job Object creation, termination and empty-job
verification are unchanged. Cross-compilation checks cover the observer with
the feature on and off; actual native runtime verification remains required.

Compatibility review found that the new plan-response cache-step counter was
required during deserialization, breaking upgraded clients against older
controllers with nonempty stages. Only that additive response counter now
defaults to zero when absent. The actual CLI HTTP fixture covers an old
nonempty process stage and preserves a current nonzero cache count; authority
fields retain their strict validation. The response-field audit found no other
new counter in this change requiring a compatibility default.

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
