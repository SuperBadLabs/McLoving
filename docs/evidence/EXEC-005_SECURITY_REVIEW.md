# EXEC-005 security review — ACTIVE cache/input slices and source prerequisites

EXEC-005 is ACTIVE. This receipt records bounded Linux cache publish/read and
input-capture integration work plus standalone source prerequisites; it does not
close the ticket. SCM acquisition,
dependency resolution and dynamic provisioning remain unwired. General
cache-to-workspace restoration and downstream input-value use remain
unimplemented. All five actual helper product gates and normal protected-main
verification remain closure requirements; no canary, cutover or production
authority is granted.

The cache review below retains its historical findings. Input implementation,
review and verification are recorded separately at the end of this receipt.

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

## Input successor review and verification

The successor contract is `docs/architecture/INPUT_PRODUCT_PATH_V1.md`.
Independent domain/runtime review and chief review cover default-deny scoped
admission, exact scheduling eligibility, IR 1.5/envelope 4, deterministic UUIDv8
and original durable acceptance time, same-parsed configuration custody and
pure verification without provider-token access or adapter construction. The
chief separately reviewed the actual submitted-job harness and its independent
request recomputation, native HMAC authentication, private-output scans and
crash observations. Qwen assisted only with extracting a design checklist;
its output was checked against the plans and is not verification evidence.

Review corrected three implementation defects before publication: an optional
expected-config environment pin initially ignored non-Unicode values; the
general symlink-refusing executable hasher could not open `/proc/self/exe`;
and receipt verification checked capture time but omitted completion-time
expiry checks. Present malformed config pins now refuse startup before
credential/state access. A separate bounded opened-image reader deliberately
follows the kernel self-image link while general file readers remain no-follow
and nonblocking. Pure verification now checks completion against request,
grant and native publication deadlines, in addition to source freshness and
capture timing.

The first actual product run failed in the independent audit observer because
it used standard Base64 for a native URL-safe, unpadded signature. That failed
run earned no positive gate. The corrected gate passed, then a strengthened
run independently observed the real running helper's memfd image digest and
all four immutable seals before releasing the counted provider response. The
strengthened local run passed one comprehensive test in 14.50 seconds. Its
scope includes real API save/submit/replay, incompatible same-pool agent
exclusion, exact provider GET/query/token/grant identity, zero provider writes,
native signed receipt/journal/full-request linkage, an exact six-field public
summary and private payload/key/token/marker/cursor/provenance/hash absence.
The final strengthened run passed in 16.92 seconds and separately proved
ineligibility for both a different mapping ID and the same ID with a different
mapping digest, retaining full positive linkage and privacy checks for each.

Negative product fixtures reject unknown or mismatched mappings and client
authority overrides before queueing; expired configured grants and unapproved
operator queries fail before provider access. Actual provider responses cover
wrong cursor, stale/future observation, secret confidentiality, raw/escaped
secret markers, duplicate/trailing JSON and wrong schema. Configuration, key,
token, marker and executable substitutions cannot produce successful work or
downstream execution. These tests use the real sealed helper, not a fake
positive implementation.

The real post-helper/pre-result crash preserves native receipt count, full
assignment digest, capture ID and original journal acceptance time. Restart
observes the named parked-recovery refusal without another provider read or a
successful terminal inference. A separate fresh fixture exercises the
terminal-commit crash and proves one durable terminal replay without recapture.
No fixture clears the unresolved journal to obtain replay success.

Focused producer and agent tests additionally bind every signed authority field,
request/content commitment, confidentiality and timing. Whole-cache product
regression and private-IO suites remain required because executable/file custody
is shared. Local Foundation, protected PR checks and exact-main Foundation/native
Windows results must be observed on the final candidate; the local product
observations above do not substitute for those gates. EXEC-005 remains ACTIVE
regardless of this slice's publication, until all helper integrations earn their
own required evidence.

Focused local receipts record 25 adapter tests, 77 agent unit tests plus the
subsequently added version-4 context mutation test, four private-IO tests and
the durable acceptance/reopen timestamp test passing, with final all-target
agent/adapter Clippy clean. Initial sandbox socket refusals and two new fixtures
that inherited internal confidentiality were corrected or rerun under the proper
test environment; they are not counted as passing evidence. A Linux-hosted
Windows cross-check could not build its C dependency because MinGW GCC was
missing. This is an unavailable local check, not a Windows pass or a waiver of
the required native Windows gate.

The first frozen candidate, `bc5da5820a4ad0c4a8996c47ad18d785121f9859`,
passed all 22 commands in the local PostgreSQL workflow replay: 154 executed
tests, with six existing backup/restore canaries explicitly ignored as in the
workflow. Actual remote, identity, long-lease, cache, input and sequential
denominators all passed, and source and shipped-binary hashes remained unchanged.
This qualifies that frozen source; it does not claim protected publication.

Its general Foundation run failed in an existing renewal fixture: the test
reserved then dropped a TCP listener before tonic rebound the port. The retained
trace reports `Address already in use` at server startup and a subsequent
response timeout, with 77 other agent tests passing. The correction retains the
bound Tokio listener and hands it directly to tonic's incoming stream. It adds
only an already-locked, test-only tokio-stream dependency; production renewal
logic and test timing assertions are unchanged. The failed Foundation run is
preserved separately, and the corrected candidate requires fresh validation.

The corrected signed candidate `680e88f8c766f88317ae923639eeba539711469b`
passed local general and host Foundation lanes with unchanged source snapshots.
The host lane reused byte-identical loaded policy and transport mounts; dependency
mounts ran only in verified private user/mount namespaces, with cleanup and
unchanged outer-host mount state verified. This was the reviewed alternative to
an automatically rejected privileged host-policy setup, not a policy bypass.
Protected PR #140's first native Windows job compiled the production agent but
failed strict Clippy on three explicit drops of the adapter's non-Unix empty
spool-lock type. That newly reachable dependency lint failure is retained;
Windows execution remains required before publication can be credited.
The correction consumes the spool lock in a private synchronous scope at each
original release boundary. Unix still drops the real file lock there; non-Unix
acquisition still refuses. It adds no fake destructor or lint suppression.
Independent review, all 25 adapter tests and agent/adapter strict Clippy passed
on Linux; the corrected native Windows result must be observed separately.

A later PR review identified that startup allowed 64 fixed query keys while the
native adapter allows 32. Startup now rejects more than 32, whitespace-only query
keys, blank expected cursors and pool names over the controller catalog's
128-byte bound. A real pinned mode-0400 loader test accepts a native-valid
32-key request and rejects 33, with adjacent boundary cases. Three focused input
tests, strict agent Clippy and independent review passed. This proves the loader
boundary; pre-advertisement refusal follows configuration construction ordering,
not a separately executed capability-exchange fixture. Prior candidate gates
remain source-qualified and the corrected head still requires protected checks.


## Standalone source-helper custody prerequisite, ACTIVE scope

Input PR #140 merged as `30a79f3f3c7c1318d09668da9d77adda266a0889`,
with exact-main Foundation `34528466630` and actual native Windows
`34528466620` successful. Its tree equals reviewed candidate `fabddc5`;
all eight required app-bound checks and three resolved review threads were
verified before normal protected merge. Those gates qualify the input slice.

The subsequent source change is a standalone prerequisite. The normal
acquisition entrypoint optionally checks the exact parsed canonical config
digest before private authority reads or state creation. Missing pins preserve
the existing interface; malformed, non-Unicode and mismatched pins refuse.
Internal resolver, askpass and transport modes keep their existing admission
and deadline checks. Running-image hashing and constructor self-snapshot each
use a deliberately opened kernel self-image, authenticate original bytes, and
preserve the existing derived ELF interpreter/runtime binding. Ordinary file
readers remain bounded and final-symlink refusing, and nonblocking opens reject
FIFO substitutions without waiting for a writer. The generic file hasher still
accepts empty regular files.

Independent source review found no changes to native requests, claims, receipts,
replay, process groups, profile contents, agent dispatch or controller admission.
The source fixture and full native suite must earn their own results; the
input gates above do not substitute for them. No source product gate, downstream
checkout, production source authority or expanded JCOMP-003 claim is earned.
Source-native commands create nested process groups, so the existing agent
outer-group emptiness check cannot certify their complete cancellation. This
is a source-inspected integration mismatch, not an observed process escape.
Production source-only profile selection, nested-process lifetime enforcement,
held-directory retained-tree custody and bounded retention ownership remain
separate obligations. EXEC-005 stays ACTIVE.

Local native verification passed 35 tests: eight library, four CLI, 21 contained
and two inventory tests, with zero failures or ignored tests. The final
fixture-only refinement then passed its focused test and strict Clippy; native
implementation hashes were unchanged. That refinement observes the actual
held helper's named profile and proves a pretty-printed configuration's raw
hash differs from its accepted canonical pin.

The real fixture executes an immutable original helper image after replacing
its former pathname. While authenticated Git traffic is held, it verifies the
running image hash and all four seals. It then independently checks the native
HMAC, complete request digest, receipt authority/time fields, Git commit/tree,
retained manifest/content and modes, unchanged provider repository and absence
of private authority bytes. Upload-pack POST is counted as a read; unapproved
routes are denied and counted. Owned-file inotify watches with a positive
open/read control observe zero credential/key/marker opens for wrong, malformed
and non-Unicode pins. Eight actual CLI symlink/FIFO cases refuse within bounded
waits before output state or provider access. Existing loaded profile and
transport evidence remained unchanged; no host policy or mount mutation was
performed. These are standalone source gates, not submitted-job source or
outer-agent descendant-cancellation evidence. Protected PR and exact-main
Foundation/native Windows results remain separate required observations.

The standalone fixture preserves the existing host-capability contract. The
named source-profile gate must complete the authenticated positive acquisition.
Where the native sealed-launcher probe establishes namespace unavailability,
the fixture executes the real sealed helper and requires exactly
`transport_namespace_unavailable`, zero provider requests, and no acquisition,
claim or staging publication. This is an asserted native refusal, not a skipped
test. Other capable hosts retain the full positive path and verify the actual
inherited profile. Foundation runs the named source suite; it syntax-checks the
separate Podman differential script but does not execute that complete script.
The startup observer represents arbitrary output bytes losslessly as Base64 and
names its `IN_OPEN`/`IN_ACCESS` event mask.

Local correction validation exercised three actual routes: named-profile
authenticated acquisition (one passed), the Podman source invocation with the
differential lane's security settings on this capable host (one positive passed),
and the unconfined host's existing namespace restriction (one exact refusal
passed). Strict Clippy passed. No injected denial or host policy mutation was
needed, and this targeted container run is not a full differential-lane result.

## Pure source receipt authentication prerequisite, ACTIVE scope

The source verifier now accepts explicit immutable authority snapshots and the
complete original acquisition request without constructing a native acquirer or
opening provider credentials/runtime paths. Shared native configuration shape,
authority hashes, signing-key and marker-set checks remain in force; filesystem
canonicalization stays in native construction. The key-bearing verifier has no
`Debug` implementation and does not retain marker bytes. Typed authority inputs
are caller size-controlled; hostile stored receipt bytes use a strict 64 MiB
bounded parser with duplicate, unknown and trailing-data refusal.

Independent chief review required complete signed-field binding, separation of
historical authentication from current admission, preserved native constructor
checks and refusal of impossible zero-file receipts. The implementation compares
the complete canonical original-request digest plus repeated context/config,
grant, primary/submodule repository and output identities. HMAC verification is
constant-time. Historical authenticated receipts may outlive their original
window; native replay still checks current request/grant admission first. No
receipt changes a request timestamp or authorizes a new provider operation.

Focused local validation: `RUSTC_WRAPPER= cargo test --locked -p
mcloving-source-acquirer --lib receipt_auth` passed eight tests with zero failed
or ignored. The denominator includes every original request field, 39 correctly
re-signed receipt context/authority/limit substitutions with an independently
successful HMAC check, primary/submodule identity and graph substitution, time
boundaries (including nonnegative native acquisition time and the checked native
publication-lifetime upper bound), zero-file refusal,
malformed/duplicate/unknown/trailing/oversize frames, key/marker/config drift,
native credential-marker size admission, and positive historical authentication using
absent native-state/runtime paths. These are pure unit tests, not a submitted-job
or retained-tree custody gate. A separate direct runtime-loader unit test passed
with a correct-hash caller-owned regular file and executed the ordinary
non-root-owner refusal branch; strict source all-targets Clippy also passed.
Actual native fixture results are recorded with
the source launch verification below when executed.

Held-directory root binding, descriptor-relative complete inventory, finite
retained-state accounting/crash reconciliation and submitted-job source wiring
remain outstanding. Existing pathname-based tree verification and cooperative
read-only sealing modes do not isolate a fully compromised same-UID actor.
EXEC-005 remains ACTIVE; all existing production/canary/cutover exclusions and
frozen compatibility denominators remain in force.


## Closed standalone source lifetime and runtime custody review, ACTIVE scope

The bounded contract is `docs/architecture/SOURCE_CONTAINMENT_V1.md`. Independent
review identified that original agent process-group emptiness cannot cover native
source children that create new groups. The standalone fixed source path selects
its exact source-only profile, uses a private namespace PID1 and staged control
pipes, and requires the caller to retain/join the exact init pidfd before any
native response can be accepted. A normal outer `waitpid(init)` is a completion
proof; outer death by itself is not. Durable agent dispatch/recovery is not added.

A real native acquisition attempt exposed another boundary: root-owned host
libraries become an unmapped UID in the caller-only user namespace. An earlier
review of generic executable readers missed the dedicated runtime-loader owner
check; the observed failure was preserved and the review corrected. The fix
does not accept overflow ownership. The original full-identity outer process
checks root-owned, non-group/world-writable exact runtime files through held
opens before namespace creation. A typed receiver checks live sealed supervisor
lineage and the parent-held sealed manifest before consuming those descriptors.
Ordinary construction preserves native root-ownership admission and all existing
runtime path-drift and derived loader/snapshot checks.

Independent adversarial review required guarded proc authority reads: plain
UID/GID map paths can be forged with static bind overlays before launch. Held
proc root/task descriptors, pinned kernel self links and same-mount `openat2`
reads now protect map/status/environment/fdinfo interpretation. The fixed
profile transition and label checks also use same-mount guarded task
`attr/current` opens; this closes an independent review finding where plain
profile paths could overclaim early P/N evidence under static overlays. Final genuine
proc executable/FD links cross mounts when followed, so static overlays are
rejected with pinned before/after leaf checks; active same-UID mount/ptrace
interference remains outside the claimed boundary. The operator launcher must
clear the initial dynamic-loader environment before first exec; an environment
check after startup cannot establish that no loader injection already occurred.
Neither supervisor reads credential/key/marker files. The selected profile is
unconfined, not a restrictive workload sandbox.

After guarded profile/parent checks and the deliberate separate-session
heartbeat fixture were added, an earlier pre-freeze targeted matrix passed eleven
tests with zero failures or ignored tests. Each of the three authenticated
cancellation routes joined the exact init pidfd and observed seven pinned native
descendants exit, including the deliberately detached process; its observed
heartbeat stopped and the provider count stayed stable. Normal native completion
also authenticated the receipt/tree and joined init with the deliberate separate
group present. Eight direct init/worker forged-parent launches refused before
parent lineage could authorize a capsule; these cases do not claim downstream
capsule-parser mutation coverage. The eleven Rust tests group five real native acquisition/lifetime scenarios,
twelve setup paths, eight early-parent exits, eight initial caller-identity
refusals, three root-custody refusals, one static-map scenario with two installed
UID/GID overlays, and eight forged private-entry launches. All executed the
supported-host routes without unavailable-host fallbacks. This is a targeted dirty-candidate
result, with exact reviewed-path/log hashes retained in the independent review;
complete frozen-suite and protected-main evidence remain separate obligations.
An earlier ticker observation failed because Linux truncated its process name;
that failed attempt and its weaker cleanup evidence remain separately retained.
Later successful pidfd joins do not retroactively establish teardown authority
for the failed attempt. Fixture-only offline transport retirement after proven
init exit preserves synthetic claims and does not implement product reclamation.

PR 144 review then identified a missed admission topology: distinct readiness and
gate descriptor numbers could refer to opposite ends of one pipe, allowing the
supervisor to consume its own phase bytes as caller acknowledgements. The actual
old-source regression used valid pinned configuration and private authority,
asserted different descriptor numbers but equal held device/inode identity, and
sent no acknowledgements or request. A calibrated inotify watch observed private
credential/key/marker access (160 event bytes after a 32-byte positive control),
and the old source exited successfully. No provider request or acquisition was
claimed by that EOF-driven reproduction.

Both supervisors now compare the held FIFO device/inode identities, with the
outer check before profile/P/config and the init check before profile/custody/R.
The same regression then refused before P with zero watched private-authority
access, no output and a still-working positive watch control. The corrected
complete targeted matrix passed twelve tests with zero failures or ignored tests,
including the distinct-pipe authenticated positives and all eleven earlier
tests. The watch observes private authority files, not configuration; the
earlier configuration boundary is established by the code placement. Prior
candidate validation remains evidence for its observed cases and omitted this
alias case; corrected frozen-candidate full-suite and protected-main results
must be recorded separately. No broader source integration gate is earned.
Held acquisition-directory custody, finite retained-state reservations and crash
reconciliation, controller/agent wiring and actual submitted-job replay remain
open. EXEC-005 remains ACTIVE and no production/canary/cutover or frozen JCOMP
claim is expanded.
