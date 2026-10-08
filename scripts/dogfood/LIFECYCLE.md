# DOGFOOD-001 sender ownership and lane contract

This is a scripts-only candidate. Source authoring does not earn runtime,
protected-check, ticket-closure or deployment credit. Product Rust, Cargo
manifests/lock, the credential signer and verdict interpretation are unchanged.

`heman-up.sh STATE` runs under `hook-lifecycle.py run STATE`. The supervisor
validates an owner-private, non-symlinked 0700 state directory and holds an
owner-private CLOEXEC flock through the entire deployment subprocess. The
internal script entry authenticates its actual parent supervisor and held lock
inode; a flag or environment variable alone cannot authorize it. Bridge delivery
subprocesses hold the same lock through signing, HTTP capture, ledger update and
watermark publication. A deployment encountering a delivery lock refuses rather
than changing senders while that request is running.

The closed 0600 `hook-owner.json` records owner UID, state device/inode,
deployment and operation UUIDs, exact numeric repository identity, trigger
binding/generation, route, retained hook ID, mode and transition phase. Repository
admin readback and complete paginated repository-hook visibility are required.
This visibility is scoped to repository webhooks; it asserts nothing about global
GitHub App hooks. A matching URL is never sufficient to adopt an unowned hook.
Unrelated repository hooks are neither adopted nor disabled.

The v2 receipt additionally binds an observed `hook_quiesced` boolean. After
durable begin, the full deployment quiesces a previous public sender before
stopping any old runtime or doing a build, source/output replacement, route or
trigger mutation. Exact old private sender context, repository-admin identity,
complete owned-hook inventory and same-ID active/old-URL GET are checked first.
`pending-quiesce` is durable before the inactive PATCH; response and independent
GET must agree before `hook_quiesced:true` and deploying continuation are durable.
Uncertain fence failure preserves the old runtime and refuses continuation.
Same-public restart configures/reactivates that same inactive ID only after new
runtime/trigger readiness. This does not exhaust remote retries or settle any
in-flight public delivery; the real D05 producer remains missing.

Before removing prior sealed `source-output`, a held-directory traversal checks
owner UID, device and object type and restores owner write access on directories
only. Symlinks are not followed; files/hardlinks and foreign targets are never
chmodded. Foreign ownership/device/type, traversal budget or dependency failure
refuses removal. The checked private state and same-account mutation remain the
trust boundary; this is not hostile same-UID namespace containment. The shared
main owner's existing local chmod remediation is retained separately and untouched.

A new owned hook is POSTed inactive only after a durable pending-create intent.
The returned ID is persisted before activation. Configuration, URL and secret
rotation use PATCH on that exact retained ID, first inactive, then explicitly
active, with response validation and independent GET readbacks. Missing, foreign,
uncertain or mismatched state refuses a second create. The helper never prints
raw API errors, credentials or payloads. Secret-bearing request files use private
0600 files and are removed on normal, dependency-failure and handled INT/TERM
exits. SIGKILL cannot run cleanup and leaves an uncertain phase for diagnosis.

A fresh sender requires this locked deployment's successful generation-zero
trigger creation, authenticated final trigger readback, a newly private route
secret, no recorded/legacy sender or delivery history, and no unowned repository
hook on that exact route. It is not an operator attestation. Existing trigger or
secret history without a receipt fails closed. Repeated same-mode deployments
retain the receipt and the hook ID. PID receipts bind exact owner/process image,
argv and start ticks; a held pidfd carries termination and terminal observation.
An unrecorded live PID, reused PID or unconfirmed termination blocks transition.

## Cross-mode input that is still unavailable

Public-to-bridge first PATCHes the owned hook inactive and verifies response and
GET state. Bridge-to-public first confirms the old recorded bridge has terminated.
Neither transition starts a new sender. Both write `blocked-handoff` with exact
repository, branch, trigger generation/source generation, deployment/operation
and old/new mode, then refuse. An interrupted disable remains pending and cannot
be reinterpreted as success.

Today's documented controller public API has no complete trigger delivery,
admission and build-history export or payload-bound public GUID-to-PushEvent-ID
association. GitHub's Events API also has a finite visibility window and does not
provide this association. The missing real installer input must come from a
named producer able to bind the exact deployed ingress fence and retry horizon,
complete source event/delivery identities and original payload/ref/body hashes,
controller acceptance/admission/build bindings, rejected requests and unresolved
in-flight work. There is currently no reviewed producer in these scripts/current
public APIs. No arbitrary operator boolean, signed-review ceremony, matching SHA,
latest-only watermark or caller-supplied receipt is accepted as that producer.
This candidate therefore makes **no usable cross-mode handoff guarantee** and
cannot close D05/D10 until that input is implemented and independently exercised.

The original bridge preserves distinct real push event IDs for repeated commits.
Fresh bootstrap deliberately uses the newest visible push; it does not claim
full-history replay. A missing saved watermark refuses delivery. Empty feeds do
not mint a synthetic branch-SHA identity. These rules cannot settle prior public
admissions and never authorize a cross-mode waiver.

## Six-lane source comparison

`verify-lanes.py` uses a finite YAML/shell grammar and emits ordered canonical
records containing argv, working directory, scoped environment, pinned Cargo
toolchain, package/test/features, test flags, wrapper count/label/PostgreSQL
requirement and output sink. Both command/context multiset differences and order
are checked. Unknown executables/operators, suppressed failures, dynamic context,
unnamed/duplicate steps and unreviewed actions fail closed.

The finite lexer identifies comments before escaped physical newlines. A
comment's trailing backslash cannot hide the next executable line; quoted,
escaped and word-internal hashes are literal arguments. Reviewed catalog records
are typed internal items, never trusted source-authored `# canonical-record`
comments. Unsupported source markers, overlapping catalog blocks and unterminated
continuations refuse. This is a finite lexer, not a general Bash interpreter.

`lane-contracts.json` binds shared setup, global/job context and each enumerated
complex provisioning/action/container block to its exact current source bytes.
This is a reviewed source catalog, not a runtime resealing tool. Byte changes in a
complex block invalidate it; names or broad scaffolding expressions never exempt
commands. Meaningful actionlint inventory, explicit empty config and archive
pins, Clojure action/archive/version and four directory-scoped commands,
dependency policy, pinned gitleaks rule/image/arguments and helper builds are
retained. The finite exceptions are exact Foundation ancestry verification,
required lane-only self-check, sealed-tree gitleaks versus full-history scan,
and runner provisioning. The opaque cargo-deny action and separately pinned
release have an explicit policy-check correspondence; this does not infer the
action's internal executable version. Their identities/configuration are pinned.

PostgreSQL notifications use the verified count 10 with `--include-ignored` and
serial flags. Long-step lease count is 9. The real CLI helper is built and its
path/PODMAN environment exists only around the same three remote gates as in
Foundation. Cache/input/sequential consumers keep their exact controller/helper
paths. Architecture command order follows Foundation, including the four Clojure
commands after record verification.

## Required validation, all still unexecuted by the author

The source-only adversarial tests mutate counts, labels, flags, helper packages,
commands in both directions, duplication/comments/suppression, order, CWD,
environment, tool/container pins, complex-block inventory and unknown grammar.
Lifecycle tests run actual helper logic with a stateful API spy scoped to owned
repository hooks: create ordering, same-ID URL rotation, lost responses, unknown
ownership, disable/readback failures, blocked handoffs, receipt ownership and PID
reuse. Existing credential tests retain actual-script HMAC/live argv, cleared
controller environment, private request ownership/cleanup and INT/TERM assertions,
with stateful inactive registration/activation and real pidfd process fixtures.
They additionally check distinct repeated-commit event IDs and history-gap refusal.
The signer and verdict regression source is retained unchanged.

Root must execute source/parser/script adversarial checks, independently review
D01-D10 and the threat/credential boundaries, resolve the real D05 input,
exercise actual deployment/native boundaries, and obtain all protected checks
before publication or closure. No tests, hooks, containers, network, privilege,
profiles, Git operations or product builds were run during this source authoring.
