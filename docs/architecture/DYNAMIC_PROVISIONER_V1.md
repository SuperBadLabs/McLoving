# Dynamic provisioner v1

Status: implemented for the PROV-001 contained boundary. No Mario dynamic-agent
canary, production provider, or cutover is claimed.

## Inventory boundary

The accepted Mario MIG-000 runtime-dependency manifest is
`migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/runtime-dependencies.yaml`
at SHA-256
`238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4`.
It contains 230 jobs and 230 `opaque-cps-runtime`, `controller-global`,
`scripted` dependencies. It contains zero `dynamic-provisioner` dependencies.
PROV-001 therefore implements and tests a reusable provisioner boundary without
inventing a Mario provider, account, region, template, image, identity grant,
or live dynamic-agent claim. A later inventory generation must explicitly add
and owner-review a dynamic agent class before any production mapping can use
this protocol.

## Process and authority boundary

`mcloving-provisioner` is a standalone NDJSON process. It is not loaded into the
controller or an agent. One process generation is certified for exactly one
provider endpoint, provider/account/region, provider grant, provisioner
identity, and immutable agent class. Its admitted authorities are limited to:

- read an immutable JSON configuration, a scoped provider bearer token, a
  pinned provider Ed25519 public key, and a receipt-signing key;
- create, observe, list, and delete instances only through the closed provider
  v1 routes at the configured endpoint;
- write its own private SQLite lifecycle/evidence ledger; and
- write one typed receipt or bounded typed error per NDJSON command.

The process has no scheduler, controller API listener, controller database or
filesystem, agent RPC, workload credential, unrelated secret, source checkout,
cache service, connector-control, deployment, or arbitrary external-effect
authority. The provider client disables redirects, ambient proxies, implicit
retries, and non-loopback cleartext. Production HTTPS requires a configured,
content-pinned private CA bundle and does not inherit the host root set.
Cleartext is admitted only for numeric loopback fixtures and requires both the
configuration flag and `MCLOVING_PROVISIONER_TEST_MODE=1` in the binary.

Configuration, credential, public-key, CA, executable, and command reads are
bounded. Final-component symlinks are denied. Provider-token and receipt-key
files must be effective-UID owned with no group or other bits. V1 creates or
accepts only an absolute, canonical, effective-UID-owned `0700` state directory
and a regular `0600` database file on Unix; unsupported platforms fail closed
before private state is created. Runtime deployment must additionally mount
configuration and credential files read-only, expose only the exact provider
endpoint through egress policy, place the state directory on a bounded durable
volume, and use a dedicated service identity. Host/provider administrator
compromise remains outside application-level containment.

## Certified configuration and agent class

The canonical configuration digest binds:

- protocol, provisioner implementation/deployment/operator identities, and
  monotonic generation;
- provider endpoint identity, provider/account/region/API version, scoped grant
  identity/scope/expiry/token digest, private CA digest, and provider
  attestation-key identity/content digest;
- receipt-signing key identity/content digest and private state directory;
- immutable agent-class, template, image, bootstrap, and toolchain identities
  and SHA-256 digests;
- platform, capabilities, and trust pool;
- exact network, volume, workspace, and cache policies;
- short-lived instance identity issuer/audience/role/IAM-policy digest and
  maximum TTL;
- global, tenant, and project active-instance quotas; and
- provider timeout, startup timeout/polling, and instance-lifetime bounds.

V1 denies inbound network access and instance metadata, requires an explicit
bounded egress allowlist, rejects host mounts, requires every admitted volume
to be bounded and destroyed on release, and requires an encrypted ephemeral
workspace destroyed on release. A cache is either disabled, read-only, or
isolated read-write under an exact namespace/trust class and size bound.
The provider's signed effective agent specification must equal the request and
certified configuration exactly. A broadened network, volume, workspace,
cache, capability, trust-pool, platform, template, image, bootstrap, or
toolchain response is substitution, not successful provisioning.

## Request, fencing, and quota admission

Each provision request binds a UUID request/idempotency key; tenant, project,
build, attempt, and fence; exact executable/configuration/generation;
current/cutover/rollback generation relation; provider endpoint/account/region
and grant; complete agent specification; command and instance expiry; and audit
lineage. Unknown or duplicate JSON members are rejected recursively. Commands
are capped at 128 KiB, and command authority expires within five minutes.
Instance lifetime is separately capped by configuration and does not borrow
authority from the command after admission.

The provisioner takes an immediate SQLite transaction before provider access.
It rejects a conflicting request-ID replay, a fence not strictly greater than
the maximum retained fence, or a newer fence while older compute remains
active. Global, tenant, and project quotas count `intent`, `ambiguous`,
`pending`, `ready`, and `deleting` records; a capacity denial creates no intent
and reaches no provider.

The durable intent commits and synchronizes before the create call. The request
UUID is the provider idempotency key and the complete provider create request
contains the canonical request digest. A peer process seeing the same intent
waits through the bounded create window, then recovers by signed lookup rather
than issuing a second create. Receipt publication is serialized in SQLite; two
peers reaching the same state return the same first signed receipt.

## Provider authentication and lifecycle

Every call sends only the prevalidated bearer grant and exact provisioner/grant
headers. Grant expiry is rechecked immediately before network access. Provider
responses are capped at 256 KiB plus a 64 KiB aggregate header-value ceiling,
reject duplicate JSON members, deny unknown fields, and carry an Ed25519
attestation over protocol, provider endpoint/account/region/API/key identity,
and the complete typed payload. Lookup, inventory, instance, and deletion
observations must be fresh relative to the exact request window. A signed
payload cannot be replayed for another request, instance, provider, account,
region, or generation.

The lifecycle is `intent -> pending -> ready` or a fail-closed cleanup path.
Create and pending startup are admitted only inside one absolute earlier
command, provider-grant, instance, and configured startup deadline. Startup failure, timeout, agent
loss, cancellation, expiry, effective-spec substitution, supersession, and
owned orphan discovery all enter deletion. Deletion success requires both a
signed absent result and a fresh signed lookup returning no instance. A timeout,
partition, malformed/unattested response, or uncertain deletion becomes
`ambiguous`; it never claims cleanup or silently creates again.
The deadline is rechecked after create and every provider lookup, so a late
`Ready` observation is cleaned as a timeout rather than admitted.

## Crash, partition, orphan, and scale-down truth

The private SQLite database uses `synchronous=FULL`, a closed state enum, exact
request JSON/digest, provider instance evidence, and append-only signed receipt
rows. Its immutable ledger scope binds the provisioner, provider endpoint,
account, region, API and attestation identity, grant scope, agent class, and
instance identity policy; a later runtime cannot reinterpret retained state
through another provider scope. The relevant recovery cases are:

- controller crash: replaying the same command returns the retained receipt or
  performs lookup-only recovery; controller storage is not consulted, and a
  signed absence preserves `ready` as agent loss and `deleting` as cancellation
  rather than collapsing either into startup failure;
- provisioner crash before create: the durable intent is eventually reconciled
  to signed absence without creating; a fresh absent intent, ambiguous create,
  or pending record remains non-terminal through the bounded peer-create window
  so reconciliation cannot race an in-flight provider call;
- provisioner crash after provider create but before response: signed lookup by
  idempotency key adopts the one provider instance;
- crash/partition during delete: the record remains deleting/ambiguous until a
  signed absence proof exists;
- agent startup failure or later loss: reconciliation deletes the instance and
  retains the exact outcome;
- unknown provider-owned instance: a complete signed inventory identifies the
  orphan, deletion is confirmed by signed absence, and the reconcile receipt
  binds the orphan instance ID; and
- expiry/scale-down: cleanup uses the provisioner's separately scoped current
  provider grant, not an expired build command.

Reconciliation signs the initial and final complete inventory digests plus the
exact active instance IDs, cleaned request IDs, orphan instance IDs, ambiguous
request IDs, and counts. `escaped_compute_remaining` is explicit. A nonzero
value is evidence of an unresolved safety condition, never success. Retained
active compute is admitted only when its request remains in durable `ready`
state, its signed effective specification is exact, and its instance expiry is
still in the future.

## Receipts and downstream use

Lifecycle HMAC-SHA-256 receipts bind the complete request digest and scope,
request-expected and observing provisioner implementation/configuration/
generation identities, activation relation, provider/account/region/grant,
agent specification, optional instance and short-lived identity grant,
observation time, ambiguity/cleanup truth, audit lineage, signing key, and a
monotonic retained evidence sequence. The provider attestation key is distinct
from the provisioner receipt key. Because the controller-side verifier shares
the HMAC key, verifier/provisioner collusion remains residual risk and must be
addressed by later differential and production qualification gates.

No receipt grants scheduler, trigger, workload-credential, external connector,
canary, cutover, rollback, decommission, or release authority. Those gates must
re-read the exact deployed process, configuration, provider/account/region,
template/image/policies, identity grant, final inventory, and receipt verifier,
and must reject drift. `current`, `cutover`, and `rollback` modes prove only the
generation-binding protocol against contained fixtures; they do not claim a
Mario production transition.

## Executable proof

`crates/provisioner/tests/contained_provisioner.rs` drives a real signed HTTP
provider and the standalone binary. It covers ready startup, pending-to-ready,
template substitution, startup failure and timeout, exact replay, concurrent
cross-process one-create/one-receipt convergence, stale/reordered fences,
quota exhaustion, invalid network/volume/provider/account/region/image/
bootstrap bindings, cancellation, ambiguous create plus restart recovery,
lost delete-response recovery, orphan cleanup, agent loss, expiry/scale-down,
final-inventory substitution with explicit escaped-compute truth and duplicate
identity denial,
cutover/rollback generation binding, recursive duplicate-JSON denial,
pre-state invalid-configuration denial, and provider-token/receipt-key
non-disclosure. Reopening retained state under a substituted provider scope is
also denied before any provider access. Exact state-directory/database modes
reject special permission bits, and the standalone process accepts a bounded
final NDJSON frame whether or not it ends with a newline.

`crates/provisioner/tests/mario_inventory.rs` pins and parses the accepted
MIG-000 manifest and proves the current Mario denominator has zero admitted
dynamic provisioners.
