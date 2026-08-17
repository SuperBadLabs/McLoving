# External connector v1

Status: EXT-001 contained implementation contract. No Mario production effect,
canary, cutover, rollback, or decommission authority is claimed.

## Purpose and modular boundary

`mcloving-external-connector` is the sole effectful boundary for one exact
versioned action at one endpoint, account, resource, and effect class. Pipeline
runners produce typed intent but never receive the connector credential. The
connector has no scheduler, controller database or filesystem, agent RPC,
repository, shell, unrelated secret, observer-control, or shadow-control
authority. This keeps effect transport replaceable: a Fogell or McLoving runner
can produce the same signed request, and either can consume the same bounded
outcome and shadow receipts without sharing a runtime implementation.

The package ships two distinct standalone strict-NDJSON processes:

- `mcloving-external-connector` owns the production endpoint credential and its
  private authoritative evidence ledger.
- `mcloving-external-shadow-replay` has no endpoint URL, transport client, or
  production credential. It accepts only a verified connector receipt and
  replays its confidentiality-safe typed truth exactly once into the
  deny-authority shadow. Deployment enters the named
  `mcloving-external-shadow-replay` AppArmor profile, whose explicit network
  denial is exercised by a protected live probe. The profile is enforcing—not
  AppArmor's allow-everything `unconfined`, `default_allow`, or `complain`
  mode—and grants broad file/inherited-execution access only so filesystem
  policy remains a separate deployment boundary.

The effectful connector, independently deployed `OBS-001` destination observer,
and shadow replayer use distinct service, configuration, request, credential,
attestation, receipt, and operator identities. None can impersonate or configure
another. A later deployment must enforce the same separation at the process,
credential-issuance, configuration, and operator boundaries.

## Authority and configuration

Configuration schema `mcloving.external-connector-config/v1` binds:

- exact connector implementation and runtime-image SHA-256 plus a pinned runtime
  attestation authority;
- deployment, operator, runtime, service, configuration, request, credential
  issuance, and independent observer identities;
- monotonic generation plus current, cutover, or rollback provenance;
- exact endpoint URL and endpoint, account, resource, effect-class identities;
- action name, request schema, closed typed scalar request-payload fields and
  closed typed scalar public-output fields, and allowed secret taints; nested
  request or output structures are not admitted by v1 because a kind-only
  object/array would not be closed;
- short-lived credential grant identity, version, scope, expiry, and token
  digest;
- pairwise-distinct request, destination-attestation, outcome-signing,
  observer-receipt, and runtime-attestation keys, with the credential token and
  private outcome seed also distinct from every authority role in every
  32-byte window of the bounded raw token and its complete or segmented
  standard/Base64URL (padded or unpadded) and hexadecimal decodings;
- the complete certified `OBS-001` implementation/image/configuration,
  deployment/operator/runtime/service/configuration/request/credential path,
  generation ancestry, destination, read grant, canonical query, state schema,
  confidentiality, destination-attestation, and receipt-signing mapping;
- denied peer identities and denied authority digests; and
- request, response, public-output, evidence, timeout, retry, and authority-window
  bounds.

Production transport requires HTTPS, a nonempty content-pinned private CA
bundle, disabled proxy inheritance, and no redirects. Literal HTTP loopback is
compiled only with the `loopback-test` feature and must also be explicitly
enabled by test configuration. The loader opens configuration, key, token, and
secret-marker files without following a final symlink; private inputs must be
single-link regular files owned by the process user and inaccessible to group or
other users.

Generation 1 is necessarily `current` with no predecessor, predecessor digest,
or rollback source. A later `cutover` names the active generation and its exact
configuration digest as its predecessor and has no rollback source. A later
`rollback` names a lower, durably retained historical generation plus its exact
configuration digest as the target, while `rollback_from_generation` names the
currently active source. The new generation remains monotonic. Impossible or
mixed-mode provenance is rejected before the ledger opens; the ledger then
verifies cutover ancestry against the active row and rollback ancestry against
both the active row and the bounded immutable runtime-history table. The signed
outcome and shadow bindings carry the target generation and digest plus the
active rollback source.

Runtime-history growth is bounded by `max_runtime_history`; exact-generation
restart remains available at the bound, while another cutover or rollback fails
closed. The state directory must be a real owner-private directory, not a symlink. Each
SQLite database is pre-created through `O_NOFOLLOW` as an owner-private,
single-link regular file before SQLite opens it. The database, WAL, and shared
memory sidecars are revalidated after WAL activation. Both ledgers use
`synchronous=FULL`, bounded writer waiting, and immediate transactions for
claims and final evidence. Admission durably attaches two evidence-slot
reservations to every pending effect, including across a pre-dispatch crash, so
an ambiguous receipt can always retain its original truth and append the
required reconciliation receipt. A fixed owner-private nonblocking lineage lease is
held across claim, transport, and finalization; a separate fixed lease covers
shadow replay. Overlapping processes therefore cannot dispatch or replay the
same pending truth concurrently.

## Signed action protocol

Protocol `mcloving.external-connector/v1` accepts an Ed25519-signed
`mcloving.external-action-request/v1`. It binds request, tenant, project,
pipeline, build, attempt, effect fence and key; exact connector implementation,
image, configuration and generation; endpoint/account/resource/effect class;
idempotency class; action and schema; canonical typed payload; credential grant;
validity window; and audit provenance.

Unknown or duplicate members, nil identifiers, invalid signatures, stale or
oversized requests, divergent runtime/endpoint/grant bindings, empty physical
authority/key/grant identifiers, payload fields or types outside the exact
  configured closed scalar schema, and secret-marker disclosure in public request fields
fail before transport. Secret markers cover
raw, standard-Base64, unpadded-Base64, hexadecimal, and percent-encoded forms.
The connector token itself must be in the marker set, so accidental reflection
is denied. Decoded Base64 payloads are searched at every byte offset, including
when a marker is wrapped by non-secret bytes.

Production construction is crate-private to the standalone loader. Before it
reads a connector token or signing seed or opens state, it verifies a short-lived
Ed25519-signed runtime attestation from a configuration-pinned authority. The
attestation binds the executing-inode digest read through `/proc/self/exe`,
runtime-image and complete configuration digests, workload/deployment/runtime
identities, and the live Linux boot ID, mount-namespace inode, and cgroup digest.
A copied digest assertion from another image, container, namespace, boot, or
configuration therefore fails. Loopback construction and synthetic time exist
only under the `loopback-test` feature. Production samples trusted wall time
internally and resamples it immediately before dispatch and again when outcome
or ambiguity evidence is captured; the complete transport timeout must still fit
inside both request and grant expiry.

The connector binary accepts, in order, owner-private paths for configuration,
runtime attestation, runtime-attestation public key, request public key,
destination public key, outcome signing seed, observer public key, connector
token, and secret markers. The shadow binary accepts configuration, runtime
attestation, runtime-attestation public key, connector-receipt public key, and
replay signing seed, and secret markers. Unknown or missing arguments fail
closed.

Before an HTTP request, the connector commits an immutable request digest,
physical effect-scope key, idempotency class, attempt count, and pending claim.
It then commits `dispatched=true` and the trusted pre-send timestamp immediately
before transport. Crash recovery clamps ambiguity capture strictly after that
durable dispatch boundary even if the host clock moves backward. A request ID can
be reused only with byte-identical canonical truth. A completed replay returns
the exact stored signed receipt without another HTTP request. Each
tenant/project/attempt/fence/effect key is durably single-use across pending,
ambiguous, reconciled, failed, and successful rows. New authority requires a new
certified fence/scope; a different request ID cannot bypass uncertainty.
Configuration rotation must advance in place from the exact recorded previous
generation. It atomically updates the runtime fence while retaining the same
request/scope ledger; a later generation cannot bootstrap an empty directory or
bypass permanent physical-scope deduplication. Rotation is rejected while any
claim is pending or any ambiguous outcome still reserves its reconciliation
slot. Retry, terminalization, and reconciliation therefore complete under the
original request and outcome-signing generation before its authority is fenced.

Retry behavior is closed by idempotency class:

- `idempotent` and `externally_idempotent` may retry only up to the configured
  bound and always reuse the same signed request ID and digest;
- `non_idempotent` is never retried after dispatch; timeout, connection loss, or
  process death after the durable dispatch marker becomes `ambiguous`;
- for retry-safe actions, authentication, malformed/substituted/oversized
  response, and confidentiality failures are durable failures; for a
  non-idempotent action those same post-dispatch unverifiable outcomes are
  `ambiguous`, because the destination may have committed before returning bad
  evidence; and
- retry exhaustion is a signed `retryable_failure`, not a fabricated success or
  absence claim.

## Typed destination outcome

The destination returns a signed
`mcloving.external-action-response/v1`. Its body repeats the request digest and
all physical authority bindings, then supplies:

- one closed status: `succeeded`, `failed`, `retryable_failure`, or `ambiguous`;
- a typed status code;
- canonical public values matching the configured closed schema;
- protected secret references containing provider, reference, version, and an
  allowlisted taint, never secret bytes;
- external identifiers;
- downstream-control and later-intent digests; and
- completion time, exact grant binding, and destination attestation identity.

Only HTTP 200 `application/json` is admitted. For retry-safe actions,
authentication denial is permanent and other non-success status/transport
failure is unavailable. After a non-idempotent dispatch, either class is
ambiguous unless a valid signed destination outcome proves the result. Response
headers and the bounded complete body are secret-scanned. The detached
destination signature and every request/endpoint/grant binding are verified
before a receipt can be committed.

The connector emits a signed
`mcloving.external-outcome-receipt/v1` containing the complete action authority,
request-payload digest, typed outcome, public values, protected references,
external IDs, control-flow and later-intent digests, destination evidence,
attempt count, exact credential grant, ambiguity truth, audit provenance,
outcome-signing identity, and—after the durable dispatch marker is committed—the
freshly resampled and revalidated pre-send `dispatched_at_unix_ms`. The marker's
earlier timestamp is crash-recovery evidence and cannot authenticate the send.
A terminal result produced before dispatch
omits that optional field. Because absent optional fields are not serialized,
previous valid v1 pre-dispatch receipts retain their canonical signed form.
Receipts are stored durably and count against a fixed evidence quota.

## Independent ambiguity reconciliation

An ambiguous non-idempotent effect freezes new authority for that effect. It can
be resolved only by `mcloving.external-reconcile-request/v1` carrying a valid
signed `OBS-001` reconciliation receipt from the separately configured observer
key and complete certified observer mapping. The observation must bind the same
tenant, project, pipeline, build, attempt, effect fence, endpoint, account,
resource, and effect class, plus the pinned observer implementation, image,
configuration, generation ancestry, deployment identities, read grant, canonical
query, state schema, confidentiality class, and signing/attestation identities.
Its destination-observed and captured times must be no earlier than the durable
post-dispatch ambiguity capture and no later than the reconciliation clock. Its
typed state must contain exactly the connector request digest and whether the
effect is present. Presence is positive causal evidence and may resolve the
ambiguity. Absence is only a point-in-time observation: a timed-out request may
still commit after it, so absence remains ambiguous until a future protocol
version carries a destination-signed terminal-request or cursor/fence barrier
proving that the original request can no longer commit.

For observed presence, the connector appends a new signed `succeeded` outcome
receipt, preserving the ambiguous receipt in evidence and binding the observation
receipt digest. Observed absence fails reconciliation without changing the
ambiguous receipt or releasing its reservation. Connector self-report, runner
state, destination response replay, unsigned operator assertion, or causally
unfenced absence cannot unfreeze ambiguity.

## Deny-authority shadow replay

The shadow protocol `mcloving.external-shadow-replay/v1` accepts the complete
signed connector receipt plus its expected digest, replay ID, shadow identity,
caller timestamp claim, and audit provenance. The caller timestamp remains part
of the canonical request digest for replay identity but is not trusted as replay
evidence. The replayer first verifies and durably claims the exact replay lineage
and outcome, then samples the host clock and signs that completion-boundary value
as `replayed_at_unix_ms`; sampling at request entry is forbidden. Configuration contains no endpoint
URL or connector token. It explicitly lists production endpoint identities that it is forbidden
to own; a replay must describe one of those denied endpoints. It also pins the
connector receipt's complete implementation/image/configuration,
deployment/runtime/service and authority identities, generation ancestry,
endpoint/account/resource/effect, action/schema, credential grant, and
outcome-signing mapping. A valid receipt from an old or differently scoped
connector is rejected.

Shadow audit provenance is scanned against the owner-private marker set before
request hashing, signing, or persistence. Raw, hexadecimal, percent-encoded,
and normalized Base64 representations—including markers at nonzero decoded
offsets—fail with `confidentiality_denied`; a denied replay ID remains unused.

The shadow loader applies the same short-lived signed live-runtime attestation
check as the effectful loader before reading its replay signing seed or opening
state. The AppArmor probe first verifies the live named non-complain label and
then requires the kernel to reject an IPv4 stream socket with permission denied;
the policy source denies all network families. Shadow construction requires its
connector-receipt, replay-signing, and runtime-attestation public keys to be
pairwise distinct and rejects replay-secret material equal to any public
authority-key bytes, so deny-authority compromise cannot mint connector outcomes
or attest a substituted runtime. The shadow ledger is fenced to the complete canonical shadow
configuration; a changed signing or replay-authority mapping cannot return a
receipt stored under the prior configuration.

The shadow verifies the connector receipt and stores an exactly-once replay keyed
by both replay ID and outcome digest. A FULL-synchronous claim transaction first
durably records that verified replay; only then is completion time sampled and
the signed receipt retained. A crash between those transactions resumes receipt
finalization without re-running or backdating the replay. Exact restart replay returns the same
signed `mcloving.external-shadow-receipt/v1`; divergent reuse fails. The receipt
contains only typed outcome truth, public values, protected references, external
IDs, and downstream-control/later-intent digests. It cannot execute an external
effect.

## Contained acceptance

The standard crate gate proves:

- signed success and exact replay across restart without a second effect;
- bounded retry for an externally idempotent request with one stable identity;
- timeout ambiguity and zero retry for a non-idempotent request;
- ambiguity freeze across a different request ID in the same physical scope and
  terminalization after a final-attempt pre-dispatch crash;
- non-idempotent malformed post-dispatch evidence becoming ambiguity rather than
  a false failure;
- malformed, substituted, secret-bearing, stale, signature-substituted,
  divergent-replay, and permission-negative denial;
- extra/wrong-typed request payload and empty authority-mapping denial;
- signed observer-only ambiguous-effect reconciliation with stale and substituted
  deployment/configuration denial;
- exactly-once signed shadow replay across restart with no endpoint authority and
  substituted connector mapping denial;
- fresh signed runtime attestation and live boot/namespace/cgroup binding;
- pairwise connector authority-key and connector/shadow signing-key separation;
- durable dispatch-time recovery under backward clock movement;
- evidence-capacity reservation for the original ambiguity plus reconciliation;
- crash-after-dispatch recovery into ambiguity; and
- permissive or symlinked state-directory denial, cross-process lease
  contention, private SQLite evidence, and live AppArmor network denial for the
  shadow process.

The sealed Mario inventory grants zero production external-effect authority.
`SECRET-001`, `DIFF-003`, `CANARY-001`, cutover, rollback, and decommission must
bind real connector mappings, credentials, observations, releases, and live
receipts before any production authority is granted.
