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
  denial is exercised by a protected live probe.

The effectful connector, independently deployed `OBS-001` destination observer,
and shadow replayer use distinct service, configuration, request, credential,
attestation, receipt, and operator identities. None can impersonate or configure
another. A later deployment must enforce the same separation at the process,
credential-issuance, configuration, and operator boundaries.

## Authority and configuration

Configuration schema `mcloving.external-connector-config/v1` binds:

- exact connector implementation and runtime-image SHA-256;
- deployment, operator, runtime, service, configuration, request, credential
  issuance, and independent observer identities;
- monotonic generation plus current, cutover, or rollback provenance;
- exact endpoint URL and endpoint, account, resource, effect-class identities;
- action name, request schema, closed public-output schema, and allowed secret
  taints;
- short-lived credential grant identity, version, scope, expiry, and token
  digest;
- request, destination-attestation, outcome-signing, and observer-receipt keys;
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

The state directory must be a real owner-private directory, not a symlink. Each
SQLite database is pre-created through `O_NOFOLLOW` as an owner-private,
single-link regular file before SQLite opens it. The database, WAL, and shared
memory sidecars are revalidated after WAL activation. Both ledgers use
`synchronous=FULL`, bounded writer waiting, and immediate transactions for
claims and final evidence. A fixed owner-private nonblocking lineage lease is
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
oversized requests, divergent runtime/endpoint/grant bindings, and secret-marker
disclosure in public request fields fail before transport. Secret markers cover
raw, standard-Base64, unpadded-Base64, hexadecimal, and percent-encoded forms.
The connector token itself must be in the marker set, so accidental reflection
is denied.

Production construction is crate-private to the standalone loader. It hashes
the executing inode through `/proc/self/exe`, verifies the separately mounted
runtime-image attestation, then binds both to the complete configuration before
opening state. Loopback construction and synthetic time exist only under the
`loopback-test` feature. Production samples trusted wall time internally and
resamples it after ledger/lease delay immediately before dispatch; the complete
transport timeout must still fit inside both request and grant expiry.

Before an HTTP request, the connector commits an immutable request digest,
physical effect-scope key, idempotency class, attempt count, and pending claim.
It then commits `dispatched=true` immediately before transport. A request ID can
be reused only with byte-identical canonical truth. A completed replay returns
the exact stored signed receipt without another HTTP request. A unique pending
claim per tenant/project/attempt/fence/effect key prevents competing actions.

Retry behavior is closed by idempotency class:

- `idempotent` and `externally_idempotent` may retry only up to the configured
  bound and always reuse the same signed request ID and digest;
- `non_idempotent` is never retried after dispatch; timeout, connection loss, or
  process death after the durable dispatch marker becomes `ambiguous`;
- terminal authentication, malformed/substituted/oversized response, and
  confidentiality failures are durable failures; and
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

Only HTTP 200 `application/json` is admitted. Authentication denial is
permanent. Other non-success status and transport failure are unavailable.
Response headers and the bounded complete body are secret-scanned. The detached
destination signature and every request/endpoint/grant binding are verified
before a receipt can be committed.

The connector emits a signed
`mcloving.external-outcome-receipt/v1` containing the complete action authority,
request-payload digest, typed outcome, public values, protected references,
external IDs, control-flow and later-intent digests, destination evidence,
attempt count, ambiguity truth, audit provenance, and outcome-signing identity.
Receipts are stored durably and count against a fixed evidence quota.

## Independent ambiguity reconciliation

An ambiguous non-idempotent effect freezes new authority for that effect. It can
be resolved only by `mcloving.external-reconcile-request/v1` carrying a valid
signed `OBS-001` reconciliation receipt from the separately configured observer
key and identity. The observation must bind the same tenant, project, build,
attempt, effect fence, endpoint, account, resource, and effect class. Its typed
state must repeat the connector request digest and whether the effect is present.

The connector appends a new signed outcome receipt, preserving the ambiguous
receipt in evidence. Observed presence becomes `succeeded`; observed absence
becomes a terminal `failed` outcome. The observation receipt digest is bound to
the new outcome. Connector self-report, runner state, destination response
replay, or unsigned operator assertion cannot unfreeze ambiguity.

## Deny-authority shadow replay

The shadow protocol `mcloving.external-shadow-replay/v1` accepts the complete
signed connector receipt plus its expected digest, replay ID, shadow identity,
time, and audit provenance. Configuration contains no endpoint URL or connector
token. It explicitly lists production endpoint identities that it is forbidden
to own; a replay must describe one of those denied endpoints.

The shadow verifies the connector receipt and stores an exactly-once replay keyed
by both replay ID and outcome digest. Exact restart replay returns the same
signed `mcloving.external-shadow-receipt/v1`; divergent reuse fails. The receipt
contains only typed outcome truth, public values, protected references, external
IDs, and downstream-control/later-intent digests. It cannot execute an external
effect.

## Contained acceptance

The standard crate gate proves:

- signed success and exact replay across restart without a second effect;
- bounded retry for an externally idempotent request with one stable identity;
- timeout ambiguity and zero retry for a non-idempotent request;
- malformed, substituted, secret-bearing, stale, signature-substituted,
  divergent-replay, and permission-negative denial;
- signed observer-only ambiguous-effect reconciliation;
- exactly-once signed shadow replay across restart with no endpoint authority;
- crash-after-dispatch recovery into ambiguity; and
- permissive or symlinked state-directory denial, cross-process lease
  contention, private SQLite evidence, and live AppArmor network denial for the
  shadow process.

The sealed Mario inventory grants zero production external-effect authority.
`SECRET-001`, `DIFF-003`, `CANARY-001`, cutover, rollback, and decommission must
bind real connector mappings, credentials, observations, releases, and live
receipts before any production authority is granted.
