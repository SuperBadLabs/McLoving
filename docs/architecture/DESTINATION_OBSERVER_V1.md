# Destination observer v1

Status: OBS-001 contained implementation contract. No Mario production effect,
canary, cutover, rollback, or decommission authority is claimed.

## Inventory boundary

The sealed Mario scenario contract denies effect authority and canary
eligibility, every one of its scenario families remains unsupported, and all
230 jobs in the bound eligibility ledger remain unsupported. There is therefore
no admitted production destination-observer mapping. OBS-001 supplies a reusable
contained observer boundary; a later inventory generation must name each effect
class, endpoint, account, resource, typed state, and grant before it can earn
authority.

## Deployment and authority boundary

`mcloving-destination-observer` is a standalone strict-NDJSON process. One
deployment observes one destination and effect class. A deployment uses its own
service identity, read-only credential grant, credential-issuance path,
configuration authority, runtime boundary, operator trust identity, request
authority public key, destination-attestation public key, and receipt-signing
key. These identities and authority-material digests must be distinct and may
not match configured runner or connector identities or denied authority
digests.

The process can issue only an HTTP `GET` to its configured endpoint, read and
write its private SQLite evidence ledger, and return signed receipts. It has no
write method, redirect or proxy inheritance, implicit HTTP retry, scheduler,
controller database or filesystem, agent RPC, shell, repository, workload
secret, connector-control, or external-effect capability. Production requires
HTTPS with a content-pinned private CA bundle. Plain HTTP is accepted only when
both the explicit test flag and a literal loopback address are present.

The standalone process accepts bounded newline-complete frames from stdin and
emits generic bounded responses on stdout. Configuration and authority files
are opened without following a final symlink; secret files and the state
directory must be owned by the process user and inaccessible to group or other
users. The executable, image, complete configuration, read token, three signing
authorities, CA, and secret-marker set are digest-bound before the ledger opens.

## Signed request and canonical read

An Ed25519-signed observation request binds the protocol and schema versions,
observation ID, tenant, project, pipeline, build, attempt, effect fence, phase,
observer and request authority, exact implementation/image/configuration and
monotonic generation, cutover or rollback provenance, endpoint/account/resource
and effect class, grant ID/version/scope, canonical allowlisted query, prior
cursor and predecessor receipt, short validity window, and audit provenance.
Unknown fields, duplicate JSON members, unknown query keys, stale requests,
substituted bindings, or invalid signatures fail before network access.

The observer persists a pending claim in a `synchronous=FULL` WAL ledger before
the GET. An observation ID can be replayed only with byte-identical canonical
request truth. A completed replay returns the same receipt without another GET;
a pending replay is the only retry path and is bounded. Completed evidence is
returned even after the request or grant window closes because no new authority
is exercised. Expired, generation-fenced, explicitly failed, or retry-exhausted
pending claims become bounded failure tombstones and release the destination;
only complete evidence consumes the receipt-count and evidence-byte quotas. A
unique pending claim per destination scope prevents competing reads across
builds and effect fences. Rate, receipt-count, evidence byte, response, header,
timeout, freshness, and retry limits are configuration authority.

## Destination attestation and state ordering

The destination returns strict JSON containing a typed state body and a
detached Ed25519 signature. The signed body binds the observation, observer and
destination service identities, endpoint/account/resource/effect class and
effect fence, phase, canonical-query digest, monotonically advancing cursor,
observation time, state schema and confidentiality, complete typed state,
grant, and destination key ID. Only status 200 with `application/json` is
admitted. Authentication denial remains a typed denial; all other missing or
unavailable outcomes remain failures, never evidence of absence.

Response headers and every streamed body chunk are continuously bounded. The
complete raw response and decoded JSON are checked against the configured
secret markers and their common Base64, hexadecimal, and percent encodings.
Secret-labelled state is denied. Fields not in the closed response schema,
wrong JSON types, stale or future observations, substituted signatures or
bindings, and a cursor that does not advance from the signed predecessor are
denied.

Each effect fence admits exactly this chain:

1. `pre_action` with no predecessor;
2. `post_action` naming the exact pre-action receipt and cursor; and
3. zero or more `reconciliation` reads, each naming the exact post-action or
   reconciliation receipt and cursor.

Suppression, fabrication, and reordering cannot create a valid chain. A runner
or connector possesses neither the request-authority private key, destination
attestation private key, read credential, configuration authority, nor receipt
signing seed, so compromising either effectful peer does not grant observation
authority.

## Receipt and generation fencing

The observer signs a versioned receipt with its independent Ed25519 key. The
receipt binds the complete request scope and provenance, canonical query,
implementation/image/configuration and every deployment identity, monotonic
generation/cutover/rollback fields, grant, destination cursor and observation
time, capture and publication deadline, typed state and confidentiality,
complete raw response digest and destination signature, retry count, audit
provenance, receipt sequence, key identity, and public-key digest.

The complete signed standalone success envelope must fit the process frame
before the pending claim can commit. An oversized envelope becomes a failed
claim, never committed evidence followed by an error-only response. Stored
completed receipts are signature-, binding-, and frame-size-verified again on
every replay.

Every claim, sequence allocation, and finalization rereads the active
generation/configuration fence. Cutover requires a greater generation and the
exact active predecessor. Rollback is also a new greater generation and names
the generation it fences; it never resurrects an old process. A process fenced
during a network call cannot finalize evidence. Credential rotation is a new
configuration generation with a new exact grant and token digest.

## Required proof and residual boundary

Contained tests cover signed pre/post/reconciliation reads, exact completed
replay, durable pending restart/retry, signature and request substitution,
phase and cursor rollback, stale, malformed, oversized, resource-substituted,
secret-bearing body and header, timeout, outage, destination permission denial,
grant expiry, configuration and credential substitution, receipt verification,
duplicate protocol fields, and bounded frames. A sealed-inventory test proves
that none of this contained evidence grants Mario authority.

The trusted Unix host and containing directories, deployment/configuration and
credential operators, private CA and destination attestation owner, request
authority, destination implementation, system clock, and independently retained
receipt verifier remain trusted. Transformed secrets outside the marker set are
residual risk. Real effect-class inventory, live destination behavior,
least-privilege platform policy, canary, cutover, rollback, and decommission
remain future ticket gates.
