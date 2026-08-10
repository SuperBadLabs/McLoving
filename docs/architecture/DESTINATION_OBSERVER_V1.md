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
write its private SQLite evidence ledger, and return signed receipts. SQLite
writers use a bounded busy wait so a restart or generation cutover converges
when the prior process is completing a transaction. It has no
write method, redirect or proxy inheritance, implicit HTTP retry, scheduler,
controller database or filesystem, agent RPC, shell, repository, workload
secret, connector-control, or external-effect capability. Production requires
HTTPS with a content-pinned, nonempty private CA bundle. Plain HTTP is accepted only when
both the explicit test flag and a literal loopback address are present.
The only public direct constructor is restricted to that literal-loopback test
boundary. Production construction is crate-internal to the standalone loader,
which supplies the measured executable digest and sealed runtime-image digest.

The observer is a fail-closed Linux process: its implementation digest is read
from the kernel's `/proc/self/exe` handle for the executing inode, never by
reopening a replaceable executable pathname. The standalone process accepts
bounded newline-complete frames from stdin; the newline is included in the
frame-size limit. Crossing that bound produces `oversized_request` and
terminates immediately without draining an attacker-controlled tail. It emits
generic bounded responses on stdout. Configuration
and authority files
are opened without following a final symlink; the complete configuration,
deployment-provided runtime-image attestation file, secret files, and the state
directory must be owned by the process user and inaccessible to group or other
users. The executable is measured through `/proc/self/exe`; the separately
mounted runtime-image digest must match the image identity certified by
configuration. The executable, image, complete configuration, read token, three signing
authorities, CA, and secret-marker set are digest-bound before the ledger opens.
The startup denylist is applied to every authority digest and to the attested
executable, image, complete configuration, CA bundle, prior configuration, and
secret-marker-set digests; duplicate or malformed denylist entries fail closed.

## Signed request and canonical read

An Ed25519-signed observation request binds the protocol and schema versions,
observation ID, tenant, project, pipeline, build, attempt, effect fence, phase,
observer and request authority, exact implementation/image/configuration and
monotonic generation, cutover or rollback provenance, endpoint/account/resource
and effect class, grant ID/version/scope, canonical allowlisted query, prior
cursor and predecessor receipt, short validity window, and audit provenance.
Unknown fields, duplicate JSON members, unknown query keys, stale requests,
substituted bindings, or invalid signatures fail before network access.
Configuration admission rejects query-key names beyond the request-protocol
bound and header budgets too small for the mandatory JSON response header.
It also proves that the largest legal signed request fits the complete NDJSON
frame before the ledger opens. Response headers are confidentiality-scanned
before status or size classification, including non-success responses.
The HTTP/2 decoder has a fixed 256 KiB hard ceiling above the lower certified
application header budget, allowing bounded oversized blocks to be scanned
before they are classified as application overflows.
The GET carries reserved non-secret headers for the observation ID, effect
fence, phase, canonical-query digest, and complete signed-request digest. An
independently deployed destination therefore receives every fresh binding it
must echo and sign without shared process state.

The observer persists a pending claim in a `synchronous=FULL` WAL ledger before
the GET. An observation ID can be replayed only with byte-identical canonical
request truth. A completed replay returns the same receipt without another GET;
a stored terminal replay is checked before taking the live destination lease,
and a pending replay is temporally fenced and tombstoned there as well, so
unrelated destination activity or availability cannot suppress either outcome;
a pending replay is the only retry path and is bounded. Completed evidence is
returned after the request or grant window closes while it remains inside the
bounded replay-retention window because no new authority is exercised. After
retention pruning, the expired signed request is denied without another GET.
Expired, generation-fenced, explicitly failed, or retry-exhausted
pending claims become bounded failure tombstones and release the destination;
if a concurrent in-flight read returns after that transition, its failure
bookkeeping or successful finalization converges on and returns the stored
tombstone instead of replacing it, surfacing a replay mismatch, or returning a
different local terminal error;
terminal authentication, validation, confidentiality, freshness, cursor, body,
and evidence-envelope size denials do the same immediately. HTTP/2 decoder or
application header-list overflow is treated as destination unavailability and,
like other transport outages, retains the bounded pending retry path;
request and grant validity are checked again at the monotonic GET-completion
time before any receipt can be signed. They are also resampled after ledger and
lease delays immediately before dispatch, so authority that expires while
waiting cannot cause a GET;
only complete evidence consumes the receipt-count and evidence-byte quotas.
Replay and new-admission transactions prune complete and failed observations
whose signed request expiry is more than one freshness window old before they
serve terminal state or enforce quotas. Orphaned phase/cursor heads are pruned
with them, while heads for a still-retained chain remain durable.
Every initial or retrying outbound GET reserves a durable timestamped outbound
intent in the same claim transaction, so process death cannot bypass the
per-minute rate limit. That conservative reservation expires with the rate
window, but the retry-failure counter advances only after the transport returns
an actual destination-unavailable result; a crash between reservation and GET
therefore cannot falsely exhaust the observation's retry budget. A
unique pending claim per destination scope prevents competing reads across
builds and effect fences. A nonblocking kernel lease held for the complete
observation call also prevents a same-ID retry or overlapping process from
duplicating an in-flight GET; process exit releases the lease for restart.
That physical-destination contention key is separate from cursor history:
cursor heads are keyed by tenant/project/pipeline, destination, effect fence,
and canonical query, so independent chains can attest equal snapshots.
Receipt-count and evidence-byte quotas are rechecked in the atomic finalization
transaction. Rate, receipt-count, evidence byte, response, header,
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

The observer requires HTTP/2 and advertises a fixed 256 KiB hard header-list
ceiling to the protocol stack, so a transport-over-limit block is refused
during decoding rather than accepted into an unbounded application allocation.
The lower certified application ceiling is enforced after bounded
confidentiality scanning.
Response headers, including canonical separator and terminator framing bytes,
are also measured before the body is consumed, and exactly one `Content-Type`
header is required. Every streamed body chunk is continuously bounded.
Receipt-bound query and audit-provenance fields are checked before dispatch.
Every bounded response body is checked before HTTP status or content-type
classification, and the complete raw response and decoded JSON are checked
against the configured secret markers and their standard and URL-safe padded
and unpadded Base64 plus per-nibble case-insensitive hexadecimal, fully
percent-encoded, and mixed percent-encoded forms. Marker count and aggregate
bytes are bounded. Decoded
JSON string values are scanned directly and after Base64 decoding, including
strings whose marker bytes require JSON escaping.
Secret-labelled state is denied. Fields not in the closed response schema,
wrong JSON types, observations captured before the signed request or stale or
future observations, substituted signatures or
bindings, a cursor outside the signed SQLite integer range, and a cursor that
does not advance from the signed predecessor are denied.

Each tenant/project/pipeline, destination, effect-fence identity, and canonical
query admits exactly this chain. Build and attempt IDs remain signed receipt provenance but
do not create independent phase chains for controller retries:

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
The publication deadline is the minimum of the freshness bound, signed request
expiry, and read-grant expiry. `observation_receipt_digest` is the supported
predecessor helper: SHA-256 over
`mcloving-observer-receipt-digest-v1 || 0x00 || serde_json(receipt)`, including
the receipt signature.

The complete signed standalone success envelope must fit the process frame
before the pending claim can commit. Configuration is rejected before the
ledger or network opens unless the configured response limit, maximum request
query and audit fields, and exact static receipt metadata fit that envelope
together. The runtime check remains defense in depth: an oversized envelope
becomes a failed claim, never committed evidence followed by an error-only response. Stored
completed receipts are signature-, binding-, and frame-size-verified again on
every replay.

Every claim, sequence allocation, and finalization rereads the active
generation/configuration fence. An empty ledger bootstraps only generation 1;
a later generation without its durable ancestry is rejected. Cutover requires a greater generation and the
exact active predecessor. Rollback is also a new greater generation and names
the generation it fences; it never resurrects an old process. A process fenced
during a network call cannot finalize evidence. Credential rotation is a new
configuration generation with a new exact grant and token digest. Once a
cutover or rollback is active, restarting its byte-identical generation and
configuration is idempotent and does not fence its own pending observations.

## Required proof and residual boundary

Contained tests cover signed pre/post/reconciliation reads, exact completed
replay, durable pending restart/retry and retry rate-budget enforcement,
signature and request substitution,
phase and cursor rollback, stale, malformed, oversized, resource-substituted,
secret-bearing body and header, timeout, outage, destination permission denial,
grant expiry, configuration and credential substitution, receipt verification,
duplicate protocol fields, and bounded frames. A sealed-inventory test proves
that none of this contained evidence grants Mario authority.

The trusted Linux host and containing directories, deployment/configuration and
credential operators, private CA and destination attestation owner, request
authority, destination implementation, system clock, and independently retained
receipt verifier remain trusted. Transformed secrets outside the marker set are
residual risk. Real effect-class inventory, live destination behavior,
least-privilege platform policy, canary, cutover, rollback, and decommission
remain future ticket gates.
