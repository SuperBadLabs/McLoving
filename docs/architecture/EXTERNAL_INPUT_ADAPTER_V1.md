# External input adapter v1

Status: implemented for the INPUT-001 contained boundary. No Mario production
input or cutover is claimed.

## Inventory boundary

The accepted Mario MIG-000 runtime-dependency manifest is
`migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/runtime-dependencies.yaml`
at SHA-256
`238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4`.
It contains 230 jobs and exactly 230 `opaque-cps-runtime`,
`controller-global`, `scripted` dependency entries. It contains no admitted
live external-read dependency. INPUT-001 therefore establishes and tests the
reusable adapter boundary without inventing a Mario endpoint, grant, schema,
or production-read claim. A later inventory generation must explicitly add an
input before a production mapping can use this protocol.

## Process and authority boundary

`mcloving-input-adapter` is a standalone NDJSON process. Its only admitted
authorities are:

- read its immutable JSON configuration;
- read a scoped bearer token, receipt-signing key, and secret-marker set from
  separate files;
- issue `GET` to the single configured endpoint with a canonical allowlisted
  query;
- write signed receipts and atomic capture claims to its private spool; and
- write one response envelope per request to standard output.

The adapter has no method field, write-capable endpoint, redirect following,
proxy inheritance, scheduler, controller database, agent RPC, controller
filesystem, unrelated secret, connector-control, or effect authority. The
configured endpoint cannot contain user information, a query, or a fragment.
Production HTTPS requires a configured content-pinned private CA bundle and
does not inherit the host root set. The complete bounded PEM bundle is loaded,
not only its first certificate.
Cleartext is admitted only for loopback fixtures and requires both the
configuration flag and `MCLOVING_INPUT_ADAPTER_TEST_MODE=1`.

Configuration, bearer-token, signing-key, marker-set, private-CA, executable,
claim, and receipt reads have explicit byte ceilings and require regular,
non-symlink files. Receipt absence is distinguished from invalid or substituted
receipt state. Runtime deployment must still protect the containing directories
from untrusted writers.

The runtime should mount configuration and credential files read-only, expose
only the exact destination through an egress policy, give the private spool its
own bounded volume, and run under a dedicated service identity. Host or adapter
operator compromise remains outside application-level containment.

V1 is admitted only on Unix hosts where the implementation can synchronize a
containing directory. Construction preflights that primitive before accepting
any capture. The final spool path must be absolute, canonical, non-symlink,
`0700`, and owned by the adapter's effective UID whether it already exists or
is concurrently created by a peer. Other platforms fail closed before creating the private spool or
publishing a claim; this adapter restriction does not narrow McLoving's
separate first-class Windows agent execution support.

## Certified configuration

The canonical configuration digest binds:

- protocol and response-schema versions;
- adapter, deployment, and operator identities plus monotonic generation;
- exact endpoint, endpoint identity, and data-source identity;
- query-key allowlist and top-level typed JSON field schema;
- read-grant identity, version, scope, expiry, and bearer-token digest;
- receipt-signing key identity/content digest and secret-marker-set digest;
- confidentiality ceiling;
- response-size, request-rate, timeout, freshness, and retry bounds;
- private spool path and exact private-CA bundle path/content digest; and
- the loopback-only test flag.

The caller must present that digest and the exact running executable SHA-256.
The binary hashes its own executable before accepting requests. Any adapter,
configuration, endpoint, data source, grant, schema, or generation substitution
fails before network access.

## Capture request

Every request binds:

- capture ID;
- tenant, project, pipeline, build, and attempt IDs;
- logical input name;
- expected executable/configuration, adapter, protocol, schema, and generation;
- optional prior generation for a rollback capture;
- endpoint/data-source and grant identity/version/scope;
- canonical query and optional exact source cursor;
- request and expiry times;
- confidentiality ceiling; and
- audit lineage.

The NDJSON request frame is capped at 64 KiB, and unknown fields are denied.
UUIDs, names, and lineage must be non-empty. A
rollback generation must be strictly older than the active generation. Query
keys outside the certified allowlist never reach the source.

## One-capture semantics

Before a request reaches the source, the adapter atomically creates
`CAPTURE_ID.claim` containing the canonical request digest. Concurrent or
cross-process reuse with different content is denied. A matching concurrent
caller waits for the complete retry-expanded network window plus a fixed
one-second local publication allowance independent of the configured network
timeout, then receives the exact signed receipt. A process crash after claiming
but before receipt publication remains
fail-closed and requires operator reconciliation; it never silently samples the
mutable source again. Claim contents and the containing spool directory are
synchronized before any network read. Matching claimed or completed captures
bypass source-read admission and converge on the same receipt; new captures are
serialized through rate admission before claim creation, so a denied request
cannot strand an unfulfillable claim.

Admission durably reserves the complete explicit attempt budget. Immediately
before each GET, one reservation becomes an in-flight charge that cannot age
out during filesystem coordination, scheduling delay, or response-body
transport. Completion converts it to a conservative sliding-window timestamp.
If the adapter exits mid-attempt, the charge reconciles after the earlier of
request or grant expiry plus the per-attempt timeout, then ages out through the
same one-minute history; a crash can neither free capacity early nor consume it
forever. The expiry-plus-timeout calculation is checked during admission before
claim publication.

Claim contents are first synchronized under an unpredictable private temporary
name, then atomically linked into the final capture path without overwrite.
Another adapter process can therefore observe either no claim or the complete
64-byte digest, never a partially published claim.

Receipts are written to a unique temporary file, synchronized, atomically
linked into the final capture path without overwrite, and followed by a spool
directory synchronization before success. A restart replays the
same verified receipt without another source read. HMAC-SHA-256 covers the
complete receipt, and verification also re-hashes the canonical JSON response.
The HMAC key is not exposed to a pipeline runner. Because the verifier shares
that key, adapter/verifier collusion remains residual risk and requires the
later independent differential and production gates.

## Source and response policy

The adapter sends only a scoped bearer-authenticated `GET`, disables redirects
and ambient proxies, disables the HTTP client's implicit retry policy, applies
`timeout_ms` as the connect and total timeout for each outbound attempt, and
retries only transport failures or HTTP 502-504 up to the configured bound.
The network-wait ceiling is therefore
`(retry_attempts + 1) * timeout_ms`; request and grant expiry must cover that
retry-expanded window plus bounded local admission and durable publication.
Authentication
authorization and grant-header construction is validated once during adapter
construction, before the spool is created or a claim can be published.
Authentication denials do not retry. A successful response must provide:

- `Content-Type: application/json`;
- `X-McLoving-Cursor`;
- `X-McLoving-Observed-At-Ms`;
- `X-McLoving-Provenance`;
- `X-McLoving-Confidentiality`; and
- an optional `ETag`.

The observed timestamp age is calculated with checked signed arithmetic and
cannot be in the future, overflow the Unix-millisecond domain, or exceed the
configured freshness window. If the request names an exact cursor, it must
match. The body is read incrementally and rejected before exceeding the byte
limit. It must be valid JSON, contain no field outside the closed schema, and
satisfy every required top-level field/type contract. Configuration also has
hard upper bounds for response size, request rate, timeout, freshness, query
keys/values, binding text, schema fields, marker length/count, and aggregate
`2 * max_response_bytes * total_marker_bytes` comparison work for the raw and
decoded JSON scans. Duplicate markers are rejected before spool creation.

V1 admits `public` and policy-bounded `internal` values. A response labelled
`secret` is always denied. The adapter also scans every bounded body for the
independently supplied marker set before JSON parsing and emits only a typed
error code/message on failure, never the source body or credential. Every
source-derived response header is scanned by the same marker set before parsing
or receipt construction, so cursor, provenance, ETag, and incidental headers
cannot become a disclosure path. This is a
canary-marker non-disclosure gate, not a claim that arbitrary transformed
secrets are detectable.

## Receipt and runner use

The signed receipt repeats every relevant request/configuration identity and
adds canonical query, source cursor/ETag/time/provenance, capture time,
confidentiality, canonical response SHA-256 and value, retry count, marker-set
digest, signing-key identity, and signature. SHADOW-001 or CANARY-001 must
capture once and supply the identical receipt/value to both runners; neither
runner may contact the mutable source independently. Later gates must compare
response consumption, downstream control flow, effect intent, result, and
published output.

No receipt produced by this crate grants effect, cutover, rollback, or
decommission authority. Those gates must re-read the exact deployed adapter,
configuration, endpoint, schema, grant, marker set, receipt verifier, and
generation and must reject drift.

## Executable proof

`crates/input-adapter/tests/contained_adapter.rs` exercises a real contained
HTTP fixture and the standalone binary. It covers valid and branch-varying
responses, exact cursor, stale/missing/malformed/wrong-schema/oversized values,
authorization and query denial, endpoint binding, bounded outage retry,
rate limiting, secret-label and marker non-disclosure, concurrent deduplication,
restart replay, replay substitution, zero write requests, generation cutover,
and rollback binding.

`crates/input-adapter/tests/mario_inventory.rs` pins and parses the accepted
MIG-000 manifest and proves the current Mario denominator has zero admitted live
external inputs.
