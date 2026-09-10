# Cache product path v1

EXEC-005 remains ACTIVE. This bounded Linux slice submits cache publish/read
operations through the actual API, controller, mTLS agent and sealed cache
executable. It verifies read bytes privately and publishes an authenticated
receipt identity. It does not restore cache content into a downstream workspace
or artifact, connect the other four helpers, certify Jenkins cache semantics,
or grant production, canary or cutover authority.

## Submission and deployment authority

Strict YAML `version: 1` can contain one `cache_intent` per stage. Such pipelines
use canonical IR 1.4 and execution envelope 3. The existing literal-shell
migration planner remains process-only. An intent contains `mapping_id`,
`mapping_digest` (`sha256:` plus 64 lowercase hex digits), `operation` (`read`
or `publish`), `logical_key_sha256`, `input_sha256`, and `timeout_seconds` in
1..=60. Publish additionally requires canonical standard `content_base64`,
including an explicitly empty string for empty content; read forbids it.
Decoded content is at most 12 KiB, retaining the existing 16 KiB scalar bound.
There is no endpoint, executable, credential, policy, caller, trust-promotion,
cleanup, audit-maintenance or arbitrary-command field in a submitted intent.

The default controller and agent have no cache authority. The controller loads
`MCLOVING_CACHE_MAPPING_CATALOG` with its exact raw-byte
`MCLOVING_CACHE_MAPPING_CATALOG_SHA256`. Its closed
`mcloving.cache-mapping-catalog/v1` records bind mapping id/digest,
organization/project/pipeline UUIDs, trust pool and allowed operations. The
catalog is bounded, no-follow, regular-file checked, not group/other-writable
and frozen at startup. Every validation, plan, save, submission and saved-replay path
checks scope and the exact mapping. Validate/plan requests containing a cache
intent must supply `pipeline_id`; saved pipeline and build paths use their
authoritative identities. Unsupported Windows and mixed/unbounded forms are
refused before queueing. Nodes require `sealed-cache-v1` and a domain-separated
capability digest binding the exact mapping id, full mapping digest and operation
in the allowed trust pool. Linux agents advertise those exact capabilities only
for their configured operations and matching pool. A same-pool agent with a
different mapping, digest or operation cannot claim the attempt; the generic
protocol capability alone is insufficient. Agent-side authority checks remain
mandatory after scheduling.
Catalogs do not promise hot revocation: changing them requires service restart.

The CLI accepts `validate pipeline.yaml --pipeline-id <uuid>` and
`plan pipeline.yaml --pipeline-id <uuid>` to send the required scope through
the same public API. Process-only validation/planning can omit that option.
Validate, plan and apply also accept `--trust-pool` (default `trusted-linux`)
and `--platform` (default `linux`), matching submit's admission context. A
custom Linux mapping needs its matching pool on all four commands. Apply uses
its pipeline UUID path and revision precondition but does not save platform or
pool as submission defaults; repeat the intended options on submit. Sending
`--platform windows` makes that context explicit and does not enable cache
execution there: the server still refuses unsupported Windows cache intents.

The agent loads `MCLOVING_AGENT_CACHE_BINDINGS_PATH` with exact raw-byte
`MCLOVING_AGENT_CACHE_BINDINGS_SHA256`. The file is owner-private, single-link,
mode 0400, bounded at 256 KiB and strictly duplicate/unknown-field rejecting.
Its `mcloving.agent-cache-bindings/v1` mappings are `CacheBinding` records in
`bins/agent/src/cache.rs`. Each record adds pinned executable/configuration and
receipt-key paths, helper executable/configuration digests, policy, caller,
trust class, cache kind and toolchain/platform digests to the controller's
scope/pool/operation contract. `CacheBinding::mapping_digest()` hashes the
canonical typed JSON of the entire record; that digest is the one placed in
both the controller catalog and submitted intent. Catalog raw-byte hashes and
individual canonical mapping hashes are distinct pins.

The deployment owner grants exactly that pipeline's use of the selected cache
principal/trust namespace. The job cannot choose either identity, and the
selected caller cannot be the cache operator. Pure admission reuses the cache
store's exact policy, generation, namespace and key derivation without opening
its database. The helper configuration remains mode 0400, the receipt key
owner-private, and both must match their pinned values. Special files including
FIFOs are opened nonblocking and refused before reading, so an invalid path
cannot suspend startup or pre-execution preparation.

## Context, command custody and lifecycle

The controller supplies project/pipeline identifiers from durable
`AttemptExecution`, alongside the existing organization/build/node/attempt and
fence. Envelope 3 uses a domain-separated, length-delimited SHA-256 commitment
over all those authoritative fields and the exact execution-spec bytes. The
agent validates canonical nonnil UUIDs, a positive fence and the commitment
before journaling work. Older process/connector envelopes retain their original
digest contract. The full mapping digest commits the remaining deterministic
cache command inputs; no random native cache request identifier, wall-clock
field or unbound default is introduced.

The existing durable `Journal::accept` payload digest is the pre-dispatch
invocation commitment. The public invocation id is `sha256:` plus that same
digest; it is not a claim that raw request bytes were retained. The product test
independently recomputes this commitment from the submitted execution bytes and
actual controller attempt context, then joins journal and completion receipts.
No parallel sidecar ledger duplicates the existing journal's durable identity.

The agent opens the configured executable without following a leaf link,
copies a bounded exact image into a Linux memfd, verifies its digest, seals
write/grow/shrink/seal mutation and retains the descriptor through execution.
Replacing the original pathname cannot change the executed bytes. The cache
hashes `/proc/self/exe` on Linux so this check covers the actual running image,
including memfd execution. An explicit `--expected-config-sha256` argument
checks the canonical identity of the exact parsed helper config before
`CacheStore::open`; later pathname replacement cannot start an operation under
a different config. Existing standalone invocations without that additional
pin remain supported.

The ordinary agent acceptance, pre-spawn lease renewal, cancellation reserve,
process-group journaling, descendant cleanup, terminal finalization and replay
remain in use. A private IO entrypoint starts bounded stdout/stderr drains,
commits process identity through the spawn hook, then sends bounded stdin.
No operation request bytes are sent before successful spawn journaling;
helper startup may initialize its own private database before reading requests.
Input/output proceed concurrently, preventing a helper that writes before
reading from deadlocking the caller. Every early return aborts the input task;
a pending writer cannot delay post-containment completion by more than 100 ms.
Timeout/cancellation still kills the whole verified group before return.

## Private output and authenticated outcomes

Raw helper output stays in bounded memory (at most 256 KiB per stream,
512 KiB across both capture buffers); it is never an attempt spool. Successful
combined output must fit the configured limit, which is at most 256 KiB. Transformation occurs only after descendant containment,
complete input delivery, a successful helper exit and a nontruncated capture.
The cache client requires exactly one LF-terminated JSON frame, no trailing
frame, duplicate key, unknown field or malformed Base64. It authenticates every
returned HMAC event, exact service/runtime/configuration/caller and observation
window, and consecutive returned chain links. Maintenance receipts may concern
other evicted keys; the final primary event must bind the actual requested
policy/namespace/key/generation/restore epoch and operation/outcome. A hit's
actual bytes must match the authenticated length and content digest. The pure
verifier opens no cache state or provider connection.

`miss`, `published`, `hit` and idempotent `replay` are explicit outcomes.
`conflict`, `corrupt_rejected`, rejected responses, nonzero exits, overflow and
incomplete input cannot become successful work. Public stdout contains only
`mcloving.cache-invocation/v1`, the committed invocation id, mapping id, outcome
and authorized native receipt event identity. It contains neither raw helper
stdout/stderr nor cached bytes, keys, Base64 content or a newly exposed raw
content hash. A native cache receipt intentionally lacks build/attempt identity;
the authenticated product invocation commitment supplies that separate link.

Agent death after a helper operation but before durable terminal truth does not
permit success inference or blind redispatch. The real crash-window gate
requires ordinary recovery to abort/refuse or retain reconciliation, keeping
one native operation and the original invocation commitment. The actual
post-helper/pre-result crash may park the agent with an unresolved recovered
attempt until operator recovery; automatic terminal completion is not promised. The debug-only
`MCLOVING_TEST_CRASH_AFTER_HELPER_RECEIPT` hook exits 87 at that boundary; it is
absent from release builds. The existing terminal-commit crash hook separately
proves replay uploads durable truth without re-executing cache work.

## Evidence and limits

`bins/agent/tests/cache_work.rs` is the actual submitted-job gate, driven by
`scripts/test-cache-product.sh` under the PostgreSQL Foundation lane. It uses
shipped controller/agent/cache binaries, synthetic mTLS identities, loopback
PostgreSQL and private disposable cache state. It checks actual miss/publish/hit,
no-work admission denials, conflict/downstream skipping, both crash windows,
independent read-only audit authentication, and journal/attempt/receipt linkage.
The runner requires a nonzero exact test denominator; a missing database or
binary cannot count as a passing product gate. Hostile subprocess fixtures are
negative IO/lifecycle evidence only, never helper-positive evidence.

The trusted controller, agent, kernel, deployment owner, configured cache
producer and shared HMAC verifier remain trusted. Same-UID hostile workload
filesystem/process/IPC isolation is still SEC-005; this integration must not be
credited as that containment. General cache restore, SCM acquisition, dependency
resolution, live-input capture and dynamic provisioning remain unsupported
product capabilities for this slice. Dependency resolution still needs a
reviewed issuer for its full-request source provenance, and provisioning still
needs its own durable cancel/reconcile effect lifecycle. All five helpers and
their actual product gates remain EXEC-005 closure requirements. Existing
release, secret-broker, containment, case recertification and separately
owner-authorized production gates are unchanged.
