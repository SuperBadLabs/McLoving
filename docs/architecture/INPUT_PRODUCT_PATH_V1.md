# Input capture product path v1

EXEC-005 remains ACTIVE. This bounded Linux slice connects one operator-mapped
public input capture to submitted jobs through the API, controller, remote mTLS
agent and sealed native input adapter. Successful work exposes an authenticated
invocation identity. Captured values remain private; downstream branching,
workspace injection and generalized Jenkins input semantics are outside this
slice. Source acquisition, dependency resolution and provisioning still need
their own product integrations and gates.

## Submission and scheduling

A stage may contain exactly one literal `input_intent` with `mapping_id`,
`mapping_digest` (`sha256:` followed by 64 lowercase hex digits) and
`timeout_seconds` in 1..=60. No query, endpoint, credential, grant, executable,
schema or confidentiality override is accepted from the job. Input selects
canonical IR 1.5, opcode 4 and execution envelope 4. Independent stages can
contain existing process, cache or input steps; old process and cache byte
contracts remain unchanged. The literal-shell migration planner remains
process-only.

The default controller grants no input authority. Startup configuration pairs
`MCLOVING_INPUT_MAPPING_CATALOG` with the exact raw-byte
`MCLOVING_INPUT_MAPPING_CATALOG_SHA256`. The strict
`mcloving.input-mapping-catalog/v1` catalog contains profile, generation and
mapping records binding mapping id/digest, organization/project/pipeline and
trust pool. Every validate, plan, save, submission, trigger and saved replay
admission uses the relevant authoritative scope. Validation and planning need
an explicit pipeline ID. Unsupported platforms and scope/digest mismatches
are refused before queueing. CLI validate, plan and apply retain the existing
pipeline, platform and pool options used by cache admission.

Scheduling requires `sealed-input-v1` and a domain-separated capability for
the exact mapping id and full mapping digest. Capture is the only operation.
Agents advertise matching bindings only in their configured pool; the generic
capability cannot let an incompatible agent consume a one-attempt job.
Agent-side mapping checks remain mandatory after assignment. Catalog updates
require restart; this design makes no hot-revocation promise.

## Operator binding and durable identity

The agent pairs `MCLOVING_AGENT_INPUT_BINDINGS_PATH` with
`MCLOVING_AGENT_INPUT_BINDINGS_SHA256`. The strict, bounded, owner-private,
single-link mode-0400 `mcloving.agent-input-bindings/v1` file contains typed
`InputBinding` records. Each canonical record digest covers scope, pool,
executable path/hash, configuration path/hash, credential and marker paths,
input name, query, expected cursor, public confidentiality ceiling and explicit
fixture-only loopback opt-in. The controller references this full digest; its
public catalog cannot reconstruct the private binding.

The configured adapter fixes endpoint, data source, schema, deployment/operator
identity, generation and grant. Responses are capped at 12 KiB for this product
slice. Provider-token contents stay in the helper; agent preparation reads only
the pinned configuration, receipt signing key and approved marker set. Pure
validation neither constructs `InputAdapter` nor creates its spool or client.

Envelope 4 commits exact execution bytes and controller-authoritative
organization, project, pipeline, build, node, attempt and fence through
`mcloving.input-assignment/v1`. Canonical nonnil identities and a positive
fence are checked before durable acceptance. A separately domain-separated
SHA-256 derivation produces a deterministic UUIDv8 capture ID, while audit
lineage retains the full assignment digest.

The complete native request is derived from that digest, frozen mapping and
the original durable journal `accepted_at_unix_ms`. Checked expiry is the
minimum of acceptance plus intent timeout and configured grant expiry. An
expired original acceptance is refused; recovery cannot refresh its time or
capture ID. The canonical native request hash additionally binds acceptance
time and every native request field. The assignment digest alone is not a
claim to commit a timestamp that did not yet exist. No request sidecar is added.

## Sealed execution and private verification

Cache and input share only mechanical bounded file reads and sealed executable
custody, through closed typed dispatch. Jobs cannot register commands,
environments or verification callbacks. No-follow, nonblocking reads inspect
the opened regular file and enforce size/ownership rules. Exact executable
bytes are copied into a sealed Linux memfd retained through containment.
The input helper hashes its actual running image through `/proc/self/exe`.
Its expected canonical configuration digest is checked against the same parsed
configuration before credentials are read or adapter state is created.

The existing private IO runtime, pre-spawn lease renewal, durable spawn hook,
whole-group cleanup and terminal journal lifecycle remain mandatory. Request
bytes follow successful spawn journaling. Raw stdout/stderr remain bounded
private memory and never become public attempt spools. Success needs complete
input delivery, successful exit, nontruncated output and an authenticated
single LF-terminated, duplicate-free native receipt frame.

Pure receipt verification binds the entire canonical request, all scope and
capture identities, configuration/implementation, grant/generation, query and
cursor, schema, provenance, key and marker pins, confidentiality, response
content and observed timing. Capture and verification completion must precede
the request, grant and native publication deadlines. A signed but unrelated
receipt is refused. Marker
checks cover serialized bytes and decoded JSON strings and keys. Public output
contains only protocol `mcloving.input-invocation/v1`, full invocation ID,
mapping ID, capture ID, canonical request hash and the explicit outcome.
It exposes no captured JSON, cursor, provenance or independent response hash.

The post-helper/pre-terminal crash window remains unresolved operation truth:
ordinary recovery parks/refuses without another provider read. The original
capture ID and receipt remain intact. Terminal-commit replay separately uploads
durable completion without repeating capture. Debug crash hooks do not exist
in release builds.

## Verification and remaining scope

`bins/agent/tests/input_work.rs`, run by `scripts/test-input-product.sh`, owns
the actual submitted-job gate. It requires disposable PostgreSQL, shipped
controller/input binaries, a remote mTLS agent and a counted read-only provider.
Positive evidence must join public completion, authoritative controller work,
durable journal acceptance and the native signed stored receipt, independently
recomputing the complete request. Fake helpers contribute negative evidence
only. The wrapper requires a nonzero test denominator; unavailable prerequisites
cannot count as success. Foundation runs this gate alongside the actual cache
product regression. Focused signed-receipt mutations, source/config substitution,
confidentiality checks and both crash windows complement the product gate.

Observed verification and review results belong in the ACTIVE EXEC-005 review;
this contract alone earns no gate. Protected PR and exact-main Foundation/native
Windows remain required. Controller, agent, deployment owner, kernel, configured
producer and HMAC verifier are trusted. Hostile same-UID containment remains
SEC-005. Cache restoration, downstream input-value use, dependency provenance
issuance and provisioning's durable effect lifecycle remain separate work.
No production, canary, cutover or expanded JCOMP-003 equivalence is granted.
