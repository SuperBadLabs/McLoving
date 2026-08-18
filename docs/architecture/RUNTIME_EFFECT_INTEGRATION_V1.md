# Runtime effect integration v1

Status: EXT-002 implementation active; no production authority

## Gap this ticket closes

`EXT-001` proves a hardened standalone connector and shadow-replay boundary.
`CANARY-001` verifies a completed, independently signed one-action ceremony.
Neither currently connects a submitted McLoving pipeline to that boundary.
Pipeline IR v1 contains only native process steps, the public execution spec
emits only those process steps, and the durable effect-checkpoint methods are
called only by store tests. A real effect could therefore be demonstrated only
by an operator assembling receipts outside the product execution path. That is
not an end-to-end Jenkins replacement and cannot complete `CANARY-001`.

EXT-002 adds the missing path without widening native workload authority.

## Typed pipeline contract

Pipeline IR gains a connector-intent step. Its semantic fields are limited to:

- a versioned mapping identifier and mapping digest;
- a canonical effect class and effect key template;
- a typed public input schema plus a closed protected secret-reference schema,
  whose field names are required reference taints/names; the matching outcome
  projects each field to an opaque provider-reference string, never secret
  bytes;
- the expected public result schema;
- a timeout and explicit ambiguity policy; and
- a downstream-control digest.

The step cannot contain a raw credential, bearer token, arbitrary destination
URL, account override, executable program, shell fragment, or network policy.
Compilation resolves the mapping against the exact admitted profile and emits
stable diagnostics for an unknown or floating mapping. Canonical encoding,
component expansion, expression binding, and source provenance cover the new
variant. Existing Pipeline IR remains byte-for-byte stable.

## Controller-owned state machine

The controller owns the effect state machine. An agent may evaluate contained
inputs and return a signed, bounded intent proposal, but it cannot hold a
production credential or invoke the destination.

1. Under the current attempt lease and fence, persist `prepared` with the exact
   canonical request digest, mapping/runtime/configuration digests, grant
   requirement, pre-action observation digest, and pairwise-distinct request,
   connector-outcome, observer, and shadow signing roles.
2. Re-read operational state, attempt/fence, release, runtime, mapping,
   connector, observer, credential mapping, authority, and one-action grant.
   Any mismatch moves the node to a visible fail-closed state before dispatch.
3. Send the signed request only to the independently deployed, runtime-attested
   `EXT-001` service selected by immutable configuration. The controller cannot
   accept an endpoint from pipeline data or agent output.
4. Persist the complete signed outcome as `applied`, or durably record
   `uncertain` before any retry decision. A timeout after possible dispatch is
   ambiguous, never an ordinary failed process step.
5. Join the independent `OBS-001` post-action or reconciliation receipt and
   persist `confirmed` only when all request, destination, fence, result,
   freshness, and identity bindings match. The observer request must name the
   exact frozen pre-action receipt as its predecessor before connector dispatch.
6. Deliver the exact confirmed outcome to the deny-authority shadow replayer
   and persist its signed durable replay receipt.
7. Release downstream execution only after the outcome, observation, and
   shadow replay are durably joined. Restart reconstructs this decision from
   PostgreSQL; it never infers completion from an in-memory response.

The controller API exposes the state and evidence digests but never private
request values, credentials, or protected outputs. Cancellation or lease loss
after `prepared` cannot erase ambiguity or transfer authority to another
attempt. A controller reconciliation path may append only missing write-once
receipt slots for the exact fenced effect while the attempt is explicitly
`reconciliation_required` with no executable lease. It cannot restore dispatch
authority, replace a receipt, cross a restore epoch, or release downstream work
before the complete outcome/observation/shadow join is confirmed.

## Deployment and authority boundary

The connector, observer, shadow replayer, controller, and workload agent use
pairwise-separated service identities and grants. Only the connector receives
the one-action destination credential. Native process steps remain contained
workspace transformations with no production network route, destination
credential, or connector RPC authority.

Runtime configuration pins the connector protocol, service identity, endpoint,
implementation/image/configuration digest, request key, result key, observer
binding, and credential-mapping generation. Startup rejects partial or ambient
configuration. Per-action freeze checks the live values again; drift after an
accepted intent blocks dispatch and quarantines unresolved work.

## Current implementation boundary

Exact implementation head
`edc392524a5c229c3e5d2a1462b14d45d4611f27` includes Pipeline IR v1.3
connector intents, execution-spec v2, deployment-backed exact mapping
admission, immutable PostgreSQL outcome/observation/reconciliation/shadow
receipts, redacted public evidence digests, the controller-owned fenced state
machine, and digest-pinned out-of-process connector, observer, and shadow
invocations. Real-PostgreSQL proofs use four pairwise-distinct Ed25519 authority
and receipt roles, bind the post-action observer request to the exact frozen
pre-action receipt, hold terminal publication until the signed shadow receipt
is durable, reject a substituted executable before dispatch, permit an exact
fenced reconciliation to complete missing immutable receipt slots without an
execution lease, and freeze every post-dispatch timeout, substituted signed
response, crash, lease-loss, cancellation, retry, and reconciliation ambiguity
without a duplicate fixture effect.

The Pipeline IR uses an algorithm-qualified downstream-control reference while
the EXT-001 outcome wire format carries the raw digest; the runtime compares
their canonical digest components explicitly. Protected-reference schemas are
closed and string-only at admission, and runtime outcome validation rejects
missing, extra, duplicate-taint, malformed, or contract-incompatible protected
references. Public build status includes redacted effects from every fence of
the exact attempt and retains each fence identity, so historical restore
uncertainty cannot become invisible while blocking terminal reconciliation.

The retained earlier-candidate effect-free Mario rehearsal passed all 14 then-
current execution-spine tests on an internal-only runtime network with real
PostgreSQL and all production, canary, and cutover authority flags false. Its
owner-only result receipt SHA-256 is
`44ad8eb55386a38dfbe42a62407fd198b87aac53c9eca709f8a387bb0a81d8c7`.
It is not exact-head evidence for `edc3925`; a fresh 17-test effect-free Mario
rehearsal remains required.
`docs/evidence/EXT-002_SECURITY_REVIEW.md` records the detailed implementation
and rehearsal evidence. Exact-head review, protected CI, merge, and
protected-main verification remain required before EXT-002 may become `DONE`.

## Required evidence

Closure requires focused canonical and mutation tests plus real-PostgreSQL
integration tests for:

- process-only backward compatibility and connector-step admission;
- exact request/result canonicalization and redaction;
- missing, stale, expired, replayed, cross-attempt, and overbroad grants;
- lease loss and cancellation before and after possible dispatch;
- controller crash at every durable transition and restart recovery;
- duplicate delivery, response substitution, service/configuration drift, and
  observer/connector identity collision;
- successful, rejected, unavailable, ambiguous, and reconciled outcomes;
- exact shadow replay before downstream release; and
- zero duplicate effects across timeout, restart, retry, and reconciliation.

An effect-free Mario rehearsal must use a separately deployed non-production
fixture destination and prove all authority flags false. It validates product
wiring only. The first production action remains a fresh `CANARY-001` ceremony
for one exact migrated job and one exact action under explicit owner authority.
