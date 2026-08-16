# Shadow qualification v1

Status: SHADOW-001 verifier foundation active; no live shadow receipt or ticket closure yet

## Purpose and boundary

mcloving.jenkins.shadow-qualification/private-v1 is the owner-private,
deny-authority join between the exact MIG-007 package and a bounded paired
shadow session. It verifies that one authoritative Jenkins ingress observation
is captured once, replayed to McLoving without accepting the original
operation, and compared under frozen package, release, runtime, operational
state, authorization, clock, entropy, input, and isolation identities.

The current Mario population contains 230 disabled jobs. The one MIG-007
packaged case, corpus-052-cinqict_jenkinsdev, is also disabled. V1 therefore
requires denial parity for all five inventoried ingress classes—API, manual,
schedule, upstream, and webhook—and joins that current denial truth to the
already-certified isolated paired execution trace. It cannot reinterpret a
disabled job as live successful production traffic.

The verifier is a separate crate. It composes the MIG-007 private verifier in
memory but does not add fields to the migration package or rerun a replacement
state transform. It owns no trigger, scheduler, controller database or
filesystem, agent protocol, credential, connector, external effect, canary,
cutover, rollback, or decommission authority.

## Private inputs

The caller supplies:

- canonical private session bytes;
- independently owner-held session, source-capture public-key, live
  authorization-generation, and exact verifier-binary pins;
- the exact owner-private MIG-007 package bytes;
- the existing owner-held package, forward-manifest, reverse-manifest, and
  transform-implementation pins;
- the sealed source-history root;
- the exact reviewed SHADOW-001 implementation head.

The verifier authenticates the session against its owner pin and compares the
session's source-capture, variable authorization, and verifier identities with
their three independent owner pins. The package verifier then authenticates the package,
source, state-transfer evidence, and owner pins before the session is
considered. The session binds the package digest internally. Operational
output must never print either private digest or any package,
evidence-manifest, or owner-pin digest. Session bytes, private package bytes,
pins, and signing seeds remain owner-only on HeMan and never enter GitHub.

The Linux CLI opens every private file by walking from `/` with retained
directory descriptors, `NOFOLLOW`, and nonblocking leaf reads. It rejects
unsafe path components, redirectable foreign ancestors, a non-owner or broad
immediate parent, nonregular or multiply linked inputs, broad file modes, and
files above their byte ceiling. Publication is create-new, mode `0600`,
file-synced, and parent-directory-synced; an incomplete two-file session/pin or
four-file source-key/source-pin/shadow-key/shadow-public-identity publication is rolled back and
otherwise reported as requiring manual reconciliation.

## Frozen identity

The session freezes the exact:

- protected-main MIG-007 closure and reviewed SHADOW-001 implementation head;
- Mario controller, accepted inventory epoch and fingerprint;
- job, source, compiled pipeline, disabled source and target state, and matching
  operational generation;
- independently pinned authorization generation and the empty admitted
  agent-input set;
- v0.1.0 private Linux release identity and envelope;
- Jenkins image and plugin set, McLoving runtime image, PostgreSQL image, and
  independently pinned shadow-verifier binary;
- distinct authoritative-capture and shadow-replay Ed25519 public keys.

Runtime or state drift rejects the complete session. A later source or runtime
revision requires its own current migration package and shadow qualification.

## Capture and replay receipts

Each ingress class has one pair of canonical signed receipts:

1. the authoritative Jenkins-side capture is signed by the capture identity,
   records disabled_pre_queue, and proves zero queued build, scheduled attempt,
   credential grant, connector request, and production effect;
2. the McLoving replay is signed by a distinct shadow identity, repeats the
   exact event ID, class, capture digest, state, generation, outcome, and zero
   counts, and is explicitly marked as replayed.

The verifier authenticates both Ed25519 signatures, rejects shared signing
keys, and requires exact one-to-one joins. Omission, duplication, event-ID
reuse, capture substitution, class substitution, divergent state/outcome, or
signature mutation fails closed.

Every source receipt signature also covers one canonical session-binding
digest derived from the ceremony UUID, capture wall-clock instant, migration
package, reviewed implementation heads, source controller, inventory, job,
source and pipeline, disabled generations, authorization, release, runtime,
verifier, source-capture identity, and precommitted shadow-replay identity.
The verifier recomputes this digest from the complete session. Consequently,
an authentic receipt set from another job, controller, inventory, package,
freeze, capture instant, or session cannot be transplanted into the current
ceremony, and the same source capture cannot be resealed under a different
shadow identity.

`generate-keys` creates the two keys directly as owner-private PKCS#8 files,
publishes a separate owner-private digest pin for the source-capture public key,
and publishes the owner-private Base64 shadow public identity that the capture
sidecar must embed before it signs. The four-file bundle is create-new and
rolls back as one unit on partial publication.
The source private key is reserved for and may be consumed only by the
independently reviewed live capture sidecar; it is not an input to `seal`.
`seal` accepts only a canonical
template containing five already-signed source receipts under the independently
pinned capture identity and the precommitted shadow public identity while every
shadow signature field remains empty. It authenticates the source key pin,
exact session binding, all source signatures, and exact equality between the
precommitted shadow public identity and the supplied shadow private key, then
signs only the five replay receipts,
runs the complete MIG-007 and SHADOW-001 verification stack in memory—including
the separately supplied source-capture, authorization, and verifier pins—and
only then publishes the session and its independent owner pin. A sealing caller
cannot manufacture or replace authoritative observations, self-endorse a
variable freeze value, inject a shadow signature, or reuse one key for both
roles through the sealing interface.

The admitted case has no live external input, secret outcome, connector
outcome, administrative operation, semantic time, or semantic entropy
dependency. Its session therefore binds one wall-clock instant plus empty
clock and entropy streams with zero consumption, and requires zero receipts in
those boundary classes. A later case with any such dependency needs a new
schema and its canonical typed receipt verifier; a nonempty count cannot be
smuggled into v1.

## Paired trace and isolation

The current denial session also binds the exact DIFF-001 certified trace for the
sole admitted case, one isolated source/target replay, equal successful
normalized results, the exact newline-inclusive bounded and ordered
`+ echo Hello World` stderr and `Hello World` stdout records, zero artifacts or
effect intents, and zero mismatches. This trace
join does not by itself claim live production execution; it proves the
effect-free executable semantics that accompany the current live disabled
denial observations.

Source and target run in distinct disposable fixtures and distinct private
networks. The session requires digest-bound network and reachability receipts,
zero production endpoint mapping, network request, credential, host mount,
cross-fixture mount, or effect, plus completed teardown. The two fixture and
network identities must be distinct.

## Verification surface

The library returns only:

- the schema and private session UUID;
- five captured and five replayed ingress events;
- one compared trace and zero mismatches;
- one packaged case and 227 deterministic rejections;
- shadow_qualified=true;
- production_authority=false.

Operational tooling must omit the private session UUID if it is not approved
for disclosure and must never print private digests. A successful verifier
receipt makes only this exact disabled case eligible for continued
deny-authority shadow work. It does not make the job canary-, cutover-,
rollback-, or production-authority eligible.

## Current implementation evidence

crates/shadow-qualification provides canonical parsing, MIG-007 private
verification composition, exact identity joins, Ed25519 receipt verification,
denominator checks, exact log-sequence validation, trace/isolation checks, the
all-false authority ledger, distinct-key generation, template sealing, safe
owner-private path handling, and bounded digest-free operational output.
Focused tests cover the positive exact session; every authority bit; event
omission, duplication, substitution, and signature mutation; package/runtime
drift; undeclared inputs; production reachability; unknown fields;
noncanonical presentation; session-pin substitution; caller-supplied
shadow signatures; forged or substituted source signatures and source-key pins;
cross-session, cross-capture-time, and cross-freeze receipt transplantation;
shadow-key replacement and cross-shadow-identity capture transplantation;
shared signing keys; owner modes, hard links, aliases, create-new publication;
non-UTF-8 paths; redacted failure output; and size bounds.

SHADOW-001 remains ACTIVE until an independently reviewed exact-head
capture/replay sidecar and owner-private HeMan ceremony produce and verify the
complete session without disclosing private values.
