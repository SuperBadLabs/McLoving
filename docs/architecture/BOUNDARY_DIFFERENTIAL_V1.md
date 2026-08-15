# External-boundary differential v1

Status: accepted DIFF-003 implementation receipt; independent PR review,
protected checks, merge, and post-merge verification remain required before the
execution board can mark DIFF-003 complete. No production authority is claimed.

## Claim boundary

`mcloving.jenkins.boundary-differential/v1` is the final contained
external-boundary certificate for the current Mario migration denominator. It
does not certify a production canary, cutover, rollback, deployment, live
credential, live endpoint, or external effect. Mario's sealed inventories still
contain zero admitted production boundary mappings, while its one external
owner/operator client intentionally remains Jenkins-source-authoritative.

The certificate therefore makes two bounded claims:

1. every named DIFF-003 prerequisite implementation and protocol is frozen by
   an exact current source-manifest SHA-256 and positive receipt contract; and
2. the complete declared cross-boundary and adversarial fixture denominator is
   fail-closed, effect-safe, non-disclosing, and explicit about the absence of
   production authority.

Contained fixtures are not substituted for production observations. Later
`MIG-006`, `MIG-007`, `SHADOW-001`, `CANARY-001`, and authority-transfer tickets
retain their separate acceptance conditions.

## Immutable repository certificate

The exact two-file bundle is `migration/boundary-differential-v1`. Its JSON is
bound by both a canonical adjacent `SHA256SUMS` file and a detached SHA-256
compiled into `mcloving-boundary-differential`. Rewriting the certificate and
resealing its adjacent manifest cannot grant authority.

The verifier rejects symlinked, special, extra, missing, oversized, unknown, or
non-canonical bundle content. It checks the pinned Jenkins, Rust, and PostgreSQL
images; sealed runtime-dependency and client inventories; signed v0.1.0 release
identity, envelope, evidence-manifest, and verification-receipt digests; and the
exact zero-authority scope.

Thirteen prerequisite boundaries are ordered and frozen:

- `TRIG-001`, `SCM-001`, `SECRET-001`, `INPUT-001`, and `PROV-001`;
- `EXT-001`, `OBS-001`, `DISC-001`, `DEP-001`, and `CACHE-001`; and
- `CONSUMER-001`, `ADMIN-001`, and `REL-001`.

The controller/API implementation manifest is shared deliberately by trigger,
discovery, consumer, and administrative migration boundaries. Every other
component has its own exact crate-source manifest. Configuration, account,
resource, content, generation, and positive-receipt identities remain separate
even when code is shared.

## Actor non-collusion

Runner, connector, and destination observer have distinct implementation,
configuration, deployment, and service-account identities. Their complete
contained permissions are mutually exclusive:

- runner: contained workspace transformation only;
- connector: one fixture-destination write only; and
- observer: fixture-destination read only.

The verifier rejects identity collisions or permission broadening. The runner
cannot write the destination, the connector cannot impersonate or configure the
observer, and the observer cannot write or schedule work. This is a certificate
property and is also exercised by the focused `EXT-001` and `OBS-001` suites.

## Adversarial denominator

The 48 ordered cases cover:

- trigger substitution, replay, stale generation, and outage;
- source revision substitution, later revision preservation, and outage;
- secret consumer substitution, taint ineligibility, and marker disclosure;
- input endpoint substitution, replay, stale response, and outage;
- provisioner template substitution, exhaustion, interruption, orphan cleanup,
  and stale instance;
- connector identity substitution, replay, stale request, outage
  reconciliation, and ambiguous retry reconciliation;
- observer identity substitution, replay, stale response, outage, and write
  permission denial;
- discovery configuration substitution, replay, and stale observation;
- dependency resolver substitution, replay, and outage;
- cache generation substitution, replay, and stale content;
- residual Jenkins reads/writes, target substitution, and exact rollback for
  external clients; and
- release artifact substitution, replay, untrusted key, and timestamp outage.

Every denied case has zero intent, effect, duplicate effect, and marker
disclosure. The one ambiguous connector case reconciles one intent to exactly
one effect. Provisioner interruption/orphan cases require cleanup. Client
rollback cases restore the immediately preceding source generation. Preserved,
reconciled, cleaned, and restored cases require a fresh observation.

## Cross-boundary joins

Twelve ordered contract joins apply pair-specific compatibility rules to
independently produced, authenticated live receipts. Each projection must equal
its own receipt payload; the gate does not claim the contained fixtures are one
shared live transaction or manufacture equality from shared constants:

- trigger capture to source acquisition;
- later source revision to dependency resolution;
- secret grant to source acquisition;
- input capture to control flow;
- dependency resolution to cache;
- discovery to trigger installation;
- provisioner identity to runner admission;
- dry-run intent to connector intent;
- connector outcome to independent observer state;
- consumer cutover and rollback;
- administrative cutover and rollback; and
- trusted release to admitted runtime.

Only the contained connector-to-observer join has one destination effect. All
other joins have zero effects, and every join has zero duplicate effects.

The exact-head gate does not treat those repository assertions as runtime
observations. Each of the 13 focused positive tests exports the actual public
receipt produced by the exercised implementation into a new evidence
directory. The host requires the exact receipt set and authenticates each exact
file with a newly generated Ed25519 ceremony key. Only the public key and 13
detached signatures enter evidence; the private key stays in the private
runtime directory and is destroyed before verification and sealing. The
verifier checks every boundary-specific schema, protocol, generation,
transition, and outcome shape. Each certified scenario also requires one
machine-readable outcome emitted from a scenario-specific predicate over the
actual error, status, counter, digest, generation, or rollback state observed
by the owning focused test. The outcome file includes a nonempty structured
observation, is create-new and synchronized, and cannot be emitted by merely
reaching the end of a non-panicking test. Finally, every join compares trace, input,
control-flow, effect-intent, outcome, content, generation, retry, effect,
duplicate-effect, and rollback projections from both authenticated receipts.
`runtime-boundaries.json`, `executed-scenarios.json`, and `runtime-joins.json`
therefore bind the static differential contract to the code that ran; a
nonempty object or two unrelated receipt hashes cannot satisfy the gate.

## Secret and client truth

Thirteen synthetic markers exercise the declared artifact, audit, cache,
controller API, destination response, log, receipt, retained-state,
reverse-transform, test-report, and workspace surfaces. The accepted shape is
zero disclosure on every surface.

The contained client fixture proves zero Jenkins reads and writes after its
target generation and exact rollback restoration at generation three. It does
not claim the real owner/operator stopped using Jenkins. Unsupported production
operations are not silently retired, and the production authority field remains
`jenkins_source`.

## Contained exact-head gate

`scripts/test-boundary-differential.sh` accepts one new external evidence
directory and refuses a dirty or changing source tree. It creates two separate
internal-only Podman networks. The pinned Jenkins fixture runs first with a
per-run owner-only synthetic credential, zero jobs, zero endpoints, zero
effects, and no public-network reachability. Its credential is marker-scanned
out of retained evidence. The Jenkins container and network are destroyed
before the target network exists.

The target phase requires a rootless Podman engine, starts the pinned PostgreSQL
service, and starts a pinned Rust runner with no-new-privileges, finite CPU,
memory, and PID ceilings, a read-only source mount, read-only offline Cargo
registry, three disjoint writable mounts for public receipts, scenario
observations, and runner-only outputs, and exact-capacity source-transport tmpfs
mounts. It cannot write the retained evidence root, host-owned logs,
inspections, authentication material, merged receipts, verifier output, or
manifest. The runner drops the complete default capability set and restores
only rootless `SETUID`, `SETGID`, and `SETFCAP`. The source-acquirer needs the
first two to write the single-identity UID/GID maps for its inner transport user
namespace; Linux requires the third when the inner mapping contains namespace
UID zero. It retains no host-root mapping, `SYS_ADMIN`, mount, public-network,
or production authority.
It runs the real PostgreSQL trigger, discovery, consumer, and admin suites plus
the complete focused source-acquirer, secret-broker, input-adapter,
provisioner, external-connector, destination-observer, dependency-resolver,
cache, release-provenance, and independent differential-verifier suites. The
target network also denies public reachability.

The host recomputes each component source manifest and compares it with the
certificate, requires all 13 live public receipts and all 12 derived live
joins, verifies the exact suite ledger and verifier receipt, records all
container/image/network inspections and transcripts, rejects private-key
material, private-key paths, and every contained private marker—including
markers in retained pathnames and file contents and case-varied hexadecimal
and percent encodings—rechecks the exact source
commit/tree/status, rejects every nonregular or multiply-linked retained entry,
and seals a self-excluding evidence manifest.
Failed attempts remain unsealed and grant no authority.

Run the repository verifier with:

```text
cargo run --locked -p mcloving-boundary-differential -- \
  migration/boundary-differential-v1
```

Run the contained gate on a clean pushed head with:

```text
scripts/test-boundary-differential.sh \
  "${OWNER_PRIVATE_DIFF003_RUN}"
```

`OWNER_PRIVATE_DIFF003_RUN` resolves only inside owner-controlled operations;
the private filesystem root is never published in repository documentation.

## Exact-head acceptance receipt

The accepted receipt must bind the final reviewed PR head and tree after all
code, documentation, and board changes. To avoid a self-invalidating metadata
commit, its source head/tree, public receipt-authentication-key digest, and
independently rechecked self-excluding manifest digest are published in PR
#59's closure comment after the final run. The private HeMan run path is
retained only in the owner-controlled execution record and is not
posted publicly. No repository change may follow that run before merge.
Earlier receipts are diagnostic only.

The final receipt must contain the exact 15 component-suite entries, 13
Ed25519-authenticated public boundary receipts, 12 two-receipt validated joins,
and 48 assertion-derived scenario outcomes. It must report zero production
mappings, production effects, duplicate effects, production cutover claims,
and secret-marker disclosures, with a clean unchanged source tree at seal time.
