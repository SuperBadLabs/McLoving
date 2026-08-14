# Secret mapping and grant broker v1

Status: SECRET-001 contained implementation contract. No Mario production
credential, secret-provider, source-checkout, external-effect, canary, cutover,
rollback, or decommission authority is claimed.

## Purpose and modular boundary

`mcloving-secret-broker` converts owner-approved Jenkins credential references
into provider-neutral, short-lived grants for one exact out-of-process
`SCM-001` source acquirer or `EXT-001` external connector. Fogell, McLoving, or
another runner can use the same public mapping and receipt types without
receiving secret bytes. The broker does not depend on either runner runtime.

The only API type capable of holding secret bytes is `SecretMaterial`. It is
not serializable, prints only `[REDACTED]`, and zeroizes its allocation on drop.
Only an exact provider redemption hands that value to the selected external
consumer integration. Mapping, grant, redemption, audit, source, connector,
shadow, and runner-facing types contain references and digests only.

## Inventory and classification

Every admitted mapping reconciles exactly once to one typed credential row
from the sealed Jenkins runtime-dependency inventory. Reconciliation binds:

- inventory epoch, job, dependency, and Jenkins credential-reference identity;
- owner identity;
- exact consumer kind and identity;
- declared taint and nonempty taint path; and
- classification-evidence digest.

The closed consumer classes are external connector, source acquirer,
controller, and workload. Their only valid taints are respectively
`connector_only`, `source_acquisition_only`, `controller_only`, and
`workload_visible`; any mismatch fails closed. Controller-visible and
workload-visible mappings are always ineligible. In particular, environment,
file, stdin, and argument delivery never becomes grant-eligible through
redaction, an owner signature, or a provider mapping.

The sealed Mario inventory contains 230 jobs and no credential reference,
redaction reference, or secret-consumer entry. The executable Mario test binds
the exact runtime-inventory digest and proves a zero SECRET-001 authority
denominator.

## Owner-approved provider mapping

An eligible mapping binds tenant, project, environment, action, inventory
identity, exact external consumer identity plus implementation/configuration
digests, provider identity/version/implementation/configuration, opaque
provider reference, exact secret version, and monotonic rotation generation.

Before opening state, the broker requires a nonempty, unambiguous registry of
trusted owner key identities and Ed25519 public keys. Installation selects a
key only from that startup-pinned registry; the installation caller cannot
supply a key or self-authorize a mapping. The broker then verifies the owner
approval over the complete canonical mapping payload. It independently checks
the owner signing key identity and SHA-256, approval payload SHA-256, signature,
approval start, bounded expiry, and trusted installation time. Changing the
consumer, scope, provider, reference, version, taint, disposition, or evidence
invalidates the signature. A rotation must be the next generation and preserve
the immutable inventory, owner, tenant, scope, classification, consumer,
provider identity, and disposition. Provider implementation, configuration,
reference, API version, secret version, and owner approval may advance only in
that signed new generation.

## Fenced short-lived grants

Grant protocol `mcloving.secret-grant/v1` binds:

- mapping and rotation generation;
- organization, project, build, attempt, environment, action, and fence;
- exact external consumer identity and implementation/configuration digests;
- expected provider version;
- request, trusted issue, and expiry times; and
- audit provenance.

The total requested TTL is capped at fifteen minutes, and issue/redeem decisions
use service-supplied trusted time. A durable scope digest excludes caller-chosen
grant ID and timing fields, so changing an ID cannot issue a second grant for
the same mapping generation, build, attempt, action, fence, and consumer. An
exact in-window issue retry returns the original receipt; expired, redeemed, or
revoked grants never reactivate.

At redemption, the broker re-reads the current mapping head and grant status in
one immediate transaction, matches every tenant/build/attempt/fence/consumer
field, checks trusted time, and then requests the exact provider implementation,
configuration, reference, and secret version. A substituted provider version
fails before any redemption receipt. Successful redemption is atomic and
one-time. Rotation and emergency revocation durably revoke every issued grant
from the superseded generation before later redemption.

`GrantReceipt::consumer_binding` emits the exact public fields expected by the
existing SCM and connector configuration contracts: grant ID, protocol version,
tenant/build/attempt/action/fence scope, expiry, and exact consumer
implementation/configuration. It never emits provider reference or material.
The source acquirer continues to return only its content/provenance receipt; the
connector continues to return only its confidentiality-safe outcome receipt;
deny-authority shadows receive those receipts rather than a secret grant.

## Non-disclosure and durable evidence

Before committing redemption, the broker scans the complete mapping, request,
grant receipt, and prior audit payloads for the resolved secret's raw,
standard-Base64, unpadded-Base64, Base64URL, hexadecimal, and percent-encoded
forms. Detection denies redemption and emits no success receipt. The downstream
SCM and connector boundaries retain their broader marker scanning for source,
destination, output, artifact, and replay evidence.

The broker stores only canonical public mapping/grant truth in an
owner-private, single-link, non-symlink SQLite file below an owner-private
directory; preexisting journal, WAL, or shared-memory sidecars receive the same
validation before SQLite opens them and all materialized sidecars are
revalidated after initialization. SQLite uses foreign keys, WAL,
`synchronous=FULL`, and an untrusted
schema. Mapping heads, immutable generations, permanent scope uniqueness,
grant lifecycle, and an append-only domain-separated SHA-256 audit chain are
durable. Audit verification detects sequence, predecessor, payload, or digest
tampering. Database, installation-operator, owner-key, or provider compromise
remains inside their explicitly declared trust boundary.

## Rotation, rollback, and authority claims

A new provider or secret version is a signed monotonic mapping generation and
fences all older unredeemed grants. Emergency revocation is monotonic and
immediate. V1 intentionally has no operation that reactivates a revoked
generation or transfers a secret to a workload. A future surrogate/replay
protocol for workload-visible behavior requires a separate ticket, owner
approval, typed non-disclosing semantics, deterministic equivalence proof, and
permission-negative tests; this implementation does not provide one.

The contained provider used by tests is not production authority. Production
deployment must separately bind the broker binary/release, owner-key source,
provider adapter identity, network policy, service identity, trusted clock,
secret-manager authorization, and exact SCM or connector launch path before a
credential-dependent canary or cutover can be eligible.
