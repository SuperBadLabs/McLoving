# Cache service v1

Status: implementation contract for the CACHE-001 contained boundary. No Mario
production cache, cache-dependent canary, cutover, rollback, or decommission
authority is claimed.

## Inventory boundary

The accepted Mario MIG-000 runtime-dependency manifest contains no admitted
cache mapping. CACHE-001 therefore implements and adversarially proves a
reusable contained cache. A later inventory generation and the board-defined
differential, package, canary, cutover, rollback, and decommission gates must
explicitly admit and reverify any production cache authority.

## Component boundary

`mcloving-cache` is a standalone, non-executing strict-NDJSON process backed by
one private SQLite database. It is not loaded into the controller, scheduler,
pipeline runner, dependency resolver, source acquirer, provisioner, or agent.
The parent-controlled stdin/stdout pipe is its only request transport. It has
no listener, network client, shell, build tool, package manager, repository or
workload credential, controller database/filesystem access, scheduler or agent
RPC, connector, observer, or external-effect authority.

The process may:

- read one bounded, owner-private, read-only configuration and one private
  receipt HMAC key;
- read bounded cache commands and publication bytes from stdin;
- maintain one private FULL-synchronous SQLite database;
- return bounded cache bytes and signed receipts on stdout; and
- execute no cached bytes.

The configuration is admitted only as an owner-owned, single-link regular file
with no group/other access and no write bits. Configuration binds the protocol,
service and implementation identity,
deployment and operator identity, monotonically increasing cache generation,
receipt key identity and digest, private database path, all limits, and a
sorted closed policy set. The running executable digest, configuration digest,
and receipt-key digest are rechecked before the database is opened.
The database persists the receipt-key identity and digest and rejects rotation;
key rotation requires a newly provisioned database so one audit chain can never
mix signatures from different keys.

## Canonical namespace and key

Every cache key is canonical JSON and its domain-separated SHA-256 binds:

- tenant, project, pipeline, and exact trust class;
- cache kind (`dependency` or `build`);
- policy identity and policy digest;
- cache generation and generation digest;
- controller restore epoch;
- caller-supplied logical key digest;
- immutable input, toolchain, and platform digests; and
- key schema version.

Identifiers are bounded printable ASCII without path syntax. Digests are exact
lowercase SHA-256. Policy sets and principals are strictly sorted and
duplicate-free. The service derives policy and generation digests itself.
Callers must present that exact generation digest with every key request; a
stale caller cannot be silently rebound to the active generation, and a
request cannot supply replacement policy bytes.

The exact trust class is part of both the policy and canonical key. A publisher
must present the policy's exact writer identity and trust class. A reader must
present the exact reader identity and trust class. V1 performs no trust
promotion: trusted and untrusted rows are disjoint even if every other key
field is identical. In particular, an untrusted publication can never satisfy
a trusted read.

## Transactional storage

SQLite uses `journal_mode=DELETE`, `synchronous=FULL`, foreign keys, strict
tables, and `trusted_schema=OFF`. Every read, publication, eviction, expiry,
rotation cleanup, and corruption rejection is one `IMMEDIATE` transaction.
Publication inserts the complete content BLOB and immutable canonical metadata
under a unique `(namespace_sha256, key_sha256, generation_sha256)` key. An
identical concurrent publication converges idempotently; different bytes for
the same key produce a signed conflict and never replace the winner.

Reads reserialize and compare the stored canonical key, rederive namespace,
key, generation, and content digests, and compare the exact byte length before
returning content. Any mismatch is a corruption rejection: the row is removed
in the same transaction and no bytes are returned.

Policy independently bounds entry bytes, total live bytes, live entry count,
and TTL within service-wide maxima. Configuration also bounds retained audit
events. Before publication, expired rows are
removed and deterministic least-recently-accessed rows are evicted until both
byte and count budgets admit the new row. Receipt-producing eviction work is
bounded before commit so its complete response always fits the configured
frame. Access order is a database sequence, not caller time. Publication, read,
eviction, expiry, cleanup, and rejection sample the service clock only after
the write transaction is acquired; caller timestamps never determine
eligibility.

## Generation, restore, and cleanup

Every operation presents the current cache generation digest and controller
restore epoch. A generation rotation changes the derived generation digest;
the database atomically advances a monotonic active-generation/restore pointer,
and already-running stale processes fail closed on their next transaction. Old
rows become misses and are cleanup-eligible even when their policy no longer
exists in the active configuration. A controller restore advances
its existing monotonic restore epoch, so rows from a restored cache database
cannot satisfy current reads even when their logical key and content are
otherwise identical. Cleanup removes expired rows and any row outside the
current generation or restore epoch, with a bounded number of rows per command.
Before any explicit or publication-triggered cleanup or quota eviction signs a
stale, expired, or removed-policy disposition, it revalidates the original
signed publication against the historical runtime generation and exact stored
metadata/content, including the publication's signed absolute expiry. Missing
or substituted publication provenance or expiry is removed only as
`corrupt_rejected`. A row with a valid canonical receipt subject but corrupt
content remains purgeable and cannot indefinitely block cleanup or publication.

The restore epoch is controller-owned authority and must not be restored from
the cache backup. If that external invariant is unavailable, the cache must be
disabled rather than treating restored rows as current.

## Auditable provenance

Every admitted cache outcome appends a canonical event inside the same
transaction as the state transition. Events bind service/configuration/implementation,
policy/generation/restore epoch, caller, namespace/key/content digests, byte
length, signed absolute expiry when present, operation, outcome, event time,
and the previous event digest. The event digest is domain-separated SHA-256
and its signature is HMAC-SHA-256.
The database stores a contiguous sequence, previous digest, canonical event
bytes, digest, and signature. Verification against an independently retained
receipt count and head digest rejects deletion, reordering, substitution,
malformed canonical bytes, or signature mismatch.

The standalone audit-verification command requires that independently retained
count and head; it cannot bless a merely self-consistent shorter local chain.
Audit growth is capped by `max_audit_events`. The transaction that would exceed
the cap rolls back and the service fails closed until the operator retains the
head and provisions a new bounded database generation. Denied admission and
malformed or unterminated transport frames never mutate cache state and are not
inserted into this authoritative cache-outcome chain because their caller and
key fields have not passed canonical admission; the supervising controller
owns transport-denial telemetry.

Receipts never contain content. The standalone response carries content only
for a verified hit and is bounded by the configured frame limit. Nonempty EOF
without a newline is a malformed NDJSON frame and is never executed.

## Required proof

Contained tests must prove:

- cold miss and byte-exact valid hit;
- tenant, project, pipeline, kind, policy, principal, and trust isolation;
- key, generation, restore-epoch, metadata, and content substitution rejection;
- untrusted-write/trusted-read denial;
- same-content convergence and different-content conflict under concurrency;
- size, count, TTL, deterministic eviction, and bounded cleanup;
- generation rotation and restored-state cold behavior;
- receipt-key rotation rejection and signed stale-publication revalidation on
  explicit cleanup, publication-time cleanup, and quota eviction, including
  forged-expiry rejection and purgeability of corrupt stale content;
- complete signed audit-chain verification and tamper rejection;
- independently retained audit-head verification and bounded audit exhaustion;
- duplicate/unknown JSON rejection and bounded standalone frames;
- private state/key admission and zero network or execution authority; and
- a sealed Mario inventory assertion proving zero production cache authority.
