# State transfer v1

Status: `MIG-005A` verified implementation

## Contract

`mcloving.state-transfer/v1` is the internal, lossless persistence envelope for
moving admitted execution history between Jenkins and McLoving. It is not a
user-authored configuration format. McLoving's product configuration remains
canonical strict YAML; state-transfer receipts use deterministic canonical JSON
because they carry machine-generated record graphs, byte digests, and replay
bindings rather than human intent.

Every bundle binds the transfer direction, exact source and destination
identities and generations, source-export digest, canonical input-bundle digest,
transform implementation and
configuration digests, conflict policy, provenance, and the complete sorted
record inventory. The model preserves:

- job, queue, build, trigger, typed parameter, timing, result, and previous-result truth;
- checkout provider, repository, ref, revision, previous revision, canonical
  change entries, and changelog provenance;
- graph nodes, stages, attempts, approvals, normalized tests, ordered logs,
  artifacts, retrieval metadata, retained workspaces, and persistent dependencies;
- retention identity, policy version, policy digest, deadline, and active legal
  holds with identity, scope, reason, placement, generation, provenance, and
  release authority;
- record-level source digests, data classification, secret references or held
  evidence, and audit linkage.

The transform is pure and deterministic. Exact replay returns the original
receipt. Divergent replay, source or destination substitution, provenance
substitution, gaps, duplicate records, noncontiguous attempts or logs, stale SCM
baselines, unclassified state, retention shortening, hold omission, divergent
hold identity, and unauthorized hold release fail closed.

Nested state cannot weaken its container's trust boundary: every filesystem
entry is at least as restrictive as the object that contains it. Persistent
dependency keys are unique within a job, so replay and reconciliation never
silently collapse two distinct dependencies onto one identity.
For every graph node with attempts, the node result must equal its final
attempt result; contradictory execution history is rejected before transfer.
Each import also requires an independently supplied digest of the complete
canonical input bundle, so a claimed source-export identity cannot authenticate
substituted semantic content. Artifact and retained-workspace logical names are
unique within their destination lists, and each object kind must match its
containing list. Every artifact's producer build number must also match the
build that contains it; retained-workspace provenance remains job-scoped.
Graph-node attempts are contiguous, ordered, non-overlapping,
and bounded by their owning build's start and end timestamps.

## Persistence and reconciliation

Migration `0017_state_transfer.sql` adds immutable receipt, record-provenance,
and effective-protection truth to PostgreSQL. Import runs in one transaction,
locks the destination project's transfer history, fingerprints canonical input
before destination protections are merged, admits an exact replay only when
that input and every binding match, monotonically merges destination
retention and active holds before publishing the receipt, appends audit truth,
and writes the transactional outbox. Database triggers deny receipt/record
mutation, protection deletion, deadline shortening, hold omission, and hold
substitution even if a privileged migration caller bypasses the Rust API. The
runtime tenant has read-only access to transfer receipts, records, protections,
and migration SCM evidence; it has no direct insert/update authority. The separately
privileged import path first applies the complete Rust schema and semantic
validator. Receipt insertion then binds the raw canonical bundle and binding
hashes to every indexed binding column, and a deferred constraint requires the
exact record-provenance set and exact effective-protection set plus matching
immutable audit proof before commit. Provenance is inserted in bounded 512-row
batches; once the
matching immutable audit proof seals a receipt, a separate trigger rejects every
later provenance append. The constraint flattens each canonical record and
protection set once before set comparison; receipt validation is linear rather
than a record-by-record recursive rescan.
The database completeness fence independently rejects an empty record
denominator, an empty or structurally malformed job set, and therefore cannot
publish a vacuously complete counterfeit receipt.

Reader and execution authority consume only a committed receipt. The rehearsal
first verifies the sealed source-evidence file set and every digest, binds the
declared runtime root to the supplied Jenkins home, re-hashes the complete live
build/workspace trees and job configuration, and only then deterministically
constructs the canonical input bundle. A post-export live-configuration
substitution is rejected before bundle construction. The rehearsal then reloads
and independently revalidates the committed receipt and resolves the exact prior
SCM checkout. New change records are accepted only from an immutable canonical
evidence row written by the separately privileged migration writer and fenced
to the exact receipt, project, live attempt, agent lease, and current restore
epoch. The ordinary runtime role cannot insert, update, or delete that evidence;
PostgreSQL verifies its canonical-byte digest and conflicting replay is denied.
The controller checks that this authenticated checkout continues the transferred
revision and derives the change predicate decision from the durable evidence. It then executes the
first McLoving build through the real controller state machine with
external-effect authority explicitly false and exports the resulting history
through the same versioned reverse transform.
The source harness retains its exact stopped runtime by default because the
transform and reverse-reconciliation commands consume that runtime. Cleanup is
explicit through `CLEAN_MIG005A_RUNTIME=1`; an ordinary successful source run
never silently deletes the next phase's inputs.

## Filesystem and secret boundary

Filesystem inventories contain only canonical relative directories and regular
files. Symlinks, hardlinks, devices, sockets, and FIFOs have no representable
source kind. Literal secret bytes are not materializable; secret state must use
a credential reference or separately held evidence with release authority.

Linux materialization is quota-bound and descriptor-relative. It opens the
pre-existing staging root without following links, resolves every component
with `openat2(2)` using `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`,
`RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_XDEV`, and creates regular files with
exclusive no-follow semantics. The staging root must be empty before the first
write; existing regular files, directories, hardlinks, devices, FIFOs, sockets,
and other unclassified entries are rejected rather than retained or overwritten.
Payload count, size, classification, and SHA-256 must match before the first
write. The same pre-write pass rejects any regular file used as another entry's
ancestor, preventing a late path-type failure from leaving a partial tree.
Platforms without this safe implementation return an explicit unsupported error;
there is no weaker fallback.

## Exact-profile rehearsal

The accepted disposable rehearsal used:

- Jenkins image `docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02`;
- PostgreSQL image `docker.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`;
- transform binary SHA-256 `9b30a5218012ec46cf29ac9f2758e19ca2ad7123e87fec453e320ba28f66ab56`;
- source-evidence manifest SHA-256 `66bc739f25079abc455bb28072fcc7b747aac20594d1acd91d2879f9d307582b`;
- forward bundle SHA-256 `a4b1179a6f3671f56d5f1fb5549e54b3904567c1012eaac1008c8a47ebbc74f4`;
- reverse bundle SHA-256 `ec4dd8f75ef567a7f2cc35ca915e1f8d359c095dc74ffcdab004f3c6b18a147a`;
- reverse-evidence manifest SHA-256 `06eaed0f12272feaf2ae7998910140deae5449feeffb61feaeb98a16da758b68`;
- sealed transform-evidence manifest SHA-256 `d1159befcc9e9a17ccb10b8250c228ac810d3b1e0db1753a40955c5432eb7c30`;
- full imported-build verification receipt SHA-256 `ace08538925ffb47b81326efb7b72b8ed4cef6a0b5462d3afc87d001eabfdcc4`.

The exact database contained three receipts (destination protection seed,
forward import, reverse import), 143 record-provenance rows, nine effective
protection rows, three fenced SCM-evidence rows, and 37 outbox rows. Exact
replay reused the forward receipt. Jenkins workflow stages came from sealed
native workflow responses. McLoving build 3 was exported only after rereading
its durable five-node graph, attempts, logs, artifacts, and checkout; the
reverse Jenkins import matched the full canonical record and independently
verified native build/workflow/log/artifact/SCM semantics.
The imported shorter/expired source protections were strengthened to deadline
`2000000000000`; three overlapping active holds survived; a direct SQL hold
release was denied.

An injected failure after reverse state installation restored the original
repository revision, build set, permalinks, and next-build number, removed the
partial output, and allowed the same immutable inputs to complete on immediate
retry.

Jenkins build 1 established an empty first-build changelog. Build 2's changes
were derived from bounded sealed Git changelog bytes whose head and baseline
were bound to the exact checkout revision and previous revision. The pinned
next revision selected equivalent positive `changeset` and `changelog`
predicates in McLoving, produced one externally effect-free authoritative build
3, and advanced history to build 4. The reverse rehearsal verified the canonical
bundle digest, derived build/result/SCM/predicate state from that bundle, and
accepted artifact sidecars only after their lengths and SHA-256 digests matched
the bundle's retrieval records. The forward receipt also bound Jenkins build 2's
`persistent.state` as a first-class persistent dependency. McLoving restored
and authenticated its `build=2` payload at SHA-256
`d24c1088dcdfb2bb102abcb0d5fe3c7b71768ce10fb56efc97874d997a59c7d3`,
consumed that value to produce `build=3`, and reverse-exported both the updated
dependency and artifact at SHA-256
`929f7d96cf9c8afd8517b80afadeb4a7f01f95107f4e83fc1cfb7c5ccb58e61b`.
The same committed forward receipt carried the retained `stateful` workspace.
McLoving reconstructed its complete classified inventory through the bounded
no-follow materializer, emitted an exact materialization receipt, consumed
`src/first.target` as build 3 input at SHA-256
`b5cc31e2377133418f4f7589df551ce558a4b8820eb7c5c88583bf57e06d0c1a`,
and bound those exact bytes to build 3's `workspace.input` artifact. Jenkins
then loaded reverse-imported build 3, retrieved and independently compared both
the persistent-state and workspace-input artifacts, used its revision as the
next changelog
baseline, and ran build 4 on a nonmatching revision. Both predicate stages were
skipped, only `persistent.state` was archived, builds 1–4 were unique, and
`nextBuildNumber` became 5. Both Jenkins epochs were internal-network-only.

This is a case-specific pre-effect rehearsal, not general migration or
production-effect authority. `DIFF-002`, `MIG-006`, packaging, canary, cutover,
and rollback gates remain separate.
