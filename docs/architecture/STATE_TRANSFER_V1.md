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

## Persistence and reconciliation

Migration `0017_state_transfer.sql` adds immutable receipt, record-provenance,
and effective-protection truth to PostgreSQL. Import runs in one transaction,
locks the destination project's transfer history, fingerprints canonical input
before destination protections are merged, admits an exact replay only when
that input and every binding match, monotonically merges destination
retention and active holds before publishing the receipt, appends audit truth,
and writes the transactional outbox. Database triggers deny receipt/record
mutation, protection deletion, deadline shortening, hold omission, and hold
substitution even if an internal caller bypasses the Rust API. Receipt insertion
also binds the raw canonical bundle and binding hashes to every indexed binding
column; a deferred constraint requires the exact record-provenance set and
the exact effective-protection set plus matching audit/outbox proof before
commit, so a direct runtime insert cannot publish partial or counterfeit
committed truth. The constraint flattens each canonical record and protection
set once before set comparison; receipt validation is linear rather than a
record-by-record recursive rescan.

Reader and execution authority consume only a committed receipt. The rehearsal
reloads and independently revalidates that receipt, resolves the exact prior SCM
checkout, checks that the delivered revision continues it, and derives the
change predicate decision from those committed records. It then executes the
first McLoving build through the real controller state machine with
external-effect authority explicitly false and exports the resulting history
through the same versioned reverse transform.

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
- transform binary SHA-256 `098f8fc36d079f7bbcb4ffcf8fc3d938a8b3f3c879987e2b1b30eaa1d06c0c16`;
- source-evidence manifest SHA-256 `032e9ff221365501c0588e39877d54af0d2d90ac47f40290522c98d96494c0c8`;
- forward bundle SHA-256 `a140148aeb3bba94b09fe28240122410330ea7c9a45a2576390e0e5224624b96`;
- reverse bundle SHA-256 `f9f59b142943abc4589bb4d9dc47232acb5b5ce204505a442f2b1bf46a0a9219`;
- reverse-evidence manifest SHA-256 `103ceb4d5936573f4c832512f4ad4d0c63f32318233cd2ea00479f27924f90ef`;
- sealed transform-evidence manifest SHA-256 `ced62b7a554357722b2408a4cb32242964cf657c54a30c860b83c6a416a4c260`.

The exact database contained three receipts (destination protection seed,
forward import, reverse import), 112 record-provenance rows, eight effective
protection rows, and eight outbox rows. Exact replay reused the forward receipt.
The imported shorter/expired source protections were strengthened to deadline
`2000000000000`; three overlapping active holds survived; a direct SQL hold
release was denied.

Jenkins builds 1 and 2 established the SCM baseline and positive `changeset`
and `changelog` branches. The pinned next revision selected both equivalent
predicates in McLoving, produced one externally effect-free authoritative build
3, and advanced history to build 4. The reverse rehearsal verified the canonical
bundle digest, derived build/result/SCM/predicate state from that bundle, and
accepted artifact sidecars only after their lengths and SHA-256 digests matched
the bundle's retrieval records. Jenkins then loaded reverse-imported build 3,
retrieved its exact artifact, used its revision as the next changelog
baseline, and ran build 4 on a nonmatching revision. Both predicate stages were
skipped, only `persistent.state` was archived, builds 1–4 were unique, and
`nextBuildNumber` became 5. Both Jenkins epochs were internal-network-only.

This is a case-specific pre-effect rehearsal, not general migration or
production-effect authority. `DIFF-002`, `MIG-006`, packaging, canary, cutover,
and rollback gates remain separate.
