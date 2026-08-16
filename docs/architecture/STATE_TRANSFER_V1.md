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
Graph-node attempts are contiguous and bounded by their owning build. Executing
attempts carry distinct durable creation, dependency-readiness, and running
timestamps and are ordered and non-overlapping; an attempt can be created while
blocked, but cannot run before its recorded readiness, and a retry cannot be
queued before its predecessor terminates. Dependency generation selection uses
the child's readiness rather than its earlier creation timestamp.
A queued attempt terminalized without execution instead carries an explicit
terminal-only reason and no fabricated start time. The accepted reasons are
`fail_fast_skipped`, `dependency_not_succeeded`,
`dag_cancelled_before_execution`, and `cancelled_before_execution`; each has an
exact skipped or aborted node outcome, and only the controller-reopenable skip
reasons may precede a retry that names that exact terminal-only attempt. An
unsatisfied-dependency skip must also bind an actual `succeeded` edge to the
active non-successful parent generation; the terminal reason alone is not
accepted as evidence.

## Persistence and reconciliation

Migrations `0017_state_transfer.sql` and `0018_attempt_readiness.sql` add
immutable receipt, record-provenance, effective-protection, and per-attempt
dependency-readiness truth to PostgreSQL. Import runs in one transaction,
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
- transform binary SHA-256 `549ec832edb138cea2895cf02fc39a3e4ec244f8a0aec378473be8f952dfe4c9`;
- source-evidence manifest SHA-256 `0304557a39a7c2a58ff9e1f110bc1bd4ca3bb2df16b28d54cc3c94262b7f47c6`;
- forward bundle SHA-256 `af172be8893e282b72fc20b820382c8236e18c7b981bc3b4acbf57884ead55e4`;
- reverse bundle SHA-256 `1a66f2c6354011abd23f45671674291e0b22faeea1043791920fc5ee0123ef52`;
- reverse-evidence manifest SHA-256 `2063b41b982f2821d494bfba96d43125382ea39fb12a601fbed3ce0fd8a77e05`;
- sealed transform-evidence manifest SHA-256 `e28b47d2aa70ec2ad8cdaa2c48e1100c8862c9a47765d22a355c1660e96cafe7`;
- repair-verification receipt SHA-256 `aaf5bad61ca1b14a7bf542a71fea76291ac868d175863b3f310fffbaedcf0d5a`;
- full imported-build verification receipt SHA-256 `0e85104bdf06d4b797c9d8221087b75b98767f90b3917cafe76dc660146d7f98`;
- imported protection-record SHA-256 `ae301c2fe1fa002fcc1d9b583ccd9a56f8c6a50f59911545356b5affcd0b285e`;
- imported retry-history receipt SHA-256 `81b5fca8af93d25ce18d78474e26211b0f8568bcc1506eb401c52929a5c196cc`.

The exact database contained three receipts (destination protection seed,
forward import, reverse import), 147 record-provenance rows, nine effective
protection rows, three fenced SCM-evidence rows, and 43 outbox rows. Exact
replay reused the forward receipt. Jenkins workflow stages came from sealed
native workflow responses. McLoving build 3 was exported only after rereading
its durable five-node graph, actual `attempt.running` event times, globally
cursor-ordered committed logs, artifacts, and checkout. Graph edges preserve
their exact `succeeded` or `completed` dependency condition. A Jenkins stage
that follows an observed non-successful predecessor, including a `when`-skipped
`NOT_EXECUTED` stage, receives a `completed` edge rather than a fabricated
`succeeded` edge. Validation uses each child attempt's durable readiness time to
select the latest parent generation already admitted for either dependency
condition. It then requires that exact generation to be terminal for
`completed`, successful for `succeeded`, and ended no later than the child's
durable readiness transition.
Automatic and operator retry creation reevaluate those predicates while
holding the build-scoped DAG lock. A retry remains blocked with no readiness
timestamp until the active parent generation satisfies its exact edge; the
same transaction that advances the node records its readiness. The v18 schema
also supplies readiness for runnable attempts inserted by a pre-v18 replica
during the declared rolling-upgrade window while a trigger clears that default
for legacy blocked-DAG inserts. A second compatibility trigger serializes the
legacy insert-then-node-reopen retry sequence under the build-scoped lock,
reevaluates the exact dependency predicates, and translates an unsafe queued
transition back to blocked with no readiness timestamp.
This preserves children admitted before a later parent retry while rejecting
children started during executing or terminal-only active retries. Every retry
explicitly names its immediately preceding attempt and its
reason. A failed predecessor requires `failed`; an aborted predecessor is
eligible only with its exact reopenable terminal-only reason; dependency skips
use `dependency_not_succeeded`, while pre-execution cancellations remain final.
Missing, reordered, backward-terminal, mismatched, fabricated-running, and
post-success lineage fails closed. The
rehearsal exhausts checkout once, then operator-retries it: checkout records
`failed -> succeeded`, and three descendants each record terminal-only
`fail_fast_skipped -> succeeded`. Dependency chronology ignores the skipped
placeholder and binds to the child's first executing retry. A `completed` edge
binds to the latest parent generation that had begun when the child started: a
reopened child waits for an already-running parent retry, while an already
completed child remains valid if a later parent retry begins afterwards. The
reverse Jenkins import matched the full canonical record and
independently verified native build/workflow/log/artifact/SCM semantics; the
native workflow uses each stage's final executing attempt interval while an
exact sidecar and dedicated receipt preserve and compare all four retry
histories byte-for-byte.
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

## Exact admitted-case corrective closure

The later inventory audit found one real retained dependency outside the
synthetic rehearsal: `corpus-052-cinqict_jenkinsdev` has one aborted Jenkins
build under `build-history`. Its private five-file source tree remains only on
HeMan. The repository carries no source bytes or private source-seal metadata;
the already-public exact tree digest is
`b47cc3e1c19e1d486a2df2fc76343e3031ee370a79564fe88a471adbf6e53107`.

`mcloving-jenkins-state-transfer` implements the narrow exact adapter. It
requires the five-file denominator, denies links and special files, bounds
total bytes, rejects XML DTD/entity input and unknown workflow nodes, verifies
the tree digest before parsing, and emits the ordinary canonical
`mcloving.state-transfer/v1` bundle. The forward bundle preserves build 1 as
`aborted`, `next_build_number=2`, exact terminal timing, ordered empty
`log-index`, the `Build` workflow node, permalinks, indefinite retention, and
the `build-history` persistent dependency. Reverse preparation accepts only an
exact inverse binding and one contiguous completed successor; build gaps,
duplicate source identity, and noninverse source/destination identities fail
closed.

The exact retained run used the pinned PostgreSQL image above. Forward import,
exact replay, independent retrieval, one durable externally effect-free
McLoving build, reverse import, and independent reverse retrieval all passed.
The McLoving build actually executed the exact pinned `/bin/sh -xe` process,
captured its stdout and stderr as two ordered durable log records, produced
`Hello World`, preserved zero external effects, advanced history to build 2,
and produced reverse `next_build_number=3`.
The exact forward bundle, reverse bundle, and relocated evidence manifest all
verify in the owner-only HeMan evidence package. Their private digests are not
published to GitHub.

The reverse-continuity harness then used pinned Jenkins image
`docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02`
on an internal-only network. Before either controller started, the harness
authenticated the complete rehearsal manifest against the independently held
owner pin, copied every member into a private read-only snapshot, reverified
that snapshot, recomputed the independently pinned five-file source-tree digest
with no-follow reads, proved the authenticated build-1 record equals the
reverse bundle, and copied exactly the committed 90-plugin manifest denominator while verifying
every regular, singly linked plugin both before and after copy. A separate
non-authoritative template controller created the exact Jenkins-native
`ShellStep` structure using a recorded non-executing shell stub; it never ran
the admitted script, its raw log and byte-offset index were rebuilt so the
exact ShellStep owns both transferred process records, its ShellStep timing was
reconciled to the exact durable attempt and all other graph timestamps bounded
inside the canonical build interval, its unrepresentable native queue ID was
set to Jenkins sentinel `-1`, its template cause and queue-timing actions were
removed in favor of an
exact typed canonical-trigger sidecar that was byte-verified after install,
restart, and archival, and it was checked free of the template
marker and provenance before being destroyed ahead of
the destination proof. A fresh destination controller
then loaded private build 1 as `ABORTED`, loaded the reverse-imported build 2 as
`SUCCESS` without executing it, returned the exact `Build` workflow stage and
the two McLoving process-log records, restarted, and executed build 3 exactly
once as `SUCCESS`. Numeric history was exactly `[1,2,3]`, `nextBuildNumber`
became 4, public egress was denied, and the reverse-import receipt retained
`external_effects=0` and `production_authority=false`. Its owner-only retained
evidence manifest verifies on HeMan; its private digest and contents are not
published to GitHub.

These receipts close the exact recorded dependency in addition to the earlier
synthetic denominator. They grant no production identity, reader, trigger,
scheduler, credential, agent, connector, effect, shadow, canary, cutover,
rollback, or decommission authority. `MIG-007` must still embed or immutably
retrieve and verify these exact objects in its separately reviewed package.
