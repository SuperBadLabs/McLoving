# Sequential shell steps: contained runtime contract v1

Status: JCOMP-002A design draft. No implementation or runtime compatibility
claim is earned by this document. JCOMP-002 post-main checks have passed at
`904fd1f`; its board closure remains the next chief's first action. Recheck
current-main custody before starting implementation, as described in [README](README.md).

## Objective and boundary

Execute every selected literal shell step as a distinct, durable process attempt
through the actual controller and remote agent. Preserve ordered stage/step
identity, fresh-shell semantics, terminal results, logs, cancellation, fencing,
retry and recovery. JCOMP-002B separately supplies build-workspace continuity;
JCOMP-003 later earns paired Jenkins/product compatibility evidence.

This design adds no HTTP or gRPC endpoint, production opt-in flag, agent
protocol, multiprocess attempt, journal version, or database migration. Existing
Jenkins imported definitions remain disabled. Contained test pipelines are
fresh authored fixtures with their own explicit enabled state.

Contained admission uses platform `linux` and trust pool
`migration-deny-authority`, fixed by the trusted planner/test setup. No production
pool or scheduler authority is derived from source text. Existing generic public
pipeline admission and its one-step-per-stage guard remain unchanged.

## Execution unit and ordering

Lower each ordered shell step to one existing DAG work node containing exactly
one version-1 process step. It uses Direct mode, `/bin/sh`, and exact arguments
`[-xe, -c, script]`. The per-step environment map stays empty. No credentials, timeout override,
connectors, parameters, parameter values or expressions may be supplied through
the plan; the agent retains its existing base environment.

Each node after the first depends on its immediate predecessor succeeding,
including the transition between stages. Set `max_attempts=1` and
`fail_fast=false` at admission. The linear Succeeded edges provide downstream
skipping without changing global fail-fast semantics.

Every shell receives a separate process and attempt-local workspace. An exported
variable or cwd change cannot become another shell's environment/cwd. This does
not establish file continuity, placement on one agent, transfer between agents,
or hostile same-UID filesystem isolation.

Controller planning currently emits one node per stage at
`crates/controller-api/src/lib.rs:4258`. Reuse its process payload renderer at
`:4426` for one-step slices. Both remote agent `supported_process_spec` at
`bins/agent/src/worker.rs:696` and embedded spine `supported_spec` at
`crates/execution-spine/src/lib.rs:226` retain their one-process contract.

## Pure planner and frozen source

Expose a small doc-hidden, authority-free Rust library planner. It returns an
owned validated sequential plan and performs no database mutation. No Cargo
feature is needed; calling the function must not relax public validation.

The planner consumes strict-YAML-compiled PipelineIr from the saved source
revision. It validates 1–32 stages, at least one step per stage, at most 64 total
steps, stage labels of at most 96 UTF-8 bytes, nonempty shell literals of at most
4096 bytes each and in aggregate, and the exact process shape above. Reject
shell NUL and a shell prefix `#!`. Stage IDs must match the protected ASCII-only
normalization of their retained UTF-8 labels and remain distinct/nonempty.

The planner can validate only invariants represented in IR. It cannot recheck
original Jenkinsfile grammar or its 16-KiB source limit because those bytes are
not present. Generated YAML has its own existing strict parse limits; do not
apply the Jenkinsfile limit to escaped YAML. Original lexical admission remains
the versioned compiler/admission boundary established by JCOMP-002.

The contained harness compiles its actual saved YAML directly through the strict
IR compiler before calling this planner. It does not use the public guarded
compile helper to admit multi-step fixtures, nor maintain a second hand-written
DAG planner. See `crates/pipeline-ir/src/model.rs:254` and the unchanged guard in
`crates/controller-api/src/lib.rs:4520`.

## Immutable execution layout

Keep existing NewDagBuild/NewDagNode and legacy Store admission APIs unchanged.
Add an owned SequentialDagBuild wrapper with private fields, a validating
constructor, and immutable accessors. Do not derive unchecked deserialization.
Its ordered layout contains one row per node:

- node key, original stage ID and UTF-8 stage name;
- contiguous one-based stage ordinal and within-stage step ordinal;
- contiguous one-based global execution ordinal.

A key such as `stage-id[step=01]` fits existing bounded DAG key syntax, but names
and ordinals must never be recovered by splitting the key. Ordinals determine
canonical ordering; input vectors may be canonicalized only after validating
unique and contiguous identity.

Persist the full versioned layout inside the existing immutable
`builds.dag_contract`, in the same transaction as build/nodes/attempts/edges and
admission event/outbox. No additional table or post-admission layout write is
needed. Existing normalized contract bytes are unchanged for legacy mode.

Store validates complete node/layout bijection, bounded consistent stage
identity, contiguous ordinals, exact linear Succeeded edges, compatible v1
process payloads, fixed placement metadata and admission retry/fail-fast policy.
It independently checks structural consistency; trusted controller planning
owns source-to-IR semantics. Store needs no new pipeline parser dependency.

## Saved digest binding and replay

For new sequential admission only, require the planner's semantic IR digest to
equal the saved revision semantic digest returned by the existing enabled
pipeline lock, before inserting durable truth. This is valid because this mode
admits no parameterization. Use `PipelineIr::semantic_digest()`, which hashes its deterministic semantic
`canonical_bytes()`. Do not substitute Jenkinsfile bytes, generated YAML bytes,
layout bytes, or a differently wrapped canonical representation for those bytes.

Preserve both existing stored digest columns and require equality in sequential
mode. Do not impose that equality on legacy parameterized builds, where saved
and instantiated digests may differ. See
`crates/controller-store/src/lib.rs:6896` and `dag.rs:315`.

Exact existing replay is checked before consulting the current enabled
revision/generation. Compare original pipeline/revision/generation, both frozen
digests, mode, complete contract/layout and original node identities. Replay
after source edit or disable returns the original admission; it does not grant
new execution authority to a disabled generation. Mismatching mode/layout/digest
conflicts, including concurrent insertion races.

Replay after an authorized retry still returns original admission node and
ordinal-one attempt IDs. It does not compare those against the latest retry
attempt or rewrite the immutable admission contract.

## Coherent ordered results

Add a tenant/project/build-scoped internal result projection; preserve public
BuildResponse and BuildGraph serialization. Return frozen revision/digest,
layout version, stored build status, ordered stages/steps, current logical node
states, and complete ordered attempt lineage with UUID/fence/log references.
An explicit operational read limit returns an incomplete-read error; it must not
silently truncate lineage or treat legitimate retry history as corruption.

Read build, contract, nodes, attempts and edges in one PostgreSQL statement
snapshot, or an explicitly equivalent coherent snapshot. Existing multi-SELECT
BuildGraph reads are not sufficient for the new aggregate during races. Verify
layout version and complete immutable node/edge bindings before projection.
Legacy builds without a sequential layout return no sequential projection;
present malformed sequential metadata is an integrity error.

Compare immutable identity, payload, normalized capabilities, placement,
priority, fail-fast and edges with the original contract. Read mutable status,
logical outcome, cancellation, retry budget, attempt lineage and timestamps as
runtime truth; never reconstruct admission from mutable rows.

Aggregate current logical node outcomes, not historical attempt failures. While
children remain nonterminal, report reconciliation_required first, otherwise
running for active/cancelling or partially progressed stages, then queued or
blocked. Once terminal: failed outranks aborted; all succeeded is succeeded;
all skipped is skipped. A succeeded+skipped mixture without failed/aborted is
an integrity error for this admitted linear chain. Build status follows existing
durable build policy, not an independently invented aggregate.

Owner cancellation marks never-started nodes aborted. Failed dependencies mark
logical nodes skipped, although their precreated placeholder attempt may be
aborted with `dependency_not_succeeded`. Preserve that distinction and do not
fabricate shell exit codes for processless terminal accounting.

`attempt.running` timestamps record controller lifecycle accounting, not proof
that a shell spawned: StartWork precedes remote process creation. Expose these
as attempt-start/accounting times and use actual bounded output/result/process
identity observations for process-execution evidence. Synthetic skipped rows
have no running event. Terminal accounting time follows the current logical
terminal attempt; an older failed attempt cannot terminate a retried node.

## Retry, cancellation and recovery

Retain existing authority checks for session, restore epoch, fence, lease,
pipeline enabled generation, cancellation and terminal replay. Successor work
cannot become claimable until successful predecessor finalization commits.
Stale completion or uncertain process recovery cannot advance the chain.

An explicit authorized retry may raise current max_attempts and reopen skipped
descendants with new attempt ordinals. Preserve original max1 admission bytes;
do not reject projection because mutable budget or attempt count increased.
Earlier successful nodes do not rerun. Read current logical outcomes, keeping
older failed/aborted placeholders visible as history. See
`crates/controller-store/src/lib.rs:4797` and `:4886`.

Each existing agent journal still owns one process leader per attempt, with its
process-birth identity and terminal spool recovery. Logs retain existing
attempt/fence/stream/sequence keys. Layout supplies step attribution; never
concatenate streams or scripts into an opaque stage result.

## Contained acceptance and gates

Add a separate real remote-agent integration target using the established
`bins/agent/tests/remote_work.rs` topology: disposable DB/project, fresh authored
saved pipeline, same pure planner and atomic store admission, shipped controller,
shipped remote agent, test mTLS and per-test journal/workspace. Disable embedded
execution using its existing exact sentinel. No mock agent may supply execution
evidence. Record candidate revision and executed controller/agent binary hashes.

Run reviewed benign processes only in a disposable test boundary. Local tests
use a private no-external-network database/runner namespace, no published ports,
no production credentials or host workspace; hosted tests reuse the ephemeral
Foundation PostgreSQL lane. Missing DB/binaries, skipped or empty populations,
timeouts and unverified results fail the gate.

Required acceptance covers actual shell freshness and order; first/middle/last
failure with explicit downstream skipped results; pre-start and active owner
cancellation with aborted accounting; stale fence/session/restore epoch refusal;
lease loss; crash-after-terminal-commit replay; no duplicate process/log evidence;
correct step/stage/build results; atomic layout/replay/rollback and tenant
isolation; and coherent projection during retry/cancellation/finalization.
Preserve existing remote, embedded-spine, journal and native Windows checks.

Keep S03/S06/S07 out of contained JCOMP-002A submissions. S03/S06 multi-step
shapes remain rejected by the public guard. S07 has one shell per stage and may
already pass the generic YAML API; that legacy acceptance promises no workspace
continuity. No heuristic detects arbitrary workspace-dependent shell text.
The new Jenkins integration/compatibility campaign remains unavailable until
JCOMP-002B, and full paired fixture certification belongs to JCOMP-003.

Closure requires completed implementation, focused real-controller/agent and
store evidence, independent review, protected merge and exact post-main gates.
This draft establishes none of those outcomes.


Source references in this planning note describe repository commit `904fd1fed083cd17a6fc371e0a300c3696d93483` (tree `26240208f51f6028bf6bb6e619a2dcd5d19555f0`). Re-resolve paths and line numbers on the successor head. Planning and historical tool observations are not new runtime evidence.
