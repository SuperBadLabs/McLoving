# Contained sequential step execution v1

Status: JCOMP-002A implementation candidate. Runtime acceptance and closure
remain subject to the security review, protected merge, and exact-main gates.

The design derives from the September 9
[settled handoff](../handoffs/2026-09-09-master-chief/sequential-steps-design.md).
Each literal shell step becomes one existing version-1 process node, with an
immediate-predecessor Succeeded edge. Shells use Direct `/bin/sh` with exact
`[-xe, -c, script]` arguments and no explicit environment or timeout override.
Admission fixes Linux placement, `migration-deny-authority`, priority zero,
one attempt, and false fail-fast. The existing scheduler, remote protocol,
journal, process supervision, cancellation and retry machinery executes them.

`controller_api::sequential::plan_sequential_build` is a doc-hidden pure
library planner. It consumes strict-YAML-compiled IR and a saved revision
binding; it saves nothing and grants no execution authority. It rejects
parameters, values, expressions and nonliteral/unsupported process shapes.
Bounds are 1–32 nonempty stages, at most 64 steps, 96 UTF-8 bytes per retained
stage label, and 4096 script bytes individually and in aggregate. Empty scripts,
NUL and a `#!` prefix are refused. Stage IDs must match the protected ASCII
normalization of the labels. Original Jenkins grammar and source-byte limits
remain the independent compiler/admission boundary; IR cannot recheck source
bytes it no longer contains.

`SequentialDagBuild` owns its DAG and layout behind immutable accessors and
has no unchecked deserializer. Its constructor independently validates node
policy, exact process payloads, the linear dependency chain, node/layout
bijection, stage identity and contiguous stage/step/execution ordinals.
Layout rows carry labels and ordinals explicitly; keys are never parsed for
identity. Presentation order may be canonicalized only after identity checks.

`Store::admit_sequential_dag` saves the versioned layout in `builds.dag_contract`
within the existing build/nodes/attempts/edges/event/outbox transaction. Legacy
contract bytes remain unchanged. New sequential admission requires the planned
semantic digest to equal the saved enabled revision digest; legacy parameterized
admission retains its separate saved and instantiated digests. Replay checks
original revision, generation, both frozen digests and the complete contract
before consulting current enabled state. It returns the original node and
ordinal-one attempt IDs even after authorized retries or later source edits.

`Store::sequential_build_result` reads a scoped PostgreSQL repeatable-read,
read-only transaction. All build, contract, node, edge, attempt and log-reference
reads share that snapshot. It validates immutable layout and node payload,
capabilities, placement, priority and edge bindings, while reading cancellation,
retry budgets and attempt lineage as mutable runtime truth. An explicit
operational bound returns `SequentialReadIncomplete`; it never truncates
history silently or treats a legitimate long retry lineage as corruption.
Malformed present sequential metadata returns `SequentialIntegrity`; legacy
and absent builds have no sequential projection. Public BuildGraph and HTTP
responses retain their existing serialization.

Stage status uses current logical node outcomes. While children remain
nonterminal, reconciliation takes precedence, followed by running for active
or partly progressed work, queued, then blocked. Terminal failure outranks
abortion; all succeeded and all skipped retain their distinct outcomes.
Succeeded+skipped terminal mixtures without failed/aborted outcomes violate
the admitted linear chain. Build status is the existing stored build policy.
Owner cancellation aborts unstarted nodes; failed dependencies skip logical
nodes even when their precreated placeholder attempts are accounted aborted.
Historical failed attempts do not determine the status of successfully retried
nodes, and earlier successful nodes do not rerun.

The real lease-loss campaign exposed an existing generic requeue policy that
could execute the same attempt again under a higher fence when no protected
connector effect existed. Contained sequential mode now requires reconciliation
after an expired lease if StartWork was recorded for that fence. StartWork does
not prove process birth, but the controller can no longer prove absence of a
process after it. Pre-start offers remain safely requeueable. This change is
scoped to the new sequential contract; generic DAG policy is unchanged.

Attempt started/completed timestamps are controller accounting observations,
not process-birth or process-exit observations. Actual shell markers and bounded
stdout/results supply process-execution evidence. Attempt UUID, fence, stream
and sequence ranges preserve log attribution without concatenating scripts or
presenting processless terminal accounting as a shell exit.

The public one-step guard remains. This mode has no new HTTP/gRPC route,
production opt-in flag, schema table, imported-job enablement or agent protocol.
Its fixtures are fresh authored saved pipelines. S03/S06/S07 remain outside
this contained campaign until JCOMP-002B supplies workspace continuity.
S07's preexisting generic one-step-per-stage YAML acceptance promises no file
continuity. No arbitrary-shell workspace heuristic is claimed.

Foundation's PostgreSQL lane invokes `scripts/test-sequential-runtime.sh` with
the shipped controller and agent. The verified-test wrapper rejects missing
PostgreSQL, failed/skipped/empty/wrong-sized populations. The separate store
tests exercise digest binding, replay, retry, scope, corruption refusal and
snapshot coherence; actual remote tests exercise shell lifecycle and durable
ordering. Local execution uses a private disposable database/runner namespace,
with no published ports, production credentials or host workspace.

JCOMP-002B owns workspace lifecycle and non-collision; SEC-005 owns hostile
same-UID workload isolation. JCOMP-003 owns paired Jenkins execution and
separate 228-source reclassification. This candidate grants none of those
claims and no production authority.
