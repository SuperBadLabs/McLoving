# Controller truth v1

Status: implemented through batch W3-A.

## Transaction boundary

PostgreSQL is authoritative. Build admission commits the build, first node,
first attempt, durable event, and outbox message in one transaction. A
project-scoped idempotency key returns the original identifiers and does not
emit duplicate durable records.

Terminal publication is accepted only for the current attempt fence and
restore epoch, its exact lease owner, an accepted/running state, and an
unexpired lease. Attempt, node, build, event, and outbox mutations commit
together. Unleased, expired, concurrent, or stale publishers receive a
negative result. If the current fence contains an uncertain effect, ordinary
terminal publication instead atomically clears the lease, moves the attempt,
node, and build to `reconciliation_required`, and emits its durable audit
event/outbox record. Only the explicit reconciliation path may then confirm
the exact effect and close the attempt.

Retries never rewrite an attempt. A failed or reconciliation-required attempt
may create exactly one child attempt with an incremented ordinal and an
immutable `retry_of` link. Replaying the retry decision returns that same
child. Scheduling that child and terminally closing the parent reconciliation
are mutually exclusive decisions under the same advisory lock. Exhausted retry
budgets enter a checksummed dead-letter ledger, and that dead-letter decision
is likewise mutually exclusive with terminal reconciliation. Replaying the
decision cannot replace the dead letter with a larger retry budget.
Dead-lettering reconciliation work terminally fails its attempt hierarchy in
the same transaction instead of stranding non-runnable reconciliation state.

External effects use a fenced, immutable-payload checkpoint ledger. Effect
class and payload digest cannot change after preparation. State advances
monotonically through prepared, applied, and confirmed, or enters the explicit
uncertain state. Uncertain work is listed for reconciliation and cannot regress
to an unconfirmed applied state.
If a lease expires with any non-idempotent effect checkpoint, the same
transaction moves the attempt, node, and build to `reconciliation_required`.
Prepared and applied effects become uncertain; confirmed effects retain their
stronger evidence. Such work is never returned to the runnable queue or made
retry-eligible. A fenced operator may confirm an exact uncertain payload and
then explicitly terminate the reconciled attempt, with event and outbox audit.
An exact replay of a committed terminal reconciliation returns success without
emitting another event; a conflicting actor, outcome, fence, or summary is
rejected.

Claims share-lock and record the controller restore epoch. Every agent
authority operation presents `(attempt_id, fence, restore_epoch, agent_id)`,
shares the restore lock, and requires the attempt epoch to equal current
controller metadata. This prevents a database rewind from reviving an
otherwise identical owner/fence pair. Restore activation exclusively
increments the epoch, invalidates every active lease, and commits
`reconciliation_required` attempt, node, and build state with matching events
and outbox messages. Activation of one sealed backup is single-use and
idempotently returns its first result; unused recovery points from an older
epoch are rejected. Prepared or applied effect checkpoints on affected work
become `uncertain` in that same transaction. Pre-restore agents can no longer
renew or publish. A narrow reconciliation operation may only confirm an
existing payload-identical uncertain effect; it cannot create new historical
effects or restore execution authority. Same-epoch lease reconciliation is
restricted to the current fence. Restore reconciliation may confirm an exact
historical fence swept to uncertain, and terminal reconciliation is blocked
until no uncertain checkpoint remains on any fence. The old attempt and its
epoch remain history; reconciliation may explicitly schedule a new retry
rather than rewriting that history.

Migrations use a database advisory lock and a version ledger, so concurrent
controller startup installs each migration exactly once.

## Scheduler and pipeline-DAG boundary

Pipeline structure is first-class PostgreSQL truth rather than controller
memory. A DAG admission transaction persists the build, every logical node,
every first attempt, every typed dependency edge, one event, and one outbox
record. An exact project/idempotency-key replay returns the original
identifiers. A conflicting pipeline digest or node set fails closed.

Matrix axes and values are sorted before Cartesian expansion. Admission caps
axes at 8, values per axis at 32, and total cells at 256. DAG admission caps
logical nodes at 256, edges at 4,096, retries per node at 16, contract text at
256 bytes, and each execution specification at 256 KiB. Node keys are unique,
all dependencies exist, and a deterministic topological walk rejects cycles
before the transaction begins.

Every node carries an exact trust pool and normalized
`platform:<platform>` capability. Active-active claims require both exact
constraints and recheck durable dependency conditions in the locked claim
transaction. Candidate rows use `FOR UPDATE SKIP LOCKED`, priority, queue age,
and a caller-provided deterministic fairness seed. `succeeded` edges release
only after successful logical parents; `completed` edges release after any
terminal logical parent. Join nodes require at least two parents. Post nodes
require completion-only parents so cleanup can run after success, failure,
fail-fast cancellation, or skip.

Attempts retain individual terminal history. A retryable failure creates one
immutable `retry_of` child and returns the logical node to the queue in the
same transaction. Only exhaustion writes the node's single
`logical_outcome`. Fail-fast marks active peers for lease-polled cancellation,
skips unstarted non-post peers, and leaves completion-only post nodes blocked
until all parents settle. Owner cancellation atomically aborts all unstarted
nodes and marks active peers for the same fenced cancellation path.

After each exhausted logical outcome, the controller repeatedly advances
newly impossible and newly ready nodes, then derives build status from all
logical outcomes. No in-memory queue is required for restart recovery.
Terminal replay is identical-only, dependency advancement is transactional,
and concurrent replicas serialize graph transitions through locked build,
node, and attempt rows.

Every offer increments the attempt fence. Expired offers return to the queue
without changing the fence; the next offer increments it before work can be
accepted. Offer acceptance itself checks owner, fence, state, and expiry. Wait
diagnostics run inside tenant context, distinguish an empty queue from a
concrete capability mismatch, and report the missing capability set.

## Identity and tenant boundary

Organizations own projects, identities, builds, nodes, attempts, events, and
outbox records. Composite foreign keys prevent cross-tenant parent
substitution. The unprivileged `mcloving_tenant` PostgreSQL role has forced RLS
on every tenant-bearing table. A transaction-local organization setting is
mandatory; absent context exposes no rows, cross-tenant reads are filtered,
and cross-tenant writes are rejected.

Authentication never grants authority. The Rust policy engine denies by
default, rejects tenant mismatch before role evaluation, applies a
least-privilege human project-role matrix, and requires explicit service
scopes. Imported Jenkins policy uses immutable versioned action grants; its
presence disables role-lattice fallback, missing grants deny, deny wins mapping
conflicts, and stale identity provenance or generations produce no grant.
Scheduler control is service-only and cannot be imported from a Jenkins ACL.
See `AUTHORIZATION_MAPPING_V1.md`.

Schema installation and organization/project bootstrap require a separately
privileged connection. The runtime tenant role has read-only access to that
metadata and to identity, project-membership, and service-scope grants; grant
mutation is also privileged. Runtime request and scheduler transactions use
tenant context.

## Verification

The real-PostgreSQL gate proves:

- atomic and idempotent admission;
- one winner from 16 concurrent terminal publishers, with uncertain effects
  routed to explicit reconciliation rather than terminalized;
- capability-filtered scheduling and stable wait diagnostics;
- deterministic bounded matrices, parallel platform-specific claims,
  dependency-safe joins, bounded durable retries, completion-only post work,
  fail-fast active cancellation and unstarted skip, controller restart
  recovery, owner cancellation, terminal monotonicity, and one logical outcome
  per DAG node;
- accepted-lease expiry, safe requeue and fence increment, uncertain-effect
  reconciliation routing, and stale-result rejection;
- a tenant-prefixed scheduler claim-order index;
- immutable, idempotent, bounded retry history and dead-letter exhaustion;
- mutually exclusive retry/dead-letter-versus-terminal reconciliation
  decisions;
- monotonic effect checkpoints, payload substitution rejection, and explicit
  uncertain-effect reconciliation;
- monotonic retention, legal-hold precedence, durable serialized deletion
  claims, logical backup/restore,
  idempotent single-use activation, same-fence restore-epoch collision
  rejection, and stale recovery-point rejection; and
- forced-RLS read filtering and cross-tenant write rejection.

Rust unit tests independently prove the authorization matrix and deny defaults.
Real-PostgreSQL tests prove immutable policy generations, exact source/target
provenance, conflict and lifecycle fencing, revocation, rollback, audit, RLS,
and logical restore behavior.
