# Controller truth v1

Status: implemented through batch W2-A.

## Transaction boundary

PostgreSQL is authoritative. Build admission commits the build, first node,
first attempt, durable event, and outbox message in one transaction. A
project-scoped idempotency key returns the original identifiers and does not
emit duplicate durable records.

Terminal publication is accepted only for the current attempt fence and
restore epoch, its exact lease owner, an accepted/running state, and an
unexpired lease. Attempt, node, build, event, and outbox mutations commit
together. Unleased, expired, concurrent, or stale publishers receive a
negative result.

Retries never rewrite an attempt. A failed or reconciliation-required attempt
may create exactly one child attempt with an incremented ordinal and an
immutable `retry_of` link. Replaying the retry decision returns that same
child. Exhausted retry budgets enter a checksummed dead-letter ledger.

External effects use a fenced, immutable-payload checkpoint ledger. Effect
class and payload digest cannot change after preparation. State advances
monotonically through prepared, applied, and confirmed, or enters the explicit
uncertain state. Uncertain work is listed for reconciliation and cannot regress
to an unconfirmed applied state.

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
effects or restore execution authority. The old attempt and its epoch remain
history; reconciliation may explicitly schedule a new retry rather than
rewriting that history.

Migrations use a database advisory lock and a version ledger, so concurrent
controller startup installs each migration exactly once.

## Scheduler boundary

The Wave 1 scheduler is intentionally single-node. A tenant-scoped
transaction advisory lock serializes claims. Candidate rows are selected with
`FOR UPDATE SKIP LOCKED`, the partial claim-order index, required-capability
containment, priority, queue age, and a caller-provided deterministic fairness
seed.

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
scopes. Scheduler control is service-only.

Schema installation and organization/project bootstrap require a separately
privileged connection. The runtime tenant role has read-only access to that
metadata and to identity, project-membership, and service-scope grants; grant
mutation is also privileged. Runtime request and scheduler transactions use
tenant context.

## Verification

The real-PostgreSQL gate proves:

- atomic and idempotent admission;
- one winner from 16 concurrent terminal publishers;
- capability-filtered scheduling and stable wait diagnostics;
- accepted-lease expiry, requeue, fence increment, and stale-result rejection;
- a tenant-prefixed scheduler claim-order index;
- immutable, idempotent, bounded retry history and dead-letter exhaustion;
- monotonic effect checkpoints, payload substitution rejection, and explicit
  uncertain-effect reconciliation;
- monotonic retention, legal-hold precedence, logical backup/restore,
  idempotent single-use activation, same-fence restore-epoch collision
  rejection, and stale recovery-point rejection; and
- forced-RLS read filtering and cross-tenant write rejection.

Rust unit tests independently prove the authorization matrix and deny defaults.
