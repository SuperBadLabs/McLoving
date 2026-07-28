# Controller truth v1

Status: implemented by batch W1-A.

## Transaction boundary

PostgreSQL is authoritative. Build admission commits the build, first node,
first attempt, durable event, and outbox message in one transaction. A
project-scoped idempotency key returns the original identifiers and does not
emit duplicate durable records.

Terminal publication is accepted only for the current attempt fence, its exact
lease owner, an accepted/running state, and an unexpired lease. Attempt, node,
build, event, and outbox mutations commit together. Unleased, expired,
concurrent, or stale publishers receive a negative result.

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

Schema installation and organization bootstrap require a separately
privileged migration/bootstrap connection. Runtime request and scheduler
transactions use tenant context.

## Verification

The real-PostgreSQL gate proves:

- atomic and idempotent admission;
- one winner from 16 concurrent terminal publishers;
- capability-filtered scheduling and stable wait diagnostics;
- expiry, requeue, fence increment, and stale-result rejection;
- forced-RLS read filtering and cross-tenant write rejection.

Rust unit tests independently prove the authorization matrix and deny defaults.
