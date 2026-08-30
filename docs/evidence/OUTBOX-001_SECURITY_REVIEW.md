# OUTBOX-001 retrospective security review

Date: 2026-08-30

`OUTBOX-001` closed in protected-main commit `ec1529b` (PR #75). The controller
transactionally wrote an outbox copy for every durable transition while no
shipped binary consumed those rows. Treating `published_at IS NULL` as a queue
would therefore grow without bound and mislead operators about a delivery
contract that did not exist.

The selected design keeps the transactional outbox because state-transfer
receipt admission depends on its exact proof row and every ordinary transition
also has durable `build_events` and hash-chained `audit_events`. A bounded
tenant-scoped reaper removes staging older than the configured horizon,
excludes `state_transfer.imported`, uses bounded batches, and preserves RLS.
Current code reports retained rows as expected retention-bounded staging once
at startup and after reclamation; it no longer emits a recurring “backlog”
warning suggestive of a missing live consumer. No downstream consumer is
claimed or silently simulated.

The threat-model review covered unbounded database growth, cross-tenant reap,
loss of the protected transfer proof, operator misinterpretation, and deletion
of durable history. Existing controller-storage, tenant-isolation, audit, and
state-transfer boundaries cover these risks; ADR 0005 records the no-consumer
truth and retention contract. Runtime database tests prove bounded inputs,
oldest-first batches, tenant isolation, protected rows, and publish/reap
interaction.

Residual risk is explicit: no external event delivery exists. A future
consumer requires its own delivery, retry, idempotency, retention, and privacy
contract. `build_events` and `audit_events`, not retained outbox staging, remain
the durable operator and forensic records. This receipt supplies the omitted
retrospective review for `OUTBOX-001`.
