# Operational data v1

Status: compact-deployment object contract implemented by W2-A.

## Object commitment

The filesystem backend stages bytes outside the immutable namespace, fsyncs
the staged file, computes SHA-256 after any required log redaction, and commits
with a create-only hard link. The durable object path is
`objects/sha256/<prefix>/<digest>`. Existing content is accepted only when its
digest and byte count match exactly; it is never overwritten.

Artifacts are binary-preserving. Log redaction replaces exact configured
secret byte sequences before hashing and commitment, so unredacted bytes never
enter the durable namespace. The PostgreSQL controller records object kind,
logical name, digest, byte count, attempt, and fence. Registration requires the
exact live fenced owner, and an existing logical object cannot change identity.

## Quotas and gaps

Compact deployments enforce both per-object and total committed-byte quotas
before staging. Quota exhaustion is explicit backpressure rather than silent
truncation.

Reads verify both SHA-256 and byte count. Missing and corrupt objects are typed
gaps. Reconciliation compares the PostgreSQL-declared set with committed
content and reports missing, corrupt, and orphaned objects separately. Gap
status is durable controller truth and does not rewrite the expected digest.

## Recovery authority

Every scheduler claim records the controller-wide restore epoch while holding a
shared lock on that epoch. A restore activation takes the exclusive lock,
increments the epoch, clears every active lease, and moves the affected
attempt, node, and build to `reconciliation_required` in the same transaction
as its event and outbox record. Pre-restore agents consequently cannot renew,
publish logs or objects, or finalize work.

A sealed recovery point binds a stable backup identifier to the current restore
epoch and PostgreSQL WAL position. Compact deployments use the executable
logical dump/restore drill in `scripts/test-backup-restore.sh`. HA deployments
must pair the same recovery-point and restore-epoch protocol with physical base
backups and continuous WAL archiving; a recovery-point record alone is not a
claim that WAL replay is configured.

After restoration, object reconciliation compares the restored PostgreSQL
references with immutable object content. Missing and corrupt references remain
explicit gaps, while committed content absent from controller truth is reported
as orphaned and is not silently adopted or deleted.

## Retention and legal hold

Content is fail-closed for deletion: an object becomes eligible only after a
retention record exists, its deadline has expired, and no active legal hold
references its digest. Retention deadlines can be extended but never shortened.
Legal holds have stable keys and immutable reasons; release timestamps preserve
their audit history, and a released hold cannot be silently reactivated.

## Boundaries

The W2-A backend is for the compact filesystem profile. S3-compatible
multipart upload, bucket lifecycle policy, and cross-region replication remain
future HA-profile work. Physical PostgreSQL PITR infrastructure is also a
deployment-profile responsibility; W2-A supplies the checkpoint, fencing, and
differential restore contract plus a real compact logical-restore drill.
PostgreSQL log chunks remain inline and checksummed; the object reference model
supports their later externalization without weakening the existing public API.
