# Operational data v1

Status: compact-deployment object contract implemented by W2-A.

## Object commitment

The filesystem backend stages bytes outside the immutable namespace, fsyncs
the staged file, computes SHA-256 after any required log redaction, and commits
with a create-only hard link. The durable object path is
`objects/sha256/<prefix>/<digest>`. Existing content is accepted only when its
digest and byte count match exactly; it is never overwritten. The destination
directory is synced before the staged link is removed, so a crash cannot erase
both names. Failed staging writes are removed and the staging directory is
synced before the failure is returned.

Artifacts are binary-preserving. Log redaction deletes exact configured secret
byte sequences to a fixed point before hashing and commitment, including
matches that appear only after an earlier deletion joins two byte ranges.
Raw log input is bounded by the per-object quota before redaction. A redaction
request is rejected above 256 nonempty patterns, 64 KiB of aggregate secret
bytes, or 64 MiB of worst-case comparison work.
The PostgreSQL controller records object kind, logical name, digest, byte count,
attempt, and fence. Registration requires the exact live owner, fence, and
restore epoch, and an existing logical object cannot change identity.

## Quotas and gaps

Compact deployments enforce both per-object and total reserved-byte quotas.
An exclusive filesystem lock serializes reservation and commitment across
processes; outstanding staged objects consume quota before publication. Quota
exhaustion is explicit backpressure rather than silent truncation.

Reads verify both SHA-256 and byte count. Missing and corrupt objects are typed
gaps. Reconciliation compares the PostgreSQL-declared set with committed
content and reports missing, corrupt, and orphaned objects separately. Gap
status is durable controller truth and does not rewrite the expected digest.

## Recovery authority

Every scheduler claim records the controller-wide restore epoch while holding a
shared lock on that epoch. Every subsequent agent read or write must present
that epoch together with the attempt, fence, and agent identity while holding
the same shared lock. The attempt epoch must still equal current controller
metadata, so a restored queued attempt may safely reuse a numeric fence without
accepting authority from the discarded timeline. Worker workspace paths also
include the restore epoch. The compact agent journal packs the positive restore
epoch and attempt fence into one ordered local authority value (31 epoch bits,
32 fence bits); values outside that explicit envelope are rejected before
acceptance rather than aliased.

Lease expiry is not permission to repeat a non-idempotent external effect. Any
non-idempotent checkpoint routes the attempt hierarchy to
`reconciliation_required` instead of queued. Prepared and applied checkpoints
become `uncertain`; confirmed checkpoints remain confirmed and still prohibit
automatic retry. A payload-identical fenced operator confirmation and an
explicit audited terminal reconciliation are required to close uncertain work.
Effect-free and safely repeatable work retains the normal
requeue-and-new-fence path.

A restore activation takes the exclusive lock, increments the epoch, clears
every active lease, and moves the affected attempt, node, and build to
`reconciliation_required` in the same transaction as its event and outbox
record. Replaying activation for the same backup returns the original epoch and
affected count without another increment. Once an epoch advances, a different
unused recovery point sealed in the prior epoch is stale and is rejected.
Prepared or applied external effects on affected attempts become `uncertain`
for explicit reconciliation. Pre-restore agents consequently cannot renew,
checkpoint new effects, publish logs or objects, or finalize work.
Reconciliation can only confirm an existing payload-identical uncertain effect
and does not restore the historical attempt's authority. A restore may sweep
prepared or applied checkpoints from earlier attempt fences; those exact
historical rows remain confirmable, and terminal reconciliation is prohibited
while any fence still contains an uncertain checkpoint.

A sealed recovery point binds a stable backup identifier to the current restore
epoch. After the recovery-point row commits, a first PostgreSQL WAL position is
stored as its immutable seal. After that finalizing transaction commits, a
second WAL position is advertised as the recovery boundary; backup tooling
must retain through this later boundary so replay includes the sealed row.
Compact deployments use the executable logical dump/restore drill in
`scripts/test-backup-restore.sh`. HA deployments
must pair the same recovery-point and restore-epoch protocol with physical base
backups and continuous WAL archiving; a recovery-point record alone is not a
claim that WAL replay is configured.

After restoration, object reconciliation compares the restored PostgreSQL
references with immutable object content. Missing and corrupt references remain
explicit gaps, while committed content absent from controller truth is reported
as orphaned and is not silently adopted or deleted.

## Retention and legal hold

Content is fail-closed for deletion: a globally deduplicated object becomes
eligible only after every referencing tenant has an expired retention record
and no tenant has an active legal hold on its digest. Retention deadlines can
be extended but never shortened.
Legal holds have stable keys and immutable reasons; release timestamps preserve
their audit history, and a released hold cannot be silently reactivated.
Eligibility inspection is diagnostic only. Physical deletion requires a
durable tokenized claim under a digest-scoped transaction lock. While claimed,
new references, retention extensions, and legal holds lose to that same lock.
Active claims are listable with their exact token after process restart. The
deleter must commit an irrevocable `deleting` transition before touching
physical storage. A merely claimed token can be abandoned; a deleting token
cannot be revoked because its physical outcome may be ambiguous and must
instead be recovered and completed. Completion leaves a permanent tombstone,
so stale metadata cannot recreate a reference to physically deleted content.
The global claim table and its trigger guard are inaccessible to the tenant
role; tenant writes are fenced by the trigger without exposing a callable
cross-tenant state oracle.

## Boundaries

The W2-A backend is for the compact filesystem profile. S3-compatible
multipart upload, bucket lifecycle policy, and cross-region replication remain
future HA-profile work. Physical PostgreSQL PITR infrastructure is also a
deployment-profile responsibility; W2-A supplies the checkpoint, fencing, and
differential restore contract plus a real compact logical-restore drill.
PostgreSQL log chunks remain inline and checksummed; the object reference model
supports their later externalization without weakening the existing public API.
