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

## Boundaries

The W2-A backend is for the compact filesystem profile. S3-compatible
multipart upload, bucket lifecycle policy, and cross-region replication remain
future HA-profile work. PostgreSQL log chunks remain inline and checksummed;
the object reference model supports their later externalization without
weakening the existing public API.
