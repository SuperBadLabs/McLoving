# ADR 0010: Operational data and recovery

Status: Accepted

Execution state, build output, telemetry, and audit are distinct. Logs and
artifacts use staged, checksummed commitment. Caches never establish
correctness. Quotas create controlled backpressure. Disaster restoration fences
old authority and reconciles agent journals.

Recovery points bind backup identifiers to a PostgreSQL WAL position. Compact
deployments prove logical backup and restore; HA deployments add physical base
backups and continuous WAL archiving without changing the restore-epoch
protocol. Restore activation is a controller-wide transaction that invalidates
active leases and makes unresolved work explicit.

Retention is monotonic. Content is not deletion-eligible without an assigned,
expired deadline, and an active legal hold always wins. Hold release preserves
the audit record.
