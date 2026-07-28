# ADR 0010: Operational data and recovery

Status: Accepted

Execution state, build output, telemetry, and audit are distinct. Logs and
artifacts use staged, checksummed commitment. Caches never establish
correctness. Quotas create controlled backpressure. Disaster restoration fences
old authority and reconciles agent journals.
