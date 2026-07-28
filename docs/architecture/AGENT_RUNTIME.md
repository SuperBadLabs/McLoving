# Agent runtime contract

Status: implemented Wave 1-B baseline

## Authority and transport

- The agent initiates HTTPS gRPC connections to the controller.
- The outbound endpoint requires an explicit controller CA, DNS identity,
  agent certificate, and agent private key.
- Enrollment bootstrap tokens are retained only as SHA-256 digests and are
  consumed once.
- Protocol major versions must match. Minor ranges must overlap, and only the
  highest common minor plus intersected features are admitted.
- Session and certificate epochs increase monotonically. Only the exact current
  session may act; reconnecting with a newer epoch fences the previous session.

The generated controller service is a contract surface. The agent crate does
not expose a listener.

## Acceptance and reconciliation

The local SQLite journal uses WAL, `synchronous=FULL`, foreign keys, strict
tables, and a bounded busy timeout. An acceptance acknowledgement is created
only after the immediate transaction commits.

Idempotent replay must match organization, attempt, fence, session, payload
digest, and workspace exactly. Any mismatch fails closed. Workload payloads and
credentials are not stored in the journal.

On restart, reconciliation reports every non-terminal attempt plus process-group
identity and checksummed log/result spool metadata. Terminal attempts remain
durable history but are excluded from active reconciliation.

## Linux execution boundary

- Each attempt receives one new normalized workspace beneath a configured
  canonical root.
- Existing destinations, absolute paths, traversal, non-directory parents, and
  symlink components are rejected.
- The direct child starts a new process group.
- Timeout and cancellation signal the whole group with `SIGTERM`, wait for the
  configured grace period, then use `SIGKILL`.
- Standard output and error are written directly to files, fsynced, and hashed
  before the outcome is returned.

Process groups are lifecycle containment. They are not a hostile multi-tenant
security boundary. Untrusted multi-tenant workloads still require a VM or
equivalent isolation; cgroup quotas remain deployment hardening.
