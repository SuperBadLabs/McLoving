# ADR 0005: Controller, storage, and HA

Status: Accepted

The Rust controller begins as a modular monolith. PostgreSQL is authoritative;
state, events, and outbox messages commit together. Controller replicas are
active-active where practical. Filesystem storage supports compact deployment
and S3-compatible storage supports HA.

## Amendment (2026-08)

Outbox rows are delivery staging with bounded retention, not durable history:
the controller reaps rows older than a configured horizon (default 168 hours,
`MCLOVING_OUTBOX_RETENTION_HOURS`), while `audit_events` remains the durable
tamper-evident record and `build_events` the durable build history. No outbox
consumer is currently shipped, so unpublished rows are the expected steady
state and are reported as retention-bounded staging rather than a consumer
backlog. A future consumer gets its own explicit contract and cannot assume
unbounded outbox history; rows
with topic `state_transfer.imported` are excluded from reaping in defense of
the state-transfer receipt completeness fence.
