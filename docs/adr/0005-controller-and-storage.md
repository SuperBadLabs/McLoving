# ADR 0005: Controller, storage, and HA

Status: Accepted

The Rust controller begins as a modular monolith. PostgreSQL is authoritative;
state, events, and outbox messages commit together. Controller replicas are
active-active where practical. Filesystem storage supports compact deployment
and S3-compatible storage supports HA.
