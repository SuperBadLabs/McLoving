# ADR 0003: Durable state machines

Status: Accepted

Builds, nodes, and attempts have distinct durable state. Attempts are immutable
history. Delivery is at least once and transitions are idempotent. Lost
communication enters reconciliation rather than implying process failure or
authorizing blind re-execution.
