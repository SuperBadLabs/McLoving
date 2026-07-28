# McLoving execution board

Updated: 2026-07-28

Status values: `PENDING`, `ACTIVE`, `BLOCKED`, `DONE`, `DEFERRED`.

## Wave 0 — Architecture and foundation

| Ticket | Status | Objective | Acceptance |
|---|---|---|---|
| FOUND-001 | DONE | Establish private greenfield repository | Monorepo skeleton, ADRs 1–15, board, threat model, CI policy, clean foundation commit and draft PR |
| ARCH-001 | PENDING | Validate the attempt/lease formal model | TLC runs in CI; stale finish, fencing, and terminal monotonicity invariants proven for bounded model |
| FOUND-002 | PENDING | Reproducible developer and CI toolchain | Pinned Rust/container toolchain, dependency cache policy, one-command HeMan validation |
| SEC-001 | PENDING | Complete initial threat model | Actors, assets, abuse cases, mitigations, residual risks, and test ownership reviewed |
| IR-001 | PENDING | Implement strict-YAML syntax gate | Restricted YAML rules, resource bounds, source spans, fuzz target, negative corpus |
| IR-002 | PENDING | Define Pipeline IR v1 schema | Canonical encoding, digest, provenance, version compatibility, independent validation |

## Wave 1 — Smallest truthful end-to-end slice

| Ticket | Status | Objective |
|---|---|---|
| CTRL-001 | PENDING | PostgreSQL schema, migration runner, and transactional state/event/outbox commit |
| CTRL-002 | PENDING | Single-node fenced scheduler and explainable queue decision |
| AGENT-001 | PENDING | Outbound mTLS session and version negotiation |
| AGENT-002 | PENDING | SQLite WAL acceptance journal and reconciliation report |
| AGENT-003 | PENDING | Linux workspace, process group, durable logs, cancellation cleanup |
| UX-001 | PENDING | CLI submit, inspect, logs, cancel, and explain |
| E2E-001 | PENDING | One-stage strict-YAML pipeline through the complete real spine |
| E2E-002 | PENDING | Controller restart without duplicate or lost execution |
| E2E-003 | PENDING | Agent reconnect and descendant-process cancellation proof |

## Wave 2 — Durability and platform parity

`CTRL-003` retry/timeout/post, `OPS-001` object storage and artifacts,
`WIN-001` Windows service agent, `WIN-002` PowerShell/cmd/direct execution,
`WIN-003` Job Object cancellation and reboot reconciliation.

## Wave 3 — Native product surface

Parallel and matrix execution, components, tenancy, credential grants, public
API, complete CLI journeys, initial UI, tests, and artifact browsing.

## Wave 4 — Jenkins migration

Pinned compatibility worker, Declarative compiler, Scripted classifier, mapping
catalog, shared-library inventory, differential traces, generated strict YAML,
shadow, and canary.

## Wave 5 — Extensions and operations

SCM, secrets, notifications, provisioners, protected deployments, retention,
backup, compact/HA packaging, upgrade, and rollback.

## Wave 6 — Better-and-faster proof

OSS/private corpus, Linux/Windows war hosts, Jenkins comparison, capacity
envelope, soak, security review, disaster campaign, private alpha canary, and
release-readiness assessment.

## Board rule

Finish the active ticket satisfactorily, preserve its evidence and coherent
commit, then select the next logical unblocked ticket. Stop only for an
owner-level decision or authorization.
