# McLoving execution board

Updated: 2026-07-28

Status values: `PENDING`, `ACTIVE`, `BLOCKED`, `DONE`, `DEFERRED`.

## Working rules

- Select a coherent batch of three to six logically coupled tickets.
- Use one `codex/` branch and pull request per batch.
- Keep one coherent commit per ticket where practical.
- Address every actionable Copilot review thread before merge.
- Required checks, review threads, exact commit, and clean worktree must be
  verified before protected-main merge.
- After merge, select the next unblocked batch without waiting for ceremony.
- Stop only for an owner-level decision, new authority, or genuine blocker.

## Batch ledger

| Batch | Tickets | Status | Outcome |
|---|---|---|---|
| W0-A | FOUND-001 | DONE | PR #1 established private repository and architecture baseline |
| W0-B | ARCH-001, FOUND-002, SEC-001 | DONE | Finite formal model, reproducible HeMan gate, and owned threat model |
| W0-C | IR-001, IR-002, ARCH-002 | DONE | Bounded strict YAML, canonical IR v1, and admission properties |
| W1-A | CTRL-001, CTRL-002, SEC-002 | PENDING | PostgreSQL truth, outbox, scheduler, and tenant enforcement |
| W1-B | AGENT-001, AGENT-002, AGENT-003 | PENDING | mTLS agent session, SQLite journal, Linux execution |
| W1-C | UX-001, E2E-001, E2E-002, E2E-003 | PENDING | Truthful CLI-driven end-to-end spine and recovery |

## Wave 0 — Architecture and foundation

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| FOUND-001 | DONE | — | Private monorepo, ADRs 1–15, board, threat model skeleton, CI, clean protected merge |
| ARCH-001 | DONE | FOUND-001 | Finite TLC model; lease type, stale publication rejection, fencing, terminal monotonicity, and completion stability checked in CI |
| FOUND-002 | DONE | FOUND-001 | Digest-pinned Rust/gitleaks, checksummed tools, documented cache policy, one-command HeMan validation |
| SEC-001 | DONE | FOUND-001 | Actors, assets, boundaries, assumptions, 24 owned threats, mitigations, residual risk, and verification map |
| IR-001 | DONE | ARCH-001, SEC-001 | Restricted YAML 1.2 parser; stable errors; duplicate/alias/anchor/tag/directive rejection; byte-exact UTF-8 spans; six resource limits; arbitrary-input and seven-fixture negative gates |
| IR-002 | DONE | IR-001 | Pipeline/process IR v1; source/compiler provenance; structural validator; deterministic binary encoding and SHA-256; golden digest; explicit compatibility; independent byte validator |
| ARCH-002 | DONE | IR-001, IR-002 | Property gates prove deterministic admission, bounded sequence expansion, arbitrary-input panic freedom, and unknown-field fail-closed behavior at every schema level |

## Wave 1 — Smallest truthful end-to-end slice

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| CTRL-001 | PENDING | IR-002 | PostgreSQL migrations and one transaction for build/node/attempt/event/outbox with real-DB race tests |
| CTRL-002 | PENDING | CTRL-001 | Fenced single-node scheduler, indexed claims, capability filtering, fairness seed, explainable wait reason |
| SEC-002 | PENDING | SEC-001, CTRL-001 | Organization/project identity, tenant-keyed schema, PostgreSQL RLS, centralized deny-by-default authorization |
| AGENT-001 | PENDING | ARCH-001, CTRL-001 | Outbound mTLS, enrollment, certificate rotation, session epoch, protocol negotiation, stale-session fencing |
| AGENT-002 | PENDING | AGENT-001 | SQLite WAL acceptance-before-ack, journal recovery, log/result spool metadata, reconciliation report |
| AGENT-003 | PENDING | AGENT-002 | Linux workspace/process group, durable logs, timeout/cancel tree cleanup, no escaped descendants |
| UX-001 | PENDING | CTRL-002 | Rust CLI submit/status/logs/cancel/explain through documented public API and idempotency keys |
| E2E-001 | PENDING | IR-002, CTRL-002, AGENT-003, UX-001 | One-stage strict-YAML process through real PostgreSQL, outbox, scheduler, agent, logs, terminal result |
| E2E-002 | PENDING | E2E-001 | Controller kill/restart at every durable transition without lost or duplicate logical execution |
| E2E-003 | PENDING | E2E-001 | Agent disconnect/restart reconciliation and complete descendant-process cancellation proof |

## Wave 2 — Durability and platform parity

| Ticket | Status | Depends on | Objective |
|---|---|---|---|
| CTRL-003 | PENDING | E2E-002 | Durable retry, timeout, post, cleanup, and uncertain-effect reconciliation |
| OPS-001 | PENDING | E2E-001 | Staged object storage, immutable artifacts, checksummed log chunks, explicit gaps and quotas |
| OPS-002 | PENDING | OPS-001 | Backup, PITR, restore epoch, object reconciliation, retention and legal-hold drills |
| WIN-001 | PENDING | AGENT-003 | Signed Windows service agent, journal, enrollment, restart and reboot recovery |
| WIN-002 | PENDING | WIN-001 | Direct process, cmd, PowerShell, Job Objects, ACL workspaces, descendant cleanup |
| WIN-003 | PENDING | WIN-002, E2E-003 | Linux/Windows semantic parity and destructive recovery suite |

## Wave 3 — Native product surface

Parallel and matrix execution, components, parameters, expressions, credential
grants, protected environments, full REST API, CLI journeys, initial static UI,
test normalization, artifacts, and audit.

## Wave 4 — Jenkins migration

Pinned isolated compiler, exact target profiles, Declarative compilation,
Scripted classification, mapping catalog, shared-library inventory,
differential traces, generated strict YAML, shadow, canary, and cutover.

## Wave 5 — Extensions and operations

SCM, secrets, notifications, provisioners, deployment connectors, compact and
HA packaging, upgrades, rollback, retention, and disaster recovery.

## Wave 6 — Better-and-faster proof

OSS/private corpus, Linux/Windows war hosts, Jenkins comparison, capacity
envelope, multi-day soak, security review, disaster campaign, private alpha
canary, and release-readiness assessment.

## Current next batch

`W1-A`: `CTRL-001`, `CTRL-002`, and `SEC-002`.
