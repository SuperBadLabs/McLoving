# ADR 0016: Product parity before migration authority

Status: Accepted

Accepted 2026-09-10.

## Context

A code-level audit on 2026-09-10 read the shipped crates rather than the
board. McLoving's durable core -- PostgreSQL as single truth with fenced
leases, the outbound-only mTLS agent protocol, the hash-chained audit, OIDC
with pinned key sets, the immutable object store, and the process-group
teardown proof -- is better engineered than Jenkins' equivalents. The surface
a Jenkins team uses every day was mostly absent: one process per stage, no
live log output, no agent-side artifact upload, no webhook receiver, no cron
evaluator, no checkout on the product path, no container execution, no way to
grant a human a role, and no notification egress. About 45k lines of migration
substrate had no caller, and the board's critical path ran through
migration-authority ceremonies for a product no team could yet use.

Since 2026-08-21 the board closed 21 tickets and filed 38; remaining work grew
while throughput stayed high. A board that grows as fast as it drains does not
converge.

## Decision

1. **Daily-workflow parity is the north star.** Native strict-YAML pipelines
   are the product. The measure of progress is one concrete pipeline: a GitHub
   push checks a repository out inside a digest-pinned container, runs several
   steps in one stage, streams logs while running, uploads artifacts, and
   reports a commit status. McLoving builds McLoving with it.
2. **Jenkinsfile support is a compile-only migration aid.** ADR 0006 stands.
   Declarative directives are widened in corpus-frequency order only where a
   native construct exists first. Groovy is never evaluated; the GROOVY-001
   answer is NO and is recorded as an amendment to ADR 0006.
3. **Migration-authority lanes are deferred, not cancelled.** CASE, CANARY,
   CUTOVER, ROLLBACK, RECUTOVER, DECOM, MIG-008/009, PROOF-001, the
   post-release campaigns and the web-interface rewrite chain move to
   `DEFERRED` and leave the remaining topology. They resume when a real team
   runs real pipelines. Their crates stay in the tree untouched.
4. **Dormant substrate whose counterparties do not exist is not wired.** The
   dependency resolver and provisioner require a McLoving-private attestation
   from public registries and cloud providers. They are left unlinked; if the
   need returns, a plain mirror client or cloud API client replaces them.
5. **Progress is a falling distance.** The parity chain on the execution board
   is the dispatch queue; the count of unclosed tickets to the dogfood ticket
   is reported every two weeks and must fall. A ticket added to the chain is a
   reported regression.
6. **Proof replaces ceremony for parity work.** Each parity ticket names a
   command whose output is recorded in its pull request; the threat-model row
   requirement is unchanged.

## Consequences

- The execution spec becomes an explicit versioned envelope with an ordered
  step list; one node and one attempt per stage remain.
- Rootless podman is the Linux containment for container stages and the
  partial answer to `SEC-005`; plain process steps stay uncontained and say so.
- Artifact upload rides the existing mTLS agent channel rather than a second
  HTTP credential.
- Trigger sources (webhook, cron) and a notification consumer feed and drain
  the existing durable trigger and outbox machinery rather than replacing it.
- Tickets that depend on deferred tickets (`REL-003`, `DEPLOY-002`,
  `PERF-001`) keep those edges; they are re-derived when the parity phase
  closes.
