# PAR-000 closure receipt: product-parity re-orientation

Ticket: `PAR-000`. Docs-only. Merged as PR #143, squash commit
`aeb6dd851e14e3eb9214075557dc1c7126fa8306` on 2026-09-11.

## What merged

- ADR 0016 (product parity before migration authority) and the GROOVY-001 = NO
  amendment to ADR 0006, including the disposition of the measured
  malformed-quoting over-acceptance defect.
- 23 ceremony, campaign and web-interface tickets moved to `DEFERRED` and out of
  the remaining topology; rows and dependency edges preserved. UI-002 closed on
  main while the PR was open and stayed `DONE`.
- The `PAR-000` to `PAR-015` chain as the dispatch queue with its lane row, a
  proof clause on every row, and the distance metric and dated milestones in
  the handoff.
- Verifier pins raised deliberately: 11 ticket tables, 6 lane tables, 137-row
  floor, 16 ADRs in the local gate and Foundation.

## Review

Three Codex review rounds produced eleven findings, all addressed and resolved
before merge: ADR status convention, verifier history comment, the per-step
log storage plan (schema change owned by PAR-010), confined artifact
collection (PAR-014), the Groovy defect disposition, proof commands on every
row, crash ambiguity wording (PAR-010), the lane's self-blocking start gate,
deployment-owned notification targets and DNS-bound connects (PAR-004),
idempotent webhook redelivery (PAR-001), confined checkout publication
(PAR-012) and a mutable schedule slot table (PAR-002).

## Verification

| Check | Result |
|---|---|
| `scripts/verify-execution-board.py` | ok, 137 tickets, 19 remaining |
| `scripts/test-execution-board.py` | ok |
| `scripts/verify-ticket-closure-receipts.py` | ok, debt 37 unchanged |
| `scripts/test-ticket-closure-receipts.py` | ok |
| PR head Foundation and Windows | success |
| Exact-main Foundation | run 34560483683, success |
| Exact-main Windows Agent | run 34560483674, success |

## Threat model

No runtime, protocol, persistence, identity, secret, connector, compiler,
deployment or migration boundary changed. Every threat row was reviewed and
needs no semantic change; the closure attribution row names this document.
No production authority is granted.
