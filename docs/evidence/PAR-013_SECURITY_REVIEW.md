# PAR-013 closure receipt: live log streaming

Ticket: `PAR-013`. Merged as PR #149, squash commit
`0e2cf2133e35f6001d6a5439c7674dffa1a46018` on 2026-09-11.

## What merged

- Agent journal schema 6 and 7: `log_reservations` holds every chunk's
  sequence, step ordinal, stream, byte range, digest and receipt, written
  before the chunk is first sent, so the live tail, the terminal pass and a
  post-crash replay number one range of one stream once;
  `attempts.live_log_stream` records that a live tail streamed the attempt,
  so recovery under a session that did not negotiate `live-log-stream-v1`
  defers it for a compatible peer rather than failing every attempt's
  recovery at an older replica.
- Live tail (Unix, plain process steps; not helper steps, not a
  credential-bearing step): the spawn hook opens the step's live spool by
  path with `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` and judges the descriptor a
  regular file; a task ticks every 250 ms, flushes at 64 KiB or one second,
  paces its flushes so the sequence budget lasts the step's timeout with the
  budget shared across the attempt's remaining steps, stops 128 sequences
  short of the bound and never streams past the aggregate output limit; the
  executor's quota cut keeps every streamed byte through per-stream
  retention floors read under the same lock the tail raises them under.
- Terminal publish through one `SpoolPublisher`: strict coverage and digest
  re-check of every reserved range against the durable spool, unreceipted
  reservations re-sent under their sequences, the unstreamed tail reserved
  and sent. Recovery of a step the crashed session was still running:
  restores the agent's own access to the spool chain (a workload-revoked
  permission is restored, never read as an absent stream), applies the
  executor's aggregate quota cut with the reservations as floors and the
  budget the finished steps left, publishes from the reservations under the
  renewed lease, and an empty stream with a reservation outstanding fails
  the coverage check rather than vanishing; a failed publication keeps the
  attempt cancelling for the next session.
- Store: migration 0039 adds `attempt_log_chunks.build_id` and
  `build_position` (assigned under the per-build advisory lock, backfilled,
  NOT NULL, unique per build) with an ADR 0012 compatibility trigger that
  derives both for a pre-v39 writer's insert under the same lock; the
  per-attempt chunk bound rises to 262 144 for a session that negotiated the
  feature, read from the durable session record.
- API: `GET .../builds/{id}/logs` takes `after_cursor` and `wait_ms`
  (bounded at 30 s, re-read at 200 ms, the chunks read once more after a
  terminal status), answers `next_cursor` and `live` from the ledger only;
  a build parked in `reconciliation_required` is not terminal. Cursors are
  build-scoped positions in commit order. CLI `logs --follow
  [--after-cursor N]` writes the exact bytes of each chunk as it commits,
  human output only, and refuses a controller that does not answer the
  follow fields.

## Review

Thirty-three findings across twenty Codex rounds
(7,2,1,2,2,1,1,1,2,2,2,1,1,1,1,2,1,1,1,1), clean on the twenty-first
review. Thirty-one fixed in the pull request; two filed as tickets past the
ten-round cap: `CTRL-005` (incremental committed-log byte accounting, cost
not exposure) and `AGENT-011` (reserved live chunks kept in agent custody so
a workload that unlinks, renames, truncates or overwrites its own spool can
neither strand a reserved sequence nor pin the attempt in recovery). Rounds
14 through 17 were one family, a workload tampering with its own spool
before a crash; rounds 19 and 20 were the rolling-upgrade replay boundary,
closed by persisting the attempt's log mode.

## Verification

| Check | Result |
|---|---|
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | clean |
| `cargo test -p mcloving-agent-runtime` | 45 lib incl. reservation uniqueness, coverage, stale authority, retirement, schema 5 → 6 → 7 migrations, durable live-log mode |
| `cargo test -p mcloving-agent --lib` | 97 |
| `cargo test -p mcloving-controller-store --test postgres_truth` (fresh PostgreSQL) | 57 incl. follow read, resume after a cursor, terminal bound without the feature, live bound with it, pre-v39 writer through the compatibility trigger |
| `cargo test -p mcloving-controller --test deployable_runtime -- --ignored` | 2, runtime-role preflight unchanged |
| `cargo test -p mcloving-agent --test long_step_lease` (pin 5 → 8) | 8: first line visible while the step runs with the paged read agreeing with the follow; a restart replaying reserved chunks under their journaled sequences; a crash mid-step with the workload's spool permissions revoked, the interrupted output published on restart, sequences dense and unique, one terminal-class event |
| Proof (HeMan): shipped controller and agent over mTLS | `mcloving logs --follow` printed a line within one second of the step writing it; `kill -9` of the agent mid-stream, restart, `mcloving logs` showed every sequence once |
| PR head Foundation and Windows | success |
| Exact-main Foundation | run 34636714250, success |
| Exact-main Windows Agent | run 34636714092, success |

## Threat model

Boundaries reviewed: TM-003, TM-006, TM-013, TM-018 and TM-052; the closure
section in `docs/threat-model/README.md` records the review and its
residuals (a workload can write anything into its own stdout, as before; a
spool it unlinks or rewrites under a reservation is `AGENT-011`; the byte
quota's per-append sum is `CTRL-005`). No production authority is granted.
