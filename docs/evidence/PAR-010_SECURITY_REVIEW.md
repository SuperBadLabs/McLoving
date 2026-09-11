# PAR-010 closure receipt: multi-step stages

Ticket: `PAR-010`. Merged as PR #145, squash commit
`cca42de59271820826248c35ed195e8e81e637a6` on 2026-09-11.

## What merged

- Version-5 execution envelope: one to sixteen ordered process steps of one
  stage run inside one node, one attempt and one lease. Emitted only for
  stages with more than one step; single-step stages keep the version-1 shape.
- Scheduler capability `multi-step-v1` and wire feature
  `multi-step-execution-v1`; the controller drops the capability from a session
  that did not negotiate the feature, and an agent that still receives
  version-5 work without it declines rather than refuses.
- Migration `0037_step_ordinal.sql` adds `attempt_log_chunks.step_ordinal`
  (default 0, bounded below 65536); the log publication RPC, inline chunks and
  the logs route carry it. The per-attempt chunk cap is 96 on both sides.
- Agent: per-step spools written under `spool/step-N/` and relocated by rename
  into `.agent-results/<workspace>/steps/` when the step ends; both descriptors
  journaled in one transaction before the next spawn; journal schema 3 with
  `attempts.current_step` written before every spawn; `Running -> Running`
  rebinds the leader per step; execution stops at the first step that does not
  succeed; per-step outcomes ride the result and the terminal summary as
  `steps`, with attempt terminal, exit code and reason taken from the last step
  record; credentials redeemed once per attempt, injected per step, redacted as
  a union bounded at eight targets; multi-step stages are Linux-only at
  admission; terminal reclaim removes the relocated step directory whether or
  not the journal references its contents.
- Crash between a step's process exit and its finalization parks the attempt
  reconciliation-required naming `interrupted_at_step:N`; nothing is re-run or
  skipped.

## Review

Twelve findings across eleven Codex and Copilot rounds; eleven fixed in the
PR and one refuted with executor line evidence (output limits are enforced on
the file-spool path). One further finding, publishing journaled step logs
before a recovered cancellation completes, predates this ticket's recovery
ordering and is filed as `AGENT-008`.

## Verification

| Check | Result |
|---|---|
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo test -p mcloving-agent --lib` | 84 passed |
| `cargo test -p mcloving-agent-runtime --lib` | 40 passed |
| `cargo test -p mcloving-controller-api --lib` | 42 passed |
| `cargo test -p mcloving-agent --test remote_work` (PostgreSQL, shipped binaries) | 5 passed, including the ordered three-step run with a hostile cleanup step and the exact crash point |
| `cargo test -p mcloving-controller-store --test postgres_truth` | 54 passed |
| `cargo test -p mcloving-execution-spine --test real_spine` | 30 passed |
| PR head Foundation and Windows | success |
| Exact-main Foundation | run 34571458905, success |
| Exact-main Windows Agent | run 34571458894, success |

Proof fixture: `examples/parity/three-steps.pipeline.yaml`.

## Threat model

Boundaries reviewed: TM-003, TM-005, TM-006, TM-023, TM-052; the closure
section in `docs/threat-model/README.md` records the review and its residuals
(`AGENT-008`, `SEC-005`). No production authority is granted.
