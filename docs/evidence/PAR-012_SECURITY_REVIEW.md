# PAR-012 closure receipt: checkout step on the product path

Ticket: `PAR-012`. Merged as PR #147, squash commit
`e22a94ed49b259f52e6c16c2e3bf65891eb9a3b3` on 2026-09-11. Closes the source slice of `EXEC-005`.

## What merged

- Pipeline IR v1.7: a stage may hold one `checkout` step beside its process
  steps, also inside a container stage. Fields `mapping_id`, `mapping_digest`,
  `ref`, `commit` (literal or expression over typed parameters, the one
  materializable checkout field), `destination` (one path component,
  default `source`, `spool` reserved) and `timeout_seconds` (1..=3600,
  default 600). Canonical opcode 5; the sequential planner refuses checkout
  stages; Windows refuses them at admission.
- Controller: version-5 envelope with a `checkout` step kind; capabilities
  `multi-step-v1`, `sealed-source-v1` and `sealed-source-binding-v1-<hex>`;
  startup-frozen `MCLOVING_SOURCE_MAPPING_CATALOG` checked on validate, plan,
  save, submit and replay; plans report `checkout_steps`.
- Agent: `MCLOVING_AGENT_SOURCE_BINDINGS_PATH` (owner-private, 0400,
  digest-pinned) with an optional `aa-exec` launcher sealed against
  `aa_exec_sha256`; each checkout prepared before the first spawn (acquirer
  configuration, signing key and marker digests re-checked, ref prefix
  checked), its request window opened at the step's spawn, the acquirer sealed
  into a memory file; the answer authenticated (HMAC receipt, digests, request
  hash, identities, exact resolved commit); the retained tree verified with
  the acquirer's own routine (streamed hashes, bounded inventory,
  deadline-aware) immediately before a `renameat2(RENAME_NOREPLACE)` move
  between held directory descriptors with the destination checked absent
  before and by inode after; the tree made owner-writable by a descriptor walk;
  helper output capped by the remaining attempt budget.
- Cleanup: a refused, rejected, timed-out, cancelled, output-limited or
  executor-failed checkout discards its acquisition tree; journal schema 5
  records `attempts.acquisition_directory` before the spawn, and restart
  recovery reclaims it, parking the attempt reconciliation-required until the
  tree is gone, including past a discharge receipt; live discard failures park
  the attempt the same way.
- Acquirer crate: `request_sha256`, `authenticate_receipt` and
  `verify_retained_acquisition` exposed for the launching agent.
- Deployment: bindings path secret-class with the exact mode/owner/link rule;
  catalog trust-class; agent-synthesized `MCLOVING_SOURCE_ACQUIRER_*` names
  are reviewed smoke-test exclusions.

## Review

Twenty-three findings across twelve Codex rounds (2,1,1,2,2,2,2,1,2,3,3,2);
eighteen fixed in the PR. Past the ten-round cap, five were filed as
`AGENT-010`: descriptor-relative verification, a manifest bound aligned with
the admitted limits, deadline-bounded final syncs, a journaled recovery walk
bound, and the zero-budget checkout termination.

## Verification

| Check | Result |
|---|---|
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | clean |
| `cargo test -p mcloving-agent --lib` | 97 passed |
| `cargo test -p mcloving-agent-runtime --lib` | 40 passed |
| `cargo test -p mcloving-controller-api --lib` | 45 passed |
| `cargo test -p mcloving-pipeline-ir` (incl. `tests/checkout.rs`) | all passed |
| `cargo test -p mcloving-source-acquirer --lib` | 17 passed |
| `cargo test -p mcloving-agent --test source_work` (PostgreSQL, shipped binaries, bounded transport tmpfs, `aa-exec` launcher) | 2 passed: eligibility routing, exact branch head landing with the next step building in it, receipt without tree, planted symlink destination refused by name, five API refusals |
| `cargo test -p mcloving-agent --test remote_work` (podman) | 7 passed |
| `cargo test -p mcloving-agent --test long_step_lease` | 5 passed |
| `cargo test -p mcloving-agent --test sequential_work` | 11 passed |
| `cargo test -p mcloving-agent --test cache_work` / `--test input_work` | 1 passed each |
| `deploy/test-deployment.sh` (local) | passed |
| GitHub proof: `SuperBadLabs/cljest` at `507956c8` over https through the sealed acquirer and the sealed launcher, next step ran in the checkout | build succeeded, `resolved_commit` matches |
| PR head Foundation and Windows | success |
| Exact-main Foundation | run 34598819224, success |
| Exact-main Windows Agent | run 34598819193, success |

Proof fixture: `examples/parity/checkout-and-test.pipeline.yaml`.

## Threat model

Boundaries reviewed: TM-003, TM-005, TM-006, TM-016, TM-023, TM-052 and
`SEC-005` (plain process steps remain on the host); the closure section in
`docs/threat-model/README.md` records the review and its residuals
(`AGENT-010`, `SEC-005`). No production authority is granted.
