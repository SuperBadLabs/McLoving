# Contributing

All changes land through a protected pull request.

Before requesting review:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Every material change must update tests, documentation, the execution board,
and threat-model or architecture records when its boundary changes. Unsupported
behavior must remain explicit and must never be represented as successful.

Use `codex/` for Codex implementation branches. Keep commits coherent and do
not mix unrelated repairs into a ticket.
