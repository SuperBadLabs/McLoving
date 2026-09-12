#!/usr/bin/env bash
# Foundation `rust-lint`: format, lockfile and clippy, as the lane runs them.
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
dogfood_lane rust-lint
cargo "+${RUST_TOOLCHAIN}" fmt --all -- --check
cargo "+${RUST_TOOLCHAIN}" metadata --locked --no-deps --format-version 1 >/dev/null
cargo "+${RUST_TOOLCHAIN}" clippy --locked --workspace --all-targets -- -D warnings
