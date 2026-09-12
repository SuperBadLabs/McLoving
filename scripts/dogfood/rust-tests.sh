#!/usr/bin/env bash
# Foundation `rust-tests`: the workspace tests outside the source-acquirer
# policy, as the lane runs them.
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
dogfood_lane rust-tests
cargo "+${RUST_TOOLCHAIN}" test --locked --workspace --exclude mcloving-source-acquirer
