#!/usr/bin/env bash
# Foundation `rust-tests`: the workspace tests outside the source-acquirer
# policy, as the lane runs them.
# shellcheck source=lib.sh
# dogfood-contract-begin rust-tests-preamble
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
dogfood_lane rust-tests
# dogfood-contract-end rust-tests-preamble
cargo "+${RUST_TOOLCHAIN}" test --locked --workspace --exclude mcloving-source-acquirer
