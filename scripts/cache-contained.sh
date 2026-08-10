#!/usr/bin/env bash
set -euo pipefail

cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 clippy --locked -p mcloving-cache --all-targets -- -D warnings
cargo +1.97.1 test --locked -p mcloving-cache
