#!/usr/bin/env bash
# Shared preamble for the dogfood lanes (PAR-005). A process step starts
# with a cleared environment (PATH and LANG only), so every lane derives the
# rest from the running user rather than from the pipeline file: the home
# directory, the Rust toolchain, and the rootless podman runtime directory.
# Each lane mirrors one Foundation job's commands; the commands themselves
# are read from .github/workflows/foundation.yml by
# scripts/dogfood/verify-lanes.py so the two cannot drift silently.
set -euo pipefail

dogfood_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
export HOME="${dogfood_home}"
export CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export PATH="${CARGO_HOME}/bin:${PATH}"
export CARGO_TERM_COLOR=never
export RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-1.97.1}"

# Every lane runs from the checkout the pipeline's checkout step placed in
# the workspace; a lane invoked by hand from a checkout works the same.
dogfood_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${dogfood_repo}"

# shellcheck source=../../tools/versions.env
. "${dogfood_repo}/tools/versions.env"
# shellcheck source=versions.env
. "${dogfood_repo}/scripts/dogfood/versions.env"

dogfood_lane() {
  printf '== dogfood lane %s in %s (%s)\n' "$1" "${dogfood_repo}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
