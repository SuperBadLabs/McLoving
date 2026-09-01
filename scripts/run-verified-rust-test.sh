#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if (( $# < 3 )); then
  printf 'usage: %s EXPECTED LABEL [--require-postgres] COMMAND [ARG ...]\n' "$0" >&2
  exit 2
fi

expected="$1"
label="$2"
shift 2

if [[ "${1:-}" == "--require-postgres" ]]; then
  if [[ -z "${MCLOVING_TEST_DATABASE_URL:-}" ]]; then
    printf 'verified Rust test %s requires MCLOVING_TEST_DATABASE_URL\n' \
      "${label}" >&2
    exit 2
  fi
  shift
fi

if (( $# == 0 )); then
  printf 'verified Rust test %s has no command\n' "${label}" >&2
  exit 2
fi

log_path="$(mktemp "${TMPDIR:-/tmp}/mcloving-rust-test.XXXXXX")"
cleanup() {
  rm -f -- "${log_path}"
}
trap cleanup EXIT

if ! "$@" 2>&1 | tee "${log_path}"; then
  printf 'verified Rust test command failed: %s\n' "${label}" >&2
  exit 1
fi

python3 "${script_dir}/verify-rust-test-execution.py" \
  "${log_path}" "${expected}" "${label}"
