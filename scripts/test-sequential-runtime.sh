#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"
: "${MCLOVING_TEST_DATABASE_URL:?an explicit disposable PostgreSQL database is required}"
: "${MCLOVING_CONTROLLER_BINARY:?the shipped controller binary is required}"
test -x "${MCLOVING_CONTROLLER_BINARY}"
test -s bins/agent/tests/sequential_work.rs
test -s crates/controller-api/tests/sequential_store.rs
test -s crates/controller-api/tests/workspace_store.rs

log_dir="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-sequential-gate.XXXXXX")"
trap 'rm -rf -- "${log_dir}"' EXIT

run_case() {
  local label="$1"
  shift
  "$@" 2>&1 | tee "${log_dir}/${label}.log"
  python3 - "${log_dir}/${label}.log" <<'PY'
import re
import sys
from pathlib import Path
output = Path(sys.argv[1]).read_text()
if "skipped:" in output.lower() or re.search(r"\b[1-9][0-9]* ignored;", output):
    raise SystemExit("sequential runtime gate refuses skipped or ignored tests")
PY
}

run_case store bash scripts/run-verified-rust-test.sh \
  4 sequential-store --require-postgres \
  cargo test --locked -p mcloving-controller-api --test sequential_store -- --nocapture --test-threads=1
run_case workspace bash scripts/run-verified-rust-test.sh \
  4 workspace-store --require-postgres \
  cargo test --locked -p mcloving-controller-api --test workspace_store -- --nocapture --test-threads=1
run_case remote bash scripts/run-verified-rust-test.sh \
  11 sequential-remote-work --require-postgres \
  cargo test --locked -p mcloving-agent --test sequential_work -- --nocapture --test-threads=1
