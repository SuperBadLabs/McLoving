#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
: "${MCLOVING_TEST_DATABASE_URL:?an explicit disposable PostgreSQL database is required}"
: "${MCLOVING_CONTROLLER_BINARY:?the actual shipped controller binary is required}"
: "${MCLOVING_CACHE_BINARY:?the actual shipped cache binary is required}"
test -x "${MCLOVING_CONTROLLER_BINARY}"
test -x "${MCLOVING_CACHE_BINARY}"
command -v python3 >/dev/null
command -v openssl >/dev/null
bash scripts/run-verified-rust-test.sh \
  1 cache-product --require-postgres \
  cargo test --locked -p mcloving-agent --test cache_work -- --nocapture --test-threads=1
