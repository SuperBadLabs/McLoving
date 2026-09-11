#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
: "${MCLOVING_TEST_DATABASE_URL:?an explicit disposable PostgreSQL database is required}"
: "${MCLOVING_CONTROLLER_BINARY:?the actual shipped controller binary is required}"
: "${MCLOVING_SOURCE_ACQUIRER_BINARY:?the actual shipped source acquirer binary is required}"
test -x "${MCLOVING_CONTROLLER_BINARY}"
test -x "${MCLOVING_SOURCE_ACQUIRER_BINARY}"
command -v python3 >/dev/null
command -v openssl >/dev/null
command -v git >/dev/null
# The sealed acquirer creates a user namespace for its transport. Under the
# Ubuntu restriction the agent enters it through the AppArmor profile, which
# the harness selects on its own; this gate only requires the profile to be
# loaded when the restriction is on.
if [[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" == "1" ]]; then
  aa-exec -p mcloving-source-acquirer -- /bin/true
fi
bash scripts/run-verified-rust-test.sh \
  2 source-product --require-postgres \
  cargo test --locked -p mcloving-agent --test source_work -- --nocapture --test-threads=1
