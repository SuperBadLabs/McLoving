#!/usr/bin/env bash
# Foundation `architecture`: the retained Jenkins sequential contract, the
# workflow aggregate and runtime gates, the workflows linted with the pinned
# actionlint, the Jenkins compatibility and plugin-directory contracts, and
# the record-verification step, as the lane runs them.
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
dogfood_lane architecture
bash scripts/verify-jenkins-sequential-retained.sh
/usr/bin/python3 -I scripts/test-workflow-aggregate.py
/usr/bin/python3 -I scripts/test-sequential-runtime-gate.py

cache="${HOME}/.cache/mcloving-dogfood"
mkdir -p "${cache}"
actionlint_archive="${cache}/actionlint-${ACTIONLINT_VERSION}.tar.gz"
if [ ! -f "${actionlint_archive}" ] || ! printf '%s  %s\n' "${ACTIONLINT_SHA256}" "${actionlint_archive}" | sha256sum -c - >/dev/null 2>&1; then
  curl --fail --location --silent --show-error \
    "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" \
    --output "${actionlint_archive}.part"
  printf '%s  %s\n' "${ACTIONLINT_SHA256}" "${actionlint_archive}.part" | sha256sum -c -
  mv "${actionlint_archive}.part" "${actionlint_archive}"
fi
actionlint_dir="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-dogfood-actionlint.XXXXXX")"
trap 'rm -rf -- "${actionlint_dir}"' EXIT
tar -xzf "${actionlint_archive}" -C "${actionlint_dir}"
actionlint_config="${actionlint_dir}/actionlint-empty.yaml"
: > "${actionlint_config}"
unset GLOBIGNORE
shopt -u failglob
shopt -s nullglob dotglob
workflow_files=(
  .github/workflows/*.yml
  .github/workflows/*.yaml
)
((${#workflow_files[@]} > 0))
"${actionlint_dir}/actionlint" \
  -config-file "${actionlint_config}" \
  "${workflow_files[@]}"
shopt -u nullglob dotglob

(
  cd compat/jenkins-worker
  timeout 60 clojure -M:test
  ./test-plugin-directory.sh
  ../../scripts/test-jenkins-sequential-contract.sh
  ../../scripts/test-jenkins-sequential-compiler.sh
)

bash -n scripts/validate-foundation.sh
bash -n scripts/validate-source-acquirer-apparmor.sh
bash -n scripts/validate-external-shadow-apparmor.sh
bash -n scripts/dependency-resolver-contained.sh
bash -n scripts/release-builder-contained.sh
bash -n scripts/release-build-inner.sh
bash -n scripts/mario-alpha-demo.sh
bash -n scripts/mario-runtime-effect-rehearsal.sh
bash -n scripts/test-state-policy-differential.sh
bash -n scripts/test-boundary-differential.sh
bash -n scripts/test-backup-restore.sh
bash -n scripts/run-verified-rust-test.sh
bash -n scripts/test-cache-product.sh
bash -n scripts/test-input-product.sh
bash -n scripts/test-source-product.sh
bash -n scripts/verify-boundary-runtime.sh
bash -n scripts/test-ui-browser.sh
bash -n scripts/ui-browser/build-image.sh
python3 scripts/test-execution-board.py
python3 scripts/verify-execution-board.py
python3 scripts/test-ticket-closure-receipts.py
python3 scripts/verify-ticket-closure-receipts.py
python3 scripts/test-verify-rust-test-execution.py
python3 scripts/verify-ui-browser-gate.py
test "$(find docs/adr -maxdepth 1 -name '[0-9][0-9][0-9][0-9]-*.md' | wc -l)" -eq 16
test -s docs/architecture/CHARTER.md
test -s docs/ALPHA_DEMO.md
test -s docs/threat-model/README.md
test -s docs/EXECUTION_BOARD.md
