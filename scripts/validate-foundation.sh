#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
# shellcheck source=../tools/versions.env
source "${repo_root}/tools/versions.env"

cache_base="${XDG_CACHE_HOME:-${HOME}/.cache}/mcloving/foundation-tools"
mkdir -p "${cache_base}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required command is missing: %s\n' "$1" >&2
    exit 1
  fi
}

fetch_verified() {
  local url="$1"
  local destination="$2"
  local expected_sha="$3"
  local temporary="${destination}.download"

  if [[ -f "${destination}" ]] &&
    printf '%s  %s\n' "${expected_sha}" "${destination}" | sha256sum -c - >/dev/null; then
    return
  fi

  curl --fail --location --silent --show-error "${url}" --output "${temporary}"
  printf '%s  %s\n' "${expected_sha}" "${temporary}" | sha256sum -c -
  mv "${temporary}" "${destination}"
}

for command in curl java clojure mktemp podman python3 sha256sum tar timeout; do
  require_command "${command}"
done

actionlint_archive="${cache_base}/actionlint-${ACTIONLINT_VERSION}.tar.gz"
fetch_verified \
  "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" \
  "${actionlint_archive}" \
  "${ACTIONLINT_SHA256}"

cargo_deny_archive="${cache_base}/cargo-deny-${CARGO_DENY_VERSION}.tar.gz"
fetch_verified \
  "https://github.com/EmbarkStudios/cargo-deny/releases/download/${CARGO_DENY_VERSION}/cargo-deny-${CARGO_DENY_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
  "${cargo_deny_archive}" \
  "${CARGO_DENY_SHA256}"

tlaplus_jar="${cache_base}/tla2tools-${TLAPLUS_VERSION}.jar"
fetch_verified \
  "https://github.com/tlaplus/tlaplus/releases/download/v${TLAPLUS_VERSION}/tla2tools.jar" \
  "${tlaplus_jar}" \
  "${TLAPLUS_SHA256}"

actionlint_dir="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-actionlint.XXXXXX")"
cargo_deny_dir="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-cargo-deny.XXXXXX")"
cleanup() {
  rm -rf -- "${actionlint_dir}" "${cargo_deny_dir}"
}
trap cleanup EXIT

tar -xzf "${actionlint_archive}" -C "${actionlint_dir}"
tar -xzf "${cargo_deny_archive}" \
  -C "${cargo_deny_dir}" \
  --strip-components=1

podman pull "${MCLOVING_RUST_IMAGE}" >/dev/null
podman pull "${MCLOVING_GITLEAKS_IMAGE}" >/dev/null

podman run --rm \
  -v "${repo_root}:/work:Z" \
  -w /work \
  "${MCLOVING_RUST_IMAGE}" \
  bash -c \
  'cargo fmt --all -- --check &&
   cargo metadata --locked --no-deps --format-version 1 >/tmp/metadata.json &&
   cargo clippy --locked --workspace --all-targets -- -D warnings &&
   cargo test --locked --workspace'

podman run --rm \
  -v "${repo_root}:/work:Z" \
  -v "${cargo_deny_dir}:/tools:ro,Z" \
  -w /work \
  "${MCLOVING_RUST_IMAGE}" \
  /tools/cargo-deny check

python3 "${repo_root}/scripts/test-windows-agent-impact.py"
"${actionlint_dir}/actionlint" "${repo_root}/.github/workflows/"*.yml

java -cp "${tlaplus_jar}" tla2sany.SANY \
  "${repo_root}/formal/tla/AttemptLease.tla"
java -cp "${tlaplus_jar}" tlc2.TLC \
  -config "${repo_root}/formal/tla/AttemptLease.cfg" \
  -workers auto \
  "${repo_root}/formal/tla/AttemptLease.tla"

(
  cd "${repo_root}/compat/jenkins-worker"
  timeout 60 clojure -M:foundation -m mcloving.compat.main
  ./test-plugin-directory.sh
)

podman run --rm \
  -v "${repo_root}:/repo:Z" \
  "${MCLOVING_GITLEAKS_IMAGE}" \
  dir /repo --no-banner --redact

test "$(
  find "${repo_root}/docs/adr" -maxdepth 1 \
    -name '[0-9][0-9][0-9][0-9]-*.md' | wc -l
)" -eq 15
test -s "${repo_root}/docs/architecture/CHARTER.md"
test -s "${repo_root}/docs/threat-model/README.md"
test -s "${repo_root}/docs/EXECUTION_BOARD.md"

printf 'McLoving foundation validation passed.\n'
