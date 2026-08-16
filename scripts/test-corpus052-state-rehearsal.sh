#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 4 ]]; then
  echo "usage: $0 SEALED_BUILDS EXPECTED_TREE_SHA256 OPAQUE_EVIDENCE_ID OUTPUT_ROOT" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../tools/versions.env
source "${repo_root}/tools/versions.env"
sealed_builds=$1
expected_tree_sha256=$2
opaque_evidence_id=$3
requested_output=$4
output_parent=$(realpath -e "$(dirname -- "${requested_output}")")
output_leaf=$(basename -- "${requested_output}")

if [[ ! "${output_leaf}" =~ ^rehearsal-v[0-9]+$ || -e "${requested_output}" ]]; then
  echo "output must be one new rehearsal-vN directory" >&2
  exit 73
fi
if [[ ! -d "${sealed_builds}" || -L "${sealed_builds}" ]]; then
  echo "sealed source must be a plain directory" >&2
  exit 66
fi

staging=$(mktemp -d "${output_parent}/.${output_leaf}.staging.XXXXXX")
container="mcloving-mig005a-corpus052-postgres-$$"
network="mcloving-mig005a-corpus052-$$"
port=$((20000 + ($$ % 1000)))
completed=0

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  podman rm --force "${container}" >/dev/null 2>&1 || true
  podman network rm "${network}" >/dev/null 2>&1 || true
  if [[ "${completed}" != 1 ]]; then
    rm -rf -- "${staging}"
  fi
  exit "${status}"
}
trap cleanup EXIT

mkdir -p "${staging}/evidence"
podman network create --internal "${network}" >/dev/null
podman run --detach \
  --name "${container}" \
  --network "${network}" \
  --publish "127.0.0.1:${port}:5432" \
  --cpus 2 --memory 2g --pids-limit 1024 \
  --env POSTGRES_USER=mcloving \
  --env POSTGRES_HOST_AUTH_METHOD=trust \
  --env POSTGRES_DB=mcloving \
  "${MCLOVING_POSTGRES_IMAGE}" >/dev/null

for _ in $(seq 1 120); do
  if podman exec "${container}" pg_isready \
    --username mcloving --dbname mcloving >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
podman exec "${container}" pg_isready \
  --username mcloving --dbname mcloving >/dev/null || {
    podman logs "${container}" >&2
    exit 1
  }

(
  cd "${repo_root}"
  cargo run --locked --quiet \
    -p mcloving-jenkins-state-transfer --example normalize_history -- \
    "${sealed_builds}" "${expected_tree_sha256}" "${opaque_evidence_id}" \
    "${staging}/forward-bundle.json"
) > "${staging}/evidence/forward-normalization.txt"
forward_transform_executable="${repo_root}/target/debug/examples/normalize_history"
forward_transform_sha256=$(sha256sum "${forward_transform_executable}" | awk '{print $1}')
forward_bundle_transform_sha256=$(jq -r \
  '.binding.transform_implementation_digest[]' "${staging}/forward-bundle.json" \
  | awk '{printf "%02x", $1} END {print ""}')
test "${forward_transform_sha256}" = "${forward_bundle_transform_sha256}"

MCLOVING_TEST_DATABASE_URL="postgres://mcloving@127.0.0.1:${port}/mcloving" \
  cargo run --locked --quiet \
  --manifest-path "${repo_root}/Cargo.toml" \
  -p mcloving-jenkins-state-transfer --example rehearse_history -- \
  "${sealed_builds}" "${expected_tree_sha256}" "${opaque_evidence_id}" \
  "${staging}/forward-bundle.json" "${forward_transform_sha256}" \
  "${staging}/mcloving"

podman inspect "${container}" > "${staging}/evidence/postgres-container-inspect.json"
podman image inspect "${MCLOVING_POSTGRES_IMAGE}" \
  > "${staging}/evidence/postgres-image-inspect.json"

jq --exit-status '
  .schema == "mcloving.corpus052-state-rehearsal/v1"
  and .build_count == 2
  and .next_build_number == 3
  and .previous_result == "succeeded"
  and .imported_previous_build_number == 1
  and .imported_previous_result == "aborted"
  and .log_count == 2
  and .actual_process_execution == true
  and .external_effects == 0
  and .production_authority == false
  and .forward_retrieval_verified == true
  and .reverse_retrieval_verified == true
  and .reverse_replay_verified == true
' "${staging}/mcloving/rehearsal-summary.json" >/dev/null
test "$(sha256sum "${repo_root}/target/debug/examples/rehearse_history" | awk '{print $1}')" = \
  "$(jq -r '.reverse_transform_implementation_sha256' \
    "${staging}/mcloving/rehearsal-summary.json")"
test "$(cat "${staging}/mcloving/mcloving-build-2.log")" = \
  $'+ echo Hello World\nHello World'

(
  cd "${staging}"
  find . -type f ! -name SHA256SUMS -printf '%P\0' \
    | sort -z \
    | while IFS= read -r -d '' path; do
        sha256sum "${path}"
      done > SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)

podman rm --force "${container}" >/dev/null
podman network rm "${network}" >/dev/null
mv -- "${staging}" "${output_parent}/${output_leaf}"
completed=1
(
  cd "${output_parent}/${output_leaf}"
  sha256sum -c SHA256SUMS >/dev/null
)
printf '%s\n' "${output_parent}/${output_leaf}"
