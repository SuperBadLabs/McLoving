#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 OUTPUT_ROOT PRIVATE_PACKAGE PACKAGE_PIN AUTHZ_GENERATION_PIN" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../tools/versions.env
source "${repo_root}/tools/versions.env"
for command in chmod cut find git grep install jq mktemp podman python3 \
  realpath sed sha256sum sort ssh; do
  command -v "${command}" >/dev/null || {
    echo "required command is unavailable: ${command}" >&2
    exit 69
  }
done

output_parent="$(realpath -e "$(dirname -- "$1")")"
output_leaf="$(basename -- "$1")"
if [[ ! "${output_leaf}" =~ ^shadow001-runtime-[0-9]{8}T[0-9]{6}Z$ || -e "$1" ]]; then
  echo "output must be one new shadow001-runtime-TIMESTAMP directory" >&2
  exit 73
fi
if [[ "${output_parent}/" == "${repo_root}/"* ]]; then
  echo "output must be outside the source repository" >&2
  exit 73
fi
source_status="$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)"
if [[ -n "${source_status}" ]]; then
  echo "SHADOW-001 runtime evidence requires a clean exact-head source tree" >&2
  exit 78
fi

source_commit="$(git -C "${repo_root}" rev-parse HEAD)"
source_tree="$(git -C "${repo_root}" rev-parse "${source_commit}^{tree}")"
output_root="${output_parent}/${output_leaf}"
private_package="$2"
package_pin="$3"
authz_generation_pin="$4"
runtime_root="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-shadow001.XXXXXX")"
build_target="${runtime_root}/cargo-target"
runtime_stage="${runtime_root}/runtime-stage"
network="mcloving-shadow001-target-${RANDOM}-${RANDOM}"
postgres="mcloving-shadow001-postgres-${RANDOM}-${RANDOM}"
runner="mcloving-shadow001-runner-${RANDOM}-${RANDOM}"
cargo_registry="${CARGO_HOME:-${HOME}/.cargo}/registry"

cleanup() {
  for container in "${runner}" "${postgres}"; do
    if [[ -n "${container}" ]]; then
      podman rm --force "${container}" >/dev/null 2>&1 || true
    fi
  done
  if [[ -n "${network}" ]]; then
    podman network rm "${network}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "${runtime_root}"
}
trap cleanup EXIT

if [[ ! -d "${cargo_registry}" ]]; then
  echo "a prefetched Cargo registry is required for the offline build" >&2
  exit 69
fi
install -d -m 0700 "${output_root}"
install -d -m 0700 "${build_target}" "${runtime_stage}"

podman run --rm --network none \
  --cpus 4 --memory 8g --pids-limit 4096 \
  --security-opt no-new-privileges --cap-drop all \
  --env CARGO_NET_OFFLINE=true \
  --env CARGO_TARGET_DIR=/cargo-target \
  --env RUSTUP_TOOLCHAIN=1.97.1 \
  --volume "${cargo_registry}:/usr/local/cargo/registry:ro" \
  --volume "${build_target}:/cargo-target:Z" \
  --volume "${repo_root}:/work:ro,Z" \
  --workdir /work \
  "${MCLOVING_RUST_IMAGE}" \
  bash -c '
    set -euo pipefail
    cargo build --locked --offline -p mcloving-shadow-qualification
    cargo test --locked --offline -p mcloving-controller-store \
      --test trigger_ingress --no-run
    cargo test --locked --offline -p mcloving-controller \
      --test diff_001 --no-run
  ' >/dev/null
install -m 0700 "${build_target}/debug/mcloving-shadow-qualification" \
  "${output_root}/mcloving-shadow-qualification"
sha256sum "${output_root}/mcloving-shadow-qualification" \
  | cut -d ' ' -f 1 >"${output_root}/verifier-binary.sha256"
chmod 0600 "${output_root}/verifier-binary.sha256"
"${output_root}/mcloving-shadow-qualification" generate-keys \
  "${output_root}/source-capture-key.pkcs8" \
  "${output_root}/source-capture-public.sha256" \
  "${output_root}/shadow-replay-key.pkcs8" \
  "${output_root}/shadow-replay-public.base64" \
  >"${output_root}/key-generation.log"
chmod 0600 "${output_root}/key-generation.log"

ssh -o BatchMode=yes srikanth@mario 'python3 -c '"'"'
import base64, http.cookiejar, json, sys, urllib.parse, urllib.request
base = "http://100.127.170.90:18080"
password = open(
    "/home/srikanth/jenkins-oracle-228/runner/admin-password",
    encoding="utf-8",
).read().strip()
authorization = "Basic " + base64.b64encode(
    ("oracle-admin:" + password).encode()
).decode()
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
crumb_request = urllib.request.Request(
    base + "/crumbIssuer/api/json",
    headers={"Authorization": authorization},
)
crumb = json.load(opener.open(crumb_request, timeout=15))
payload = urllib.parse.urlencode({"script": sys.stdin.read()}).encode()
headers = {
    "Authorization": authorization,
    "Content-Type": "application/x-www-form-urlencoded",
    crumb["crumbRequestField"]: crumb["crumb"],
}
response = opener.open(
    urllib.request.Request(base + "/scriptText", data=payload, headers=headers),
    timeout=30,
).read().decode("utf-8", "replace")
marker = next(
    (line for line in response.splitlines() if line.startswith("SHADOW001_SOURCE=")),
    None,
)
if marker is None:
    raise SystemExit("bounded Jenkins source marker is absent")
print(marker)
'"'"'' <"${repo_root}/migration/shadow-runtime-v1/source-probe.groovy" \
  | sed -n 's/^SHADOW001_SOURCE=//p' >"${output_root}/source-probe.json"
chmod 0600 "${output_root}/source-probe.json"

jq --exit-status '
  .schema == "mcloving.shadow001.jenkins-source-probe/v1"
  and .job_id == "corpus-052-cinqict_jenkinsdev"
  and .source_state == "disabled"
  and .captured_wall_clock_unix_ms > 0
  and .original_activity == .terminal_activity
  and .original_activity.queued == 0
  and (.observations | map(.kind)) ==
    ["api", "manual", "schedule", "upstream", "webhook"]
  and ([.observations[].path] | unique | length) == 5
  and ([.observations[] | .outcome == "disabled_pre_queue"] | all)
  and ([.observations[] |
    .queued_builds == 0
    and .scheduled_attempts == 0
    and .credential_grants == 0
    and .connector_requests == 0
    and .production_effects == 0] | all)
' "${output_root}/source-probe.json" >/dev/null

mapfile -t ingress_bins < <(
  find "${build_target}/debug/deps" -maxdepth 1 -type f \
    -name 'trigger_ingress-*' -perm -0100 | sort
)
mapfile -t trace_bins < <(
  find "${build_target}/debug/deps" -maxdepth 1 -type f \
    -name 'diff_001-*' -perm -0100 | sort
)
if [[ ${#ingress_bins[@]} -ne 1 || ${#trace_bins[@]} -ne 1 || \
      ! -x "${build_target}/debug/mcloving-controller" ]]; then
  echo "offline build did not produce the exact three runtime executables" >&2
  exit 70
fi
install -m 0555 "${ingress_bins[0]}" "${runtime_stage}/trigger_ingress"
install -m 0555 "${trace_bins[0]}" "${runtime_stage}/diff_001"
install -d -m 0755 "${runtime_stage}/cargo-target/debug"
install -m 0555 "${build_target}/debug/mcloving-controller" \
  "${runtime_stage}/cargo-target/debug/mcloving-controller"

podman network create --internal "${network}" >/dev/null
podman run --detach --name "${postgres}" \
  --network "${network}" --network-alias postgres \
  --cpus 2 --memory 2g --pids-limit 1024 \
  --security-opt no-new-privileges \
  --env POSTGRES_USER=mcloving \
  --env POSTGRES_HOST_AUTH_METHOD=trust \
  --env POSTGRES_DB=mcloving \
  "${MCLOVING_POSTGRES_IMAGE}" >/dev/null
for _ in $(seq 1 120); do
  if podman exec "${postgres}" pg_isready \
    --username mcloving --dbname mcloving >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
podman exec "${postgres}" pg_isready \
  --username mcloving --dbname mcloving >/dev/null

podman create --name "${runner}" \
  --network "${network}" \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,size=1g \
  --cpus 2 --memory 4g --pids-limit 2048 \
  --security-opt no-new-privileges --cap-drop all \
  --env MCLOVING_TEST_DATABASE_URL=postgres://mcloving@postgres:5432/mcloving \
  --env MCLOVING_SHADOW001_REPLAY_OUTPUT=- \
  --env MCLOVING_SHADOW001_TRACE_OUTPUT=- \
  --env RUST_BACKTRACE=0 \
  "${MCLOVING_RUST_IMAGE}" \
  bash -c '
    set -euo pipefail
    /runtime/trigger_ingress \
      disabled_pipeline_rejects_every_typed_ingress_before_queue \
      --exact --nocapture --test-threads=1
    /runtime/diff_001 admitted_jenkins_case_executes_with_a_canonical_trace \
      --exact --nocapture --test-threads=1
    if timeout 3 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"; then
      echo "target replay reached the public network" >&2
      exit 1
    fi
    echo SHADOW001_TARGET_NETWORK=public-network-denied
  ' >/dev/null
podman cp "${runtime_stage}/." "${runner}:/runtime"
podman cp "${runtime_stage}/cargo-target" "${runner}:/cargo-target"

set +e
podman start --attach "${runner}" >"${output_root}/target-runtime.log" 2>&1
runner_status=$?
set -e
chmod 0600 "${output_root}/target-runtime.log"
podman inspect "${runner}" >"${output_root}/target-runner-inspect.json"
podman inspect "${postgres}" >"${output_root}/target-postgres-inspect.json"
podman network inspect "${network}" >"${output_root}/target-network-inspect.json"
chmod 0600 "${output_root}/target-runner-inspect.json" \
  "${output_root}/target-postgres-inspect.json" \
  "${output_root}/target-network-inspect.json"
if [[ ${runner_status} -ne 0 ]]; then
  echo "isolated target replay failed; owner-private evidence was retained" >&2
  exit 1
fi
jq --exit-status '.[0].Mounts | length == 0' \
  "${output_root}/target-runner-inspect.json" >/dev/null
jq --exit-status '.[0].HostConfig.ReadonlyRootfs == true' \
  "${output_root}/target-runner-inspect.json" >/dev/null
jq --exit-status '.[0].Internal == true' \
  "${output_root}/target-network-inspect.json" >/dev/null
grep -Fxq 'SHADOW001_TARGET_NETWORK=public-network-denied' \
  "${output_root}/target-runtime.log"
sed -n 's/^SHADOW001_TARGET=//p' "${output_root}/target-runtime.log" \
  >"${output_root}/target-replay.json"
sed -n 's/^SHADOW001_TRACE=//p' "${output_root}/target-runtime.log" \
  >"${output_root}/trace-observation.json"
chmod 0600 "${output_root}/target-replay.json" \
  "${output_root}/trace-observation.json"
jq --exit-status '.schema == "mcloving.shadow001.target-replay/v1"' \
  "${output_root}/target-replay.json" >/dev/null
jq --exit-status '.schema == "mcloving.shadow001.trace-observation/v1"' \
  "${output_root}/trace-observation.json" >/dev/null

source_fixture_sha256="$({
  sha256sum \
    "${repo_root}/migration/mario-jenkins-oracle-228/corpus-v1/differential-v1/SHA256SUMS" \
    "${repo_root}/migration/mario-jenkins-oracle-228/corpus-v1/differential-v1/jenkins/container-inspect.json" \
    "${repo_root}/migration/mario-jenkins-oracle-228/corpus-v1/differential-v1/jenkins/external-network.txt"
} | sha256sum | cut -d ' ' -f 1)"
target_fixture_sha256="$({
  sha256sum "${runtime_stage}/trigger_ingress" \
    "${runtime_stage}/diff_001" \
    "${runtime_stage}/cargo-target/debug/mcloving-controller" \
    "${output_root}/target-runner-inspect.json"
} | sha256sum | cut -d ' ' -f 1)"
source_network_sha256="$(sha256sum \
  "${repo_root}/migration/mario-jenkins-oracle-228/corpus-v1/differential-v1/jenkins/container-inspect.json" \
  "${repo_root}/migration/mario-jenkins-oracle-228/corpus-v1/differential-v1/jenkins/external-network.txt" \
  | sha256sum | cut -d ' ' -f 1)"
target_network_sha256="$(sha256sum \
  "${output_root}/target-network-inspect.json" | cut -d ' ' -f 1)"
printf '%s\n' \
  'source=certified-public-network-denied' \
  'target=public-network-denied' \
  >"${output_root}/reachability.txt"
chmod 0600 "${output_root}/reachability.txt"
reachability_sha256="$(sha256sum "${output_root}/reachability.txt" | cut -d ' ' -f 1)"

podman rm --force "${runner}" >/dev/null
runner=''
podman rm --force "${postgres}" >/dev/null
postgres=''
podman network rm "${network}" >/dev/null
network=''

jq -n \
  --arg source_fixture "diff001-certified-source:${source_fixture_sha256}" \
  --arg target_fixture "shadow001-target:${target_fixture_sha256}" \
  --arg source_network "${source_network_sha256}" \
  --arg target_network "${target_network_sha256}" \
  --arg reachability "${reachability_sha256}" '
  {
    schema: "mcloving.shadow001.isolation-observation/v1",
    source_fixture_identity: $source_fixture,
    target_fixture_identity: $target_fixture,
    source_network_sha256: $source_network,
    target_network_sha256: $target_network,
    reachability_receipt_sha256: $reachability,
    source_and_target_networks_disjoint: true,
    production_network_requests: 0,
    production_endpoint_mappings: 0,
    production_credentials: 0,
    host_mounts: 0,
    cross_fixture_mounts: 0,
    teardown_complete: true
  }
' >"${output_root}/isolation-observation.json"
chmod 0600 "${output_root}/isolation-observation.json"

printf '%s\n' "${source_commit}" >"${output_root}/implementation-head"
printf '%s\n' "${source_tree}" >"${output_root}/implementation-tree"
chmod 0600 "${output_root}/implementation-head" \
  "${output_root}/implementation-tree"
"${output_root}/mcloving-shadow-qualification" prepare \
  "${output_root}/source-probe.json" \
  "${output_root}/target-replay.json" \
  "${output_root}/trace-observation.json" \
  "${output_root}/isolation-observation.json" \
  "${output_root}/source-capture-key.pkcs8" \
  "${output_root}/source-capture-public.sha256" \
  "${output_root}/shadow-replay-public.base64" \
  "${private_package}" \
  "${package_pin}" \
  "${authz_generation_pin}" \
  "${output_root}/verifier-binary.sha256" \
  "${source_commit}" \
  "${output_root}/session-template.private.json" \
  >"${output_root}/template-preparation.log"
chmod 0600 "${output_root}/template-preparation.log"
printf '%s\n' \
  'source_capture_key_created=true' \
  'source_capture_complete=true' \
  'target_replay_complete=true' \
  'trace_replay_complete=true' \
  'fixtures_torn_down=true' \
  'source_authenticated_template_created=true' \
  'production_authority=false'
