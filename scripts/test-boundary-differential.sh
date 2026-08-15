#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_ROOT" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../tools/versions.env
source "${repo_root}/tools/versions.env"
jenkins_image='docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02'
cargo_registry="${CARGO_HOME:-${HOME}/.cargo}/registry"
if [[ ! -d "${cargo_registry}" ]]; then
  echo "a prefetched Cargo registry is required for the offline contained run" >&2
  exit 69
fi
if [[ "$(podman info --format '{{.Host.Security.Rootless}}')" != true ]]; then
  echo "DIFF-003 requires a rootless Podman engine" >&2
  exit 78
fi

output_parent="$(realpath -e "$(dirname -- "$1")")"
output_leaf="$(basename -- "$1")"
if [[ ! "${output_leaf}" =~ ^diff003-boundary-[0-9]{8}T[0-9]{6}Z$ || -e "$1" ]]; then
  echo "output must be one new diff003-boundary-TIMESTAMP directory" >&2
  exit 73
fi
if [[ "${output_parent}/" == "${repo_root}/"* ]]; then
  echo "output must be outside the source repository" >&2
  exit 73
fi
source_status="$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)"
if [[ -n "${source_status}" ]]; then
  echo "DIFF-003 evidence requires a clean source tree including untracked files" >&2
  printf '%s\n' "${source_status}" >&2
  exit 78
fi
source_commit="$(git -C "${repo_root}" rev-parse HEAD)"
source_tree="$(git -C "${repo_root}" rev-parse "${source_commit}^{tree}")"
output_root="${output_parent}/${output_leaf}"
evidence="${output_root}/evidence"
jenkins_network="mcloving-diff003-jenkins-${RANDOM}-${RANDOM}"
target_network="mcloving-diff003-target-${RANDOM}-${RANDOM}"
jenkins="mcloving-diff003-jenkins-${RANDOM}-${RANDOM}"
postgres="mcloving-diff003-postgres-${RANDOM}-${RANDOM}"
runner="mcloving-diff003-runner-${RANDOM}-${RANDOM}"
connector_runner="mcloving-diff003-connector-${RANDOM}-${RANDOM}"
observer_runner="mcloving-diff003-observer-${RANDOM}-${RANDOM}"
runtime_root="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-diff003.XXXXXX")"
jenkins_home="${runtime_root}/jenkins-home"
cargo_target="${runtime_root}/cargo-target"
cargo_target_connector="${runtime_root}/cargo-target-connector"
cargo_target_observer="${runtime_root}/cargo-target-observer"
main_runner_output="${runtime_root}/main-runner-output"
main_boundary_dir="${evidence}/runtime-boundaries-main"
connector_boundary_dir="${evidence}/runtime-boundaries-connector"
observer_boundary_dir="${evidence}/runtime-boundaries-observer"
main_assertion_dir="${evidence}/runtime-assertions-main"
connector_assertion_dir="${evidence}/runtime-assertions-connector"
observer_assertion_dir="${evidence}/runtime-assertions-observer"
receipt_auth_dir="${evidence}/runtime-receipt-auth"
receipt_signing_private="${runtime_root}/receipt-signing-private.pkcs8"
jenkins_port="$((21000 + (RANDOM % 2000)))"
jenkins_password="$(openssl rand -hex 32)"
jenkins_password_file="${runtime_root}/jenkins-password"
jenkins_netrc="${runtime_root}/netrc"

cleanup() {
  for container in "${observer_runner}" "${connector_runner}" "${runner}" "${postgres}" "${jenkins}"; do
    if [[ -n "${container}" ]]; then
      podman rm --force "${container}" >/dev/null 2>&1 || true
    fi
  done
  for fixture_network in "${target_network}" "${jenkins_network}"; do
    podman network rm "${fixture_network}" >/dev/null 2>&1 || true
  done
  podman unshare chown -R 0:0 "${runtime_root}" >/dev/null 2>&1 || true
  rm -rf -- "${runtime_root}"
}
trap cleanup EXIT

umask 077
mkdir -p "${evidence}" "${jenkins_home}/init.groovy.d" "${cargo_target}" \
  "${cargo_target_connector}" "${cargo_target_observer}" \
  "${main_runner_output}" \
  "${main_boundary_dir}" "${connector_boundary_dir}" "${observer_boundary_dir}" \
  "${main_assertion_dir}" "${connector_assertion_dir}" "${observer_assertion_dir}" \
  "${receipt_auth_dir}"
chmod 700 "${output_root}" "${evidence}" "${runtime_root}"
openssl genpkey -algorithm ED25519 -out "${receipt_signing_private}" >/dev/null 2>&1
chmod 600 "${receipt_signing_private}"
openssl pkey -in "${receipt_signing_private}" -pubout \
  -out "${receipt_auth_dir}/receipt-signing-public.pem" >/dev/null 2>&1
printf '%s\n' "${jenkins_password}" >"${jenkins_password_file}"
printf 'machine 127.0.0.1 login diff003-admin password %s\n' \
  "${jenkins_password}" >"${jenkins_netrc}"
chmod 600 "${jenkins_password_file}" "${jenkins_netrc}"
cp "${repo_root}/migration/boundary-differential-runtime-v1/init.groovy" \
  "${jenkins_home}/init.groovy.d/10-diff003.groovy"
podman unshare chown -R 1000:1000 "${jenkins_home}"
podman unshare chown 1000:1000 "${jenkins_password_file}"

podman network create --internal "${jenkins_network}" >/dev/null
podman run --detach --name "${jenkins}" \
  --network "${jenkins_network}" \
  --publish "127.0.0.1:${jenkins_port}:8080" \
  --cpus 2 --memory 3g --pids-limit 2048 \
  --security-opt no-new-privileges \
  --cap-drop all \
  --env JAVA_OPTS='-Djenkins.install.runSetupWizard=false -Djava.awt.headless=true' \
  --volume "${jenkins_password_file}:/run/secrets/diff003-admin-password:ro,Z" \
  --volume "${jenkins_home}:/var/jenkins_home:Z" \
  "${jenkins_image}" >/dev/null

jenkins_ready=false
for _ in $(seq 1 180); do
  if curl --fail --silent --show-error --connect-timeout 1 --max-time 2 \
    "http://127.0.0.1:${jenkins_port}/login" >/dev/null 2>&1; then
    jenkins_ready=true
    break
  fi
  if [[ "$(podman inspect --format '{{.State.Running}}' "${jenkins}")" != true ]]; then
    podman logs "${jenkins}" >"${evidence}/jenkins-controller.log" 2>&1
    podman inspect "${jenkins}" >"${evidence}/jenkins-inspect.json"
    echo "DIFF-003 Jenkins fixture exited before readiness" >&2
    exit 1
  fi
  sleep 1
done
if [[ "${jenkins_ready}" != true ]]; then
  podman logs "${jenkins}" >"${evidence}/jenkins-controller.log" 2>&1
  podman inspect "${jenkins}" >"${evidence}/jenkins-inspect.json"
  echo "DIFF-003 Jenkins fixture did not become ready" >&2
  exit 1
fi

read -r crumb_field crumb_value < <(
  curl --fail --silent --show-error --connect-timeout 2 --max-time 10 \
    --netrc-file "${jenkins_netrc}" \
    --cookie-jar "${runtime_root}/cookies" \
    "http://127.0.0.1:${jenkins_port}/crumbIssuer/api/json" \
    | jq --raw-output '[.crumbRequestField, .crumb] | @tsv'
)
curl --fail --silent --show-error --connect-timeout 2 --max-time 30 \
  --netrc-file "${jenkins_netrc}" \
  --cookie "${runtime_root}/cookies" \
  --header "${crumb_field}: ${crumb_value}" \
  --data-urlencode \
    "script@${repo_root}/migration/boundary-differential-runtime-v1/probe.groovy" \
  "http://127.0.0.1:${jenkins_port}/scriptText" \
  >"${evidence}/jenkins-probe.txt"
sed -n 's/^DIFF003=//p' "${evidence}/jenkins-probe.txt" \
  >"${evidence}/jenkins-runtime.json"
jq --exit-status '
  .schema == "mcloving.diff003.jenkins-runtime/v1"
  and .security_realm == "hudson.security.HudsonPrivateSecurityRealm"
  and .authorization_strategy ==
    "hudson.security.FullControlOnceLoggedInAuthorizationStrategy"
  and .loaded_trigger_classes == [
    "hudson.triggers.SCMTrigger",
    "hudson.triggers.TimerTrigger"
  ]
  and .jobs == 0
  and .production_boundary_mappings == 0
  and .external_effects == 0
  and (.production_credentials | not)
  and .production_endpoints == []
  and .authenticated_operator == "diff003-admin"
' "${evidence}/jenkins-runtime.json" >/dev/null
if podman exec "${jenkins}" bash -c \
  'timeout 3 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"' >/dev/null 2>&1; then
  echo "DIFF-003 Jenkins fixture unexpectedly reached the public network" >&2
  exit 1
fi
printf 'public-network-denied\n' >"${evidence}/jenkins-network-negative.txt"
podman logs "${jenkins}" >"${evidence}/jenkins-controller.log" 2>&1
podman inspect "${jenkins}" >"${evidence}/jenkins-inspect.json"
podman network inspect "${jenkins_network}" >"${evidence}/jenkins-network-inspect.json"
podman image inspect "${jenkins_image}" >"${evidence}/jenkins-image-inspect.json"
if grep -R -F -- "${jenkins_password}" "${evidence}" >/dev/null; then
  echo "DIFF-003 generated Jenkins credential entered retained evidence" >&2
  exit 1
fi
podman rm --force "${jenkins}" >/dev/null
jenkins=''
podman network rm "${jenkins_network}" >/dev/null
printf 'jenkins-stack-destroyed-before-target-phase\n' \
  >"${evidence}/stack-lifecycle.txt"
jenkins_password=''

podman network create --internal "${target_network}" >/dev/null
podman run --detach --name "${postgres}" \
  --network "${target_network}" --network-alias postgres \
  --cpus 2 --memory 2g --pids-limit 1024 \
  --security-opt no-new-privileges \
  --env POSTGRES_USER=mcloving \
  --env POSTGRES_HOST_AUTH_METHOD=trust \
  --env POSTGRES_DB=mcloving \
  "${MCLOVING_POSTGRES_IMAGE}" >/dev/null
postgres_ready=false
for _ in $(seq 1 120); do
  if podman run --rm --network "${target_network}" \
    --security-opt no-new-privileges --cap-drop all \
    "${MCLOVING_POSTGRES_IMAGE}" pg_isready --host postgres \
    --username mcloving --dbname mcloving >/dev/null 2>&1; then
    postgres_ready=true
    break
  fi
  if [[ "$(podman inspect --format '{{.State.Running}}' "${postgres}")" != true ]]; then
    podman logs "${postgres}" >"${evidence}/postgres.log" 2>&1
    podman inspect "${postgres}" >"${evidence}/postgres-inspect.json"
    echo "DIFF-003 PostgreSQL fixture exited before readiness" >&2
    exit 1
  fi
  sleep 0.25
done
if [[ "${postgres_ready}" != true ]]; then
  podman logs "${postgres}" >"${evidence}/postgres.log" 2>&1
  podman inspect "${postgres}" >"${evidence}/postgres-inspect.json"
  echo "DIFF-003 PostgreSQL fixture did not become ready" >&2
  exit 1
fi

podman create --name "${runner}" \
  --network "${target_network}" \
  --cpus 2 --memory 6g --pids-limit 4096 \
  --security-opt no-new-privileges \
  --cap-drop all \
  --cap-add SETUID --cap-add SETGID --cap-add SETFCAP \
  --env CARGO_NET_OFFLINE=true \
  --env CARGO_TARGET_DIR=/cargo-target \
  --env RUSTUP_TOOLCHAIN=1.97.1 \
  --env MCLOVING_TEST_DATABASE_URL=postgres://mcloving@postgres:5432/mcloving \
  --tmpfs /tmp/mcloving-source-transport-16m:rw,nodev,nosuid,noexec,size=16777216,mode=0700 \
  --tmpfs /tmp/mcloving-source-transport-512k:rw,nodev,nosuid,noexec,size=524288,mode=0700 \
  --tmpfs /tmp/mcloving-dependency-transport-16m:rw,nodev,nosuid,noexec,size=16777216,mode=0700 \
  --volume "${cargo_registry}:/usr/local/cargo/registry:ro" \
  --volume "${cargo_target}:/cargo-target:Z" \
  --volume "${main_boundary_dir}:/receipt:Z" \
  --volume "${main_assertion_dir}:/assertions:Z" \
  --volume "${main_runner_output}:/runner-output:Z" \
  --volume "${repo_root}:/work:ro,Z" \
  --workdir /work \
  "${MCLOVING_RUST_IMAGE}" \
  bash -c '
    set -euo pipefail
    export MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR=/receipt
    export MCLOVING_DIFF003_ASSERTION_OUTPUT_DIR=/assertions
    run_suite() {
      suite="$1"
      shift
      printf "suite_begin=%s\n" "${suite}"
      "$@"
      printf "%s\n" "${suite}" >>/runner-output/component-suites.txt
      printf "suite_end=%s\n" "${suite}"
    }
    run_suite input-adapter cargo test --locked --offline \
      -p mcloving-input-adapter -- --test-threads=1
    run_suite source-acquirer cargo test --locked --offline \
      -p mcloving-source-acquirer -- --test-threads=1
    run_suite controller-trigger cargo test --locked --offline \
      -p mcloving-controller-store --test trigger_ingress -- --test-threads=1
    run_suite controller-discovery cargo test --locked --offline \
      -p mcloving-controller-store --test discovery -- --test-threads=1
    run_suite controller-consumer cargo test --locked --offline \
      -p mcloving-controller-store --test external_read_consumers -- --test-threads=1
    run_suite controller-admin cargo test --locked --offline \
      -p mcloving-controller-store --test external_admin_clients -- --test-threads=1
    run_suite secret-broker cargo test --locked --offline \
      -p mcloving-secret-broker
    run_suite provisioner cargo test --locked --offline \
      -p mcloving-provisioner
    run_dependency_suite() {
      cargo test --locked --offline -p mcloving-dependency-resolver
      env \
        MCLOVING_DEPENDENCY_TRANSPORT_ROOT=/tmp/mcloving-dependency-transport-16m \
        MCLOVING_DEPENDENCY_TRANSPORT_CAPACITY=16777216 \
        MCLOVING_DEPENDENCY_RESOLVER_TEST_MODE=1 \
        MCLOVING_DIFF003_CONTAINED=1 \
        cargo test --locked --offline -p mcloving-dependency-resolver \
          --test contained_resolver standalone_exact_resolution_and_offline_restart_replay \
          -- --ignored --nocapture --test-threads=1
    }
    run_suite dependency-resolver run_dependency_suite
    run_suite cache cargo test --locked --offline -p mcloving-cache
    run_suite release-provenance cargo test --locked --offline \
      -p mcloving-release-provenance
    run_suite boundary-differential cargo test --locked --offline \
      -p mcloving-boundary-differential
    cargo run --locked --offline --quiet \
      -p mcloving-boundary-differential -- \
      migration/boundary-differential-v1 \
      >/runner-output/verifier-receipt.txt
    if timeout 3 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" \
      >/dev/null 2>&1; then
      echo "target fixture unexpectedly reached the public network" >&2
      exit 1
    fi
    printf "public-network-denied\n" >/runner-output/target-network-negative.txt
  ' >/dev/null

set +e
podman start --attach "${runner}" >"${evidence}/test-output.txt" 2>&1
runner_status=$?
set -e
podman inspect "${runner}" >"${evidence}/runner-inspect.json"
podman inspect "${postgres}" >"${evidence}/postgres-inspect.json"
podman logs "${postgres}" >"${evidence}/postgres.log" 2>&1
podman network inspect "${target_network}" >"${evidence}/target-network-inspect.json"
podman image inspect "${MCLOVING_RUST_IMAGE}" >"${evidence}/rust-image-inspect.json"
podman image inspect "${MCLOVING_POSTGRES_IMAGE}" >"${evidence}/postgres-image-inspect.json"
if [[ ${runner_status} -ne 0 ]]; then
  echo "DIFF-003 contained runner failed; evidence retained unsealed at ${output_root}" >&2
  exit "${runner_status}"
fi
cp "${main_runner_output}/component-suites.txt" "${evidence}/component-suites.txt"
cp "${main_runner_output}/verifier-receipt.txt" "${evidence}/verifier-receipt.txt"
cp "${main_runner_output}/target-network-negative.txt" \
  "${evidence}/target-network-negative.txt"

podman create --name "${connector_runner}" --network none \
  --cpus 2 --memory 4g --pids-limit 2048 \
  --security-opt no-new-privileges --cap-drop all \
  --env CARGO_NET_OFFLINE=true --env CARGO_TARGET_DIR=/cargo-target \
  --env RUSTUP_TOOLCHAIN=1.97.1 \
  --env MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR=/receipt \
  --env MCLOVING_DIFF003_ASSERTION_OUTPUT_DIR=/assertions \
  --tmpfs /tmp:rw,nodev,nosuid,size=536870912,mode=0700 \
  --volume "${cargo_registry}:/usr/local/cargo/registry:ro" \
  --volume "${cargo_target_connector}:/cargo-target:Z" \
  --volume "${connector_boundary_dir}:/receipt:Z" \
  --volume "${connector_assertion_dir}:/assertions:Z" \
  --volume "${repo_root}:/work:ro,Z" --workdir /work \
  "${MCLOVING_RUST_IMAGE}" \
  cargo test --locked --offline -p mcloving-external-connector \
    --features loopback-test -- --test-threads=1 >/dev/null
set +e
podman start --attach "${connector_runner}" >>"${evidence}/test-output.txt" 2>&1
connector_status=$?
set -e
podman inspect "${connector_runner}" >"${evidence}/connector-runner-inspect.json"
[[ ${connector_status} -eq 0 ]] || {
  echo "DIFF-003 isolated connector suite failed" >&2
  exit "${connector_status}"
}
printf 'external-connector\n' >>"${evidence}/component-suites.txt"

podman create --name "${observer_runner}" --network none \
  --cpus 2 --memory 4g --pids-limit 2048 \
  --security-opt no-new-privileges --cap-drop all \
  --env CARGO_NET_OFFLINE=true --env CARGO_TARGET_DIR=/cargo-target \
  --env RUSTUP_TOOLCHAIN=1.97.1 \
  --env MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR=/receipt \
  --env MCLOVING_DIFF003_ASSERTION_OUTPUT_DIR=/assertions \
  --env MCLOVING_DIFF003_CONNECTOR_RECEIPT=/connector-receipt/EXT-001.json \
  --tmpfs /tmp:rw,nodev,nosuid,size=536870912,mode=0700 \
  --volume "${cargo_registry}:/usr/local/cargo/registry:ro" \
  --volume "${cargo_target_observer}:/cargo-target:Z" \
  --volume "${observer_boundary_dir}:/receipt:Z" \
  --volume "${observer_assertion_dir}:/assertions:Z" \
  --volume "${connector_boundary_dir}:/connector-receipt:ro,Z" \
  --volume "${repo_root}:/work:ro,Z" --workdir /work \
  "${MCLOVING_RUST_IMAGE}" \
  cargo test --locked --offline -p mcloving-destination-observer \
    --features loopback-test -- --test-threads=1 >/dev/null
set +e
podman start --attach "${observer_runner}" >>"${evidence}/test-output.txt" 2>&1
observer_status=$?
set -e
podman inspect "${observer_runner}" >"${evidence}/observer-runner-inspect.json"
[[ ${observer_status} -eq 0 ]] || {
  echo "DIFF-003 isolated observer suite failed" >&2
  exit "${observer_status}"
}
printf 'destination-observer\n' >>"${evidence}/component-suites.txt"

runtime_boundary_dir="${evidence}/runtime-boundaries"
mkdir -p "${runtime_boundary_dir}"
cp "${main_boundary_dir}"/*.json "${runtime_boundary_dir}/"
cp "${connector_boundary_dir}/EXT-001.json" "${runtime_boundary_dir}/"
cp "${observer_boundary_dir}/OBS-001.json" "${runtime_boundary_dir}/"

runtime_assertion_dir="${evidence}/runtime-assertions"
mkdir -p "${runtime_assertion_dir}"
cp "${main_assertion_dir}"/*.json "${runtime_assertion_dir}/"
cp "${connector_assertion_dir}"/*.json "${runtime_assertion_dir}/"
cp "${observer_assertion_dir}"/*.json "${runtime_assertion_dir}/"

for boundary_file in "${runtime_boundary_dir}"/*.json; do
  boundary_id="$(basename "${boundary_file}" .json)"
  openssl pkeyutl -sign -rawin -inkey "${receipt_signing_private}" \
    -in "${boundary_file}" -out "${receipt_auth_dir}/${boundary_id}.sig"
done
rm -f -- "${receipt_signing_private}"
receipt_signing_private=''

# The resolver's two bind-topology authority-alias negatives require mount
# authority. Run that one exact test in a separate rootless user-namespace
# container with no network, no host-root mapping, and no writable source mount.
podman run --rm --network none \
  --cpus 2 --memory 4g --pids-limit 2048 \
  --security-opt no-new-privileges --security-opt apparmor=unconfined \
  --cap-drop all --cap-add SYS_ADMIN \
  --env CARGO_NET_OFFLINE=true \
  --env CARGO_TARGET_DIR=/cargo-target \
  --env RUSTUP_TOOLCHAIN=1.97.1 \
  --env MCLOVING_DEPENDENCY_TRANSPORT_ROOT=/tmp/mcloving-dependency-transport-16m \
  --env MCLOVING_DEPENDENCY_TRANSPORT_CAPACITY=16777216 \
  --env MCLOVING_DEPENDENCY_RESOLVER_TEST_MODE=1 \
  --env MCLOVING_DIFF003_CONTAINED=1 \
  --env MCLOVING_DIFF003_MOUNT_DIRECT=1 \
  --tmpfs /tmp/mcloving-dependency-transport-16m:rw,nodev,nosuid,noexec,size=16777216,mode=0700 \
  --volume "${cargo_registry}:/usr/local/cargo/registry:ro" \
  --volume "${cargo_target}:/cargo-target:Z" \
  --volume "${repo_root}:/work:ro,Z" \
  --workdir /work \
  "${MCLOVING_RUST_IMAGE}" \
  cargo test --locked --offline -p mcloving-dependency-resolver \
    --test contained_resolver standalone_exact_resolution_and_offline_restart_replay \
    -- --ignored --nocapture --test-threads=1 \
  >>"${evidence}/test-output.txt" 2>&1
printf 'rootless-isolated-bind-alias-negatives-passed\n' \
  >"${evidence}/dependency-authority-alias-negative.txt"
printf 'dependency-resolver-authority-alias\n' \
  >>"${evidence}/component-suites.txt"

expected_suites="${runtime_root}/expected-suites.txt"
printf '%s\n' \
  input-adapter \
  source-acquirer \
  controller-trigger \
  controller-discovery \
  controller-consumer \
  controller-admin \
  secret-broker \
  provisioner \
  dependency-resolver \
  cache \
  release-provenance \
  boundary-differential \
  external-connector \
  destination-observer \
  dependency-resolver-authority-alias \
  >"${expected_suites}"
diff -u "${expected_suites}" "${evidence}/component-suites.txt"

component_manifest="${evidence}/component-source-manifests.txt"
: >"${component_manifest}"
component_digest() {
  git -C "${repo_root}" ls-files -s -- "$@" | sha256sum | awk '{print $1}'
}
printf 'controller %s\n' "$(component_digest crates/controller-store crates/controller-api crates/test-support/diff003.rs)" >>"${component_manifest}"
printf 'SCM-001 %s\n' "$(component_digest crates/source-acquirer crates/test-support/diff003.rs)" >>"${component_manifest}"
printf 'SECRET-001 %s\n' "$(component_digest crates/secret-broker crates/test-support/diff003.rs)" >>"${component_manifest}"
printf 'INPUT-001 %s\n' "$(component_digest crates/input-adapter crates/test-support/diff003.rs)" >>"${component_manifest}"
printf 'PROV-001 %s\n' "$(component_digest crates/provisioner crates/test-support/diff003.rs)" >>"${component_manifest}"
printf 'EXT-001 %s\n' "$(component_digest crates/external-connector crates/test-support/diff003.rs)" >>"${component_manifest}"
printf 'OBS-001 %s\n' "$(component_digest crates/destination-observer crates/test-support/diff003.rs)" >>"${component_manifest}"
printf 'DEP-001 %s\n' "$(component_digest crates/dependency-resolver crates/test-support/diff003.rs)" >>"${component_manifest}"
printf 'CACHE-001 %s\n' "$(component_digest crates/cache crates/test-support/diff003.rs)" >>"${component_manifest}"
printf 'REL-001 %s\n' "$(component_digest crates/release-provenance crates/test-support/diff003.rs)" >>"${component_manifest}"

certificate="${repo_root}/migration/boundary-differential-v1/boundary-differential.json"
while read -r component_id actual_digest; do
  if [[ "${component_id}" == controller ]]; then
    expected_digest="$(jq -r '.boundaries[] | select(.id == "TRIG-001") | .implementation_source_manifest_sha256' "${certificate}")"
  else
    expected_digest="$(jq -r --arg id "${component_id}" '.boundaries[] | select(.id == $id) | .implementation_source_manifest_sha256' "${certificate}")"
  fi
  if [[ -z "${expected_digest}" || "${actual_digest}" != "${expected_digest}" ]]; then
    echo "DIFF-003 component source manifest mismatch for ${component_id}" >&2
    exit 1
  fi
done <"${component_manifest}"

runtime_boundary_jsonl="${evidence}/runtime-boundaries.jsonl"
: >"${runtime_boundary_jsonl}"
for boundary_id in \
  TRIG-001 SCM-001 SECRET-001 INPUT-001 PROV-001 EXT-001 OBS-001 \
  DISC-001 DEP-001 CACHE-001 CONSUMER-001 ADMIN-001 REL-001; do
  boundary_file="${runtime_boundary_dir}/${boundary_id}.json"
  if [[ ! -f "${boundary_file}" || -L "${boundary_file}" ]]; then
    echo "DIFF-003 live receipt missing or unsafe for ${boundary_id}" >&2
    exit 1
  fi
  jq --exit-status 'type == "object" and length > 0' "${boundary_file}" >/dev/null
  boundary_sha256="$(sha256sum "${boundary_file}" | awk '{print $1}')"
  jq -cn \
    --arg boundary "${boundary_id}" \
    --arg receipt_sha256 "${boundary_sha256}" \
    --slurpfile receipt "${boundary_file}" \
    '{boundary: $boundary, receipt_sha256: $receipt_sha256, receipt: $receipt[0]}' \
    >>"${runtime_boundary_jsonl}"
done
jq --slurp '.' "${runtime_boundary_jsonl}" >"${evidence}/runtime-boundaries.json"

"${repo_root}/scripts/verify-boundary-runtime.sh" \
  "${certificate}" "${runtime_boundary_dir}" "${receipt_auth_dir}" \
  "${runtime_assertion_dir}" "${evidence}/test-output.txt" \
  "${evidence}/runtime-verification"
cp "${evidence}/runtime-verification/validated-joins.json" \
  "${evidence}/runtime-joins.json"
cp "${evidence}/runtime-verification/executed-scenarios.json" \
  "${evidence}/executed-scenarios.json"

certificate_sha256="$(sha256sum "${certificate}" | awk '{print $1}')"
receipt_auth_public_key_sha256=$(
  openssl pkey -pubin -in "${receipt_auth_dir}/receipt-signing-public.pem" \
    -outform DER | sha256sum | awk '{print $1}'
)
jq -n \
  --arg source_commit "${source_commit}" \
  --arg source_tree "${source_tree}" \
  --arg certificate_sha256 "${certificate_sha256}" \
  --arg receipt_auth_public_key_sha256 "${receipt_auth_public_key_sha256}" \
  --slurpfile certificate "${certificate}" \
  --slurpfile jenkins "${evidence}/jenkins-runtime.json" \
  --slurpfile live_boundaries "${evidence}/runtime-boundaries.json" \
  --slurpfile live_joins "${evidence}/runtime-joins.json" \
  --slurpfile executed_scenarios "${evidence}/executed-scenarios.json" '
  {
    schema: "mcloving.diff003.runtime-comparison/v1",
    source_commit: $source_commit,
    source_tree: $source_tree,
    certificate_sha256: $certificate_sha256,
    certificate_schema: $certificate[0].schema,
    jenkins_schema: $jenkins[0].schema,
    boundary_count: ($certificate[0].boundaries | length),
    live_boundary_receipt_count: ($live_boundaries[0] | length),
    authenticated_boundary_receipt_count: ($live_boundaries[0] | length),
    receipt_auth_public_key_sha256: $receipt_auth_public_key_sha256,
    scenario_count: ($certificate[0].scenarios | length),
    executed_scenario_count: ($executed_scenarios[0] | length),
    join_count: ($certificate[0].joins | length),
    live_join_count: ($live_joins[0] | length),
    component_suites_passed: 15,
    separate_private_stacks: $certificate[0].network.separate_private_stacks,
    jenkins_destroyed_before_target: $certificate[0].network.jenkins_destroyed_before_target,
    production_boundary_mappings: $certificate[0].authority.production_boundary_mappings,
    production_external_effects: $certificate[0].authority.production_external_effects,
    production_cutover_claimed: $certificate[0].clients.production_cutover_claimed,
    duplicate_effects: ([$live_joins[0][].duplicate_effects] | add),
    secret_marker_disclosures: null,
    encoded_marker_scan_passed: false,
    verifier_passed: true
  }
' >"${evidence}/runtime-comparison.json"
jq --exit-status '
  .schema == "mcloving.diff003.runtime-comparison/v1"
  and .certificate_schema == "mcloving.jenkins.boundary-differential/v1"
  and .jenkins_schema == "mcloving.diff003.jenkins-runtime/v1"
  and .boundary_count == 13
  and .live_boundary_receipt_count == 13
  and .authenticated_boundary_receipt_count == 13
  and (.receipt_auth_public_key_sha256 | test("^[0-9a-f]{64}$"))
  and .scenario_count == 48
  and .executed_scenario_count == 48
  and .join_count == 11
  and .live_join_count == 11
  and .component_suites_passed == 15
  and .separate_private_stacks
  and .jenkins_destroyed_before_target
  and .production_boundary_mappings == 0
  and .production_external_effects == 0
  and (.production_cutover_claimed | not)
  and .duplicate_effects == 0
  and .verifier_passed
' "${evidence}/runtime-comparison.json" >/dev/null

for required_line in \
  'schema=mcloving.jenkins.boundary-differential/v1' \
  'case=mario-contained-boundaries-zero-authority' \
  'boundaries=13' \
  'scenarios=48' \
  'joins=11' \
  'production_boundary_mappings=0' \
  'duplicate_effects=0' \
  'secret_marker_disclosures=0'; do
  grep -Fqx "${required_line}" "${evidence}/verifier-receipt.txt"
done

if grep -R -E -- 'BEGIN (OPENSSH |EC |RSA )?PRIVATE KEY|BEGIN PRIVATE KEY|release-key\.pkcs8' \
  "${evidence}" >/dev/null; then
  echo "DIFF-003 retained evidence contains private-key material or a private-key path" >&2
  exit 1
fi
for private_marker in \
  contained-source-credential-marker-00000001 \
  contained-source-receipt-signing-key-00000000000000000001 \
  unique-secret-marker-do-not-disclose \
  fixture-read-token-32-bytes-minimum-value \
  fixture-adapter-signing-key-32-bytes-minimum \
  mcloving-secret-marker-never-disclose \
  contained-provider-token \
  contained-receipt-signing-key-000000000000000000000000 \
  connector-only-token \
  never-publish-connector-secret \
  read-only-observer-token \
  never-publish-this-secret \
  contained-dependency-credential \
  contained-dependency-receipt-key-material-v1; do
  marker_base64="$(printf '%s' "${private_marker}" | base64 -w0)"
  marker_base64url="$(printf '%s' "${marker_base64}" | tr '+/' '-_' | sed 's/=*$//')"
  marker_hex="$(printf '%s' "${private_marker}" | od -An -v -tx1 | tr -d ' \n')"
  marker_percent="$(printf '%s' "${marker_hex}" | sed 's/../%&/g')"
  marker_nested="$(printf '%s' "${marker_base64}" | base64 -w0)"
  for marker_variant in \
    "${private_marker}" "${marker_base64}" "${marker_base64url}" \
    "${marker_hex}" "${marker_percent}" "${marker_nested}"; do
    if grep -R -F -- "${marker_variant}" "${evidence}" >/dev/null; then
      echo "DIFF-003 retained evidence disclosed a raw or encoded contained marker" >&2
      exit 1
    fi
    while IFS= read -r -d '' retained_name; do
      if [[ "${retained_name}" == *"${marker_variant}"* ]]; then
        echo "DIFF-003 retained evidence pathname disclosed a contained marker" >&2
        exit 1
      fi
    done < <(find "${evidence}" -mindepth 1 -printf '%P\0')
  done
  for case_insensitive_variant in "${marker_hex}" "${marker_percent}"; do
    if grep -R -F -i -- "${case_insensitive_variant}" "${evidence}" >/dev/null; then
      echo "DIFF-003 retained evidence disclosed a case-varied encoded marker" >&2
      exit 1
    fi
    folded_variant=$(printf '%s' "${case_insensitive_variant}" | tr '[:upper:]' '[:lower:]')
    while IFS= read -r -d '' retained_name; do
      folded_name=$(printf '%s' "${retained_name}" | tr '[:upper:]' '[:lower:]')
      if [[ "${folded_name}" == *"${folded_variant}"* ]]; then
        echo "DIFF-003 retained evidence pathname disclosed a case-varied marker" >&2
        exit 1
      fi
    done < <(find "${evidence}" -mindepth 1 -printf '%P\0')
  done
done
printf 'contents-and-pathnames-raw-base64-base64url-hex-all-case-percent-all-case-nested-base64-clean\n' \
  >"${evidence}/encoded-marker-scan.txt"
comparison_update="${runtime_root}/runtime-comparison.json"
jq '.secret_marker_disclosures = 0 | .encoded_marker_scan_passed = true' \
  "${evidence}/runtime-comparison.json" >"${comparison_update}"
mv "${comparison_update}" "${evidence}/runtime-comparison.json"
jq --exit-status '
  .secret_marker_disclosures == 0 and .encoded_marker_scan_passed
' "${evidence}/runtime-comparison.json" >/dev/null

for source_file in \
  Cargo.lock \
  crates/boundary-differential/Cargo.toml \
  crates/boundary-differential/src/lib.rs \
  crates/boundary-differential/src/main.rs \
  crates/test-support/diff003.rs \
  migration/boundary-differential-v1/SHA256SUMS \
  migration/boundary-differential-v1/boundary-differential.json \
  migration/boundary-differential-runtime-v1/init.groovy \
  migration/boundary-differential-runtime-v1/probe.groovy \
  scripts/verify-boundary-runtime.sh \
  scripts/test-boundary-differential.sh; do
  sha256sum "${repo_root}/${source_file}"
done >"${evidence}/source-files.sha256"

seal_source_status="$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)"
seal_source_commit="$(git -C "${repo_root}" rev-parse HEAD)"
seal_source_tree="$(git -C "${repo_root}" rev-parse HEAD^{tree})"
if [[ -n "${seal_source_status}" || "${seal_source_commit}" != "${source_commit}" \
  || "${seal_source_tree}" != "${source_tree}" ]]; then
  echo "DIFF-003 source commit, tree, or status changed before sealing" >&2
  printf '%s\n' "${seal_source_status}" >&2
  exit 78
fi

{
  printf 'schema=mcloving.diff003.runtime/v1\n'
  printf 'source_commit=%s\n' "${source_commit}"
  printf 'source_tree=%s\n' "${source_tree}"
  printf 'source_status=\n'
  printf 'jenkins_image=%s\n' "${jenkins_image}"
  printf 'rust_image=%s\n' "${MCLOVING_RUST_IMAGE}"
  printf 'postgres_image=%s\n' "${MCLOVING_POSTGRES_IMAGE}"
  printf 'runner_exit=%s\n' "${runner_status}"
} >"${evidence}/runtime.txt"

manifest="${output_root}/evidence-manifest.sha256"
non_regular_entry=$(
  find "${evidence}" -mindepth 1 ! -type f ! -type d -print -quit
)
if [[ -n "${non_regular_entry}" ]]; then
  echo "DIFF-003 retained evidence contains a non-regular entry" >&2
  exit 1
fi
linked_file=$(find "${evidence}" -type f -links +1 -print -quit)
if [[ -n "${linked_file}" ]]; then
  echo "DIFF-003 retained evidence contains a multiply linked file" >&2
  exit 1
fi
(
  cd "${output_root}"
  find evidence -type f -printf '%P\0' \
    | sort -z \
    | while IFS= read -r -d '' retained_file; do
        sha256sum "evidence/${retained_file}"
      done
) >"${manifest}"
(
  cd "${output_root}"
  sha256sum --check "${manifest}" >/dev/null
)
chmod 600 "${manifest}"
printf 'DIFF-003 evidence sealed at %s\n' "${output_root}"
printf 'evidence_manifest_sha256=%s\n' "$(sha256sum "${manifest}" | awk '{print $1}')"
