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

output_parent="$(realpath -e "$(dirname -- "$1")")"
output_leaf="$(basename -- "$1")"
if [[ ! "${output_leaf}" =~ ^diff002-state-policy-[0-9]{8}T[0-9]{6}Z$ || -e "$1" ]]; then
  echo "output must be one new diff002-state-policy-TIMESTAMP directory" >&2
  exit 73
fi
if [[ "${output_parent}/" == "${repo_root}/"* ]]; then
  echo "output must be outside the source repository" >&2
  exit 73
fi
source_status="$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)"
if [[ -n "${source_status}" ]]; then
  echo "DIFF-002 evidence requires a clean source tree including untracked files" >&2
  printf '%s\n' "${source_status}" >&2
  exit 78
fi
output_root="${output_parent}/${output_leaf}"
evidence="${output_root}/evidence"
network="mcloving-diff002-${RANDOM}-${RANDOM}"
postgres="mcloving-diff002-postgres-${RANDOM}-${RANDOM}"
runner="mcloving-diff002-runner-${RANDOM}-${RANDOM}"
jenkins="mcloving-diff002-jenkins-${RANDOM}-${RANDOM}"
jenkins_runtime="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-diff002-jenkins.XXXXXX")"
jenkins_home="${jenkins_runtime}/home"
jenkins_port="$((19000 + (RANDOM % 2000)))"
jenkins_password="$(openssl rand -hex 32)"
jenkins_netrc="${jenkins_runtime}/netrc"
printf 'machine 127.0.0.1 login diff002-admin password %s\n' \
  "${jenkins_password}" >"${jenkins_netrc}"
chmod 600 "${jenkins_netrc}"

cleanup() {
  podman rm --force "${runner}" "${postgres}" "${jenkins}" >/dev/null 2>&1 || true
  podman network rm "${network}" >/dev/null 2>&1 || true
  podman unshare chown -R 0:0 "${jenkins_runtime}" >/dev/null 2>&1 || true
  rm -rf -- "${jenkins_runtime}"
}
trap cleanup EXIT

mkdir -p "${evidence}"
mkdir -p "${jenkins_home}/init.groovy.d"
cp "${repo_root}/migration/state-policy-runtime-v1/init.groovy" \
  "${jenkins_home}/init.groovy.d/10-diff002.groovy"
podman unshare chown -R 1000:1000 "${jenkins_home}"
podman network create --internal "${network}" >/dev/null
podman run --detach --name "${jenkins}" \
  --network "${network}" \
  --publish "127.0.0.1:${jenkins_port}:8080" \
  --cpus 2 --memory 3g --pids-limit 2048 \
  --security-opt no-new-privileges \
  --cap-drop all \
  --env JAVA_OPTS='-Djenkins.install.runSetupWizard=false -Djava.awt.headless=true' \
  --env DIFF002_ADMIN_PASSWORD="${jenkins_password}" \
  --volume "${jenkins_home}:/var/jenkins_home:Z" \
  "${jenkins_image}" >/dev/null

jenkins_ready=false
for _ in $(seq 1 180); do
  if curl --fail --silent --show-error \
    "http://127.0.0.1:${jenkins_port}/login" >/dev/null 2>&1; then
    jenkins_ready=true
    break
  fi
  if [[ "$(podman inspect --format '{{.State.Running}}' "${jenkins}")" != true ]]; then
    podman logs "${jenkins}" >"${evidence}/jenkins-controller.log" 2>&1
    podman inspect "${jenkins}" >"${evidence}/jenkins-inspect.json"
    echo "DIFF-002 Jenkins fixture exited before readiness; evidence retained at ${output_root}" >&2
    exit 1
  fi
  sleep 1
done
if [[ "${jenkins_ready}" != true ]]; then
  podman logs "${jenkins}" >"${evidence}/jenkins-controller.log" 2>&1
  podman inspect "${jenkins}" >"${evidence}/jenkins-inspect.json"
  echo "DIFF-002 Jenkins fixture did not become ready; evidence retained at ${output_root}" >&2
  exit 1
fi
read -r crumb_field crumb_value < <(
  curl --fail --silent --show-error \
    --netrc-file "${jenkins_netrc}" \
    --cookie-jar "${jenkins_runtime}/cookies" \
    "http://127.0.0.1:${jenkins_port}/crumbIssuer/api/json" \
    | jq --raw-output '[.crumbRequestField, .crumb] | @tsv'
)
curl --fail --silent --show-error \
  --netrc-file "${jenkins_netrc}" \
  --cookie "${jenkins_runtime}/cookies" \
  --header "${crumb_field}: ${crumb_value}" \
  --data-urlencode \
    "script@${repo_root}/migration/state-policy-runtime-v1/probe.groovy" \
  "http://127.0.0.1:${jenkins_port}/scriptText" \
  >"${evidence}/jenkins-probe.txt"
sed -n 's/^DIFF002=//p' "${evidence}/jenkins-probe.txt" \
  >"${evidence}/jenkins-runtime.json"
jq --exit-status '
  .schema == "mcloving.diff002.jenkins-runtime/v1"
  and (.decisions | length) == 4
  and .deleted_reuse_immutable_id == "jenkins-user-deleted-reuse-2042"
  and ([.deleted_reuse_decisions[]] | all(. == "deny"))
  and .states == [
    {"state":"enabled","generation":1},
    {"state":"disabled","generation":2},
    {"state":"enabled","generation":3}
  ]
  and .disabled_prequeue_denied
  and .rollback_admitted
' "${evidence}/jenkins-runtime.json" >/dev/null
if podman exec "${jenkins}" bash -c \
  'timeout 3 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"' >/dev/null 2>&1; then
  echo "DIFF-002 Jenkins fixture unexpectedly reached the public network" >&2
  exit 1
fi
printf 'public-network-denied\n' >"${evidence}/jenkins-network-negative.txt"
podman logs "${jenkins}" >"${evidence}/jenkins-controller.log" 2>&1
podman inspect "${jenkins}" >"${evidence}/jenkins-inspect.json"
podman image inspect "${jenkins_image}" >"${evidence}/jenkins-image-inspect.json"

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
  --cpus 2 --memory 4g --pids-limit 2048 \
  --security-opt no-new-privileges \
  --cap-drop all \
  --env CARGO_NET_OFFLINE=true \
  --env RUSTUP_TOOLCHAIN=1.97.1 \
  --env MCLOVING_TEST_DATABASE_URL=postgres://mcloving@postgres:5432/mcloving \
  --env MCLOVING_DIFF002_AUTHZ_OUTPUT=/evidence/target-authorization.json \
  --env MCLOVING_DIFF002_OPERATIONAL_OUTPUT=/evidence/target-operational.json \
  --volume "${cargo_registry}:/usr/local/cargo/registry:ro" \
  --volume "${evidence}:/evidence:Z" \
  --volume "${repo_root}:/work:Z" \
  --workdir /work \
  "${MCLOVING_RUST_IMAGE}" \
  bash -c '
    set -euo pipefail
    cargo test --locked --offline -p mcloving-state-policy-differential
    cargo test --locked --offline -p mcloving-controller-store \
      --test identity_lifecycle -- --test-threads=1
    cargo test --locked --offline -p mcloving-controller-store \
      --test authorization_mapping -- --test-threads=1
    cargo test --locked --offline -p mcloving-controller-store \
      --test pipeline_operational_state -- --test-threads=1
    cargo run --locked --offline --quiet \
      -p mcloving-state-policy-differential -- \
      migration/state-policy-differential-v1
  ' >/dev/null

set +e
podman start --attach "${runner}" >"${evidence}/test-output.txt" 2>&1
runner_status=$?
set -e
podman inspect "${runner}" >"${evidence}/runner-inspect.json"
podman inspect "${postgres}" >"${evidence}/postgres-inspect.json"
podman network inspect "${network}" >"${evidence}/network-inspect.json"
podman image inspect "${MCLOVING_RUST_IMAGE}" >"${evidence}/rust-image-inspect.json"
podman image inspect "${MCLOVING_POSTGRES_IMAGE}" >"${evidence}/postgres-image-inspect.json"

jq -n \
  --slurpfile source "${evidence}/jenkins-runtime.json" \
  --slurpfile authorization "${evidence}/target-authorization.json" \
  --slurpfile operational "${evidence}/target-operational.json" '
  {
    schema: "mcloving.diff002.runtime-comparison/v1",
    source_schema: $source[0].schema,
    authorization_schema: $authorization[0].schema,
    operational_schema: $operational[0].schema,
    immutable_identity_equal:
      ($source[0].immutable_id == $authorization[0].immutable_id),
    decisions_equal:
      ($source[0].decisions == $authorization[0].decisions),
    deleted_reuse_identity_equal:
      ($source[0].deleted_reuse_immutable_id
       == $authorization[0].deleted_reuse_immutable_id),
    deleted_reuse_decisions_equal:
      ($source[0].deleted_reuse_decisions
       == $authorization[0].deleted_reuse_decisions),
    operational_states_equal:
      ($source[0].states == $operational[0].states),
    disabled_prequeue_equal:
      ($source[0].disabled_prequeue_denied
       == $operational[0].disabled_prequeue_denied),
    rollback_admission_equal:
      ($source[0].rollback_admitted == $operational[0].rollback_admitted),
    parity:
      ($source[0].immutable_id == $authorization[0].immutable_id
       and $source[0].decisions == $authorization[0].decisions
       and $source[0].deleted_reuse_immutable_id
          == $authorization[0].deleted_reuse_immutable_id
       and $source[0].deleted_reuse_decisions
          == $authorization[0].deleted_reuse_decisions
       and $source[0].states == $operational[0].states
       and $source[0].disabled_prequeue_denied
          == $operational[0].disabled_prequeue_denied
       and $source[0].rollback_admitted
          == $operational[0].rollback_admitted)
  }
' >"${evidence}/runtime-comparison.json"
jq --exit-status '.parity == true' \
  "${evidence}/runtime-comparison.json" >/dev/null

source_status="$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)"
if [[ -n "${source_status}" ]]; then
  echo "DIFF-002 source tree changed during execution; evidence remains unsealed at ${output_root}" >&2
  printf '%s\n' "${source_status}" >&2
  exit 78
fi

{
  printf 'source_commit=%s\n' "$(git -C "${repo_root}" rev-parse HEAD)"
  printf 'source_tree=%s\n' "$(git -C "${repo_root}" rev-parse HEAD^{tree})"
  printf 'source_status='
  printf '%s' "${source_status}" | tr '\n' ','
  printf '\n'
  printf 'rust_image=%s\n' "${MCLOVING_RUST_IMAGE}"
  printf 'postgres_image=%s\n' "${MCLOVING_POSTGRES_IMAGE}"
  printf 'jenkins_image=%s\n' "${jenkins_image}"
  printf 'runner_exit=%s\n' "${runner_status}"
} >"${evidence}/runtime.txt"

for path in \
  Cargo.lock \
  crates/state-policy-differential/Cargo.toml \
  crates/state-policy-differential/src/lib.rs \
  crates/state-policy-differential/src/main.rs \
  crates/controller-store/tests/authorization_mapping.rs \
  crates/controller-store/tests/pipeline_operational_state.rs \
  migration/state-policy-differential-v1/SHA256SUMS \
  migration/state-policy-differential-v1/state-policy.json \
  migration/state-policy-runtime-v1/init.groovy \
  migration/state-policy-runtime-v1/probe.groovy; do
  sha256sum "${repo_root}/${path}"
done >"${evidence}/source-files.sha256"

if [[ ${runner_status} -ne 0 ]]; then
  echo "DIFF-002 contained runner failed; evidence retained at ${output_root}" >&2
  exit "${runner_status}"
fi

find "${evidence}" -type f ! -name SHA256SUMS -printf '%P\0' \
  | sort -z \
  | while IFS= read -r -d '' path; do
      sha256sum "${evidence}/${path}"
    done >"${evidence}/SHA256SUMS"
sha256sum -c "${evidence}/SHA256SUMS"
printf 'diff002_evidence=%s\n' "${output_root}"
printf 'diff002_manifest_sha256=%s\n' \
  "$(sha256sum "${evidence}/SHA256SUMS" | awk '{print $1}')"
