#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091 # resolved from the repository root at runtime
source "${repo_root}/tools/versions.env"

if [[ "$(hostname -s)" != "mario" ]]; then
  echo "mario-alpha-demo must run on the Mario host" >&2
  exit 1
fi
for command in podman python3 jq curl git sha256sum; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required command is unavailable: ${command}" >&2
    exit 1
  fi
done
if ! git -C "${repo_root}" diff --quiet ||
  ! git -C "${repo_root}" diff --cached --quiet; then
  echo "mario-alpha-demo requires a clean source checkout" >&2
  exit 1
fi

umask 077
run_id="alpha001-$(date -u +%Y%m%dT%H%M%SZ)-$(python3 - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
)"
run_root="${MCLOVING_ALPHA_RUN_ROOT:-${HOME}/.local/share/mcloving/alpha-runs}"
install -d -m 0700 "${run_root}"
run_dir="${run_root}/${run_id}"
mkdir "${run_dir}"
chmod 0700 "${run_dir}"
runtime_dir="${run_dir}/runtime"
mkdir "${runtime_dir}"
chmod 0700 "${runtime_dir}"

reserve_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

postgres_port="$(reserve_port)"
controller_port="$(reserve_port)"
container_name="mcloving-${run_id}"
source_head="$(git -C "${repo_root}" rev-parse HEAD)"
organization_id="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
project_id="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
pipeline_id="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
api_token="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
artifact_agent_token="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
pipeline="${repo_root}/examples/mario-alpha.pipeline.yaml"
pipeline_sha256="$(sha256sum "${pipeline}" | cut -d ' ' -f 1)"
controller_pid=""
services_stopped=false

stop_controller() {
  if [[ -n "${controller_pid}" ]] && kill -0 "${controller_pid}" 2>/dev/null; then
    kill "${controller_pid}" 2>/dev/null || true
    wait "${controller_pid}" 2>/dev/null || true
  fi
  controller_pid=""
}

stop_services() {
  if [[ "${services_stopped}" == true ]]; then
    return
  fi
  stop_controller
  podman logs "${container_name}" >"${run_dir}/postgres.log" 2>&1 || true
  podman rm --force "${container_name}" >/dev/null 2>&1 || true
  services_stopped=true
}

record_failure() {
  local status=$?
  stop_services
  if [[ ! -e "${run_dir}/result.json" ]]; then
    jq -n \
      --arg run_id "${run_id}" \
      --arg source_head "${source_head}" \
      --argjson exit_code "${status}" \
      '{schema:"mcloving.mario-alpha-result/v1", run_id:$run_id, source_head:$source_head, alpha_demo_complete:false, exit_code:$exit_code}' \
      >"${run_dir}/result.json"
  fi
  echo "Mario alpha demo failed; evidence retained at ${run_dir}" >&2
  exit "${status}"
}
trap record_failure EXIT

target_root="${repo_root}/target/alpha-demo"
if [[ "${MCLOVING_ALPHA_SKIP_BUILD:-0}" != "1" ]]; then
  install -d -m 0700 "${target_root}" "${repo_root}/target/alpha-cargo-home"
  podman run --rm \
    --network host \
    --volume "${repo_root}:/work:Z" \
    --workdir /work \
    --env CARGO_HOME=/work/target/alpha-cargo-home \
    --env CARGO_TARGET_DIR=/work/target/alpha-demo \
    "${MCLOVING_RUST_IMAGE}" \
    cargo build --locked --release \
      -p mcloving-controller \
      -p mcloving-cli \
      --bin mcloving-controller \
      --bin mcloving-identity-admin \
      --bin mcloving \
      >"${run_dir}/build.log" 2>&1
fi

controller_bin="${target_root}/release/mcloving-controller"
admin_bin="${target_root}/release/mcloving-identity-admin"
cli_bin="${target_root}/release/mcloving"
for binary in "${controller_bin}" "${admin_bin}" "${cli_bin}"; do
  if [[ ! -x "${binary}" ]]; then
    echo "required alpha binary is missing: ${binary}" >&2
    exit 1
  fi
done
sha256sum "${controller_bin}" "${admin_bin}" "${cli_bin}" \
  >"${run_dir}/binaries.sha256"

podman run --detach --rm \
  --name "${container_name}" \
  --publish "127.0.0.1:${postgres_port}:5432" \
  --env POSTGRES_USER=mcloving \
  --env POSTGRES_HOST_AUTH_METHOD=trust \
  --env POSTGRES_DB=mcloving \
  "${MCLOVING_POSTGRES_IMAGE}" >/dev/null
for _ in $(seq 1 120); do
  if podman exec "${container_name}" pg_isready \
    --username mcloving --dbname mcloving >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
podman exec "${container_name}" pg_isready \
  --username mcloving --dbname mcloving >/dev/null

migration_url="postgres://mcloving@127.0.0.1:${postgres_port}/mcloving"
runtime_url="postgres://mcloving_tenant@127.0.0.1:${postgres_port}/mcloving"
MCLOVING_MIGRATION_DATABASE_URL="${migration_url}" \
  "${admin_bin}" migrate >"${run_dir}/migration.txt"
podman exec "${container_name}" psql \
  --username mcloving --dbname mcloving \
  --set ON_ERROR_STOP=1 \
  --command "ALTER ROLE mcloving_tenant LOGIN" \
  >"${run_dir}/runtime-role.txt"
MCLOVING_MIGRATION_DATABASE_URL="${migration_url}" \
  "${admin_bin}" create-project \
  --organization "${organization_id}" \
  --organization-slug "mario-alpha-${run_id}" \
  --project "${project_id}" \
  --project-slug alpha \
  >"${run_dir}/project.txt"

export MCLOVING_URL="http://127.0.0.1:${controller_port}"
export MCLOVING_API_TOKEN="${api_token}"
export MCLOVING_ORGANIZATION_ID="${organization_id}"
export MCLOVING_PROJECT_ID="${project_id}"

start_controller() {
  local log_path=$1
  MCLOVING_MIGRATION_DATABASE_URL="${migration_url}" \
  MCLOVING_DATABASE_URL="${runtime_url}" \
  MCLOVING_API_TOKEN="${api_token}" \
  MCLOVING_API_TOKEN_GENERATION=1 \
  MCLOVING_ARTIFACT_AGENT_TOKEN="${artifact_agent_token}" \
  MCLOVING_LISTEN="127.0.0.1:${controller_port}" \
  MCLOVING_ORGANIZATION_ID="${organization_id}" \
  MCLOVING_AGENT_ID=mario-alpha-embedded \
  MCLOVING_AGENT_CAPABILITIES=platform:linux \
  MCLOVING_AGENT_TRUST_POOL=trusted-linux \
  MCLOVING_LEASE_SECONDS=5 \
  MCLOVING_POLL_MILLISECONDS=25 \
  MCLOVING_CANCELLATION_POLL_MILLISECONDS=50 \
  MCLOVING_TERMINATION_GRACE_MILLISECONDS=250 \
  MCLOVING_SESSION_EPOCH=1 \
  MCLOVING_WORKSPACE_ROOT="${runtime_dir}/workspace" \
  MCLOVING_AGENT_JOURNAL="${runtime_dir}/agent.sqlite3" \
  MCLOVING_OBJECT_ROOT="${runtime_dir}/objects" \
  "${controller_bin}" >"${log_path}" 2>&1 &
  controller_pid=$!
  for _ in $(seq 1 240); do
    if "${cli_bin}" --output json audit --limit 1 >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "${controller_pid}" 2>/dev/null; then
      echo "controller exited during startup" >&2
      return 1
    fi
    sleep 0.25
  done
  echo "controller did not become ready" >&2
  return 1
}

start_controller "${run_dir}/controller-first.log"
curl --fail --silent --show-error "${MCLOVING_URL}/" \
  >"${run_dir}/ui-index.html"
curl --fail --silent --show-error "${MCLOVING_URL}/app.js" \
  >"${run_dir}/ui-app.js"
curl --fail --silent --show-error "${MCLOVING_URL}/openapi.json" \
  >"${run_dir}/openapi.json"
grep -Fq "McLoving" "${run_dir}/ui-index.html"

"${cli_bin}" --output json validate "${pipeline}" \
  >"${run_dir}/validate.json"
"${cli_bin}" --output json plan "${pipeline}" \
  >"${run_dir}/plan.json"
"${cli_bin}" --output json apply "${pipeline_id}" \
  --slug mario-alpha \
  --expected-revision 0 \
  "${pipeline}" \
  >"${run_dir}/apply.json"
"${cli_bin}" --output json pipeline-state "${pipeline_id}" \
  >"${run_dir}/pipeline-state.json"
"${cli_bin}" --output json submit "${pipeline_id}" \
  --idempotency-key "${run_id}" \
  --platform linux \
  --trust-pool trusted-linux \
  >"${run_dir}/submit.json"
build_id="$(jq -er '.build_id' "${run_dir}/submit.json")"
"${cli_bin}" --output json watch "${build_id}" \
  --interval-ms 100 \
  --max-polls 300 \
  >"${run_dir}/watch.json"
jq -e '
  .state == "terminal" and
  .last_status.status == "succeeded" and
  ([.logs[].text // ""] | join("") | contains("mcloving-alpha:mario:complete"))
' "${run_dir}/watch.json" >/dev/null
"${cli_bin}" --output json status "${build_id}" >"${run_dir}/status.json"
"${cli_bin}" --output json graph "${build_id}" >"${run_dir}/graph.json"
"${cli_bin}" --output json logs "${build_id}" >"${run_dir}/logs.json"
"${cli_bin}" --output json audit --limit 1000 >"${run_dir}/audit.json"
"${cli_bin}" --output json pipelines --limit 100 >"${run_dir}/pipelines.json"
"${cli_bin}" --output json builds --limit 100 >"${run_dir}/builds.json"
"${cli_bin}" --output json artifacts "${build_id}" >"${run_dir}/artifacts.json"
"${cli_bin}" --output json tests "${build_id}" >"${run_dir}/tests.json"
jq -e '.status == "succeeded"' "${run_dir}/status.json" >/dev/null

stop_controller
start_controller "${run_dir}/controller-restart.log"
"${cli_bin}" --output json status "${build_id}" \
  >"${run_dir}/restart-status.json"
"${cli_bin}" --output json logs "${build_id}" \
  >"${run_dir}/restart-logs.json"
"${cli_bin}" --output json graph "${build_id}" \
  >"${run_dir}/restart-graph.json"
"${cli_bin}" --output json submit "${pipeline_id}" \
  --idempotency-key "${run_id}" \
  --platform linux \
  --trust-pool trusted-linux \
  >"${run_dir}/restart-resubmit.json"
jq -e --arg build_id "${build_id}" \
  '.status == "succeeded" and .build_id == $build_id' \
  "${run_dir}/restart-status.json" >/dev/null
jq -e --arg build_id "${build_id}" '.build_id == $build_id' \
  "${run_dir}/restart-resubmit.json" >/dev/null
jq -e '
  ([.items[].text // ""] | join("") |
    ([scan("mcloving-alpha:mario:complete")] | length) == 1)
' "${run_dir}/restart-logs.json" >/dev/null

stop_services
manifest_tmp="$(mktemp)"
jq -n \
  --arg run_id "${run_id}" \
  --arg source_head "${source_head}" \
  --arg host "$(hostname -s)" \
  --arg organization_id "${organization_id}" \
  --arg project_id "${project_id}" \
  --arg pipeline_id "${pipeline_id}" \
  --arg pipeline_sha256 "${pipeline_sha256}" \
  --arg build_id "${build_id}" \
  '{
    schema:"mcloving.mario-alpha-result/v1",
    run_id:$run_id,
    source_head:$source_head,
    host:$host,
    organization_id:$organization_id,
    project_id:$project_id,
    pipeline_id:$pipeline_id,
    pipeline_sha256:$pipeline_sha256,
    build_id:$build_id,
    terminal_status:"succeeded",
    controller_restart_verified:true,
    idempotent_resubmission_verified:true,
    duplicate_completion_markers:0,
    production_effects:0,
    alpha_demo_complete:true
  }' >"${run_dir}/result.json"
(
  cd "${run_dir}"
  find . -type f ! -name MANIFEST.sha256 -print0 |
    sort -z |
    xargs -0 sha256sum >"${manifest_tmp}"
)
mv "${manifest_tmp}" "${run_dir}/MANIFEST.sha256"
chmod -R go-rwx "${run_dir}"
trap - EXIT
echo "Mario alpha demo complete"
echo "build_id=${build_id}"
echo "evidence=${run_dir}"
