#!/usr/bin/env bash
# End-to-end smoke test for the systemd + rootless-podman deployment lane.
# Runs without root and without a systemd user session: every invocation is
# DERIVED from the shipped unit definitions by mcloving-unit-command, so the
# test cannot drift from what the units actually declare. The only
# deviations are explicit test overrides (published port, container name,
# volume name), each recorded by the deriving tool.
#
# Proves: verified install -> postgres healthy -> db-init -> controller
# healthy -> agent probe + foreground -> CLI apply/submit -> terminal
# success -> logs -> deterministic digest re-read -> upgrade/rollback
# symlink discipline. Also proves fail-closed behavior: tampered binaries
# refuse to install and placeholder contracts refuse to pass the guard.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tools/versions.env
source "${repo_root}/tools/versions.env"

for tool in podman openssl python3 curl jq cargo sha256sum; do
  command -v "${tool}" >/dev/null || {
    echo "missing required tool: ${tool}" >&2
    exit 1
  }
done

suffix="${RANDOM}-${RANDOM}"
container_name="mcloving-smoke-postgres-${suffix}"
volume_name="mcloving-smoke-pgdata-${suffix}"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-smoke.XXXXXX")"
controller_pid=""
agent_pid=""

cleanup() {
  local status=$?
  if [[ -n "${agent_pid}" ]]; then
    kill "${agent_pid}" >/dev/null 2>&1 || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  if [[ -n "${controller_pid}" ]]; then
    kill "${controller_pid}" >/dev/null 2>&1 || true
    wait "${controller_pid}" 2>/dev/null || true
  fi
  podman rm --force "${container_name}" >/dev/null 2>&1 || true
  podman volume rm --force "${volume_name}" >/dev/null 2>&1 || true
  if [[ ${status} -ne 0 ]]; then
    echo "smoke test FAILED; logs preserved under ${workdir}" >&2
    tail -n 40 "${workdir}"/logs/*.log 2>/dev/null || true
  else
    rm -rf "${workdir}"
  fi
  exit "${status}"
}
trap cleanup EXIT

echo "== [0/9] pinned-digest drift guard"
quadlet_image="$(sed -n 's/^Image=//p' "${repo_root}/deploy/podman/mcloving-postgres.container")"
if [[ "${quadlet_image}" != "${MCLOVING_POSTGRES_IMAGE}" ]]; then
  echo "quadlet image ${quadlet_image} drifted from tools/versions.env ${MCLOVING_POSTGRES_IMAGE}" >&2
  exit 1
fi

echo "== [1/9] build deployable binaries"
(cd "${repo_root}" && cargo build --locked \
  -p mcloving-controller -p mcloving-agent -p mcloving-cli)

release_dir="${workdir}/release"
mkdir -p "${release_dir}" "${workdir}/logs"
for binary in mcloving-controller mcloving-agent mcloving-cli mcloving-identity-admin; do
  cp "${repo_root}/target/debug/${binary}" "${release_dir}/${binary}"
done
(cd "${release_dir}" && sha256sum mcloving-controller mcloving-agent \
  mcloving-cli mcloving-identity-admin > "${workdir}/checksums.sha256")

home="${workdir}/home"
mkdir -p "${home}"

echo "== [2/9] fail-closed install: tampered binary must be refused"
tampered_dir="${workdir}/tampered"
cp -r "${release_dir}" "${tampered_dir}"
printf 'x' >> "${tampered_dir}/mcloving-agent"
if "${repo_root}/deploy/bin/mcloving-install" --home "${home}" \
  --release-dir "${tampered_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install accepted a tampered binary; digest verification is broken" >&2
  exit 1
fi
if [[ -e "${home}/.local/libexec/mcloving/current" ]]; then
  echo "failed install left a current release behind" >&2
  exit 1
fi

echo "== [3/9] verified install"
"${repo_root}/deploy/bin/mcloving-install" --home "${home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd
libexec="${home}/.local/libexec/mcloving"
config="${home}/.config/mcloving"
unit_command="${libexec}/helpers/mcloving-unit-command"

echo "== [4/9] fail-closed contracts: placeholder contract must be refused"
if "${libexec}/helpers/mcloving-env-guard" controller \
  "${config}/controller.env" >/dev/null 2>&1; then
  echo "env guard accepted a placeholder contract" >&2
  exit 1
fi

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}
pg_port="$(free_port)"
api_port="$(free_port)"
agent_port="$(free_port)"

organization_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
project_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
pipeline_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
superuser_password="smoke-superuser-${suffix}"
tenant_password="smoke-tenant-${suffix}"
api_token="smoke-api-bearer-token-32-bytes-minimum-${suffix}"
artifact_token="smoke-artifact-agent-token-32-bytes-${suffix}"
agent_id="smoke-agent"

echo "== [5/9] mTLS material and environment contracts"
pki="${config}/pki"
openssl req -new -newkey rsa:2048 -nodes -x509 -days 1 \
  -subj "/CN=mcloving-smoke-ca" \
  -keyout "${pki}/ca-key.pem" -out "${pki}/ca.pem" >/dev/null 2>&1
printf 'subjectAltName=DNS:controller.internal,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' \
  > "${pki}/server.ext"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=controller.internal" \
  -keyout "${pki}/controller-server-key.pem" -out "${pki}/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "${pki}/server.csr" -CA "${pki}/ca.pem" \
  -CAkey "${pki}/ca-key.pem" -CAcreateserial -extfile "${pki}/server.ext" \
  -out "${pki}/controller-server.pem" >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > "${pki}/agent.ext"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${agent_id}" \
  -keyout "${pki}/agent-key.pem" -out "${pki}/agent.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "${pki}/agent.csr" -CA "${pki}/ca.pem" \
  -CAkey "${pki}/ca-key.pem" -CAcreateserial -extfile "${pki}/agent.ext" \
  -out "${pki}/agent.pem" >/dev/null 2>&1
cp "${pki}/ca.pem" "${pki}/agent-ca.pem"
cp "${pki}/ca.pem" "${pki}/controller-ca.pem"
openssl x509 -in "${pki}/agent.pem" -outform DER -out "${pki}/agent.der" >/dev/null 2>&1
agent_cert_sha256="$(sha256sum "${pki}/agent.der" | awk '{print $1}')"
printf '%s %s trusted-linux %s\n' "${agent_cert_sha256}" "${agent_id}" \
  "${organization_id}" > "${config}/agent-identity-bindings.txt"

# Fill the installed placeholder contracts. The examples are the contract:
# only placeholder values, endpoints, and the example home prefix change.
fill_contract() {
  local file="$1"
  sed -i \
    -e "s#/home/mcloving#${home}#g" \
    -e "s/127\.0\.0\.1:5432/127.0.0.1:${pg_port}/g" \
    -e "s/127\.0\.0\.1:8080/127.0.0.1:${api_port}/g" \
    -e "s/127\.0\.0\.1:8443/127.0.0.1:${agent_port}/g" \
    -e "s/__SET_ME_POSTGRES_SUPERUSER_PASSWORD__/${superuser_password}/g" \
    -e "s/__SET_ME_TENANT_PASSWORD__/${tenant_password}/g" \
    -e "s/__SET_ME_API_BEARER_TOKEN_MINIMUM_32_BYTES__/${api_token}/g" \
    -e "s/__SET_ME_DISTINCT_ARTIFACT_TOKEN_MINIMUM_32_BYTES__/${artifact_token}/g" \
    -e "s/__SET_ME_ORGANIZATION_UUID__/${organization_id}/g" \
    -e "s/__SET_ME_ORGANIZATION_SLUG__/smoke-org/g" \
    -e "s/__SET_ME_PROJECT_UUID__/${project_id}/g" \
    -e "s/__SET_ME_PROJECT_SLUG__/smoke-project/g" \
    -e "s/__SET_ME_AGENT_ID__/${agent_id}/g" \
    -e "s/mcloving-postgres$/${container_name}/" \
    "${file}"
  if grep -Eq '__SET_ME_[A-Z0-9_]+__' "${file}"; then
    echo "contract ${file} still carries placeholders" >&2
    exit 1
  fi
}
for contract in postgres db-init controller agent; do
  fill_contract "${config}/${contract}.env"
done

# Mirror what StateDirectory= creates for the real units.
mkdir -p "${home}/.local/state/mcloving-controller" \
  "${home}/.local/state/mcloving-agent/workspace"

run_with_env() { # ENV_FILE COMMAND...
  local env_file="$1"
  shift
  (
    set -a
    # shellcheck disable=SC1090
    source "${env_file}"
    set +a
    exec "$@"
  )
}

derived_argv() { # OUT_ARRAY_NAME JSON_FILE JQ_PATH
  # shellcheck disable=SC2034 # assigned through the nameref
  local -n out_ref="$1"
  # shellcheck disable=SC2034 # assigned through the nameref
  mapfile -d '' -t out_ref < <(jq -j "$3 | join(\"\\u0000\")" "$2")
}

echo "== [6/9] postgres (derived from quadlet) -> db-init -> controller -> agent"
"${unit_command}" "${home}/.config/containers/systemd/mcloving-postgres.container" \
  --home "${home}" --publish-override "127.0.0.1:${pg_port}" \
  --name-override "${container_name}" --volume-override "${volume_name}" \
  > "${workdir}/postgres.derived.json"
pre_argv=()
derived_argv pre_argv "${workdir}/postgres.derived.json" '.exec_start_pre[0]'
"${pre_argv[@]}"
postgres_argv=()
derived_argv postgres_argv "${workdir}/postgres.derived.json" '.exec_start'
"${postgres_argv[@]}" >/dev/null
health_argv=()
derived_argv health_argv "${workdir}/postgres.derived.json" '.health_cmd'
for _ in $(seq 1 120); do
  if podman exec "${container_name}" "${health_argv[@]}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
podman exec "${container_name}" "${health_argv[@]}" >/dev/null

"${unit_command}" "${home}/.config/systemd/user/mcloving-db-init.service" \
  --home "${home}" > "${workdir}/db-init.derived.json"
db_init_env="$(jq -r '.environment_files[0]' "${workdir}/db-init.derived.json")"
db_init_pre=()
derived_argv db_init_pre "${workdir}/db-init.derived.json" '.exec_start_pre[0]'
run_with_env "${db_init_env}" "${db_init_pre[@]}"
db_init_argv=()
derived_argv db_init_argv "${workdir}/db-init.derived.json" '.exec_start'
run_with_env "${db_init_env}" "${db_init_argv[@]}" | tee "${workdir}/logs/db-init.log"
# The bootstrap must be idempotent: run it twice.
run_with_env "${db_init_env}" "${db_init_argv[@]}" >> "${workdir}/logs/db-init.log"

"${unit_command}" "${home}/.config/systemd/user/mcloving-controller.service" \
  --home "${home}" > "${workdir}/controller.derived.json"
controller_env="$(jq -r '.environment_files[0]' "${workdir}/controller.derived.json")"
controller_pre=()
derived_argv controller_pre "${workdir}/controller.derived.json" '.exec_start_pre[0]'
run_with_env "${controller_env}" "${controller_pre[@]}"
controller_argv=()
derived_argv controller_argv "${workdir}/controller.derived.json" '.exec_start'
run_with_env "${controller_env}" "${controller_argv[@]}" \
  > "${workdir}/logs/controller.log" 2>&1 &
controller_pid=$!
controller_post=()
derived_argv controller_post "${workdir}/controller.derived.json" '.exec_start_post[0]'
run_with_env "${controller_env}" "${controller_post[@]}"

"${unit_command}" "${home}/.config/systemd/user/mcloving-agent.service" \
  --home "${home}" > "${workdir}/agent.derived.json"
agent_env="$(jq -r '.environment_files[0]' "${workdir}/agent.derived.json")"
agent_guard=()
derived_argv agent_guard "${workdir}/agent.derived.json" '.exec_start_pre[0]'
run_with_env "${agent_env}" "${agent_guard[@]}"
agent_probe=()
derived_argv agent_probe "${workdir}/agent.derived.json" '.exec_start_pre[1]'
run_with_env "${agent_env}" "${agent_probe[@]}" | tee "${workdir}/logs/agent-probe.log"
agent_argv=()
derived_argv agent_argv "${workdir}/agent.derived.json" '.exec_start'
run_with_env "${agent_env}" "${agent_argv[@]}" \
  > "${workdir}/logs/agent.log" 2>&1 &
agent_pid=$!

echo "== [7/9] submit one build through the CLI and require terminal success"
marker="deployment-smoke-ran-${suffix}"
cat > "${workdir}/pipeline.yaml" <<PIPELINE
version: 1
name: deployment-smoke
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf '${marker}\\n'"]
          timeout_seconds: 30
PIPELINE
cli="${libexec}/current/mcloving-cli"
export MCLOVING_URL="http://127.0.0.1:${api_port}"
export MCLOVING_API_TOKEN="${api_token}"
export MCLOVING_ORGANIZATION_ID="${organization_id}"
export MCLOVING_PROJECT_ID="${project_id}"
"${cli}" --output json apply "${pipeline_id}" --slug deployment-smoke \
  --expected-revision 0 "${workdir}/pipeline.yaml" \
  > "${workdir}/logs/apply.json"
"${cli}" --output json submit "${pipeline_id}" \
  --idempotency-key "smoke-${suffix}" \
  --trust-pool trusted-linux --platform linux \
  > "${workdir}/logs/submit.json"
build_id="$(jq -r '.build_id' "${workdir}/logs/submit.json")"
[[ "${build_id}" != "null" && -n "${build_id}" ]] || {
  echo "submission returned no build id" >&2
  exit 1
}
echo "submitted build ${build_id}"

status=""
for _ in $(seq 1 120); do
  status="$("${cli}" --output json status "${build_id}" | jq -r '.status')"
  case "${status}" in
    succeeded | failed | aborted) break ;;
  esac
  sleep 0.5
done
echo "terminal status: ${status}"
[[ "${status}" == "succeeded" ]] || {
  echo "build ${build_id} did not succeed (status: ${status})" >&2
  "${cli}" --output json status "${build_id}" >&2 || true
  "${cli}" --output json logs "${build_id}" >&2 || true
  exit 1
}
"${cli}" --output json logs "${build_id}" > "${workdir}/logs/build-logs.json"
grep -q "${marker}" "${workdir}/logs/build-logs.json" || {
  echo "build logs do not contain the smoke marker" >&2
  exit 1
}
lease_owner="$("${cli}" --output json status "${build_id}" | jq -r '.lease_owner')"
[[ "${lease_owner}" == "${agent_id}" ]] || {
  echo "build was not executed by the remote agent (lease owner: ${lease_owner})" >&2
  exit 1
}

echo "== [8/9] deterministic digest re-read"
"${libexec}/helpers/mcloving-deployed-digests" --home "${home}" \
  > "${workdir}/digests-1.json"
"${libexec}/helpers/mcloving-deployed-digests" --home "${home}" \
  > "${workdir}/digests-2.json"
cmp "${workdir}/digests-1.json" "${workdir}/digests-2.json" || {
  echo "digest re-read output is not deterministic" >&2
  exit 1
}
jq -e '
  .schema == "mcloving.deployed-digests/v1"
  and (.current_release | startswith("releases/"))
  and (.releases | length >= 4)
  and (.units | length == 5)
  and (.environment_contracts | length >= 5)
' "${workdir}/digests-1.json" >/dev/null || {
  echo "digest document is missing required coverage" >&2
  exit 1
}
echo "digest re-read summary:"
jq '{schema, current_release, previous_release,
     releases: (.releases | length), units: (.units | length),
     environment_contracts: (.environment_contracts | length)}' \
  "${workdir}/digests-1.json"

echo "== [9/9] upgrade and rollback symlink discipline (--no-systemd)"
release2_dir="${workdir}/release2"
cp -r "${release_dir}" "${release2_dir}"
printf '\n' >> "${release2_dir}/mcloving-cli"
(cd "${release2_dir}" && sha256sum mcloving-controller mcloving-agent \
  mcloving-cli mcloving-identity-admin > "${workdir}/checksums2.sha256")
first_release="$(readlink "${libexec}/current")"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd
second_release="$(readlink "${libexec}/current")"
[[ "${second_release}" != "${first_release}" ]] || {
  echo "upgrade did not change the current release" >&2
  exit 1
}
[[ "$(readlink "${libexec}/previous")" == "${first_release}" ]] || {
  echo "upgrade did not preserve the previous release" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${home}" --no-systemd
[[ "$(readlink "${libexec}/current")" == "${first_release}" ]] || {
  echo "rollback did not restore the first release" >&2
  exit 1
}
"${libexec}/current/mcloving-cli" --help >/dev/null

# A staged release is writable by the service user, so rollback must recompute
# digests rather than trust that a present, executable binary is the one that
# was verified at installation.
printf '\n' >> "${libexec}/${second_release}/mcloving-cli"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${home}" --no-systemd \
  >/dev/null 2>&1; then
  echo "rollback accepted a modified previous release" >&2
  exit 1
fi
[[ "$(readlink "${libexec}/current")" == "${first_release}" ]] || {
  echo "refused rollback must leave the current release untouched" >&2
  exit 1
}

# systemd's environment grammar, not Bash's: a partially quoted value is one
# value, and a value that is literal to systemd must not be executed.
guard_env="${workdir}/grammar.env"
cat > "${guard_env}" <<'GRAMMAR'
MCLOVING_CONTROLLER_ENDPOINT=https://controller.example.test:8443
MCLOVING_AGENT_ID=/tmp/'agent id'
MCLOVING_TRUST_POOL=p&ss w$rd
GRAMMAR
(
  # shellcheck source=/dev/null
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  load_environment_file "${guard_env}"
  [[ "${MCLOVING_AGENT_ID}" == "/tmp/agent id" ]] || {
    echo "partially quoted value was not concatenated: [${MCLOVING_AGENT_ID}]" >&2
    exit 1
  }
  [[ "${MCLOVING_TRUST_POOL}" == 'p&ss w$rd' ]] || {
    echo "literal value was altered or executed: [${MCLOVING_TRUST_POOL}]" >&2
    exit 1
  }
)

# A single-quoted value may span physical lines; systemd loads it, so the
# guard must too rather than refusing a valid contract at ExecStartPre.
multiline_env="${workdir}/multiline.env"
printf "MCLOVING_SPAN='line one\nline two'\nMCLOVING_AFTER=tail\n" > "${multiline_env}"
(
  # shellcheck source=/dev/null
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  load_environment_file "${multiline_env}"
  expected_span="$(printf 'line one\nline two')"
  [[ "${MCLOVING_SPAN}" == "${expected_span}" ]] || {
    echo "multiline single-quoted value was not read: [${MCLOVING_SPAN}]" >&2
    exit 1
  }
  [[ "${MCLOVING_AFTER}" == "tail" ]] || {
    echo "parsing did not resume after a multiline value: [${MCLOVING_AFTER}]" >&2
    exit 1
  }
)

# Configuration reached through a symlink is consumed by the services, so the
# drift re-read must cover it.
config_dir="${home}/.config/mcloving"
ln -s "${config_dir}/controller.env" "${config_dir}/controller-linked.env"
linked_digests="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${linked_digests}" <<'LINKED'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
linked = [entry for entry in contracts if entry["path"].endswith("controller-linked.env")]
if not linked:
    raise SystemExit("symlinked contract missing from the deployed-digest re-read")
if "symlink_target" not in linked[0]:
    raise SystemExit("symlinked contract recorded without its target")
LINKED
rm -f "${config_dir}/controller-linked.env"

# A symlinked configuration *directory* is traversed too: rglob would not
# descend it, so every key inside would be consumed by the services and absent
# from the re-read.
mkdir -p "${workdir}/managed-pki"
cp "${config_dir}/pki/"* "${workdir}/managed-pki/" 2>/dev/null || true
mv "${config_dir}/pki" "${config_dir}/pki.real"
ln -s "${workdir}/managed-pki" "${config_dir}/pki"
linked_dir_digests="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${linked_dir_digests}" <<'LINKEDDIR'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
inside = [entry for entry in contracts if "/pki/" in entry["path"]]
if not inside:
    raise SystemExit("symlinked configuration directory was not traversed")
LINKEDDIR
rm -f "${config_dir}/pki"
mv "${config_dir}/pki.real" "${config_dir}/pki"

# The recovery command the upgrade path prints must exist on the host.
[[ -x "${libexec}/helpers/mcloving-rollback" ]] || {
  echo "rollback helper is not installed; the printed recovery command would not resolve" >&2
  exit 1
}

echo "deployment smoke test passed: install -> bootstrap -> submit ${build_id} -> succeeded -> digest re-read -> upgrade/rollback -> tamper refusal -> env grammar (incl. multiline) -> symlinked contract -> symlinked pki -> rollback helper"
