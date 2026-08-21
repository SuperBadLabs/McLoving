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
config_dir="${home}/.config/mcloving"
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
# Staging must check the copied bytes against the supplied digest source, not
# against a second measurement of the same mutable directory. A release
# directory whose contents disagree with its checksums file must be refused
# even though the directory is internally self-consistent.
mismatch_dir="${workdir}/mismatch-release"
rm -rf "${mismatch_dir}"
cp -r "${release_dir}" "${mismatch_dir}"
(cd "${mismatch_dir}" && sha256sum mcloving-controller mcloving-agent \
  mcloving-cli mcloving-identity-admin > "${workdir}/mismatch.sha256")
printf '\n' >> "${mismatch_dir}/mcloving-cli"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${home}" \
  --release-dir "${mismatch_dir}" --checksums "${workdir}/mismatch.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "staging accepted bytes that do not match the supplied checksums" >&2
  exit 1
fi

tampered="${libexec}/${second_release}/mcloving-cli"
cp "${tampered}" "${workdir}/untampered-cli"
printf '\n' >> "${tampered}"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${home}" --no-systemd \
  >/dev/null 2>&1; then
  echo "rollback accepted a modified previous release" >&2
  exit 1
fi
[[ "$(readlink "${libexec}/current")" == "${first_release}" ]] || {
  echo "refused rollback must leave the current release untouched" >&2
  exit 1
}
# Restore the release so the later gates run against an intact tree; the
# refusal above is the assertion, not a lasting state.
cp "${workdir}/untampered-cli" "${tampered}"
chmod 0755 "${tampered}"

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
  [[ "$(contract_value MCLOVING_AGENT_ID)" == "/tmp/agent id" ]] || {
    echo "partially quoted value was not concatenated: [$(contract_value MCLOVING_AGENT_ID)]" >&2
    exit 1
  }
  [[ "$(contract_value MCLOVING_TRUST_POOL)" == 'p&ss w$rd' ]] || {
    echo "literal value was altered or executed: [$(contract_value MCLOVING_TRUST_POOL)]" >&2
    exit 1
  }
)

# The guards must accept the contracts this install actually wrote. Every other
# guard assertion here is a refusal, so a regression that broke acceptance —
# an unset variable, a renamed lookup — would pass unnoticed.
"${libexec}/helpers/mcloving-env-guard" controller "${config_dir}/controller.env" >/dev/null || {
  echo "controller guard rejected the contract this install wrote" >&2
  exit 1
}
"${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" >/dev/null || {
  echo "agent guard rejected the contract this install wrote" >&2
  exit 1
}

# A file that parses partially must not be accepted. The required assignments
# come first here, so a guard that ignored the parser's status would fill its
# map, report the contract satisfied, and exit 0 on a malformed file.
partial_env="${workdir}/partial.env"
printf 'POSTGRES_USER=x\nPOSTGRES_DB=y\nPOSTGRES_PASSWORD=z\nthis line has no equals\n' \
  > "${partial_env}"
if "${libexec}/helpers/mcloving-env-guard" postgres "${partial_env}" >/dev/null 2>&1; then
  echo "guard accepted a contract whose parse failed after the required values" >&2
  exit 1
fi

# A symlink whose target is gone is drift, so the re-read must report it rather
# than fail trying to hash a missing file.
ln -s "${workdir}/definitely-absent" "${config_dir}/dangling.env"
dangling_digests="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")" || {
  echo "digest re-read failed on a dangling symlink instead of recording it" >&2
  exit 1
}
python3 - "${dangling_digests}" <<'DANGLING'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
entry = [item for item in contracts if item["path"].endswith("dangling.env")]
if not entry:
    raise SystemExit("dangling symlink missing from the re-read")
if entry[0].get("kind") != "dangling_symlink":
    raise SystemExit("dangling symlink was not recorded as such")
DANGLING
rm -f "${config_dir}/dangling.env"

# Token length is measured in bytes, as the controller measures it. A
# multi-byte token that satisfies the controller must satisfy the guard, or a
# valid contract stops a service that could have run it.
utf8_env="${workdir}/utf8-token.env"
utf8_api="$(python3 -c "print('\u00e9' * 16)")"
utf8_artifact="$(python3 -c "print('\u00fc' * 16)")"
sed -e "s|^MCLOVING_API_TOKEN=.*|MCLOVING_API_TOKEN=${utf8_api}|" \
    -e "s|^MCLOVING_ARTIFACT_AGENT_TOKEN=.*|MCLOVING_ARTIFACT_AGENT_TOKEN=${utf8_artifact}|" \
    "${config_dir}/controller.env" > "${utf8_env}"
"${libexec}/helpers/mcloving-env-guard" controller "${utf8_env}" >/dev/null || {
  echo "guard rejected a 32-byte token because it counted characters" >&2
  exit 1
}

# Two spellings of one database role are one role. Comparing URL text would
# accept them as distinct and let the controller run as the migration role.
equivalent_env="${workdir}/equivalent.env"
sed -e 's|^MCLOVING_DATABASE_URL=.*|MCLOVING_DATABASE_URL=postgres://mcloving_migration@127.0.0.1:5432/mcloving|' \
    -e 's|^MCLOVING_MIGRATION_DATABASE_URL=.*|MCLOVING_MIGRATION_DATABASE_URL=postgres://mcloving_migration@127.0.0.1/mcloving|' \
    "${config_dir}/controller.env" > "${equivalent_env}"
if "${libexec}/helpers/mcloving-env-guard" controller "${equivalent_env}" >/dev/null 2>&1; then
  echo "guard accepted two spellings of one database role as distinct" >&2
  exit 1
fi

# Only systemd's ASCII whitespace is padding. A non-breaking space is part of
# the value, so trimming it would validate a different value from the one the
# service receives.
nbsp_env="${workdir}/nbsp.env"
python3 - "${nbsp_env}" <<'NBSP'
import sys
from pathlib import Path

Path(sys.argv[1]).write_text("MCLOVING_NBSP=\u00a0value\u00a0\nMCLOVING_PLAIN=  plain  \n")
NBSP
(
  # shellcheck source=/dev/null
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  load_environment_file "${nbsp_env}"
  expected_nbsp="$(python3 -c "print('\u00a0value\u00a0')")"
  [[ "$(contract_value MCLOVING_NBSP)" == "${expected_nbsp}" ]] || {
    echo "non-ASCII whitespace was trimmed as padding" >&2
    exit 1
  }
  [[ "$(contract_value MCLOVING_PLAIN)" == "plain" ]] || {
    echo "ASCII padding was not trimmed" >&2
    exit 1
  }
)

# A contract-supplied name must not reach a helper's own control variables:
# Bash is dynamically scoped, so an assignment named `service` could otherwise
# rewrite the guard's dispatch selector and validate the wrong service.
hijack_env="${workdir}/hijack.env"
cat > "${hijack_env}" <<'HIJACK'
service=postgres
POSTGRES_USER=x
POSTGRES_DB=x
POSTGRES_PASSWORD=x
HIJACK
if "${libexec}/helpers/mcloving-env-guard" controller "${hijack_env}" >/dev/null 2>&1; then
  echo "a contract assignment hijacked the guard's service dispatch" >&2
  exit 1
fi

# Escaped trailing whitespace is part of the value; unquoted padding is not.
whitespace_env="${workdir}/whitespace.env"
printf 'MCLOVING_TRAIL=/tmp/key.pem\\ \nMCLOVING_PAD=  spaced  \n' > "${whitespace_env}"
(
  # shellcheck source=/dev/null
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  load_environment_file "${whitespace_env}"
  [[ "$(contract_value MCLOVING_TRAIL)" == "/tmp/key.pem " ]] || {
    echo "escaped trailing space was lost: [$(contract_value MCLOVING_TRAIL)]" >&2
    exit 1
  }
  [[ "$(contract_value MCLOVING_PAD)" == "spaced" ]] || {
    echo "unquoted padding was not trimmed: [$(contract_value MCLOVING_PAD)]" >&2
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
  [[ "$(contract_value MCLOVING_SPAN)" == "${expected_span}" ]] || {
    echo "multiline single-quoted value was not read: [$(contract_value MCLOVING_SPAN)]" >&2
    exit 1
  }
  [[ "$(contract_value MCLOVING_AFTER)" == "tail" ]] || {
    echo "parsing did not resume after a multiline value: [$(contract_value MCLOVING_AFTER)]" >&2
    exit 1
  }
)

# Configuration reached through a symlink is consumed by the services, so the
# drift re-read must cover it.
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

# A special filesystem node inside a walked tree must not be opened. Hashing a
# FIFO with no writer blocks forever, so CUTOVER-001 would receive no document
# at all precisely when this kind of drift is present.
mkfifo "${config_dir}/stall"
special_digests="$(timeout 60 "${libexec}/helpers/mcloving-deployed-digests" --home "${home}")" || {
  echo "digest re-read stalled or failed on a FIFO instead of recording it" >&2
  rm -f "${config_dir}/stall"
  exit 1
}
rm -f "${config_dir}/stall"
python3 - "${special_digests}" <<'SPECIAL'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
entry = [item for item in contracts if item["path"].endswith("/stall")]
if not entry:
    raise SystemExit("special node missing from the re-read")
if entry[0].get("kind") != "fifo":
    raise SystemExit(f"special node recorded as {entry[0]}")
if "sha256" in entry[0]:
    raise SystemExit("special node was digested as a regular file")
SPECIAL

# The root of a walked tree is configuration too. Repointing ~/.config/mcloving
# itself at another managed directory with identical contents must not leave
# the re-read byte-identical: that substitution redirects every contract, key,
# and certificate the services read.
before_root_swap="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
# The copy is taken before the move so the live configuration path is absent
# for as little as possible: the controller and agent started in step 6 are
# still running against it.
cp -a "${config_dir}" "${config_dir}.alias"
mv "${config_dir}" "${config_dir}.real"
ln -s "$(basename "${config_dir}").alias" "${config_dir}"
after_root_swap="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
rm -f "${config_dir}"
rm -rf "${config_dir}.alias"
mv "${config_dir}.real" "${config_dir}"
if [[ "${before_root_swap}" == "${after_root_swap}" ]]; then
  echo "a repointed configuration root left the re-read byte-identical" >&2
  exit 1
fi
python3 - "${after_root_swap}" <<'ROOT'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
entry = [item for item in contracts if item["path"] == ".config/mcloving"]
if not entry:
    raise SystemExit("symlinked configuration root missing from the re-read")
if entry[0].get("kind") != "directory_symlink":
    raise SystemExit(f"configuration root recorded as {entry[0]}")
if "symlink_target" not in entry[0]:
    raise SystemExit("configuration root recorded without its target")
ROOT

# `systemctl start` reaching the started state is not the same as a service
# that is still running: Type=exec reports success once the exec succeeds. The
# agent's health gate reads its journal and an intact journal says nothing
# about the process, so without this an upgrade over a binary that execs and
# exits reports "complete and healthy" while Restart=on-failure cycles. Driven
# against a scripted manager because this test runs no user systemd instance.
stability_shim="${workdir}/stability-shim"
mkdir -p "${stability_shim}"
cat > "${stability_shim}/systemctl" <<'SHIM'
#!/usr/bin/env bash
count="$(cat "${MCLOVING_FAKE_STATE}" 2>/dev/null || echo 0)"
count=$((count + 1))
echo "${count}" > "${MCLOVING_FAKE_STATE}"
case "${MCLOVING_FAKE_MODE}" in
  steady)
    printf 'ActiveState=active\nSubState=running\nMainPID=4242\nNRestarts=0\n' ;;
  flapping)
    printf 'ActiveState=active\nSubState=running\nMainPID=%s\nNRestarts=%s\n' \
      "$((4242 + count))" "${count}" ;;
  restarting)
    printf 'ActiveState=activating\nSubState=auto-restart\nMainPID=0\nNRestarts=3\n' ;;
  *) exit 1 ;;
esac
SHIM
chmod +x "${stability_shim}/systemctl"
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  export PATH="${stability_shim}:${PATH}"
  export MCLOVING_FAKE_STATE="${stability_shim}/count"
  export MCLOVING_FAKE_MODE=steady
  : > "${MCLOVING_FAKE_STATE}"
  require_service_stable 0 mcloving-agent.service 3 >/dev/null || {
    echo "stability check refused a service that stayed active/running" >&2
    exit 1
  }
  for mode in flapping restarting; do
    export MCLOVING_FAKE_MODE="${mode}"
    : > "${MCLOVING_FAKE_STATE}"
    if require_service_stable 0 mcloving-agent.service 3 >/dev/null 2>&1; then
      echo "stability check accepted a ${mode} service" >&2
      exit 1
    fi
  done
)

# The recovery command the upgrade path prints must actually run from where it
# is installed. Checking only that the file exists proved nothing: the helper
# resolved its shared library against the repository layout and exited before
# touching anything.
[[ -x "${libexec}/helpers/mcloving-rollback" ]] || {
  echo "rollback helper is not installed; the printed recovery command would not resolve" >&2
  exit 1
}
"${libexec}/helpers/mcloving-rollback" --home "${home}" --no-systemd >/dev/null || {
  echo "installed rollback helper is not runnable from its installed location" >&2
  exit 1
}
"${libexec}/helpers/mcloving-rollback" --home "${home}" --no-systemd >/dev/null || {
  echo "installed rollback helper is not runnable on the return swap" >&2
  exit 1
}
[[ "$(readlink "${libexec}/current")" == "${first_release}" ]] || {
  echo "paired installed rollbacks did not return to the original release" >&2
  exit 1
}

echo "deployment smoke test passed: install -> bootstrap -> submit ${build_id} -> succeeded -> digest re-read -> upgrade/rollback -> tamper refusal -> env grammar (incl. multiline) -> symlinked contract -> symlinked pki -> special node -> symlinked config root -> service stability -> installed rollback runs"
