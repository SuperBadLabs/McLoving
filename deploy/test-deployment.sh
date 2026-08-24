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

for tool in podman openssl python3 curl jq cargo sha256sum flock; do
  command -v "${tool}" >/dev/null || {
    echo "missing required tool: ${tool}" >&2
    exit 1
  }
done

# The suite is hermetic against the invoking environment's XDG settings.
# GitHub's runners export XDG_CONFIG_HOME, and an inherited value would --
# and in CI did -- steer the installer's derived unit roots away from the
# tree the harness reads. The inherited values are captured for the
# preserved-workdir artifact (so this class of environmental question
# answers itself), then cleared; the XDG gates set the variables
# explicitly, per command, in subshell-confined prefixes.
invoking_xdg_environment="$(env | grep -E '^XDG_' || true)"
unset XDG_CONFIG_HOME XDG_STATE_HOME XDG_CACHE_HOME

# The test's own directories must not depend on the invoking shell's umask.
# An operator umask of 002 -- the Debian/Ubuntu user-private-group default --
# would create every test home group-writable, and the installer's ancestor
# refusal would then fire for reasons unrelated to what each gate asserts.
# Gates that need a hostile umask set one explicitly in a subshell.
umask 022

suffix="${RANDOM}-${RANDOM}"
container_name="mcloving-smoke-postgres-${suffix}"
volume_name="mcloving-smoke-pgdata-${suffix}"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-smoke.XXXXXX")"
controller_pid=""
agent_pid=""

cleanup() {
  local status=$?
  local preserved
  if [[ -n "${agent_pid}" ]]; then
    kill "${agent_pid}" >/dev/null 2>&1 || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  if [[ -n "${controller_pid}" ]]; then
    kill "${controller_pid}" >/dev/null 2>&1 || true
    wait "${controller_pid}" 2>/dev/null || true
  fi
  if [[ ${status} -ne 0 ]]; then
    # Capture the container's own account of the failure BEFORE the forced
    # removal below destroys it. Without this, the single most informative
    # log on a runner -- what PostgreSQL itself printed -- exists only inside
    # a container this trap is about to delete, and the preserved ${workdir}
    # never held it. A failure before step [1/9] predates the logs
    # directory, so the trap makes it rather than losing its captures.
    mkdir -p "${workdir}/logs" 2>/dev/null || true
    {
      echo "== podman ps --all"
      podman ps --all 2>&1 || true
      echo "== podman inspect ${container_name}"
      podman inspect "${container_name}" \
        --format 'status={{.State.Status}} exit_code={{.State.ExitCode}} oom_killed={{.State.OOMKilled}} error={{.State.Error}}' 2>&1 || true
      echo "== podman logs ${container_name}"
      podman logs "${container_name}" 2>&1 || true
    } > "${workdir}/logs/postgres-container-state.log" 2>&1 || true
    podman info > "${workdir}/logs/podman-info.log" 2>&1 || true
  fi
  podman rm --force "${container_name}" >/dev/null 2>&1 || true
  podman volume rm --force "${volume_name}" >/dev/null 2>&1 || true
  if [[ ${status} -ne 0 ]]; then
    # Everything below goes to stderr, in full. A CI runner's /tmp does not
    # survive the job, so "logs preserved under ${workdir}" names files
    # nobody can read unless they are printed here and uploaded as a job
    # artifact by the workflow.
    {
      echo "smoke test FAILED with status ${status}; logs preserved under ${workdir}"
      for preserved in "${workdir}"/logs/*; do
        [[ -f "${preserved}" ]] || continue
        printf '===> %s <===\n' "${preserved}"
        cat "${preserved}" || true
      done
    } >&2
  else
    rm -rf "${workdir}"
  fi
  exit "${status}"
}
trap cleanup EXIT

# `local` outside a function aborts under `set -e`, and the helpers put their
# service logic in a top-level `case` block where that is easy to do by
# accident -- it has happened twice in this lane, each time rejecting every
# valid contract at ExecStartPre. shellcheck does not flag it, so this does.
python3 - "${repo_root}" <<'LOCALSCOPE'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]) / "deploy" / "bin"
opens = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{")
failures = []
for script in sorted(root.iterdir()):
    if not script.is_file():
        continue
    depth = 0
    for number, line in enumerate(script.read_text().splitlines(), 1):
        code = line.split("#", 1)[0]
        if depth == 0 and opens.match(code.strip()):
            depth = 1
            continue
        if depth:
            depth += code.count("{") - code.count("}")
            continue
        if re.match(r"\s*local\s", code):
            failures.append(f"{script.name}:{number}: `local` outside a function")
for failure in failures:
    print(failure, file=sys.stderr)
raise SystemExit(1 if failures else 0)
LOCALSCOPE

# Every MCLOVING_* environment variable the shipped binaries read must be
# either classified in deployment_contract_path_variables (the guard's and
# the inventory's one authority) or excluded HERE with a reviewed reason --
# so a path-bearing variable added in Rust cannot ship unclassified.
python3 - "${repo_root}" <<'CLASSCOVER'
import pathlib
import re
import subprocess
import sys

repo_root = pathlib.Path(sys.argv[1])
swept = set()
for base in ["bins/agent/src", "bins/controller/src", "bins/cli/src"]:
    for source in (repo_root / base).rglob("*.rs"):
        swept |= set(re.findall(r"MCLOVING_[A-Z0-9_]+", source.read_text()))
if not swept or "MCLOVING_CONTROLLER_CA_PATH" not in swept:
    raise SystemExit("the variable sweep found nothing plausible; the scan went blind")
classified = set()
for service in ["postgres", "db-init", "controller", "agent"]:
    listing = subprocess.run(
        ["bash", "-ec",
         'source "$0" && deployment_contract_path_variables "$1"',
         str(repo_root / "deploy/bin/mcloving-deploy-lib.sh"), service],
        capture_output=True, text=True, check=True,
    ).stdout
    # "CLASS LINK-POLICY VARIABLE" -- the variable is the third field.
    classified |= {line.split()[2] for line in listing.splitlines() if line}
if not classified:
    raise SystemExit("the classification enumeration is empty; the authority went blind")
# Reviewed exclusions: value-typed variables that carry no filesystem path.
excluded_patterns = [
    r"^MCLOVING_OIDC_",         # OIDC endpoints, URLs, TTLs, and flags
    r"^MCLOVING_TEST_",         # test-only toggles, never in shipped contracts
    r"_FOR_TESTS$",             # test-only toggles
    r"(_SECONDS|_MILLISECONDS|_HOURS|_EPOCH|_GENERATION|_BYTES|_OBJECTS)$",  # numerics
    r"_TOKEN$",                 # bearer secrets passed by value, not path
    r"(_URL|_URI)$",            # network addresses
    r"_SHA256$",                # digest strings pinning a path variable's content
]
excluded_literals = {
    "MCLOVING_AGENT_CAPABILITIES": "capability name list",
    "MCLOVING_AGENT_ID": "agent identifier",
    "MCLOVING_AGENT_LISTEN": "socket bind address",
    "MCLOVING_LISTEN": "socket bind address",
    "MCLOVING_AGENT_ORGANIZATION_ID": "uuid",
    "MCLOVING_ORGANIZATION_ID": "uuid",
    "MCLOVING_PROJECT_ID": "uuid",
    "MCLOVING_AGENT_TRUST_POOL": "trust pool name",
    "MCLOVING_CONTROLLER_DNS_NAME": "TLS server name, not a path",
    "MCLOVING_ALLOW_INSECURE_LOOPBACK": "boolean flag",
    # RETIRED: the controller refuses any value by name
    # (bins/controller/src/main.rs); deliberately unclassified so setting
    # it stays an error, never a validated configuration.
    "MCLOVING_API_PRINCIPALS_PATH": "retired, refused by the controller",
}
unaccounted = []
for name in sorted(swept - classified):
    if name in excluded_literals:
        continue
    if any(re.search(pattern, name) for pattern in excluded_patterns):
        continue
    unaccounted.append(name)
if unaccounted:
    raise SystemExit(
        "binaries read MCLOVING_* variables that are neither classified in "
        "deployment_contract_path_variables nor excluded with a reviewed "
        "reason: " + " ".join(unaccounted)
    )
CLASSCOVER

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
printf '%s\n' "${invoking_xdg_environment}" > "${workdir}/logs/environment-xdg.log"
for binary in mcloving-controller mcloving-agent mcloving-cli mcloving-identity-admin; do
  cp "${repo_root}/target/debug/${binary}" "${release_dir}/${binary}"
done
(cd "${release_dir}" && sha256sum mcloving-controller mcloving-agent \
  mcloving-cli mcloving-identity-admin > "${workdir}/checksums.sha256")

home="${workdir}/home"
mkdir -p "${home}"
# The harness reads unit and quadlet paths through the SAME library
# derivation the installer writes with -- a hard-coded default here is how
# a runner-exported XDG base made reader and writer disagree in CI.
smoke_config_base="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
  deployment_config_root "${home}"
)"
smoke_unit_root="${smoke_config_base}/systemd/user"
smoke_quadlet_root="${smoke_config_base}/containers/systemd"
# The wrapper-to-payload exports carry base64 items (one per line); the
# race drivers bypass the wrapper and must speak the same transport.
smoke_unit_dirs_env="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
  encode_path_item "${smoke_unit_root}"
  encode_path_item "${smoke_quadlet_root}"
)"

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
# Identity bindings are identity material: the guard requires owner-only.
chmod 0600 "${config}/agent-identity-bindings.txt"

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

# Assert the guard ACCEPTS a valid contract, explicitly. Every other guard
# assertion in this file is a refusal, and a guard that refuses everything
# satisfies all of them; a break in the accepting path would otherwise surface
# much later as a confusing downstream failure. It has to come after the state
# directories above, because the agent contract names a workspace root the
# guard requires to exist -- which is what the units get from StateDirectory=.
for guarded in controller agent; do
  "${libexec}/helpers/mcloving-env-guard" "${guarded}" \
    "${config}/${guarded}.env" >/dev/null || {
    echo "env guard refused a valid ${guarded} contract:" >&2
    "${libexec}/helpers/mcloving-env-guard" "${guarded}" "${config}/${guarded}.env" >&2 || true
    exit 1
  }
done

# Private keys and identity bindings are stealable and replaceable identity
# material: readable-regular-file is not enough, and the guard now applies
# the installer's full secret-file treatment to the configured paths. A
# 0666 key must be refused by name at ExecStartPre; restored to 0600, the
# same contract must satisfy the guard again.
chmod 0666 "${pki}/agent-key.pem"
if "${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" \
  > "${workdir}/logs/guard-key-mode.log" 2>&1; then
  echo "env guard accepted a world-writable agent private key" >&2
  exit 1
fi
grep -q "agent-key.pem (mode 666, expected owner-only)" \
  "${workdir}/logs/guard-key-mode.log" || {
  echo "the guard's key-mode refusal did not name the path and mode:" >&2
  cat "${workdir}/logs/guard-key-mode.log" >&2
  exit 1
}
chmod 0600 "${pki}/agent-key.pem"
"${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" >/dev/null || {
  echo "env guard refused the restored 0600 agent private key" >&2
  exit 1
}
# Group-readable bindings leak nothing secret but invite substitution
# confusion; they are identity material and get the same owner-only rule.
chmod 0640 "${config}/agent-identity-bindings.txt"
if "${libexec}/helpers/mcloving-env-guard" controller "${config}/controller.env" \
  > "${workdir}/logs/guard-bindings-mode.log" 2>&1; then
  echo "env guard accepted group-readable identity bindings" >&2
  exit 1
fi
grep -q "agent-identity-bindings.txt (mode 640, expected owner-only)" \
  "${workdir}/logs/guard-bindings-mode.log" || {
  echo "the guard's bindings-mode refusal did not name the path and mode:" >&2
  cat "${workdir}/logs/guard-bindings-mode.log" >&2
  exit 1
}
chmod 0600 "${config}/agent-identity-bindings.txt"
"${libexec}/helpers/mcloving-env-guard" controller "${config}/controller.env" >/dev/null || {
  echo "env guard refused the restored owner-only bindings" >&2
  exit 1
}

# Trust inputs are public to READ and critical to WRITE: a writable CA lets
# another local user choose what the TLS handshake trusts. The class
# distinction from secret-file is pinned in both directions -- group/other
# READ stays legal for the CA while the same mode is refused for a key.
chmod 0666 "${pki}/controller-ca.pem"
if "${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" \
  > "${workdir}/logs/guard-ca-mode.log" 2>&1; then
  echo "env guard accepted a world-writable controller CA" >&2
  exit 1
fi
grep -q "controller-ca.pem (mode 666)" "${workdir}/logs/guard-ca-mode.log" || {
  echo "the writable-CA refusal did not name the path and mode:" >&2
  cat "${workdir}/logs/guard-ca-mode.log" >&2
  exit 1
}
chmod 0644 "${pki}/controller-ca.pem"
"${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" >/dev/null || {
  echo "env guard refused a world-READABLE 0644 CA; trust inputs are public to read" >&2
  exit 1
}
chmod 0644 "${pki}/agent-key.pem"
if "${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" \
  > "${workdir}/logs/guard-key-read.log" 2>&1; then
  echo "env guard accepted a group/other-readable private key" >&2
  exit 1
fi
grep -q "agent-key.pem (mode 644, expected owner-only)" \
  "${workdir}/logs/guard-key-read.log" || {
  echo "the readable-key refusal did not name the path and mode:" >&2
  cat "${workdir}/logs/guard-key-read.log" >&2
  exit 1
}
chmod 0600 "${pki}/agent-key.pem"
"${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" >/dev/null || {
  echo "env guard refused the restored key/CA pair" >&2
  exit 1
}

# A relative trust path means whatever the runtime working directory says
# it means -- ambient-context substitution. The guard refuses it by name;
# the inventory, which records drift rather than refusing, must SHOW it as
# a named record instead of silently skipping the un-inventoried file.
cp "${config}/agent.env" "${workdir}/agent.env.before-relative"
sed -i "s#^MCLOVING_CONTROLLER_CA_PATH=.*#MCLOVING_CONTROLLER_CA_PATH=relative/ca.pem#" \
  "${config}/agent.env"
grep -q "^MCLOVING_CONTROLLER_CA_PATH=relative/ca.pem\$" "${config}/agent.env" || {
  echo "relative-path gate could not rewrite MCLOVING_CONTROLLER_CA_PATH; contract shape changed" >&2
  exit 1
}
if "${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" \
  > "${workdir}/logs/guard-relative-path.log" 2>&1; then
  echo "env guard accepted a relative trust path" >&2
  exit 1
fi
grep -q "MCLOVING_CONTROLLER_CA_PATH must be an absolute path" \
  "${workdir}/logs/guard-relative-path.log" || {
  echo "the relative-path refusal did not name the variable:" >&2
  cat "${workdir}/logs/guard-relative-path.log" >&2
  exit 1
}
relative_doc="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${relative_doc}" <<'RELREC'
import json
import sys

document = json.loads(sys.argv[1])
records = [
    record
    for record in document.get("configured_paths", [])
    if record.get("kind") == "relative_configured_path"
]
if not records or records[0].get("variable") != "MCLOVING_CONTROLLER_CA_PATH":
    raise SystemExit(f"relative configured path not recorded by name: {records}")
RELREC
cp "${workdir}/agent.env.before-relative" "${config}/agent.env"
chmod 0600 "${config}/agent.env"
"${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" >/dev/null || {
  echo "env guard refused the restored absolute contract" >&2
  exit 1
}

# Optional variables inherit their class the moment they are set: a
# relative session receipt refused as ambient (state class), a
# group-readable effect plan refused as secret-class (the controller
# itself demands owner-only), a group-readable mapping catalog accepted
# as trust-class (read stays legal), and the unset originals untouched.
receipt_env="${home}/receipt-relative.env"
sed "s#^MCLOVING_AGENT_JOURNAL_PATH=#MCLOVING_AGENT_SESSION_RECEIPT_PATH=relative/receipt.json\nMCLOVING_AGENT_JOURNAL_PATH=#" \
  "${config}/agent.env" > "${receipt_env}"
chmod 0600 "${receipt_env}"
grep -q "^MCLOVING_AGENT_SESSION_RECEIPT_PATH=relative/receipt.json\$" "${receipt_env}" || {
  echo "receipt gate could not add MCLOVING_AGENT_SESSION_RECEIPT_PATH; contract shape changed" >&2
  exit 1
}
if "${libexec}/helpers/mcloving-env-guard" agent "${receipt_env}" \
  > "${workdir}/logs/guard-receipt-relative.log" 2>&1; then
  echo "env guard accepted a relative session receipt path" >&2
  exit 1
fi
grep -q "MCLOVING_AGENT_SESSION_RECEIPT_PATH must be an absolute path" \
  "${workdir}/logs/guard-receipt-relative.log" || {
  echo "the relative receipt refusal did not name the variable:" >&2
  cat "${workdir}/logs/guard-receipt-relative.log" >&2
  exit 1
}
rm -f "${receipt_env}"
effect_plan="${home}/effect-plan.json"
printf '{}' > "${effect_plan}"
chmod 0644 "${effect_plan}"
effect_env="${home}/effect-plan.env"
sed "s#^MCLOVING_LISTEN=#MCLOVING_EFFECT_RUNTIME_PLAN=${effect_plan}\nMCLOVING_LISTEN=#" \
  "${config}/controller.env" > "${effect_env}"
chmod 0600 "${effect_env}"
grep -q "^MCLOVING_EFFECT_RUNTIME_PLAN=${effect_plan}\$" "${effect_env}" || {
  echo "effect gate could not add MCLOVING_EFFECT_RUNTIME_PLAN; contract shape changed" >&2
  exit 1
}
if "${libexec}/helpers/mcloving-env-guard" controller "${effect_env}" \
  > "${workdir}/logs/guard-effect-plan.log" 2>&1; then
  echo "env guard accepted a group-readable effect runtime plan" >&2
  exit 1
fi
grep -q "effect-plan.json (mode 644, expected owner-only)" \
  "${workdir}/logs/guard-effect-plan.log" || {
  echo "the effect-plan refusal did not name the path and mode:" >&2
  cat "${workdir}/logs/guard-effect-plan.log" >&2
  exit 1
}
chmod 0600 "${effect_plan}"
"${libexec}/helpers/mcloving-env-guard" controller "${effect_env}" >/dev/null || {
  echo "env guard refused an owner-only effect runtime plan" >&2
  exit 1
}
# Parity with the binary: the controller inspects the plan with
# symlink_metadata() and refuses every symlink, so the guard must refuse
# the link itself rather than follow it to a valid target and report a
# contract the unit then fails on after ExecStartPre.
mv "${effect_plan}" "${effect_plan}.real"
ln -s "${effect_plan}.real" "${effect_plan}"
if "${libexec}/helpers/mcloving-env-guard" controller "${effect_env}" \
  > "${workdir}/logs/guard-effect-symlink.log" 2>&1; then
  echo "env guard accepted a symlinked effect runtime plan the controller refuses" >&2
  exit 1
fi
grep -q "MCLOVING_EFFECT_RUNTIME_PLAN must not be a symlink" \
  "${workdir}/logs/guard-effect-symlink.log" || {
  echo "the symlinked-plan refusal did not name the parity rule:" >&2
  cat "${workdir}/logs/guard-effect-symlink.log" >&2
  exit 1
}
rm -f "${effect_plan}"
mv "${effect_plan}.real" "${effect_plan}"
catalog_env="${home}/effect-catalog.env"
sed "s#^MCLOVING_LISTEN=#MCLOVING_EFFECT_MAPPING_CATALOG=${effect_plan}\nMCLOVING_LISTEN=#" \
  "${config}/controller.env" > "${catalog_env}"
chmod 0600 "${catalog_env}"
chmod 0644 "${effect_plan}"
"${libexec}/helpers/mcloving-env-guard" controller "${catalog_env}" >/dev/null || {
  echo "env guard refused a world-READABLE mapping catalog; trust inputs are public to read" >&2
  exit 1
}
rm -f "${effect_env}" "${catalog_env}" "${effect_plan}"

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
"${unit_command}" "${smoke_quadlet_root}/mcloving-postgres.container" \
  --home "${home}" --publish-override "127.0.0.1:${pg_port}" \
  --name-override "${container_name}" --volume-override "${volume_name}" \
  > "${workdir}/postgres.derived.json"
pre_argv=()
derived_argv pre_argv "${workdir}/postgres.derived.json" '.exec_start_pre[0]'
"${pre_argv[@]}" > "${workdir}/logs/postgres-volume.log" 2>&1 || {
  echo "postgres volume creation failed:" >&2
  cat "${workdir}/logs/postgres-volume.log" >&2
  podman info --format '{{.Host.CgroupsVersion}} {{.Host.CgroupManager}}' >&2 2>&1 || true
  exit 1
}
postgres_argv=()
derived_argv postgres_argv "${workdir}/postgres.derived.json" '.exec_start'
# Output captured rather than discarded: when this fails the smoke test has
# nothing else to say about why, and a container that will not start is the
# single most likely thing to differ between an operator's host and a CI
# runner. Podman's host configuration is printed alongside, since rootless
# cgroup and user-namespace setup is what usually differs.
"${postgres_argv[@]}" > "${workdir}/logs/postgres.log" 2>&1 || {
  echo "postgres container failed to start:" >&2
  cat "${workdir}/logs/postgres.log" >&2
  podman info --format '{{.Host.CgroupsVersion}} {{.Host.CgroupManager}} {{.Host.OCIRuntime.Name}}' >&2 2>&1 || true
  exit 1
}
health_argv=()
derived_argv health_argv "${workdir}/postgres.derived.json" '.health_cmd'
echo "postgres container started; waiting for the derived health command"
# Two consecutive successes, exactly like mcloving-db-init's ready() wait:
# the pinned image's entrypoint starts a temporary server during
# initialization and restarts it, and a single success can land in that
# window -- after which the settling re-check below meets a server that is
# gone again.
for _ in $(seq 1 120); do
  if podman exec "${container_name}" "${health_argv[@]}" >/dev/null 2>&1; then
    sleep 0.5
    if podman exec "${container_name}" "${health_argv[@]}" >/dev/null 2>&1; then
      break
    fi
  fi
  sleep 0.5
done
# The settling re-check used to discard its output and had no failure
# handler, so the one failure CI actually produced was pg_isready's exit
# status with every diagnostic thrown away: neither the loop above nor this
# line said which of them gave up, and the container holding the answer was
# force-removed before anything read its logs. Failures on this path must
# describe themselves like the volume-create and container-start paths do.
podman exec "${container_name}" "${health_argv[@]}" || {
  echo "postgres never reported healthy within the wait budget:" >&2
  podman ps --all --filter "name=${container_name}" >&2 || true
  podman logs "${container_name}" >&2 || true
  podman info --format '{{.Host.CgroupsVersion}} {{.Host.CgroupManager}} {{.Host.OCIRuntime.Name}}' >&2 2>&1 || true
  exit 1
}
echo "postgres healthy; deriving db-init"

"${unit_command}" "${smoke_unit_root}/mcloving-db-init.service" \
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
# The pre-migration endpoint check must compare the complete published
# host-and-port, not the port alone: a URL reaching another loopback address
# at the same port is a different PostgreSQL server. The accepting direction
# is proven by the two runs above; this is the refusing one, against the same
# live container.
wrong_endpoint_env="${workdir}/db-init-wrong-endpoint.env"
sed 's#^\(MCLOVING_MIGRATION_DATABASE_URL=.*\)@127\.0\.0\.1:#\1@127.0.0.2:#' \
  "${db_init_env}" > "${wrong_endpoint_env}"
if cmp -s "${wrong_endpoint_env}" "${db_init_env}"; then
  echo "endpoint refusal gate could not rewrite MCLOVING_MIGRATION_DATABASE_URL; contract shape changed" >&2
  exit 1
fi
if run_with_env "${wrong_endpoint_env}" "${db_init_argv[@]}" \
  > "${workdir}/logs/db-init-wrong-endpoint.log" 2>&1; then
  echo "db-init migrated through a URL addressing a different loopback endpoint" >&2
  exit 1
fi
grep -q "different PostgreSQL instance" "${workdir}/logs/db-init-wrong-endpoint.log" || {
  echo "db-init refused the mismatched endpoint for the wrong reason:" >&2
  cat "${workdir}/logs/db-init-wrong-endpoint.log" >&2
  exit 1
}
rm -f "${wrong_endpoint_env}"
# A refused bootstrap must not rotate live credentials. Point the contract at
# a project the organization does not have, with a canary password: the
# refusal must fire before ALTER ROLE. Detection compares the role's stored
# password hash rather than attempting logins -- container-internal loopback
# is `trust` in this image's default pg_hba, so any password "authenticates"
# from inside. The detector itself is then proven able to see a rotation, by
# rotating through the accepting path and requiring the hash to change.
tenant_hash() {
  printf "SELECT rolpassword FROM pg_authid WHERE rolname = 'mcloving_tenant';\n" \
    | podman exec --interactive "${container_name}" \
      psql --username mcloving --dbname mcloving \
      --set ON_ERROR_STOP=1 --no-psqlrc --quiet --tuples-only --no-align --file -
}
tenant_hash_before="$(tenant_hash)"
[[ -n "${tenant_hash_before}" ]] || {
  echo "mcloving_tenant has no stored password after a successful bootstrap" >&2
  exit 1
}
stale_project_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
canary_password="rotation-canary-${suffix}"
stale_project_env="${workdir}/db-init-stale-project.env"
sed -e "s#^MCLOVING_PROJECT_ID=.*#MCLOVING_PROJECT_ID=${stale_project_id}#" \
    -e "s#^MCLOVING_TENANT_PASSWORD=.*#MCLOVING_TENANT_PASSWORD=${canary_password}#" \
  "${db_init_env}" > "${stale_project_env}"
grep -q "^MCLOVING_PROJECT_ID=${stale_project_id}\$" "${stale_project_env}" || {
  echo "credential-rotation gate could not rewrite MCLOVING_PROJECT_ID; contract shape changed" >&2
  exit 1
}
grep -q "^MCLOVING_TENANT_PASSWORD=${canary_password}\$" "${stale_project_env}" || {
  echo "credential-rotation gate could not rewrite MCLOVING_TENANT_PASSWORD; contract shape changed" >&2
  exit 1
}
if run_with_env "${stale_project_env}" "${db_init_argv[@]}" \
  > "${workdir}/logs/db-init-stale-project.log" 2>&1; then
  echo "db-init reported success for a project the organization does not have" >&2
  exit 1
fi
grep -q "provision the project explicitly" "${workdir}/logs/db-init-stale-project.log" || {
  echo "db-init refused the missing project for the wrong reason:" >&2
  cat "${workdir}/logs/db-init-stale-project.log" >&2
  exit 1
}
[[ "$(tenant_hash)" == "${tenant_hash_before}" ]] || {
  echo "a refused bootstrap rotated the tenant password" >&2
  exit 1
}
# Prove the detector detects: an ACCEPTED bootstrap carrying the canary
# password must change the stored hash -- without this, a hash comparison
# that always reported "unchanged" would pass the refusal check above even
# against a bootstrap that rotates on every path.
canary_accept_env="${workdir}/db-init-canary-accept.env"
sed "s#^MCLOVING_TENANT_PASSWORD=.*#MCLOVING_TENANT_PASSWORD=${canary_password}#" \
  "${db_init_env}" > "${canary_accept_env}"
run_with_env "${canary_accept_env}" "${db_init_argv[@]}" \
  >> "${workdir}/logs/db-init.log"
[[ "$(tenant_hash)" != "${tenant_hash_before}" ]] || {
  echo "an accepted bootstrap did not rotate the tenant password; the rotation detector is blind" >&2
  exit 1
}
# Restore the contract's password for the controller started below.
run_with_env "${db_init_env}" "${db_init_argv[@]}" >> "${workdir}/logs/db-init.log"
rm -f "${stale_project_env}" "${canary_accept_env}"
# Provisioned identity includes the slugs. UUIDs that exist under different
# slugs are a different deployment identity wearing the configured ids, and
# reporting them as provisioned would silently discard both requested slugs.
slug_mismatch_env="${workdir}/db-init-slug-mismatch.env"
sed "s#^MCLOVING_ORGANIZATION_SLUG=.*#MCLOVING_ORGANIZATION_SLUG=smoke-org-imposter#" \
  "${db_init_env}" > "${slug_mismatch_env}"
grep -q "^MCLOVING_ORGANIZATION_SLUG=smoke-org-imposter\$" "${slug_mismatch_env}" || {
  echo "slug gate could not rewrite MCLOVING_ORGANIZATION_SLUG; contract shape changed" >&2
  exit 1
}
if run_with_env "${slug_mismatch_env}" "${db_init_argv[@]}" \
  > "${workdir}/logs/db-init-slug-mismatch.log" 2>&1; then
  echo "db-init reported provisioned for an organization holding a different slug" >&2
  exit 1
fi
grep -q "refusing to report a different identity as provisioned" \
  "${workdir}/logs/db-init-slug-mismatch.log" || {
  echo "db-init refused the slug mismatch for the wrong reason:" >&2
  cat "${workdir}/logs/db-init-slug-mismatch.log" >&2
  exit 1
}
rm -f "${slug_mismatch_env}"
# Ownership runs the other direction too: fresh UUIDs with a slug that is
# already owned by ANOTHER organization classify as a clean provision and
# then fail on the unique slug constraint -- after rotating credentials.
# The refusal must come first and must leave the stored hash untouched.
slug_owner_env="${workdir}/db-init-slug-owner.env"
owner_gate_org="$(python3 -c 'import uuid; print(uuid.uuid4())')"
owner_gate_project="$(python3 -c 'import uuid; print(uuid.uuid4())')"
sed -e "s#^MCLOVING_ORGANIZATION_ID=.*#MCLOVING_ORGANIZATION_ID=${owner_gate_org}#" \
    -e "s#^MCLOVING_PROJECT_ID=.*#MCLOVING_PROJECT_ID=${owner_gate_project}#" \
  "${db_init_env}" > "${slug_owner_env}"
grep -q "^MCLOVING_ORGANIZATION_ID=${owner_gate_org}\$" "${slug_owner_env}" || {
  echo "slug-ownership gate could not rewrite MCLOVING_ORGANIZATION_ID; contract shape changed" >&2
  exit 1
}
owner_hash_before="$(tenant_hash)"
if run_with_env "${slug_owner_env}" "${db_init_argv[@]}" \
  > "${workdir}/logs/db-init-slug-owner.log" 2>&1; then
  echo "db-init classified an already-owned organization slug as a clean provision" >&2
  exit 1
fi
grep -q "already owned by another organization" "${workdir}/logs/db-init-slug-owner.log" || {
  echo "db-init refused the owned slug for the wrong reason:" >&2
  cat "${workdir}/logs/db-init-slug-owner.log" >&2
  exit 1
}
[[ "$(tenant_hash)" == "${owner_hash_before}" ]] || {
  echo "the owned-slug refusal still rotated the tenant password" >&2
  exit 1
}
rm -f "${slug_owner_env}"
# UUID case is spelling, not identity. PostgreSQL renders uuids in canonical
# lowercase, so a contract whose valid UUIDs use uppercase hex must still
# resolve to the provisioned identity instead of being refused as belonging
# to another organization on every bootstrap after the first.
uppercase_env="${workdir}/db-init-uppercase.env"
uppercase_org="${organization_id^^}"
uppercase_project="${project_id^^}"
sed -e "s#^MCLOVING_ORGANIZATION_ID=.*#MCLOVING_ORGANIZATION_ID=${uppercase_org}#" \
    -e "s#^MCLOVING_PROJECT_ID=.*#MCLOVING_PROJECT_ID=${uppercase_project}#" \
  "${db_init_env}" > "${uppercase_env}"
grep -q "^MCLOVING_ORGANIZATION_ID=${uppercase_org}\$" "${uppercase_env}" || {
  echo "uppercase-UUID gate could not rewrite MCLOVING_ORGANIZATION_ID; contract shape changed" >&2
  exit 1
}
run_with_env "${uppercase_env}" "${db_init_argv[@]}" \
  > "${workdir}/logs/db-init-uppercase.log" 2>&1 || {
  echo "db-init refused a valid uppercase spelling of the provisioned UUIDs:" >&2
  cat "${workdir}/logs/db-init-uppercase.log" >&2
  exit 1
}
grep -q "already provisioned" "${workdir}/logs/db-init-uppercase.log" || {
  echo "the uppercase spelling did not resolve to the provisioned identity:" >&2
  cat "${workdir}/logs/db-init-uppercase.log" >&2
  exit 1
}
rm -f "${uppercase_env}"

"${unit_command}" "${smoke_unit_root}/mcloving-controller.service" \
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

"${unit_command}" "${smoke_unit_root}/mcloving-agent.service" \
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
# Named paths rather than a count: the document grew unit-root and directory
# records, and an exact length asserts the shape of the walker instead of the
# coverage this gate is about.
jq -e '
  . as $document
  | .schema == "mcloving.deployed-digests/v1"
  and (.current_release | startswith("releases/"))
  and (.releases | length >= 4)
  and (["mcloving-db-init.service", "mcloving-controller.service",
        "mcloving-agent.service", "mcloving-postgres.container",
        "mcloving-postgres-data.volume"]
       | all(. as $unit
             | ([$document.units[].path] | any(endswith("/" + $unit)))))
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

# The manifest is the other first-class digest source and gets both
# directions too: a valid manifest must install, and a digest source that is
# not a regular file must be refused promptly rather than read -- an
# ordinary open blocks forever on a writerless FIFO, and the verification
# would hang exactly when the source has been swapped out from under it.
manifest_home="${workdir}/manifest-home"
rm -rf "${manifest_home}"
mkdir -p "${manifest_home}"
python3 - "${release_dir}" "${workdir}/release-manifest.json" <<'MANIFEST'
import hashlib
import json
import sys
from pathlib import Path

source_dir, out = sys.argv[1], sys.argv[2]
components = []
for name in [
    "mcloving-controller",
    "mcloving-agent",
    "mcloving-cli",
    "mcloving-identity-admin",
]:
    payload = (Path(source_dir) / name).read_bytes()
    components.append(
        {
            "path": f"components/{name}",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        }
    )
Path(out).write_text(
    json.dumps({"manifest": {"components": components}}), encoding="utf-8"
)
MANIFEST
"${repo_root}/deploy/bin/mcloving-install" --home "${manifest_home}" \
  --release-dir "${release_dir}" --manifest "${workdir}/release-manifest.json" \
  --no-systemd >/dev/null
[[ -x "${manifest_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "manifest-verified install did not complete" >&2
  exit 1
}
rm -rf "${manifest_home}"

fifo_source="${workdir}/digest-source.fifo"
for digest_flag in --manifest --checksums; do
  rm -f "${fifo_source}"
  mkfifo "${fifo_source}"
  fifo_digest_home="${workdir}/fifo-digest-home"
  rm -rf "${fifo_digest_home}"
  mkdir -p "${fifo_digest_home}"
  digest_status=0
  timeout 60 "${repo_root}/deploy/bin/mcloving-install" --home "${fifo_digest_home}" \
    --release-dir "${release_dir}" "${digest_flag}" "${fifo_source}" \
    --no-systemd > "${workdir}/logs/fifo-digest-source.log" 2>&1 || digest_status=$?
  if [[ "${digest_status}" -eq 0 ]]; then
    echo "install accepted a ${digest_flag} source that is not a regular file" >&2
    exit 1
  fi
  if [[ "${digest_status}" -eq 124 ]]; then
    echo "install hung reading a FIFO ${digest_flag} source" >&2
    exit 1
  fi
  grep -q "is not a regular file" "${workdir}/logs/fifo-digest-source.log" || {
    echo "the FIFO ${digest_flag} source was refused for the wrong reason:" >&2
    cat "${workdir}/logs/fifo-digest-source.log" >&2
    exit 1
  }
  rm -rf "${fifo_digest_home}"
  rm -f "${fifo_source}"
done

# Every required entry must be present in the SAME snapshot sha256sum
# verifies. --ignore-missing used to make a vanished entry a silent pass, so
# a checksums file missing one binary must now be refused by name.
partial_checksums="${workdir}/partial-checksums.sha256"
grep -v "mcloving-agent" "${workdir}/checksums.sha256" > "${partial_checksums}"
partial_checksums_home="${workdir}/partial-checksums-home"
rm -rf "${partial_checksums_home}"
mkdir -p "${partial_checksums_home}"
if "${repo_root}/deploy/bin/mcloving-install" --home "${partial_checksums_home}" \
  --release-dir "${release_dir}" --checksums "${partial_checksums}" \
  --no-systemd > "${workdir}/logs/partial-checksums.log" 2>&1; then
  echo "install verified against a checksums file missing a required entry" >&2
  exit 1
fi
grep -q "no entry for mcloving-agent" "${workdir}/logs/partial-checksums.log" || {
  echo "the incomplete checksums file was refused for the wrong reason:" >&2
  cat "${workdir}/logs/partial-checksums.log" >&2
  exit 1
}
rm -rf "${partial_checksums_home}"
rm -f "${partial_checksums}"

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

# Install-time validation proves install-time state only: a contract
# relaxed AFTER install must be refused at service start, before parsing.
chmod 0644 "${config_dir}/agent.env"
if "${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" \
  > "${workdir}/logs/guard-contract-mode.log" 2>&1; then
  echo "env guard parsed a contract that became group-readable after install" >&2
  exit 1
fi
grep -q "agent.env (mode 644, expected owner-only)" \
  "${workdir}/logs/guard-contract-mode.log" || {
  echo "the guard's runtime contract refusal did not name the file and mode:" >&2
  cat "${workdir}/logs/guard-contract-mode.log" >&2
  exit 1
}
chmod 0600 "${config_dir}/agent.env"
"${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" >/dev/null || {
  echo "env guard refused the restored owner-only contract" >&2
  exit 1
}
# Configured state is dereferenced directly by the binaries: a writable
# workspace root or journal must refuse the start, and the agent's own
# 0644 journal must keep passing.
agent_workspace="${home}/.local/state/mcloving-agent/workspace"
chmod 0777 "${agent_workspace}"
if "${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" \
  > "${workdir}/logs/guard-workspace-mode.log" 2>&1; then
  echo "env guard accepted a world-writable agent workspace root" >&2
  exit 1
fi
grep -q "workspace (mode 777)" "${workdir}/logs/guard-workspace-mode.log" || {
  echo "the workspace refusal did not name the directory and mode:" >&2
  cat "${workdir}/logs/guard-workspace-mode.log" >&2
  exit 1
}
chmod 0755 "${agent_workspace}"
agent_journal="${home}/.local/state/mcloving-agent/journal.db"
if [[ -f "${agent_journal}" ]]; then
  journal_mode="$(stat -c '%a' "${agent_journal}")"
  chmod 0666 "${agent_journal}"
  if "${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" \
    > "${workdir}/logs/guard-journal-mode.log" 2>&1; then
    echo "env guard accepted a world-writable agent journal" >&2
    exit 1
  fi
  grep -q "journal.db (mode 666)" "${workdir}/logs/guard-journal-mode.log" || {
    echo "the journal refusal did not name the file and mode:" >&2
    cat "${workdir}/logs/guard-journal-mode.log" >&2
    exit 1
  }
  chmod "${journal_mode}" "${agent_journal}"
fi
"${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" >/dev/null || {
  echo "env guard refused the restored state paths" >&2
  exit 1
}

# A file that parses partially must not be accepted. The required assignments
# come first here, so a guard that ignored the parser's status would fill its
# map, report the contract satisfied, and exit 0 on a malformed file.
partial_env="${home}/partial.env"
printf 'POSTGRES_USER=x\nPOSTGRES_DB=y\nPOSTGRES_PASSWORD=z\nthis line has no equals\n' \
  > "${partial_env}"
chmod 0600 "${partial_env}"
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
utf8_env="${home}/utf8-token.env"
utf8_api="$(python3 -c "print('\u00e9' * 16)")"
utf8_artifact="$(python3 -c "print('\u00fc' * 16)")"
sed -e "s|^MCLOVING_API_TOKEN=.*|MCLOVING_API_TOKEN=${utf8_api}|" \
    -e "s|^MCLOVING_ARTIFACT_AGENT_TOKEN=.*|MCLOVING_ARTIFACT_AGENT_TOKEN=${utf8_artifact}|" \
    "${config_dir}/controller.env" > "${utf8_env}"
chmod 0600 "${utf8_env}"
"${libexec}/helpers/mcloving-env-guard" controller "${utf8_env}" >/dev/null || {
  echo "guard rejected a 32-byte token because it counted characters" >&2
  exit 1
}

# Two spellings of one database role are one role. Comparing URL text would
# accept them as distinct and let the controller run as the migration role.
equivalent_env="${home}/equivalent.env"
sed -e 's|^MCLOVING_DATABASE_URL=.*|MCLOVING_DATABASE_URL=postgres://mcloving_migration@127.0.0.1:5432/mcloving|' \
    -e 's|^MCLOVING_MIGRATION_DATABASE_URL=.*|MCLOVING_MIGRATION_DATABASE_URL=postgres://mcloving_migration@127.0.0.1/mcloving|' \
    "${config_dir}/controller.env" > "${equivalent_env}"
chmod 0600 "${equivalent_env}"
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
hijack_env="${home}/hijack.env"
cat > "${hijack_env}" <<'HIJACK'
service=postgres
POSTGRES_USER=x
POSTGRES_DB=x
POSTGRES_PASSWORD=x
HIJACK
chmod 0600 "${hijack_env}"
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

# --home must be checked against the account home systemd expands %h to, not
# against HOME, which the caller controls. Comparing two copies of HOME always
# agrees, so an install could write a whole deployment under one tree while
# daemon-reload and every later service operation acted on units pointing at
# another.
overridden_home="${workdir}/overridden-home"
mkdir -p "${overridden_home}"
if HOME="${overridden_home}" "${repo_root}/deploy/bin/mcloving-install" \
  --home "${overridden_home}" --release-dir "${release_dir}" \
  --checksums "${workdir}/checksums.sha256" >/dev/null 2>&1; then
  echo "install drove systemd for a tree its units do not describe" >&2
  exit 1
fi
rm -rf "${overridden_home}"

# The staging trap must survive a home containing shell metacharacters. A
# single quote is legal in a directory name and would break a trap body that
# wrapped the path in quotes instead of rendering it.
quoted_staging="${workdir}/"$'o\'h staging'
rm -rf "${quoted_staging}"
mkdir -p "${quoted_staging}/.local/libexec/mcloving/releases"
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  stage_release "${quoted_staging}/.local/libexec/mcloving" "${tampered_dir}" \
    "" "${workdir}/checksums.sha256"
) >/dev/null 2>&1 && {
  echo "staging accepted a tampered release under a quoted home" >&2
  exit 1
}
if compgen -G "${quoted_staging}/.local/libexec/mcloving/releases/.staging.*" >/dev/null; then
  echo "the staging cleanup trap did not run for a home containing a single quote" >&2
  exit 1
fi
rm -rf "${quoted_staging}"

# A directory's permissions are deployment state too. Relaxing the config root
# to 0777 lets another local user replace every contract and key inside it,
# while each file record stays byte-identical.
dir_mode_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod 0777 "${config_dir}"
dir_mode_after="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod 0700 "${config_dir}"
if [[ "${dir_mode_before}" == "${dir_mode_after}" ]]; then
  echo "a world-writable configuration root left the re-read unchanged" >&2
  exit 1
fi
python3 - "${dir_mode_after}" <<'DIRMODE'
import json
import sys

document = json.loads(sys.argv[1])
entry = [
    item
    for item in document.get("environment_contracts", [])
    if item["path"] == ".config/mcloving"
]
if not entry:
    raise SystemExit("configuration root missing from the re-read")
if entry[0].get("mode") != 0o777:
    raise SystemExit(f"configuration root mode not recorded: {entry[0]}")
DIRMODE

# The ANCESTORS of the walked trees are deployment state too. Relaxing
# ${libexec} itself to 0777 leaves every walked child record byte-identical
# while another local user renames current, releases, or helpers aside and
# substitutes deployed code; the same holds for ~/.config over the contract
# trees. The re-read must record the whole chain from ~ down to each walked
# root, and a mode change on any link of it must change the document.
libexec_mode="$(stat -c '%a' "${libexec}")"
ancestor_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod 0777 "${libexec}"
ancestor_after="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod "${libexec_mode}" "${libexec}"
if [[ "${ancestor_before}" == "${ancestor_after}" ]]; then
  echo "a world-writable libexec root left the re-read unchanged" >&2
  exit 1
fi
python3 - "${ancestor_after}" <<'ANCESTORS'
import json
import sys

document = json.loads(sys.argv[1])
records = {item["path"]: item for item in document.get("ancestors", [])}
relaxed = records.get(".local/libexec/mcloving")
if relaxed is None:
    raise SystemExit("libexec root missing from the ancestor records")
if relaxed.get("mode") != 0o777:
    raise SystemExit(f"libexec root mode not recorded: {relaxed}")
# Coverage of the whole chain, not just the directory this gate relaxed:
# every directory between ~ and a walked root is a place where a rename
# swaps a protected subtree aside.
required = {
    ".",
    ".local",
    ".local/libexec",
    ".local/libexec/mcloving",
    ".config",
    ".config/systemd",
    ".config/containers",
}
missing = required - set(records)
if missing:
    raise SystemExit(f"ancestor records missing: {sorted(missing)}")
ANCESTORS

# A chmod landing between a record's fstat and its pathname re-check must
# not survive into the canonical document: the inode is unchanged, so a
# device+inode re-check alone keeps the stale mode. Driven against the
# INSTALLED helper's own code with a hook that fires the chmod exactly
# inside that window (after the record is built, before the pathname
# re-check), this requires the returned document to carry the settled mode.
race_mode_before="$(stat -c '%a' "${libexec}")"
race_status=0
# The driver executes the helper's payload directly, bypassing the shell
# wrapper that normally derives and exports the ancestor set, so it supplies
# the same set through the same library derivation.
race_ancestors="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  deployment_ancestor_chain "${home}" \
    "${libexec}/releases" "${libexec}/helpers" \
    "${smoke_unit_root}" "${smoke_quadlet_root}" \
    "${home}/.config/mcloving" "${home}/.config/mcloving/pki"
)"
MCLOVING_ANCESTOR_DIRS="${race_ancestors}" \
MCLOVING_DEPLOY_LIB="${libexec}/helpers/mcloving-deploy-lib.sh" \
MCLOVING_UNIT_DIRS="${smoke_unit_dirs_env}" \
python3 - "${libexec}/helpers/mcloving-deployed-digests" "${home}" "${libexec}" <<'MODERACE' || race_status=$?
import contextlib
import io
import json
import os
import sys

helper, home, target = sys.argv[1], sys.argv[2], sys.argv[3]
source = open(helper, encoding="utf-8").read()
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
state = {"fd": None, "fired": False}
real_open, real_close = os.open, os.close


def hooked_open(path, flags, *args, **kwargs):
    fd = real_open(path, flags, *args, **kwargs)
    if not state["fired"] and os.fspath(path) == target:
        state["fd"] = fd
    return fd


def hooked_close(fd):
    if fd == state["fd"] and not state["fired"]:
        state["fired"] = True
        os.chmod(target, 0o777)
    return real_close(fd)


os.open, os.close = hooked_open, hooked_close
buffer = io.StringIO()
sys.argv = ["-", home]
try:
    with contextlib.redirect_stdout(buffer):
        exec(compile(payload, helper, "exec"), {"__name__": "__main__"})
finally:
    os.open, os.close = real_open, real_close
if not state["fired"]:
    raise SystemExit("the racing chmod never fired; the hook missed the record window")
document = json.loads(buffer.getvalue())
records = {record["path"]: record for record in document["ancestors"]}
entry = records[".local/libexec/mcloving"]
if entry.get("mode") != 0o777:
    raise SystemExit(f"record kept the pre-chmod mode: {entry}")
MODERACE
chmod "${race_mode_before}" "${libexec}"
if [[ "${race_status}" -ne 0 ]]; then
  echo "digest re-read kept a stale directory mode across a racing chmod" >&2
  exit 1
fi

# The same window, content edition: a write landing between the post-read
# fstat and the pathname re-check leaves inode, mode, and owner untouched
# while the bytes changed. Driven with a hook appending to the probe inside
# that exact window, the returned record must carry the settled bytes.
printf 'probe-content' > "${config_dir}/race-probe.txt"
chmod 0600 "${config_dir}/race-probe.txt"
content_race_status=0
MCLOVING_ANCESTOR_DIRS="${race_ancestors}" \
MCLOVING_DEPLOY_LIB="${libexec}/helpers/mcloving-deploy-lib.sh" \
MCLOVING_UNIT_DIRS="${smoke_unit_dirs_env}" \
python3 - "${libexec}/helpers/mcloving-deployed-digests" "${home}" \
  "${config_dir}/race-probe.txt" <<'CONTENTRACE' || content_race_status=$?
import contextlib
import hashlib
import io
import json
import os
import sys

helper, home, target = sys.argv[1], sys.argv[2], sys.argv[3]
source = open(helper, encoding="utf-8").read()
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
state = {"fd": None, "fired": False}
real_open, real_close = os.open, os.close


def hooked_open(path, flags, *args, **kwargs):
    fd = real_open(path, flags, *args, **kwargs)
    if not state["fired"] and os.fspath(path) == target:
        state["fd"] = fd
    return fd


def hooked_close(fd):
    if fd == state["fd"] and not state["fired"]:
        state["fired"] = True
        append_fd = real_open(target, os.O_WRONLY | os.O_APPEND)
        os.write(append_fd, b"-appended")
        real_close(append_fd)
    return real_close(fd)


os.open, os.close = hooked_open, hooked_close
buffer = io.StringIO()
sys.argv = ["-", home]
try:
    with contextlib.redirect_stdout(buffer):
        exec(compile(payload, helper, "exec"), {"__name__": "__main__"})
finally:
    os.open, os.close = real_open, real_close
if not state["fired"]:
    raise SystemExit("the racing append never fired; the hook missed the window")
document = json.loads(buffer.getvalue())
records = {
    record["path"]: record
    for record in document.get("environment_contracts", [])
}
entry = records.get(".config/mcloving/race-probe.txt")
if entry is None:
    raise SystemExit("probe file missing from the re-read")
settled = b"probe-content-appended"
if entry.get("sha256") != hashlib.sha256(settled).hexdigest() or entry.get(
    "size_bytes"
) != len(settled):
    raise SystemExit(f"record kept the pre-append content identity: {entry}")
CONTENTRACE
rm -f "${config_dir}/race-probe.txt"
if [[ "${content_race_status}" -ne 0 ]]; then
  echo "digest re-read kept a stale content identity across a racing write" >&2
  exit 1
fi

# mtime alone is forgeable. An in-place rewrite of the SAME size with the
# original mtime restored via utime() slides through the read window unless
# ctime -- which cannot be set back without clock-level privilege -- anchors
# the post-read identity tuple. The hook fires the rewrite exactly at the
# settled fstat, restores the mtime, and the record must still carry the
# settled bytes (or the named instability), never the stale digest.
printf 'ctime-probe-original' > "${config_dir}/ctime-probe.txt"
chmod 0600 "${config_dir}/ctime-probe.txt"
ctime_race_status=0
MCLOVING_ANCESTOR_DIRS="${race_ancestors}" \
MCLOVING_DEPLOY_LIB="${libexec}/helpers/mcloving-deploy-lib.sh" \
MCLOVING_UNIT_DIRS="${smoke_unit_dirs_env}" \
python3 - "${libexec}/helpers/mcloving-deployed-digests" "${home}" \
  "${config_dir}/ctime-probe.txt" <<'CTIMERACE' || ctime_race_status=$?
import contextlib
import hashlib
import io
import json
import os
import sys

helper, home, target = sys.argv[1], sys.argv[2], sys.argv[3]
source = open(helper, encoding="utf-8").read()
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
original = os.stat(target)
new_bytes = b"ctime-probe-REWRITE!"
state = {"fd": None, "fires": 0}
real_open, real_fstat = os.open, os.fstat


def hooked_open(path, flags, *args, **kwargs):
    fd = real_open(path, flags, *args, **kwargs)
    if state["fd"] is None and os.fspath(path) == target:
        state["fd"] = fd
    return fd


def hooked_fstat(fd):
    if fd == state["fd"]:
        state["fires"] += 1
        if state["fires"] == 2:
            write_fd = real_open(target, os.O_WRONLY)
            os.write(write_fd, new_bytes)
            os.close(write_fd)
            os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
    return real_fstat(fd)


os.open, os.fstat = hooked_open, hooked_fstat
buffer = io.StringIO()
sys.argv = ["-", home]
try:
    with contextlib.redirect_stdout(buffer):
        exec(compile(payload, helper, "exec"), {"__name__": "__main__"})
finally:
    os.open, os.fstat = real_open, real_fstat
if state["fires"] < 2:
    raise SystemExit("the forged rewrite never fired; the hook missed the window")
document = json.loads(buffer.getvalue())
records = {
    record["path"]: record
    for record in document.get("environment_contracts", [])
}
entry = records.get(".config/mcloving/ctime-probe.txt")
if entry is None:
    raise SystemExit("probe file missing from the re-read")
if entry.get("kind") == "unstable_entry":
    raise SystemExit(0)
if entry.get("sha256") != hashlib.sha256(new_bytes).hexdigest():
    raise SystemExit(f"record kept the stale digest behind a forged mtime: {entry}")
CTIMERACE
rm -f "${config_dir}/ctime-probe.txt"
if [[ "${ctime_race_status}" -ne 0 ]]; then
  echo "digest re-read accepted a stale digest behind a forged mtime" >&2
  exit 1
fi

# A listing is a snapshot: a file created right after iterdir() must still
# reach the document (the walk re-lists after processing and retries) or be
# named as an unstable listing -- never silently omitted while present on
# disk when the command returns.
listing_race_status=0
MCLOVING_ANCESTOR_DIRS="${race_ancestors}" \
MCLOVING_DEPLOY_LIB="${libexec}/helpers/mcloving-deploy-lib.sh" \
MCLOVING_UNIT_DIRS="${smoke_unit_dirs_env}" \
MCLOVING_CONFIGURED_PATHS="" \
python3 - "${libexec}/helpers/mcloving-deployed-digests" "${home}" \
  "${config_dir}" <<'LISTRACE' || listing_race_status=$?
import contextlib
import io
import json
import os
import sys

helper, home, target = sys.argv[1], sys.argv[2], sys.argv[3]
source = open(helper, encoding="utf-8").read()
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
born = os.path.join(target, "race-born.txt")
state = {"fired": False}
real_listdir = os.listdir


def hooked_listdir(path=None):
    result = real_listdir(path)
    try:
        same = path is not None and os.path.samefile(path, target)
    except (OSError, TypeError):
        same = False
    if same and not state["fired"]:
        state["fired"] = True
        with open(born, "w") as handle:
            handle.write("born-in-the-window")
        os.chmod(born, 0o600)
    return result


os.listdir = hooked_listdir
buffer = io.StringIO()
sys.argv = ["-", home]
try:
    with contextlib.redirect_stdout(buffer):
        exec(compile(payload, helper, "exec"), {"__name__": "__main__"})
finally:
    os.listdir = real_listdir
if not state["fired"]:
    raise SystemExit("the racing creation never fired; the hook missed the window")
document = json.loads(buffer.getvalue())
present = any(
    record["path"] == ".config/mcloving/race-born.txt"
    for record in document.get("environment_contracts", [])
)
named_unstable = any(
    record.get("kind") == "unstable_listing"
    for record in document.get("ancestors", [])
)
if not (present or named_unstable):
    raise SystemExit(
        "a file created after the listing snapshot was silently omitted"
    )
LISTRACE
rm -f "${config_dir}/race-born.txt"
if [[ "${listing_race_status}" -ne 0 ]]; then
  echo "digest re-read silently omitted a file created during the walk" >&2
  exit 1
fi

# Identity material configured OUTSIDE the walked trees must be in the
# inventory: the guard validates an external CA at service start, and a
# document that recorded only the path string would stay byte-identical
# across its substitution. Both directions, against the real agent
# contract, restored afterwards.
external_baseline="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${external_baseline}" <<'EXTBASE'
import json
import sys

document = json.loads(sys.argv[1])
if document.get("configured_paths") != []:
    raise SystemExit(
        f"in-tree config produced configured_paths records: {document.get('configured_paths')}"
    )
EXTBASE
mkdir -p "${home}/external-trust"
chmod 0755 "${home}/external-trust"
cp "${pki}/controller-ca.pem" "${home}/external-trust/controller-ca.pem"
chmod 0644 "${home}/external-trust/controller-ca.pem"
cp "${config_dir}/agent.env" "${workdir}/agent.env.before-external"
sed -i "s#^MCLOVING_CONTROLLER_CA_PATH=.*#MCLOVING_CONTROLLER_CA_PATH=${home}/external-trust/controller-ca.pem#" \
  "${config_dir}/agent.env"
grep -q "^MCLOVING_CONTROLLER_CA_PATH=${home}/external-trust/controller-ca.pem\$" \
  "${config_dir}/agent.env" || {
  echo "external-CA gate could not rewrite MCLOVING_CONTROLLER_CA_PATH; contract shape changed" >&2
  exit 1
}
external_doc="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${external_doc}" <<'EXTREC'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("configured_paths", [])}
entry = records.get("external-trust/controller-ca.pem")
if entry is None:
    raise SystemExit(f"external CA missing from configured_paths: {sorted(records)}")
if "sha256" not in entry or "mode" not in entry:
    raise SystemExit(f"external CA record lacks digest or mode: {entry}")
ancestors = {record["path"] for record in document.get("ancestors", [])}
if "external-trust" not in ancestors:
    raise SystemExit(f"external CA ancestor chain missing: {sorted(ancestors)}")
EXTREC
printf 'SUBSTITUTED-TRUST-ROOT-BYTES\n' > "${home}/external-trust/controller-ca.pem"
chmod 0644 "${home}/external-trust/controller-ca.pem"
external_substituted="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
if [[ "${external_doc}" == "${external_substituted}" ]]; then
  echo "substituting the external CA left the digest re-read unchanged" >&2
  exit 1
fi
cp "${pki}/controller-ca.pem" "${home}/external-trust/controller-ca.pem"
chmod 0644 "${home}/external-trust/controller-ca.pem"
cp "${workdir}/agent.env.before-external" "${config_dir}/agent.env"
chmod 0600 "${config_dir}/agent.env"
rm -rf "${home}/external-trust"
external_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
[[ "${external_baseline}" == "${external_restored}" ]] || {
  echo "the re-read did not return to baseline after the external CA was removed" >&2
  exit 1
}

# A quoted multiline contract value carrying a newline in an absolute path
# is legal to the shared parser and to systemd; the inventory transport
# must carry it as ONE item with the right digest, never split it into
# records that hash unrelated paths.
newline_dir_literal="${home}/nl
dir"
mkdir -p "${newline_dir_literal}"
chmod 0755 "${newline_dir_literal}"
printf 'newline-path-trust-bytes' > "${newline_dir_literal}/ca.pem"
chmod 0644 "${newline_dir_literal}/ca.pem"
cp "${config_dir}/agent.env" "${workdir}/agent.env.before-newline"
python3 - "${config_dir}/agent.env" "${newline_dir_literal}/ca.pem" <<'NLREWRITE'
import sys
from pathlib import Path

contract = Path(sys.argv[1])
target = sys.argv[2]
lines = []
for line in contract.read_text().splitlines():
    if line.startswith("MCLOVING_CONTROLLER_CA_PATH="):
        lines.append("MCLOVING_CONTROLLER_CA_PATH='" + target + "'")
    else:
        lines.append(line)
contract.write_text("\n".join(lines) + "\n")
NLREWRITE
chmod 0600 "${config_dir}/agent.env"
newline_doc="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${newline_doc}" <<'NLCHECK'
import hashlib
import json
import sys

document = json.loads(sys.argv[1])
records = [
    record
    for record in document.get("configured_paths", [])
    if "nl" in record.get("path", "")
]
if len(records) != 1:
    raise SystemExit(f"newline-bearing path did not round-trip as one record: {records}")
expected = hashlib.sha256(b"newline-path-trust-bytes").hexdigest()
if records[0].get("sha256") != expected:
    raise SystemExit(f"newline-bearing path hashed the wrong bytes: {records[0]}")
if "\n" not in records[0]["path"]:
    raise SystemExit(f"the record lost the newline from the path: {records[0]}")
NLCHECK
cp "${workdir}/agent.env.before-newline" "${config_dir}/agent.env"
chmod 0600 "${config_dir}/agent.env"
rm -rf "${newline_dir_literal}"
newline_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
[[ "${external_baseline}" == "${newline_restored}" ]] || {
  echo "the re-read did not return to baseline after the newline path was removed" >&2
  exit 1
}

# Ownership is identity too. An ancestor that changes hands can be re-moded
# by its new owner at will, so the canonical document must change when the
# owner does -- and the change must be visible in the record, both proven
# with a REAL foreign uid via `podman unshare chown` (no root needed). The
# foreign-owned directory is opened to 0755 for the duration: at the
# installed 0700 the invoking user could no longer traverse its own
# deployment to run the helper at all -- which is the attack in miniature,
# but not what this gate measures.
owner_gate_dir="${home}/.local"
owner_gate_mode="$(stat -c '%a' "${owner_gate_dir}")"
owner_doc_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
podman unshare sh -c "chown 1:1 '${owner_gate_dir}' && chmod 0755 '${owner_gate_dir}'"
# Ownership is restored on the failure path too: a workdir preserved with a
# subuid-owned directory inside cannot be removed by the invoking user, and
# the next run's cleanup would fail on it.
owner_doc_after="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")" || {
  podman unshare chown 0:0 "${owner_gate_dir}" || true
  chmod "${owner_gate_mode}" "${owner_gate_dir}" || true
  echo "digest re-read failed while an ancestor was foreign-owned" >&2
  exit 1
}
podman unshare chown 0:0 "${owner_gate_dir}"
chmod "${owner_gate_mode}" "${owner_gate_dir}"
if [[ "${owner_doc_before}" == "${owner_doc_after}" ]]; then
  echo "a re-owned ancestor left the digest re-read unchanged" >&2
  exit 1
fi
python3 - "${owner_doc_after}" <<'OWNERSHIP'
import json
import os
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("ancestors", [])}
entry = records.get(".local")
if entry is None:
    raise SystemExit(f"ancestor .local missing from the re-read: {sorted(records)}")
if entry.get("uid") in (None, os.getuid()):
    raise SystemExit(f"foreign owner not recorded on the ancestor: {entry}")
if entry.get("gid") in (None, os.getgid()):
    raise SystemExit(f"foreign group not recorded on the ancestor: {entry}")
OWNERSHIP
owner_doc_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
if [[ "${owner_doc_before}" != "${owner_doc_restored}" ]]; then
  echo "the re-read did not return to baseline after ownership was restored" >&2
  exit 1
fi

# Nested symlinks discovered by the walk feed their resolved target's
# parent chain into the ancestors too: pki/certs -> ~/depot/certs is
# followed and inventoried, and without this the mode of ~/depot could
# change while the document stayed byte-identical. Both directions, plus
# the totality rule: an unresolvable nested link becomes a RECORD, never a
# failed run.
mkdir -p "${home}/depot/certs"
chmod 0755 "${home}/depot" "${home}/depot/certs"
ln -s "${home}/depot/certs" "${config_dir}/pki/certs-link"
nested_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${nested_before}" <<'NESTED'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("ancestors", [])}
if "depot" not in records:
    raise SystemExit(f"nested link target parent missing: {sorted(records)}")
NESTED
chmod 0777 "${home}/depot"
nested_after="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod 0755 "${home}/depot"
if [[ "${nested_before}" == "${nested_after}" ]]; then
  echo "a relaxed nested-link target parent left the re-read unchanged" >&2
  exit 1
fi
python3 - "${nested_after}" <<'NESTEDMODE'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("ancestors", [])}
if records.get("depot", {}).get("mode") != 0o777:
    raise SystemExit(f"nested target parent mode not recorded: {records.get('depot')}")
NESTEDMODE
nested_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
[[ "${nested_before}" == "${nested_restored}" ]] || {
  echo "the nested-link re-read did not return to baseline" >&2
  exit 1
}
# Totality: an unresolvable nested link is recorded, not fatal.
ln -s "${workdir}/definitely-absent-target" "${config_dir}/pki/broken-link"
nested_unresolvable="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")" || {
  echo "an unresolvable nested link failed the whole re-read" >&2
  rm -f "${config_dir}/pki/broken-link" "${config_dir}/pki/certs-link"
  exit 1
}
python3 - "${nested_unresolvable}" <<'NESTEDBROKEN'
import json
import sys

document = json.loads(sys.argv[1])
entries = [
    record
    for record in document.get("ancestors", [])
    if record.get("kind") == "unresolvable_link_chain"
    and record["path"].endswith("pki/broken-link")
]
if not entries:
    raise SystemExit("unresolvable nested link chain was not recorded")
NESTEDBROKEN
rm -f "${config_dir}/pki/broken-link" "${config_dir}/pki/certs-link"
rm -rf "${home}/depot"

# systemd and Quadlet read every file inside a matching drop-in directory
# regardless of its basename, so the inventory must too: an override.conf
# changing Restart= or ExecStart= alters the real configuration, and a
# basename filter applied below the top level left the canonical document
# byte-identical across it. Both unit trees follow the convention; both are
# gated.
dropin_service_dir="${smoke_unit_root}/mcloving-controller.service.d"
dropin_quadlet_dir="${smoke_quadlet_root}/mcloving-postgres.container.d"
dropin_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
mkdir -p "${dropin_service_dir}" "${dropin_quadlet_dir}"
printf '[Service]\nRestart=always\n' > "${dropin_service_dir}/override.conf"
printf '[Container]\nEnvironment=SMOKE=1\n' > "${dropin_quadlet_dir}/tweak.conf"
dropin_added="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
if [[ "${dropin_before}" == "${dropin_added}" ]]; then
  echo "adding unit drop-ins left the digest re-read unchanged" >&2
  exit 1
fi
python3 - "${dropin_added}" <<'DROPIN'
import json
import sys

document = json.loads(sys.argv[1])
paths = {record["path"] for record in document.get("units", [])}
required = {
    ".config/systemd/user/mcloving-controller.service.d",
    ".config/systemd/user/mcloving-controller.service.d/override.conf",
    ".config/containers/systemd/mcloving-postgres.container.d",
    ".config/containers/systemd/mcloving-postgres.container.d/tweak.conf",
}
missing = required - paths
if missing:
    raise SystemExit(f"drop-in records missing from the unit inventory: {sorted(missing)}")
DROPIN
printf '[Service]\nRestart=no\n' > "${dropin_service_dir}/override.conf"
dropin_changed="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
if [[ "${dropin_added}" == "${dropin_changed}" ]]; then
  echo "changing a drop-in's content left the digest re-read unchanged" >&2
  exit 1
fi
rm -rf "${dropin_service_dir}" "${dropin_quadlet_dir}"
dropin_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
[[ "${dropin_before}" == "${dropin_restored}" ]] || {
  echo "the re-read did not return to baseline after the drop-ins were removed" >&2
  exit 1
}

# Content is not the whole identity. A deployed binary that loses its execute
# bit keeps its digest and size while systemd can no longer run it, and the
# release manifest records executable: true per component, so the re-read has
# to carry the mode or the cutover freeze cannot see that drift.
mode_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
current_agent="${libexec}/current/mcloving-agent"
chmod 0644 "${current_agent}"
mode_after="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod 0755 "${current_agent}"
if [[ "${mode_before}" == "${mode_after}" ]]; then
  echo "a deployed binary that lost its execute bit left the re-read unchanged" >&2
  exit 1
fi
python3 - "${mode_after}" <<'MODE'
import json
import sys

document = json.loads(sys.argv[1])
# Scoped to the release that `current` points at. Earlier upgrades leave other
# release directories on disk, and only the current one had its execute bit
# stripped -- asserting across all of them tests the wrong thing.
current = document.get("current_release")
if not current:
    raise SystemExit("re-read has no current release")
suffix = f"/{current}/mcloving-agent"
entry = [
    item for item in document.get("releases", []) if item["path"].endswith(suffix)
]
if not entry:
    raise SystemExit(f"agent of the current release {current} missing from the re-read")
if any(item.get("executable") is not False for item in entry):
    raise SystemExit(f"non-executable agent not recorded as such: {entry}")
MODE

# Changing the active release is the upgrade path's job: it stops the services,
# flips the symlinks, restarts, and gates on health. An installer rerun would
# repoint current under running processes, leaving them on the old binaries
# while the digest re-read reports the new release as current. Run in its own
# home so the assertion does not depend on which release is current here.
rerun_home="${workdir}/rerun-home"
rm -rf "${rerun_home}"
mkdir -p "${rerun_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${rerun_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
rerun_libexec="${rerun_home}/.local/libexec/mcloving"
# Reinstalling the release that is already current is accepted, and must not
# leave the redundant staging copy behind.
"${repo_root}/deploy/bin/mcloving-install" --home "${rerun_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
if compgen -G "${rerun_libexec}/releases/.staging.*" >/dev/null; then
  echo "reinstalling the current release left a redundant staging copy" >&2
  exit 1
fi
# A different release must be refused and must change nothing.
rerun_before="$(readlink "${rerun_libexec}/current")"
rerun_releases_before="$(ls "${rerun_libexec}/releases" | sort | tr '\n' ' ')"
if "${repo_root}/deploy/bin/mcloving-install" --home "${rerun_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install repointed current for a differing existing installation" >&2
  exit 1
fi
[[ "$(readlink "${rerun_libexec}/current")" == "${rerun_before}" ]] || {
  echo "a refused installer rerun still moved the current release" >&2
  exit 1
}
if compgen -G "${rerun_libexec}/releases/.staging.*" >/dev/null; then
  echo "a refused installer rerun left staging behind" >&2
  exit 1
fi
# A refused command must not have published anything either: staging the copy
# before deciding would add a release to disk and to the canonical inventory
# under an operation reported as refused.
[[ "$(ls "${rerun_libexec}/releases" | sort | tr '\n' ' ')" == "${rerun_releases_before}" ]] || {
  echo "a refused installer rerun still published a release" >&2
  exit 1
}
rm -rf "${rerun_home}"

# A release entry that is not a regular file must be refused before it is
# copied: `install` reading a FIFO blocks until something writes, and reading a
# symlinked device fills the disk, both before digest verification runs.
fifo_release="${workdir}/fifo-release"
rm -rf "${fifo_release}"
cp -r "${release_dir}" "${fifo_release}"
rm -f "${fifo_release}/mcloving-cli"
mkfifo "${fifo_release}/mcloving-cli"
fifo_home="${workdir}/fifo-home"
rm -rf "${fifo_home}"
mkdir -p "${fifo_home}"
fifo_status=0
timeout 60 "${repo_root}/deploy/bin/mcloving-install" --home "${fifo_home}" \
  --release-dir "${fifo_release}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1 || fifo_status=$?
if [[ "${fifo_status}" -eq 0 ]]; then
  echo "install accepted a release entry that is not a regular file" >&2
  exit 1
fi
if [[ "${fifo_status}" -eq 124 ]]; then
  echo "install hung reading a FIFO release entry" >&2
  exit 1
fi
rm -rf "${fifo_release}" "${fifo_home}"

# Identical bytes without execute permission still cannot run, so a published
# release that lost its execute bits must be refused rather than reported
# usable.
noexec_home="${workdir}/noexec-home"
rm -rf "${noexec_home}"
mkdir -p "${noexec_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${noexec_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
chmod 0644 "${noexec_home}/.local/libexec/mcloving/current/mcloving-agent"
if "${repo_root}/deploy/bin/mcloving-install" --home "${noexec_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install reported success over a release whose binaries cannot execute" >&2
  exit 1
fi
rm -rf "${noexec_home}"

# A directory where a contract file belongs must be refused. Without -T, GNU
# install copies the example *into* that directory and reports success while
# the unit's EnvironmentFile= still names a directory and startup must fail.
dir_dest_home="${workdir}/dir-dest-home"
rm -rf "${dir_dest_home}"
mkdir -p "${dir_dest_home}/.config/mcloving/agent.env"
if "${repo_root}/deploy/bin/mcloving-install" --home "${dir_dest_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install reported success with a directory where a contract must be" >&2
  exit 1
fi
rm -rf "${dir_dest_home}"

# A refusal must never delete a release it did not publish: the same id can
# already be the retained rollback target.
retain_home="${workdir}/retain-home"
rm -rf "${retain_home}"

# A retained release tree under the SAME truncated id as a newly verified
# release must be byte-compared, never adopted by name: the id keeps only 48
# digest bits, and without the comparison a colliding or substituted tree
# would be reused while the newly verified staging copy is deleted. The
# benign-reuse acceptance direction is the reinstall-the-current-release
# gate above, which still passes with the comparison in place.
collision_home="${workdir}/collision-home"
rm -rf "${collision_home}"

# A symlink where a retained release directory belongs has no legitimate
# state -- stage_release only publishes real directories -- and -d, cmp,
# and the digest re-verification would all follow it into an unvalidated
# external chain. Refused by name at stage time; and the current/previous
# links the upgrade and rollback paths trust are validated the same way:
# targets must be releases/<id> entries, and the entry must be a real
# directory.
linktrap_home="${workdir}/linktrap-home"
rm -rf "${linktrap_home}"

# Release state transitions are serialized by one deployment-wide advisory
# lock across install, upgrade, and rollback. A held lock must produce a
# named refusal -- never a silent queue behind a snapshot that is about to
# go stale -- and the release must be untouched; a released lock must let
# the same transition through.
lock_home="${workdir}/lock-home"
rm -rf "${lock_home}"

# An ancestor relaxed AFTER installation must refuse the next transition --
# upgrade and rollback rerun the full shared validation inside the lock,
# before anything mutates and before rollback stops any service.
transguard_home="${workdir}/transguard-home"
rm -rf "${transguard_home}"
mkdir -p "${transguard_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${transguard_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
transguard_libexec="${transguard_home}/.local/libexec/mcloving"
transguard_current="$(readlink "${transguard_libexec}/current")"
chmod 0777 "${transguard_home}/.local"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${transguard_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/transguard-upgrade.log" 2>&1; then
  echo "upgrade proceeded over an ancestor relaxed after installation" >&2
  exit 1
fi
grep -q "\.local (mode 777)" "${workdir}/logs/transguard-upgrade.log" || {
  echo "the upgrade transition refusal did not name the ancestor:" >&2
  cat "${workdir}/logs/transguard-upgrade.log" >&2
  exit 1
}
[[ "$(readlink "${transguard_libexec}/current")" == "${transguard_current}" ]] || {
  echo "a refused upgrade transition still moved the current release" >&2
  exit 1
}
chmod 0755 "${transguard_home}/.local"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${transguard_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
transguard_upgraded="$(readlink "${transguard_libexec}/current")"
chmod 0777 "${transguard_home}/.local"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd > "${workdir}/logs/transguard-rollback.log" 2>&1; then
  echo "rollback proceeded over an ancestor relaxed after installation" >&2
  exit 1
fi
grep -q "\.local (mode 777)" "${workdir}/logs/transguard-rollback.log" || {
  echo "the rollback transition refusal did not name the ancestor:" >&2
  cat "${workdir}/logs/transguard-rollback.log" >&2
  exit 1
}
if grep -q "rolling back" "${workdir}/logs/transguard-rollback.log"; then
  echo "the rollback refusal came after the transition had begun" >&2
  exit 1
fi
[[ "$(readlink "${transguard_libexec}/current")" == "${transguard_upgraded}" ]] || {
  echo "a refused rollback transition still moved the current release" >&2
  exit 1
}
chmod 0755 "${transguard_home}/.local"
"${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${transguard_libexec}/current")" == "${transguard_current}" ]] || {
  echo "rollback did not restore the original release after the ancestor was secured" >&2
  exit 1
}
# LEAF managed roots are nodes in the validated set, not only their
# parents: a helpers or releases directory relaxed after install is a
# helper or release substitution waiting for the next transition.
chmod 0777 "${transguard_libexec}/helpers"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${transguard_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/transguard-helpers.log" 2>&1; then
  echo "upgrade proceeded over a world-writable helpers root" >&2
  exit 1
fi
grep -q "helpers (mode 777)" "${workdir}/logs/transguard-helpers.log" || {
  echo "the helpers-root refusal did not name the leaf:" >&2
  cat "${workdir}/logs/transguard-helpers.log" >&2
  exit 1
}
[[ "$(readlink "${transguard_libexec}/current")" == "${transguard_current}" ]] || {
  echo "a refused helpers-root upgrade still moved the current release" >&2
  exit 1
}
chmod 0700 "${transguard_libexec}/helpers"
chmod 0777 "${transguard_libexec}/releases"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd > "${workdir}/logs/transguard-releases.log" 2>&1; then
  echo "rollback proceeded over a world-writable releases root" >&2
  exit 1
fi
grep -q "releases (mode 777)" "${workdir}/logs/transguard-releases.log" || {
  echo "the releases-root refusal did not name the leaf:" >&2
  cat "${workdir}/logs/transguard-releases.log" >&2
  exit 1
}
if grep -q "rolling back" "${workdir}/logs/transguard-releases.log"; then
  echo "the releases-root refusal came after the transition had begun" >&2
  exit 1
fi
chmod 0700 "${transguard_libexec}/releases"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${transguard_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${transguard_libexec}/current")" != "${transguard_current}" ]] || {
  echo "the secured leaf roots did not admit the transition" >&2
  exit 1
}
rm -rf "${transguard_home}"
mkdir -p "${lock_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${lock_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
lock_libexec="${lock_home}/.local/libexec/mcloving"
lock_current="$(readlink "${lock_libexec}/current")"
# The holder is an UNRELATED process, exactly like a real concurrent
# transition: a holder that spawned the upgrade would leak its locked
# descriptor into the child, and inherited-descriptor flock semantics are
# not the case this lock exists for.
# `exec sleep` keeps the holder a single process: `flock -c` would hold
# the lock in a child that survives killing the parent, and the gate could
# never release it.
( exec 200>"${lock_libexec}/.transition-lock" \
  && flock -n 200 \
  && exec sleep 60 ) &
lock_holder=$!
lock_taken=""
for _ in $(seq 1 50); do
  if ! flock -n "${lock_libexec}/.transition-lock" -c true 2>/dev/null; then
    lock_taken=1
    break
  fi
  sleep 0.1
done
[[ -n "${lock_taken}" ]] || {
  echo "the lock gate's holder never took the transition lock" >&2
  kill "${lock_holder}" 2>/dev/null || true
  exit 1
}
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${lock_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/transition-lock.log" 2>&1; then
  echo "an upgrade proceeded while another transition held the deployment lock" >&2
  kill "${lock_holder}" 2>/dev/null || true
  exit 1
fi
grep -q "another deployment transition holds the lock" \
  "${workdir}/logs/transition-lock.log" || {
  echo "the held-lock refusal did not name the lock:" >&2
  cat "${workdir}/logs/transition-lock.log" >&2
  exit 1
}
[[ "$(readlink "${lock_libexec}/current")" == "${lock_current}" ]] || {
  echo "a lock-refused upgrade still moved the current release" >&2
  kill "${lock_holder}" 2>/dev/null || true
  exit 1
}
# The digest reader participates in the same lock, shared side: while a
# transition holds it exclusively the read is a named refusal -- a document
# captured between the two symlink writes could describe a deployment that
# never existed.
if "${lock_libexec}/helpers/mcloving-deployed-digests" --home "${lock_home}" \
  > "${workdir}/logs/digests-under-lock.log" 2>&1; then
  echo "the digest reader ran while a transition held the lock exclusively" >&2
  kill "${lock_holder}" 2>/dev/null || true
  exit 1
fi
grep -q "a deployment transition is in progress" \
  "${workdir}/logs/digests-under-lock.log" || {
  echo "the under-transition digest refusal was not named:" >&2
  cat "${workdir}/logs/digests-under-lock.log" >&2
  kill "${lock_holder}" 2>/dev/null || true
  exit 1
}
kill "${lock_holder}" 2>/dev/null || true
wait "${lock_holder}" 2>/dev/null || true
# Shared holders coexist: a concurrent digest read must not block another.
( exec 200>>"${lock_libexec}/.transition-lock" \
  && flock -s -n 200 \
  && exec sleep 60 ) &
shared_holder=$!
sleep 0.3
"${lock_libexec}/helpers/mcloving-deployed-digests" --home "${lock_home}" >/dev/null || {
  echo "a shared lock holder blocked a digest read" >&2
  kill "${shared_holder}" 2>/dev/null || true
  exit 1
}
kill "${shared_holder}" 2>/dev/null || true
wait "${shared_holder}" 2>/dev/null || true
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${lock_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${lock_libexec}/current")" != "${lock_current}" ]] || {
  echo "the released lock did not admit the same transition" >&2
  exit 1
}
rm -rf "${lock_home}"
mkdir -p "${linktrap_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${linktrap_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
linktrap_libexec="${linktrap_home}/.local/libexec/mcloving"
linktrap_current="$(readlink "${linktrap_libexec}/current")"
linktrap_idb="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  release_id "${release2_dir}"
)"
mkdir -p "${linktrap_home}/evil-parent"
cp -r "${release2_dir}" "${linktrap_home}/evil-parent/tree"
chmod 0777 "${linktrap_home}/evil-parent"
ln -s "../../../../evil-parent/tree" "${linktrap_libexec}/releases/${linktrap_idb}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${linktrap_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/linktrap.log" 2>&1; then
  echo "upgrade adopted a symlinked retained release directory" >&2
  exit 1
fi
grep -q "releases/${linktrap_idb} is a symlink" "${workdir}/logs/linktrap.log" || {
  echo "the symlinked retained target was refused for the wrong reason:" >&2
  cat "${workdir}/logs/linktrap.log" >&2
  exit 1
}
[[ "$(readlink "${linktrap_libexec}/current")" == "${linktrap_current}" ]] || {
  echo "a refused symlinked retained target still moved the current release" >&2
  exit 1
}
rm -f "${linktrap_libexec}/releases/${linktrap_idb}"
rm -rf "${linktrap_home}/evil-parent"
# Legitimate upgrade, then tamper with the links rollback trusts.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${linktrap_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
linktrap_previous="$(readlink "${linktrap_libexec}/previous")"
ln -sfn "../evil-rel" "${linktrap_libexec}/previous"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${linktrap_home}" \
  --no-systemd > "${workdir}/logs/linktrap-rollback.log" 2>&1; then
  echo "rollback followed a previous link pointing outside releases/" >&2
  exit 1
fi
grep -q "not a releases/<id> entry" "${workdir}/logs/linktrap-rollback.log" || {
  echo "the escaping previous link was refused for the wrong reason:" >&2
  cat "${workdir}/logs/linktrap-rollback.log" >&2
  exit 1
}
ln -sfn "${linktrap_previous}" "${linktrap_libexec}/previous"
mv "${linktrap_libexec}/${linktrap_previous}" "${linktrap_libexec}/releases/.aside"
ln -s ".aside" "${linktrap_libexec}/${linktrap_previous}"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${linktrap_home}" \
  --no-systemd > "${workdir}/logs/linktrap-rollback2.log" 2>&1; then
  echo "rollback followed a symlinked release entry" >&2
  exit 1
fi
grep -q "is itself a symlink" "${workdir}/logs/linktrap-rollback2.log" || {
  echo "the symlinked release entry was refused for the wrong reason:" >&2
  cat "${workdir}/logs/linktrap-rollback2.log" >&2
  exit 1
}
rm -f "${linktrap_libexec}/${linktrap_previous}"
mv "${linktrap_libexec}/releases/.aside" "${linktrap_libexec}/${linktrap_previous}"
"${repo_root}/deploy/bin/mcloving-rollback" --home "${linktrap_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${linktrap_libexec}/current")" == "${linktrap_previous}" ]] || {
  echo "rollback did not restore the validated previous release" >&2
  exit 1
}
rm -rf "${linktrap_home}"
mkdir -p "${collision_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${collision_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
collision_libexec="${collision_home}/.local/libexec/mcloving"
collision_current="$(readlink "${collision_libexec}/current")"
collision_id="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  release_id "${release2_dir}"
)"
mkdir -p "${collision_libexec}/releases/${collision_id}"
for imposter in mcloving-controller mcloving-agent mcloving-cli mcloving-identity-admin; do
  printf 'imposter %s\n' "${imposter}" \
    > "${collision_libexec}/releases/${collision_id}/${imposter}"
  chmod 0755 "${collision_libexec}/releases/${collision_id}/${imposter}"
done
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${collision_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/collision.log" 2>&1; then
  echo "upgrade adopted a retained release tree whose bytes differ from the verified staging" >&2
  exit 1
fi
grep -q "does not match the newly verified bytes" "${workdir}/logs/collision.log" || {
  echo "the colliding retained tree was refused for the wrong reason:" >&2
  cat "${workdir}/logs/collision.log" >&2
  exit 1
}
[[ "$(readlink "${collision_libexec}/current")" == "${collision_current}" ]] || {
  echo "a refused colliding upgrade still moved the current release" >&2
  exit 1
}
grep -q "imposter mcloving-cli" \
  "${collision_libexec}/releases/${collision_id}/mcloving-cli" || {
  echo "the refusal altered the pre-existing tree it refused to adopt" >&2
  exit 1
}
rm -rf "${collision_home}"
mkdir -p "${retain_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${retain_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
retain_libexec="${retain_home}/.local/libexec/mcloving"
retain_id="$(basename "$(readlink "${retain_libexec}/current")")"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${retain_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${retain_libexec}/previous")" == "releases/${retain_id}" ]] || {
  echo "upgrade did not retain the first release as previous" >&2
  exit 1
}
if "${repo_root}/deploy/bin/mcloving-install" --home "${retain_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install accepted a release differing from the current one" >&2
  exit 1
fi
[[ -d "${retain_libexec}/releases/${retain_id}" ]] || {
  echo "a refused install destroyed the retained rollback release" >&2
  exit 1
}
rm -rf "${retain_home}"

# stage_release's stdout is a protocol its callers parse. A diagnostic written
# there is indistinguishable from the result, and was being parsed as one: the
# status came back as "verified" and the path as the rest of that sentence.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  protocol_home="${workdir}/protocol-home"
  rm -rf "${protocol_home}"
  mkdir -p "${protocol_home}/.local/libexec/mcloving"
  line="$(stage_release "${protocol_home}/.local/libexec/mcloving" "${release_dir}" \
    "" "${workdir}/checksums.sha256" 2>/dev/null)"
  [[ "$(printf '%s' "${line}" | wc -l)" -eq 0 ]] || {
    echo "stage_release emitted more than one line on stdout: ${line}" >&2
    exit 1
  }
  [[ "${line%% *}" == "published" ]] || {
    echo "stage_release status parsed as ${line%% *}, not published" >&2
    exit 1
  }
  [[ -d "${line#* }" ]] || {
    echo "stage_release path did not parse to a directory: ${line#* }" >&2
    exit 1
  }
  rm -rf "${protocol_home}"
)

# The bootstrap migrates through MCLOVING_MIGRATION_DATABASE_URL and provisions
# through the container fields, so a URL naming a different database would
# migrate one and modify another.
db_mismatch="${home}/db-mismatch.env"
cp "${config_dir}/db-init.env" "${db_mismatch}"
sed -i "s#^MCLOVING_POSTGRES_DB=.*#MCLOVING_POSTGRES_DB=someotherdb#" "${db_mismatch}"
if "${libexec}/helpers/mcloving-env-guard" db-init "${db_mismatch}" >/dev/null 2>&1; then
  echo "env guard accepted a bootstrap whose URL and container name different databases" >&2
  exit 1
fi
rm -f "${db_mismatch}"

# Deployment directories must not inherit a permissive umask. World-writable
# releases or helpers lets another local user rename a verified binary out and
# a chosen one in -- code execution as the service account with every file
# still 0755.
umask_home="${workdir}/umask-home"
rm -rf "${umask_home}"
mkdir -p "${umask_home}"
( umask 000
  "${repo_root}/deploy/bin/mcloving-install" --home "${umask_home}" \
    --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
    --no-systemd >/dev/null )
for guarded_dir in \
  "${umask_home}/.local/libexec/mcloving" \
  "${umask_home}/.local/libexec/mcloving/helpers" \
  "${umask_home}/.local/libexec/mcloving/releases" \
  "${umask_home}/.local/libexec/mcloving/current" \
  "${umask_home}/.config/mcloving" \
  "${umask_home}/.config/systemd/user" \
  "${umask_home}/.config/containers/systemd"; do
  mode="$(stat -Lc '%a' "${guarded_dir}")"
  case "${mode}" in
    *[2367])
      echo "deployment directory ${guarded_dir} is group- or world-writable (${mode})" >&2
      exit 1
      ;;
  esac
done
rm -rf "${umask_home}"

# A PRE-EXISTING writable ancestor is repaired by neither the umask nor the
# chmods on the managed roots: the install must refuse it by name, create
# nothing under it, and accept the same home once the ancestor is secured.
preexisting_home="${workdir}/preexisting-home"
rm -rf "${preexisting_home}"
mkdir -p "${preexisting_home}/.local"
chmod 0777 "${preexisting_home}/.local"
if "${repo_root}/deploy/bin/mcloving-install" --home "${preexisting_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/preexisting-ancestor.log" 2>&1; then
  echo "install accepted a pre-existing world-writable ancestor" >&2
  exit 1
fi
grep -q "group- or world-writable" "${workdir}/logs/preexisting-ancestor.log" || {
  echo "the writable-ancestor refusal fired for the wrong reason:" >&2
  cat "${workdir}/logs/preexisting-ancestor.log" >&2
  exit 1
}
grep -q "\.local (mode 777)" "${workdir}/logs/preexisting-ancestor.log" || {
  echo "the writable-ancestor refusal did not name the offender and its mode:" >&2
  cat "${workdir}/logs/preexisting-ancestor.log" >&2
  exit 1
}
if [[ -e "${preexisting_home}/.local/libexec" ]]; then
  echo "a refused install still created deployment directories" >&2
  exit 1
fi
chmod 0755 "${preexisting_home}/.local"
"${repo_root}/deploy/bin/mcloving-install" --home "${preexisting_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${preexisting_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete after the ancestor was secured" >&2
  exit 1
}
rm -rf "${preexisting_home}"

# The TARGET of a symlinked ancestor has parents of its own -- the fourth
# instance of the ancestor class. With ~/.local -> stash/dot-local, checking
# the target directory itself while never walking stash leaves the one
# rename that swaps the whole deployment aside unexamined. The install must
# refuse a writable target parent by name, create nothing, and accept the
# same home once it is secured; the digest inventory must record it and
# change when its mode changes.
relocated_home="${workdir}/relocated-home"
rm -rf "${relocated_home}"
mkdir -p "${relocated_home}/stash/dot-local"
ln -s "stash/dot-local" "${relocated_home}/.local"
chmod 0777 "${relocated_home}/stash"
if "${repo_root}/deploy/bin/mcloving-install" --home "${relocated_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/relocated-ancestor.log" 2>&1; then
  echo "install accepted a symlinked ancestor whose target parent is world-writable" >&2
  exit 1
fi
grep -q "stash (mode 777)" "${workdir}/logs/relocated-ancestor.log" || {
  echo "the writable target-parent refusal did not name the offender:" >&2
  cat "${workdir}/logs/relocated-ancestor.log" >&2
  exit 1
}
if [[ -e "${relocated_home}/stash/dot-local/libexec" ]]; then
  echo "a refused install still created directories under the symlink target" >&2
  exit 1
fi
chmod 0755 "${relocated_home}/stash"
"${repo_root}/deploy/bin/mcloving-install" --home "${relocated_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${relocated_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete through a secured symlinked ancestor" >&2
  exit 1
}
# The inventory side of the same class: the resolved target's parent must be
# a recorded ancestor, and relaxing it must change the canonical document.
relocated_before="$("${relocated_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${relocated_home}")"
chmod 0777 "${relocated_home}/stash"
relocated_after="$("${relocated_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${relocated_home}")"
chmod 0755 "${relocated_home}/stash"
if [[ "${relocated_before}" == "${relocated_after}" ]]; then
  echo "a world-writable symlink-target parent left the digest re-read unchanged" >&2
  exit 1
fi
python3 - "${relocated_after}" <<'TARGETPARENT'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("ancestors", [])}
entry = records.get("stash")
if entry is None:
    raise SystemExit(
        f"symlink-target parent missing from the ancestors: {sorted(records)}"
    )
if entry.get("mode") != 0o777:
    raise SystemExit(f"symlink-target parent mode not recorded: {entry}")
TARGETPARENT
rm -rf "${relocated_home}"

# Ownership is the fifth face of the same class: a chain component owned by
# a third user is unsafe at ANY mode, because its owner can chmod it
# writable at will and then rename children like any writable ancestor
# permits. `podman unshare chown` writes a REAL foreign uid (the first
# subuid) to disk without root, and the suite already requires rootless
# podman, so this gate exercises genuine ownership rather than a stub.
foreign_home="${workdir}/foreign-owner-home"
rm -rf "${foreign_home}"
mkdir -p "${foreign_home}/.local"
podman unshare chown 1:1 "${foreign_home}/.local"
if "${repo_root}/deploy/bin/mcloving-install" --home "${foreign_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/foreign-owner.log" 2>&1; then
  echo "install accepted an ancestor owned by a third user" >&2
  exit 1
fi
grep -q "\.local (owned by uid .*, expected uid $(id -u) or root)" \
  "${workdir}/logs/foreign-owner.log" || {
  echo "the foreign-owner refusal did not name the component and uids:" >&2
  cat "${workdir}/logs/foreign-owner.log" >&2
  exit 1
}
if [[ -e "${foreign_home}/.local/libexec" ]]; then
  echo "a refused install still created directories under a foreign-owned ancestor" >&2
  exit 1
fi
podman unshare chown 0:0 "${foreign_home}/.local"
"${repo_root}/deploy/bin/mcloving-install" --home "${foreign_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${foreign_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete after ownership was restored" >&2
  exit 1
}
rm -rf "${foreign_home}"

# systemd, not the installer, creates the StateDirectory= leaves under
# ~/.local/state -- so the validator derives those roots from the staged
# unit declarations themselves, and a pre-existing writable state ancestor
# must refuse the install even though no install command ever touches it.
state_home="${workdir}/state-ancestor-home"
rm -rf "${state_home}"
mkdir -p "${state_home}/.local/state"
chmod 0777 "${state_home}/.local/state"
if "${repo_root}/deploy/bin/mcloving-install" --home "${state_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/state-ancestor.log" 2>&1; then
  echo "install accepted a pre-existing world-writable runtime-state ancestor" >&2
  exit 1
fi
grep -q "\.local/state (mode 777)" "${workdir}/logs/state-ancestor.log" || {
  echo "the state-ancestor refusal did not name the directory and mode:" >&2
  cat "${workdir}/logs/state-ancestor.log" >&2
  exit 1
}
chmod 0755 "${state_home}/.local/state"
"${repo_root}/deploy/bin/mcloving-install" --home "${state_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${state_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete after the state ancestor was secured" >&2
  exit 1
}
rm -rf "${state_home}"

# The user manager honors XDG_CONFIG_HOME (the unit search root moves) and
# XDG_STATE_HOME (StateDirectory leaves are created there), so the lane
# derives every base the same way: units and quadlets land where systemctl
# --user actually looks, the units-declared state roots are validated in
# the tree systemd will actually use, and the inventory walks the same
# dirs. Contracts stay at %h/.config/mcloving -- the literal text of the
# units' EnvironmentFile= lines, which %h-expansion keeps XDG-independent.
# A relative XDG value is ignored exactly as systemd ignores it.
xdg_home="${workdir}/xdg-home"
rm -rf "${xdg_home}"
mkdir -p "${xdg_home}/custom-config" "${xdg_home}/custom-state"
chmod 0777 "${xdg_home}/custom-state"
if XDG_CONFIG_HOME="${xdg_home}/custom-config" \
  XDG_STATE_HOME="${xdg_home}/custom-state" \
  "${repo_root}/deploy/bin/mcloving-install" --home "${xdg_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/xdg-state-ancestor.log" 2>&1; then
  echo "install accepted a world-writable custom XDG state root" >&2
  exit 1
fi
grep -q "custom-state (mode 777)" "${workdir}/logs/xdg-state-ancestor.log" || {
  echo "the custom-state refusal did not name the derived tree:" >&2
  cat "${workdir}/logs/xdg-state-ancestor.log" >&2
  exit 1
}
chmod 0755 "${xdg_home}/custom-state"
XDG_CONFIG_HOME="${xdg_home}/custom-config" \
  XDG_STATE_HOME="${xdg_home}/custom-state" \
  "${repo_root}/deploy/bin/mcloving-install" --home "${xdg_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -f "${xdg_home}/custom-config/systemd/user/mcloving-controller.service" ]] || {
  echo "units were not written under the manager's XDG configuration root" >&2
  exit 1
}
[[ -f "${xdg_home}/custom-config/containers/systemd/mcloving-postgres.container" ]] || {
  echo "quadlets were not written under the manager's XDG configuration root" >&2
  exit 1
}
[[ ! -e "${xdg_home}/.config/systemd/user/mcloving-controller.service" ]] || {
  echo "units were duplicated under the hard-coded default root" >&2
  exit 1
}
[[ -f "${xdg_home}/.config/mcloving/agent.env" ]] || {
  echo "contracts left %h/.config/mcloving, where the units' own text points" >&2
  exit 1
}
xdg_digests="$(XDG_CONFIG_HOME="${xdg_home}/custom-config" \
  XDG_STATE_HOME="${xdg_home}/custom-state" \
  "${xdg_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${xdg_home}")"
python3 - "${xdg_digests}" <<'XDGUNITS'
import json
import sys

document = json.loads(sys.argv[1])
paths = {record["path"] for record in document.get("units", [])}
if not any(p.endswith("custom-config/systemd/user/mcloving-controller.service") for p in paths):
    raise SystemExit(f"inventory did not walk the XDG unit root: {sorted(paths)}")
XDGUNITS
xdg_state_roots="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${xdg_home}/.local/libexec/mcloving/helpers/mcloving-deploy-lib.sh"
  XDG_STATE_HOME="${xdg_home}/custom-state" deployment_unit_declared_roots \
    "${xdg_home}" "${repo_root}"/deploy/systemd/*.service \
    | while IFS= read -r encoded_root; do
        [[ -n "${encoded_root}" ]] || continue
        base64 -d <<<"${encoded_root}"
        echo
      done
)"
grep -q "^${xdg_home}/custom-state/mcloving-agent/workspace$" <<<"${xdg_state_roots}" || {
  echo "the declared-roots parser did not follow XDG_STATE_HOME:" >&2
  printf '%s\n' "${xdg_state_roots}" >&2
  exit 1
}
rm -rf "${xdg_home}"
# A relative XDG value is ignored, exactly as systemd ignores it.
relative_xdg_home="${workdir}/relative-xdg-home"
rm -rf "${relative_xdg_home}"
mkdir -p "${relative_xdg_home}"
XDG_CONFIG_HOME="relative-config" XDG_STATE_HOME="also/relative" \
  "${repo_root}/deploy/bin/mcloving-install" --home "${relative_xdg_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -f "${relative_xdg_home}/.config/systemd/user/mcloving-controller.service" ]] || {
  echo "a relative XDG_CONFIG_HOME was not ignored like systemd ignores it" >&2
  exit 1
}
[[ ! -e "${relative_xdg_home}/relative-config" ]] || {
  echo "a relative XDG_CONFIG_HOME was honored as a path" >&2
  exit 1
}
rm -rf "${relative_xdg_home}"
# An absolute XDG base inherited from ANOTHER account's environment -- the
# CI runner's exported XDG_CONFIG_HOME was exactly this -- must be ignored
# for an alternate target home: it describes nobody's view of that tree,
# and honoring it wrote a scratch deployment's units into the runner's
# real configuration root.
foreign_xdg_home="${workdir}/foreign-xdg-home"
rm -rf "${foreign_xdg_home}" "${workdir}/foreign-config"
mkdir -p "${foreign_xdg_home}"
XDG_CONFIG_HOME="${workdir}/foreign-config" \
  "${repo_root}/deploy/bin/mcloving-install" --home "${foreign_xdg_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -f "${foreign_xdg_home}/.config/systemd/user/mcloving-controller.service" ]] || {
  echo "a foreign XDG base kept units out of the target home's default root" >&2
  exit 1
}
[[ ! -e "${workdir}/foreign-config" ]] || {
  echo "an install honored an XDG base belonging to another account's tree" >&2
  exit 1
}
rm -rf "${foreign_xdg_home}"

# One realpath of the whole root keeps only the FINAL chain. With
# .local -> srv-a/user-local and user-local/libexec -> opt-m/libexec, the
# opt-m chain is walked but srv-a is the directory whose writability lets
# another user replace user-local wholesale -- so the derivation resolves
# component by component and every intermediate target's parents join the
# set. Refused writable by name, accepted once secured, and visible to the
# digest inventory in both states.
twohop_home="${workdir}/twohop-home"
rm -rf "${twohop_home}"
mkdir -p "${twohop_home}/srv-a/user-local" "${twohop_home}/opt-m/libexec"
chmod 0755 "${twohop_home}" "${twohop_home}/srv-a" "${twohop_home}/srv-a/user-local" \
  "${twohop_home}/opt-m" "${twohop_home}/opt-m/libexec"
ln -s "srv-a/user-local" "${twohop_home}/.local"
ln -s "${twohop_home}/opt-m/libexec" "${twohop_home}/srv-a/user-local/libexec"
chmod 0777 "${twohop_home}/srv-a"
if "${repo_root}/deploy/bin/mcloving-install" --home "${twohop_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/twohop.log" 2>&1; then
  echo "install accepted a writable intermediate symlink-target parent" >&2
  exit 1
fi
grep -q "srv-a (mode 777)" "${workdir}/logs/twohop.log" || {
  echo "the intermediate target-parent refusal did not name srv-a:" >&2
  cat "${workdir}/logs/twohop.log" >&2
  exit 1
}
if [[ -e "${twohop_home}/opt-m/libexec/mcloving" ]]; then
  echo "a refused install still created directories through the two-hop chain" >&2
  exit 1
fi
chmod 0755 "${twohop_home}/srv-a"
"${repo_root}/deploy/bin/mcloving-install" --home "${twohop_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${twohop_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete through the secured two-hop chain" >&2
  exit 1
}
twohop_before="$("${twohop_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${twohop_home}")"
chmod 0777 "${twohop_home}/srv-a"
twohop_after="$("${twohop_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${twohop_home}")"
chmod 0755 "${twohop_home}/srv-a"
if [[ "${twohop_before}" == "${twohop_after}" ]]; then
  echo "a relaxed intermediate target parent left the digest re-read unchanged" >&2
  exit 1
fi
python3 - "${twohop_after}" <<'TWOHOP'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("ancestors", [])}
entry = records.get("srv-a")
if entry is None:
    raise SystemExit(f"intermediate target parent missing: {sorted(records)}")
if entry.get("mode") != 0o777:
    raise SystemExit(f"intermediate target parent mode not recorded: {entry}")
if "opt-m" not in records:
    raise SystemExit(f"final target parent missing: {sorted(records)}")
TWOHOP
twohop_restored="$("${twohop_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${twohop_home}")"
[[ "${twohop_before}" == "${twohop_restored}" ]] || {
  echo "the two-hop re-read did not return to baseline" >&2
  exit 1
}
rm -rf "${twohop_home}"

# pki heads a subtree of keys and certificates and is created and secured by
# this installer, so it is a managed root in its own right: a pre-existing
# pki symlink must have its target chain judged -- writable parent and
# foreign-owned parent refused by name, secured chain accepted.
pki_home="${workdir}/pki-link-home"
rm -rf "${pki_home}"
mkdir -p "${pki_home}/shared/pki" "${pki_home}/.config/mcloving"
chmod 0755 "${pki_home}" "${pki_home}/shared" "${pki_home}/shared/pki" \
  "${pki_home}/.config" "${pki_home}/.config/mcloving"
ln -s "../../shared/pki" "${pki_home}/.config/mcloving/pki"
chmod 0777 "${pki_home}/shared"
if "${repo_root}/deploy/bin/mcloving-install" --home "${pki_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/pki-link.log" 2>&1; then
  echo "install accepted a pki symlink whose target parent is world-writable" >&2
  exit 1
fi
grep -q "shared (mode 777)" "${workdir}/logs/pki-link.log" || {
  echo "the pki target-parent refusal did not name shared:" >&2
  cat "${workdir}/logs/pki-link.log" >&2
  exit 1
}
chmod 0755 "${pki_home}/shared"
podman unshare chown 1:1 "${pki_home}/shared"
if "${repo_root}/deploy/bin/mcloving-install" --home "${pki_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/pki-link-owner.log" 2>&1; then
  echo "install accepted a pki symlink whose target parent is foreign-owned" >&2
  exit 1
fi
grep -q "shared (owned by uid .*, expected uid $(id -u) or root)" \
  "${workdir}/logs/pki-link-owner.log" || {
  echo "the pki foreign-owner refusal did not name shared and the uids:" >&2
  cat "${workdir}/logs/pki-link-owner.log" >&2
  exit 1
}
podman unshare chown 0:0 "${pki_home}/shared"
"${repo_root}/deploy/bin/mcloving-install" --home "${pki_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${pki_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete with a secured pki symlink" >&2
  exit 1
}
[[ "$(stat -Lc '%a' "${pki_home}/.config/mcloving/pki")" == "700" ]] || {
  echo "the pki symlink target was not secured to 0700" >&2
  exit 1
}
rm -rf "${pki_home}"

# A PRESERVED contract may be a pre-existing symlink: `-f` follows it, the
# preserve branch keeps it, and whoever can write its target chain -- or
# the resolved target file itself -- controls the environment systemd
# loads. The contract destinations are therefore validated as roots (chain)
# and as files (mode/ownership), in both directions.
ctlink_home="${workdir}/contract-link-home"
rm -rf "${ctlink_home}"
mkdir -p "${ctlink_home}/ext" "${ctlink_home}/.config/mcloving"
chmod 0755 "${ctlink_home}" "${ctlink_home}/ext" \
  "${ctlink_home}/.config" "${ctlink_home}/.config/mcloving"
printf 'PRESERVED_MARKER=%s\n' "${suffix}" > "${ctlink_home}/ext/agent.env"
chmod 0600 "${ctlink_home}/ext/agent.env"
ln -s "${ctlink_home}/ext/agent.env" "${ctlink_home}/.config/mcloving/agent.env"
chmod 0777 "${ctlink_home}/ext"
if "${repo_root}/deploy/bin/mcloving-install" --home "${ctlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/contract-link.log" 2>&1; then
  echo "install preserved a contract symlink whose target parent is world-writable" >&2
  exit 1
fi
grep -q "ext (mode 777)" "${workdir}/logs/contract-link.log" || {
  echo "the contract target-parent refusal did not name ext:" >&2
  cat "${workdir}/logs/contract-link.log" >&2
  exit 1
}
chmod 0755 "${ctlink_home}/ext"
chmod 0666 "${ctlink_home}/ext/agent.env"
if "${repo_root}/deploy/bin/mcloving-install" --home "${ctlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/contract-file-mode.log" 2>&1; then
  echo "install preserved a world-writable contract file" >&2
  exit 1
fi
grep -q "agent.env (mode 666, expected owner-only)" \
  "${workdir}/logs/contract-file-mode.log" || {
  echo "the writable contract-file refusal did not name the file and mode:" >&2
  cat "${workdir}/logs/contract-file-mode.log" >&2
  exit 1
}
# Read bits are secrets too: 0644 exposes database passwords and API tokens
# to every user on the host even though nobody else can write the file.
chmod 0644 "${ctlink_home}/ext/agent.env"
if "${repo_root}/deploy/bin/mcloving-install" --home "${ctlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/contract-file-read.log" 2>&1; then
  echo "install preserved a group/other-readable secret-bearing contract" >&2
  exit 1
fi
grep -q "agent.env (mode 644, expected owner-only)" \
  "${workdir}/logs/contract-file-read.log" || {
  echo "the readable contract-file refusal did not name the file and mode:" >&2
  cat "${workdir}/logs/contract-file-read.log" >&2
  exit 1
}
chmod 0600 "${ctlink_home}/ext/agent.env"
podman unshare chown 1:1 "${ctlink_home}/ext/agent.env"
if "${repo_root}/deploy/bin/mcloving-install" --home "${ctlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/contract-file-owner.log" 2>&1; then
  echo "install preserved a foreign-owned contract file" >&2
  exit 1
fi
grep -q "agent.env (owned by uid .*, expected uid $(id -u) or root)" \
  "${workdir}/logs/contract-file-owner.log" || {
  echo "the foreign-owned contract-file refusal did not name the file and uids:" >&2
  cat "${workdir}/logs/contract-file-owner.log" >&2
  exit 1
}
# The same subuid-owned 0600 file is genuinely unreadable by this user, so
# the availability annotation must appear beside the ownership one:
# writability and ownership guard substitution, readability guards
# availability, and an install must accept no contract the runtime cannot
# read.
grep -q "agent.env (unreadable by uid $(id -u))" \
  "${workdir}/logs/contract-file-owner.log" || {
  echo "the unreadable contract-file refusal did not name the file and uid:" >&2
  cat "${workdir}/logs/contract-file-owner.log" >&2
  exit 1
}
podman unshare chown 0:0 "${ctlink_home}/ext/agent.env"
"${repo_root}/deploy/bin/mcloving-install" --home "${ctlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -L "${ctlink_home}/.config/mcloving/agent.env" ]] || {
  echo "install replaced a secured preserved contract symlink" >&2
  exit 1
}
grep -q "PRESERVED_MARKER=${suffix}" "${ctlink_home}/.config/mcloving/agent.env" || {
  echo "install did not preserve the secured contract's content" >&2
  exit 1
}
rm -rf "${ctlink_home}"

# The managed-roots list stays honest mechanically: an install is traced
# with xtrace, every directory-touching command's path under its home is
# parsed from the trace, and each must be covered by the very root set the
# installer passed to require_secure_ancestors -- itself read from the same
# trace, so there is no second copy of the list to drift.
trace_home="${workdir}/trace-home"
rm -rf "${trace_home}"
mkdir -p "${trace_home}"
bash -x "${repo_root}/deploy/bin/mcloving-install" --home "${trace_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > /dev/null 2> "${workdir}/logs/install-trace.log"
python3 - "${workdir}/logs/install-trace.log" "${trace_home}" <<'TRACECOVER'
import shlex
import sys

trace_path, home = sys.argv[1], sys.argv[2]
home = home.rstrip("/")
prefix = home + "/"
roots = None
touched = set()
commands = {"mkdir", "chmod", "install", "ln"}
for raw in open(trace_path, encoding="utf-8", errors="replace"):
    line = raw.lstrip()
    if not line.startswith("+"):
        continue
    line = line.lstrip("+ ").rstrip("\n")
    try:
        tokens = shlex.split(line)
    except ValueError:
        continue
    if not tokens:
        continue
    if tokens[0] == "require_secure_ancestors":
        roots = [token for token in tokens[2:] if token.startswith(prefix)]
        continue
    if tokens[0] not in commands:
        continue
    for token in tokens[1:]:
        if token.startswith(prefix):
            touched.add(token.rstrip("/"))
if not roots:
    raise SystemExit("trace never showed require_secure_ancestors with its roots")
if not touched:
    raise SystemExit("trace parsing found no touched paths; the xtrace format drifted")
if not any(path.endswith("/pki") for path in touched):
    raise SystemExit(f"expected core paths missing from the parsed trace: {sorted(touched)}")
if not any("/.local/state/" in root for root in roots):
    raise SystemExit(
        "no units-derived runtime-state root reached the ancestor walk; "
        "the unit-declaration parser has gone blind: " + " ".join(sorted(roots))
    )
uncovered = []
for path in sorted(touched):
    covered = path == home or any(
        path == root or path.startswith(root + "/") or root.startswith(path + "/")
        for root in roots
    )
    if not covered:
        uncovered.append(path)
if uncovered:
    raise SystemExit(
        "installer touches paths not covered by its validated roots: "
        + " ".join(uncovered)
    )
TRACECOVER
rm -rf "${trace_home}"

# A RELATIVE --home must see exactly what the absolute spelling sees. The
# component walk used to anchor resolution at "/", so relative-home/.local
# was inspected as /relative-home/.local -- a tree that does not exist --
# and an install through a relative home accepted a symlinked .local whose
# target parent was world-writable. Refusal through the relative spelling,
# acceptance once secured, and document identity across both spellings.
relative_home_name="relative-home"
relative_home="${workdir}/${relative_home_name}"
rm -rf "${relative_home}"
mkdir -p "${relative_home}/stash/dot-local"
chmod 0755 "${relative_home}" "${relative_home}/stash" "${relative_home}/stash/dot-local"
ln -s "stash/dot-local" "${relative_home}/.local"
chmod 0777 "${relative_home}/stash"
if ( cd "${workdir}" && "${repo_root}/deploy/bin/mcloving-install" \
  --home "${relative_home_name}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd ) > "${workdir}/logs/relative-home.log" 2>&1; then
  echo "a relative --home install accepted a writable symlink-target parent" >&2
  exit 1
fi
grep -q "stash (mode 777)" "${workdir}/logs/relative-home.log" || {
  echo "the relative-home refusal did not name the target parent:" >&2
  cat "${workdir}/logs/relative-home.log" >&2
  exit 1
}
chmod 0755 "${relative_home}/stash"
( cd "${workdir}" && "${repo_root}/deploy/bin/mcloving-install" \
  --home "${relative_home_name}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd ) >/dev/null
[[ -x "${relative_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete through a relative --home once secured" >&2
  exit 1
}
relative_doc="$( cd "${workdir}" && "${relative_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${relative_home_name}" )"
absolute_doc="$("${relative_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${relative_home}")"
if [[ "${relative_doc}" != "${absolute_doc}" ]]; then
  echo "the canonical document differs between relative and absolute --home spellings" >&2
  exit 1
fi
rm -rf "${relative_home}"

# The bootstrap's two halves must address one instance, not merely one database
# name: provisioning runs podman exec into the local container.
for bad_url in "postgres://mcloving:pw@remote.example:5432/mcloving" \
  "postgres://someoneelse:pw@127.0.0.1:5432/mcloving"; do
  endpoint_contract="${home}/endpoint.env"
  cp "${config_dir}/db-init.env" "${endpoint_contract}"
  sed -i "s#^MCLOVING_MIGRATION_DATABASE_URL=.*#MCLOVING_MIGRATION_DATABASE_URL=${bad_url}#" \
    "${endpoint_contract}"
  if "${libexec}/helpers/mcloving-env-guard" db-init "${endpoint_contract}" >/dev/null 2>&1; then
    echo "env guard accepted a bootstrap URL addressing ${bad_url}" >&2
    exit 1
  fi
  rm -f "${endpoint_contract}"
done

# The controller migrates through one URL and opens its runtime pool through
# the other, so both must name one database instance, not merely distinct roles.
for endpoint_edit in \
  "s#\(^MCLOVING_DATABASE_URL=.*127.0.0.1\):[0-9]*#\\1:6543#" \
  "s#\(^MCLOVING_DATABASE_URL=.*\)/mcloving\$#\\1/otherdb#"; do
  endpoint_contract="${home}/controller-endpoint.env"
  cp "${config_dir}/controller.env" "${endpoint_contract}"
  sed -i "${endpoint_edit}" "${endpoint_contract}"
  if cmp -s "${endpoint_contract}" "${config_dir}/controller.env"; then
    echo "controller endpoint gate did not modify the contract; shape changed" >&2
    exit 1
  fi
  if "${libexec}/helpers/mcloving-env-guard" controller "${endpoint_contract}" >/dev/null 2>&1; then
    echo "env guard accepted controller URLs addressing different databases" >&2
    exit 1
  fi
  rm -f "${endpoint_contract}"
done

# A readable directory is not a readable file. `-r` alone accepts one, and the
# binary would then fail at startup on a contract the guard called satisfied.
dir_contract="${home}/dir-contract.env"
cp "${config_dir}/agent.env" "${dir_contract}"
sed -i "s#^MCLOVING_AGENT_PRIVATE_KEY_PATH=.*#MCLOVING_AGENT_PRIVATE_KEY_PATH=${config_dir}/pki#" \
  "${dir_contract}"
if "${libexec}/helpers/mcloving-env-guard" agent "${dir_contract}" >/dev/null 2>&1; then
  echo "env guard accepted a directory where a regular file is required" >&2
  exit 1
fi
rm -f "${dir_contract}"

# Staging must not survive a refused install. verify_release_dir exits through
# deploy_fail, which ends the command-substitution subshell, so cleanup has to
# be a trap; otherwise unverified binaries stay under releases/.staging.* and
# the digest re-read reports them as part of the release inventory.
staging_home="${workdir}/staging-home"
rm -rf "${staging_home}"
mkdir -p "${staging_home}"
if "${repo_root}/deploy/bin/mcloving-install" --home "${staging_home}" \
  --release-dir "${tampered_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install accepted a tampered release" >&2
  exit 1
fi
if compgen -G "${staging_home}/.local/libexec/mcloving/releases/.staging.*" >/dev/null; then
  echo "a refused install left unverified binaries under releases/.staging.*" >&2
  exit 1
fi
rm -rf "${staging_home}"

# Publication must fail loudly. Both callers run stage_release inside command
# substitution, where bash clears errexit, so a failed mv would otherwise fall
# through and report a staged release that is not there -- after the upgrade
# has already stopped the services.
blocked_release="${workdir}/blocked-release"
rm -rf "${blocked_release}"
cp -r "${release_dir}" "${blocked_release}"
blocked_home="${workdir}/blocked-home"
rm -rf "${blocked_home}"
mkdir -p "${blocked_home}/.local/libexec/mcloving/releases"
blocked_id="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  release_id "${blocked_release}"
)"
# A regular file sitting where the release directory must go.
printf 'not a directory\n' > "${blocked_home}/.local/libexec/mcloving/releases/${blocked_id}"
if "${repo_root}/deploy/bin/mcloving-install" --home "${blocked_home}" \
  --release-dir "${blocked_release}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install reported success when the release could not be published" >&2
  exit 1
fi
if [[ -e "${blocked_home}/.local/libexec/mcloving/current" ]]; then
  echo "a failed publication still produced a current release" >&2
  exit 1
fi
rm -rf "${blocked_home}" "${blocked_release}"

# systemd accepts a quoted multiline value that ends in a newline and passes it
# to the service intact. A guard reading contracts through command substitution
# would silently validate the value without it and report a contract satisfied
# that the binary then refuses, so the reader must reproduce the exact bytes.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  declare -gA MCLOVING_CONTRACT
  MCLOVING_CONTRACT[NEWLINE_PATH]=$'/tmp/key.pem\n'
  contract_into exact NEWLINE_PATH
  # shellcheck disable=SC2154  # contract_into assigns through a nameref
  [[ "${exact}" == $'/tmp/key.pem\n' ]] || {
    echo "contract reader dropped a trailing newline systemd would supply" >&2
    exit 1
  }
)

# Distinct database roles are not enough: the controller requires the runtime
# session role to be exactly mcloving_tenant, so a second privileged role must
# be refused before anything binds a listener.
tenant_swap="${home}/tenant-swap.env"
cp "${config_dir}/controller.env" "${tenant_swap}"
sed -i "s#\(^MCLOVING_DATABASE_URL=.*\)mcloving_tenant#\1mcloving_admin#" "${tenant_swap}"
if grep -q "mcloving_admin" "${tenant_swap}"; then
  if "${libexec}/helpers/mcloving-env-guard" controller "${tenant_swap}" >/dev/null 2>&1; then
    echo "env guard accepted a runtime role other than mcloving_tenant" >&2
    exit 1
  fi
else
  echo "tenant-role gate could not rewrite MCLOVING_DATABASE_URL; contract shape changed" >&2
  exit 1
fi
rm -f "${tenant_swap}"

# `stat()` succeeding does not mean the bytes can be read. A contract whose
# mode or ACL withdrew access is drift, and losing the whole canonical document
# to it would deny CUTOVER-001 the re-read exactly when it matters.
echo "locked" > "${config_dir}/locked.env"
chmod 000 "${config_dir}/locked.env"
if [[ -r "${config_dir}/locked.env" ]]; then
  # Running as root (or under a permissive ACL) defeats mode 000, so the gate
  # cannot be asserted here. Say so rather than passing silently.
  echo "NOTE: ${config_dir}/locked.env is still readable at mode 000; skipping the unreadable-file gate" >&2
  rm -f "${config_dir}/locked.env"
else
  unreadable_digests="$(timeout 60 "${libexec}/helpers/mcloving-deployed-digests" --home "${home}")" || {
    echo "digest re-read failed on an unreadable file instead of recording it" >&2
    rm -f "${config_dir}/locked.env"
    exit 1
  }
  rm -f "${config_dir}/locked.env"
  python3 - "${unreadable_digests}" <<'UNREADABLE'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
entry = [item for item in contracts if item["path"].endswith("/locked.env")]
if not entry:
    raise SystemExit("unreadable file missing from the re-read")
if entry[0].get("kind") != "unreadable":
    raise SystemExit(f"unreadable file recorded as {entry[0]}")
if entry[0].get("reason") != "permission_denied":
    raise SystemExit(f"unreadable file recorded without its reason: {entry[0]}")
if "sha256" in entry[0]:
    raise SystemExit("unreadable file was recorded with a digest it could not compute")
UNREADABLE
fi

# A symlinked unit root must survive the mcloving-* name filter: the root is
# named `user`, so filtering it out would leave the document unchanged while
# systemd read an entirely different tree.
unit_root="${smoke_unit_root}"
cp -a "${unit_root}" "${unit_root}.alias"
mv "${unit_root}" "${unit_root}.real"
ln -s "user.alias" "${unit_root}"
unit_alias_digests="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
rm -f "${unit_root}"
rm -rf "${unit_root}.alias"
mv "${unit_root}.real" "${unit_root}"
python3 - "${unit_alias_digests}" <<'UNITROOT'
import json
import sys

document = json.loads(sys.argv[1])
units = document.get("units", [])
entry = [item for item in units if item["path"] == ".config/systemd/user"]
if not entry:
    raise SystemExit("symlinked unit root missing from the re-read")
if entry[0].get("kind") != "directory_symlink":
    raise SystemExit(f"unit root recorded as {entry[0]}")
if entry[0].get("symlink_target") != "user.alias":
    raise SystemExit(f"unit root recorded without its target: {entry[0]}")
UNITROOT

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

# The recovery command is printed to be copied and run. A service account home
# containing a space or a shell metacharacter must survive that round trip, so
# the emitted text is evaluated against stub helpers that record their argv.
quoted_home="${workdir}/od d & home"
quoted_libexec="${quoted_home}/.local/libexec/mcloving"
mkdir -p "${quoted_libexec}/helpers"
for stub in mcloving-deployed-digests mcloving-rollback; do
  cat > "${quoted_libexec}/helpers/${stub}" <<STUB
#!/usr/bin/env bash
printf '%s\n' "\$#" > "${quoted_libexec}/${stub}.argc"
printf '%s\n' "\$2" > "${quoted_libexec}/${stub}.home"
STUB
  chmod +x "${quoted_libexec}/helpers/${stub}"
done
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  eval "$(recovery_command "${quoted_libexec}" "${quoted_home}")"
)
for stub in mcloving-deployed-digests mcloving-rollback; do
  [[ "$(cat "${quoted_libexec}/${stub}.argc")" == "2" ]] || {
    echo "recovery command split the ${stub} arguments: got $(cat "${quoted_libexec}/${stub}.argc")" >&2
    exit 1
  }
  [[ "$(cat "${quoted_libexec}/${stub}.home")" == "${quoted_home}" ]] || {
    echo "recovery command mangled the --home value for ${stub}" >&2
    exit 1
  }
done

# Under --no-systemd the units resolve %h to the invoking user's home, not to
# --home, so telling the operator to start them would start an unrelated
# deployment or fail on units that are not there.
alternate_home="${workdir}/alternate-home"
mkdir -p "${alternate_home}"
alternate_output="$("${repo_root}/deploy/bin/mcloving-install" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --home "${alternate_home}" --no-systemd)"
if grep -q -- "systemctl --user enable" <<<"${alternate_output}"; then
  echo "install told an alternate-home deployment to start the invoking user's units" >&2
  exit 1
fi
grep -q "did not touch systemd" <<<"${alternate_output}" || {
  echo "install gave no operable next step for --no-systemd" >&2
  exit 1
}
# The prescribed recovery path must carry the reload: a --no-systemd rerun
# replaces assets but cannot reload the manager, so both the changed-assets
# diagnostic and the --no-systemd epilogue must tell the operator to
# daemon-reload before starting units, or the manager starts cached
# previous configuration.
grep -q "daemon-reload" <<<"${alternate_output}" || {
  echo "the --no-systemd epilogue does not prescribe daemon-reload" >&2
  exit 1
}
grep -q "daemon-reload so the manager" "${repo_root}/deploy/bin/mcloving-install" || {
  echo "the changed-assets diagnostic does not prescribe daemon-reload" >&2
  exit 1
}

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
