#!/usr/bin/env bash
# The service-managed arm of the deployment lane.
#
# WHY THIS IS A SEPARATE SCRIPT. `deploy/test-deployment.sh` passes
# `--no-systemd` at every one of its 184 install, upgrade and rollback sites,
# and that is not a flag it chooses -- `require_systemd_home` compares `--home`
# against the passwd database, and the suite installs into `mktemp -d` trees, so
# the flag is forced. Everything systemd would do is instead re-derived in bash:
# `mcloving-unit-command` parses the units and the suite runs their `ExecStart`
# itself. That proves the install, contract, digest and rollback MECHANICS. It
# proves nothing about the lane the units describe, because systemd never
# generates, enables, orders or starts anything in any gate.
#
# `DEPLOY-001`'s acceptance is "a scripted install on a clean host brings up the
# controller and agent", for a lane its own row defines as "systemd units or
# podman quadlets". Closing it on derived-command evidence is the substitution
# the board's receipt rules exist to prevent, which is why the ticket was
# reverted to ACTIVE. This arm is the missing half.
#
# WHAT IT REQUIRES, AND WHY IT REFUSES RATHER THAN SKIPS. It needs a real
# service account: its own passwd home, a running `systemd --user` manager,
# lingering enabled, and working rootless podman. Every one of those is checked
# below and every failure is a refusal by name. A skip here would be worse than
# no arm at all -- the deployable-runtime gate this ticket also names returns
# success when `MCLOVING_TEST_DATABASE_URL` is unset, and a silent skip inside
# an acceptance criterion is exactly the failure this repository is named for.
set -euo pipefail
umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_dir=""
checksums=""
keep=0
runtime_gate=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-dir) release_dir="$2"; shift 2 ;;
    --checksums) checksums="$2"; shift 2 ;;
    --keep) keep=1; shift ;;
    --runtime-gate) runtime_gate="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

fail() { echo "systemd-arm: $1" >&2; exit 1; }
step() { echo "== $1"; }

# ---------------------------------------------------------------------------
step "[1/10] preconditions -- every one refuses, none skips"

[[ -n "${release_dir}" && -d "${release_dir}" ]] \
  || fail "--release-dir must name a staged release directory"
[[ -n "${checksums}" && -f "${checksums}" ]] \
  || fail "--checksums must name a sha256sum file for that release"
# NOT OPTIONAL. DEPLOY-001's acceptance is "brings up the controller and agent
# AND passes the deployable-runtime gate". Making the gate optional here would
# leave the arm able to report success on half the sentence -- which is the
# shape of the very defect the gate itself had.
[[ -n "${runtime_gate}" && -x "${runtime_gate}" ]] \
  || fail "--runtime-gate must name the prebuilt deployable-runtime test binary (cargo test --no-run -p mcloving-controller --test deployable_runtime)"
# ORDERING THAT BIT ONCE: stage the release from the SAME build that produced
# the gate binary. Building the gate rebuilds the controller in the build tree,
# so a release staged earlier no longer matches what the gate will spawn -- and
# step 10 refuses that rather than testing one binary while running another.

account="$(id -un)"
home_dir="$(getent passwd "$(id -u)" | cut -d: -f6)"
[[ -n "${home_dir}" ]] || fail "this account has no passwd home; the lane resolves %h there"
[[ "${HOME}" == "${home_dir}" ]] \
  || fail "HOME (${HOME}) is not this account's passwd home (${home_dir}); systemd expands %h to the passwd home, so a mismatched HOME would install one tree and manage another"

# The one thing that makes this arm different from the other suite: the install
# must be able to run WITHOUT --no-systemd, and that is exactly the condition
# require_systemd_home enforces.
# shellcheck source=deploy/bin/mcloving-deploy-lib.sh
source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
require_systemd_home "${home_dir}" 0 \
  || fail "the deployment home is not this account's passwd home"

[[ "$(loginctl show-user "$(id -u)" --property=Linger 2>/dev/null)" == "Linger=yes" ]] \
  || fail "lingering is not enabled for ${account}; without it the user manager stops at logout and a service-managed deployment is not what the runbook describes"

systemctl --user show -p UnitPath >/dev/null 2>&1 \
  || fail "no reachable systemd --user manager for ${account}; this arm exists to exercise the manager and cannot stand in for it"

[[ -x /usr/lib/systemd/user-generators/podman-user-generator ]] \
  || fail "podman's Quadlet generator is absent; the postgres quadlet cannot become a unit without it"

podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null | grep -qx true \
  || fail "rootless podman is not working for ${account}; the quadlet runs the database as this account"

echo "   account=${account} home=${home_dir} manager=$(systemctl --user is-system-running 2>&1) podman=$(podman --version | awk '{print $3}')"

# START FROM NOTHING, and say so when there was something. A surviving data
# volume carries a password from a previous run and would fail db-init for a
# reason that has nothing to do with the code under test.
if podman volume exists mcloving-postgres-data 2>/dev/null; then
  echo "   removing a data volume left by an earlier run (its password predates this one)"
  podman volume rm -f mcloving-postgres-data >/dev/null 2>&1 || true
  rm -rf "${scratch}" >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
config_base="$(deployment_config_root "${home_dir}")"
unit_root="${config_base}/systemd/user"
quadlet_root="${config_base}/containers/systemd"
libexec_root="${home_dir}/.local/libexec/mcloving"
units=(mcloving-db-init.service mcloving-controller.service mcloving-agent.service)
generated=(mcloving-postgres.service)

scratch="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-d001.XXXXXX")"

teardown() {
  local status=$?
  trap '' INT TERM HUP
  step "teardown"
  systemctl --user stop mcloving-agent.service mcloving-controller.service \
    mcloving-db-init.service mcloving-postgres.service >/dev/null 2>&1 || true
  systemctl --user disable mcloving-agent.service mcloving-controller.service \
    mcloving-db-init.service >/dev/null 2>&1 || true
  podman rm -f mcloving-postgres >/dev/null 2>&1 || true
  # THE VOLUME TOO. Removing the container and leaving the volume makes the
  # NEXT run fail in a way that looks like a lane defect and is not: the
  # cluster keeps the password baked in at initdb, this arm generates a fresh
  # one per run, and db-init then fails with "password authentication failed
  # for user mcloving". Measured, after it happened.
  podman volume rm -f mcloving-postgres-data >/dev/null 2>&1 || true
  if (( keep == 0 )); then
    rm -rf "${libexec_root}" "${config_base}/mcloving" >/dev/null 2>&1 || true
    rm -f "${unit_root}"/mcloving-*.service "${quadlet_root}"/mcloving-* >/dev/null 2>&1 || true
    systemctl --user daemon-reload >/dev/null 2>&1 || true
  else
    echo "   --keep: the deployment under ${home_dir} was left in place"
  fi
  # Honest about what teardown cannot promise: a container the manager started
  # may outlive a SIGKILL of this script, and saying so beats implying otherwise.
  echo "   teardown ran (status ${status}); any surviving mcloving-postgres container is reported, not hidden:"
  podman ps -a --filter name=mcloving-postgres --format '     {{.Names}} {{.Status}}' || true
  exit "${status}"
}
trap teardown EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# ---------------------------------------------------------------------------
step "[2/10] scripted install to the passwd home, WITHOUT --no-systemd"

"${repo_root}/deploy/bin/mcloving-install" --home "${home_dir}" \
  --release-dir "${release_dir}" --checksums "${checksums}"
echo "   installed into ${libexec_root}"

# ---------------------------------------------------------------------------
step "[3/10] the manager knows the installed units"

# `mcloving-install` runs `systemctl --user daemon-reload` only when it is NOT
# given --no-systemd, so this is the first gate anywhere that the reload
# happened at all. Asked of the manager, not of the filesystem: a unit file on
# disk that the manager has not loaded is precisely the state a missing reload
# leaves behind, and `ls` cannot tell the two apart.
for unit in "${units[@]}"; do
  state="$(systemctl --user show -p LoadState --value "${unit}" 2>/dev/null || true)"
  [[ "${state}" == "loaded" ]] \
    || fail "${unit} is ${state:-unknown} to the manager after install; either the unit was not written or daemon-reload did not run"
  echo "   ${unit} LoadState=${state}"
done

# ---------------------------------------------------------------------------
step "[4/10] Quadlet generated the postgres unit, and the library's model agrees"

# THE POINT OF THIS GATE. `deployment_quadlet_generated_name` MODELS podman's
# .container -> .service naming in bash, and the other suite tests that model
# against a hard-coded table whose comment says "verified against
# /usr/libexec/podman/quadlet's actual output" -- verified once, by hand, in a
# comment. Here the generator actually runs, and the model is checked against
# what it produced rather than against a remembered example.
for unit in "${generated[@]}"; do
  state="$(systemctl --user show -p LoadState --value "${unit}" 2>/dev/null || true)"
  [[ "${state}" == "loaded" ]] \
    || fail "${unit} was not generated from ${quadlet_root}/mcloving-postgres.container; Quadlet either did not run or named it something else"
  echo "   ${unit} LoadState=${state} (generated)"
done
modelled="$(deployment_quadlet_generated_name mcloving-postgres.container)"
[[ "${modelled}" == "mcloving-postgres.service" ]] \
  || fail "the library models mcloving-postgres.container as ${modelled}, but the generator produced mcloving-postgres.service; the model and the generator disagree"
echo "   library model agrees with the generator: ${modelled}"

# ---------------------------------------------------------------------------
step "[5/10] systemd resolved the ordering the units declare"

# Ordering is the thing the other suite most conspicuously cannot prove: it
# achieves the sequence by writing the steps one after another in bash, so
# Requires=/After= are asserted by nobody. Read back from the manager.
requires="$(systemctl --user show -p Requires --value mcloving-controller.service)"
after="$(systemctl --user show -p After --value mcloving-controller.service)"
[[ "${requires}" == *"mcloving-db-init.service"* ]] \
  || fail "the manager does not report mcloving-controller.service requiring mcloving-db-init.service; it reported: ${requires}"
[[ "${after}" == *"mcloving-postgres.service"* ]] \
  || fail "the manager does not order mcloving-controller.service after mcloving-postgres.service; it reported: ${after}"
echo "   controller Requires=${requires}"
echo "   controller After=${after}"

agent_after="$(systemctl --user show -p After --value mcloving-agent.service)"
[[ "${agent_after}" == *"mcloving-controller.service"* ]] \
  || fail "the manager does not order mcloving-agent.service after mcloving-controller.service; it reported: ${agent_after}"
echo "   agent After=${agent_after}"

# ---------------------------------------------------------------------------
step "[6/10] the runbook's own enable command must work"

# THE GATE THAT FOUND A SHIPPED DEFECT. `mcloving-install` prints, and
# docs/operations/DEPLOYMENT_V1.md step 5 documents,
#   systemctl --user enable --now mcloving-postgres mcloving-db-init ...
# and that command FAILS: `mcloving-postgres.service` is generated by Quadlet
# and systemd refuses to enable a generated unit --
#   "Unit .../generator/mcloving-postgres.service is transient or generated."
# Quadlet honours the quadlet's own `[Install] WantedBy=default.target`, so the
# generated unit needs starting, not enabling. Nothing could have found this
# without running systemctl, which is the entire argument for this arm.
#
# So the documented sequence is asserted here, as a command, rather than
# trusted as prose.
documented=(mcloving-db-init mcloving-controller mcloving-agent)
systemctl --user enable "${documented[@]}" \
  || fail "the documented enable command failed for ${documented[*]}"
for unit in "${documented[@]}"; do
  enabled="$(systemctl --user is-enabled "${unit}.service" 2>&1 || true)"
  [[ "${enabled}" == "enabled" ]] \
    || fail "${unit}.service reports is-enabled=${enabled} after the documented enable"
done
# And the generated one must NOT be enablable -- pinning the reason the runbook
# had to change, so a future edit cannot quietly put it back.
if systemctl --user enable mcloving-postgres >/dev/null 2>&1; then
  fail "systemd accepted 'enable mcloving-postgres'; the runbook's original wording would then have been correct and this gate is now wrong"
fi
echo "   enabled: ${documented[*]}; mcloving-postgres refuses enable (generated), as expected"

# ---------------------------------------------------------------------------
step "[7/10] contracts, PKI and enrollment"

config="${config_base}/mcloving"
pki="${config}/pki"
organization_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
project_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
superuser_password="d001-$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
tenant_password="d001-$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
api_token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
artifact_token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
agent_id="deploy001-agent"

openssl req -new -newkey rsa:2048 -nodes -x509 -days 1 -subj "/CN=mcloving-d001-ca" \
  -keyout "${pki}/ca-key.pem" -out "${pki}/ca.pem" 2>/dev/null
printf 'subjectAltName=DNS:controller.internal,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "${pki}/server.ext"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=controller.internal" \
  -keyout "${pki}/controller-server-key.pem" -out "${pki}/server.csr" 2>/dev/null
openssl x509 -req -days 1 -in "${pki}/server.csr" -CA "${pki}/ca.pem" -CAkey "${pki}/ca-key.pem" \
  -CAcreateserial -extfile "${pki}/server.ext" -out "${pki}/controller-server.pem" 2>/dev/null
printf 'extendedKeyUsage=clientAuth\n' > "${pki}/agent.ext"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${agent_id}" \
  -keyout "${pki}/agent-key.pem" -out "${pki}/agent.csr" 2>/dev/null
openssl x509 -req -days 1 -in "${pki}/agent.csr" -CA "${pki}/ca.pem" -CAkey "${pki}/ca-key.pem" \
  -CAcreateserial -extfile "${pki}/agent.ext" -out "${pki}/agent.pem" 2>/dev/null
cp "${pki}/ca.pem" "${pki}/agent-ca.pem"
cp "${pki}/ca.pem" "${pki}/controller-ca.pem"

openssl x509 -in "${pki}/agent.pem" -outform DER -out "${pki}/agent.der" 2>/dev/null
agent_cert_sha256="$(sha256sum "${pki}/agent.der" | awk '{print $1}')"
printf '%s %s trusted-linux %s\n' "${agent_cert_sha256}" "${agent_id}" "${organization_id}" \
  > "${config}/agent-identity-bindings.txt"
chmod 0600 "${config}/agent-identity-bindings.txt"

# EVERY SHIPPED PORT AND HOST IS KEPT. The other suite rewrites 5432/8080/8443
# to reserved ports because several of its trees run concurrently; this arm is
# the real lane on a dedicated account, so the shipped defaults are what get
# tested -- including that the quadlet's PublishPort and the contracts agree.
for pair in \
  "__SET_ME_POSTGRES_SUPERUSER_PASSWORD__|${superuser_password}" \
  "__SET_ME_TENANT_PASSWORD__|${tenant_password}" \
  "__SET_ME_API_BEARER_TOKEN_MINIMUM_32_BYTES__|${api_token}" \
  "__SET_ME_DISTINCT_ARTIFACT_TOKEN_MINIMUM_32_BYTES__|${artifact_token}" \
  "__SET_ME_ORGANIZATION_UUID__|${organization_id}" \
  "__SET_ME_ORGANIZATION_SLUG__|d001-org" \
  "__SET_ME_PROJECT_UUID__|${project_id}" \
  "__SET_ME_PROJECT_SLUG__|d001-project" \
  "__SET_ME_AGENT_ID__|${agent_id}"; do
  sed -i "s|${pair%%|*}|${pair#*|}|g" "${config}"/*.env
done
! grep -Eq '__SET_ME_[A-Z0-9_]+__' "${config}"/*.env \
  || fail "a placeholder survived contract rendering: $(grep -Eho '__SET_ME_[A-Z0-9_]+__' "${config}"/*.env | sort -u | tr '\n' ' ')"
echo "   contracts rendered, PKI written, ${agent_id} enrolled"

# The guard is the gate the units run at ExecStartPre; ask it now so a contract
# defect is named here rather than as an opaque unit failure.
"${libexec_root}/helpers/mcloving-env-guard" controller "${config}/controller.env" >/dev/null \
  || fail "the controller contract does not satisfy mcloving-env-guard"
echo "   mcloving-env-guard: controller contract satisfied"
# THE AGENT'S GUARD CANNOT BE PRE-FLIGHTED, and that is a finding rather than an
# inconvenience. It requires MCLOVING_AGENT_WORKSPACE_ROOT to already exist, and
# the only thing that creates it is `StateDirectory=mcloving-agent
# mcloving-agent/workspace` on the unit, which systemd materialises at 0700
# BEFORE any Exec* line. So the agent contract is validated by the unit's own
# ExecStartPre, and asserted below by the unit reaching active.
#
# The other suite has to `mkdir -p` that path by hand, with the comment "Mirror
# what StateDirectory= creates for the real units" -- a hand-made stand-in for
# a systemd feature, which is precisely the coupling this arm exists to replace
# with the real thing. Step 8 asserts systemd created it, and that we did not.
[[ ! -e "${home_dir}/.local/state/mcloving-agent/workspace" ]] \
  || fail "the agent workspace root already exists before any unit ran; this arm must not create what StateDirectory= is supposed to"

# ---------------------------------------------------------------------------
step "[8/10] systemd starts the lane, in the order the units declare"

# `Notify=healthy` on the quadlet means the generated postgres unit reports
# started only once `pg_isready` passes, so `After=mcloving-postgres.service`
# genuinely means "after PostgreSQL is healthy" and no wait loop belongs here.
systemctl --user start mcloving-postgres.service \
  || fail "systemd could not start the generated postgres unit"
systemctl --user start mcloving-db-init.service \
  || fail "systemd could not start mcloving-db-init.service"
systemctl --user start mcloving-controller.service \
  || fail "systemd could not start mcloving-controller.service"
systemctl --user start mcloving-agent.service \
  || fail "systemd could not start mcloving-agent.service"

for unit in mcloving-postgres.service mcloving-controller.service mcloving-agent.service; do
  active="$(systemctl --user show -p ActiveState --value "${unit}")"
  sub="$(systemctl --user show -p SubState --value "${unit}")"
  [[ "${active}" == "active" ]] \
    || fail "${unit} is ${active}/${sub} after start; $(systemctl --user status "${unit}" --no-pager -n 20 2>&1 | tail -20)"
  echo "   ${unit} ${active}/${sub} MainPID=$(systemctl --user show -p MainPID --value "${unit}")"
done
# db-init is Type=oneshot RemainAfterExit=yes: active/exited is its success.
db_init="$(systemctl --user show -p ActiveState --value mcloving-db-init.service)/$(systemctl --user show -p SubState --value mcloving-db-init.service)"
[[ "${db_init}" == "active/exited" ]] \
  || fail "mcloving-db-init.service is ${db_init}, not active/exited"
echo "   mcloving-db-init.service ${db_init}"

# systemd created the agent's state tree, not this script. The other suite
# mkdir -p's this path to stand in for StateDirectory=; here the real directive
# is what made it, at the mode the directive specifies.
workspace="${home_dir}/.local/state/mcloving-agent/workspace"
[[ -d "${workspace}" ]] \
  || fail "StateDirectory= did not create ${workspace}; the agent's guard passed on something this arm cannot account for"
mode="$(stat -c '%a' "${workspace}")"
[[ "${mode}" == "700" ]] \
  || fail "${workspace} is mode ${mode}, not the 0700 StateDirectoryMode= specifies"
echo "   StateDirectory= created ${workspace} at ${mode}, unaided"

# THE STABILITY WINDOW, against real units for the first time. The library's
# require_service_stable samples ActiveState/SubState/MainPID/NRestarts to catch
# a Type=exec unit that execs, exits, and is restarted in a loop by
# Restart=on-failure -- a shape that looks "active" at any single instant. The
# other suite skips this entirely under --no-systemd.
require_service_stable 0 mcloving-controller.service \
  || fail "mcloving-controller.service did not hold steady"
require_service_stable 0 mcloving-agent.service \
  || fail "mcloving-agent.service did not hold steady"
echo "   controller and agent held steady across the sampling window"

# ExecStartPost=mcloving-health on the controller unit means a controller that
# never answers fails the UNIT. Ask the manager, from outside, the way a
# transition does.
"${libexec_root}/helpers/mcloving-health" controller "${config}/controller.env" \
  --unit mcloving-controller.service \
  || fail "mcloving-health could not reach the controller through the manager"
echo "   mcloving-health answered through the manager"

# ---------------------------------------------------------------------------
step "[9/10] service-managed upgrade and rollback"

# Both scripts `exit 0` immediately under --no-systemd, so everything past the
# symlink flip -- stop order, restart order, and the health gates between them --
# has never executed in any gate. Here they run for real.
# A SECOND release, because upgrading to the one already installed is refused
# by name ("release ... is already current; nothing to upgrade") and would prove
# nothing about the transition. A trailing newline on mcloving-cli changes the
# release digest without touching a binary any unit starts -- the same device
# the other suite uses for the same reason.
release2_dir="${scratch}/release2"
cp -r "${release_dir}" "${release2_dir}"
printf '\n' >> "${release2_dir}/mcloving-cli"
( cd "${release2_dir}" && sha256sum mcloving-controller mcloving-agent \
    mcloving-cli mcloving-identity-admin > "${scratch}/checksums2.sha256" )

before_release="$(readlink "${libexec_root}/current")"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${home_dir}" \
  --release-dir "${release2_dir}" --checksums "${scratch}/checksums2.sha256" \
  || fail "service-managed upgrade failed"
after_release="$(readlink "${libexec_root}/current")"
echo "   upgrade: current ${before_release} -> ${after_release}"
for unit in mcloving-controller.service mcloving-agent.service; do
  active="$(systemctl --user show -p ActiveState --value "${unit}")"
  [[ "${active}" == "active" ]] || fail "${unit} is ${active} after the upgrade"
done
echo "   controller and agent active after a service-managed upgrade"

"${repo_root}/deploy/bin/mcloving-rollback" --home "${home_dir}" \
  || fail "service-managed rollback failed"
rolled_back="$(readlink "${libexec_root}/current")"
[[ "${rolled_back}" == "${before_release}" ]] \
  || fail "rollback left current at ${rolled_back}, not the pre-upgrade ${before_release}"
[[ "${after_release}" != "${before_release}" ]] \
  || fail "the upgrade did not change the current release, so the rollback proved nothing"
for unit in mcloving-controller.service mcloving-agent.service; do
  active="$(systemctl --user show -p ActiveState --value "${unit}")"
  [[ "${active}" == "active" ]] || fail "${unit} is ${active} after the rollback"
done
echo "   rollback: current back to ${rolled_back}, both services active"

# ---------------------------------------------------------------------------
step "[10/10] the deployable-runtime gate, against this installed deployment"

# The other half of the acceptance sentence. The gate spawns a controller whose
# path `CARGO_BIN_EXE_mcloving-controller` baked in at compile time, so it runs
# the BUILD TREE's binary rather than the installed one -- which is checkable
# rather than hand-waved: the installed release was staged from that build and
# digest-verified, so the two are byte-identical, and this asserts it instead of
# assuming it.
installed_controller="${libexec_root}/current/mcloving-controller"
gate_controller="$(dirname "$(dirname "${runtime_gate}")")/mcloving-controller"
[[ -x "${installed_controller}" ]] || fail "no installed controller at ${installed_controller}"
if [[ -x "${gate_controller}" ]]; then
  [[ "$(sha256sum < "${installed_controller}")" == "$(sha256sum < "${gate_controller}")" ]] \
    || fail "the controller the gate will spawn is not byte-identical to the installed one; the gate would be testing a different binary than this deployment runs"
  echo "   the gate's controller is byte-identical to the installed one"
else
  echo "   note: could not locate the gate's controller beside ${runtime_gate}; identity unasserted"
fi

# The DATABASE, ROLES and split credentials are this deployment's, read from the
# contract systemd starts the controller with -- not a database the test brought
# up for itself, which is what made this gate and the install two unrelated CI
# jobs sharing no state.
migration_url="$(grep -E '^MCLOVING_MIGRATION_DATABASE_URL=' "${config}/controller.env" | cut -d= -f2-)"
runtime_db_url="$(grep -E '^MCLOVING_DATABASE_URL=' "${config}/controller.env" | cut -d= -f2-)"
[[ -n "${migration_url}" && -n "${runtime_db_url}" ]] \
  || fail "could not read both database URLs from ${config}/controller.env"
[[ "${migration_url}" != "${runtime_db_url}" ]] \
  || fail "the migration and runtime URLs are identical; the split this gate checks does not exist"

MCLOVING_TEST_DATABASE_URL="${migration_url}" \
MCLOVING_TEST_RUNTIME_DATABASE_URL="${runtime_db_url}" \
  "${runtime_gate}" --ignored --test-threads=1 \
  || fail "the deployable-runtime gate failed against this installed deployment"
echo "   deployable-runtime gate passed against the installed deployment's database and roles"

echo
echo "service-managed deployment lane passed: install -> daemon-reload -> quadlet generation ->"
echo "  documented enable -> ordered start -> stability -> health through the manager ->"
echo "  service-managed upgrade -> service-managed rollback -> deployable-runtime gate"
