#!/usr/bin/env bash
# Build-job wrapper for DEPLOY-003's real user-manager arm.
#
# The hosted runner is ephemeral, but a fresh account alone is not a controlled
# input: root-owned UnitPath and user-generator directories are shared with the
# image. This wrapper gives the disposable manager an exact UnitPath, an exact
# Quadlet source path, one read-only vendor-unit bind, and no unrelated user
# generators. It then runs the same service-managed arm used by operators.
set -euo pipefail
umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
controlled_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# shellcheck source=deploy/systemd-ci-lib.sh
source "${repo_root}/deploy/systemd-ci-lib.sh"

if [[ "${1:-}" == --check-host ]]; then
  [[ $# -eq 1 ]] || { echo "usage: run-systemd-ci.sh --check-host" >&2; exit 64; }
  command -v sha256sum >/dev/null 2>&1 \
    || { echo "required command is absent: sha256sum" >&2; exit 1; }
  mcloving_ci_select_podman_generator
  mcloving_ci_print_podman_generator
  exit 0
fi

usage() {
  echo "usage: run-systemd-ci.sh RUNTIME_GATE RELEASE_DIR CHECKSUMS" >&2
  exit 64
}

[[ $# -eq 3 ]] || usage
if (( EUID != 0 )); then
  exec sudo bash "${BASH_SOURCE[0]}" "$@"
fi
runtime_gate="$(readlink -f "$1")"
release_dir="$(readlink -f "$2")"
checksums="$(readlink -f "$3")"

[[ -x "${runtime_gate}" ]] || { echo "runtime gate is not executable: ${runtime_gate}" >&2; exit 1; }
[[ -d "${release_dir}" ]] || { echo "release directory is absent: ${release_dir}" >&2; exit 1; }
[[ -f "${checksums}" ]] || { echo "checksums are absent: ${checksums}" >&2; exit 1; }
for command_name in systemctl loginctl podman busctl jq mount findmnt setpriv useradd userdel sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 \
    || { echo "required command is absent: ${command_name}" >&2; exit 1; }
done
mcloving_ci_select_podman_generator
mcloving_ci_print_podman_generator

account=mcloving-ci
home_dir=/home/mcloving-ci
vendor_root=/run/mcloving-ci/vendor-user-units
manager_dropin=""
uid=""
generator_masks=()
vendor_mounted=0
account_created=0
proof_started_epoch="$(date +%s)"
user_env=()

diagnostics() {
  [[ -n "${uid}" ]] || return 0
  local runtime_dir="/run/user/${uid}"
  echo "== systemd-arm diagnostics"
  (( ${#user_env[@]} > 0 )) || return 0
  "${user_env[@]}" systemctl --user show -p UnitPath --value 2>&1 || true
  "${user_env[@]}" systemctl --user status \
      mcloving-postgres.service mcloving-postgres-data-volume.service \
      mcloving-db-init.service \
      mcloving-controller.service mcloving-agent.service --no-pager -n 80 2>&1 || true
  sudo journalctl _UID="${uid}" --since "@${proof_started_epoch}" \
    --no-pager -n 300 2>&1 || true
  # Podman diagnostics are forbidden here. A wrapper failure can happen before
  # the generated volume unit performs the account's cold first operation;
  # even `podman ps` creates state on supported Podman 4.9 and previously both
  # broke that invariant and obscured the actual pre-arm refusal.
  findmnt -T "${vendor_root}" 2>&1 || true
  systemd --version | head -1 || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  (( status == 0 )) || diagnostics
  if [[ -n "${uid}" ]]; then
    sudo systemctl stop "user@${uid}.service" >/dev/null 2>&1 || true
  fi
  sudo loginctl disable-linger "${account}" >/dev/null 2>&1 || true
  if [[ -n "${manager_dropin}" ]]; then
    sudo rm -f -- "${manager_dropin}" >/dev/null 2>&1 || true
    sudo rmdir -- "${manager_dropin%/*}" >/dev/null 2>&1 || true
  fi
  for mask in "${generator_masks[@]}"; do
    sudo rm -f -- "${mask}" >/dev/null 2>&1 || true
  done
  if (( vendor_mounted )); then
    sudo umount -- "${vendor_root}" >/dev/null 2>&1 || true
  fi
  sudo rmdir -- "${vendor_root}" /run/mcloving-ci >/dev/null 2>&1 || true
  sudo systemctl daemon-reload >/dev/null 2>&1 || true
  if (( account_created )); then
    sudo userdel -r "${account}" >/dev/null 2>&1 || true
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if getent passwd "${account}" >/dev/null; then
  echo "refusing to reuse pre-existing account ${account}" >&2
  exit 1
fi
if [[ -e "${home_dir}" || -L "${home_dir}" ]]; then
  echo "refusing to adopt pre-existing home path ${home_dir}" >&2
  exit 1
fi
sudo useradd --create-home --home-dir "${home_dir}" --shell /bin/bash "${account}"
account_created=1
uid="$(id -u "${account}")"
gid="$(id -g "${account}")"
runtime_dir="/run/user/${uid}"
bus_address="unix:path=${runtime_dir}/bus"
# Invoke account commands through a direct credential transition. Repeated
# `sudo -u` calls open PAM sessions whose pam_systemd hooks can mutate the live
# user-manager environment after it has been sanitized.
manager_private_env=(setpriv
  --reuid="${uid}" --regid="${gid}" --init-groups
  env -i
  HOME="${home_dir}"
  XDG_CONFIG_HOME="${home_dir}/.config"
  XDG_DATA_HOME="${home_dir}/.local/share"
  XDG_STATE_HOME="${home_dir}/.local/state"
  XDG_CACHE_HOME="${home_dir}/.cache"
  XDG_RUNTIME_DIR="${runtime_dir}"
  # systemctl prefers the manager's private socket. Poison its session-bus
  # fallback so a transient private-socket failure cannot activate D-Bus early.
  DBUS_SESSION_BUS_ADDRESS="unix:path=${runtime_dir}/mcloving-no-session-bus"
  USER="${account}" LOGNAME="${account}" SHELL=/bin/bash
  PATH="${controlled_path}" LANG=C.UTF-8)
user_env=("${manager_private_env[@]}" DBUS_SESSION_BUS_ADDRESS="${bus_address}")
if [[ -e "${runtime_dir}" || -L "${runtime_dir}" ]]; then
  echo "refusing to adopt pre-existing runtime path ${runtime_dir}" >&2
  exit 1
fi

# One package-owned vendor tree, mounted read-only at a path that is unique to
# this job. It supplies default.target/dbus.service without admitting any of
# the runner image's /etc, /usr/local, XDG, or global runtime unit paths.
sudo install -d -m 0755 "${vendor_root}"
sudo mount --bind /usr/lib/systemd/user "${vendor_root}"
vendor_mounted=1
sudo mount -o remount,bind,ro /usr/lib/systemd/user "${vendor_root}"

absent_bound_parent="${home_dir}/deploy003 creation parent"
space_unit_root="${absent_bound_parent}/future unit root"
"${manager_private_env[@]}" install -d -m 0755 "${absent_bound_parent}"
unit_path="${home_dir}/.config/systemd/user.control:${runtime_dir}/systemd/user.control:${runtime_dir}/systemd/transient:${runtime_dir}/systemd/generator.early:${home_dir}/.config/systemd/user:${space_unit_root}:${runtime_dir}/systemd/user:${runtime_dir}/systemd/generator:${vendor_root}:${runtime_dir}/systemd/generator.late"
quadlet_custom_root="${home_dir}/.config/containers/deploy003-sources"
quadlet_install_root="${home_dir}/.config/containers/systemd"
quadlet_path="${quadlet_custom_root}:${quadlet_install_root}"
manager_dropin_dir="/etc/systemd/system/user@${uid}.service.d"
manager_dropin="${manager_dropin_dir}/mcloving-ci.conf"
if sudo test -e "${manager_dropin}" || sudo test -L "${manager_dropin}"; then
  echo "refusing to replace pre-existing manager drop-in ${manager_dropin}" >&2
  exit 1
fi
sudo install -d -m 0755 "${manager_dropin_dir}"
dropin_tmp="$(mktemp)"
printf '[Service]\nEnvironment="HOME=%s"\nEnvironment="XDG_CONFIG_HOME=%s/.config"\nEnvironment="XDG_DATA_HOME=%s/.local/share"\nEnvironment="XDG_STATE_HOME=%s/.local/state"\nEnvironment="XDG_CACHE_HOME=%s/.cache"\nEnvironment="XDG_RUNTIME_DIR=%s"\nEnvironment="USER=%s"\nEnvironment="LOGNAME=%s"\nEnvironment="SHELL=/bin/bash"\nEnvironment="PATH=%s"\nEnvironment="LANG=C.UTF-8"\nEnvironment="SYSTEMD_UNIT_PATH=%s"\nEnvironment="QUADLET_UNIT_DIRS=%s"\nUnsetEnvironment=CONTAINER_CONNECTION CONTAINER_HOST CONTAINER_SSHKEY CONTAINERS_CONF CONTAINERS_CONF_OVERRIDE CONTAINERS_STORAGE_CONF CONTAINERS_REGISTRIES_CONF CONTAINERS_REGISTRIES_CONF_DIR CONTAINERS_POLICY CONTAINERS_REGISTRIES_AUTH_FILE STORAGE_DRIVER STORAGE_OPTS REGISTRY_AUTH_FILE DOCKER_CONFIG PODMAN_PREEXEC_HOOKS_DIR\n' \
  "${home_dir}" "${home_dir}" "${home_dir}" "${home_dir}" "${home_dir}" \
  "${runtime_dir}" "${account}" "${account}" "${controlled_path}" \
  "${unit_path}" "${quadlet_path}" \
  > "${dropin_tmp}"
sudo install -m 0644 "${dropin_tmp}" "${manager_dropin}"
rm -f -- "${dropin_tmp}"

# Only the selected version-matched Quadlet generator may populate the controlled generator
# output directory. Refuse a higher-precedence replacement and mask unrelated
# generator basenames for this disposable runner after the fallback smoke has
# already completed.
sudo install -d -m 0755 /run/systemd/user-generators
# A differently named runtime generator already occupies the highest
# precedence directory and cannot be safely hidden by adding another entry at
# the same path. Refuse it; /run is clean on the ephemeral runner by contract.
for generator in /run/systemd/user-generators/*; do
  [[ -e "${generator}" || -L "${generator}" ]] || continue
  generator_name="${generator##*/}"
  [[ "${generator_name}" == podman-user-generator ]] \
    && { echo "higher-precedence Podman user generator exists at ${generator}" >&2; exit 1; }
  [[ -L "${generator}" && "$(readlink "${generator}")" == /dev/null ]] && continue
  echo "uncontrolled runtime user generator exists at ${generator}" >&2
  exit 1
done
declare -A masked_names=()
for generator_dir in /etc/systemd/user-generators /usr/local/lib/systemd/user-generators /usr/lib/systemd/user-generators; do
  [[ -d "${generator_dir}" ]] || continue
  for generator in "${generator_dir}"/*; do
    [[ -e "${generator}" || -L "${generator}" ]] || continue
    generator_name="${generator##*/}"
    if [[ "${generator_name}" == podman-user-generator ]]; then
      [[ "${generator}" == "${MCLOVING_CI_PODMAN_GENERATOR}" ]] \
        || { echo "unselected Podman user generator exists at ${generator}" >&2; exit 1; }
      continue
    fi
    [[ -z "${masked_names["${generator_name}"]:-}" ]] || continue
    mask="/run/systemd/user-generators/${generator_name}"
    [[ ! -e "${mask}" && ! -L "${mask}" ]] \
      || { echo "refusing to replace existing generator mask ${mask}" >&2; exit 1; }
    sudo ln -s /dev/null "${mask}"
    generator_masks+=("${mask}")
    masked_names["${generator_name}"]=1
  done
done

sudo systemctl daemon-reload
sudo loginctl enable-linger "${account}"
sudo systemctl start "user@${uid}.service"
for _ in $(seq 1 60); do
  if "${manager_private_env[@]}" systemctl --user show-environment >/dev/null 2>&1; then
    manager_ready=1
    break
  fi
  sleep 0.5
done
[[ "${manager_ready:-0}" == 1 ]] \
  || { echo "user manager did not answer an authenticated query" >&2; exit 1; }
for _ in $(seq 1 60); do
  manager_running_state="$("${manager_private_env[@]}" systemctl --user is-system-running 2>/dev/null || true)"
  if [[ "${manager_running_state}" == running ]]; then
    manager_startup_complete=1
    break
  fi
  case "${manager_running_state}" in
    initializing | starting | "") sleep 0.1 ;;
    *) echo "fresh user manager entered ${manager_running_state} state during startup" >&2; exit 1 ;;
  esac
done
[[ "${manager_startup_complete:-0}" == 1 ]] \
  || { echo "fresh user manager did not complete startup" >&2; exit 1; }

expected_manager_environment=(
  "HOME=${home_dir}" \
  "XDG_CONFIG_HOME=${home_dir}/.config" \
  "XDG_DATA_HOME=${home_dir}/.local/share" \
  "XDG_STATE_HOME=${home_dir}/.local/state" \
  "XDG_CACHE_HOME=${home_dir}/.cache" \
  "XDG_RUNTIME_DIR=${runtime_dir}" \
  "USER=${account}" "LOGNAME=${account}" "SHELL=/bin/bash" \
  "PATH=${controlled_path}" \
  "LANG=C.UTF-8" \
  "SYSTEMD_UNIT_PATH=${unit_path}" \
  "QUADLET_UNIT_DIRS=${quadlet_path}" \
  "DBUS_SESSION_BUS_ADDRESS=${bus_address}"
)
declare -A expected_manager_environment_names=()
for expected_manager_environment_line in "${expected_manager_environment[@]}"; do
  expected_manager_environment_names["${expected_manager_environment_line%%=*}"]=1
done

# Keep the private manager connection free of D-Bus activation until the
# environment that dbus.service will inherit is exact. Set controlled values
# first, then remove only snapshot extras: no empty or uncontrolled-core window
# is observable, and no generator, reload, or service start occurs between.
"${manager_private_env[@]}" systemctl --user set-environment \
  "${expected_manager_environment[@]}"
# A host user-environment helper may finish just after default.target. Converge
# only while D-Bus is still unavailable, and refuse if the manager does not
# stabilize promptly rather than racing activation against a late import.
for _ in $(seq 1 20); do
  private_manager_environment_json="$("${manager_private_env[@]}" \
    systemctl --user --output=json show-environment)"
  private_manager_environment_names_text="$(jq -er '
    if type == "object"
      and length > 0
      and all(keys[]; test("^[A-Za-z_][A-Za-z0-9_]*$"))
      and all(.[]; type == "string")
    then keys[]
    else error("invalid private manager environment")
    end
  ' <<<"${private_manager_environment_json}")" \
    || { echo "private manager returned an invalid typed environment" >&2; exit 1; }
  mapfile -t private_manager_environment_names \
    <<<"${private_manager_environment_names_text}"
  private_manager_environment_extras=()
  for manager_environment_name in "${private_manager_environment_names[@]}"; do
    if [[ -z "${expected_manager_environment_names["${manager_environment_name}"]:-}" ]]; then
      private_manager_environment_extras+=("${manager_environment_name}")
    fi
  done
  if (( ${#private_manager_environment_extras[@]} == 0 )); then
    break
  fi
  "${manager_private_env[@]}" systemctl --user unset-environment \
    "${private_manager_environment_extras[@]}"
  sleep 0.1
done
private_manager_environment_json="$("${manager_private_env[@]}" \
  systemctl --user --output=json show-environment)"
private_manager_environment_text="$(jq -er '
  if type == "object"
    and all(keys[]; test("^[A-Za-z_][A-Za-z0-9_]*$"))
    and all(.[]; type == "string")
  then to_entries[] | "\(.key)=\(.value)"
  else error("invalid private manager environment")
  end
' <<<"${private_manager_environment_json}")" \
  || { echo "private manager returned an invalid typed environment after replacement" >&2; exit 1; }
mapfile -t private_manager_environment_lines <<<"${private_manager_environment_text}"
if [[ ${#private_manager_environment_lines[@]} -ne ${#expected_manager_environment[@]} ]]; then
  for manager_environment_line in "${private_manager_environment_lines[@]}"; do
    manager_environment_name="${manager_environment_line%%=*}"
    [[ -n "${expected_manager_environment_names["${manager_environment_name}"]:-}" ]] \
      || echo "private manager retained uncontrolled variable ${manager_environment_name}" >&2
  done
  echo "private manager retained variables outside the controlled environment" >&2
  exit 1
fi
for expected_manager_environment_line in "${expected_manager_environment[@]}"; do
  grep -Fqx "${expected_manager_environment_line}" \
    <<<"${private_manager_environment_text}" \
    || { echo "private manager did not retain ${expected_manager_environment_line}" >&2; exit 1; }
done

# D-Bus now inherits only the controlled block. Its activation is state-free
# with respect to Podman and completes before the typed atomic transaction.
"${manager_private_env[@]}" systemctl --user start dbus.service
[[ "$("${manager_private_env[@]}" systemctl --user is-active dbus.service)" == active ]] \
  || { echo "packaged user D-Bus service did not become active" >&2; exit 1; }

# User environment generators may add arbitrary image-account variables after
# the service drop-in is applied. Read names from the typed manager property,
# then atomically replace the whole block with the exact minimal set this arm
# permits. No empty intermediate block is observable and no Podman is invoked.
manager_environment_json="$("${user_env[@]}" busctl --user --json=short \
  get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager Environment)"
manager_environment_names_text="$(jq -er '
  if .type == "as"
    and (.data | type) == "array"
    and (.data | length) > 0
    and all(.data[]; test("^[A-Za-z_][A-Za-z0-9_]*="))
  then .data[] | capture("^(?<name>[A-Za-z_][A-Za-z0-9_]*)=").name
  else error("invalid typed manager environment")
  end
' <<<"${manager_environment_json}")" \
  || { echo "manager returned an invalid typed environment" >&2; exit 1; }
mapfile -t manager_environment_names <<<"${manager_environment_names_text}"
"${user_env[@]}" busctl --user call \
  org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager UnsetAndSetEnvironment asas \
  "${#manager_environment_names[@]}" "${manager_environment_names[@]}" \
  "${#expected_manager_environment[@]}" "${expected_manager_environment[@]}"

user_env+=(MCLOVING_CLEAN_PODMAN_BY_CONSTRUCTION=1
  MCLOVING_PODMAN_USER_GENERATOR="${MCLOVING_CI_PODMAN_GENERATOR}"
  MCLOVING_EXPECT_UNIT_PATH_WITH_SPACE="${space_unit_root}"
  MCLOVING_EXPECT_ABSENT_UNIT_PATH_PARENT="${absent_bound_parent}")
actual_unit_path="$("${user_env[@]}" systemctl --user show -p UnitPath --value)"
[[ -n "${actual_unit_path}" ]] \
  || { echo "controlled manager returned an empty UnitPath" >&2; exit 1; }
manager_environment_json="$("${user_env[@]}" busctl --user --json=short \
  get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager Environment)"
manager_environment_text="$(jq -er '
  if .type == "as" and (.data | type) == "array"
  then .data[]
  else error("invalid typed manager environment")
  end
' <<<"${manager_environment_json}")" \
  || { echo "manager returned an invalid typed environment after replacement" >&2; exit 1; }
mapfile -t manager_environment_lines <<<"${manager_environment_text}"
for manager_environment_line in "${manager_environment_lines[@]}"; do
  manager_environment_name="${manager_environment_line%%=*}"
  [[ -n "${expected_manager_environment_names["${manager_environment_name}"]:-}" ]] \
    || { echo "manager retained uncontrolled variable ${manager_environment_name}" >&2; exit 1; }
done
[[ ${#manager_environment_lines[@]} -eq ${#expected_manager_environment[@]} ]] \
  || { echo "manager retained variables outside the exact controlled environment" >&2; exit 1; }
for expected_manager_environment_line in "${expected_manager_environment[@]}"; do
  grep -Fqx "${expected_manager_environment_line}" <<<"${manager_environment_text}" \
    || { echo "manager did not retain ${expected_manager_environment_line}" >&2; exit 1; }
done
findmnt -n -o OPTIONS -T "${vendor_root}" | tr ',' '\n' | grep -qx ro \
  || { echo "vendor unit bind is not read-only" >&2; exit 1; }
if "${user_env[@]}" test -w "${vendor_root}"; then
  echo "service account can write the vendor unit bind" >&2
  exit 1
fi

# Do not run Podman here. The account is new and its store is absent by
# construction; even a read-only-looking `podman info` or `volume exists`
# creates the persistent rootless pause namespace. The generated volume unit
# must perform the first Podman operation so the arm proves a cold production
# start. The dependent generated container unit's shipped 300-second start
# bound owns the pinned image pull.

# Cargo embeds the absolute controller path in the runtime gate. Prove the
# disposable account can traverse and execute both before starting a 10-step
# arm that would otherwise fail only at its final acceptance gate.
gate_controller="$(dirname "$(dirname "${runtime_gate}")")/mcloving-controller"
"${user_env[@]}" test -x "${runtime_gate}" \
  || { echo "service account cannot traverse and execute runtime gate ${runtime_gate}" >&2; exit 1; }
"${user_env[@]}" test -x "${gate_controller}" \
  || { echo "service account cannot traverse and execute embedded controller ${gate_controller}" >&2; exit 1; }
"${user_env[@]}" test -r "${release_dir}/mcloving-controller" \
  || { echo "service account cannot traverse and read staged release ${release_dir}" >&2; exit 1; }

echo "controlled manager: uid=${uid} UnitPath=${actual_unit_path} Quadlet=${quadlet_path}"
"${user_env[@]}" bash "${repo_root}/deploy/test-deployment-systemd.sh" \
  --release-dir "${release_dir}" --checksums "${checksums}" \
  --runtime-gate "${runtime_gate}"
