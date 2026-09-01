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

usage() {
  echo "usage: run-systemd-ci.sh RUNTIME_GATE RELEASE_DIR CHECKSUMS" >&2
  exit 64
}

[[ $# -eq 3 ]] || usage
runtime_gate="$(readlink -f "$1")"
release_dir="$(readlink -f "$2")"
checksums="$(readlink -f "$3")"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ -x "${runtime_gate}" ]] || { echo "runtime gate is not executable: ${runtime_gate}" >&2; exit 1; }
[[ -d "${release_dir}" ]] || { echo "release directory is absent: ${release_dir}" >&2; exit 1; }
[[ -f "${checksums}" ]] || { echo "checksums are absent: ${checksums}" >&2; exit 1; }
for command_name in systemctl loginctl podman busctl mount findmnt useradd userdel; do
  command -v "${command_name}" >/dev/null 2>&1 \
    || { echo "required command is absent: ${command_name}" >&2; exit 1; }
done
[[ -x /usr/lib/systemd/user-generators/podman-user-generator ]] \
  || { echo "the packaged Podman user generator is absent" >&2; exit 1; }

account=mcloving-ci
home_dir=/home/mcloving-ci
vendor_root=/run/mcloving-ci/vendor-user-units
manager_dropin=""
uid=""
generator_masks=()
vendor_mounted=0
account_created=0
proof_started_epoch="$(date +%s)"

diagnostics() {
  [[ -n "${uid}" ]] || return 0
  local runtime_dir="/run/user/${uid}" bus="unix:path=/run/user/${uid}/bus"
  echo "== systemd-arm diagnostics"
  sudo -u "${account}" env HOME="${home_dir}" XDG_RUNTIME_DIR="${runtime_dir}" \
    DBUS_SESSION_BUS_ADDRESS="${bus}" systemctl --user show -p UnitPath --value 2>&1 || true
  sudo -u "${account}" env HOME="${home_dir}" XDG_RUNTIME_DIR="${runtime_dir}" \
    DBUS_SESSION_BUS_ADDRESS="${bus}" systemctl --user status \
      mcloving-postgres.service mcloving-postgres-data-volume.service \
      mcloving-db-init.service \
      mcloving-controller.service mcloving-agent.service --no-pager -n 80 2>&1 || true
  sudo journalctl _UID="${uid}" --since "@${proof_started_epoch}" \
    --no-pager -n 300 2>&1 || true
  sudo -u "${account}" env HOME="${home_dir}" XDG_RUNTIME_DIR="${runtime_dir}" \
    DBUS_SESSION_BUS_ADDRESS="${bus}" podman ps -a 2>&1 || true
  sudo -u "${account}" env HOME="${home_dir}" XDG_RUNTIME_DIR="${runtime_dir}" \
    DBUS_SESSION_BUS_ADDRESS="${bus}" podman logs mcloving-postgres 2>&1 || true
  findmnt -T "${vendor_root}" 2>&1 || true
  systemd --version | head -1 || true
  podman --version || true
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
runtime_dir="/run/user/${uid}"
bus_address="unix:path=${runtime_dir}/bus"
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
sudo -u "${account}" install -d -m 0755 "${absent_bound_parent}"
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
printf '[Service]\nEnvironment="SYSTEMD_UNIT_PATH=%s"\nEnvironment="QUADLET_UNIT_DIRS=%s"\n' \
  "${unit_path}" "${quadlet_path}" > "${dropin_tmp}"
sudo install -m 0644 "${dropin_tmp}" "${manager_dropin}"
rm -f -- "${dropin_tmp}"

# Only the packaged Quadlet generator may populate the controlled generator
# output directory. Refuse a higher-precedence replacement and mask unrelated
# generator basenames for this disposable runner after the fallback smoke has
# already completed.
sudo install -d -m 0755 /run/systemd/user-generators
for generator_dir in /run/systemd/user-generators /etc/systemd/user-generators /usr/local/lib/systemd/user-generators; do
  [[ ! -e "${generator_dir}/podman-user-generator" ]] \
    || { echo "higher-precedence Podman user generator exists at ${generator_dir}" >&2; exit 1; }
done
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
    [[ "${generator_name}" == podman-user-generator ]] && continue
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
  if sudo -u "${account}" env HOME="${home_dir}" XDG_RUNTIME_DIR="${runtime_dir}" \
    DBUS_SESSION_BUS_ADDRESS="${bus_address}" \
    systemctl --user show-environment >/dev/null 2>&1; then
    manager_ready=1
    break
  fi
  sleep 0.5
done
[[ "${manager_ready:-0}" == 1 ]] \
  || { echo "user manager did not answer an authenticated query" >&2; exit 1; }

user_env=(sudo -u "${account}" env HOME="${home_dir}" XDG_RUNTIME_DIR="${runtime_dir}"
  DBUS_SESSION_BUS_ADDRESS="${bus_address}" PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  MCLOVING_CLEAN_PODMAN_BY_CONSTRUCTION=1
  MCLOVING_EXPECT_UNIT_PATH_WITH_SPACE="${space_unit_root}"
  MCLOVING_EXPECT_ABSENT_UNIT_PATH_PARENT="${absent_bound_parent}")
actual_unit_path="$("${user_env[@]}" systemctl --user show -p UnitPath --value)"
[[ -n "${actual_unit_path}" ]] \
  || { echo "controlled manager returned an empty UnitPath" >&2; exit 1; }
manager_environment="$("${user_env[@]}" systemctl --user show-environment)"
grep -qx "QUADLET_UNIT_DIRS=${quadlet_path}" <<<"${manager_environment}" \
  || { echo "manager did not retain the exact Quadlet source boundary" >&2; exit 1; }
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
"${user_env[@]}" test -x "${runtime_gate}"
"${user_env[@]}" test -x "${gate_controller}"
"${user_env[@]}" test -r "${release_dir}/mcloving-controller"

echo "controlled manager: uid=${uid} UnitPath=${actual_unit_path} Quadlet=${quadlet_path}"
"${user_env[@]}" bash "${repo_root}/deploy/test-deployment-systemd.sh" \
  --release-dir "${release_dir}" --checksums "${checksums}" \
  --runtime-gate "${runtime_gate}"
