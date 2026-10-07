#!/usr/bin/env bash
# Focused AGENT-009 deployment custody adversaries; no Podman/systemd invocation.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
workload_fixture="$(mktemp -d)"
trap 'rm -rf -- "${workload_fixture}"' EXIT
workload_root="${workload_fixture}/podman"
mkdir -p "${workload_root}/.config/containers"
chmod 0700 "${workload_root}" "${workload_root}/.config" "${workload_root}/.config/containers"
restore_configuration() {
  rm -f -- "${workload_root}/containers.conf" "${workload_root}/storage.conf" "${workload_root}/.config/containers/mounts.conf" "${workload_fixture}/alias"
  install -m 0400 "${repo_root}/deploy/podman/workload-containers.conf" "${workload_root}/containers.conf"
  install -m 0400 "${repo_root}/deploy/podman/workload-storage.conf" "${workload_root}/storage.conf"
  install -m 0400 "${repo_root}/deploy/podman/workload-mounts.conf" "${workload_root}/.config/containers/mounts.conf"
}
refused() {
  if (require_workload_podman_configuration "${workload_root}") >"${workload_fixture}/refusal.log" 2>&1; then
    echo "workload Podman custody accepted $1" >&2; exit 1
  fi
}
restore_configuration
require_workload_podman_configuration "${workload_root}"
chmod 0600 "${workload_root}/containers.conf"; refused writable; restore_configuration
ln "${workload_root}/storage.conf" "${workload_fixture}/alias"; refused hardlink; restore_configuration
rm "${workload_root}/containers.conf"; ln -s "${workload_root}/storage.conf" "${workload_root}/containers.conf"; refused symlink; restore_configuration
rm "${workload_root}/storage.conf"; refused missing-companion; restore_configuration
chmod 0600 "${workload_root}/.config/containers/mounts.conf"; printf '/host:/escaped\n' >"${workload_root}/.config/containers/mounts.conf"; chmod 0400 "${workload_root}/.config/containers/mounts.conf"; refused implicit-mount; restore_configuration
chmod 0755 "${workload_root}/.config"; refused public-config-root; chmod 0700 "${workload_root}/.config"
require_workload_podman_configuration "${workload_root}"
# Upgrade and rollback invoke the same integrity function; don't duplicate a
# derived model instead of checking those actual source call sites.
for transition in mcloving-install mcloving-upgrade mcloving-rollback; do
  grep -q 'require_deployment_integrity' "${repo_root}/deploy/bin/${transition}" || { echo "${transition} lost its integrity gate" >&2; exit 1; }
done
printf 'workload-podman-config-ok\n'
