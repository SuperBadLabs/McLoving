#!/usr/bin/env bash
set -euo pipefail

prepare_transport_filesystem() {
  local path="$1"
  local bytes="$2"
  local owner_uid owner_gid observed_bytes

  owner_uid="$(id -u)"
  owner_gid="$(id -g)"
  sudo mkdir -p "$path"
  if ! mountpoint --quiet "$path"; then
    sudo mount -t tmpfs \
      -o "size=${bytes},nr_inodes=4096,nosuid,nodev,noexec,mode=0700,uid=${owner_uid},gid=${owner_gid}" \
      tmpfs "$path"
  fi
  if [[ "$(findmnt --noheadings --output FSTYPE --target "$path" | tr -d ' ')" != "tmpfs" ]]; then
    printf 'transport test root is not tmpfs: %s\n' "$path" >&2
    exit 1
  fi
  observed_bytes="$(( $(stat --file-system --format='%b' "$path") * $(stat --file-system --format='%S' "$path") ))"
  if [[ "$observed_bytes" -ne "$bytes" ]]; then
    printf 'transport test root capacity mismatch: path=%s expected=%s observed=%s\n' \
      "$path" "$bytes" "$observed_bytes" >&2
    exit 1
  fi
  sudo chown "$owner_uid:$owner_gid" "$path"
  sudo chmod 0700 "$path"
}

prepare_transport_filesystem /tmp/mcloving-source-transport-16m 16777216
prepare_transport_filesystem /tmp/mcloving-source-transport-512k 524288
printf 'source transport test filesystems are ready\n'
