#!/usr/bin/env bash
set -euo pipefail

fixture_root="$(mktemp -d /tmp/mcloving-dependency-contained.XXXXXX)"
transport_root="${fixture_root}/transport"
mkdir -m 0700 "${transport_root}"

cleanup() {
  sudo umount "${transport_root}" >/dev/null 2>&1 || true
  rmdir "${transport_root}" >/dev/null 2>&1 || true
  rmdir "${fixture_root}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sudo mount -t tmpfs \
  -o "size=16777216,mode=0700,uid=$(id -u),gid=$(id -g),nosuid,nodev,noexec" \
  tmpfs "${transport_root}"

block_count="$(stat -f -c '%b' "${transport_root}")"
fragment_size="$(stat -f -c '%S' "${transport_root}")"
transport_capacity="$((block_count * fragment_size))"

MCLOVING_DEPENDENCY_TRANSPORT_ROOT="${transport_root}" \
MCLOVING_DEPENDENCY_TRANSPORT_CAPACITY="${transport_capacity}" \
MCLOVING_DEPENDENCY_RESOLVER_TEST_MODE=1 \
cargo +1.97.1 test --locked -p mcloving-dependency-resolver \
  --test contained_resolver -- --ignored --nocapture
