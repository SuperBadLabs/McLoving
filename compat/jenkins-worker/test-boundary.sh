#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
IMAGE=${1:-localhost/mcloving/jenkins-compiler-worker:mario-jenkins-oracle-228-v1}
EXPECTED_PROFILE=243e40cca38b4e789f81dbfd004470b2338b3af402e9dda97e467ee4f788bb41
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/mcloving-compiler-test.XXXXXXXX")
CONTAINER_ID=

cleanup() {
  if [[ -n "$CONTAINER_ID" ]]; then
    podman rm --force "$CONTAINER_ID" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

printf 'pipeline { agent any; stages { stage("Build") { steps { echo "ok" } } } }\n' \
  > "$TEST_ROOT/Jenkinsfile"

first=$("$SCRIPT_DIR/run-worker.sh" compile "$TEST_ROOT/Jenkinsfile" boundary-a)
second=$("$SCRIPT_DIR/run-worker.sh" compile "$TEST_ROOT/Jenkinsfile" boundary-a)
[[ "$first" == "$second" ]]
grep -q ':status :unsupported' <<<"$first"
grep -q 'E_COMPILER_SUBSET_NOT_IMPLEMENTED' <<<"$first"
grep -q ':effects false' <<<"$first"

probe=$("$SCRIPT_DIR/run-worker.sh" probe boundary-probe)
grep -q ':status :ok' <<<"$probe"
grep -q ':network false' <<<"$probe"
grep -q ":profile-sha256 \"$EXPECTED_PROFILE\"" <<<"$probe"

ln -s "$TEST_ROOT/Jenkinsfile" "$TEST_ROOT/symlink"
if "$SCRIPT_DIR/run-worker.sh" compile "$TEST_ROOT/symlink" boundary-symlink \
  >"$TEST_ROOT/symlink.out" 2>"$TEST_ROOT/symlink.err"; then
  echo "symlink source was not rejected" >&2
  exit 1
fi

dd if=/dev/zero of="$TEST_ROOT/oversize" bs=262145 count=1 status=none
if "$SCRIPT_DIR/run-worker.sh" compile "$TEST_ROOT/oversize" boundary-oversize \
  >"$TEST_ROOT/oversize.out" 2>"$TEST_ROOT/oversize.err"; then
  echo "oversize source was not rejected" >&2
  exit 1
fi

# shellcheck source=worker-podman-options.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/worker-podman-options.sh"
poison_marker=MCLOVING-DO-NOT-LEAK-7a1983
poison_request=$(printf \
  '{:operation :probe :protocol "mcloving.jenkins.compiler/1" :request-id "boundary-env" :target-profile-sha256 "%s"}' \
  "$EXPECTED_PROFILE")
poison_output=$(printf '%s\n' "$poison_request" |
  timeout --signal=KILL 5s \
    podman run --rm \
      "${WORKER_PODMAN_OPTIONS[@]}" \
      --env "DATABASE_PASSWORD=$poison_marker" \
      "$IMAGE")
grep -q 'E_ENV_AUTHORITY' <<<"$poison_output"
if grep -q "$poison_marker" <<<"$poison_output"; then
  echo "secret marker escaped into worker output" >&2
  exit 1
fi

CONTAINER_ID=$(podman create \
  "${WORKER_PODMAN_OPTIONS[@]}" \
  --volume "$TEST_ROOT/Jenkinsfile:/input/Jenkinsfile:ro" \
  --entrypoint /bin/sleep \
  "$IMAGE" 30)
[[ "$(podman inspect "$CONTAINER_ID" --format '{{.HostConfig.NetworkMode}}')" == "none" ]]
[[ "$(podman inspect "$CONTAINER_ID" --format '{{.HostConfig.ReadonlyRootfs}}')" == "true" ]]
[[ "$(podman inspect "$CONTAINER_ID" --format '{{.HostConfig.PidsLimit}}')" == "64" ]]
[[ "$(podman inspect "$CONTAINER_ID" --format '{{.HostConfig.Memory}}')" == "536870912" ]]
cap_drop=$(podman inspect "$CONTAINER_ID" \
  --format '{{range .HostConfig.CapDrop}}{{println .}}{{end}}')
for capability in \
  CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID CAP_KILL \
  CAP_NET_BIND_SERVICE CAP_SETFCAP CAP_SETGID CAP_SETPCAP CAP_SETUID \
  CAP_SYS_CHROOT; do
  grep -qx "$capability" <<<"$cap_drop"
done
[[ "$(wc -l <<<"$cap_drop" | tr -d ' ')" == "11" ]]
[[ "$(podman inspect "$CONTAINER_ID" --format '{{range .Mounts}}{{if eq .Destination "/input/Jenkinsfile"}}{{.RW}}{{end}}{{end}}')" == "false" ]]
[[ "$(podman inspect "$CONTAINER_ID" --format '{{len .Mounts}}')" == "1" ]]
mount_destinations=$(podman inspect "$CONTAINER_ID" \
  --format '{{range .Mounts}}{{println .Destination}}{{end}}' |
  sed '/^$/d' |
  sort)
[[ "$mount_destinations" == "/input/Jenkinsfile" ]]
tmpfs_spec=$(podman inspect "$CONTAINER_ID" \
  --format '{{index .HostConfig.Tmpfs "/tmp"}}')
for option in rw noexec nosuid nodev size=16777216; do
  grep -q "$option" <<<"$tmpfs_spec"
done
podman rm "$CONTAINER_ID" >/dev/null
CONTAINER_ID=

echo "worker-boundary-ok profile=$EXPECTED_PROFILE"
