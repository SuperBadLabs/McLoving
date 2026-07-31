#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
IMAGE=${1:-localhost/mcloving/jenkins-compiler-worker:mario-jenkins-oracle-228-v1}
EXPECTED_PROFILE=feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/mcloving-compiler-test.XXXXXXXX")
CONTAINER_ID=

cleanup() {
  if [[ -n "$CONTAINER_ID" ]]; then
    podman rm --force "$CONTAINER_ID" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

ADMITTED_SOURCE="$SCRIPT_DIR/../../migration/mario-jenkins-oracle-228/corpus-v1/sources/cinqict_jenkinsdev.Jenkinsfile"
ADMITTED_JOB=corpus-052-cinqict_jenkinsdev
ADMITTED_GENERATION=e76362bbc8e899510b8498808ffd0d2f83bb64d3215cf2c5b31690895f251d97
cp "$ADMITTED_SOURCE" "$TEST_ROOT/Jenkinsfile"
cargo build --quiet --locked \
  --manifest-path "$SCRIPT_DIR/../../Cargo.toml" \
  -p mcloving-jenkins-compiler-admission

FAKE_BIN="$TEST_ROOT/fake-bin"
mkdir -p "$FAKE_BIN"
ln -s "$SCRIPT_DIR/test/fake-podman.sh" "$FAKE_BIN/podman"
for stream in stdout stderr; do
  stream_tmp="$TEST_ROOT/limit-$stream"
  mkdir -p "$stream_tmp"
  if PATH="$FAKE_BIN:$PATH" \
    TMPDIR="$stream_tmp" \
    FAKE_PODMAN_STREAM="$stream" \
    "$SCRIPT_DIR/run-worker.sh" probe "boundary-limit-$stream" \
    >"$TEST_ROOT/limit-$stream.out" 2>"$TEST_ROOT/limit-$stream.err"; then
    echo "untrusted $stream stream exceeded its bound without rejection" >&2
    exit 1
  fi
  grep -q 'isolated compiler exceeded stream limit' "$TEST_ROOT/limit-$stream.err"
  [[ -z "$(find "$stream_tmp" -mindepth 1 -maxdepth 1 -print -quit)" ]]
done

first=$("$SCRIPT_DIR/run-worker.sh" compile "$TEST_ROOT/Jenkinsfile" boundary-a \
  "$ADMITTED_JOB" "$ADMITTED_GENERATION")
second=$("$SCRIPT_DIR/run-worker.sh" compile "$TEST_ROOT/Jenkinsfile" boundary-a \
  "$ADMITTED_JOB" "$ADMITTED_GENERATION")
[[ "$first" == "$second" ]]
grep -q ':status :compiled' <<<"$first"
grep -q ':state: disabled' <<<"$first" || grep -q 'state: disabled' <<<"$first"
grep -q ':effects false' <<<"$first"
printf '%s\n' "$first" > "$TEST_ROOT/compiled.edn"
cargo run --quiet --locked \
  --manifest-path "$SCRIPT_DIR/../../Cargo.toml" \
  -p mcloving-jenkins-compiler-admission -- \
  "$TEST_ROOT/compiled.edn" "$TEST_ROOT/Jenkinsfile" boundary-a \
  "$ADMITTED_JOB" "$ADMITTED_GENERATION" > "$TEST_ROOT/admission.receipt"
grep -qx 'status=admitted' "$TEST_ROOT/admission.receipt"
grep -qx 'state=disabled' "$TEST_ROOT/admission.receipt"

printf 'pipeline { agent any; stages { stage("Build") { steps { echo "ok" } } } }\n' \
  > "$TEST_ROOT/unsupported.Jenkinsfile"
unsupported=$("$SCRIPT_DIR/run-worker.sh" compile \
  "$TEST_ROOT/unsupported.Jenkinsfile" boundary-unsupported \
  "$ADMITTED_JOB" "$ADMITTED_GENERATION")
grep -q ':status :unsupported' <<<"$unsupported"
grep -q 'E_SOURCE_NOT_ADMITTED' <<<"$unsupported"

sed 's/:effect-authority false/:effect-authority true/' \
  "$TEST_ROOT/compiled.edn" > "$TEST_ROOT/authority-substitution.edn"
if cargo run --quiet --locked \
  --manifest-path "$SCRIPT_DIR/../../Cargo.toml" \
  -p mcloving-jenkins-compiler-admission -- \
  "$TEST_ROOT/authority-substitution.edn" "$TEST_ROOT/Jenkinsfile" boundary-a \
  "$ADMITTED_JOB" "$ADMITTED_GENERATION" \
  >"$TEST_ROOT/authority.out" 2>"$TEST_ROOT/authority.err"; then
  echo "Rust admission accepted substituted effect authority" >&2
  exit 1
fi

probe=$("$SCRIPT_DIR/run-worker.sh" probe boundary-probe)
grep -q ':status :ok' <<<"$probe"
grep -q ':network false' <<<"$probe"
grep -q ":profile-sha256 \"$EXPECTED_PROFILE\"" <<<"$probe"

ln -s "$TEST_ROOT/Jenkinsfile" "$TEST_ROOT/symlink"
if "$SCRIPT_DIR/run-worker.sh" compile "$TEST_ROOT/symlink" boundary-symlink \
  "$ADMITTED_JOB" "$ADMITTED_GENERATION" \
  >"$TEST_ROOT/symlink.out" 2>"$TEST_ROOT/symlink.err"; then
  echo "symlink source was not rejected" >&2
  exit 1
fi

dd if=/dev/zero of="$TEST_ROOT/oversize" bs=262145 count=1 status=none
if "$SCRIPT_DIR/run-worker.sh" compile "$TEST_ROOT/oversize" boundary-oversize \
  "$ADMITTED_JOB" "$ADMITTED_GENERATION" \
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
