#!/usr/bin/env bash
# Additive, compile-only v2 launcher. No controller or workload is invoked.
set -euo pipefail
[[ $# -eq 4 && "$1" == compile-sequential ]] || { echo E_SEQUENTIAL_ARGUMENTS >&2; exit 64; }
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SOURCE=$2
REQUEST_ID=$3
CONTEXT=$4
IMAGE=${MCLOVING_JENKINS_WORKER_IMAGE:-localhost/mcloving/jenkins-compiler-worker:sequential-v2}
IMAGE_SHA256=${MCLOVING_JENKINS_SEQUENTIAL_WORKER_IMAGE_SHA256:-}
[[ "$IMAGE_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo E_WORKER_IMAGE_PIN >&2; exit 65; }
EXPECTED_PROFILE=feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271
[[ $(sha256sum "$SCRIPT_DIR/profile-v1.properties" | awk '{print $1}') == "$EXPECTED_PROFILE" ]] || {
  echo E_WORKER_PROFILE >&2; exit 65;
}
selected_id=$(podman image inspect "$IMAGE" --format '{{.Id}}')
[[ "${selected_id#sha256:}" == "$IMAGE_SHA256" ]] || { echo E_WORKER_IMAGE_PIN >&2; exit 65; }
IMAGE="sha256:$IMAGE_SHA256"
[[ $(podman image inspect "$IMAGE" --format '{{index .Labels "io.mcloving.compiler.profile.sha256"}}') == "$EXPECTED_PROFILE" ]] || {
  echo E_WORKER_PROFILE >&2; exit 65;
}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mcloving-sequential.XXXXXXXX")
trap 'rm -rf -- "$WORK_DIR"' EXIT
ADMISSION_SELECTED=${MCLOVING_JENKINS_ADMISSION_BIN:-"$SCRIPT_DIR/../../target/debug/mcloving-jenkins-compiler-admission"}
[[ -f "$ADMISSION_SELECTED" && -x "$ADMISSION_SELECTED" ]] || { echo E_ADMISSION_BINARY >&2; exit 70; }
# Use one private executable copy for request and validation; hash that copy.
ADMISSION_BIN="$WORK_DIR/admission"
cp -- "$ADMISSION_SELECTED" "$ADMISSION_BIN"
chmod 500 "$ADMISSION_BIN"
ADMISSION_SHA256=$(sha256sum "$ADMISSION_BIN" | awk '{print $1}')
SOURCE_SNAPSHOT="$WORK_DIR/source"
CONTEXT_SNAPSHOT="$WORK_DIR/context"
REQUEST_FILE="$WORK_DIR/request"
"$ADMISSION_BIN" snapshot-sequential-source "$SOURCE" >"$SOURCE_SNAPSHOT"
"$ADMISSION_BIN" snapshot-sequential-context "$CONTEXT" >"$CONTEXT_SNAPSHOT"
"$ADMISSION_BIN" request-sequential "$SOURCE_SNAPSHOT" "$CONTEXT_SNAPSHOT" "$REQUEST_ID" >"$REQUEST_FILE"
SOURCE_SHA256=$(sha256sum "$SOURCE_SNAPSHOT" | awk '{print $1}')
CONTEXT_SHA256=$(sha256sum "$CONTEXT_SNAPSHOT" | awk '{print $1}')
# shellcheck source=worker-podman-options.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/worker-podman-options.sh"
PODMAN_EXTRA=(--volume "$SOURCE_SNAPSHOT:/input/Jenkinsfile:ro")

STREAM_LIMIT=65536
STREAM_SENTINEL=$((STREAM_LIMIT + 1))
OUTPUT="$WORK_DIR/response"
: >"$OUTPUT"
ERROR_OUTPUT="$WORK_DIR/worker-error"
: >"$ERROR_OUTPUT"
OUTPUT_PIPE="${OUTPUT}.pipe"
ERROR_PIPE="${ERROR_OUTPUT}.pipe"
CID_FILE="${OUTPUT}.cid"
mkfifo "$OUTPUT_PIPE" "$ERROR_PIPE"
cleanup() {
  if [[ -s "$CID_FILE" ]]; then
    container_id=$(cat "$CID_FILE")
    if [[ -n "$container_id" ]]; then
      podman rm --force "$container_id" >/dev/null 2>&1 || true
    fi
  fi
  for reader_pid in "${OUTPUT_READER_PID:-}" "${ERROR_READER_PID:-}"; do
    if [[ -n "$reader_pid" ]] && kill -0 "$reader_pid" 2>/dev/null; then
      kill "$reader_pid" 2>/dev/null || true
      wait "$reader_pid" 2>/dev/null || true
    fi
  done
  rm -f -- "$OUTPUT" "$ERROR_OUTPUT" "$OUTPUT_PIPE" "$ERROR_PIPE" "$CID_FILE" \
    "$SOURCE_SNAPSHOT" "$CONTEXT_SNAPSHOT" "$REQUEST_FILE" "$ADMISSION_BIN" \
    "$WORK_DIR/admission-receipt"
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

head -c "$STREAM_SENTINEL" <"$OUTPUT_PIPE" >"$OUTPUT" &
OUTPUT_READER_PID=$!
head -c "$STREAM_SENTINEL" <"$ERROR_PIPE" >"$ERROR_OUTPUT" &
ERROR_READER_PID=$!

set +e
cat "$REQUEST_FILE" |
  timeout --signal=KILL 5s \
    podman run --rm \
      --cidfile "$CID_FILE" \
      "${WORKER_PODMAN_OPTIONS[@]}" \
      "${PODMAN_EXTRA[@]}" \
      "$IMAGE" >"$OUTPUT_PIPE" 2>"$ERROR_PIPE" &
PRODUCER_PID=$!
limit_exceeded=0
while kill -0 "$PRODUCER_PID" 2>/dev/null; do
  if [[ $(wc -c <"$OUTPUT") -gt $STREAM_LIMIT ]] ||
    [[ $(wc -c <"$ERROR_OUTPUT") -gt $STREAM_LIMIT ]]; then
    limit_exceeded=1
    if [[ -s "$CID_FILE" ]]; then
      podman kill --signal KILL "$(cat "$CID_FILE")" >/dev/null 2>&1 || true
    fi
    break
  fi
  sleep 0.01
done
wait "$PRODUCER_PID"
status=$?
wait "$OUTPUT_READER_PID" 2>/dev/null || true
wait "$ERROR_READER_PID" 2>/dev/null || true
set -e

if [[ $limit_exceeded -eq 1 ]] ||
  [[ $(wc -c <"$OUTPUT") -gt $STREAM_LIMIT ]] ||
  [[ $(wc -c <"$ERROR_OUTPUT") -gt $STREAM_LIMIT ]]; then
  echo "isolated compiler exceeded stream limit" >&2
  exit 70
fi
[[ $status -eq 0 ]] || {
  echo "isolated compiler failed with status $status" >&2
  exit 70
}
[[ $(wc -l < "$OUTPUT") -eq 1 ]] || {
  echo "isolated compiler emitted a non-canonical response count" >&2
  exit 70
}
[[ ! -s "$ERROR_OUTPUT" ]] || {
  echo "isolated compiler wrote diagnostics outside its protocol" >&2
  exit 70
}

"$ADMISSION_BIN" validate-sequential "$OUTPUT" "$SOURCE_SNAPSHOT" "$CONTEXT_SNAPSHOT" "$REQUEST_ID" >"$WORK_DIR/admission-receipt"
# Trusted-side observations are released only after independent validation.
printf 'worker_image_sha256=%s\nadmission_binary_sha256=%s\nlaunch_source_sha256=%s\nlaunch_context_sha256=%s\n' \
  "$IMAGE_SHA256" "$ADMISSION_SHA256" "$SOURCE_SHA256" "$CONTEXT_SHA256" >&2
cat "$WORK_DIR/admission-receipt" >&2
cat "$OUTPUT"
