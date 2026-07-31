#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 probe REQUEST_ID | compile SOURCE REQUEST_ID JOB_ID JOB_GENERATION" >&2
  exit 64
}

[[ $# -ge 2 ]] || usage

OPERATION=$1
IMAGE=${MCLOVING_JENKINS_WORKER_IMAGE:-localhost/mcloving/jenkins-compiler-worker:mario-jenkins-oracle-228-v1}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PROFILE_SHA256=$(sha256sum "$SCRIPT_DIR/profile-v1.properties" | awk '{print $1}')
EXPECTED_PROFILE=feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271
REQUEST_ID=$2
SOURCE_SNAPSHOT=
cleanup_source_snapshot() {
  if [[ -n "$SOURCE_SNAPSHOT" ]]; then
    rm -f -- "$SOURCE_SNAPSHOT"
  fi
}
trap cleanup_source_snapshot EXIT
if [[ "$OPERATION" == "compile" ]]; then
  [[ $# -ge 3 ]] || usage
  REQUEST_ID=$3
fi

[[ "$PROFILE_SHA256" == "$EXPECTED_PROFILE" ]] || {
  echo "worker profile digest mismatch" >&2
  exit 65
}
[[ "$REQUEST_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$ ]] || {
  echo "invalid request id" >&2
  exit 64
}

# shellcheck source=worker-podman-options.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/worker-podman-options.sh"

image_profile=$(podman image inspect "$IMAGE" \
  --format '{{index .Labels "io.mcloving.compiler.profile.sha256"}}')
[[ "$image_profile" == "$EXPECTED_PROFILE" ]] || {
  echo "worker image profile mismatch" >&2
  exit 65
}

PODMAN_EXTRA=()
case "$OPERATION" in
  probe)
    [[ $# -eq 2 ]] || usage
    REQUEST=$(printf \
      '{:operation :probe :protocol "mcloving.jenkins.compiler/1" :request-id "%s" :target-profile-sha256 "%s"}' \
      "$REQUEST_ID" "$PROFILE_SHA256")
    ;;
  compile)
    [[ $# -eq 5 ]] || usage
    SOURCE=$2
    JOB_ID=$4
    JOB_GENERATION=$5
    [[ "$JOB_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || {
      echo "invalid job id" >&2
      exit 64
    }
    [[ "$JOB_GENERATION" =~ ^[0-9a-f]{64}$ ]] || {
      echo "invalid job generation" >&2
      exit 64
    }
    ADMISSION_BIN=${MCLOVING_JENKINS_ADMISSION_BIN:-"$SCRIPT_DIR/../../target/debug/mcloving-jenkins-compiler-admission"}
    [[ -x "$ADMISSION_BIN" ]] || {
      echo "independent Rust admission binary is missing" >&2
      exit 70
    }
    SOURCE_SNAPSHOT=$(mktemp "${TMPDIR:-/tmp}/mcloving-compiler-source.XXXXXXXX")
    "$ADMISSION_BIN" snapshot "$SOURCE" >"$SOURCE_SNAPSHOT"
    SOURCE=$SOURCE_SNAPSHOT
    SOURCE_BYTES=$(wc -c < "$SOURCE" | tr -d ' ')
    [[ "$SOURCE_BYTES" -le 262144 ]] || {
      echo "source exceeds 262144-byte compiler limit" >&2
      exit 65
    }
    SOURCE_SHA256=$(sha256sum "$SOURCE" | awk '{print $1}')
    REQUEST=$(printf \
      '{:inventory-fingerprint "b1c2f81c74ec0ffc36971f358f920b2d0775c6009f474bea924448cd2a1915c1" :job-actor "jenkins/system" :job-effective-time "2026-07-31T06:44:17Z" :job-enabled false :job-generation "%s" :job-id "%s" :job-reason "offline-frozen-source-state" :operation :compile :protocol "mcloving.jenkins.compiler/1" :request-id "%s" :source-path "/input/Jenkinsfile" :source-sha256 "%s" :target-profile-sha256 "%s"}' \
      "$JOB_GENERATION" "$JOB_ID" "$REQUEST_ID" "$SOURCE_SHA256" "$PROFILE_SHA256")
    PODMAN_EXTRA+=(--volume "$SOURCE:/input/Jenkinsfile:ro")
    ;;
  *)
    usage
    ;;
esac

STREAM_LIMIT=65536
STREAM_SENTINEL=$((STREAM_LIMIT + 1))
OUTPUT=$(mktemp "${TMPDIR:-/tmp}/mcloving-compiler-output.XXXXXXXX")
ERROR_OUTPUT=$(mktemp "${TMPDIR:-/tmp}/mcloving-compiler-error.XXXXXXXX")
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
    "$SOURCE_SNAPSHOT"
}
trap cleanup EXIT

head -c "$STREAM_SENTINEL" <"$OUTPUT_PIPE" >"$OUTPUT" &
OUTPUT_READER_PID=$!
head -c "$STREAM_SENTINEL" <"$ERROR_PIPE" >"$ERROR_OUTPUT" &
ERROR_READER_PID=$!

set +e
printf '%s\n' "$REQUEST" |
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

if [[ "$OPERATION" == "compile" ]]; then
  "$ADMISSION_BIN" \
    "$OUTPUT" "$SOURCE" "$REQUEST_ID" "$JOB_ID" "$JOB_GENERATION" >/dev/null
fi

cp "$OUTPUT" /dev/stdout
