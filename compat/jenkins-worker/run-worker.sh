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
    [[ -f "$SOURCE" && ! -L "$SOURCE" ]] || {
      echo "source must be a regular non-symlink file" >&2
      exit 65
    }
    SOURCE=$(cd -- "$(dirname -- "$SOURCE")" && printf '%s/%s\n' "$PWD" "$(basename -- "$SOURCE")")
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

OUTPUT=$(mktemp "${TMPDIR:-/tmp}/mcloving-compiler-output.XXXXXXXX")
ERROR_OUTPUT=$(mktemp "${TMPDIR:-/tmp}/mcloving-compiler-error.XXXXXXXX")
cleanup() {
  rm -f -- "$OUTPUT" "$ERROR_OUTPUT"
}
trap cleanup EXIT

set +e
printf '%s\n' "$REQUEST" |
  timeout --signal=KILL 5s \
    podman run --rm \
      "${WORKER_PODMAN_OPTIONS[@]}" \
      "${PODMAN_EXTRA[@]}" \
      "$IMAGE" >"$OUTPUT" 2>"$ERROR_OUTPUT"
status=$?
set -e

[[ $status -eq 0 ]] || {
  echo "isolated compiler failed with status $status" >&2
  exit 70
}
[[ $(wc -c < "$OUTPUT") -le 65536 ]] || {
  echo "isolated compiler exceeded output limit" >&2
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
  ADMISSION_BIN=${MCLOVING_JENKINS_ADMISSION_BIN:-"$SCRIPT_DIR/../../target/debug/mcloving-jenkins-compiler-admission"}
  [[ -x "$ADMISSION_BIN" ]] || {
    echo "independent Rust admission binary is missing" >&2
    exit 70
  }
  "$ADMISSION_BIN" \
    "$OUTPUT" "$SOURCE" "$REQUEST_ID" "$JOB_ID" "$JOB_GENERATION" >/dev/null
fi

cp "$OUTPUT" /dev/stdout
