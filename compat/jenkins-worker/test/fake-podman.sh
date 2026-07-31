#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  image)
    [[ "${2:-}" == "inspect" ]]
    printf '%s\n' feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271
    ;;
  run)
    shift
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == "--cidfile" ]]; then
        printf 'fake-stream-container\n' >"$2"
        break
      fi
      shift
    done
    if [[ "${FAKE_PODMAN_STREAM:-stdout}" == "stderr" ]]; then
      while printf 'untrusted-worker-diagnostic-flood\n' >&2; do :; done
    else
      while printf 'untrusted-worker-response-flood\n'; do :; done
    fi
    ;;
  kill | rm)
    ;;
  *)
    printf 'unexpected fake podman command: %s\n' "${1:-}" >&2
    exit 64
    ;;
esac
