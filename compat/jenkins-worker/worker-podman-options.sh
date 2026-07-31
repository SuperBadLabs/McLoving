#!/usr/bin/env bash

# This file is sourced by the launcher and its independent boundary test. Keep
# every authority-bearing Podman option in this single audited array.
# shellcheck disable=SC2034
WORKER_PODMAN_OPTIONS=(
  --pull never
  --interactive
  --image-volume ignore
  --network none
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 64
  --memory 512m
  --memory-swap 512m
  --cpus 1
  --ulimit nofile=64:64
  --userns "keep-id:uid=1000,gid=1000"
  --user 1000:1000
  --unsetenv-all
  --env LANG=C.UTF-8
  --env TZ=UTC
  --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=16777216"
  --log-driver none
)
