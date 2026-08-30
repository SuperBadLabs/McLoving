#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${repo_root}/tools/versions.env"
container_name="mcloving-postgres-benchmark-${RANDOM}-${RANDOM}"
port="$({ python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
} )"

cleanup() {
  podman rm --force "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

podman run --detach --rm \
  --name "${container_name}" \
  --publish "127.0.0.1:${port}:5432" \
  --env POSTGRES_USER=mcloving \
  --env POSTGRES_HOST_AUTH_METHOD=trust \
  --env POSTGRES_DB=mcloving \
  "${MCLOVING_POSTGRES_IMAGE}" >/dev/null

for _ in $(seq 1 60); do
  if podman exec "${container_name}" pg_isready \
    --username mcloving --dbname mcloving >/dev/null 2>&1; then
    # The image briefly starts a bootstrap postmaster before exec'ing the
    # durable server. Require readiness to remain true across that handoff.
    sleep 0.5
    if podman exec "${container_name}" pg_isready \
      --username mcloving --dbname mcloving >/dev/null 2>&1; then
      break
    fi
  fi
  sleep 0.25
done
podman exec "${container_name}" pg_isready \
  --username mcloving --dbname mcloving >/dev/null

database_url="postgres://mcloving@127.0.0.1:${port}/mcloving"
podman run --rm \
  --network host \
  --env "MCLOVING_TEST_DATABASE_URL=${database_url}" \
  --env "MCLOVING_BENCH_SMALL_STAGES=${MCLOVING_BENCH_SMALL_STAGES:-50}" \
  --env "MCLOVING_BENCH_LARGE_STAGES=${MCLOVING_BENCH_LARGE_STAGES:-100}" \
  --env "MCLOVING_BENCH_HEATS=${MCLOVING_BENCH_HEATS:-5}" \
  --env "MCLOVING_BENCH_IDLE_SECONDS=${MCLOVING_BENCH_IDLE_SECONDS:-10}" \
  --volume "${repo_root}:/work:Z" \
  --workdir /work \
  "${MCLOVING_RUST_IMAGE}" \
  cargo test --locked --release -p mcloving-controller \
    --test stage_latency -- --ignored --nocapture
