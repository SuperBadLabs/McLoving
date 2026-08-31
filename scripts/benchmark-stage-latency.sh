#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${repo_root}/tools/versions.env"
if [[ -n "$(git -C "${repo_root}" status --porcelain)" ]]; then
  echo "stage-latency benchmark requires a clean source checkout" >&2
  exit 2
fi
source_head="$(git -C "${repo_root}" rev-parse HEAD)"
source_tree="$(git -C "${repo_root}" rev-parse 'HEAD^{tree}')"
receipt_host_path="${MCLOVING_BENCH_RECEIPT_PATH:-${repo_root}/target/stage-latency-${source_head}.json}"
case "${receipt_host_path}" in
  "${repo_root}"/*) ;;
  *)
    echo "MCLOVING_BENCH_RECEIPT_PATH must be inside the source checkout" >&2
    exit 2
    ;;
esac
receipt_relative_path="${receipt_host_path#"${repo_root}"/}"
receipt_container_path="/work/${receipt_relative_path}"
mkdir -p "$(dirname "${receipt_host_path}")"
rm -f "${receipt_host_path}"
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
  --env "MCLOVING_BENCH_SOURCE_HEAD=${source_head}" \
  --env "MCLOVING_BENCH_SOURCE_TREE=${source_tree}" \
  --env "MCLOVING_BENCH_RUST_IMAGE=${MCLOVING_RUST_IMAGE}" \
  --env "MCLOVING_BENCH_POSTGRES_IMAGE=${MCLOVING_POSTGRES_IMAGE}" \
  --env "MCLOVING_BENCH_HOST=$(hostname -s)" \
  --env "MCLOVING_BENCH_RECEIPT_PATH=${receipt_container_path}" \
  --volume "${repo_root}:/work:Z" \
  --workdir /work \
  "${MCLOVING_RUST_IMAGE}" \
  cargo test --locked --release -p mcloving-controller \
    --test stage_latency -- --ignored --nocapture

test -s "${receipt_host_path}"
sha256sum "${receipt_host_path}"
