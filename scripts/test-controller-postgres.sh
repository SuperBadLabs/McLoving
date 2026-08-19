#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../tools/versions.env
source "${repo_root}/tools/versions.env"
container_name="mcloving-postgres-test-${RANDOM}-${RANDOM}"
port="$(
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"

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
  --volume "${repo_root}:/work:Z" \
  --workdir /work \
  "${MCLOVING_RUST_IMAGE}" \
  bash -c \
  'cargo test --locked -p mcloving-controller-store --test postgres_truth &&
   cargo test --locked -p mcloving-controller-store --test identity_lifecycle &&
   cargo test --locked -p mcloving-controller-store --test authorization_mapping &&
   cargo test --locked -p mcloving-controller-store --test external_read_consumers &&
   cargo test --locked -p mcloving-controller-store --test external_admin_clients &&
   cargo test --locked -p mcloving-controller-api --test oidc_flow &&
   cargo test --locked -p mcloving-execution-spine --test real_spine &&
   cargo test --locked -p mcloving-controller --test deployable_runtime &&
   cargo test --locked -p mcloving-controller --test diff_001 &&
   cargo build --locked -p mcloving-controller &&
   MCLOVING_CONTROLLER_BINARY=/work/target/debug/mcloving-controller \
     cargo test --locked -p mcloving-agent --test remote_work &&
   MCLOVING_CONTROLLER_BINARY=/work/target/debug/mcloving-controller \
     cargo test --locked -p mcloving-agent --test identity_collision'
