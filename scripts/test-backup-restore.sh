#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../tools/versions.env
source "${repo_root}/tools/versions.env"

engine="${1:-podman}"
source_name="mcloving-backup-source-${RANDOM}-${RANDOM}"
target_name="mcloving-backup-target-${RANDOM}-${RANDOM}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-backup-restore.XXXXXX")"
dump_path="${work_dir}/controller.dump"

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

source_port="$(free_port)"
target_port="$(free_port)"

cleanup() {
  "${engine}" rm --force "${source_name}" "${target_name}" >/dev/null 2>&1 || true
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT

start_postgres() {
  local name="$1"
  local port="$2"
  "${engine}" run --detach --rm \
    --name "${name}" \
    --publish "127.0.0.1:${port}:5432" \
    --env POSTGRES_USER=mcloving \
    --env POSTGRES_HOST_AUTH_METHOD=trust \
    --env POSTGRES_DB=mcloving \
    "${MCLOVING_POSTGRES_IMAGE}" >/dev/null
  for _ in $(seq 1 60); do
    if "${engine}" exec "${name}" pg_isready \
      --username mcloving --dbname mcloving >/dev/null 2>&1; then
      return
    fi
    sleep 0.25
  done
  printf 'PostgreSQL container did not become ready: %s\n' "${name}" >&2
  exit 1
}

run_canary() {
  local port="$1"
  local test_name="$2"
  "${engine}" run --rm \
    --network host \
    --env "MCLOVING_TEST_DATABASE_URL=postgres://mcloving@127.0.0.1:${port}/mcloving" \
    --volume "${repo_root}:/work:Z" \
    --workdir /work \
    "${MCLOVING_RUST_IMAGE}" \
    cargo test --locked \
      -p mcloving-controller-store \
      --test postgres_truth \
      "${test_name}" -- \
      --ignored --exact --test-threads=1
}

start_postgres "${source_name}" "${source_port}"
start_postgres "${target_name}" "${target_port}"
run_canary "${source_port}" backup_restore_canary_seed

"${engine}" exec "${source_name}" \
  pg_dump --username mcloving --dbname mcloving \
  --format=custom --no-owner >"${dump_path}"
test -s "${dump_path}"

"${engine}" exec "${target_name}" \
  psql --username mcloving --dbname mcloving \
  --set ON_ERROR_STOP=1 \
  --command "CREATE ROLE mcloving_tenant NOLOGIN NOSUPERUSER NOBYPASSRLS" \
  >/dev/null
"${engine}" exec --interactive "${target_name}" \
  pg_restore --username mcloving --dbname mcloving \
  --exit-on-error --no-owner <"${dump_path}"

run_canary "${target_port}" backup_restore_canary_verify

printf 'backup_restore_drill=passed\n'
printf 'dump_sha256=%s\n' "$(sha256sum "${dump_path}" | awk '{print $1}')"
printf 'restore_policy=all_pre_restore_leases_reconciliation_required\n'
