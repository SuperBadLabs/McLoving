#!/usr/bin/env bash
set -euo pipefail

script_dir="${BASH_SOURCE[0]%/*}"
if [[ "${script_dir}" == "${BASH_SOURCE[0]}" ]]; then
  script_dir=.
fi
repo_root="$(cd "${script_dir}/.." && pwd)"
# shellcheck disable=SC1091 # resolved from the repository root at runtime
# shellcheck source=../tools/versions.env
source "${repo_root}/tools/versions.env"

for command in hostname date mkdir sleep mv podman python3 sha256sum git find chmod install cut sort seq; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "required command is unavailable: ${command}" >&2
    exit 1
  }
done
if [[ "$(hostname -s)" != "mario" ]]; then
  echo "runtime-effect rehearsal must run on Mario" >&2
  exit 1
fi
if [[ -n "$(git -C "${repo_root}" status --porcelain --untracked-files=all)" ]]; then
  echo "runtime-effect rehearsal requires a clean exact-head checkout" >&2
  exit 1
fi

umask 077
run_id="ext002-$(date -u +%Y%m%dT%H%M%SZ)-$(python3 - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
)"
run_root="${MCLOVING_EXT002_RUN_ROOT:-${HOME}/.local/share/mcloving/ext002-runs}"
install -d -m 0700 "${run_root}"
run_dir="${run_root}/${run_id}"
mkdir "${run_dir}"
chmod 0700 "${run_dir}"

source_head="$(git -C "${repo_root}" rev-parse HEAD)"
fixture="${repo_root}/crates/execution-spine/tests/fixtures/effect_service.py"
fixture_sha256="$(sha256sum "${fixture}" | cut -d ' ' -f 1)"
network="mcloving-${run_id}"
postgres="mcloving-postgres-${run_id}"
services_stopped=false

cleanup_best_effort() {
  if [[ "${services_stopped}" == true ]]; then
    return
  fi
  podman logs "${postgres}" >"${run_dir}/postgres.log" 2>&1 || true
  podman rm --force "${postgres}" >/dev/null 2>&1 || true
  podman network rm "${network}" >/dev/null 2>&1 || true
  services_stopped=true
}

record_failure() {
  local status=$?
  trap - EXIT
  set +e
  cleanup_best_effort
  python3 - "${run_dir}/result.json" "${run_id}" "${source_head}" "${fixture_sha256}" "${status}" <<'PY'
import json
import os
import sys

path, run_id, source_head, fixture_sha256, status = sys.argv[1:]
result = {
    "schema_version": "mcloving.runtime-effect-mario-rehearsal/v1",
    "run_id": run_id,
    "source_head": source_head,
    "fixture_sha256": fixture_sha256,
    "complete": False,
    "exit_code": int(status),
    "production_endpoint_authority": False,
    "production_credential_authority": False,
    "production_effect_authority": False,
}
with open(path, "x", encoding="utf-8") as output:
    json.dump(result, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PY
  echo "Mario runtime-effect rehearsal failed; evidence retained at ${run_dir}" >&2
  exit "${status}"
}
trap record_failure EXIT

target_root="${repo_root}/target/ext002-mario"
cargo_home="${repo_root}/target/ext002-mario-cargo-home"
install -d -m 0700 "${target_root}" "${cargo_home}"
podman run --rm \
  --volume "${repo_root}:/work:Z" \
  --workdir /work \
  --env CARGO_HOME=/work/target/ext002-mario-cargo-home \
  --env CARGO_TARGET_DIR=/work/target/ext002-mario \
  "${MCLOVING_RUST_IMAGE}" \
  cargo test --locked -p mcloving-execution-spine --test real_spine --no-run \
  >"${run_dir}/build.log" 2>&1

mapfile -t test_binaries < <(
  find "${target_root}/debug/deps" -maxdepth 1 -type f \
    -name 'real_spine-*' -perm -0100 -print | sort
)
if [[ "${#test_binaries[@]}" -ne 1 ]]; then
  echo "expected one real_spine test binary, found ${#test_binaries[@]}" >&2
  exit 1
fi
test_binary="${test_binaries[0]}"
test_binary_sha256="$(sha256sum "${test_binary}" | cut -d ' ' -f 1)"
test_binary_in_container="/work/${test_binary#"${repo_root}/"}"

podman network create --internal "${network}" >"${run_dir}/network-create.txt"
podman network inspect "${network}" >"${run_dir}/network.json"
python3 - "${run_dir}/network.json" <<'PY'
import json
import sys

network = json.load(open(sys.argv[1], encoding="utf-8"))
record = network[0] if isinstance(network, list) else network
if not record.get("internal", record.get("Internal", False)):
    raise SystemExit("runtime network is not internal")
PY

podman run --detach --rm \
  --name "${postgres}" \
  --network "${network}" \
  --network-alias postgres \
  --env POSTGRES_USER=mcloving \
  --env POSTGRES_HOST_AUTH_METHOD=trust \
  --env POSTGRES_DB=mcloving \
  "${MCLOVING_POSTGRES_IMAGE}" >/dev/null

postgres_final_ready() {
  podman exec "${postgres}" sh -c \
    'read -r process_name < /proc/1/comm && [ "${process_name}" = postgres ]' \
    >/dev/null 2>&1 &&
    podman exec "${postgres}" pg_isready \
      --username mcloving --dbname mcloving >/dev/null 2>&1
}
for _ in $(seq 1 120); do
  if postgres_final_ready; then
    break
  fi
  sleep 0.25
done
postgres_final_ready

podman run --rm \
  --network "${network}" \
  --volume "${repo_root}:/work:Z" \
  --workdir /work \
  --env MCLOVING_TEST_DATABASE_URL=postgres://mcloving@postgres:5432/mcloving \
  "${MCLOVING_RUST_IMAGE}" \
  "${test_binary_in_container}" --test-threads=1 \
  >"${run_dir}/test.log" 2>&1

python3 - "${run_dir}/test.log" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"test result: ok\. (\d+) passed; 0 failed", text)
if not match or int(match.group(1)) != 17:
    raise SystemExit("complete real_spine result was not observed")
PY

cleanup_best_effort
if podman container exists "${postgres}"; then
  echo "PostgreSQL fixture container remains after cleanup" >&2
  exit 1
fi
if podman network exists "${network}"; then
  echo "internal fixture network remains after cleanup" >&2
  exit 1
fi

python3 - "${run_dir}/result.pending" "${run_id}" "${source_head}" \
  "${fixture_sha256}" "${test_binary_sha256}" <<'PY'
import json
import os
import sys

path, run_id, source_head, fixture_sha256, test_binary_sha256 = sys.argv[1:]
result = {
    "schema_version": "mcloving.runtime-effect-mario-rehearsal/v1",
    "run_id": run_id,
    "source_head": source_head,
    "fixture_sha256": fixture_sha256,
    "test_binary_sha256": test_binary_sha256,
    "complete": True,
    "real_postgresql": True,
    "real_spine_tests_passed": 17,
    "runtime_network_internal": True,
    "connector_observer_shadow_process_isolation": True,
    "pairwise_distinct_receipt_keys": True,
    "zero_duplicate_effect_assertions": True,
    "production_endpoint_authority": False,
    "production_credential_authority": False,
    "production_effect_authority": False,
    "canary_authority": False,
    "cutover_authority": False,
}
with open(path, "x", encoding="utf-8") as output:
    json.dump(result, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PY
python3 - "${run_dir}" <<'PY'
import hashlib
import os
import sys

run_dir = sys.argv[1]
names = ["build.log", "network.json", "postgres.log", "test.log", "result.pending"]
manifest = os.path.join(run_dir, "files.sha256.pending")
with open(manifest, "x", encoding="utf-8") as output:
    for name in names:
        path = os.path.join(run_dir, name)
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        label = "result.json" if name == "result.pending" else name
        output.write(f"{digest.hexdigest()}  {os.path.join(run_dir, label)}\n")
    output.flush()
    os.fsync(output.fileno())
PY
chmod 0600 "${run_dir}"/*
mv "${run_dir}/files.sha256.pending" "${run_dir}/files.sha256"
mv "${run_dir}/result.pending" "${run_dir}/result.json"
trap - EXIT
echo "run_dir=${run_dir}"
echo "source_head=${source_head}"
echo "fixture_sha256=${fixture_sha256}"
echo "test_binary_sha256=${test_binary_sha256}"
echo "production_effect_authority=false"
echo "complete=true"
