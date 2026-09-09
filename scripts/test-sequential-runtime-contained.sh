#!/usr/bin/env bash
# Build from a clean immutable archive; execute only copied binaries in a private network namespace.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"
if (( $# != 1 )); then
  printf 'usage: %s NEW_EVIDENCE_DIRECTORY\n' "$0" >&2
  exit 2
fi
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  printf 'contained runtime evidence requires a clean committed candidate\n' >&2
  exit 2
fi
source tools/versions.env
mkdir -m 0700 -- "$1"
evidence_dir="$(cd "$1" && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-sequential-contained.XXXXXX")"
database_name="mcloving-sequential-db-${scratch##*.}"
runner_name="mcloving-sequential-runner-${scratch##*.}"
compiler_name="mcloving-sequential-compiler-${scratch##*.}"
cleanup() {
  podman rm -f "${runner_name}" "${database_name}" "${compiler_name}" >/dev/null 2>&1 || true
  rm -rf -- "${scratch}"
}
trap cleanup EXIT
mkdir "${scratch}/source" "${scratch}/target" "${scratch}/binaries"
git rev-parse HEAD > "${evidence_dir}/source-commit.txt"
git rev-parse 'HEAD^{tree}' > "${evidence_dir}/source-tree.txt"
git archive HEAD > "${evidence_dir}/source.tar"
tar -xf "${evidence_dir}/source.tar" -C "${scratch}/source"
podman image inspect "${MCLOVING_RUST_IMAGE}" "${MCLOVING_POSTGRES_IMAGE}" \
  --format '{{.Id}} {{.RepoDigests}}' > "${evidence_dir}/images.txt"

# Only this build-only phase may download the pinned compiler and locked dependencies.
# The workload runner below has no external network and never receives this build mount.
timeout 600 podman run --rm --name "${compiler_name}" --pull=never \
  --cap-drop=all --security-opt=no-new-privileges \
  -v "${scratch}/source:/work:ro" \
  -v "${scratch}/target:/tmp/mcloving-sequential-target:rw" -w /work \
  -e CARGO_TARGET_DIR=/tmp/mcloving-sequential-target \
  "${MCLOVING_RUST_IMAGE}" bash -c '
    set -euo pipefail
    rustc --version
    cargo build --locked -p mcloving-controller -p mcloving-agent
    cargo test --locked -p mcloving-controller-api --test sequential_store --no-run --message-format=json > /tmp/mcloving-sequential-target/store-artifacts.json
    cargo test --locked -p mcloving-controller-api --test workspace_store --no-run --message-format=json > /tmp/mcloving-sequential-target/workspace-artifacts.json
    cargo test --locked -p mcloving-agent --test sequential_work --no-run --message-format=json > /tmp/mcloving-sequential-target/remote-artifacts.json
  ' > "${evidence_dir}/build.log" 2>&1
cp "${scratch}/target/debug/mcloving-controller" "${scratch}/target/debug/mcloving-agent" "${scratch}/binaries/"
python3 - "${scratch}" <<'PY'
import json
from pathlib import Path
import shutil
import sys
root = Path(sys.argv[1])
for records, name in (("store-artifacts.json", "sequential_store"), ("workspace-artifacts.json", "workspace_store"), ("remote-artifacts.json", "sequential_work")):
    artifacts = [json.loads(line) for line in (root / "target" / records).read_text().splitlines()]
    paths = [Path(item["executable"]) for item in artifacts
             if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == name
             and item.get("executable") and item.get("profile", {}).get("test")]
    if len(paths) != 1:
        raise SystemExit(f"expected exactly one compiled {name} executable")
    relative = paths[0].relative_to("/tmp/mcloving-sequential-target")
    shutil.copyfile(root / "target" / relative, root / "binaries" / name)
    (root / "binaries" / name).chmod(0o755)
PY
(
  cd "${scratch}/binaries"
  sha256sum mcloving-controller mcloving-agent sequential_store workspace_store sequential_work
) > "${evidence_dir}/binaries.sha256"

podman run -d --name "${database_name}" --pull=never --network=none \
  --memory=1g --pids-limit=256 --tmpfs /var/lib/postgresql/data:rw,size=512m \
  -e POSTGRES_USER=mcloving -e POSTGRES_DB=mcloving -e POSTGRES_HOST_AUTH_METHOD=trust \
  "${MCLOVING_POSTGRES_IMAGE}" > "${evidence_dir}/database-id.txt"
ready=false
for _ in {1..100}; do
  if podman exec "${database_name}" pg_isready -U mcloving -d mcloving >/dev/null; then
    ready=true
    break
  fi
  sleep 0.1
done
[[ "${ready}" == true ]]
timeout 180 podman run --rm --name "${runner_name}" --pull=never \
  --network="container:${database_name}" --read-only --cap-drop=all \
  --security-opt=no-new-privileges --user=1000:1000 --memory=2g --pids-limit=512 \
  --tmpfs /tmp:rw,size=512m,mode=1777 \
  -v "${scratch}/source:/work:ro" \
  -v "${scratch}/binaries:/tmp/mcloving-sequential-target/debug:ro" -w /work \
  -e MCLOVING_TEST_DATABASE_URL=postgres://mcloving@127.0.0.1:5432/mcloving \
  -e MCLOVING_CONTROLLER_BINARY=/tmp/mcloving-sequential-target/debug/mcloving-controller \
  "${MCLOVING_RUST_IMAGE}" bash -c '
    set -euo pipefail
    bash scripts/run-verified-rust-test.sh 4 sequential-store --require-postgres /tmp/mcloving-sequential-target/debug/sequential_store --nocapture --test-threads=1
    bash scripts/run-verified-rust-test.sh 4 workspace-store --require-postgres /tmp/mcloving-sequential-target/debug/workspace_store --nocapture --test-threads=1
    bash scripts/run-verified-rust-test.sh 11 sequential-remote-work --require-postgres /tmp/mcloving-sequential-target/debug/sequential_work --nocapture --test-threads=1
  ' > "${evidence_dir}/runtime.log" 2>&1
python3 - "${evidence_dir}/runtime.log" <<'PY'
import re
import sys
from pathlib import Path
output = Path(sys.argv[1]).read_text()
if "skipped:" in output.lower() or re.search(r"\b[1-9][0-9]* ignored;", output):
    raise SystemExit("contained runtime gate refuses skipped or ignored tests")
if len(re.findall(r"^sequential-runtime-evidence ", output, re.M)) != 8:
    raise SystemExit("contained runtime evidence population is incomplete")
if len(re.findall(r"^workspace-runtime-evidence ", output, re.M)) != 5:
    raise SystemExit("contained workspace runtime evidence population is incomplete")
PY
podman rm -f "${database_name}" > "${evidence_dir}/cleanup.txt"
printf 'contained-sequential-runtime-ok store=4 workspace=4 remote=11 production_authority=false\n' | tee "${evidence_dir}/result.txt"
(
  cd "${evidence_dir}"
  sha256sum source-commit.txt source-tree.txt source.tar images.txt build.log binaries.sha256 database-id.txt runtime.log cleanup.txt result.txt
) > "${evidence_dir}/ARTIFACTS.sha256"
