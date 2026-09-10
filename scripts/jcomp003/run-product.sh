#!/usr/bin/env bash
# Build immutable committed source; run only private copied artifacts with no external route.
set -Eeuo pipefail
umask 077
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"
if (( $# != 2 )); then
  echo "usage: $0 FROZEN_INPUT_JSON NEW_EVIDENCE_DIRECTORY" >&2
  exit 2
fi
if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
  echo 'product evidence requires a clean committed candidate' >&2
  exit 2
fi
input=$(realpath -e "$1")
mkdir -m 0700 -- "$2"
evidence=$(realpath -e "$2")
scratch=$(mktemp -d /tmp/mcloving-jcomp003-product.XXXXXXXX)
chmod 0755 "$scratch"
source tools/versions.env
runtime_image='docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02'
name="mcloving-jcomp003-${scratch##*.}"
database="${name}-db"
runner="${name}-runner"
compiler="${name}-compiler"
remove_owned_container() {
  local container=$1
  podman rm --force --ignore "$container" || return $?
  if podman container exists "$container"; then
    echo "owned container remains after removal: $container" >&2
    return 1
  else
    local exists_status=$?
    [[ $exists_status == 1 ]] || return "$exists_status"
  fi
}
cleanup() {
  local status=$?
  local cleanup_status=0
  trap - EXIT
  # The runner owns a dependency on the database network namespace. Podman's
  # batch removal can race that dependency, so prove absence before continuing.
  if remove_owned_container "$runner"; then
    remove_owned_container "$database" || cleanup_status=$?
  else
    cleanup_status=$?
  fi
  remove_owned_container "$compiler" || cleanup_status=$?
  rm -rf -- "$scratch" || cleanup_status=$?
  (( status == 0 )) || exit "$status"
  exit "$cleanup_status"
}
trap cleanup EXIT
mkdir "$scratch/source" "$scratch/target" "$scratch/binaries" "$scratch/tracer" "$scratch/tracer/lib"
chmod 0755 "$scratch/binaries" "$scratch/tracer" "$scratch/tracer/lib"
git rev-parse HEAD > "$evidence/source-commit.txt"
git rev-parse 'HEAD^{tree}' > "$evidence/source-tree.txt"
git archive HEAD > "$evidence/source.tar"
tar -xf "$evidence/source.tar" -C "$scratch/source"
cp -- "$input" "$scratch/input.json"
chmod 0444 "$scratch/input.json"
cp -- "$input" "$evidence/input.json"
# Copy the independent host tracer and its non-libc dependencies, pin every byte.
# The immutable runtime supplies its own libc/loader. LD_LIBRARY_PATH is removed
# from the traced agent by strace -E, so observer libraries do not enter workloads.
cp /usr/bin/strace "$scratch/tracer/strace"
for library in libunwind-ptrace.so.0 libunwind-x86_64.so.8 libunwind.so.8 liblzma.so.5; do
  cp -- "/lib/x86_64-linux-gnu/$library" "$scratch/tracer/lib/$library"
done
cat > "$scratch/tracer/observe-exec" <<'TRACER'
#!/bin/sh
export LD_LIBRARY_PATH=/opt/jcomp/tracer/lib
exec /opt/jcomp/tracer/strace -E LD_LIBRARY_PATH "$@"
TRACER
chmod -R a+rX "$scratch/tracer"
chmod 0555 "$scratch/tracer/observe-exec"
cp -a "$scratch/tracer" "$evidence/tracer"
ldd /usr/bin/strace > "$evidence/tracer-host-linkage.txt"
podman image inspect "$MCLOVING_RUST_IMAGE" "$MCLOVING_POSTGRES_IMAGE" "$runtime_image" > "$evidence/images.json"
# Only this compiler phase has ordinary build network access. No workload executes.
timeout 900 podman run --rm --name "$compiler" --pull=never --cap-drop=all \
  --security-opt=no-new-privileges -v "$scratch/source:/work:ro" \
  -v "$scratch/target:/tmp/jcomp003-target:rw" -w /work \
  -e CARGO_TARGET_DIR=/tmp/jcomp003-target \
  -e "MCLOVING_BUILD_SOURCE_HEAD=$(cat "$evidence/source-commit.txt")" \
  -e "MCLOVING_BUILD_SOURCE_TREE=$(cat "$evidence/source-tree.txt")" "$MCLOVING_RUST_IMAGE" bash -c '
    set -euo pipefail
    rustc --version
    cargo build --locked -p mcloving-controller -p mcloving-agent
    cargo test --locked -p mcloving-agent --test jcomp003_paired --no-run --message-format=json > /tmp/jcomp003-target/artifacts.json
  ' > "$evidence/build.log" 2>&1
cp "$scratch/target/debug/mcloving-controller" "$scratch/target/debug/mcloving-agent" "$scratch/binaries/"
python3 - "$scratch" <<'PY'
import json
from pathlib import Path
import shutil
import sys
root = Path(sys.argv[1])
records = [json.loads(line) for line in (root / 'target/artifacts.json').read_text().splitlines()]
paths = [Path(r['executable']) for r in records if r.get('reason') == 'compiler-artifact'
         and r.get('target', {}).get('name') == 'jcomp003_paired' and r.get('executable')]
assert len(paths) == 1
shutil.copyfile(root / 'target' / paths[0].relative_to('/tmp/jcomp003-target'), root / 'binaries/jcomp003_paired')
(root / 'binaries/jcomp003_paired').chmod(0o555)
PY
chmod a+rx "$scratch/binaries/"*
(cd "$scratch/binaries" && sha256sum mcloving-controller mcloving-agent jcomp003_paired) > "$evidence/binaries.sha256"
# PostgreSQL owns a network-none namespace. Product joins only this private loopback.
podman run -d --name "$database" --pull=never --network=none \
  --http-proxy=false --pid=private --ipc=private --memory=1g --memory-swap=1g --cpus=2 --pids-limit=256 \
  --ulimit=nofile=1024:1024 --log-driver=k8s-file --log-opt=max-size=8mb \
  --tmpfs /var/lib/postgresql/data:rw,size=512m --entrypoint=/bin/sh \
  -e POSTGRES_USER=mcloving -e POSTGRES_DB=mcloving -e POSTGRES_HOST_AUTH_METHOD=trust \
  "$MCLOVING_POSTGRES_IMAGE" -c 'exec timeout -s KILL 600 /usr/local/bin/docker-entrypoint.sh postgres' > "$evidence/database-id.txt"
podman inspect "$database" > "$evidence/database-inspect.json"
ready=false
for _ in {1..100}; do
  if podman exec "$database" pg_isready -U mcloving -d mcloving >/dev/null; then ready=true; break; fi
  sleep 0.1
done
[[ $ready == true ]]
podman run -d --name "$runner" --pull=never --image-volume=ignore --network="container:$database" \
  --http-proxy=false --pid=private --ipc=private --read-only --cap-drop=all --security-opt=no-new-privileges --user=1000:1000 \
  --cpus=4 --memory=2g --memory-swap=2g --pids-limit=512 --tmpfs /tmp:rw,size=512m,mode=1777 \
  --ulimit=nofile=1024:1024 --log-driver=k8s-file --log-opt=max-size=8mb \
  --entrypoint=/usr/bin/timeout -v "$scratch/binaries:/tmp/jcomp003-target/debug:ro" \
  -v "$scratch/tracer:/opt/jcomp/tracer:ro" -v "$scratch/input.json:/opt/jcomp/input.json:ro" \
  -e MCLOVING_TEST_DATABASE_URL=postgres://mcloving@127.0.0.1:5432/mcloving \
  -e MCLOVING_CONTROLLER_BINARY=/tmp/jcomp003-target/debug/mcloving-controller \
  -e JCOMP_INPUT=/opt/jcomp/input.json -e JCOMP_OUTPUT=/tmp/observations \
  -e JCOMP_STRACE=/opt/jcomp/tracer/observe-exec "$runtime_image" -k 5 240 /bin/bash -c '
    set -euo pipefail
    until test -f /tmp/jcomp-boundary-approved; do sleep 0.1; done
    sha256sum /bin/sh
    printf "controller-build-provenance "
    /tmp/jcomp003-target/debug/mcloving-controller build-provenance
    printf "agent-build-provenance "
    /tmp/jcomp003-target/debug/mcloving-agent build-provenance
    set +e
    /tmp/jcomp003-target/debug/jcomp003_paired --ignored --nocapture --test-threads=1
    status=$?
    printf "%s\n" "$status" > /tmp/test-status
    sleep 600
  ' > "$evidence/runner-id.txt"
podman inspect "$runner" > "$evidence/runner-inspect.json"
python3 scripts/jcomp003/verify-product-boundary.py "$evidence/runner-inspect.json" "$evidence/database-inspect.json" "$scratch"
podman exec "$runner" touch /tmp/jcomp-boundary-approved
finished=false
for _ in {1..240}; do
  if timeout 5 podman exec "$runner" test -f /tmp/test-status; then finished=true; break; fi
  sleep 1
done
[[ $finished == true ]]
status=$(podman exec "$runner" cat /tmp/test-status)
podman logs "$runner" > "$evidence/runtime.log" 2>&1
podman cp "$runner:/tmp/observations" "$evidence/observations"
[[ $status == 0 ]]
python3 - "$evidence/runtime.log" <<'PY'
from pathlib import Path
import re
import sys
log = Path(sys.argv[1]).read_text()
assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in log
assert 'jcomp003-product-evidence positive_builds=11 negative_inputs=12 cleanup=complete' in log
assert not re.search(r'\bskipped:', log)
PY
remove_owned_container "$runner" > "$evidence/cleanup.txt" 2>&1
remove_owned_container "$database" >> "$evidence/cleanup.txt" 2>&1
! podman container exists "$runner"
! podman container exists "$database"
printf '%s\n' 'product-containers-removed=true' 'workspaces-and-database-tmpfs-removed=true' > "$evidence/cleanup-verified.txt"
python3 - "$evidence" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
artifacts = {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(root.rglob('*')) if p.is_file()}
(root / 'artifacts.json').write_text(json.dumps(artifacts, indent=2) + '\n')
PY
