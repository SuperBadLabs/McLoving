#!/usr/bin/env bash
# Fresh compiler image and Rust admission from one clean source archive; no workloads.
set -Eeuo pipefail
umask 077
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
if (( $# != 2 )); then
  echo "usage: $0 PINNED_PUBLIC_PLUGIN_SNAPSHOT NEW_BUILD_EVIDENCE" >&2
  exit 2
fi
[[ -z $(git status --porcelain --untracked-files=normal) ]]
snapshot=$(realpath -e "$1")
mkdir -m 0700 -- "$2"
evidence=$(realpath -e "$2")
scratch=$(mktemp -d /tmp/mcloving-jcomp003-compiler.XXXXXXXX)
compiler="mcloving-jcomp003-admission-${scratch##*.}"
cleanup() {
  local status=$?
  trap - EXIT
  podman rm -f "$compiler" >/dev/null 2>&1 || true
  rm -rf -- "$scratch"
  exit "$status"
}
trap cleanup EXIT
mkdir "$scratch/source" "$scratch/snapshot" "$scratch/snapshot/plugins" "$scratch/target"
git rev-parse HEAD > "$evidence/source-commit.txt"
git rev-parse 'HEAD^{tree}' > "$evidence/source-tree.txt"
git archive HEAD > "$evidence/source.tar"
tar -xf "$evidence/source.tar" -C "$scratch/source"
cp -- "$snapshot/PLUGIN_SHA256SUMS" "$scratch/snapshot/PLUGIN_SHA256SUMS"
cp -- "$snapshot/plugins/"*.jpi "$scratch/snapshot/plugins/"
image="localhost/mcloving/jcomp003-compiler:$(cat "$evidence/source-commit.txt")"
timeout 300 bash "$scratch/source/compat/jenkins-worker/build-image.sh" "$scratch/snapshot" "$image" > "$evidence/image-build.log" 2>&1
podman image inspect "$image" > "$evidence/image-inspect.json"
podman image inspect "$image" --format '{{.Id}}' > "$evidence/image-id.txt"
printf '%s\n' "$image" > "$evidence/image-reference.txt"
source "$scratch/source/tools/versions.env"
timeout 600 podman run --rm --name "$compiler" --pull=never --cap-drop=all \
  --security-opt=no-new-privileges -v "$scratch/source:/work:ro" \
  -v "$scratch/target:/tmp/jcomp003-admission-target:rw" -w /work \
  -e CARGO_TARGET_DIR=/tmp/jcomp003-admission-target "$MCLOVING_RUST_IMAGE" bash -c '
    set -euo pipefail
    rustc --version
    cargo build --locked -p mcloving-jenkins-compiler-admission
  ' > "$evidence/admission-build.log" 2>&1
cp "$scratch/target/debug/mcloving-jenkins-compiler-admission" "$evidence/admission"
chmod 0555 "$evidence/admission"
sha256sum "$evidence/admission" > "$evidence/admission.sha256"
python3 - "$scratch/source" "$evidence" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
source, evidence = map(Path, sys.argv[1:])
inputs = [p for p in (source / 'compat/jenkins-worker').rglob('*') if p.is_file() and '.cpcache' not in p.parts]
inputs += [source / name for name in ['Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml']]
inputs += [p for p in (source / 'crates/jenkins-compiler-admission').rglob('*') if p.is_file()]
records = {str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(inputs)}
(evidence / 'compiler-source-inputs.json').write_text(json.dumps(records, indent=2) + '\n')
artifacts = {str(p.relative_to(evidence)):hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(evidence.rglob('*')) if p.is_file()}
(evidence / 'artifacts.json').write_text(json.dumps(artifacts, indent=2) + '\n')
PY
