#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 SNAPSHOT_ROOT [IMAGE]" >&2
  exit 64
}

[[ $# -ge 1 && $# -le 2 ]] || usage

SNAPSHOT_ROOT=$1
IMAGE=${2:-localhost/mcloving/jenkins-compiler-worker:mario-jenkins-oracle-228-v1}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
EXPECTED_BASE=sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02
EXPECTED_PROFILE=feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271
EXPECTED_PLUGIN_MANIFEST=e33fa87646e6e360e7614373cc0057ba2e92ff18b9a9ea9419dea796dcb950b0

[[ -d "$SNAPSHOT_ROOT/plugins" ]] || usage
[[ -f "$SNAPSHOT_ROOT/PLUGIN_SHA256SUMS" ]] || usage
[[ ! -L "$SNAPSHOT_ROOT" && ! -L "$SNAPSHOT_ROOT/plugins" ]] || {
  echo "snapshot roots must not be symbolic links" >&2
  exit 65
}

actual_profile=$(sha256sum "$SCRIPT_DIR/profile-v1.properties" | awk '{print $1}')
actual_plugin_manifest=$(sha256sum "$SNAPSHOT_ROOT/PLUGIN_SHA256SUMS" | awk '{print $1}')
[[ "$actual_profile" == "$EXPECTED_PROFILE" ]] || {
  echo "profile digest mismatch" >&2
  exit 66
}
[[ "$actual_plugin_manifest" == "$EXPECTED_PLUGIN_MANIFEST" ]] || {
  echo "plugin manifest digest mismatch" >&2
  exit 66
}

"$SCRIPT_DIR/verify-plugin-directory.sh" "$SNAPSHOT_ROOT"

base_id=$(podman image inspect \
  docker.io/jenkins/jenkins@"$EXPECTED_BASE" \
  --format '{{.Id}}')
[[ "$base_id" == "3b072c3e47bfa9a97dc733fc414da2005c99180f111ac0842327bd963509a1c1" ||
   "$base_id" == "sha256:3b072c3e47bfa9a97dc733fc414da2005c99180f111ac0842327bd963509a1c1" ]] || {
  echo "base image identity mismatch" >&2
  exit 66
}

BUILD_CONTEXT=$(mktemp -d "${TMPDIR:-/tmp}/mcloving-compiler-build.XXXXXXXX")
cleanup() {
  rm -rf -- "$BUILD_CONTEXT"
}
trap cleanup EXIT

mkdir -p \
  "$BUILD_CONTEXT/runtime/clojure" \
  "$BUILD_CONTEXT/runtime/profile/plugins"
cp "$SCRIPT_DIR/Containerfile" "$BUILD_CONTEXT/Containerfile"
cp -R "$SCRIPT_DIR/src" "$BUILD_CONTEXT/src"
cp "$SCRIPT_DIR/profile-v1.properties" \
  "$BUILD_CONTEXT/runtime/profile/profile-v1.properties"
cp "$SNAPSHOT_ROOT/PLUGIN_SHA256SUMS" \
  "$BUILD_CONTEXT/runtime/profile/PLUGIN_SHA256SUMS"
cp "$SNAPSHOT_ROOT"/plugins/*.jpi \
  "$BUILD_CONTEXT/runtime/profile/plugins/"

clojure_classpath=$(cd "$SCRIPT_DIR" && clojure -Spath)
IFS=: read -r -a classpath_entries <<< "$clojure_classpath"
for entry in "${classpath_entries[@]}"; do
  [[ "$entry" == *.jar ]] || continue
  cp "$entry" "$BUILD_CONTEXT/runtime/clojure/"
done

[[ $(find "$BUILD_CONTEXT/runtime/clojure" -maxdepth 1 -type f -name '*.jar' | wc -l) -eq 3 ]] || {
  echo "expected exactly three Clojure runtime jars" >&2
  exit 66
}

podman build \
  --pull-never \
  --network none \
  --tag "$IMAGE" \
  "$BUILD_CONTEXT"

podman image inspect "$IMAGE" \
  --format 'image={{.Id}} profile={{index .Labels "io.mcloving.compiler.profile.sha256"}} base={{index .Labels "io.mcloving.compiler.base.digest"}}'
