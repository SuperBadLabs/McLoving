#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/mcloving-plugin-directory-test.XXXXXXXX")
cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

write_manifest() {
  (
    cd "$1"
    sha256sum plugins/alpha.jpi plugins/bravo-1.0.jpi > PLUGIN_SHA256SUMS
  )
}

mkdir -p "$TEST_ROOT/valid/plugins"
printf alpha > "$TEST_ROOT/valid/plugins/alpha.jpi"
printf bravo > "$TEST_ROOT/valid/plugins/bravo-1.0.jpi"
write_manifest "$TEST_ROOT/valid"
"$SCRIPT_DIR/verify-plugin-directory.sh" "$TEST_ROOT/valid"

cp -a "$TEST_ROOT/valid" "$TEST_ROOT/extra"
printf hostile > "$TEST_ROOT/extra/plugins/undeclared.jpi"
if "$SCRIPT_DIR/verify-plugin-directory.sh" "$TEST_ROOT/extra" >/dev/null 2>&1; then
  echo "undeclared plugin was accepted" >&2
  exit 1
fi

cp -a "$TEST_ROOT/valid" "$TEST_ROOT/non-plugin"
printf metadata > "$TEST_ROOT/non-plugin/plugins/README"
if "$SCRIPT_DIR/verify-plugin-directory.sh" "$TEST_ROOT/non-plugin" >/dev/null 2>&1; then
  echo "undeclared plugin-directory entry was accepted" >&2
  exit 1
fi

cp -a "$TEST_ROOT/valid" "$TEST_ROOT/symlink"
ln -s alpha.jpi "$TEST_ROOT/symlink/plugins/alias.jpi"
if "$SCRIPT_DIR/verify-plugin-directory.sh" "$TEST_ROOT/symlink" >/dev/null 2>&1; then
  echo "plugin symlink was accepted" >&2
  exit 1
fi

cp -a "$TEST_ROOT/valid" "$TEST_ROOT/tampered"
printf changed > "$TEST_ROOT/tampered/plugins/alpha.jpi"
if "$SCRIPT_DIR/verify-plugin-directory.sh" "$TEST_ROOT/tampered" >/dev/null 2>&1; then
  echo "plugin digest mismatch was accepted" >&2
  exit 1
fi

echo "plugin-directory-contract-ok"
