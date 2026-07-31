#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || {
  echo "usage: $0 SNAPSHOT_ROOT" >&2
  exit 64
}

SNAPSHOT_ROOT=$1
PLUGIN_ROOT="$SNAPSHOT_ROOT/plugins"
MANIFEST="$SNAPSHOT_ROOT/PLUGIN_SHA256SUMS"

[[ -d "$PLUGIN_ROOT" && -f "$MANIFEST" ]] || {
  echo "plugin snapshot is incomplete" >&2
  exit 65
}
[[ ! -L "$SNAPSHOT_ROOT" && ! -L "$PLUGIN_ROOT" && ! -L "$MANIFEST" ]] || {
  echo "plugin snapshot paths must not be symbolic links" >&2
  exit 65
}

manifest_plugins=$(awk '
  length($1) != 64 || $1 !~ /^[0-9a-f]+$/ || $2 !~ /^plugins\/[A-Za-z0-9._+-]+\.jpi$/ || NF != 2 {
    exit 65
  }
  { print $2 }
' "$MANIFEST" | LC_ALL=C sort)
actual_plugins=$(
  cd "$SNAPSHOT_ROOT"
  find plugins -mindepth 1 -maxdepth 1 -type f -name '*.jpi' -print | LC_ALL=C sort
)

[[ -n "$manifest_plugins" && "$actual_plugins" == "$manifest_plugins" ]] || {
  echo "plugin directory does not exactly match the sealed manifest" >&2
  exit 66
}
[[ $(find "$PLUGIN_ROOT" -mindepth 1 -maxdepth 1 | wc -l) -eq $(wc -l <<<"$manifest_plugins") ]] || {
  echo "plugin directory contains undeclared or invalid entries" >&2
  exit 66
}

(
  cd "$SNAPSHOT_ROOT"
  sha256sum --strict --check PLUGIN_SHA256SUMS
) >/dev/null
