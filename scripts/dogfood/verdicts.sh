#!/usr/bin/env bash
# Records one evidence row for PAR-005: Foundation's conclusion for a main
# commit against the dogfood build's status for the same commit, appended
# to docs/evidence/PAR-005_DOGFOOD.md as a table row. Foundation is read
# with `gh run list`; the dogfood build is found from the bridge's recorded
# answer or, when GitHub delivered directly, from the mcloving/foundation
# status the build wrote to the commit, whose target URL names the build.
# Rows are one per commit and in the order the controller created the
# builds, which is the order the pushes were admitted.
#
# usage: verdicts.sh <state-dir> <commit> [evidence-file]
set -euo pipefail
state="$1"; commit="$2"; evidence="${3:-docs/evidence/PAR-005_DOGFOOD.md}"
# shellcheck disable=SC1091
. "${state}/env"
repository="${MCLOVING_DOGFOOD_REPOSITORY}"
cli="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/target/debug/mcloving-cli"

foundation="$(gh run list --repo "${repository}" --workflow Foundation --branch main --commit "${commit}" \
  --json status,conclusion --jq 'first(.[]) | if .status == "completed" then .conclusion else .status end' 2>/dev/null || true)"
build="$(jq -r '.admission.build_id // empty' "${state}/answer-${commit}.json" 2>/dev/null || true)"
if [ -z "${build}" ]; then
  build="$(gh api "repos/${repository}/commits/${commit}/status" \
    --jq '.statuses[] | select(.context == "mcloving/foundation") | .target_url' 2>/dev/null \
    | sed -n 's/.*[?&]build=\([0-9a-f-]\{36\}\).*/\1/p' | head -1)"
fi
if [ -z "${build}" ]; then
  echo "no dogfood build is recorded for ${commit}: no bridge answer in ${state} and no mcloving/foundation status on the commit" >&2; exit 1
fi
status="$("${cli}" --output json status "${build}" | jq -r .status)"
created_ms="$("${cli}" --output json builds | jq -r --arg id "${build}" '.items[] | select(.build_id == $id) | .created_at_unix_ms')"
if [ -z "${created_ms}" ] || [ "${created_ms}" = "null" ]; then
  echo "build ${build} is not in the controller's build list" >&2; exit 1
fi
created="$(date -u -d "@$((created_ms / 1000))" +%Y-%m-%dT%H:%M:%SZ)"
case "${foundation}:${status}" in
  success:succeeded|failure:failed) match=yes ;;
  *) match=no ;;
esac
if rg -q "^\| [0-9]+ \| \`${commit:0:12}\` \|" "${evidence}"; then
  echo "${commit} is already recorded in ${evidence}" >&2; exit 1
fi
last_created="$(rg -o '^\| [0-9]+ \| `[0-9a-f]+` \| ([0-9T:Z-]+) \|' -r '$1' "${evidence}" | tail -1 || true)"
if [ -n "${last_created}" ] && [ ! "${created}" \> "${last_created}" ]; then
  echo "build ${build} (${created}) was not created after the last recorded row (${last_created})" >&2; exit 1
fi
row="$(rg -c '^\| [0-9]+ \|' "${evidence}" || true)"
printf '| %s | `%s` | %s | %s | `%s` | %s | %s |\n' "$((row + 1))" "${commit:0:12}" "${created}" "${foundation:-pending}" "${build}" "${status}" "${match}" | tee -a "${evidence}"
