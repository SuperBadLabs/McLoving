#!/usr/bin/env bash
# Records one evidence row for PAR-005: Foundation's conclusion for a main
# commit against the dogfood build's status for the same push, appended to
# docs/evidence/PAR-005_DOGFOOD.md as a table row. Foundation is read with
# `gh run list`; the dogfood build is found from the bridge's recorded
# answer or, when GitHub delivered directly, from the mcloving/foundation
# status the build wrote to the commit, whose target URL names the build.
# A row is written only when both verdicts are terminal; rows are one per
# build (a commit pushed twice is two pushes, two builds and two rows) and
# in the order the controller created the builds, to the millisecond, which
# is the order the pushes were admitted.
#
# usage: verdicts.sh <state-dir> <commit> [evidence-file] [build-id]
#   build-id selects the build when the bridge delivered the commit more
#   than once (the branch pushed away from it and back).
set -euo pipefail
state="$1"; commit="$2"; evidence="${3:-docs/evidence/PAR-005_DOGFOOD.md}"; chosen="${4:-}"
# shellcheck disable=SC1091
. "${state}/env"
repository="${MCLOVING_DOGFOOD_REPOSITORY}"
cli="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/target/debug/mcloving-cli"

foundation="$(gh run list --repo "${repository}" --workflow Foundation --branch main --commit "${commit}" \
  --json status,conclusion --jq 'first(.[]) | if .status == "completed" then .conclusion else .status end')"
case "${foundation}" in
  success|failure) ;;
  *) echo "Foundation for ${commit} is not terminal yet (${foundation:-no run}); nothing recorded" >&2; exit 1 ;;
esac
# The bridge records one line per delivery: time, push event, commit, build.
candidates="$(awk -v sha="${commit}" '$3 == sha && $4 != "-" { print $4 }' "${state}/deliveries.tsv" 2>/dev/null || true)"
build=""
if [ -n "${chosen}" ]; then
  build="${chosen}"
elif [ "$(printf '%s\n' "${candidates}" | rg -c '.' || true)" -gt 1 ]; then
  echo "${commit} was delivered more than once; name the build to record: ${candidates//$'\n'/ }" >&2; exit 1
else
  build="${candidates}"
fi
if [ -z "${build}" ]; then
  build="$(gh api "repos/${repository}/commits/${commit}/status" \
    --jq '.statuses[] | select(.context == "mcloving/foundation") | .target_url' 2>/dev/null \
    | sed -n 's/.*[?&]build=\([0-9a-f-]\{36\}\).*/\1/p' | head -1)"
fi
if [ -z "${build}" ]; then
  echo "no dogfood build is recorded for ${commit}: no bridge answer in ${state} and no mcloving/foundation status on the commit" >&2; exit 1
fi
status="$("${cli}" --output json status "${build}" | jq -r .status)"
case "${status}" in
  succeeded|failed|aborted) ;;
  *) echo "dogfood build ${build} is not terminal yet (${status}); nothing recorded" >&2; exit 1 ;;
esac
created_ms="$("${cli}" --output json builds | jq -r --arg id "${build}" '.items[] | select(.build_id == $id) | .created_at_unix_ms')"
if [ -z "${created_ms}" ] || [ "${created_ms}" = "null" ]; then
  echo "build ${build} is not in the controller's build list" >&2; exit 1
fi
created="$(date -u -d "@$((created_ms / 1000)).$((created_ms % 1000))" +%Y-%m-%dT%H:%M:%S.%3NZ)"
case "${foundation}:${status}" in
  success:succeeded|failure:failed) match=yes ;;
  *) match=no ;;
esac
if rg -q "\`${build}\`" "${evidence}"; then
  echo "build ${build} is already recorded in ${evidence}" >&2; exit 1
fi
last_created="$(rg -o '^\| [0-9]+ \| `[0-9a-f]+` \| ([0-9T:.Z-]+) \|' -r '$1' "${evidence}" | tail -1 || true)"
if [ -n "${last_created}" ] && [ ! "${created}" \> "${last_created}" ]; then
  echo "build ${build} (${created}) was not created after the last recorded row (${last_created})" >&2; exit 1
fi
row="$(rg -c '^\| [0-9]+ \|' "${evidence}" || true)"
printf '| %s | `%s` | %s | %s | `%s` | %s | %s |\n' "$((row + 1))" "${commit:0:12}" "${created}" "${foundation}" "${build}" "${status}" "${match}" | tee -a "${evidence}"
