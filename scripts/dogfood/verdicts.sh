#!/usr/bin/env bash
# Records one evidence row for PAR-005: Foundation's conclusion for a main
# push against the dogfood build's status for the same push, appended to
# docs/evidence/PAR-005_DOGFOOD.md as a table row. Both sides are keyed by
# push: GitHub starts one Foundation run per push, within moments of it,
# and the bridge records one delivery (and build) per push event with the
# time GitHub recorded the push, so the Foundation run paired with a build
# is the one run for the commit created within the pairing window after
# that push time; a push time the bridge could not record (a branch-head
# fallback), or a build read from the mcloving/foundation status because
# GitHub delivered directly, pairs only when the commit has exactly one
# Foundation run. Runs the record cannot account for are never paired by
# position.
# A row is written only when both verdicts are terminal; rows are one per
# build (a commit pushed twice is two pushes, two builds and two rows) and
# in the order the controller created the builds, to the millisecond, which
# is the order the pushes were admitted.
#
# usage: verdicts.sh <state-dir> <commit> [evidence-file] [build-id]
#   build-id selects the build when the bridge delivered the commit more
#   than once (the branch pushed away from it and back); it must be one of
#   the builds recorded for that commit.
set -euo pipefail
state="$1"; commit="$2"; evidence="${3:-docs/evidence/PAR-005_DOGFOOD.md}"; chosen="${4:-}"
# shellcheck disable=SC1091
. "${state}/env"
repository="${MCLOVING_DOGFOOD_REPOSITORY}"
cli="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/target/debug/mcloving-cli"

# Foundation's runs for the commit, oldest first: one per push of it.
runs="$(gh run list --repo "${repository}" --workflow Foundation --branch main --commit "${commit}" \
  --json databaseId,status,conclusion,createdAt \
  --jq 'sort_by(.createdAt) | .[] | "\(.databaseId) \(if .status == "completed" then .conclusion else .status end) \(.createdAt)"')"
run_count="$(printf '%s\n' "${runs}" | rg -c . || echo 0)"
if [ "${run_count}" -eq 0 ]; then
  echo "Foundation has no run for ${commit}; nothing recorded" >&2; exit 1
fi
# The bridge records one line per push event: time, event, commit, build,
# push time (`-` for a branch-head fallback), under the repository's own
# ledger; the chosen build must be one of them. A build recorded twice
# (an event delivered again after a crash) is one candidate.
ledger="${state}/deliveries.${repository//\//__}.main.tsv"
records="$(awk -v sha="${commit}" '$3 == sha && $4 != "-" && !seen[$4]++ { print $4, $5 }' "${ledger}" 2>/dev/null || true)"
candidates="$(printf '%s\n' "${records}" | awk 'NF { print $1 }')"
candidate_count="$(printf '%s\n' "${candidates}" | rg -c . || echo 0)"
# The run GitHub started for a push: created within the window after the
# push time, and the only one there.
pairing_window=900
run_for_push() {
  local pushed_at="$1" pushed_s
  pushed_s="$(date -u -d "${pushed_at}" +%s)"
  printf '%s\n' "${runs}" | while read -r id conclusion created_at; do
    [ -z "${id}" ] && continue
    created_s="$(date -u -d "${created_at}" +%s)"
    if [ "${created_s}" -ge $((pushed_s - 60)) ] && [ "${created_s}" -le $((pushed_s + pairing_window)) ]; then
      printf '%s %s\n' "${id}" "${conclusion}"
    fi
  done
}
build=""
if [ -n "${chosen}" ]; then
  if ! printf '%s\n' "${candidates}" | rg -q -x -F "${chosen}"; then
    echo "build ${chosen} is not one the bridge recorded for ${commit}: ${candidates//$'\n'/ }" >&2; exit 1
  fi
  build="${chosen}"
elif [ "${candidate_count}" -gt 1 ]; then
  echo "${commit} was delivered more than once; name the build to record: ${candidates//$'\n'/ }" >&2; exit 1
else
  build="${candidates}"
fi
if [ -n "${build}" ]; then
  pushed_at="$(printf '%s\n' "${records}" | awk -v id="${build}" '$1 == id { print $2; exit }')"
  if [ "${pushed_at}" = "-" ]; then
    if [ "${run_count}" -ne 1 ]; then
      echo "build ${build} was a branch-head delivery without a push time and ${commit} has ${run_count} Foundation runs; nothing recorded" >&2; exit 1
    fi
    run_line="${runs}"
  else
    paired="$(run_for_push "${pushed_at}")"
    paired_count="$(printf '%s\n' "${paired}" | rg -c . || echo 0)"
    if [ "${paired_count}" -ne 1 ]; then
      echo "${paired_count} Foundation runs for ${commit} were created within ${pairing_window}s of the push at ${pushed_at}; nothing recorded" >&2; exit 1
    fi
    run_line="${paired}"
  fi
else
  build="$(gh api "repos/${repository}/commits/${commit}/status" \
    --jq '.statuses[] | select(.context == "mcloving/foundation") | .target_url' 2>/dev/null \
    | sed -n 's/.*[?&]build=\([0-9a-f-]\{36\}\).*/\1/p' | head -1)"
  if [ -z "${build}" ]; then
    echo "no dogfood build is recorded for ${commit}: no bridge delivery in ${state} and no mcloving/foundation status on the commit" >&2; exit 1
  fi
  if [ "${run_count}" -ne 1 ]; then
    echo "${commit} has ${run_count} Foundation runs and no bridge record to pair the build with; nothing recorded" >&2; exit 1
  fi
  run_line="${runs}"
fi
run_id="${run_line%% *}"
foundation="$(printf '%s\n' "${run_line}" | awk '{ print $2 }')"
case "${foundation}" in
  success|failure) ;;
  *) echo "Foundation run ${run_id} for ${commit} is not terminal yet (${foundation}); nothing recorded" >&2; exit 1 ;;
esac
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
if rg -q "\| ${run_id} \|" "${evidence}"; then
  echo "Foundation run ${run_id} is already recorded in ${evidence}" >&2; exit 1
fi
last_created="$(rg -o '^\| [0-9]+ \| `[0-9a-f]+` \| ([0-9T:.Z-]+) \|' -r '$1' "${evidence}" | tail -1 || true)"
if [ -n "${last_created}" ] && [ ! "${created}" \> "${last_created}" ]; then
  echo "build ${build} (${created}) was not created after the last recorded row (${last_created})" >&2; exit 1
fi
row="$(rg -c '^\| [0-9]+ \|' "${evidence}" || true)"
printf '| %s | `%s` | %s | %s | %s | `%s` | %s | %s |\n' "$((row + 1))" "${commit:0:12}" "${created}" "${run_id}" "${foundation}" "${build}" "${status}" "${match}" | tee -a "${evidence}"
