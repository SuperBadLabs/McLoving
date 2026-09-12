#!/usr/bin/env bash
# Records one evidence row for PAR-005: Foundation's conclusion for a main
# commit against the dogfood build's status for the same commit, appended
# to docs/evidence/PAR-005_DOGFOOD.md as a table row. Foundation is read
# with `gh run list`; the dogfood build is found by the trigger delivery id,
# which the bridge (and GitHub) set to the commit id.
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
committed="$(gh api "repos/${repository}/commits/${commit}" --jq .commit.committer.date)"
# The build for a commit: from the bridge's recorded answer when the bridge
# delivered it, else from the commit status the build itself wrote to
# GitHub, whose target URL names the build (the product's own association,
# the one a public-ingress deployment leaves behind).
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
case "${foundation}:${status}" in
  success:succeeded|failure:failed) match=yes ;;
  *) match=no ;;
esac
if rg -q "^\| [0-9]+ \| \`${commit:0:12}\` \|" "${evidence}"; then
  echo "${commit} is already recorded in ${evidence}" >&2; exit 1
fi
last_committed="$(rg -o '^\| [0-9]+ \| `[0-9a-f]+` \| ([0-9T:Z-]+) \|' -r '$1' "${evidence}" | tail -1 || true)"
if [ -n "${last_committed}" ] && [ ! "${committed}" \> "${last_committed}" ]; then
  echo "${commit} (${committed}) is not newer than the last recorded row (${last_committed})" >&2; exit 1
fi
row="$(rg -c '^\| [0-9]+ \|' "${evidence}" || true)"
printf '| %s | `%s` | %s | %s | `%s` | %s | %s |\n' "$((row + 1))" "${commit:0:12}" "${committed}" "${foundation:-pending}" "${build}" "${status}" "${match}" | tee -a "${evidence}"
