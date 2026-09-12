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
pushed="$(gh api "repos/${repository}/commits/${commit}" --jq .commit.committer.date)"
build="$(jq -r '.admission.build_id // empty' "${state}/answer-${commit}.json" 2>/dev/null || true)"
if [ -z "${build}" ]; then
  echo "no dogfood build recorded for ${commit} in ${state}" >&2; exit 1
fi
status="$("${cli}" --output json status "${build}" | jq -r .status)"
case "${foundation}:${status}" in
  success:succeeded|failure:failed) match=yes ;;
  *) match=no ;;
esac
row="$(rg -c '^\| [0-9]+ \|' "${evidence}" || true)"
printf '| %s | `%s` | %s | %s | `%s` | %s | %s |\n' "$((row + 1))" "${commit:0:12}" "${pushed}" "${foundation:-pending}" "${build}" "${status}" "${match}" | tee -a "${evidence}"
