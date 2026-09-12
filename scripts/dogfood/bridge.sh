#!/usr/bin/env bash
# Webhook bridge for the dogfood deployment (PAR-005). A host without public
# ingress cannot receive GitHub's deliveries, so this loop reads the
# repository's push events for the branch and posts each one to the
# controller's own public webhook route as a push delivery, signed with the
# trigger's derived secret exactly as GitHub would sign it: the receiver, the
# trigger filter, the idempotency on the delivery id and the admission path
# are the ones GitHub exercises. The delivery id is the push event's own id,
# so a branch pushed away from a commit and back to it is two deliveries and
# two builds, as at GitHub. When Tailscale Funnel (or any public ingress)
# reaches the controller, the hook route is registered at GitHub instead and
# this loop is not run; the two never run together.
#
# usage: bridge.sh <state-dir> [interval-seconds|once]
#   state-dir holds hook.json (path + secret, written by heman-up.sh) and,
#   per repository and branch, the id of the last delivered push event and
#   the delivery record; MCLOVING_URL and MCLOVING_DOGFOOD_REPOSITORY
#   (owner/name) come from the environment.
set -euo pipefail
state="$1"
interval="${2:-60}"
repository="${MCLOVING_DOGFOOD_REPOSITORY:?owner/name}"
branch="${MCLOVING_DOGFOOD_BRANCH:-main}"
hook_path="$(jq -r .path "${state}/hook.json")"
secret="$(jq -r .secret "${state}/hook.json")"
# The watermark and the delivery record are the repository's and branch's
# own, so a state directory restarted against another repository (a fork
# sharing commit ids, say) starts that repository's record afresh.
scope="${repository//\//__}.${branch//\//__}"
last_file="${state}/last-delivered-event.${scope}"
ledger="${state}/deliveries.${scope}.tsv"
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

sign() { printf 'sha256=%s' "$(openssl dgst -sha256 -hmac "${secret}" <"$1" | sed 's/^.* //')"; }

# Delivers one push: event id, head and the time GitHub recorded the push
# (`-` for a branch-head fallback). Answers non-zero unless the route
# acknowledged it (admitted, replayed or filtered), so a failed delivery is
# retried on the next pass and never recorded as done.
deliver() {
  local event="$1" sha="$2" pushed_at="${3:--}"
  local body="${state}/delivery-${event}.json" answer="${state}/answer-${event}.json" commit="${state}/commit-${sha}.json" code
  gh api "repos/${repository}/commits/${sha}" \
    --jq '{sha, message: .commit.message, timestamp: .commit.committer.date, files: [.files[]?.filename]}' \
    >"${commit}"
  python3 - "${repository}" "${branch}" "${body}" "${commit}" <<'PY'
import json, sys
repository, branch, out, commit_path = sys.argv[1:5]
commit = json.load(open(commit_path))
owner, name = repository.split("/", 1)
body = {
    "ref": f"refs/heads/{branch}", "before": "0" * 40, "after": commit["sha"],
    "created": False, "deleted": False, "forced": False,
    "commits": [{"id": commit["sha"], "message": commit["message"], "timestamp": commit["timestamp"],
                 "added": [], "removed": [], "modified": commit["files"]}],
    "head_commit": {"id": commit["sha"], "timestamp": commit["timestamp"]},
    "repository": {"name": name, "full_name": repository, "private": False,
                   "html_url": f"https://github.com/{repository}", "default_branch": branch},
    "pusher": {"name": "dogfood-bridge"}, "sender": {"login": "dogfood-bridge"},
}
open(out, "w").write(json.dumps(body, separators=(",", ":")))
PY
  code="$(curl -sS -o "${answer}" -w '%{http_code}' -X POST "${MCLOVING_URL}${hook_path}" \
    -H 'Content-Type: application/json' -H "X-GitHub-Delivery: ${event}" \
    -H 'X-GitHub-Event: push' -H "X-Hub-Signature-256: $(sign "${body}")" --data-binary "@${body}")"
  # The bridge's own record of which build each push got, for verdicts.sh:
  # one line per push event (time, event, commit, build, push time), so a
  # commit pushed twice keeps both builds, and an event delivered again
  # after a crash between the answer and the watermark (the controller
  # replays the same build) is not recorded twice.
  local build
  build="$(jq -r '.admission.build_id // "-"' "${answer}" 2>/dev/null || echo -)"
  if [ "${build}" = "-" ] || ! awk -v ev="${event}" '$2 == ev && $4 != "-" { found = 1 } END { exit !found }' "${ledger}" 2>/dev/null; then
    printf '%s %s %s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${event}" "${sha}" "${build}" "${pushed_at}" >>"${ledger}"
  fi
  log "push ${event} ${sha} -> ${code} $(jq -c '{build_id: .admission.build_id, status: .status}' "${answer}" 2>/dev/null || true)"
  case "${code}" in 2*) return 0 ;; *) return 1 ;; esac
}

# The pushes to the branch since the last delivered one, oldest first, as
# "<event id> <head> <created_at>" lines: GitHub's push events, paged newest first until
# the watermark is found. A page request that fails aborts the pass (answer
# 1) rather than being read as the end of the events, so nothing is skipped
# on a transient error. Without a record yet, only the newest push (or the
# branch head, if the events list none) is delivered. If the watermark is
# older than the events GitHub still lists (an outage longer than its event
# window), the newest push alone is delivered and the gap is logged, since
# the pushes between cannot be known.
pending_pushes() {
  local last page events batch pushes found
  last="$(cat "${last_file}" 2>/dev/null || true)"
  pushes=""
  found=""
  # GitHub lists at most 300 events (three pages of 100); a fourth page is
  # refused with 422, so the window ends here rather than failing the pass.
  for page in 1 2 3; do
    if ! events="$(gh api "repos/${repository}/events?per_page=100&page=${page}")"; then
      log "events page ${page} failed; retrying this pass later" >&2
      return 1
    fi
    [ "$(printf '%s' "${events}" | jq 'length')" = "0" ] && break
    batch="$(printf '%s' "${events}" \
      | jq -r ".[] | select(.type == \"PushEvent\" and .payload.ref == \"refs/heads/${branch}\") | \"\\(.id) \\(.payload.head) \\(.created_at)\"")"
    pushes="${pushes}${batch}
"
    if [ -z "${last}" ]; then
      [ -n "${batch}" ] && break
      continue
    fi
    if printf '%s' "${batch}" | rg -q "^${last} "; then found=yes; break; fi
  done
  if [ -z "${last}" ]; then
    if [ -n "$(printf '%s' "${pushes}" | head -1)" ]; then
      printf '%s' "${pushes}" | awk 'NF { print; exit }'
    else
      local head
      head="$(gh api "repos/${repository}/branches/${branch}" --jq .commit.sha)" || return 1
      printf 'branch-%s %s -\n' "${head}" "${head}"
    fi
    return 0
  fi
  if [ -z "${found}" ]; then
    if [ -n "$(printf '%s' "${pushes}" | head -1)" ]; then
      log "watermark ${last} is older than the push events GitHub lists; delivering the newest push only" >&2
      printf '%s' "${pushes}" | awk 'NF { print; exit }'
      return 0
    fi
    # No push to the branch is listed at all: the branch head is delivered
    # under a branch-<sha> id unless it is the head last delivered.
    local head last_sha
    head="$(gh api "repos/${repository}/branches/${branch}" --jq .commit.sha)" || return 1
    last_sha="$(awk '$4 != "-" { sha = $3 } END { print sha }' "${ledger}" 2>/dev/null || true)"
    if [ "${head}" != "${last_sha}" ]; then
      log "watermark ${last} is older than the events GitHub lists and none is a push to ${branch}; delivering the branch head" >&2
      printf 'branch-%s %s -\n' "${head}" "${head}"
    fi
    return 0
  fi
  printf '%s' "${pushes}" | awk -v last="${last}" '$1 == last { exit } NF && !seen[$1]++ { print }' | tac
}

while :; do
  # The watermark is contiguous: a failed delivery stops this pass, so the
  # next one starts again at that push rather than skipping it.
  if pending="$(pending_pushes)"; then
    while read -r event sha pushed_at; do
      [ -z "${event}" ] && continue
      deliver "${event}" "${sha}" "${pushed_at}" || break
      # Written beside and renamed over, so a crash mid-write leaves the
      # previous watermark rather than an empty one.
      printf '%s\n' "${event}" >"${last_file}.next"
      sync "${last_file}.next"
      mv -f "${last_file}.next" "${last_file}"
    done <<<"${pending}"
  fi
  [ "${interval}" = "once" ] && exit 0
  sleep "${interval}"
done
