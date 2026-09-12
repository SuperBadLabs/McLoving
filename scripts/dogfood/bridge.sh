#!/usr/bin/env bash
# Webhook bridge for the dogfood deployment (PAR-005). A host without public
# ingress cannot receive GitHub's deliveries, so this loop asks GitHub for
# the branch head and posts each new head to the controller's own public
# webhook route as a push delivery, signed with the trigger's derived secret
# exactly as GitHub would sign it: the receiver, the trigger filter, the
# idempotency on the delivery id and the admission path are the ones GitHub
# exercises. When Tailscale Funnel (or any public ingress) reaches the
# controller, the hook route is registered at GitHub instead and this loop
# is not run; the two never run together, since a delivery id is the commit
# id and the receiver acknowledges a repeat without a second build.
#
# usage: bridge.sh <state-dir> [interval-seconds]
#   state-dir holds hook.json (path + secret, written by heman-up.sh) and
#   the last head delivered; MCLOVING_URL and MCLOVING_DOGFOOD_REPOSITORY
#   (owner/name) come from the environment.
set -euo pipefail
state="$1"
interval="${2:-60}"
repository="${MCLOVING_DOGFOOD_REPOSITORY:?owner/name}"
branch="${MCLOVING_DOGFOOD_BRANCH:-main}"
hook_path="$(jq -r .path "${state}/hook.json")"
secret="$(jq -r .secret "${state}/hook.json")"
last_file="${state}/last-delivered"

sign() { printf 'sha256=%s' "$(openssl dgst -sha256 -hmac "${secret}" <"$1" | sed 's/^.* //')"; }

deliver() {
  local sha="$1" body="${state}/delivery-${1}.json" answer="${state}/answer-${1}.json" commit="${state}/commit-${1}.json" code
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
    -H 'Content-Type: application/json' -H "X-GitHub-Delivery: ${sha}" \
    -H 'X-GitHub-Event: push' -H "X-Hub-Signature-256: $(sign "${body}")" --data-binary "@${body}")"
  printf '%s %s -> %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${sha}" "${code}" "$(jq -c '{build_id: .admission.build_id, status: .status}' "${answer}" 2>/dev/null || true)"
  # Only an acknowledged delivery (admitted, replayed or filtered) is
  # recorded as delivered; anything else is retried on the next pass.
  case "${code}" in 2*) return 0 ;; *) return 1 ;; esac
}

# The heads pushed since the last delivered one, oldest first: two pushes
# inside one polling interval are two deliveries, not one. Without a record
# yet, only the current head is delivered.
pending_heads() {
  local last
  last="$(cat "${last_file}" 2>/dev/null || true)"
  if [ -z "${last}" ]; then
    gh api "repos/${repository}/branches/${branch}" --jq .commit.sha 2>/dev/null || true
    return
  fi
  gh api "repos/${repository}/commits?sha=${branch}&per_page=100" --jq '.[].sha' 2>/dev/null \
    | awk -v last="${last}" '$0 == last { exit } { print }' | tac
}

while :; do
  for head in $(pending_heads); do
    deliver "${head}" && printf '%s\n' "${head}" >"${last_file}"
  done
  [ "${interval}" = "once" ] && exit 0
  sleep "${interval}"
done
