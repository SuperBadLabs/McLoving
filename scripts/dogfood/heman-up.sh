#!/usr/bin/env bash
# Brings the dogfood deployment up on the owner's host (PAR-005): a
# PostgreSQL container, the controller with the source and notification
# catalogs and credentials, a remote mTLS agent with a sealed source binding
# for this repository, the webhook trigger, and the pipeline from
# .mcloving/pipeline.yaml rendered with the deployment's binding digest.
# Everything lives under one state directory; running the script again
# tears the previous instance down and starts afresh from the same
# identities, so the pipeline id, the mapping id and the hook route stay
# stable across restarts.
#
# usage: heman-up.sh <state-dir>
# needs: podman, sudo (a tmpfs for the acquirer transport), gh (the GitHub
# token for commit statuses), a built target/debug (the script builds it).
set -euo pipefail
lifecycle="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hook-lifecycle.py"
if [[ "${2:-}" != --under-transition-lock ]]; then
  [[ $# == 1 ]] || { echo 'usage: heman-up.sh state-dir' >&2; exit 2; }
  exec python3 "${lifecycle}" run "$1"
fi
[[ $# == 2 ]] || exit 2
state="$1"
python3 "${lifecycle}" assert-lock "${state}"
python3 "${lifecycle}" begin "${state}"
# The old public sender must be durably observed inactive while its old
# runtime/route still exists. A failed fence leaves every runtime untouched.
python3 "${lifecycle}" quiesce "${state}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo}"
# shellcheck source=../../tools/versions.env
. tools/versions.env

repository="${MCLOVING_DOGFOOD_REPOSITORY:-SuperBadLabs/McLoving}"
db_port="${MCLOVING_DOGFOOD_DB_PORT:-41720}"
api_port="${MCLOVING_DOGFOOD_API_PORT:-41721}"
agent_port="${MCLOVING_DOGFOOD_AGENT_PORT:-41722}"
transport_root="${MCLOVING_DOGFOOD_TRANSPORT_ROOT:-/tmp/mcloving-dogfood-transport}"
transport_bytes=$((512 * 1024 * 1024))
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
secret() { python3 -c 'import secrets; print(secrets.token_hex(32))'; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

controller="${repo}/target/debug/mcloving-controller"
agent_bin="${repo}/target/debug/mcloving-agent"
admin="${repo}/target/debug/mcloving-identity-admin"
cli="${repo}/target/debug/mcloving-cli"
acquirer="${repo}/target/debug/mcloving-source-acquirer"
render="${repo}/target/debug/examples/render_source_binding"

echo "== stop the previous instance"
# Retain ambiguous receipts; pidfds bind termination to the recorded process.
python3 "${lifecycle}" stop "${state}" bridge "${repo}/scripts/dogfood/bridge.sh"
python3 "${lifecycle}" stop "${state}" agent "${agent_bin}"
python3 "${lifecycle}" stop "${state}" controller "${controller}"

echo "== build"
cargo build --locked -p mcloving-controller -p mcloving-agent -p mcloving-source-acquirer -p mcloving-cli 2>&1 | tail -1
cargo build --locked -p mcloving-agent --example render_source_binding 2>&1 | tail -1

echo "== identities (kept across restarts)"
ids="${state}/identities.env"
if [ ! -f "${ids}" ]; then
  umask 077
  cat >"${ids}" <<EOF
organization_id=$(uuid)
project_id=$(uuid)
pipeline_id=$(uuid)
trigger_id=$(uuid)
api_token=$(secret)
artifact_token=$(secret)
agent_id=dogfood-agent
EOF
  umask 022
fi
# shellcheck disable=SC1090
. "${ids}"

echo "== database (podman ${MCLOVING_POSTGRES_IMAGE##*@})"
podman rm -f mcloving-dogfood-db >/dev/null 2>&1 || true
podman volume create mcloving-dogfood-db >/dev/null 2>&1 || true
podman run --detach --name mcloving-dogfood-db --publish "127.0.0.1:${db_port}:5432" \
  --volume mcloving-dogfood-db:/var/lib/postgresql/data \
  --env POSTGRES_USER=mcloving --env POSTGRES_HOST_AUTH_METHOD=trust --env POSTGRES_DB=mcloving \
  "${MCLOVING_POSTGRES_IMAGE}" >/dev/null
for _ in $(seq 1 120); do
  if podman exec mcloving-dogfood-db pg_isready --username mcloving --dbname mcloving >/dev/null 2>&1; then sleep 1; break; fi
  sleep 0.5
done
migration_url="postgres://mcloving@127.0.0.1:${db_port}/mcloving"
runtime_url="postgres://mcloving_tenant@127.0.0.1:${db_port}/mcloving"
MCLOVING_MIGRATION_DATABASE_URL="${migration_url}" "${admin}" migrate >"${state}/migrate.txt"
podman exec mcloving-dogfood-db psql --username mcloving --dbname mcloving --set ON_ERROR_STOP=1 --quiet \
  --command "ALTER ROLE mcloving_tenant LOGIN" >/dev/null
MCLOVING_MIGRATION_DATABASE_URL="${migration_url}" "${admin}" create-project \
  --organization "${organization_id}" --organization-slug dogfood \
  --project "${project_id}" --project-slug mcloving >"${state}/project.txt" 2>&1 || true

echo "== mTLS"
pki="${state}/pki"
if [ ! -f "${pki}/ca.pem" ]; then
  mkdir -p "${pki}"
  openssl req -new -newkey rsa:2048 -nodes -x509 -days 3650 -subj /CN=mcloving-dogfood-ca \
    -keyout "${pki}/ca-key.pem" -out "${pki}/ca.pem" 2>/dev/null
  printf 'subjectAltName=DNS:controller.internal,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' >"${pki}/server.ext"
  openssl req -new -newkey rsa:2048 -nodes -subj /CN=controller.internal \
    -keyout "${pki}/server-key.pem" -out "${pki}/server.csr" 2>/dev/null
  openssl x509 -req -days 3650 -in "${pki}/server.csr" -CA "${pki}/ca.pem" -CAkey "${pki}/ca-key.pem" \
    -CAcreateserial -extfile "${pki}/server.ext" -out "${pki}/server.pem" 2>/dev/null
  printf 'extendedKeyUsage=clientAuth\n' >"${pki}/agent.ext"
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${agent_id}" \
    -keyout "${pki}/agent-key.pem" -out "${pki}/agent.csr" 2>/dev/null
  openssl x509 -req -days 3650 -in "${pki}/agent.csr" -CA "${pki}/ca.pem" -CAkey "${pki}/ca-key.pem" \
    -CAcreateserial -extfile "${pki}/agent.ext" -out "${pki}/agent.pem" 2>/dev/null
  openssl x509 -in "${pki}/agent.pem" -outform DER -out "${pki}/agent.der" 2>/dev/null
  printf '%s %s trusted-linux %s\n' "$(sha "${pki}/agent.der")" "${agent_id}" "${organization_id}" >"${pki}/identity-bindings.txt"
fi

echo "== acquirer transport (${transport_bytes} bytes tmpfs at ${transport_root})"
sudo mkdir -p "${transport_root}"
if ! mountpoint -q "${transport_root}"; then
  sudo mount -t tmpfs -o "size=${transport_bytes},nr_inodes=65536,nosuid,nodev,noexec,mode=0700,uid=$(id -u),gid=$(id -g)" tmpfs "${transport_root}"
fi
sudo chown "$(id -u):$(id -g)" "${transport_root}"; sudo chmod 0700 "${transport_root}"

if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = "1" ]; then
  echo "== acquirer AppArmor profile (user namespaces are restricted on this host)"
  if ! aa-exec -p mcloving-source-acquirer -- /bin/true 2>/dev/null; then
    sudo apparmor_parser -r "${repo}/deploy/apparmor/mcloving-source-acquirer"
  fi
  aa-exec -p mcloving-source-acquirer -- /bin/true
fi

echo "== sealed source binding for ${repository}"
mkdir -p "${state}/agent-workspace" "${state}/objects" "${state}/embedded"
python3 "${lifecycle}" writable-output "${state}"
rm -rf -- "${state}/source-output"
cat >"${state}/source-intent.json" <<EOF
{"mapping_id":"source.mcloving","organization_id":"${organization_id}","project_id":"${project_id}",
 "pipeline_id":"${pipeline_id}","trust_pool":"trusted-linux",
 "repository_url":"https://github.com/${repository}.git",
 "private_dir":"${state}/source-private","acquirer_binary":"${acquirer}",
 "transport_root":"${transport_root}","transport_bytes":${transport_bytes},
 "output_root":"${state}/source-output",
 "deployment_identity":"heman-dogfood","operator_identity":"$(id -un)@$(hostname)",
 "max_files":20000,"max_total_bytes":268435456,"max_file_bytes":33554432}
EOF
"${render}" "${state}/source-intent.json" | tee "${state}/source-binding.txt"
mapping_digest="$(rg -o 'mapping_digest=(.*)' -r '$1' "${state}/source-binding.txt")"
bindings_path="${state}/source-private/agent-source-bindings.json"
bindings_sha="$(sha "${bindings_path}")"

echo "== catalogs and credentials"
cat >"${state}/source-catalog.json" <<EOF
{"schema_version":"mcloving.source-mapping-catalog/v1","profile":"heman-dogfood","generation":1,"mappings":[
 {"mapping_id":"source.mcloving","mapping_digest":"${mapping_digest}","organization_id":"${organization_id}",
  "project_id":"${project_id}","pipeline_id":"${pipeline_id}","trust_pool":"trusted-linux"}]}
EOF
cat >"${state}/notification-catalog.json" <<EOF
{"schema_version":"mcloving.notification-mapping-catalog/v1","profile":"heman-dogfood","generation":1,"mappings":[
 {"mapping_id":"github.mcloving","kind":"github_status","organization_id":"${organization_id}",
  "project_id":"${project_id}","repository":"${repository}"}]}
EOF
chmod 0644 "${state}"/*-catalog.json
umask 077
gh auth token | tr -d '\n' >"${state}/github.token"
[ -s "${state}/notification.key" ] || head -c 48 /dev/urandom >"${state}/notification.key"
[ -s "${state}/webhook.key" ] || head -c 48 /dev/urandom >"${state}/webhook.key"
umask 022

echo "== controller on 127.0.0.1:${api_port}"
env -i HOME="${HOME}" PATH=/usr/local/bin:/usr/bin:/bin TMPDIR="${state}" \
  MCLOVING_MIGRATION_DATABASE_URL="${migration_url}" MCLOVING_DATABASE_URL="${runtime_url}" \
  MCLOVING_API_TOKEN_GENERATION=1 \
  MCLOVING_LISTEN="127.0.0.1:${api_port}" MCLOVING_AGENT_LISTEN="127.0.0.1:${agent_port}" \
  MCLOVING_AGENT_SERVER_CERT_PATH="${pki}/server.pem" MCLOVING_AGENT_SERVER_KEY_PATH="${pki}/server-key.pem" \
  MCLOVING_AGENT_CLIENT_CA_PATH="${pki}/ca.pem" MCLOVING_AGENT_IDENTITY_BINDINGS_PATH="${pki}/identity-bindings.txt" \
  MCLOVING_ORGANIZATION_ID="${organization_id}" \
  MCLOVING_AGENT_ID=embedded-disabled MCLOVING_AGENT_CAPABILITIES=disabled MCLOVING_AGENT_TRUST_POOL=trusted-linux \
  MCLOVING_LEASE_SECONDS=30 MCLOVING_POLL_MILLISECONDS=500 MCLOVING_CANCELLATION_POLL_MILLISECONDS=500 \
  MCLOVING_TERMINATION_GRACE_MILLISECONDS=2000 MCLOVING_SESSION_EPOCH=1 \
  MCLOVING_WORKSPACE_ROOT="${state}/embedded" MCLOVING_AGENT_JOURNAL="${state}/embedded-agent.db" \
  MCLOVING_OBJECT_ROOT="${state}/objects" \
  MCLOVING_SOURCE_MAPPING_CATALOG="${state}/source-catalog.json" \
  MCLOVING_SOURCE_MAPPING_CATALOG_SHA256="$(sha "${state}/source-catalog.json")" \
  MCLOVING_NOTIFICATION_MAPPING_CATALOG="${state}/notification-catalog.json" \
  MCLOVING_NOTIFICATION_MAPPING_CATALOG_SHA256="$(sha "${state}/notification-catalog.json")" \
  MCLOVING_GITHUB_TOKEN_FILE="${state}/github.token" \
  MCLOVING_NOTIFICATION_KEY_FILE="${state}/notification.key" \
  MCLOVING_WEBHOOK_KEY_FILE="${state}/webhook.key" \
  MCLOVING_PUBLIC_BASE_URL="${MCLOVING_DOGFOOD_PUBLIC_BASE_URL:-http://127.0.0.1:${api_port}}" \
  nohup /bin/bash -c 'set -euo pipefail; . "$1"; export MCLOVING_API_TOKEN="${api_token:?missing API token}" MCLOVING_ARTIFACT_AGENT_TOKEN="${artifact_token:?missing artifact token}"; exec "$2"' \
    dogfood-controller "${ids}" "${controller}" >>"${state}/controller.log" 2>&1 &
controller_pid=$!
printf '%s\n' "${controller_pid}" >"${state}/controller.pid"
python3 "${lifecycle}" record-pid "${state}" controller "${controller_pid}" "${controller}"

export MCLOVING_URL="http://127.0.0.1:${api_port}" MCLOVING_API_TOKEN="${api_token}"
export MCLOVING_ORGANIZATION_ID="${organization_id}" MCLOVING_PROJECT_ID="${project_id}"
for _ in $(seq 1 240); do
  if "${cli}" --output json audit --limit 1 >/dev/null 2>&1; then break; fi
  if ! kill -0 "$(cat "${state}/controller.pid")" 2>/dev/null; then echo "controller exited"; tail -20 "${state}/controller.log"; exit 1; fi
  sleep 0.25
done

echo "== agent ${agent_id}"
env -i HOME="${HOME}" PATH=/usr/local/bin:/usr/bin:/bin TMPDIR="${state}" USER="$(id -un)" XDG_RUNTIME_DIR="/run/user/$(id -u)" \
  MCLOVING_AGENT_ID="${agent_id}" MCLOVING_AGENT_TRUST_POOL=trusted-linux \
  MCLOVING_AGENT_ORGANIZATION_ID="${organization_id}" \
  MCLOVING_CONTROLLER_URI="https://127.0.0.1:${agent_port}" MCLOVING_CONTROLLER_DNS_NAME=controller.internal \
  MCLOVING_CONTROLLER_CA_PATH="${pki}/ca.pem" MCLOVING_AGENT_CERTIFICATE_PATH="${pki}/agent.pem" \
  MCLOVING_AGENT_PRIVATE_KEY_PATH="${pki}/agent-key.pem" \
  MCLOVING_AGENT_JOURNAL_PATH="${state}/agent.db" MCLOVING_AGENT_WORKSPACE_ROOT="${state}/agent-workspace" \
  MCLOVING_AGENT_SOURCE_BINDINGS_PATH="${bindings_path}" MCLOVING_AGENT_SOURCE_BINDINGS_SHA256="${bindings_sha}" \
  MCLOVING_AGENT_LEASE_SECONDS=30 MCLOVING_AGENT_POLL_MILLISECONDS=500 \
  MCLOVING_AGENT_RENEW_MILLISECONDS=5000 MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS=2000 \
  nohup "${agent_bin}" >>"${state}/agent.log" 2>&1 &
agent_pid=$!
printf '%s\n' "${agent_pid}" >"${state}/agent.pid"
python3 "${lifecycle}" record-pid "${state}" agent "${agent_pid}" "${agent_bin}"

echo "== pipeline ${pipeline_id} from .mcloving/pipeline.yaml"
head_commit="$(gh api "repos/${repository}/branches/main" --jq .commit.sha)"
sed -e "s#mapping_digest: sha256:0*\$#mapping_digest: ${mapping_digest}#" \
    -e "s#default: \"0\\{40\\}\"#default: \"${head_commit}\"#" \
    -e "s#repository: SuperBadLabs/McLoving#repository: ${repository}#" \
    .mcloving/pipeline.yaml >"${state}/pipeline.yaml"
revision="$("${cli}" --output json pipelines 2>/dev/null | jq -r --arg id "${pipeline_id}" '.items[]? | select(.pipeline_id==$id) | .revision' | head -1)"
"${cli}" --output json apply --slug mcloving-foundation --expected-revision "${revision:-0}" "${pipeline_id}" "${state}/pipeline.yaml" \
  | jq -c '{revision, schema_minor}'

echo "== webhook trigger ${trigger_id}"
base="${MCLOVING_URL}/api/v1/organizations/${organization_id}/projects/${project_id}/pipelines/${pipeline_id}/triggers/${trigger_id}"
filter='{"event_kinds":["push"],"branches":["main"],"path_prefixes":[]}'
configuration="{\"provider\":\"github\",\"repository_identity\":\"${repository}\",\"filter\":${filter}}"
trigger_body="$(python3 - "${configuration}" <<'PY'
import hashlib, json, sys
configuration = json.loads(sys.argv[1])
canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
digest = lambda data: hashlib.sha256(data).hexdigest()
print(json.dumps({
    "kind": "scm_webhook", "state": "enabled",
    "implementation_sha256": digest(b"scm-webhook-v1"),
    "configuration_sha256": digest(canonical(configuration)),
    "filter_sha256": digest(canonical(configuration["filter"])),
    "event_source_identity": "scm:github:webhook:mcloving",
    "source_generation": "dogfood-1",
    "configuration": configuration,
    "deduplication_window_seconds": 86400, "max_delivery_attempts": 3,
    "delivery_ttl_seconds": 86400, "reason": "PAR-005 dogfood",
}))
PY
)"
# A persisted trigger is reconciled with the configured repository: a
# restart with another MCLOVING_DOGFOOD_REPOSITORY re-PUTs the trigger at
# its current generation with a new source generation rather than leaving
# it filtering every delivery for the old repository.
# Credential-bearing command arguments are readable by other host users.
# mktemp creates these request files atomically with mode 0600 inside the
# owner-private state directory. Normal, failure and handled signal exits
# remove tracked files; an uncatchable SIGKILL cannot run cleanup.
api_header_file=""
hook_request_file=""
cleanup_request_credentials() {
  [ -z "${api_header_file}" ] || rm -f -- "${api_header_file}"
  [ -z "${hook_request_file}" ] || rm -f -- "${hook_request_file}"
}
trap cleanup_request_credentials EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
api_header_file="$(mktemp "${state}/.api-auth.XXXXXX")"
printf 'Authorization: Bearer %s\n' "${api_token}" >"${api_header_file}"
trigger_created=false
existing="$(curl -sS -o "${state}/trigger-current.json" -w '%{http_code}' "${base}" --header "@${api_header_file}")"
if [ "${existing}" = "404" ]; then
  trigger_created=true
  curl --fail-with-body -sS -o "${state}/trigger.json" -w 'trigger PUT %{http_code}\n' -X PUT "${base}" \
    --header "@${api_header_file}" -H 'Content-Type: application/json' \
    -H 'If-Match: "0"' -H 'Idempotency-Key: dogfood-trigger' --data "${trigger_body}"
elif [ "${existing}" != "200" ]; then
  echo "trigger readback refused" >&2; exit 1
elif [ "$(jq -r .configuration.repository_identity "${state}/trigger-current.json")" != "${repository}" ]; then
  generation="$(jq -r .generation "${state}/trigger-current.json")"
  trigger_body="$(printf '%s' "${trigger_body}" | jq -c --arg g "dogfood-$((generation + 1))" '.source_generation = $g')"
  curl --fail-with-body -sS -o "${state}/trigger.json" -w 'trigger PUT (reconcile) %{http_code}\n' -X PUT "${base}" \
    --header "@${api_header_file}" -H 'Content-Type: application/json' \
    -H "If-Match: \"${generation}\"" -H "Idempotency-Key: dogfood-trigger-${generation}" --data "${trigger_body}"
fi
umask 077
curl --fail-with-body -sS "${base}" --header "@${api_header_file}" >"${state}/trigger-final.json"
chmod 0600 "${state}/trigger-final.json"
curl --fail-with-body -sS "${base}/webhook" --header "@${api_header_file}" >"${state}/hook.json"
chmod 0600 "${state}/hook.json"
umask 022
jq '{path, provider}' "${state}/hook.json"

cat >"${state}/env" <<EOF
export MCLOVING_URL=${MCLOVING_URL}
export MCLOVING_API_TOKEN=${api_token}
export MCLOVING_ORGANIZATION_ID=${organization_id}
export MCLOVING_PROJECT_ID=${project_id}
export MCLOVING_DOGFOOD_REPOSITORY=${repository}
export MCLOVING_DOGFOOD_PIPELINE_ID=${pipeline_id}
EOF
chmod 0600 "${state}/env"

# Exact nonsecret trigger/repository/route metadata is produced by this
# locked deployment from the actual trigger readback and private descriptor.
mode=bridge
route_base="${MCLOVING_URL}"
if [[ "${MCLOVING_DOGFOOD_PUBLIC_HOOK:-0}" == 1 ]]; then
  mode=public
  route_base="${MCLOVING_DOGFOOD_PUBLIC_BASE_URL:?public base url for the hook}"
fi
python3 - "${state}" "${repository}" "${organization_id}" "${project_id}" "${pipeline_id}" "${trigger_id}" "${route_base}" "${trigger_created}" <<'PY_CONTEXT'
import json, os, pathlib, sys, tempfile
state, repository, organization, project, pipeline, trigger, base, created = sys.argv[1:]
state = pathlib.Path(state)
current = json.loads((state / "trigger-final.json").read_text())
descriptor = json.loads((state / "hook.json").read_text())
if current.get("configuration", {}).get("repository_identity") != repository or current.get("state") != "enabled" or type(current.get("generation")) is not int or current["generation"] < 1 or not isinstance(current.get("source_generation"), str):
    raise SystemExit("trigger binding readback refused")
if descriptor.get("provider") != "github" or not isinstance(descriptor.get("path"), str) or not descriptor["path"].startswith("/"):
    raise SystemExit("hook descriptor readback refused")
value = dict(repository=repository, organization=organization, project=project, pipeline=pipeline, trigger=trigger,
             generation=current["generation"], source_generation=current["source_generation"],
             route_url=base.rstrip("/") + descriptor["path"], trigger_created=created == "true")
fd, tmp = tempfile.mkstemp(prefix=".sender-context.", dir=state)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out); out.flush(); os.fsync(out.fileno())
    os.replace(tmp, state / "sender-context.json")
    directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY_CONTEXT
python3 "${lifecycle}" reconcile "${state}" "${mode}"
if [[ "${mode}" == bridge ]]; then
  env -i HOME="${HOME}" PATH=/usr/local/bin:/usr/bin:/bin \
    MCLOVING_URL="${MCLOVING_URL}" MCLOVING_DOGFOOD_REPOSITORY="${repository}" \
    nohup bash "${repo}/scripts/dogfood/bridge.sh" "${state}" "${MCLOVING_DOGFOOD_BRIDGE_INTERVAL:-60}" >>"${state}/bridge.log" 2>&1 &
  bridge_pid=$!
  printf '%s\n' "${bridge_pid}" >"${state}/bridge.pid"
  python3 "${lifecycle}" record-pid "${state}" bridge "${bridge_pid}" "${repo}/scripts/dogfood/bridge.sh"
  echo "== verified bridge sender started"
else
  echo "== verified owned public hook retained"
fi
echo "== up: . ${state}/env"
