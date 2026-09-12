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
state="$(mkdir -p "$1" && cd "$1" && pwd)"
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

echo "== build"
cargo build --locked -p mcloving-controller -p mcloving-agent -p mcloving-source-acquirer -p mcloving-cli 2>&1 | tail -1
cargo build --locked -p mcloving-agent --example render_source_binding 2>&1 | tail -1
controller="${repo}/target/debug/mcloving-controller"
agent_bin="${repo}/target/debug/mcloving-agent"
admin="${repo}/target/debug/mcloving-identity-admin"
cli="${repo}/target/debug/mcloving-cli"
acquirer="${repo}/target/debug/mcloving-source-acquirer"
render="${repo}/target/debug/examples/render_source_binding"

echo "== stop the previous instance"
for pid_file in "${state}"/agent.pid "${state}"/controller.pid "${state}"/bridge.pid; do
  if [ -f "${pid_file}" ]; then kill "$(cat "${pid_file}")" 2>/dev/null || true; rm -f "${pid_file}"; fi
done
sleep 1

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

echo "== sealed source binding for ${repository}"
mkdir -p "${state}/agent-workspace" "${state}/objects" "${state}/embedded"
rm -rf "${state}/source-output"
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
  MCLOVING_API_TOKEN="${api_token}" MCLOVING_API_TOKEN_GENERATION=1 \
  MCLOVING_ARTIFACT_AGENT_TOKEN="${artifact_token}" \
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
  nohup "${controller}" >>"${state}/controller.log" 2>&1 &
echo $! >"${state}/controller.pid"

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
echo $! >"${state}/agent.pid"

echo "== pipeline ${pipeline_id} from .mcloving/pipeline.yaml"
head_commit="$(gh api "repos/${repository}/branches/main" --jq .commit.sha)"
sed -e "s#mapping_digest: sha256:0*\$#mapping_digest: ${mapping_digest}#" \
    -e "s#default: \"0\\{40\\}\"#default: \"${head_commit}\"#" \
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
existing="$(curl -sS -o /dev/null -w '%{http_code}' "${base}" -H "Authorization: Bearer ${api_token}")"
if [ "${existing}" != "200" ]; then
  curl -sS -o "${state}/trigger.json" -w 'trigger PUT %{http_code}\n' -X PUT "${base}" \
    -H "Authorization: Bearer ${api_token}" -H 'Content-Type: application/json' \
    -H 'If-Match: "0"' -H 'Idempotency-Key: dogfood-trigger' --data "${trigger_body}"
fi
curl -sS "${base}/webhook" -H "Authorization: Bearer ${api_token}" >"${state}/hook.json"
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
echo "== up: . ${state}/env; scripts/dogfood/bridge.sh ${state} once"
