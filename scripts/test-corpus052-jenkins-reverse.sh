#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 7 ]]; then
  echo "usage: $0 SEALED_BUILDS EXPECTED_TREE_SHA256 OPAQUE_EVIDENCE_ID TRANSFORM_ROOT OWNER_PINNED_REHEARSAL_MANIFEST_SHA256 JENKINS_PLUGIN_SOURCE OUTPUT_ROOT" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sealed_builds=$1
expected_tree_sha256=$2
opaque_evidence_id=$3
transform_root=$4
owner_pinned_rehearsal_manifest_sha256=$5
plugin_source=$6
requested_output=$7
fixture_root="${repo_root}/migration/state-transfer-v1/fixtures"
plugin_manifest="${repo_root}/migration/mario-jenkins-oracle-228/corpus-v1/differential-v1/jenkins/PLUGIN_SHA256SUMS"
plugin_manifest_sha256='e33fa87646e6e360e7614373cc0057ba2e92ff18b9a9ea9419dea796dcb950b0'
reverse_bundle="${transform_root}/reverse-bundle.json"
rehearsal_summary="${transform_root}/rehearsal-summary.json"
rehearsal_root=$(realpath -e "${transform_root}/..")
rehearsal_manifest="${rehearsal_root}/SHA256SUMS"
log_payload="${transform_root}/mcloving-build-2.log"
stdout_payload="${transform_root}/mcloving-build-2-log-0.txt"
stderr_payload="${transform_root}/mcloving-build-2-log-1.txt"
image='docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02'
job='corpus-052-cinqict_jenkinsdev'
output_parent=$(realpath -e "$(dirname -- "${requested_output}")")
output_leaf=$(basename -- "${requested_output}")

if [[ ! "${output_leaf}" =~ ^jenkins-reverse-v[0-9]+$ || -e "${requested_output}" ]]; then
  echo "output must be one new jenkins-reverse-vN directory" >&2
  exit 73
fi
for path in "${sealed_builds}" "${transform_root}" "${plugin_source}"; do
  if [[ ! -d "${path}" || -L "${path}" ]]; then
    echo "input directory is missing or symbolic: ${path}" >&2
    exit 66
  fi
done
if [[ ! "${expected_tree_sha256}" =~ ^[0-9a-f]{64}$ ]] \
  || [[ ! "${owner_pinned_rehearsal_manifest_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "expected tree and owner-pinned manifest digests must be lowercase SHA-256" >&2
  exit 65
fi
if [[ ! -f "${plugin_manifest}" || -L "${plugin_manifest}" ]] \
  || [[ $(sha256sum "${plugin_manifest}" | awk '{print $1}') != "${plugin_manifest_sha256}" ]]; then
  echo "pinned Jenkins plugin manifest is missing or divergent" >&2
  exit 66
fi
for path in "${reverse_bundle}" "${rehearsal_summary}" "${log_payload}" \
  "${stdout_payload}" "${stderr_payload}"; do
  if [[ ! -f "${path}" || -L "${path}" ]]; then
    echo "input file is missing or symbolic: ${path}" >&2
    exit 66
  fi
done

if [[ $(basename -- "${transform_root}") != mcloving \
  || ! -f "${rehearsal_manifest}" || -L "${rehearsal_manifest}" \
  || $(stat -c '%h' "${rehearsal_manifest}") -ne 1 ]]; then
  echo "rehearsal manifest boundary is missing or nonregular" >&2
  exit 66
fi
test "$(sha256sum "${rehearsal_manifest}" | awk '{print $1}')" = \
  "${owner_pinned_rehearsal_manifest_sha256}"
awk '
  NF != 2 || $2 ~ /^\// || $2 ~ /(^|\/)\.\.(\/|$)/ || $2 ~ /\\/ { exit 1 }
' "${rehearsal_manifest}"
(
  cd "${rehearsal_root}"
  sha256sum --check --strict SHA256SUMS >/dev/null
)

reverse_digest=$(sha256sum "${reverse_bundle}" | awk '{print $1}')
test "$(awk '$2 == "mcloving/reverse-bundle.json" { print $1 }' \
  "${rehearsal_manifest}")" = "${reverse_digest}"
test "$(awk '$2 == "mcloving/reverse-bundle.json" { count += 1 } END { print count + 0 }' \
  "${rehearsal_manifest}")" -eq 1
test "${reverse_digest}" = "$(jq -r '.reverse_bundle_digest' "${rehearsal_summary}")"
jq --exit-status --arg job "${job}" '
  .binding.schema == "mcloving.state-transfer/v1"
  and .binding.direction == "mc_loving_to_jenkins"
  and .binding.source.kind == "mcloving"
  and .binding.destination.kind == "jenkins"
  and .binding.conflict_policy == "reject_divergence"
  and (.jobs | length) == 1
  and .jobs[0].source_job_id == $job
  and .jobs[0].target_pipeline_id == $job
  and .jobs[0].next_build_number == 3
  and .jobs[0].previous_result == "succeeded"
  and ([.jobs[0].builds[].number] == [1, 2])
  and .jobs[0].builds[0].result == "aborted"
  and .jobs[0].builds[1].result == "succeeded"
  and ([.jobs[0].builds[1].graph_nodes[].stage_path] == ["Build"])
  and (.jobs[0].builds[1].logs | length) == 2
  and [.jobs[0].builds[1].logs[].sequence] == [0, 1]
  and .jobs[0].builds[1].logs[0].bytes == 12
  and .jobs[0].builds[1].logs[1].bytes == 19
' "${reverse_bundle}" >/dev/null
test "$(jq -r '.binding.source.instance_id' "${reverse_bundle}")" = \
  'mcloving/disposable-postgres'
test "$(jq -r '.binding.source.generation' "${reverse_bundle}")" = 'migration-18'
test "$(jq -r '.binding.destination.instance_id' "${reverse_bundle}")" = \
  'jenkins/mario/jenkins-oracle-228'
test "$(jq -r '.binding.destination.generation' "${reverse_bundle}")" = \
  'offline-frozen-source-state'
expected_source_configuration=$(printf '%s' 'mcloving-postgresql-v18-effect-free' \
  | sha256sum | awk '{print $1}')
expected_destination_configuration=$(printf '%s' 'mario-jenkins-oracle-228-frozen-profile' \
  | sha256sum | awk '{print $1}')
actual_source_configuration=$(jq -r '.binding.source.configuration_digest[]' \
  "${reverse_bundle}" | awk '{printf "%02x", $1} END {print ""}')
actual_destination_configuration=$(jq -r '.binding.destination.configuration_digest[]' \
  "${reverse_bundle}" | awk '{printf "%02x", $1} END {print ""}')
test "${actual_source_configuration}" = "${expected_source_configuration}"
test "${actual_destination_configuration}" = "${expected_destination_configuration}"
expected_stdout_digest=$(jq -r '
  .jobs[0].builds[1].logs[0].content_digest[]
' "${reverse_bundle}" | awk '{printf "%02x", $1} END {print ""}')
expected_stderr_digest=$(jq -r '
  .jobs[0].builds[1].logs[1].content_digest[]
' "${reverse_bundle}" | awk '{printf "%02x", $1} END {print ""}')
test "$(sha256sum "${stdout_payload}" | awk '{print $1}')" = "${expected_stdout_digest}"
test "$(sha256sum "${stderr_payload}" | awk '{print $1}')" = "${expected_stderr_digest}"
test "$(wc -c < "${stdout_payload}" | tr -d ' ')" = 12
test "$(wc -c < "${stderr_payload}" | tr -d ' ')" = 19
test "$(cat "${log_payload}")" = $'Hello World\n+ echo Hello World'

staging=$(mktemp -d "${output_parent}/.${output_leaf}.staging.XXXXXX")
runtime_root=$(mktemp -d /tmp/mcloving-mig005a-corpus052-jenkins.XXXXXX)
home="${runtime_root}/destination-home"
template_home="${runtime_root}/template-home"
template="${runtime_root}/template-build-2"
job_home="${home}/jobs/${job}"
template_job_home="${template_home}/jobs/${job}"
network="mcloving-mig005a-corpus052-reverse-$$"
container="mcloving-mig005a-corpus052-reverse-$$"
port=$((21000 + ($$ % 1000)))
completed=0

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  podman rm --force "${container}" >/dev/null 2>&1 || true
  podman network rm "${network}" >/dev/null 2>&1 || true
  if [[ "${completed}" != 1 ]]; then
    rm -rf -- "${staging}"
    echo "kept failed Jenkins runtime at ${runtime_root}" >&2
  fi
  exit "${status}"
}
trap cleanup EXIT

verify_and_copy_plugins() {
  local source_root=$1
  local destination_root=$2
  local expected_digest relative extra leaf source_file destination_file
  local -a expected_plugins actual_plugins copied_plugins

  mapfile -t expected_plugins < <(
    awk '{sub(/^plugins\//, "", $2); print $2}' "${plugin_manifest}" | sort
  )
  mapfile -t actual_plugins < <(
    find "${source_root}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort
  )
  test "${#expected_plugins[@]}" -eq 90
  test "$(printf '%s\n' "${expected_plugins[@]}" | sort -u | wc -l)" -eq 90
  test "${expected_plugins[*]}" = "${actual_plugins[*]}"

  mkdir -p "${destination_root}"
  while read -r expected_digest relative extra; do
    test -z "${extra:-}"
    [[ "${expected_digest}" =~ ^[0-9a-f]{64}$ ]]
    [[ "${relative}" =~ ^plugins/[A-Za-z0-9._-]+\.jpi$ ]]
    leaf=${relative#plugins/}
    source_file="${source_root}/${leaf}"
    destination_file="${destination_root}/${leaf}"
    test -f "${source_file}"
    test ! -L "${source_file}"
    test "$(stat -c '%h' "${source_file}")" -eq 1
    test "$(sha256sum "${source_file}" | awk '{print $1}')" = "${expected_digest}"
    cp --no-dereference -- "${source_file}" "${destination_file}"
    test -f "${destination_file}"
    test ! -L "${destination_file}"
    test "$(stat -c '%h' "${destination_file}")" -eq 1
    test "$(sha256sum "${destination_file}" | awk '{print $1}')" = "${expected_digest}"
  done < "${plugin_manifest}"
  mapfile -t copied_plugins < <(
    find "${destination_root}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort
  )
  test "${expected_plugins[*]}" = "${copied_plugins[*]}"
}

authenticate_history() {
  local source_root=$1
  local output_bundle=$2
  local output_receipt=$3
  (
    cd "${repo_root}"
    cargo run --locked --quiet \
      -p mcloving-jenkins-state-transfer --example normalize_history -- \
      "${source_root}" "${expected_tree_sha256}" "${opaque_evidence_id}" \
      "${output_bundle}"
  ) > "${output_receipt}"
}

mkdir -p "${home}/init.groovy.d" "${home}/plugins" "${job_home}/builds" \
  "${template_home}/init.groovy.d" "${template_home}/plugins" \
  "${template_job_home}/builds" "${staging}/evidence"
chmod 700 "${runtime_root}" "${home}" "${template_home}" "${staging}"

authenticate_history "${sealed_builds}" \
  "${staging}/evidence/authenticated-source-forward-bundle.json" \
  "${staging}/evidence/authenticated-source.txt"
jq --sort-keys '.jobs[0].builds[0]' \
  "${staging}/evidence/authenticated-source-forward-bundle.json" \
  > "${staging}/evidence/authenticated-source-build-1.json"
jq --sort-keys '.jobs[0].builds[0]' "${reverse_bundle}" \
  > "${staging}/evidence/reverse-source-build-1.json"
cmp "${staging}/evidence/authenticated-source-build-1.json" \
  "${staging}/evidence/reverse-source-build-1.json"
jq --sort-keys '.binding | {
  transform_implementation_digest,
  transform_configuration_digest,
  conflict_policy
}' "${staging}/evidence/authenticated-source-forward-bundle.json" \
  > "${staging}/evidence/authenticated-transform-binding.json"
jq --sort-keys '.binding | {
  transform_implementation_digest,
  transform_configuration_digest,
  conflict_policy
}' "${reverse_bundle}" > "${staging}/evidence/reverse-transform-binding.json"
cmp "${staging}/evidence/authenticated-transform-binding.json" \
  "${staging}/evidence/reverse-transform-binding.json"

cp "${fixture_root}/init.groovy" "${home}/init.groovy.d/10-mig005a.groovy"
cp "${fixture_root}/corpus052-job-config.xml" "${job_home}/config.xml"
cp "${fixture_root}/init.groovy" "${template_home}/init.groovy.d/10-mig005a.groovy"
cp "${fixture_root}/corpus052-template-job-config.xml" "${template_job_home}/config.xml"
verify_and_copy_plugins "${plugin_source}" "${home}/plugins"
verify_and_copy_plugins "${plugin_source}" "${template_home}/plugins"
cp "${plugin_manifest}" "${staging}/evidence/PLUGIN_SHA256SUMS"
cp -a "${sealed_builds}/1" "${job_home}/builds/1"
cp "${sealed_builds}/permalinks" "${job_home}/builds/permalinks"
printf '%s\n' 2 > "${job_home}/nextBuildNumber"
authenticate_history "${job_home}/builds" \
  "${staging}/evidence/restored-source-forward-bundle.json" \
  "${staging}/evidence/restored-source.txt"
cmp "${staging}/evidence/authenticated-source-forward-bundle.json" \
  "${staging}/evidence/restored-source-forward-bundle.json"

printf '%s\n' 2 > "${template_job_home}/nextBuildNumber"
chmod -R u+rwX "${home}" "${template_home}"
podman unshare chown -R 1000:1000 "${home}" "${template_home}"
podman network create --internal "${network}" >/dev/null

start_controller() {
  local controller_home=$1
  podman run --detach --name "${container}" \
    --network "${network}" \
    --publish "127.0.0.1:${port}:8080" \
    --cpus 4 --memory 4g --pids-limit 2048 \
    --env JAVA_OPTS='-Djenkins.install.runSetupWizard=false' \
    --volume "${controller_home}:/var/jenkins_home:Z" \
    "${image}" >/dev/null
  for _ in $(seq 1 240); do
    if curl --fail --silent --show-error \
      "http://127.0.0.1:${port}/api/json" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  podman logs "${container}" >&2
  return 1
}

stop_controller() {
  podman stop --time 30 "${container}" >/dev/null
  podman rm "${container}" >/dev/null
}

capture_build() {
  local number=$1
  local prefix=$2
  for _ in $(seq 1 240); do
    if curl --fail --silent --show-error \
      "http://127.0.0.1:${port}/job/${job}/${number}/api/json" \
      -o "${staging}/evidence/${prefix}-build-${number}.json" 2>/dev/null \
      && [[ $(jq -r '.building' "${staging}/evidence/${prefix}-build-${number}.json") == false ]]; then
      curl --fail --silent --show-error \
        "http://127.0.0.1:${port}/job/${job}/${number}/consoleText" \
        -o "${staging}/evidence/${prefix}-build-${number}.log"
      return 0
    fi
    sleep 0.5
  done
  echo "Jenkins build ${number} did not become terminal" >&2
  return 1
}

capture_workflow() {
  local number=$1
  local prefix=$2
  curl --fail --silent --show-error \
    "http://127.0.0.1:${port}/job/${job}/${number}/wfapi/describe" \
    -o "${staging}/evidence/${prefix}-build-${number}-workflow.json"
  jq --exit-status '
    .status == "SUCCESS"
    and ([.stages[].name] == ["Build"])
    and ([.stages[].status] == ["SUCCESS"])
  ' "${staging}/evidence/${prefix}-build-${number}-workflow.json" >/dev/null
}

start_controller "${template_home}"
curl --fail --silent --show-error -X POST \
  "http://127.0.0.1:${port}/job/${job}/build" >/dev/null
capture_build 2 template
jq --exit-status '.number == 2 and .result == "SUCCESS"' \
  "${staging}/evidence/template-build-2.json" >/dev/null
rg --quiet '^MIG005A_SERIALIZATION_TEMPLATE_ONLY$' \
  "${staging}/evidence/template-build-2.log"
if rg --quiet 'Hello World|\+ echo' "${staging}/evidence/template-build-2.log"; then
  echo "serialization template executed the admitted workload" >&2
  exit 1
fi
capture_workflow 2 template
podman inspect "${container}" > "${staging}/evidence/template-container-inspect.json"
stop_controller

podman unshare cp -a "${template_job_home}/builds/2" "${template}"
podman unshare rm -rf -- "${template_home}"
printf '%s\n' \
  'schema=mcloving.jenkins-serialization-template/v1' \
  'destination_started=false' \
  'admitted_workload_process_executed=false' \
  'external_effects=0' \
  'production_authority=false' \
  > "${staging}/evidence/template-boundary.txt"
cp "${stdout_payload}" "${staging}/imported-build-2.log"
cat "${stderr_payload}" >> "${staging}/imported-build-2.log"
cmp "${log_payload}" "${staging}/imported-build-2.log"
podman unshare cp "${staging}/imported-build-2.log" "${template}/log"
jq --sort-keys '.jobs[0].builds[1]' "${reverse_bundle}" \
  > "${staging}/mcloving-state-transfer-build.json"
jq -n --arg reverse_bundle_digest "${reverse_digest}" '
  {
    schema: "mcloving.jenkins-reverse-import/v1",
    source_build: 2,
    destination_build: 2,
    next_build_number: 3,
    result: "SUCCESS",
    reverse_bundle_digest: $reverse_bundle_digest,
    external_effects: 0,
    production_authority: false
  }
' > "${staging}/mcloving-state-transfer-receipt.json"
podman unshare cp "${staging}/mcloving-state-transfer-build.json" \
  "${template}/mcloving-state-transfer-build.json"
podman unshare cp "${staging}/mcloving-state-transfer-receipt.json" \
  "${template}/mcloving-state-transfer-receipt.json"
build_started=$(jq -r '.jobs[0].builds[1].started_at_unix_ms' "${reverse_bundle}")
build_ended=$(jq -r '.jobs[0].builds[1].ended_at_unix_ms' "${reverse_bundle}")
build_duration=$((build_ended - build_started))
podman unshare sed -E -i \
  -e "s#<timestamp>[0-9]+</timestamp>#<timestamp>${build_started}</timestamp>#g" \
  -e "s#<duration>[0-9]+</duration>#<duration>${build_duration}</duration>#g" \
  -e 's#<result>[^<]+</result>#<result>SUCCESS</result>#g' \
  "${template}/build.xml"
podman unshare cp -a "${template}" "${job_home}/builds/2"
printf '%s\n' 3 > "${staging}/nextBuildNumber"
printf '%s\n' \
  'lastCompletedBuild 2' \
  'lastStableBuild 2' \
  'lastSuccessfulBuild 2' > "${staging}/permalinks"
podman unshare cp "${staging}/nextBuildNumber" "${job_home}/nextBuildNumber"
podman unshare cp "${staging}/permalinks" "${job_home}/builds/permalinks"
podman unshare chown -R 1000:1000 "${job_home}"

start_controller "${home}"
capture_build 1 imported
capture_build 2 imported
jq --exit-status '.number == 1 and .result == "ABORTED"' \
  "${staging}/evidence/imported-build-1.json" >/dev/null
jq --exit-status '.number == 2 and .result == "SUCCESS"' \
  "${staging}/evidence/imported-build-2.json" >/dev/null
test "$(cat "${staging}/evidence/imported-build-2.log")" = \
  $'Hello World\n+ echo Hello World'
capture_workflow 2 imported
test "$(podman unshare cat "${job_home}/nextBuildNumber")" = 3
stop_controller

start_controller "${home}"
capture_build 1 restarted
capture_build 2 restarted
jq --exit-status '.number == 1 and .result == "ABORTED"' \
  "${staging}/evidence/restarted-build-1.json" >/dev/null
jq --exit-status '.number == 2 and .result == "SUCCESS"' \
  "${staging}/evidence/restarted-build-2.json" >/dev/null
test "$(cat "${staging}/evidence/restarted-build-2.log")" = \
  $'Hello World\n+ echo Hello World'
capture_workflow 2 restarted
test "$(podman unshare cat "${job_home}/nextBuildNumber")" = 3
curl --fail --silent --show-error -X POST \
  "http://127.0.0.1:${port}/job/${job}/build" >/dev/null
capture_build 3 continued
jq --exit-status '.number == 3 and .result == "SUCCESS"' \
  "${staging}/evidence/continued-build-3.json" >/dev/null
rg --quiet 'Hello World' "${staging}/evidence/continued-build-3.log"
capture_workflow 3 continued
test "$(podman unshare cat "${job_home}/nextBuildNumber")" = 4

if podman run --rm --network "${network}" "${image}" \
  timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' >/dev/null 2>&1; then
  echo "contained Jenkins network unexpectedly reached the public Internet" >&2
  exit 1
else
  printf '%s\n' public-network-denied > "${staging}/evidence/network-negative.txt"
fi
podman inspect "${container}" > "${staging}/evidence/jenkins-container-inspect.json"
podman image inspect "${image}" > "${staging}/evidence/jenkins-image-inspect.json"
stop_controller

mapfile -t build_directories < <(
  podman unshare find "${job_home}/builds" -mindepth 1 -maxdepth 1 \
    -type d -printf '%f\n' | sort -n
)
test "${build_directories[*]}" = '1 2 3'
podman unshare test -f "${job_home}/builds/2/mcloving-state-transfer-build.json"
podman unshare test -f "${job_home}/builds/2/mcloving-state-transfer-receipt.json"
test "$(jq -r '.reverse_bundle_digest' \
  "${staging}/mcloving-state-transfer-receipt.json")" = "${reverse_digest}"
test "$(jq -r '.production_authority' \
  "${staging}/mcloving-state-transfer-receipt.json")" = false
podman unshare cp -a "${job_home}" "${staging}/evidence/jenkins-job-after"
podman unshare chown -R 0:0 "${staging}/evidence/jenkins-job-after"
rm -f -- "${staging}/imported-build-2.log" \
  "${staging}/mcloving-state-transfer-build.json" \
  "${staging}/mcloving-state-transfer-receipt.json" \
  "${staging}/nextBuildNumber" "${staging}/permalinks"
printf '%s\n' "${reverse_digest}" > "${staging}/evidence/reverse-bundle.sha256"
printf '%s\n' 4 > "${staging}/evidence/verified-next-build-number.txt"
find "${staging}" -type d -exec chmod 700 {} +
find "${staging}" -type f -exec chmod 600 {} +

(
  cd "${staging}"
  find . -type f ! -name SHA256SUMS -printf '%P\0' \
    | sort -z \
    | while IFS= read -r -d '' path; do
        sha256sum "${path}"
      done > SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)
podman unshare rm -rf -- "${runtime_root}"
mv -- "${staging}" "${output_parent}/${output_leaf}"
completed=1
(
  cd "${output_parent}/${output_leaf}"
  sha256sum -c SHA256SUMS >/dev/null
)
printf '%s\n' "${output_parent}/${output_leaf}"
