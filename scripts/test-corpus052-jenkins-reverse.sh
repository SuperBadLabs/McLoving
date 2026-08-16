#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
failure_line=0
trap 'failure_line=$LINENO' ERR

if [[ $# -ne 8 ]]; then
  echo "usage: $0 SEALED_BUILDS EXPECTED_TREE_SHA256 OPAQUE_EVIDENCE_ID TRANSFORM_ROOT OWNER_PINNED_REHEARSAL_MANIFEST_SHA256 JENKINS_PLUGIN_SOURCE REVIEWED_NORMALIZER OUTPUT_ROOT" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sealed_builds=$1
expected_tree_sha256=$2
opaque_evidence_id=$3
requested_transform_root=$4
owner_pinned_rehearsal_manifest_sha256=$5
plugin_source=$6
reviewed_normalizer=$7
requested_output=$8
fixture_root="${repo_root}/migration/state-transfer-v1/fixtures"
source_plugin_manifest="${repo_root}/migration/mario-jenkins-oracle-228/corpus-v1/differential-v1/jenkins/PLUGIN_SHA256SUMS"
plugin_manifest_sha256='e33fa87646e6e360e7614373cc0057ba2e92ff18b9a9ea9419dea796dcb950b0'
source_reverse_bundle="${requested_transform_root}/reverse-bundle.json"
source_rehearsal_summary="${requested_transform_root}/rehearsal-summary.json"
source_log_payload="${requested_transform_root}/mcloving-build-2.log"
source_trace_payload="${requested_transform_root}/mcloving-build-2-log-0.txt"
source_stdout_payload="${requested_transform_root}/mcloving-build-2-log-1.txt"
rehearsal_root=$(realpath -e "${requested_transform_root}/..")
rehearsal_manifest="${rehearsal_root}/SHA256SUMS"
image='docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02'
job='corpus-052-cinqict_jenkinsdev'
output_parent=$(realpath -e "$(dirname -- "${requested_output}")")
output_leaf=$(basename -- "${requested_output}")
snapshot_group=$(id -g)
if [[ "${EUID}" -eq 0 ]]; then
  echo "rehearsal must run as the unprivileged evidence owner" >&2
  exit 77
fi
command -v sudo >/dev/null
sudo -n true
privileged=(sudo -n)
test "$(getent passwd | awk -F: -v gid="${snapshot_group}" \
  '$4 == gid { count += 1 } END { print count + 0 }')" -eq 1
group_members=$(getent group "${snapshot_group}" | cut -d: -f4)
test -z "${group_members}" || test "${group_members}" = "$(id -un)"

if [[ ! "${output_leaf}" =~ ^jenkins-reverse-v[0-9]+$ || -e "${requested_output}" ]]; then
  echo "output must be one new jenkins-reverse-vN directory" >&2
  exit 73
fi
for path in "${sealed_builds}" "${requested_transform_root}" "${plugin_source}"; do
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
if [[ ! -f "${source_plugin_manifest}" || -L "${source_plugin_manifest}" ]] \
  || [[ $(stat -c '%h' "${source_plugin_manifest}") -ne 1 ]]; then
  echo "pinned Jenkins plugin manifest is missing or divergent" >&2
  exit 66
fi
for path in "${source_reverse_bundle}" "${source_rehearsal_summary}" \
  "${source_log_payload}" "${source_trace_payload}" "${source_stdout_payload}"; do
  if [[ ! -f "${path}" || -L "${path}" ]]; then
    echo "input file is missing or symbolic: ${path}" >&2
    exit 66
  fi
done
if [[ ! -f "${reviewed_normalizer}" || -L "${reviewed_normalizer}" \
  || ! -x "${reviewed_normalizer}" \
  || $(stat -c '%h' "${reviewed_normalizer}") -ne 1 \
  || $(stat -c '%u' "${reviewed_normalizer}") -ne "${EUID}" \
  || $((8#$(stat -c '%a' "${reviewed_normalizer}") & 8#077)) -ne 0 ]]; then
  echo "reviewed normalizer is missing, aliased, non-owner, or not owner-only" >&2
  exit 66
fi

if [[ $(basename -- "${requested_transform_root}") != mcloving \
  || ! -f "${rehearsal_manifest}" || -L "${rehearsal_manifest}" \
  || $(stat -c '%h' "${rehearsal_manifest}") -ne 1 ]]; then
  echo "rehearsal manifest boundary is missing or nonregular" >&2
  exit 66
fi

staging=$(mktemp -d "${output_parent}/.${output_leaf}.staging.XXXXXX")
runtime_root=$(mktemp -d /tmp/mcloving-mig005a-corpus052-jenkins.XXXXXX)
authenticated_rehearsal=$(mktemp -d /tmp/mcloving-mig005a-authenticated.XXXXXX)
authenticated_plugin_manifest=$(mktemp -d \
  /tmp/mcloving-mig005a-plugin-manifest.XXXXXX)
home_plugins=$(mktemp -d /tmp/mcloving-mig005a-destination-plugins.XXXXXX)
template_plugins=$(mktemp -d /tmp/mcloving-mig005a-template-plugins.XXXXXX)
home="${runtime_root}/destination-home"
template_home="${runtime_root}/template-home"
template="${runtime_root}/template-build-2"
job_home="${home}/jobs/${job}"
template_job_home="${template_home}/jobs/${job}"
network="mcloving-mig005a-corpus052-reverse-$$"
container="mcloving-mig005a-corpus052-reverse-$$"
completed=0

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  podman rm --force "${container}" >/dev/null 2>&1 || true
  podman network rm "${network}" >/dev/null 2>&1 || true
  if [[ "${completed}" != 1 ]]; then
    rm -rf -- "${staging}"
  fi
  "${privileged[@]}" rm -rf -- "${authenticated_rehearsal}" >/dev/null 2>&1 || true
  "${privileged[@]}" rm -rf -- "${authenticated_plugin_manifest}" \
    >/dev/null 2>&1 || true
  "${privileged[@]}" rm -rf -- "${home_plugins}" >/dev/null 2>&1 || true
  "${privileged[@]}" rm -rf -- "${template_plugins}" >/dev/null 2>&1 || true
  "${privileged[@]}" rm -rf -- "${runtime_root}" >/dev/null 2>&1 || true
  if [[ "${status}" != 0 ]]; then
    echo "rehearsal-failure-line=${failure_line}" >&2
  fi
  exit "${status}"
}
trap cleanup EXIT

# Copy the manifest once, authenticate the copied bytes against the compiled
# digest, and transfer that inode and its directory outside the invoking UID's
# mutation authority. Every later plugin copy, verification, mount, and
# retained receipt consumes only this locked snapshot.
plugin_manifest="${authenticated_plugin_manifest}/PLUGIN_SHA256SUMS"
cp --no-dereference --reflink=never "${source_plugin_manifest}" \
  "${plugin_manifest}"
test -f "${plugin_manifest}"
test ! -L "${plugin_manifest}"
test "$(stat -c '%h' "${plugin_manifest}")" -eq 1
test "$(sha256sum "${plugin_manifest}" | awk '{print $1}')" = \
  "${plugin_manifest_sha256}"
"${privileged[@]}" chown -R "0:${snapshot_group}" \
  "${authenticated_plugin_manifest}"
"${privileged[@]}" chmod 0440 "${plugin_manifest}"
"${privileged[@]}" chmod 0550 "${authenticated_plugin_manifest}"
test -z "$(find "${authenticated_plugin_manifest}" ! -user root -print -quit)"
test -z "$(find "${authenticated_plugin_manifest}" \
  ! -group "${snapshot_group}" -print -quit)"
if chmod u+w "${plugin_manifest}" 2>/dev/null \
  || mv "${authenticated_plugin_manifest}" \
    "${authenticated_plugin_manifest}.replaced" 2>/dev/null; then
  echo "authenticated plugin manifest remained mutable to the invoking UID" >&2
  exit 1
fi
test "$(sha256sum "${plugin_manifest}" | awk '{print $1}')" = \
  "${plugin_manifest_sha256}"

test "$(sha256sum "${rehearsal_manifest}" | awk '{print $1}')" = \
  "${owner_pinned_rehearsal_manifest_sha256}"
awk '
  NF != 2 || $2 ~ /^\// || $2 ~ /(^|\/)\.\.(\/|$)/ || $2 ~ /\\/ { exit 1 }
' "${rehearsal_manifest}"
(
  cd "${rehearsal_root}"
  sha256sum --check --strict SHA256SUMS >/dev/null
)

# Reopen no original authenticated input after this point. Copy every manifest
# member into a private snapshot, reauthenticate it, then transfer the snapshot
# to root ownership with read access only for this account's dedicated primary
# group. A concurrent process under the invoking UID cannot chmod or replace an
# authenticated inode before a later consumer reopens it.
cp --no-dereference --reflink=never "${rehearsal_manifest}" \
  "${authenticated_rehearsal}/SHA256SUMS"
test "$(sha256sum "${authenticated_rehearsal}/SHA256SUMS" | awk '{print $1}')" = \
  "${owner_pinned_rehearsal_manifest_sha256}"
awk '
  NF != 2 || $2 ~ /^\// || $2 ~ /(^|\/)\.\.(\/|$)/ || $2 ~ /\\/ { exit 1 }
' "${authenticated_rehearsal}/SHA256SUMS"
while read -r expected_digest relative extra; do
  test -z "${extra:-}"
  [[ "${expected_digest}" =~ ^[0-9a-f]{64}$ ]]
  source_file="${rehearsal_root}/${relative}"
  destination_file="${authenticated_rehearsal}/${relative}"
  test -f "${source_file}"
  test ! -L "${source_file}"
  test "$(stat -c '%h' "${source_file}")" -eq 1
  test "$(realpath -e -- "${source_file}")" = "${source_file}"
  mkdir -p "$(dirname -- "${destination_file}")"
  cp --no-dereference --reflink=never "${source_file}" "${destination_file}"
  test -f "${destination_file}"
  test ! -L "${destination_file}"
  test "$(stat -c '%h' "${destination_file}")" -eq 1
done < "${authenticated_rehearsal}/SHA256SUMS"
(
  cd "${authenticated_rehearsal}"
  sha256sum --check --strict SHA256SUMS >/dev/null
)
"${privileged[@]}" chown -R "0:${snapshot_group}" "${authenticated_rehearsal}"
"${privileged[@]}" find "${authenticated_rehearsal}" -type f -exec chmod 0440 {} +
"${privileged[@]}" find "${authenticated_rehearsal}" -type d -exec chmod 0550 {} +
test -z "$(find "${authenticated_rehearsal}" ! -user root -print -quit)"
test -z "$(find "${authenticated_rehearsal}" ! -group "${snapshot_group}" -print -quit)"
if chmod u+w "${authenticated_rehearsal}/SHA256SUMS" 2>/dev/null \
  || mv "${authenticated_rehearsal}" "${authenticated_rehearsal}.replaced" 2>/dev/null; then
  echo "authenticated snapshot remained mutable to the invoking UID" >&2
  exit 1
fi
test "$(sha256sum "${authenticated_rehearsal}/SHA256SUMS" | awk '{print $1}')" = \
  "${owner_pinned_rehearsal_manifest_sha256}"
(
  cd "${authenticated_rehearsal}"
  sha256sum --check --strict SHA256SUMS >/dev/null
)

rehearsal_root="${authenticated_rehearsal}"
rehearsal_manifest="${rehearsal_root}/SHA256SUMS"
transform_root="${rehearsal_root}/mcloving"
forward_bundle="${transform_root}/forward-bundle.json"
reverse_bundle="${transform_root}/reverse-bundle.json"
rehearsal_summary="${transform_root}/rehearsal-summary.json"
log_payload="${transform_root}/mcloving-build-2.log"
trace_payload="${transform_root}/mcloving-build-2-log-0.txt"
stdout_payload="${transform_root}/mcloving-build-2-log-1.txt"

reverse_digest=$(sha256sum "${reverse_bundle}" | awk '{print $1}')
expected_normalizer_digest=$(jq -r \
  '.binding.transform_implementation_digest[]' "${forward_bundle}" \
  | awk '{printf "%02x", $1} END {print ""}')
test "$(sha256sum "${reviewed_normalizer}" | awk '{print $1}')" = \
  "${expected_normalizer_digest}"
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
  and .jobs[0].builds[1].logs[0].bytes == 19
  and .jobs[0].builds[1].logs[1].bytes == 12
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
expected_trace_digest=$(jq -r '
  .jobs[0].builds[1].logs[0].content_digest[]
' "${reverse_bundle}" | awk '{printf "%02x", $1} END {print ""}')
expected_stdout_digest=$(jq -r '
  .jobs[0].builds[1].logs[1].content_digest[]
' "${reverse_bundle}" | awk '{printf "%02x", $1} END {print ""}')
test "$(sha256sum "${trace_payload}" | awk '{print $1}')" = "${expected_trace_digest}"
test "$(sha256sum "${stdout_payload}" | awk '{print $1}')" = "${expected_stdout_digest}"
test "$(wc -c < "${trace_payload}" | tr -d ' ')" = 19
test "$(wc -c < "${stdout_payload}" | tr -d ' ')" = 12
test "$(cat "${log_payload}")" = $'+ echo Hello World\nHello World'
build_started=$(jq -r '.jobs[0].builds[1].started_at_unix_ms' "${reverse_bundle}")
build_ended=$(jq -r '.jobs[0].builds[1].ended_at_unix_ms' "${reverse_bundle}")
attempt_started=$(jq -r \
  '.jobs[0].builds[1].graph_nodes[0].attempts[0].started_at_unix_ms' \
  "${reverse_bundle}")
attempt_ended=$(jq -r \
  '.jobs[0].builds[1].graph_nodes[0].attempts[0].ended_at_unix_ms' \
  "${reverse_bundle}")
[[ "${build_started}" =~ ^[0-9]+$ && "${build_ended}" =~ ^[0-9]+$ ]]
[[ "${attempt_started}" =~ ^[0-9]+$ && "${attempt_ended}" =~ ^[0-9]+$ ]]
test "${build_started}" -le "${attempt_started}"
test "${attempt_started}" -le "${attempt_ended}"
test "${attempt_ended}" -le "${build_ended}"
build_duration=$((build_ended - build_started))

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

lock_and_verify_plugins() {
  local plugin_root=$1
  local expected_digest relative extra leaf plugin_file mutation_probe
  local -a expected_plugins actual_plugins

  "${privileged[@]}" chown -R root:root "${plugin_root}"
  "${privileged[@]}" find "${plugin_root}" -type f -exec chmod 0444 {} +
  "${privileged[@]}" find "${plugin_root}" -type d -exec chmod 0555 {} +
  test -z "$(find "${plugin_root}" ! -user root -print -quit)"
  test -z "$(find "${plugin_root}" -perm /222 -print -quit)"
  mutation_probe=$(awk 'NR == 1 {sub(/^plugins\//, "", $2); print $2}' \
    "${plugin_manifest}")
  if chmod u+w "${plugin_root}/${mutation_probe}" 2>/dev/null \
    || mv "${plugin_root}" "${plugin_root}.replaced" 2>/dev/null; then
    echo "verified plugin snapshot remained mutable to the invoking UID" >&2
    exit 1
  fi
  mapfile -t expected_plugins < <(
    awk '{sub(/^plugins\//, "", $2); print $2}' "${plugin_manifest}" | sort
  )
  mapfile -t actual_plugins < <(
    find "${plugin_root}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort
  )
  test "${#expected_plugins[@]}" -eq 90
  test "${expected_plugins[*]}" = "${actual_plugins[*]}"
  while read -r expected_digest relative extra; do
    test -z "${extra:-}"
    leaf=${relative#plugins/}
    plugin_file="${plugin_root}/${leaf}"
    test -f "${plugin_file}"
    test ! -L "${plugin_file}"
    test "$(stat -c '%h' "${plugin_file}")" -eq 1
    test "$(sha256sum "${plugin_file}" | awk '{print $1}')" = "${expected_digest}"
  done < "${plugin_manifest}"
}

authenticate_history() {
  local source_root=$1
  local output_bundle=$2
  local output_receipt=$3
  "${reviewed_normalizer}" \
    "${source_root}" "${expected_tree_sha256}" "${opaque_evidence_id}" \
    "${output_bundle}" > "${output_receipt}"
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
jq --exit-status \
  --slurpfile forward \
    "${staging}/evidence/authenticated-source-forward-bundle.json" '
  (.binding.transform_implementation_digest | type) == "array"
  and (.binding.transform_implementation_digest | length) == 32
  and .binding.transform_implementation_digest
    != $forward[0].binding.transform_implementation_digest
  and .binding.transform_configuration_digest
    == $forward[0].binding.transform_configuration_digest
  and .binding.conflict_policy == $forward[0].binding.conflict_policy
' "${reverse_bundle}" >/dev/null

cp "${fixture_root}/init.groovy" "${home}/init.groovy.d/10-mig005a.groovy"
cp "${fixture_root}/corpus052-job-config.xml" "${job_home}/config.xml"
cp "${fixture_root}/init.groovy" "${template_home}/init.groovy.d/10-mig005a.groovy"
cp "${fixture_root}/corpus052-template-shell.groovy" \
  "${template_home}/init.groovy.d/20-mig005a-template-shell.groovy"
cp "${fixture_root}/corpus052-template-noop-shell" \
  "${template_home}/mig005a-nonexecuting-shell"
chmod 700 "${template_home}/mig005a-nonexecuting-shell"
cp "${fixture_root}/corpus052-template-job-config.xml" "${template_job_home}/config.xml"
verify_and_copy_plugins "${plugin_source}" "${home_plugins}"
verify_and_copy_plugins "${plugin_source}" "${template_plugins}"
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
lock_and_verify_plugins "${home_plugins}"
lock_and_verify_plugins "${template_plugins}"
podman network create --internal "${network}" >/dev/null
podman network inspect "${network}" > "${staging}/evidence/private-network-inspect.json"

start_controller() {
  local controller_home=$1
  local controller_plugins=$2
  local expected_digest relative extra leaf
  local -a plugin_mounts=()
  while read -r expected_digest relative extra; do
    test -z "${extra:-}"
    leaf=${relative#plugins/}
    plugin_mounts+=(
      --volume
      "${controller_plugins}/${leaf}:/var/jenkins_home/plugins/${leaf}:ro"
    )
  done < "${plugin_manifest}"
  test "${#plugin_mounts[@]}" -eq 180
  podman run --detach --name "${container}" \
    --network "${network}" \
    --cpus 4 --memory 4g --pids-limit 2048 \
    --env JAVA_OPTS='-Djenkins.install.runSetupWizard=false' \
    --volume "${controller_home}:/var/jenkins_home:Z" \
    "${plugin_mounts[@]}" \
    "${image}" >/dev/null
  for _ in $(seq 1 240); do
    if podman exec "${container}" curl --fail --silent --show-error \
      "http://127.0.0.1:8080/api/json" >/dev/null 2>&1; then
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
  local retained_log=${3:-}
  local expected_retained_log=${4:-}
  for _ in $(seq 1 240); do
    if podman exec "${container}" curl --fail --silent --show-error \
      "http://127.0.0.1:8080/job/${job}/${number}/api/json" \
      > "${staging}/evidence/${prefix}-build-${number}.json" 2>/dev/null \
      && [[ $(jq -r '.building' "${staging}/evidence/${prefix}-build-${number}.json") == false ]]; then
      podman exec "${container}" curl --fail --silent --show-error \
        "http://127.0.0.1:8080/job/${job}/${number}/consoleText" \
        > "${staging}/evidence/${prefix}-build-${number}.log"
      if [[ -n "${retained_log}" ]]; then
        podman unshare test -f "${retained_log}"
        podman unshare test ! -L "${retained_log}"
        if [[ -n "${expected_retained_log}" ]]; then
          podman unshare cmp "${retained_log}" "${expected_retained_log}"
        fi
        podman unshare cmp "${retained_log}" \
          "${staging}/evidence/${prefix}-build-${number}.log"
        if [[ -n "${expected_retained_log}" ]]; then
          cmp "${staging}/evidence/${prefix}-build-${number}.log" \
            "${expected_retained_log}"
        fi
      fi
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
  local expected_shell_log=${3:-}
  local expected_shell_started=${4:-}
  local expected_shell_ended=${5:-}
  local stage_id shell_id extracted_shell_log
  podman exec "${container}" curl --fail --silent --show-error \
    "http://127.0.0.1:8080/job/${job}/${number}/wfapi/describe" \
    > "${staging}/evidence/${prefix}-build-${number}-workflow.json"
  jq --exit-status '
    .status == "SUCCESS"
    and ([.stages[].name] == ["Build"])
    and ([.stages[].status] == ["SUCCESS"])
  ' "${staging}/evidence/${prefix}-build-${number}-workflow.json" >/dev/null
  stage_id=$(jq -r '.stages[0].id' \
    "${staging}/evidence/${prefix}-build-${number}-workflow.json")
  [[ "${stage_id}" =~ ^[0-9]+$ ]]
  podman exec "${container}" curl --fail --silent --show-error \
    "http://127.0.0.1:8080/job/${job}/${number}/execution/node/${stage_id}/wfapi/describe" \
    > "${staging}/evidence/${prefix}-build-${number}-stage.json"
  jq --exit-status '
    .name == "Build"
    and .status == "SUCCESS"
    and ([.stageFlowNodes[]
          | select(.name == "Shell Script" and .status == "SUCCESS")]
         | length) == 1
  ' "${staging}/evidence/${prefix}-build-${number}-stage.json" >/dev/null
  shell_id=$(jq -r \
    '.stageFlowNodes[] | select(.name == "Shell Script") | .id' \
    "${staging}/evidence/${prefix}-build-${number}-stage.json")
  [[ "${shell_id}" =~ ^[0-9]+$ ]]
  podman exec "${container}" curl --fail --silent --show-error \
    "http://127.0.0.1:8080/job/${job}/${number}/execution/node/${shell_id}/wfapi/log" \
    > "${staging}/evidence/${prefix}-build-${number}-shell-log.json"
  jq --exit-status --arg shell_id "${shell_id}" '
    .nodeId == $shell_id
    and .nodeStatus == "SUCCESS"
    and .hasMore == false
    and (.text | type) == "string"
    and .length == (.text | utf8bytelength)
  ' "${staging}/evidence/${prefix}-build-${number}-shell-log.json" >/dev/null
  if [[ -n "${expected_shell_log}" ]]; then
    [[ "${expected_shell_started}" =~ ^[0-9]+$ ]]
    [[ "${expected_shell_ended}" =~ ^[0-9]+$ ]]
    jq --exit-status \
      --arg shell_id "${shell_id}" \
      --argjson started "${expected_shell_started}" \
      --argjson duration "$((expected_shell_ended - expected_shell_started))" '
      [.stageFlowNodes[]
       | select(.id == $shell_id
                and .name == "Shell Script"
                and .status == "SUCCESS"
                and .startTimeMillis == $started
                and .durationMillis == $duration)]
      | length == 1
    ' "${staging}/evidence/${prefix}-build-${number}-stage.json" >/dev/null
    extracted_shell_log="${staging}/evidence/${prefix}-build-${number}-shell-log.txt"
    jq -j '.text' \
      "${staging}/evidence/${prefix}-build-${number}-shell-log.json" \
      > "${extracted_shell_log}"
    cmp "${expected_shell_log}" "${extracted_shell_log}"
  fi
}

start_controller "${template_home}" "${template_plugins}"
podman exec "${container}" curl --fail --silent --show-error -X POST \
  "http://127.0.0.1:8080/job/${job}/build" >/dev/null
capture_build 2 template
jq --exit-status '.number == 2 and .result == "SUCCESS"' \
  "${staging}/evidence/template-build-2.json" >/dev/null
rg --quiet '^MIG005A_SERIALIZATION_TEMPLATE_ONLY$' \
  "${staging}/evidence/template-build-2.log"
if rg --quiet 'Hello World|\+ echo' "${staging}/evidence/template-build-2.log"; then
  echo "serialization template executed the admitted workload" >&2
  exit 1
fi
test "$(podman unshare sed -n '1p' \
  "${template_home}/mig005a-template-shell-invocation.txt")" = 2
test "$(podman unshare sed -n '2p' \
  "${template_home}/mig005a-template-shell-invocation.txt")" = -xe
test "$(podman unshare awk 'END { print NR }' \
  "${template_home}/mig005a-template-shell-invocation.txt")" = 3
invoked_script=$(podman unshare sed -n '3p' \
  "${template_home}/mig005a-template-shell-invocation.txt")
case "$(basename -- "${invoked_script}")" in
  script.sh | script.sh.copy) ;;
  *) exit 1 ;;
esac
capture_workflow 2 template
shell_node_id=$(jq -r \
  '.stageFlowNodes[] | select(.name == "Shell Script") | .id' \
  "${staging}/evidence/template-build-2-stage.json")
[[ "${shell_node_id}" =~ ^[0-9]+$ ]]
template_shell_started=$(jq -r \
  '.stageFlowNodes[] | select(.name == "Shell Script") | .startTimeMillis' \
  "${staging}/evidence/template-build-2-stage.json")
template_shell_duration=$(jq -r \
  '.stageFlowNodes[] | select(.name == "Shell Script") | .durationMillis' \
  "${staging}/evidence/template-build-2-stage.json")
[[ "${template_shell_started}" =~ ^[0-9]+$ ]]
[[ "${template_shell_duration}" =~ ^[0-9]+$ ]]
template_shell_ended=$((template_shell_started + template_shell_duration))
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
cp "${trace_payload}" "${staging}/imported-build-2.log"
chmod 600 "${staging}/imported-build-2.log"
cat "${stdout_payload}" >> "${staging}/imported-build-2.log"
cmp "${log_payload}" "${staging}/imported-build-2.log"
podman unshare cp "${staging}/imported-build-2.log" "${template}/log"
printf '0 %s\n' "${shell_node_id}" > "${staging}/imported-build-2.log-index"
podman unshare cp "${staging}/imported-build-2.log-index" "${template}/log-index"
test "$(podman unshare cat "${template}/log-index")" = "0 ${shell_node_id}"
jq --sort-keys '.jobs[0].builds[1]' "${reverse_bundle}" \
  > "${staging}/mcloving-state-transfer-build.json"
jq --sort-keys '
  .jobs[0].builds[1] as $build
  | {
      schema: "mcloving.jenkins-native-provenance/v1",
      native_queue_id: -1,
      native_cause_action: "removed-unrepresentable-contained-rehearsal",
      native_time_in_queue_action: "removed-unrepresentable-contained-rehearsal",
      source_queue_id: $build.source_queue_id,
      queued_at_unix_ms: $build.queued_at_unix_ms,
      trigger_kind: $build.trigger.trigger_kind,
      trigger_external_id: $build.trigger.external_id,
      trigger_actor_subject: $build.trigger.actor_subject
    }
' "${reverse_bundle}" > "${staging}/mcloving-native-provenance.json"
jq --exit-status '
  .schema == "mcloving.jenkins-native-provenance/v1"
  and .native_queue_id == -1
  and .native_cause_action == "removed-unrepresentable-contained-rehearsal"
  and .native_time_in_queue_action == "removed-unrepresentable-contained-rehearsal"
  and .source_queue_id == "mig005a-corpus052-build-2"
  and .trigger_kind == "contained-rehearsal"
  and .trigger_external_id == "mig005a-corpus052-build-2"
  and .trigger_actor_subject == "migration:corpus052"
' "${staging}/mcloving-native-provenance.json" >/dev/null
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
podman unshare cp "${staging}/mcloving-native-provenance.json" \
  "${template}/mcloving-native-provenance.json"
podman unshare cp "${staging}/mcloving-state-transfer-receipt.json" \
  "${template}/mcloving-state-transfer-receipt.json"
podman unshare sed -E -i \
  -e "s#<timestamp>[0-9]+</timestamp>#<timestamp>${build_started}</timestamp>#g" \
  -e "s#<duration>[0-9]+</duration>#<duration>${build_duration}</duration>#g" \
  -e 's#<result>[^<]+</result>#<result>SUCCESS</result>#g' \
  "${template}/build.xml"
podman unshare perl -0pi -e '
  my $queue = s{<queueId>-?[0-9]+</queueId>}{<queueId>-1</queueId>}g;
  my $causes = s{\s*<hudson\.model\.CauseAction(?:\s[^>]*)?>.*?</hudson\.model\.CauseAction>}{}sg;
  my $queue_timing = s{\s*<jenkins\.metrics\.impl\.TimeInQueueAction(?:\s[^>]*)?>.*?</jenkins\.metrics\.impl\.TimeInQueueAction>}{}sg;
  die "native template provenance denominator mismatch\n"
    unless $queue == 1 && $causes == 1 && $queue_timing == 1;
' "${template}/build.xml"
podman unshare rg --quiet '<queueId>-1</queueId>' "${template}/build.xml"
if podman unshare rg --quiet \
  'hudson\.model\.CauseAction|jenkins\.metrics\.impl\.TimeInQueueAction' \
  "${template}/build.xml"; then
  echo "template queue or cause provenance survived reconciliation" >&2
  exit 1
fi
flow_store="${template}/workflow-completed/flowNodeStore.xml"
podman unshare test -f "${flow_store}"
podman unshare test ! -L "${flow_store}"
podman unshare rg --quiet 'ShellStep' "${flow_store}"
podman unshare rg --quiet 'Hello World' "${flow_store}"
BUILD_STARTED="${build_started}" BUILD_ENDED="${build_ended}" \
  TEMPLATE_SHELL_STARTED="${template_shell_started}" \
  TEMPLATE_SHELL_ENDED="${template_shell_ended}" \
  ATTEMPT_STARTED="${attempt_started}" ATTEMPT_ENDED="${attempt_ended}" \
  podman unshare perl -0pi -e '
    my @times = /<startTime>([0-9]+)<\/startTime>/g;
    die "native workflow has no timestamps\n" unless @times;
    my ($min, $max) = ($times[0], $times[0]);
    for my $time (@times) {
      $min = $time if $time < $min;
      $max = $time if $time > $max;
    }
    my $started = $ENV{BUILD_STARTED};
    my $ended = $ENV{BUILD_ENDED};
    my $attempt_started = $ENV{ATTEMPT_STARTED};
    my $attempt_ended = $ENV{ATTEMPT_ENDED};
    my $template_shell_started = $ENV{TEMPLATE_SHELL_STARTED};
    my $template_shell_ended = $ENV{TEMPLATE_SHELL_ENDED};
    my @shell_starts = grep { $times[$_] == $ENV{TEMPLATE_SHELL_STARTED} } 0 .. $#times;
    my @shell_ends = grep { $times[$_] == $ENV{TEMPLATE_SHELL_ENDED} } 0 .. $#times;
    die "native ShellStep timing denominator mismatch\n"
      unless @shell_starts == 1 && @shell_ends == 1
        && $template_shell_started < $template_shell_ended;
    die "invalid canonical build/attempt interval\n"
      unless $started <= $attempt_started
        && $attempt_started <= $attempt_ended
        && $attempt_ended <= $ended;
    my $scale = sub {
      my ($value, $from_started, $from_ended, $to_started, $to_ended) = @_;
      return $to_started if $from_started == $from_ended;
      return $to_started
        + int((($value - $from_started) * ($to_ended - $to_started))
          / ($from_ended - $from_started));
    };
    my @mapped;
    for my $time (@times) {
      my $value;
      if ($time < $template_shell_started) {
        $value = $scale->($time, $min, $template_shell_started,
          $started, $attempt_started);
      } elsif ($time == $template_shell_started) {
        $value = $attempt_started;
      } elsif ($time < $template_shell_ended) {
        $value = $scale->($time, $template_shell_started, $template_shell_ended,
          $attempt_started, $attempt_ended);
      } elsif ($time == $template_shell_ended) {
        $value = $attempt_ended;
      } else {
        $value = $scale->($time, $template_shell_ended, $max,
          $attempt_ended, $ended);
      }
      push @mapped, $value;
    }
    for my $left (0 .. $#times) {
      for my $right (0 .. $#times) {
        die "native workflow graph chronology is not monotonic\n"
          if $times[$left] <= $times[$right]
            && $mapped[$left] > $mapped[$right];
      }
    }
    die "native ShellStep boundary mapping is divergent\n"
      unless $mapped[$shell_starts[0]] == $attempt_started
        && $mapped[$shell_ends[0]] == $attempt_ended;
    my $index = 0;
    s{<startTime>([0-9]+)</startTime>}{
      my $mapped_time = $mapped[$index];
      $index++;
      "<startTime>${mapped_time}</startTime>"
    }ge;
    die "native workflow timing rewrite count mismatch\n" unless $index == @times;
  ' "${flow_store}"
BUILD_STARTED="${build_started}" BUILD_ENDED="${build_ended}" \
  podman unshare perl -0ne '
    my @times = /<startTime>([0-9]+)<\/startTime>/g;
    die "native workflow has no timestamps\n" unless @times;
    for my $time (@times) {
      die "native workflow timestamp escapes canonical build interval\n"
        if $time < $ENV{BUILD_STARTED} || $time > $ENV{BUILD_ENDED};
    }
  ' "${flow_store}"
if podman unshare rg --quiet 'MIG005A_SERIALIZATION_TEMPLATE_ONLY' "${template}"; then
  echo "serialization-template marker survived build-2 reconciliation" >&2
  exit 1
fi
podman unshare cp -a "${template}" "${job_home}/builds/2"
printf '%s\n' 3 > "${staging}/nextBuildNumber"
printf '%s\n' \
  'lastCompletedBuild 2' \
  'lastStableBuild 2' \
  'lastSuccessfulBuild 2' > "${staging}/permalinks"
podman unshare cp "${staging}/nextBuildNumber" "${job_home}/nextBuildNumber"
podman unshare cp "${staging}/permalinks" "${job_home}/builds/permalinks"
podman unshare chown -R 1000:1000 "${job_home}"

start_controller "${home}" "${home_plugins}"
capture_build 1 imported "${job_home}/builds/1/log" "${sealed_builds}/1/log"
capture_build 2 imported
jq --exit-status '.number == 1 and .result == "ABORTED"' \
  "${staging}/evidence/imported-build-1.json" >/dev/null
jq --exit-status '.number == 2 and .result == "SUCCESS"' \
  "${staging}/evidence/imported-build-2.json" >/dev/null
jq --exit-status '
  .queueId == -1
  and ([.actions[] | select(._class == "hudson.model.CauseAction")] | length) == 0
  and ([.actions[] | select(._class == "jenkins.metrics.impl.TimeInQueueAction")] | length) == 0
' "${staging}/evidence/imported-build-2.json" >/dev/null
test "$(cat "${staging}/evidence/imported-build-2.log")" = \
  $'+ echo Hello World\nHello World'
capture_workflow 2 imported "${log_payload}" "${attempt_started}" "${attempt_ended}"
podman unshare cmp "${job_home}/builds/2/mcloving-native-provenance.json" \
  "${staging}/mcloving-native-provenance.json"
podman unshare cmp "${job_home}/builds/2/mcloving-state-transfer-receipt.json" \
  "${staging}/mcloving-state-transfer-receipt.json"
podman unshare cmp "${job_home}/builds/2/mcloving-state-transfer-build.json" \
  "${staging}/mcloving-state-transfer-build.json"
test "$(podman unshare cat "${job_home}/nextBuildNumber")" = 3
stop_controller

start_controller "${home}" "${home_plugins}"
capture_build 1 restarted "${job_home}/builds/1/log" "${sealed_builds}/1/log"
capture_build 2 restarted
jq --exit-status '.number == 1 and .result == "ABORTED"' \
  "${staging}/evidence/restarted-build-1.json" >/dev/null
jq --exit-status '.number == 2 and .result == "SUCCESS"' \
  "${staging}/evidence/restarted-build-2.json" >/dev/null
jq --exit-status '
  .queueId == -1
  and ([.actions[] | select(._class == "hudson.model.CauseAction")] | length) == 0
  and ([.actions[] | select(._class == "jenkins.metrics.impl.TimeInQueueAction")] | length) == 0
' "${staging}/evidence/restarted-build-2.json" >/dev/null
test "$(cat "${staging}/evidence/restarted-build-2.log")" = \
  $'+ echo Hello World\nHello World'
capture_workflow 2 restarted "${log_payload}" "${attempt_started}" "${attempt_ended}"
podman unshare cmp "${job_home}/builds/2/mcloving-native-provenance.json" \
  "${staging}/mcloving-native-provenance.json"
podman unshare cmp "${job_home}/builds/2/mcloving-state-transfer-receipt.json" \
  "${staging}/mcloving-state-transfer-receipt.json"
podman unshare cmp "${job_home}/builds/2/mcloving-state-transfer-build.json" \
  "${staging}/mcloving-state-transfer-build.json"
test "$(podman unshare cat "${job_home}/nextBuildNumber")" = 3
podman exec "${container}" curl --fail --silent --show-error -X POST \
  "http://127.0.0.1:8080/job/${job}/build" >/dev/null
capture_build 3 continued "${job_home}/builds/3/log"
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
podman unshare test -f "${job_home}/builds/2/mcloving-native-provenance.json"
podman unshare cmp "${job_home}/builds/2/mcloving-native-provenance.json" \
  "${staging}/mcloving-native-provenance.json"
podman unshare cmp "${job_home}/builds/2/mcloving-state-transfer-receipt.json" \
  "${staging}/mcloving-state-transfer-receipt.json"
podman unshare cmp "${job_home}/builds/2/mcloving-state-transfer-build.json" \
  "${staging}/mcloving-state-transfer-build.json"
test "$(jq -r '.reverse_bundle_digest' \
  "${staging}/mcloving-state-transfer-receipt.json")" = "${reverse_digest}"
test "$(jq -r '.production_authority' \
  "${staging}/mcloving-state-transfer-receipt.json")" = false
podman unshare cp -a "${job_home}" "${staging}/evidence/jenkins-job-after"
podman unshare chown -R 0:0 "${staging}/evidence/jenkins-job-after"
cmp "${staging}/evidence/jenkins-job-after/builds/2/mcloving-native-provenance.json" \
  "${staging}/mcloving-native-provenance.json"
cmp "${staging}/evidence/jenkins-job-after/builds/2/mcloving-state-transfer-receipt.json" \
  "${staging}/mcloving-state-transfer-receipt.json"
cmp "${staging}/evidence/jenkins-job-after/builds/2/mcloving-state-transfer-build.json" \
  "${staging}/mcloving-state-transfer-build.json"
cmp "${staging}/evidence/imported-build-1.log" "${sealed_builds}/1/log"
cmp "${staging}/evidence/restarted-build-1.log" "${sealed_builds}/1/log"
cmp "${staging}/evidence/jenkins-job-after/builds/1/log" "${sealed_builds}/1/log"
cmp "${staging}/evidence/jenkins-job-after/builds/2/log" \
  "${staging}/evidence/imported-build-2.log"
cmp "${staging}/evidence/jenkins-job-after/builds/2/log" \
  "${staging}/evidence/restarted-build-2.log"
cmp "${staging}/evidence/jenkins-job-after/builds/3/log" \
  "${staging}/evidence/continued-build-3.log"
rm -f -- "${staging}/imported-build-2.log" \
  "${staging}/imported-build-2.log-index" \
  "${staging}/mcloving-state-transfer-build.json" \
  "${staging}/mcloving-native-provenance.json" \
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
"${privileged[@]}" rm -rf -- "${authenticated_rehearsal}"
"${privileged[@]}" rm -rf -- "${home_plugins}"
"${privileged[@]}" rm -rf -- "${template_plugins}"
"${privileged[@]}" rm -rf -- "${runtime_root}"
mv -- "${staging}" "${output_parent}/${output_leaf}"
completed=1
(
  cd "${output_parent}/${output_leaf}"
  sha256sum -c SHA256SUMS >/dev/null
)
printf '%s\n' "${output_parent}/${output_leaf}"
