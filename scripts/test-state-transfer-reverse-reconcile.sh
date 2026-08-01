#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 FIXTURE_ROOT RUNTIME_ROOT TRANSFORM_ROOT OUTPUT_ROOT" >&2
  exit 64
fi

fixture_root=$1
runtime_root=$2
transform_root=$3
output_root=$4
home="$runtime_root/jenkins-home"
repository="$runtime_root/repository"
job_home="$home/jobs/stateful"
image='docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02'
container="mcloving-mig005a-reverse-$$"
network="mcloving-mig005a-reverse-$$"
port=$((19550 + ($$ % 400)))
reverse_bundle="$transform_root/reverse-bundle.json"
rehearsal_summary="$transform_root/rehearsal-summary.json"

output_parent=$(realpath -e "$(dirname -- "$output_root")")
output_leaf=$(basename -- "$output_root")
if [[ "$output_parent" != "$(pwd -P)" \
  || ! "$output_leaf" =~ ^reverse-v[0-9]+$ \
  || -e "$output_root" ]]; then
  echo "reverse output must be one new direct reverse-vN child of the working directory" >&2
  exit 73
fi
output_root="$output_parent/$output_leaf"
evidence="$output_root/evidence"
staging="$output_root/imported-build-3"

test ! -e "$repository/docs/final.md"
original_repository_head=$(git -C "$repository" rev-parse HEAD)
repository_ref=$(git -C "$repository" symbolic-ref -q HEAD)
test -n "$repository_ref"
rollback_root=$(mktemp -d "$runtime_root/.mcloving-reverse-rollback.XXXXXX")
podman unshare cp -a "$job_home/nextBuildNumber" "$rollback_root/nextBuildNumber"
permalinks_existed=0
if [[ -e "$job_home/builds/permalinks" ]]; then
  podman unshare cp -a "$job_home/builds/permalinks" "$rollback_root/permalinks"
  permalinks_existed=1
fi
completed=0

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  podman rm -f "$container" >/dev/null 2>&1 || true
  podman network rm "$network" >/dev/null 2>&1 || true
  if [[ "$completed" != 1 ]]; then
    podman unshare rm -rf -- "$job_home/builds/3" "$job_home/builds/4"
    podman unshare rm -f -- "$job_home/nextBuildNumber" "$job_home/builds/permalinks"
    podman unshare cp -a "$rollback_root/nextBuildNumber" "$job_home/nextBuildNumber"
    if [[ "$permalinks_existed" == 1 ]]; then
      podman unshare cp -a "$rollback_root/permalinks" "$job_home/builds/permalinks"
    fi
    podman unshare chown -R 1000:1000 "$job_home/nextBuildNumber" \
      "$job_home/builds/permalinks" 2>/dev/null || true
    current_repository_head=$(git -C "$repository" rev-parse HEAD 2>/dev/null)
    if [[ -n "$current_repository_head" && "$current_repository_head" != "$original_repository_head" ]]; then
      git -C "$repository" update-ref "$repository_ref" \
        "$original_repository_head" "$current_repository_head"
    fi
    git -C "$repository" read-tree "$original_repository_head"
    rm -f -- "$repository/docs/final.md"
    rm -rf -- "$output_root"
  fi
  rm -rf -- "$rollback_root"
  exit "$status"
}
trap cleanup EXIT

test -f "$reverse_bundle"
test -f "$rehearsal_summary"
test -f "$transform_root/jenkins-import-map.json"
test -f "$job_home/builds/2/build.xml"
test ! -e "$job_home/builds/3"
test "$(cat "$job_home/nextBuildNumber")" = 3
expected_bundle_digest=$(jq -r '.reverse_bundle_digest' "$rehearsal_summary")
actual_bundle_digest=$(sha256sum "$reverse_bundle" | awk '{print $1}')
test "$expected_bundle_digest" = "$actual_bundle_digest"

jq --exit-status '
  .binding.schema == "mcloving.state-transfer/v1"
  and .binding.direction == "mc_loving_to_jenkins"
  and .binding.source.kind == "mcloving"
  and .binding.destination.kind == "jenkins"
  and .binding.conflict_policy == "reject_divergence"
  and (.jobs | length) == 1
  and ([.jobs[] | select(.source_job_id == "stateful")] | length) == 1
  and ([.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3)] | length) == 1
  and ([.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3)
        | .graph_nodes[].stage_path] | sort)
      == ["Declarative: Post Actions", "changelog-predicate", "changeset-predicate", "checkout", "effect-free-state"]
  and ([.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3)
        | .graph_nodes[] | select(.result == "succeeded")] | length) == 5
  and ([.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3)
        | .artifacts[].logical_name] | sort)
      == ["changelog.intent", "changeset.intent", "persistent.state", "workspace.input"]
' "$reverse_bundle" >/dev/null

build_number=$(jq -r '.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3) | .number' "$reverse_bundle")
next_build_number=$(jq -r '.jobs[] | select(.source_job_id == "stateful") | .next_build_number' "$reverse_bundle")
revision_2=$(jq -r '.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3) | .checkouts[0].previous_revision' "$reverse_bundle")
revision_3=$(jq -r '.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3) | .checkouts[0].revision' "$reverse_bundle")
reverse_result=$(jq -r '.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3) | .result' "$reverse_bundle")
build_started=$(jq -r '.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3) | .started_at_unix_ms' "$reverse_bundle")
build_ended=$(jq -r '.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3) | .ended_at_unix_ms' "$reverse_bundle")
build_duration=$((build_ended - build_started))
test "$build_number" = 3
test "$next_build_number" = 4
case "$reverse_result" in
  succeeded) jenkins_result=SUCCESS ;;
  failed) jenkins_result=FAILURE ;;
  aborted) jenkins_result=ABORTED ;;
  *)
    echo "unsupported reverse-bundle result: $reverse_result" >&2
    exit 65
    ;;
esac

jq --exit-status \
  --argjson build_number "$build_number" \
  --argjson next_build_number "$next_build_number" \
  --arg result "$jenkins_result" \
  --arg revision "$revision_3" \
  --arg previous_revision "$revision_2" \
  --arg reverse_bundle_digest "$actual_bundle_digest" '
  .schema == "mcloving.jenkins-rehearsal-import/v1"
  and .source_template_build == 2
  and .destination_build == $build_number
  and .next_build_number == $next_build_number
  and .result == $result
  and .revision == $revision
  and .previous_revision == $previous_revision
  and .reverse_bundle_digest == $reverse_bundle_digest
' "$transform_root/jenkins-import-map.json" >/dev/null

test "$(git -C "$repository" rev-parse HEAD)" = "$revision_3"

materialize_artifact() {
  local logical_name=$1
  local payload="$transform_root/mcloving-$logical_name"
  local destination="$staging/archive/$logical_name"
  local bundle_digest bundle_bytes payload_digest payload_bytes

  test -f "$payload"
  bundle_digest=$(jq -r --arg logical_name "$logical_name" '
    .jobs[] | select(.source_job_id == "stateful")
    | .builds[] | select(.number == 3)
    | .artifacts[] | select(.logical_name == $logical_name)
    | .content_digest[]
  ' "$reverse_bundle" | awk '{printf "%02x", $1} END {print ""}')
  bundle_bytes=$(jq -r --arg logical_name "$logical_name" '
    .jobs[] | select(.source_job_id == "stateful")
    | .builds[] | select(.number == 3)
    | .artifacts[] | select(.logical_name == $logical_name)
    | .bytes
  ' "$reverse_bundle")
  payload_digest=$(sha256sum "$payload" | awk '{print $1}')
  payload_bytes=$(wc -c < "$payload" | tr -d ' ')

  test "$bundle_digest" = "$payload_digest"
  test "$bundle_bytes" = "$payload_bytes"
  jq --exit-status --arg logical_name "$logical_name" '
    .jobs[] | select(.source_job_id == "stateful")
    | .builds[] | select(.number == 3)
    | .artifacts[] | select(.logical_name == $logical_name)
    | .kind == "artifact"
      and .producer_build_number == 3
      and .retrieval.logical_locator == ("artifacts/stateful/3/" + $logical_name)
      and .retrieval.content_digest == .content_digest
      and .data_binding.classification == "internal"
      and .data_binding.secret_disposition == null
      and .filesystem_entries == []
  ' "$reverse_bundle" >/dev/null
  cp "$payload" "$destination"
}

mkdir -p "$evidence"
cp -r "$job_home/builds/2" "$staging"
chmod -R u+rwX "$staging"
jq --sort-keys '
  .jobs[] | select(.source_job_id == "stateful")
  | .builds[] | select(.number == 3)
' "$reverse_bundle" > "$staging/mcloving-state-transfer-build.json"
jq --sort-keys '
  .jobs[] | select(.source_job_id == "stateful")
  | .builds[] | select(.number == 3)
  | .protection
' "$reverse_bundle" > "$staging/mcloving-state-transfer-protection.json"
old_persistent_md5=$(md5sum "$staging/archive/persistent.state" | awk '{print $1}')
materialize_artifact changeset.intent
materialize_artifact changelog.intent
materialize_artifact persistent.state
materialize_artifact workspace.input
new_persistent_md5=$(md5sum "$staging/archive/persistent.state" | awk '{print $1}')

sed -E -i \
  -e "s/$revision_2/$revision_3/g" \
  -e "s#<hudsonBuildNumber>2</hudsonBuildNumber>#<hudsonBuildNumber>${build_number}</hudsonBuildNumber>#g" \
  -e 's#<queueId>[0-9]+</queueId>#<queueId>5</queueId>#g' \
  -e "s#<timestamp>[0-9]+</timestamp>#<timestamp>${build_started}</timestamp>#g" \
  -e "s#<duration>[0-9]+</duration>#<duration>${build_duration}</duration>#g" \
  -e "s#<result>[^<]+</result>#<result>${jenkins_result}</result>#g" \
  -e "s#/builds/2/#/builds/${build_number}/#g" \
  -e "s/$old_persistent_md5/$new_persistent_md5/g" \
  "$staging/build.xml"

changelog=$(find "$staging" -maxdepth 1 -name 'changelog*.xml' -print -quit)
test -n "$changelog"
revision_1=$(git -C "$repository" rev-parse "$revision_2^")
sed -i \
  -e "s/$revision_2/$revision_3/g" \
  -e "s/$revision_1/$revision_2/g" \
  -e 's/MIG005A-MATCH first predicate revision/MIG005A-MATCH second predicate revision/g' \
  -e 's#src/first.target#src/second.target#g' \
  "$changelog"

: > "$staging/log"
log_count=$(jq -r '.jobs[] | select(.source_job_id == "stateful") | .builds[] | select(.number == 3) | .logs | length' "$reverse_bundle")
for sequence in $(seq 0 $((log_count - 1))); do
  payload="$transform_root/mcloving-log-${sequence}.txt"
  test -f "$payload"
  expected_log_digest=$(jq -r --argjson sequence "$sequence" '
    .jobs[] | select(.source_job_id == "stateful")
    | .builds[] | select(.number == 3)
    | .logs[] | select(.sequence == $sequence)
    | .content_digest[]
  ' "$reverse_bundle" | awk '{printf "%02x", $1} END {print ""}')
  expected_log_bytes=$(jq -r --argjson sequence "$sequence" '
    .jobs[] | select(.source_job_id == "stateful")
    | .builds[] | select(.number == 3)
    | .logs[] | select(.sequence == $sequence)
    | .bytes
  ' "$reverse_bundle")
  test "$(sha256sum "$payload" | awk '{print $1}')" = "$expected_log_digest"
  test "$(wc -c < "$payload" | tr -d ' ')" = "$expected_log_bytes"
  cat "$payload" >> "$staging/log"
done

perl -0ne '
  while (m{<entry>(.*?)</entry>}sg) {
    my $entry = $1;
    next unless $entry =~ m{<node class="cps\.n\.StepStartNode"};
    my ($id) = $entry =~ m{<id>([0-9]+)</id>};
    my ($name) = $entry =~ m{<displayName>([^<]+)</displayName>};
    print "$name\t$id\n" if defined $id && defined $name;
  }
' "$staging/workflow-completed/flowNodeStore.xml" \
  > "$evidence/native-workflow-stage-map.tsv"
test "$(wc -l < "$evidence/native-workflow-stage-map.tsv" | tr -d ' ')" = 5
test "$(cut -f1 "$evidence/native-workflow-stage-map.tsv" | sort -u | wc -l | tr -d ' ')" = 5
test "$(cut -f2 "$evidence/native-workflow-stage-map.tsv" | sort -u | wc -l | tr -d ' ')" = 5
jq -r '
  .jobs[] | select(.source_job_id == "stateful")
  | .builds[] | select(.number == 3)
  | .graph_nodes[]
  | (.attempts | map(select(.started_at_unix_ms != null)) | last) as $executing
  | select($executing != null)
  | [
      .stage_path,
      $executing.started_at_unix_ms,
      $executing.ended_at_unix_ms
    ]
  | @tsv
' "$reverse_bundle" > "$evidence/canonical-workflow-timing.tsv"
test "$(wc -l < "$evidence/canonical-workflow-timing.tsv" | tr -d ' ')" = 5
: > "$evidence/workflow-timing-map.tsv"
while IFS=$'\t' read -r stage_name stage_started stage_ended; do
  stage_id=$(awk -F '\t' -v name="$stage_name" '$1 == name {print $2}' \
    "$evidence/native-workflow-stage-map.tsv")
  test "$(printf '%s\n' "$stage_id" | wc -l | tr -d ' ')" = 1
  test -n "$stage_id"
  printf '%s\t%s\t%s\t%s\n' \
    "$stage_name" "$stage_id" "$stage_started" "$stage_ended" \
    >> "$evidence/workflow-timing-map.tsv"
done < "$evidence/canonical-workflow-timing.tsv"
test "$(wc -l < "$evidence/workflow-timing-map.tsv" | tr -d ' ')" = 5
test "$(cut -f1 "$evidence/workflow-timing-map.tsv" | sort -u | wc -l | tr -d ' ')" = 5
test "$(cut -f2 "$evidence/workflow-timing-map.tsv" | sort -u | wc -l | tr -d ' ')" = 5
while IFS=$'\t' read -r stage_name stage_id stage_started stage_ended; do
  test -n "$stage_name"
  test -n "$stage_id"
  test "$stage_started" -le "$stage_ended"
  stage_parent_id=$((stage_id - 1))
  STAGE_ID=$stage_id STAGE_PARENT_ID=$stage_parent_id \
    STAGE_STARTED=$stage_started STAGE_ENDED=$stage_ended perl -0pi -e '
      my $id = $ENV{STAGE_ID};
      my $parent = $ENV{STAGE_PARENT_ID};
      my $started = $ENV{STAGE_STARTED};
      my $ended = $ENV{STAGE_ENDED};
      my $starts = s{(<entry>(?:(?!</entry>).)*?<node class="cps\.n\.StepStartNode"(?:(?!</entry>).)*?<id>\Q$id\E</id>(?:(?!</entry>).)*?<startTime>)[0-9]+(</startTime>(?:(?!</entry>).)*?</entry>)}{$1 . $started . $2}se;
      my $ends = s{(<entry>(?:(?!</entry>).)*?<node class="cps\.n\.StepEndNode"(?:(?!</entry>).)*?<startId>\Q$parent\E</startId>(?:(?!</entry>).)*?<startTime>)[0-9]+(</startTime>(?:(?!</entry>).)*?</entry>)}{$1 . $ended . $2}se;
      die "canonical workflow timing target mismatch for stage $id\n"
        unless $starts == 1 && $ends == 1;
    ' "$staging/workflow-completed/flowNodeStore.xml"
done < "$evidence/workflow-timing-map.tsv"

rg --quiet "<sha1>$revision_3</sha1>" "$staging/build.xml"
rg --quiet "<hudsonBuildNumber>${build_number}</hudsonBuildNumber>" "$staging/build.xml"
rg --quiet "/builds/${build_number}/" "$staging/build.xml"
rg --quiet "<result>${jenkins_result}</result>" "$staging/build.xml"
rg --quiet "<timestamp>${build_started}</timestamp>" "$staging/build.xml"
rg --quiet "<duration>${build_duration}</duration>" "$staging/build.xml"
test "$(cat "$staging/archive/persistent.state")" = 'build=3'
test "$(cat "$staging/archive/changeset.intent")" = 'selected'
test "$(cat "$staging/archive/changelog.intent")" = 'selected'
cmp "$staging/archive/workspace.input" "$fixture_root/repo/first.target"

printf '%s\n' "$next_build_number" > "$output_root/nextBuildNumber"
printf '%s\n' \
  'lastCompletedBuild 3' \
  'lastStableBuild 3' \
  'lastSuccessfulBuild 3' > "$output_root/permalinks"
podman unshare cp -a "$staging" "$job_home/builds/3"
podman unshare cp "$output_root/nextBuildNumber" "$job_home/nextBuildNumber"
podman unshare cp "$output_root/permalinks" "$job_home/builds/permalinks"
podman unshare chown -R 1000:1000 \
  "$job_home/builds/3" "$job_home/nextBuildNumber" "$job_home/builds/permalinks"

cp "$fixture_root/repo/final.md" "$repository/docs/final.md"
git -C "$repository" add docs/final.md
git -C "$repository" commit -m 'final non-matching revision' >/dev/null
revision_4=$(git -C "$repository" rev-parse HEAD)

if [[ ${MCLOVING_REVERSE_FAIL_AFTER_INSTALL:-0} == 1 ]]; then
  echo 'injected failure after reverse state installation' >&2
  exit 86
fi

podman network create --internal "$network" >/dev/null
podman run -d --name "$container" \
  --network "$network" \
  --publish "127.0.0.1:${port}:8080" \
  --cpus 4 --memory 4g --pids-limit 2048 \
  --security-opt no-new-privileges \
  --cap-drop all \
  --env JAVA_OPTS='-Djenkins.install.runSetupWizard=false -Dhudson.plugins.git.GitSCM.ALLOW_LOCAL_CHECKOUT=true' \
  --env GIT_ALLOW_PROTOCOL=file \
  --env GIT_CONFIG_COUNT=1 \
  --env GIT_CONFIG_KEY_0=safe.directory \
  --env GIT_CONFIG_VALUE_0=/fixture/repo/.git \
  --volume "$home:/var/jenkins_home:Z" \
  --volume "$repository:/fixture/repo:ro,Z" \
  "$image" >/dev/null

for _ in $(seq 1 180); do
  if curl --fail --silent --show-error "http://127.0.0.1:${port}/api/json" >/dev/null; then
    break
  fi
  sleep 1
done
curl --fail --silent --show-error "http://127.0.0.1:${port}/api/json" >/dev/null
for _ in $(seq 1 180); do
  if curl --fail --silent --show-error \
    "http://127.0.0.1:${port}/job/stateful/3/api/json" \
    -o "$evidence/jenkins-imported-build-3.json" 2>/dev/null \
    && jq --exit-status --argjson number "$build_number" --arg result "$jenkins_result" \
      '.number == $number and .result == $result and .building == false' \
      "$evidence/jenkins-imported-build-3.json" >/dev/null; then
    break
  fi
  sleep 1
done
jq --exit-status --argjson number "$build_number" --arg result "$jenkins_result" \
  --argjson started "$build_started" --argjson duration "$build_duration" '
  .number == $number
  and .result == $result
  and .building == false
  and .timestamp == $started
  and .duration == $duration
  and .queueId == 5
' \
  "$evidence/jenkins-imported-build-3.json" >/dev/null
curl --fail --silent --show-error \
  "http://127.0.0.1:${port}/job/stateful/3/wfapi/describe" \
  -o "$evidence/jenkins-imported-build-3-workflow.json"
jq --sort-keys '
  .jobs[] | select(.source_job_id == "stateful")
  | .builds[] | select(.number == 3)
' "$reverse_bundle" > "$evidence/expected-build-3.json"
jq --sort-keys '
  def jenkins_status:
    if . == "succeeded" then "SUCCESS"
    elif . == "failed" then "FAILED"
    elif . == "aborted" then "ABORTED"
    elif . == "unstable" then "UNSTABLE"
    elif . == "not_built" then "NOT_EXECUTED"
    else error("unsupported canonical stage result")
    end;
  [
    .graph_nodes[]
    | (.attempts | map(select(.started_at_unix_ms != null)) | last) as $executing
    | select($executing != null)
    | {
        name: .stage_path,
        status: (.result | jenkins_status),
        startTimeMillis: $executing.started_at_unix_ms,
        durationMillis: ($executing.ended_at_unix_ms - $executing.started_at_unix_ms)
      }
  ] | sort_by(.name)
' "$evidence/expected-build-3.json" > "$evidence/expected-build-3-workflow.json"
jq --sort-keys '
  [.stages[] | {name, status, startTimeMillis, durationMillis}] | sort_by(.name)
' "$evidence/jenkins-imported-build-3-workflow.json" \
  > "$evidence/observed-build-3-workflow.json"
cmp "$evidence/expected-build-3-workflow.json" \
  "$evidence/observed-build-3-workflow.json"
podman unshare cp "$job_home/builds/3/mcloving-state-transfer-build.json" \
  "$evidence/observed-build-3.json"
cmp "$evidence/expected-build-3.json" "$evidence/observed-build-3.json"
jq --sort-keys '
  [.graph_nodes[] | select(.attempts | length > 1) | {stage_path, attempts}]
' "$evidence/expected-build-3.json" > "$evidence/expected-build-3-retry-history.json"
jq --sort-keys '
  [.graph_nodes[] | select(.attempts | length > 1) | {stage_path, attempts}]
' "$evidence/observed-build-3.json" > "$evidence/observed-build-3-retry-history.json"
test "$(jq 'length' "$evidence/expected-build-3-retry-history.json")" = 4
cmp "$evidence/expected-build-3-retry-history.json" \
  "$evidence/observed-build-3-retry-history.json"
jq --sort-keys '.protection' "$evidence/expected-build-3.json" \
  > "$evidence/expected-build-3-protection.json"
podman unshare cp "$job_home/builds/3/mcloving-state-transfer-protection.json" \
  "$evidence/observed-build-3-protection.json"
cmp "$evidence/expected-build-3-protection.json" \
  "$evidence/observed-build-3-protection.json"
jq --exit-status '
  .retention.retain_until_unix_ms == 2000000000000
  and ([.active_holds[].hold_id] | sort)
      == ["destination-case", "source-case-a", "source-case-b"]
  and ([.active_holds[] | select(.release_authority == "custodian:mig005a")] | length) == 3
' "$evidence/observed-build-3-protection.json" >/dev/null
cat "$transform_root"/mcloving-log-*.txt > "$evidence/expected-build-3.log"
podman unshare cp "$job_home/builds/3/log" "$evidence/observed-build-3.log"
cmp "$evidence/expected-build-3.log" "$evidence/observed-build-3.log"
jq -n --sort-keys \
  --slurpfile expected "$evidence/expected-build-3.json" \
  --slurpfile api "$evidence/jenkins-imported-build-3.json" \
  --slurpfile workflow "$evidence/jenkins-imported-build-3-workflow.json" '
  {
    schema: "mcloving.jenkins-import-verification/v1",
    canonical_record_equal: true,
    protection_record_equal: true,
    native_build: {
      number: $api[0].number,
      queue_id: $api[0].queueId,
      result: $api[0].result,
      timestamp: $api[0].timestamp,
      duration: $api[0].duration
    },
    canonical_build: {
      number: $expected[0].number,
      result: $expected[0].result,
      queued_at_unix_ms: $expected[0].queued_at_unix_ms,
      started_at_unix_ms: $expected[0].started_at_unix_ms,
      ended_at_unix_ms: $expected[0].ended_at_unix_ms,
      source_queue_id: $expected[0].source_queue_id,
      source_build_id: $expected[0].source_build_id,
      trigger: $expected[0].trigger,
      checkouts: $expected[0].checkouts,
      graph_nodes: $expected[0].graph_nodes,
      approvals: $expected[0].approvals,
      normalized_tests: $expected[0].normalized_tests,
      logs: $expected[0].logs,
      artifacts: $expected[0].artifacts,
      protection: $expected[0].protection,
      audit_digest: $expected[0].audit_digest
    },
    native_workflow_stages: [$workflow[0].stages[] | {id, name, status, startTimeMillis, durationMillis}],
    log_payload_equal: true,
    artifact_payloads_equal: true,
    scm_changelog_rewritten_from_canonical_checkout: true
  }
' > "$evidence/jenkins-imported-build-3-verification.json"
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error \
    "http://127.0.0.1:${port}/job/stateful/3/artifact/persistent.state" \
    -o "$evidence/imported-persistent.state" 2>/dev/null; then
    break
  fi
  sleep 1
done
cmp "$evidence/imported-persistent.state" "$transform_root/mcloving-persistent.state"
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error \
    "http://127.0.0.1:${port}/job/stateful/3/artifact/workspace.input" \
    -o "$evidence/imported-workspace.input" 2>/dev/null; then
    break
  fi
  sleep 1
done
cmp "$evidence/imported-workspace.input" "$transform_root/mcloving-workspace.input"
cmp "$evidence/imported-workspace.input" "$fixture_root/repo/first.target"

triggered=0
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error -X POST \
    "http://127.0.0.1:${port}/job/stateful/build" >/dev/null 2>&1; then
    triggered=1
    break
  fi
  sleep 1
done
test "$triggered" = 1
for _ in $(seq 1 180); do
  if curl --fail --silent --show-error \
    "http://127.0.0.1:${port}/job/stateful/4/api/json" \
    -o "$evidence/jenkins-resumed-build-4.json" 2>/dev/null \
    && [[ $(jq -r '.building' "$evidence/jenkins-resumed-build-4.json") == false ]]; then
    break
  fi
  sleep 1
done
jq --exit-status '.number == 4 and .result == "SUCCESS" and .building == false' \
  "$evidence/jenkins-resumed-build-4.json" >/dev/null
test ! -e "$job_home/builds/4/archive/changeset.intent"
test ! -e "$job_home/builds/4/archive/changelog.intent"
test "$(cat "$job_home/builds/4/archive/persistent.state")" = 'build=4'
rg --quiet "git rev-list --no-walk $revision_3" "$job_home/builds/4/log"
rg --quiet "<sha1>$revision_4</sha1>" "$job_home/builds/4/build.xml"
test "$(cat "$job_home/nextBuildNumber")" = 5
test "$(find "$job_home/builds" -mindepth 1 -maxdepth 1 -type d -name '[1-4]' | wc -l)" = 4

if podman run --rm --network "$network" "$image" \
  timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' >/dev/null 2>&1; then
  echo 'private reverse fixture unexpectedly reached the public network' >&2
  exit 1
else
  printf '%s\n' 'public-network-denied' > "$evidence/network-negative.txt"
fi

podman stop --time 30 "$container" >/dev/null
cp "$job_home/builds/3/build.xml" "$evidence/jenkins-imported-build-3.xml"
cp "$job_home/builds/4/build.xml" "$evidence/jenkins-resumed-build-4.xml"
cp "$job_home/builds/4/log" "$evidence/jenkins-resumed-build-4.log"
cp "$job_home/nextBuildNumber" "$evidence/jenkins-next-build-number.txt"
cp "$transform_root/reverse-bundle.json" "$evidence/reverse-bundle.json"
cp "$transform_root/jenkins-import-map.json" "$evidence/jenkins-import-map.json"
podman inspect "$container" > "$evidence/jenkins-container-inspect.json"
podman image inspect "$image" > "$evidence/jenkins-image-inspect.json"
printf '%s\n' "$revision_2" > "$evidence/revision-2.txt"
printf '%s\n' "$revision_3" > "$evidence/revision-3.txt"
printf '%s\n' "$revision_4" > "$evidence/revision-4.txt"
find "$job_home/builds" -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum > "$evidence/jenkins-build-tree.sha256"
find "$evidence" -type f ! -name SHA256SUMS -printf '%P\0' \
  | sort -z \
  | while IFS= read -r -d '' path; do
      sha256sum "$evidence/$path"
    done > "$evidence/SHA256SUMS"
sha256sum -c "$evidence/SHA256SUMS"
completed=1
