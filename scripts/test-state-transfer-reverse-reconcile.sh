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
evidence="$output_root/evidence"
image='docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02'
container="mcloving-mig005a-reverse-$$"
network="mcloving-mig005a-reverse-$$"
port=$((19550 + ($$ % 400)))
staging="$output_root/imported-build-3"

if [[ -e "$staging" ]]; then
  echo "refusing to reuse existing reverse-import staging path: $staging" >&2
  exit 73
fi

cleanup() {
  podman rm -f "$container" >/dev/null 2>&1 || true
  podman network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

test -f "$transform_root/reverse-bundle.json"
test -f "$transform_root/jenkins-import-map.json"
test -f "$job_home/builds/2/build.xml"
test ! -e "$job_home/builds/3"
test "$(cat "$job_home/nextBuildNumber")" = 3
jq --exit-status '
  .schema == "mcloving.jenkins-rehearsal-import/v1"
  and .source_template_build == 2
  and .destination_build == 3
  and .next_build_number == 4
  and .result == "SUCCESS"
' "$transform_root/jenkins-import-map.json" >/dev/null

revision_2=$(jq -r '.previous_revision' "$transform_root/jenkins-import-map.json")
revision_3=$(jq -r '.revision' "$transform_root/jenkins-import-map.json")
test "$(git -C "$repository" rev-parse HEAD)" = "$revision_3"

mkdir -p "$evidence"
cp -r "$job_home/builds/2" "$staging"
chmod -R u+rwX "$staging"
old_persistent_md5=$(md5sum "$staging/archive/persistent.state" | awk '{print $1}')
cp "$transform_root/mcloving-changeset.intent" "$staging/archive/changeset.intent"
cp "$transform_root/mcloving-changelog.intent" "$staging/archive/changelog.intent"
cp "$transform_root/mcloving-persistent.state" "$staging/archive/persistent.state"
new_persistent_md5=$(md5sum "$staging/archive/persistent.state" | awk '{print $1}')

sed -i \
  -e "s/$revision_2/$revision_3/g" \
  -e 's#<hudsonBuildNumber>2</hudsonBuildNumber>#<hudsonBuildNumber>3</hudsonBuildNumber>#g' \
  -e 's#<queueId>3</queueId>#<queueId>4</queueId>#g' \
  -e 's#/builds/2/#/builds/3/#g' \
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
sed -i \
  -e "s/$revision_2/$revision_3/g" \
  -e "s/$revision_1/$revision_2/g" \
  -e 's/MIG005A-MATCH first predicate revision/MIG005A-MATCH second predicate revision/g' \
  -e 's#src/first.target#src/second.target#g' \
  "$staging/log"

rg --quiet "<sha1>$revision_3</sha1>" "$staging/build.xml"
rg --quiet '<hudsonBuildNumber>3</hudsonBuildNumber>' "$staging/build.xml"
rg --quiet '/builds/3/' "$staging/build.xml"
test "$(cat "$staging/archive/persistent.state")" = 'build=3'
test "$(cat "$staging/archive/changeset.intent")" = 'selected'
test "$(cat "$staging/archive/changelog.intent")" = 'selected'

printf '%s\n' 4 > "$output_root/nextBuildNumber"
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
    && jq --exit-status '.number == 3 and .result == "SUCCESS" and .building == false' \
      "$evidence/jenkins-imported-build-3.json" >/dev/null; then
    break
  fi
  sleep 1
done
jq --exit-status '.number == 3 and .result == "SUCCESS" and .building == false' \
  "$evidence/jenkins-imported-build-3.json" >/dev/null
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error \
    "http://127.0.0.1:${port}/job/stateful/3/artifact/persistent.state" \
    -o "$evidence/imported-persistent.state" 2>/dev/null; then
    break
  fi
  sleep 1
done
cmp "$evidence/imported-persistent.state" "$transform_root/mcloving-persistent.state"

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
