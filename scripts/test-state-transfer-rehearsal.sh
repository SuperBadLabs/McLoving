#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 FIXTURE_ROOT JENKINS_PLUGIN_SOURCE OUTPUT_ROOT" >&2
  exit 64
fi

fixture_root=$1
plugin_source=$2
output_root=$3
image='docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02'
container="mcloving-mig005a-jenkins-$$"
network="mcloving-mig005a-$$"
port=$((19000 + ($$ % 500)))
runtime_root=$(mktemp -d /tmp/mcloving-mig005a.XXXXXX)
home="$runtime_root/jenkins-home"
repository="$runtime_root/repository"
evidence="$output_root/evidence"

cleanup() {
  podman rm -f "$container" >/dev/null 2>&1 || true
  podman network rm "$network" >/dev/null 2>&1 || true
  if [[ ${CLEAN_MIG005A_RUNTIME:-0} == 1 ]]; then
    rm -rf "$runtime_root"
  else
    echo "kept runtime at $runtime_root" >&2
  fi
}
trap cleanup EXIT

mkdir -p "$home/init.groovy.d" "$home/plugins" "$repository/src" "$repository/docs" "$evidence"
chmod 755 "$runtime_root" "$home" "$repository"
cp "$fixture_root/init.groovy" "$home/init.groovy.d/10-mig005a.groovy"
cp "$fixture_root/gitconfig" "$home/.gitconfig"
cp -a "$plugin_source/." "$home/plugins/"
cp "$fixture_root/repo/README.initial.md" "$repository/README.md"
podman unshare chown -R 1000:1000 "$home"

git -C "$repository" init --initial-branch=main >/dev/null
git -C "$repository" config user.name 'MIG-005A Fixture'
git -C "$repository" config user.email 'mig005a@example.test'
git -C "$repository" add README.md
git -C "$repository" commit -m 'initial non-matching revision' >/dev/null
revision_1=$(git -C "$repository" rev-parse HEAD)

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
curl --fail --silent --show-error "http://127.0.0.1:${port}/api/json" \
  -o "$evidence/jenkins-controller.json"
curl --fail --silent --show-error -X POST \
  -H 'Content-Type: application/xml' \
  --data-binary "@$fixture_root/job-config.xml" \
  "http://127.0.0.1:${port}/createItem?name=stateful" >/dev/null

run_build() {
  local number=$1
  curl --fail --silent --show-error -X POST \
    "http://127.0.0.1:${port}/job/stateful/build" >/dev/null
  for _ in $(seq 1 180); do
    if curl --fail --silent --show-error \
      "http://127.0.0.1:${port}/job/stateful/${number}/api/json" \
      -o "$evidence/jenkins-build-${number}.json" 2>/dev/null \
      && [[ $(jq -r '.building' "$evidence/jenkins-build-${number}.json") == false ]]; then
      jq --exit-status '.result == "SUCCESS"' \
        "$evidence/jenkins-build-${number}.json" >/dev/null
      return 0
    fi
    sleep 1
  done
  echo "Jenkins build $number did not finish" >&2
  return 1
}

run_build 1
cp "$fixture_root/repo/first.target" "$repository/src/first.target"
git -C "$repository" add src/first.target
git -C "$repository" commit -m 'MIG005A-MATCH first predicate revision' >/dev/null
revision_2=$(git -C "$repository" rev-parse HEAD)
run_build 2

test ! -e "$home/jobs/stateful/builds/1/archive/changeset.intent"
test ! -e "$home/jobs/stateful/builds/1/archive/changelog.intent"
test -f "$home/jobs/stateful/builds/2/archive/changeset.intent"
test -f "$home/jobs/stateful/builds/2/archive/changelog.intent"

cp "$fixture_root/repo/second.target" "$repository/src/second.target"
git -C "$repository" add src/second.target
git -C "$repository" commit -m 'MIG005A-MATCH second predicate revision' >/dev/null
revision_3=$(git -C "$repository" rev-parse HEAD)

if podman run --rm --network "$network" "$image" \
  timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' >/dev/null 2>&1; then
  echo 'private fixture unexpectedly reached the public network' >&2
  exit 1
else
  printf '%s\n' 'public-network-denied' > "$evidence/network-negative.txt"
fi

podman stop --time 30 "$container" >/dev/null
cp "$home/jobs/stateful/config.xml" "$evidence/jenkins-job-config.xml"
cp "$home/jobs/stateful/nextBuildNumber" "$evidence/jenkins-next-build-number.txt"
cp "$home/jobs/stateful/builds/1/build.xml" "$evidence/jenkins-build-1.xml"
cp "$home/jobs/stateful/builds/2/build.xml" "$evidence/jenkins-build-2.xml"
for number in 1 2; do
  changelogs=()
  while IFS= read -r -d '' changelog; do
    changelogs+=("$changelog")
  done < <(find "$home/jobs/stateful/builds/$number" -maxdepth 1 -type f \
    -name 'changelog*.xml' -print0 | sort -z)
  if [[ ${#changelogs[@]} -ne 1 ]]; then
    echo "expected exactly one Jenkins changelog for build $number" >&2
    exit 65
  fi
  cp "${changelogs[0]}" "$evidence/jenkins-build-${number}-changelog.xml"
done
find "$home/jobs/stateful/builds" -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum > "$evidence/jenkins-build-tree.sha256"
find "$home/workspace" -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum > "$evidence/jenkins-workspace-tree.sha256"
podman inspect "$container" > "$evidence/jenkins-container-inspect.json"
podman image inspect "$image" > "$evidence/jenkins-image-inspect.json"

printf '%s\n' "$revision_1" > "$evidence/revision-1.txt"
printf '%s\n' "$revision_2" > "$evidence/revision-2.txt"
printf '%s\n' "$revision_3" > "$evidence/revision-3.txt"
printf '%s\n' "$runtime_root" > "$evidence/runtime-root.txt"

find "$evidence" -type f ! -name SHA256SUMS -printf '%P\0' \
  | sort -z \
  | while IFS= read -r -d '' path; do
      sha256sum "$evidence/$path"
    done > "$evidence/SHA256SUMS"
sha256sum -c "$evidence/SHA256SUMS"
