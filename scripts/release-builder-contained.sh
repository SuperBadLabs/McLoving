#!/usr/bin/env bash
set -euo pipefail

readonly BUILDER_IMAGE="docker.io/library/rust:1.97.1-bookworm@sha256:408fe88047cef61a2087653b0c5255fa51c0f2d6d94ddedd7a2562a9b91a46f6"
readonly BUILDER_DIGEST="sha256:408fe88047cef61a2087653b0c5255fa51c0f2d6d94ddedd7a2562a9b91a46f6"
readonly TARGET_TRIPLE="x86_64-unknown-linux-gnu"

deny() {
  printf 'release_builder_denied: %s\n' "$1" >&2
  exit 1
}

if [[ $# -ne 3 ]]; then
  deny "usage: release-builder-contained.sh ABSOLUTE_CLEAN_SOURCE ABSOLUTE_NEW_OUTPUT ABSOLUTE_CARGO_CACHE"
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  deny "the production builder requires a Linux Docker host"
fi

source_root="$1"
output_root="$2"
cargo_cache="$3"
[[ "${source_root}" == /* && "${output_root}" == /* && "${cargo_cache}" == /* ]] ||
  deny "every path must be absolute"
[[ ! -L "${source_root}" && ! -L "${cargo_cache}" ]] || deny "source and cache roots cannot be symlinks"
source_root_canonical="$(realpath -e -- "${source_root}")"
cargo_cache_canonical="$(realpath -e -- "${cargo_cache}")"
[[ "${source_root}" == "${source_root_canonical}" && -d "${source_root}" ]] ||
  deny "source root must be a canonical directory"
[[ "${cargo_cache}" == "${cargo_cache_canonical}" && -d "${cargo_cache}/registry" ]] ||
  deny "Cargo cache must be canonical and contain registry metadata"
[[ ! -e "${output_root}" && ! -L "${output_root}" ]] || deny "output root already exists"
output_parent="$(dirname -- "${output_root}")"
output_name="$(basename -- "${output_root}")"
output_parent_canonical="$(realpath -e -- "${output_parent}")"
[[ "${output_parent}" == "${output_parent_canonical}" && "${output_name}" != "." && "${output_name}" != ".." ]] ||
  deny "output parent and name must be canonical"

git -C "${source_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1 || deny "source is not a Git worktree"
[[ "$(git -C "${source_root}" rev-parse --show-toplevel)" == "${source_root}" ]] ||
  deny "source must be the worktree root"
[[ -z "$(git -C "${source_root}" status --porcelain=v1 --untracked-files=all)" ]] ||
  deny "source worktree is not clean"

source_commit="$(git -C "${source_root}" rev-parse --verify 'HEAD^{commit}')"
source_tree="$(git -C "${source_root}" rev-parse --verify 'HEAD^{tree}')"
source_date_epoch="$(git -C "${source_root}" show -s --format=%ct "${source_commit}")"
[[ "${source_commit}" =~ ^[0-9a-f]{40}$ && "${source_tree}" =~ ^[0-9a-f]{40}$ ]] ||
  deny "source identities are not lowercase SHA-1 object IDs"
[[ "${source_date_epoch}" =~ ^[1-9][0-9]*$ ]] || deny "source timestamp is invalid"

outer_digest="$(sha256sum "${source_root}/scripts/release-builder-contained.sh" | cut -d' ' -f1)"
inner_digest="$(sha256sum "${source_root}/scripts/release-build-inner.sh" | cut -d' ' -f1)"
workflow_digest="$(printf 'mcloving-release-workflow-v1\0%s\0%s\n' "${outer_digest}" "${inner_digest}" | sha256sum | cut -d' ' -f1)"

scratch_root="$(mktemp -d /tmp/mcloving-release-builder.XXXXXX)"
archive_path="${scratch_root}/source.tar"
cleanup() {
  rm -rf -- "${scratch_root}"
}
trap cleanup EXIT
git -C "${source_root}" archive --format=tar --output="${archive_path}" "${source_commit}"
source_archive_digest="$(sha256sum "${archive_path}" | cut -d' ' -f1)"

umask 077
mkdir -m 0700 -- "${output_root}"
docker image inspect "${BUILDER_IMAGE}" >/dev/null 2>&1 ||
  deny "the exact pinned builder image is not present; pull it out of band by digest"

docker run --rm --pull never --platform linux/amd64 \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --security-opt apparmor=docker-default \
  --pids-limit 512 \
  --memory 8g \
  --cpus 4 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /build-src:rw,nosuid,nodev,noexec,size=256m,mode=0700,uid="$(id -u)",gid="$(id -g)" \
  --tmpfs /cargo-home:rw,exec,nosuid,nodev,size=2g,mode=0700,uid="$(id -u)",gid="$(id -g)" \
  --tmpfs /target:rw,exec,nosuid,nodev,size=8g,mode=0700,uid="$(id -u)",gid="$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --mount "type=bind,src=${scratch_root},dst=/input,readonly" \
  --mount "type=bind,src=${cargo_cache}/registry,dst=/cargo-cache/registry,readonly" \
  --mount "type=bind,src=${output_root},dst=/out" \
  --env CARGO_HOME=/cargo-home \
  --env CARGO_NET_OFFLINE=true \
  --env SOURCE_DATE_EPOCH="${source_date_epoch}" \
  --env MCLOVING_SOURCE_COMMIT="${source_commit}" \
  --env MCLOVING_SOURCE_TREE="${source_tree}" \
  --env MCLOVING_SOURCE_ARCHIVE_SHA256="${source_archive_digest}" \
  --env MCLOVING_BUILDER_IMAGE="${BUILDER_IMAGE}" \
  --env MCLOVING_BUILDER_DIGEST="${BUILDER_DIGEST}" \
  --env MCLOVING_WORKFLOW_SHA256="${workflow_digest}" \
  --env MCLOVING_TARGET_TRIPLE="${TARGET_TRIPLE}" \
  "${BUILDER_IMAGE}" \
  /bin/bash -c 'tar -xf /input/source.tar -C /build-src && exec /bin/bash /build-src/scripts/release-build-inner.sh'

expected_files="$(find "${output_root}" -mindepth 1 -type f -printf '%P\n' | LC_ALL=C sort)"
[[ "${expected_files}" == $'Cargo.lock\nbuild-receipt.json\ncomponents.json\ncomponents/bin/mcloving-agent\ncomponents/bin/mcloving-cli\ncomponents/bin/mcloving-controller\nrelease.bundle\nsbom.json\nsource.tar\ntoolchain.txt' ]] ||
  deny "builder emitted an unexpected release file set"
[[ -z "$(find "${output_root}" -type l -print -quit)" ]] || deny "builder emitted a symlink"
printf 'release_builder_complete source=%s tree=%s bundle=%s\n' \
  "${source_commit}" \
  "${source_tree}" \
  "$(sha256sum "${output_root}/release.bundle" | cut -d' ' -f1)"
