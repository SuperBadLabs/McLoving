#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${repo_root}/tools/versions.env"
if [[ -n "$(git -C "${repo_root}" status --porcelain)" ]]; then
  echo "idle-profile binaries require a clean source checkout" >&2
  exit 2
fi
source_head="$(git -C "${repo_root}" rev-parse HEAD)"
source_tree="$(git -C "${repo_root}" rev-parse 'HEAD^{tree}')"

podman run --rm --network host \
  --env "MCLOVING_BUILD_SOURCE_HEAD=${source_head}" \
  --env "MCLOVING_BUILD_SOURCE_TREE=${source_tree}" \
  --volume "${repo_root}:/work:Z" \
  --workdir /work \
  "${MCLOVING_RUST_IMAGE}" \
  cargo build --locked --release -p mcloving-controller -p mcloving-agent

expected="source_head=${source_head} source_tree=${source_tree}"
for binary in mcloving-controller mcloving-agent; do
  path="${repo_root}/target/release/${binary}"
  provenance="$("${path}" build-provenance)"
  if [[ "${provenance}" != "${expected}" ]]; then
    echo "${binary} build provenance mismatch: ${provenance}" >&2
    exit 1
  fi
  sha256sum "${path}"
done
