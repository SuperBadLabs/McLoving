#!/usr/bin/env bash
set -euo pipefail

deny() {
  printf 'release_build_inner_denied: %s\n' "$1" >&2
  exit 1
}

readonly SOURCE_ROOT="/build-src"
readonly OUTPUT_ROOT="/out"
readonly TARGET_ROOT="/target/${MCLOVING_TARGET_TRIPLE}/release"
readonly DIGEST_PATTERN='^[0-9a-f]{64}$'
readonly SHA1_PATTERN='^[0-9a-f]{40}$'

[[ "${MCLOVING_SOURCE_COMMIT}" =~ ${SHA1_PATTERN} && "${MCLOVING_SOURCE_TREE}" =~ ${SHA1_PATTERN} ]] ||
  deny "source identities are invalid"
[[ "${MCLOVING_SOURCE_ARCHIVE_SHA256}" =~ ${DIGEST_PATTERN} ]] || deny "source archive identity is invalid"
[[ "${MCLOVING_BUILDER_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || deny "builder digest is invalid"
[[ "${MCLOVING_BUILDER_IMAGE}" == *@"${MCLOVING_BUILDER_DIGEST}" ]] || deny "builder reference is not digest bound"
[[ "${MCLOVING_WORKFLOW_SHA256}" =~ ${DIGEST_PATTERN} ]] || deny "workflow digest is invalid"
[[ "${MCLOVING_TARGET_TRIPLE}" == "x86_64-unknown-linux-gnu" ]] || deny "target triple is denied"
[[ "${SOURCE_DATE_EPOCH}" =~ ^[1-9][0-9]*$ ]] || deny "source timestamp is invalid"
[[ -d "${SOURCE_ROOT}" && -d "${OUTPUT_ROOT}" && -z "$(find "${OUTPUT_ROOT}" -mindepth 1 -print -quit)" ]] ||
  deny "source or output boundary is invalid"

mkdir -p /cargo-home/registry
if [[ -d /cargo-cache/registry/cache ]]; then
  cp -a /cargo-cache/registry/cache /cargo-home/registry/cache
fi
if [[ -d /cargo-cache/registry/index ]]; then
  cp -a /cargo-cache/registry/index /cargo-home/registry/index
fi
[[ ! -e /cargo-home/credentials && ! -e /cargo-home/credentials.toml ]] ||
  deny "Cargo credentials entered the builder"

cd "${SOURCE_ROOT}"
export LC_ALL=C
export TZ=UTC
export RUSTFLAGS="-C debuginfo=0 -C strip=symbols -C link-arg=-Wl,--build-id=none"
export CARGO_INCREMENTAL=0
cargo +1.97.1 build --locked --offline --release \
  --target "${MCLOVING_TARGET_TRIPLE}" \
  -p mcloving-agent \
  -p mcloving-cli \
  -p mcloving-controller \
  -p mcloving-release-provenance \
  --bin mcloving-agent \
  --bin mcloving-cli \
  --bin mcloving-controller \
  --bin mcloving-release-provenance

install -d -m 0700 "${OUTPUT_ROOT}/components" "${OUTPUT_ROOT}/components/bin"
for binary in mcloving-agent mcloving-cli mcloving-controller; do
  install -m 0700 "${TARGET_ROOT}/${binary}" "${OUTPUT_ROOT}/components/bin/${binary}"
done
install -m 0600 /input/source.tar "${OUTPUT_ROOT}/source.tar"
install -m 0600 "${SOURCE_ROOT}/Cargo.lock" "${OUTPUT_ROOT}/Cargo.lock"

agent_digest="$(sha256sum "${OUTPUT_ROOT}/components/bin/mcloving-agent" | cut -d' ' -f1)"
cli_digest="$(sha256sum "${OUTPUT_ROOT}/components/bin/mcloving-cli" | cut -d' ' -f1)"
controller_digest="$(sha256sum "${OUTPUT_ROOT}/components/bin/mcloving-controller" | cut -d' ' -f1)"
agent_size="$(stat -c '%s' "${OUTPUT_ROOT}/components/bin/mcloving-agent")"
cli_size="$(stat -c '%s' "${OUTPUT_ROOT}/components/bin/mcloving-cli")"
controller_size="$(stat -c '%s' "${OUTPUT_ROOT}/components/bin/mcloving-controller")"
printf '%s' "[{\"path\":\"bin/mcloving-agent\",\"role\":\"agent\",\"sha256\":\"${agent_digest}\",\"size_bytes\":${agent_size},\"executable\":true},{\"path\":\"bin/mcloving-cli\",\"role\":\"cli\",\"sha256\":\"${cli_digest}\",\"size_bytes\":${cli_size},\"executable\":true},{\"path\":\"bin/mcloving-controller\",\"role\":\"controller\",\"sha256\":\"${controller_digest}\",\"size_bytes\":${controller_size},\"executable\":true}]" >"${OUTPUT_ROOT}/components.json"
chmod 0600 "${OUTPUT_ROOT}/components.json"

release_tool="${TARGET_ROOT}/mcloving-release-provenance"
release_tool_digest="$(sha256sum "${release_tool}" | cut -d' ' -f1)"
"${release_tool}" sbom \
  "${OUTPUT_ROOT}/Cargo.lock" \
  "${release_tool_digest}" \
  "${OUTPUT_ROOT}/sbom.json"
"${release_tool}" bundle \
  "${OUTPUT_ROOT}/components" \
  "${OUTPUT_ROOT}/components.json" \
  "${OUTPUT_ROOT}/release.bundle"

{
  rustc +1.97.1 --version --verbose
  cargo +1.97.1 --version --verbose
} >"${OUTPUT_ROOT}/toolchain.txt"
chmod 0600 "${OUTPUT_ROOT}/toolchain.txt"

cargo_lock_digest="$(sha256sum "${OUTPUT_ROOT}/Cargo.lock" | cut -d' ' -f1)"
sbom_digest="$(sha256sum "${OUTPUT_ROOT}/sbom.json" | cut -d' ' -f1)"
bundle_digest="$(sha256sum "${OUTPUT_ROOT}/release.bundle" | cut -d' ' -f1)"
bundle_size="$(stat -c '%s' "${OUTPUT_ROOT}/release.bundle")"
components_digest="$(sha256sum "${OUTPUT_ROOT}/components.json" | cut -d' ' -f1)"
toolchain_digest="$(sha256sum "${OUTPUT_ROOT}/toolchain.txt" | cut -d' ' -f1)"
printf '%s' "{\"schema_version\":\"mcloving.release-build/v1\",\"source_commit_sha1\":\"${MCLOVING_SOURCE_COMMIT}\",\"source_tree_sha1\":\"${MCLOVING_SOURCE_TREE}\",\"source_archive_sha256\":\"${MCLOVING_SOURCE_ARCHIVE_SHA256}\",\"cargo_lock_sha256\":\"${cargo_lock_digest}\",\"builder_image_reference\":\"${MCLOVING_BUILDER_IMAGE}\",\"builder_image_digest\":\"${MCLOVING_BUILDER_DIGEST}\",\"rust_toolchain\":\"1.97.1\",\"rust_toolchain_manifest_sha256\":\"${toolchain_digest}\",\"workflow_sha256\":\"${MCLOVING_WORKFLOW_SHA256}\",\"target_triple\":\"${MCLOVING_TARGET_TRIPLE}\",\"source_date_epoch\":${SOURCE_DATE_EPOCH},\"release_tool_sha256\":\"${release_tool_digest}\",\"components_sha256\":\"${components_digest}\",\"sbom_sha256\":\"${sbom_digest}\",\"bundle_sha256\":\"${bundle_digest}\",\"bundle_size_bytes\":${bundle_size}}" >"${OUTPUT_ROOT}/build-receipt.json"
chmod 0600 "${OUTPUT_ROOT}/build-receipt.json"
