#!/usr/bin/env bash
# Build the contained browser image for the UI-002 gate, fail-closed.
#
# Every input is pinned in browser-pin.json and verified here before it reaches
# the build context, so the Containerfile itself downloads nothing. A digest
# mismatch is a hard refusal, never a warning: the whole point of the pin is
# that an archive which changed under us must not silently become the browser
# the gate's evidence was captured with.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pin="${script_dir}/browser-pin.json"

for required in podman python3 curl sha256sum; do
  if ! command -v "${required}" >/dev/null 2>&1; then
    printf 'required command is missing: %s\n' "${required}" >&2
    exit 69
  fi
done

read_pin() {
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."): d=d[key]
print(d)' "${pin}" "$1"
}

image="$(read_pin image_tag)"
base_reference="$(read_pin base_image.reference)"
base_digest="$(read_pin base_image.manifest_digest)"
base_image_id="$(read_pin base_image.image_id)"

# The recipe digest covers the Containerfile itself, not just the pinned
# downloads. Without it an edit to the Containerfile leaves a stale image that
# still carries matching browser digests, and the gate silently runs against a
# browser environment the repository no longer describes.
recipe_digest="$(sha256sum "${script_dir}/Containerfile" | awk '{print $1}')"

# A cached image is only reusable if it was built from this exact pin and this
# exact recipe. The tag carries the Chrome version, but the tag is not evidence,
# so re-check the labels the Containerfile stamped.
if podman image exists "${image}"; then
  cached_chrome="$(podman image inspect "${image}" \
    --format '{{index .Labels "io.mcloving.ui.chrome.sha256"}}')"
  cached_driver="$(podman image inspect "${image}" \
    --format '{{index .Labels "io.mcloving.ui.chromedriver.sha256"}}')"
  cached_recipe="$(podman image inspect "${image}" \
    --format '{{index .Labels "io.mcloving.ui.recipe.sha256"}}')"
  if [[ "${cached_chrome}" == "$(read_pin downloads.chrome.sha256)" &&
        "${cached_driver}" == "$(read_pin downloads.chromedriver.sha256)" &&
        "${cached_recipe}" == "${recipe_digest}" ]]; then
    printf 'Contained browser image already built from this pin: %s\n' "${image}"
    exit 0
  fi
  printf 'cached image %s was built from a different pin or recipe; rebuilding\n' \
    "${image}" >&2
fi

# The download cache is keyed by digest, so a second run of the gate on the same
# host re-verifies rather than re-fetches ~200MB.
cache="${MCLOVING_BROWSER_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/mcloving-ui-browser}"
mkdir -p "${cache}"

context="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-ui-browser-build.XXXXXXXX")"
cleanup() {
  rm -rf -- "${context}"
}
trap cleanup EXIT

for component in chrome chromedriver; do
  url="$(read_pin "downloads.${component}.url")"
  expected="$(read_pin "downloads.${component}.sha256")"
  archive="${cache}/${component}-${expected}.zip"
  if [[ ! -f "${archive}" ]]; then
    printf 'Fetching pinned %s\n' "${component}" >&2
    curl --fail --silent --show-error --location --max-time 600 \
      --output "${archive}.partial" "${url}"
    mv -- "${archive}.partial" "${archive}"
  fi
  actual="$(sha256sum "${archive}" | awk '{print $1}')"
  if [[ "${actual}" != "${expected}" ]]; then
    printf '%s digest mismatch: expected %s, got %s\n' \
      "${component}" "${expected}" "${actual}" >&2
    # A mismatched archive must not survive to be trusted by a later run.
    rm -f -- "${archive}"
    exit 66
  fi
  cp -- "${archive}" "${context}/${component}-linux64.zip"
done

printf 'Pulling pinned base image\n' >&2
podman pull --quiet "${base_reference}@${base_digest}" >/dev/null
actual_base_id="$(podman image inspect "${base_reference}@${base_digest}" \
  --format '{{.Id}}')"
actual_base_id="${actual_base_id#sha256:}"
if [[ "${actual_base_id}" != "${base_image_id}" ]]; then
  printf 'base image identity mismatch: expected %s, got %s\n' \
    "${base_image_id}" "${actual_base_id}" >&2
  exit 66
fi

# The label has to carry the digest of the Containerfile as written in the
# repository, so stamp it into the copy rather than hashing the copy.
sed -e "s/RECIPE_DIGEST_PLACEHOLDER/${recipe_digest}/" \
  -- "${script_dir}/Containerfile" >"${context}/Containerfile"
if grep -Fq RECIPE_DIGEST_PLACEHOLDER "${context}/Containerfile"; then
  printf 'Containerfile recipe digest placeholder was not substituted\n' >&2
  exit 66
fi
podman build --tag "${image}" --file "${context}/Containerfile" "${context}"

printf 'Contained browser image built: %s\n' "${image}"
