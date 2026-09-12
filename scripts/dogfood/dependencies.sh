#!/usr/bin/env bash
# Foundation `dependencies`: `cargo deny check` with the cargo-deny release
# the repository pins (the lane uses the cargo-deny action at the same
# version; here the release archive is fetched once and verified against
# tools/versions.env).
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
dogfood_lane dependencies
cache="${HOME}/.cache/mcloving-dogfood"
mkdir -p "${cache}"
archive="${cache}/cargo-deny-${CARGO_DENY_VERSION}.tar.gz"
if [ ! -f "${archive}" ] || ! printf '%s  %s\n' "${CARGO_DENY_SHA256}" "${archive}" | sha256sum -c - >/dev/null 2>&1; then
  curl --fail --location --silent --show-error \
    "https://github.com/EmbarkStudios/cargo-deny/releases/download/${CARGO_DENY_VERSION}/cargo-deny-${CARGO_DENY_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
    --output "${archive}.part"
  printf '%s  %s\n' "${CARGO_DENY_SHA256}" "${archive}.part" | sha256sum -c -
  mv "${archive}.part" "${archive}"
fi
tool_dir="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-dogfood-cargo-deny.XXXXXX")"
trap 'rm -rf -- "${tool_dir}"' EXIT
tar -xzf "${archive}" -C "${tool_dir}" --strip-components=1
"${tool_dir}/cargo-deny" --version
"${tool_dir}/cargo-deny" check
