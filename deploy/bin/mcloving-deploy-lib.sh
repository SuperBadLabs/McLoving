# Shared helpers for mcloving-install / mcloving-upgrade / mcloving-rollback.
# Sourced, not executed. Requires: bash, sha256sum, python3.
# shellcheck shell=bash

MCLOVING_DEPLOY_BINARIES=(
  mcloving-controller
  mcloving-agent
  mcloving-cli
  mcloving-identity-admin
)

deploy_fail() {
  echo "$(basename "$0"): $1" >&2
  exit 1
}

# verify_release_dir RELEASE_DIR (MANIFEST|"") (CHECKSUMS|"")
#
# Fail-closed digest verification of every deployed binary. Exactly one
# verification source must be provided:
#
#   MANIFEST   a release-provenance document: either the SignedReleaseEnvelope
#              JSON or the bare ReleaseManifest JSON (schema
#              mcloving.release-manifest via REL-001). Component digests and
#              sizes are read from manifest.components[]. NOTE: this checks
#              artifact digests only; it does not verify the Ed25519 release
#              signature or the transparency chain (use
#              mcloving-release-provenance verify-chain for that). The gap is
#              deliberate and documented in docs/operations/DEPLOYMENT_V1.md.
#
#   CHECKSUMS  an operator-supplied `sha256sum` format file with one line per
#              deployed binary.
verify_release_dir() {
  local release_dir="$1" manifest="$2" checksums="$3" binary
  [[ -d "${release_dir}" ]] || deploy_fail "release directory ${release_dir} does not exist"
  if [[ -n "${manifest}" && -n "${checksums}" ]]; then
    deploy_fail "provide either --manifest or --checksums, not both"
  fi
  if [[ -z "${manifest}" && -z "${checksums}" ]]; then
    deploy_fail "digest verification is mandatory: provide --manifest or --checksums"
  fi
  for binary in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
    [[ -f "${release_dir}/${binary}" ]] || deploy_fail "release directory is missing ${binary}"
  done
  if [[ -n "${manifest}" ]]; then
    [[ -f "${manifest}" ]] || deploy_fail "manifest ${manifest} does not exist"
    python3 - "${manifest}" "${release_dir}" "${MCLOVING_DEPLOY_BINARIES[@]}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest_path, release_dir, *binaries = sys.argv[1:]
document = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
manifest = document.get("manifest", document)
components = {
    Path(component["path"]).name: component
    for component in manifest["components"]
}
failures = []
for binary in binaries:
    component = components.get(binary)
    if component is None:
        failures.append(f"{binary}: not listed in manifest components")
        continue
    payload = (Path(release_dir) / binary).read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != component["sha256"]:
        failures.append(
            f"{binary}: sha256 {digest} != manifest {component['sha256']}"
        )
    elif len(payload) != component["size_bytes"]:
        failures.append(
            f"{binary}: size {len(payload)} != manifest {component['size_bytes']}"
        )
if failures:
    for failure in failures:
        print(f"digest verification failed: {failure}", file=sys.stderr)
    raise SystemExit(1)
print(f"verified {len(binaries)} binaries against manifest {manifest_path}")
PY
  else
    [[ -f "${checksums}" ]] || deploy_fail "checksums file ${checksums} does not exist"
    local resolved_checksums
    resolved_checksums="$(cd "$(dirname "${checksums}")" && pwd)/$(basename "${checksums}")"
    for binary in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
      grep -Eq "^[0-9a-f]{64}[[:space:]]+\*?${binary}\$" "${resolved_checksums}" \
        || deploy_fail "checksums file has no entry for ${binary}"
    done
    (
      cd "${release_dir}"
      sha256sum --check --strict --ignore-missing "${resolved_checksums}" >/dev/null
    ) || deploy_fail "sha256 verification against ${checksums} failed"
    echo "verified ${#MCLOVING_DEPLOY_BINARIES[@]} binaries against checksums ${checksums}"
  fi
}

# release_id RELEASE_DIR -> deterministic 12-hex id over the binary digests
release_id() {
  local release_dir="$1" binary
  for binary in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
    sha256sum "${release_dir}/${binary}" | awk '{print $1}'
  done | sha256sum | awk '{print substr($1, 1, 12)}'
}

# stage_release LIBEXEC_ROOT RELEASE_DIR RELEASE_ID
stage_release() {
  local libexec_root="$1" release_dir="$2" id="$3" binary target
  target="${libexec_root}/releases/${id}"
  mkdir -p "${target}"
  for binary in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
    install -m 0755 "${release_dir}/${binary}" "${target}/${binary}"
  done
  # Retain the verified digests beside the release. Installation is the only
  # point at which these binaries are known to match the manifest, so rollback
  # has nothing else to check a staged release against.
  (
    cd "${target}" || exit 1
    sha256sum "${MCLOVING_DEPLOY_BINARIES[@]}" > SHA256SUMS
  )
  chmod 0444 "${target}/SHA256SUMS"
  echo "${target}"
}

# verify_staged_release RELEASE_PATH
#
# Recomputes every binary digest against the checksums retained at
# installation. A staged release is writable by the service user, so
# "still executable" is not evidence that it is the release that was verified.
verify_staged_release() {
  local release_path="$1"
  [[ -f "${release_path}/SHA256SUMS" ]] \
    || deploy_fail "release ${release_path} has no retained checksums; refusing to use it"
  (
    cd "${release_path}" || exit 1
    sha256sum --quiet --check SHA256SUMS
  ) || deploy_fail "release ${release_path} does not match its retained checksums"
}

# point_symlink LINK TARGET (atomic replace)
point_symlink() {
  local link="$1" target="$2" staging
  staging="${link}.staging.$$"
  ln -s "${target}" "${staging}"
  mv -T "${staging}" "${link}"
}

# stop/start service helpers honoring --no-systemd
service_control() {
  local no_systemd="$1" action="$2" unit="$3"
  if [[ "${no_systemd}" == "1" ]]; then
    echo "skipping systemctl --user ${action} ${unit} (--no-systemd)"
    return 0
  fi
  systemctl --user "${action}" "${unit}"
}
