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

# Parse systemd's environment-file grammar without executing it. Sourcing
# would let a value that is literal to systemd — an unquoted token containing
# `&`, `$`, or a space — fork jobs, run commands, and expand variables as the
# service user. Shared by every helper that reads a contract file so the two
# cannot diverge.
#
# Emits NUL-separated name/value pairs so no value can be mistaken for a
# delimiter.
parse_environment_file() {
  python3 - "$1" <<'PARSE'
import sys

# systemd's EnvironmentFile= grammar, not Bash's. A value is a concatenation of
# unquoted runs, single-quoted runs, and double-quoted runs, so
# `/tmp/'agent key.pem'` is the single value `/tmp/agent key.pem` — stripping
# only fully surrounding quotes would keep the quote characters and reject a
# valid contract. Backslash continues a line; inside double quotes and
# unquoted runs it also escapes the next character. Single quotes are literal.

path = sys.argv[1]
out = sys.stdout.buffer


def parse_value(text, handle):
    result = []
    index = 0
    while True:
        while index < len(text):
            char = text[index]
            if char == "\\":
                if index + 1 == len(text):
                    # Line continuation: pull the next physical line.
                    following = handle.readline()
                    if not following:
                        raise SystemExit("environment file ends with a continuation")
                    text = following.rstrip("\n")
                    index = 0
                    break
                result.append(text[index + 1])
                index += 2
                continue
            if char == "'":
                # A single-quoted value may span physical lines, exactly as the
                # double-quoted branch below allows. Reporting an unterminated
                # quote here would refuse a contract systemd loads happily and
                # stop the service at ExecStartPre.
                index += 1
                while True:
                    closing = text.find("'", index)
                    if closing != -1:
                        result.append(text[index:closing])
                        index = closing + 1
                        break
                    result.append(text[index:])
                    following = handle.readline()
                    if not following:
                        raise SystemExit("unterminated single quote")
                    result.append("\n")
                    text = following.rstrip("\n")
                    index = 0
                continue
            if char == '"':
                index += 1
                while True:
                    if index >= len(text):
                        following = handle.readline()
                        if not following:
                            raise SystemExit("unterminated double quote")
                        text += "\n" + following.rstrip("\n")
                        continue
                    char = text[index]
                    if char == "\\":
                        if index + 1 >= len(text):
                            # Backslash-newline continues the line and produces
                            # nothing, as it does outside quotes.
                            following = handle.readline()
                            if not following:
                                raise SystemExit("unterminated double quote")
                            text = following.rstrip("\n")
                            index = 0
                            continue
                        following_char = text[index + 1]
                        # systemd only treats a backslash as an escape before a
                        # character that is special inside double quotes.
                        # Anything else keeps the backslash, so a path such as
                        # "/tmp/key\\q.pem" survives intact rather than losing it.
                        if following_char in ('"', "\\", "$", "`"):
                            result.append(following_char)
                        else:
                            result.append(char)
                            result.append(following_char)
                        index += 2
                        continue
                    if char == '"':
                        index += 1
                        break
                    result.append(char)
                    index += 1
                continue
            result.append(char)
            index += 1
        else:
            return "".join(result).strip() if not result else "".join(result)


with open(path, "r", encoding="utf-8") as handle:
    while True:
        raw = handle.readline()
        if not raw:
            break
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        name, separator, value = line.partition("=")
        if not separator:
            sys.stderr.write("environment file line is not NAME=VALUE\n")
            raise SystemExit(1)
        name = name.strip()
        out.write(name.encode() + b"\0" + parse_value(value.strip(), handle).encode() + b"\0")
PARSE
}

# load_environment_file ENV_FILE — export the parsed contract.
load_environment_file() {
  local name value
  while IFS= read -r -d '' name && IFS= read -r -d '' value; do
    printf -v "${name}" '%s' "${value}"
    export "${name?}"
  done < <(parse_environment_file "$1")
}

# stage_release LIBEXEC_ROOT RELEASE_DIR MANIFEST CHECKSUMS
#
# Copies the release, verifies the copy against the operator-supplied digest
# source, and only then publishes it under the identity of those exact bytes.
#
# The verification has to run against the staged copy, not the source. Anything
# derived from the source — including its identity — describes whatever the
# source holds at the moment it is read, so a source that changes after
# verification would simply be re-measured and agree with itself. The manifest
# or checksums file is the only fixed reference here, so that is what the
# copied bytes are checked against. Echoes the published path.
stage_release() {
  local libexec_root="$1" release_dir="$2" manifest="$3" checksums="$4"
  local binary target staging id
  mkdir -p "${libexec_root}/releases"
  staging="${libexec_root}/releases/.staging.$$"
  rm -rf "${staging}"
  mkdir -p "${staging}"
  for binary in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
    install -m 0755 "${release_dir}/${binary}" "${staging}/${binary}"
  done
  if ! verify_release_dir "${staging}" "${manifest}" "${checksums}"; then
    rm -rf "${staging}"
    deploy_fail "staged copy does not match the supplied digest source"
  fi
  id="$(release_id "${staging}")"
  target="${libexec_root}/releases/${id}"
  if [[ -d "${target}" ]]; then
    rm -rf "${staging}"
    verify_staged_release "${target}"
  else
    mv -T "${staging}" "${target}"
  fi
  echo "${target}"
}

# verify_staged_release RELEASE_PATH
#
# Recomputes the release identity from the binaries and requires it to equal
# the directory name assigned at installation. "Still executable" is not
# evidence that a staged release is the one that was verified against the
# manifest.
#
# The identity is the check rather than a retained checksum file, because such
# a file lives beside the binaries under the same ownership and can simply be
# rewritten; binding to the install-time name leaves no in-place side channel.
# This detects corruption, partial writes, and in-place substitution. It is not
# a defence against a compromised service user, which can rewrite anything it
# owns — see the isolation boundary recorded in docs/operations/DEPLOYMENT_V1.md.
verify_staged_release() {
  local release_path="$1" expected actual
  expected="$(basename "${release_path}")"
  for binary in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
    [[ -f "${release_path}/${binary}" ]] \
      || deploy_fail "release ${release_path} is missing ${binary}"
  done
  actual="$(release_id "${release_path}")"
  [[ "${actual}" == "${expected}" ]] \
    || deploy_fail "release ${release_path} has identity ${actual}, not ${expected}; refusing to use it"
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
