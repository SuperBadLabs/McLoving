# Shared helpers for mcloving-install / mcloving-upgrade / mcloving-rollback.
# Sourced, not executed. Requires: bash, sha256sum, python3.
# shellcheck shell=bash

# The constrained runtime login. Store::preflight_tenant_runtime refuses any
# other session role, so the guard must require this exact name rather than
# merely a name different from the migration role.
# shellcheck disable=SC2034  # read by mcloving-env-guard, which sources this
MCLOVING_RUNTIME_ROLE="mcloving_tenant"

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

# release_dir_is_complete RELEASE_DIR — every deployed binary is present.
#
# A cheap precondition for computing a prospective release id from a source
# directory. It is not verification: verify_release_dir does that against the
# staged copy.
release_dir_is_complete() {
  local release_dir="$1" binary
  for binary in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
    [[ -f "${release_dir}/${binary}" ]] || return 1
  done
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

# systemd's WHITESPACE set, exactly. Python's str.isspace() and str.strip()
# also treat U+00A0, U+2028 and others as whitespace, so using them would trim
# characters systemd keeps — the guard would then validate a different value
# from the one the service receives.
WHITESPACE = " \t\n\r\v\f"


def parse_value(text, handle):
    # `protected` marks characters that were quoted or escaped, so trailing
    # whitespace can be trimmed only where it is syntactically insignificant.
    # Stripping the raw text first would destroy an escaped trailing space and
    # leave a dangling backslash, disagreeing with what systemd loads.
    result = []
    protected = []
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
                protected.append(True)
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
                        protected.append(True)
                        index = closing + 1
                        break
                    result.append(text[index:])
                    protected.append(True)
                    following = handle.readline()
                    if not following:
                        raise SystemExit("unterminated single quote")
                    result.append("\n")
                    protected.append(True)
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
                            protected.append(True)
                        else:
                            result.append(char)
                            protected.append(True)
                            result.append(following_char)
                            protected.append(True)
                        index += 2
                        continue
                    if char == '"':
                        index += 1
                        break
                    result.append(char)
                    protected.append(True)
                    index += 1
                continue
            result.append(char)
            protected.append(False)
            index += 1
        else:
            # Trim only whitespace that is neither quoted nor escaped.
            text_out = "".join(result)
            # One flag per appended chunk, expanded to per-character here.
            # Anything else silently misaligns the two lists and misclassifies
            # every character after the first multi-character run.
            if len(result) != len(protected):
                raise SystemExit("internal parser error: protection flags misaligned")
            flags = []
            for chunk, guard in zip(result, protected):
                flags.extend([guard] * len(chunk))
            end = len(text_out)
            while end > 0 and text_out[end - 1] in WHITESPACE and not flags[end - 1]:
                end -= 1
            start = 0
            while start < end and text_out[start] in WHITESPACE and not flags[start]:
                start += 1
            return text_out[start:end]


with open(path, "r", encoding="utf-8") as handle:
    while True:
        raw = handle.readline()
        if not raw:
            break
        # Only the newline is removed. Stripping the line would delete an
        # escaped trailing space before the parser could see it was escaped,
        # leaving a dangling backslash that reads as a line continuation.
        probe = raw.strip(WHITESPACE)
        if not probe or probe.startswith("#") or probe.startswith(";"):
            continue
        line = raw.rstrip("\n")
        name, separator, value = line.partition("=")
        if not separator:
            sys.stderr.write("environment file line is not NAME=VALUE\n")
            raise SystemExit(1)
        name = name.strip(WHITESPACE)
        out.write(name.encode() + b"\0" + parse_value(value, handle).encode() + b"\0")
PARSE
}

# database_url_role URL -> the role a PostgreSQL URL authenticates as.
#
# Compares roles rather than URL text, so two spellings of one role do not read
# as two roles.
database_url_role() {
  python3 - "$1" <<'ROLE'
import sys
from urllib.parse import unquote, urlsplit

url = sys.argv[1]
if not url:
    raise SystemExit(0)
parts = urlsplit(url)
if parts.username:
    print(unquote(parts.username))
ROLE
}

# load_environment_file ENV_FILE — parse the contract into MCLOVING_CONTRACT.
#
# The values are deliberately not assigned to shell variables. Bash is
# dynamically scoped, so `printf -v` on a contract-supplied name can overwrite
# a caller's own control variable: a file containing `service=postgres` would
# rewrite the guard's dispatch selector and validate the wrong service
# entirely. An associative array keyed by name has no such reach, and
# `contract_value` is the only way to read one.
declare -gA MCLOVING_CONTRACT=()

load_environment_file() {
  local name value parsed status
  # The parser's exit status has to be checked before any value is accepted.
  # Reading directly from a process substitution discards it, so a file that
  # parses partially — its required assignments emitted, then a malformed line
  # — would fill the map, report success, and defeat the fail-closed contract
  # this guard exists to enforce. A temporary file is used because values may
  # contain NUL separators, which command substitution strips.
  parsed="$(mktemp)" || deploy_fail "cannot create a temporary file for the contract"
  status=0
  parse_environment_file "$1" > "${parsed}" || status=$?
  if [[ "${status}" -ne 0 ]]; then
    rm -f "${parsed}"
    deploy_fail "environment file $1 could not be parsed"
  fi
  MCLOVING_CONTRACT=()
  while IFS= read -r -d '' name && IFS= read -r -d '' value; do
    MCLOVING_CONTRACT["${name}"]="${value}"
  done < "${parsed}"
  rm -f "${parsed}"
}

# contract_value NAME — the parsed value, or empty when unset.
#
# Command substitution strips every trailing newline from what it captures, so
# `$(contract_value X)` cannot reproduce a value that ends in one. systemd
# accepts such values from a quoted multiline assignment and passes them to the
# service intact, which means a guard reading through `$( )` would validate
# `/tmp/key.pem` while the service receives `/tmp/key.pem\n` — a contract
# reported satisfied that the binary then refuses. Use `contract_into` for any
# check whose verdict must describe the exact bytes systemd supplies.
contract_value() {
  printf '%s' "${MCLOVING_CONTRACT[$1]-}"
}

# contract_into VARNAME NAME — assign the parsed value, trailing newlines and
# all, to VARNAME.
contract_into() {
  local -n __mcloving_contract_target="$1"
  __mcloving_contract_target="${MCLOVING_CONTRACT[$2]-}"
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
  # verify_release_dir calls deploy_fail on several paths, and deploy_fail
  # exits. In command substitution that ends the subshell immediately, so an
  # explicit rm after the call is unreachable for exactly the failures that
  # matter. Without this trap a refused install leaves unverified binaries
  # under releases/.staging.*, which the deployed-digest re-read then reports
  # as part of the release inventory even though nothing was published.
  # The path is rendered with %q rather than wrapped in quotes: a home
  # containing a single quote -- /tmp/o'h is a valid directory -- would
  # otherwise produce a trap body that does not parse, and the cleanup this
  # exists for would be lost for exactly the alternate-home paths that need it.
  # shellcheck disable=SC2064  # expand the path now; the variable is reassigned
  trap "rm -rf -- $(printf '%q' "${staging}")" EXIT
  for binary in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
    # Checked before the copy, because the copy is what gets hurt. `install`
    # reading a FIFO blocks until something writes to it, and reading a device
    # such as a symlinked /dev/zero fills the disk -- both before
    # verify_release_dir ever sees the bytes. `-f` is true only for a regular
    # file and follows symlinks, so it rejects both while still admitting a
    # symlinked release directory.
    [[ -f "${release_dir}/${binary}" ]] \
      || deploy_fail "release ${release_dir} does not provide ${binary} as a regular file"
    install -m 0755 "${release_dir}/${binary}" "${staging}/${binary}"
  done
  if ! verify_release_dir "${staging}" "${manifest}" "${checksums}"; then
    deploy_fail "staged copy does not match the supplied digest source"
  fi
  id="$(release_id "${staging}")"
  target="${libexec_root}/releases/${id}"
  if [[ -d "${target}" ]]; then
    # The release is already published, so the copy just made is redundant.
    # Removing it here rather than leaving it to the trap matters because the
    # trap is cleared before this function returns: otherwise reinstalling the
    # current release, or upgrading back to a previously staged one, leaves
    # releases/.staging.$$ behind and the digest re-read reports those
    # duplicate binaries as release inventory.
    rm -rf -- "${staging}"
    verify_staged_release "${target}"
  else
    # Both callers run this function inside command substitution, and bash
    # clears errexit inside one, so a failed publication would fall through to
    # the echo below and report success. An upgrade would then stop the
    # services and point `current` at whatever is actually sitting at that
    # path -- a regular file, a dangling link -- producing an outage while
    # announcing that the release was staged.
    if ! mv -T "${staging}" "${target}"; then
      deploy_fail "could not publish the staged release at ${target}"
    fi
  fi
  # Both callers use command substitution, so the trap would die with the
  # subshell anyway; clearing it keeps the function safe to call directly.
  trap - EXIT
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
    # Executable, not merely present with the right bytes. Identical content
    # with the execute bits stripped passes a digest check and cannot be run,
    # so reinstalling such a release would report completion over binaries the
    # services cannot start, and upgrading back to one costs an outage that
    # only startup discovers. mcloving-rollback already requires this of the
    # release it is about to make current.
    [[ -f "${release_path}/${binary}" ]] \
      || deploy_fail "release ${release_path} is missing ${binary}"
    [[ -x "${release_path}/${binary}" ]] \
      || deploy_fail "release ${release_path} has ${binary} without execute permission; refusing to use it"
  done
  actual="$(release_id "${release_path}")"
  [[ "${actual}" == "${expected}" ]] \
    || deploy_fail "release ${release_path} has identity ${actual}, not ${expected}; refusing to use it"
}

# point_symlink LINK TARGET (atomic replace)
# account_home -> the home directory systemd expands %h to.
#
# From the passwd database for the effective uid, never from HOME. HOME is set
# by whoever invoked this script, so comparing --home against it compares two
# copies of the same caller-controlled value and always agrees, while the user
# manager keeps expanding %h to the account's real home. An install could then
# write a whole deployment under one tree while daemon-reload and every later
# service operation acted on units pointing at another.
account_home() {
  getent passwd "$(id -u)" | cut -d: -f6
}

# require_systemd_home HOME_DIR NO_SYSTEMD
#
# Refuse to drive systemd for a tree its units do not describe.
require_systemd_home() {
  local home_dir="$1" no_systemd="$2" resolved
  [[ "${no_systemd}" == "1" ]] && return 0
  resolved="$(account_home)"
  [[ -n "${resolved}" ]] || deploy_fail \
    "cannot read the service account home from the passwd database; pass --no-systemd"
  [[ "${home_dir}" == "${resolved}" ]] || deploy_fail \
    "--home ${home_dir} is not the service account home ${resolved}; systemd units resolve %h there, so pass --no-systemd for an alternate tree"
}

# recovery_command LIBEXEC_ROOT HOME_DIR
#
# The exact shell command that re-reads the deployed digests and then rolls
# back, ready to copy and run.
#
# Absolute paths, because nothing adds deploy/bin to PATH and a bare command
# name would resolve to nothing exactly when recovery is needed. Every argument
# is rendered with %q, because this text is meant to be pasted into a shell: a
# service account home containing a space or a shell metacharacter would
# otherwise split the path or execute part of it, and the one moment this line
# exists for is the moment an operator cannot afford to debug it.
recovery_command() {
  local libexec_root="$1" home_dir="$2" rendered
  printf -v rendered '%q --home %q; %q --home %q' \
    "${libexec_root}/helpers/mcloving-deployed-digests" "${home_dir}" \
    "${libexec_root}/helpers/mcloving-rollback" "${home_dir}"
  printf '%s' "${rendered}"
}

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

# require_service_stable NO_SYSTEMD UNIT [SAMPLES]
#
# A successful `systemctl start` means the manager reached the started state.
# For Type=exec that state is the successful exec, not a process that is still
# running: a binary that execs and then exits -- a shared library that only
# resolves at first use, a contract the guard admits but the binary refuses --
# leaves Restart=on-failure cycling behind a start that reported success. The
# agent's health gate reads its journal, and an intact journal says nothing
# about whether anything is still accepting work, so without this the upgrade
# reports "complete and healthy" over a unit that is restarting in a loop.
#
# The window spans more than two RestartSec intervals (2s in the shipped
# units), so a unit that is cycling is observed either mid-restart or under a
# main PID that has changed. Both are refusals.
require_service_stable() {
  local no_systemd="$1" unit="$2" samples="${3:-12}"
  if [[ "${no_systemd}" == "1" ]]; then
    echo "skipping the stability check for ${unit} (--no-systemd)"
    return 0
  fi
  local first_pid="" first_restarts="" properties key value
  local state sub pid restarts sample
  for ((sample = 0; sample < samples; sample++)); do
    if ! properties="$(systemctl --user show "${unit}" \
      --property=ActiveState --property=SubState \
      --property=MainPID --property=NRestarts 2>/dev/null)"; then
      echo "${unit} could not be queried after start" >&2
      return 1
    fi
    state=""
    sub=""
    pid=""
    # NRestarts is absent on older systemd; the main PID comparison below
    # catches a restart on its own, so a missing counter is not fatal.
    restarts=""
    while IFS='=' read -r key value; do
      case "${key}" in
        ActiveState) state="${value}" ;;
        SubState) sub="${value}" ;;
        MainPID) pid="${value}" ;;
        NRestarts) restarts="${value}" ;;
      esac
    done <<<"${properties}"
    if [[ "${state}" != "active" || "${sub}" != "running" ]]; then
      echo "${unit} is ${state:-unknown}/${sub:-unknown}, not active/running" >&2
      return 1
    fi
    if [[ -z "${pid}" || "${pid}" == "0" ]]; then
      echo "${unit} reports active but has no main process" >&2
      return 1
    fi
    if [[ -z "${first_pid}" ]]; then
      first_pid="${pid}"
      first_restarts="${restarts}"
    elif [[ "${pid}" != "${first_pid}" ]]; then
      echo "${unit} restarted during the stability window (main PID ${first_pid} -> ${pid})" >&2
      return 1
    elif [[ -n "${restarts}" && "${restarts}" != "${first_restarts}" ]]; then
      echo "${unit} restarted during the stability window (NRestarts ${first_restarts} -> ${restarts})" >&2
      return 1
    fi
    sleep 0.5
  done
  echo "${unit} held active/running as PID ${first_pid} across the stability window"
}
