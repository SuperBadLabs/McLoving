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

# require_secure_ancestors HOME ROOT...
#
# Refuse every PRE-EXISTING directory on the way from HOME down to each
# managed root that is group- or world-writable. `umask` before `mkdir -p`
# secures only the ancestors that mkdir creates; an ancestor that already
# exists writable -- a 0777 ~/.local, say -- is untouched by both the umask
# and the explicit chmods on the managed roots, and a writable ancestor is as
# good as a writable root: the protected subtree can simply be renamed aside
# and replaced wholesale.
#
# Refused, not repaired: these are shared XDG locations (and the home itself)
# that hold unrelated content, and an installer silently re-moding a
# directory it did not create has side effects beyond this deployment -- the
# same reasoning that keeps the unit roots at `chmod go-w` instead of a
# forced mode applies with more force to directories this tool does not even
# manage. The diagnostic names every offending ancestor and its mode so one
# operator action fixes the tree.
#
# The chain is derived by deployment_ancestor_chain below -- lexical AND
# physical, never an enumerated list: enumeration is how this class of gap
# has already happened three times, and following a symlinked ancestor to
# its target while never walking the target's own parents made it four.
# Directories that do not exist yet are skipped -- mkdir -p under the
# caller's umask decides those.
require_secure_ancestors() {
  local home_dir="${1%/}" ancestor mode_owner mode owner home_owner offending chain
  shift
  chain="$(deployment_ancestor_chain "${home_dir}" "$@")" \
    || deploy_fail "cannot derive the deployment ancestor chain"
  home_owner="$(stat -Lc '%u' "${home_dir}")" \
    || deploy_fail "cannot stat deployment home ${home_dir}"
  offending=""
  while IFS= read -r ancestor; do
    # -d and stat -L follow a symlinked ancestor deliberately: the directory
    # the services traverse is the target, and a writable target permits the
    # same rename regardless of how it is reached. The target's own parents
    # arrive through the physical half of the chain, and following the link
    # means the OWNERSHIP judged below is the target's too.
    [[ -n "${ancestor}" && -d "${ancestor}" ]] || continue
    mode_owner="$(stat -Lc '%a %u' "${ancestor}")" \
      || deploy_fail "cannot stat deployment ancestor ${ancestor}"
    mode="${mode_owner%% *}"
    owner="${mode_owner##* }"
    if (( (8#${mode} & 8#022) != 0 )); then
      offending+="${ancestor} (mode ${mode}) "
    fi
    # Ownership is judged independently of mode: a chain component owned by
    # a third user is unsafe at ANY mode, because its owner can chmod it
    # writable at will and then rename children exactly as a writable
    # ancestor permits. Only root and the home's owning uid may hold a link
    # of the chain.
    if [[ "${owner}" != "0" && "${owner}" != "${home_owner}" ]]; then
      offending+="${ancestor} (owned by uid ${owner}, expected uid ${home_owner} or root) "
    fi
  done <<<"${chain}"
  if [[ -n "${offending}" ]]; then
    deploy_fail "deployment ancestor(s) group- or world-writable or foreign-owned: ${offending% }-- another local user could rename the protected subtree aside; run chmod go-w (or restore ownership) on them and retry"
  fi
}

# deployment_ancestor_chain HOME ROOT... -> every security-relevant ancestor
# directory of the managed roots, one absolute path per line, sorted. The
# single derivation consumed by BOTH the installer's refusal walk and the
# deployed-digests inventory, so the two cannot drift apart.
#
# Each root contributes two chains, because a path has two spellings. The
# LEXICAL parent chain up to HOME covers the components an operator sees --
# any of which may itself be a symlink, checked and recorded through its
# target. The PHYSICAL parent chain of the fully resolved root covers where
# the deployment actually lives: following a symlinked ancestor to its
# target without walking the target's OWN parents is how this class of gap
# happened a fourth time -- ~/.local -> /srv/mcloving/user left /srv/mcloving
# unexamined while its writability permits the same rename-substitution the
# direct checks refuse. Resolving the whole root also covers every
# intermediate link's target chain at once.
#
# Stop points: a chain inside the (resolved) home stops at the home
# directory, whose own parents are the platform's -- the boundary the
# installer has always drawn. A resolved chain that leaves the home has no
# such anchor and is walked to "/" inclusive. That deliberately refuses a
# deployment routed through a sticky world-writable directory such as /tmp:
# the sticky bit only narrows who may rename, and any attacker-owned
# component inside such a chain defeats it entirely. A looping or dangling
# link on the way to a root is refused by name rather than resolved around.
deployment_ancestor_chain() {
  python3 - "$@" <<'CHAIN'
import os
import sys

home = os.path.normpath(sys.argv[1])
roots = sys.argv[2:]
try:
    resolved_home = os.path.realpath(home, strict=True)
except OSError as error:
    raise SystemExit(f"deployment home {home} does not resolve: {error}")


def resolve_root(root):
    # The deepest existing prefix is resolved strictly (os.stat succeeding
    # proves the prefix is loop-free); missing trailing components are
    # appended lexically, because mkdir -p will create them under the
    # resolved prefix. A dangling or looping link is refused by name -- the
    # services cannot read through it and mkdir cannot create through it.
    remainder = []
    probe = os.path.normpath(root)
    while True:
        try:
            os.stat(probe)
            break
        except FileNotFoundError:
            if os.path.islink(probe):
                raise SystemExit(
                    f"deployment path {root} crosses a dangling symlink at {probe}"
                )
            head, tail = os.path.split(probe)
            if not tail or head == probe:
                raise SystemExit(f"deployment path {root} has no existing ancestor")
            probe = head
            remainder.append(tail)
        except OSError as error:
            raise SystemExit(
                f"deployment path {root} does not resolve at {probe}: {error}"
            )
    resolved = os.path.realpath(probe, strict=True)
    for tail in reversed(remainder):
        resolved = os.path.join(resolved, tail)
    return resolved


found = set()


def ascend(path, stop):
    current = os.path.normpath(path)
    while True:
        parent = os.path.dirname(current)
        if parent == current:
            break
        found.add(parent)
        if parent == stop or parent == "/":
            break
        current = parent


for root in roots:
    ascend(root, home)
    resolved_root = resolve_root(root)
    inside_home = resolved_root == resolved_home or resolved_root.startswith(
        resolved_home + os.sep
    )
    ascend(resolved_root, resolved_home if inside_home else "/")

for path in sorted(found):
    print(path)
CHAIN
}

# verify_release_dir RELEASE_DIR (MANIFEST|"") (CHECKSUMS|"")
#
# Diagnostics go to stderr. This runs inside stage_release, whose stdout is a
# protocol its callers parse; a progress line written there is indistinguishable
# from the result, and was in fact being parsed as one.
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
    python3 - "${manifest}" "${release_dir}" "${MCLOVING_DEPLOY_BINARIES[@]}" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

manifest_path, release_dir, *binaries = sys.argv[1:]
# The manifest is operator-supplied and read at a time the operator does not
# control, so the classification happens on the descriptor that is read, not
# on the pathname -- the same race copy_regular_file and release_id already
# refuse. A pathname check followed by an ordinary open leaves a window in
# which the manifest becomes a FIFO (read_text blocks forever) or a device
# such as /dev/zero (read_text exhausts memory), both before the release is
# accepted or refused.
try:
    descriptor = os.open(manifest_path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError as error:
    raise SystemExit(f"cannot open manifest {manifest_path}: {error}")
try:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise SystemExit(f"manifest {manifest_path} is not a regular file")
    os.set_blocking(descriptor, True)
    with os.fdopen(descriptor, "rb", closefd=False) as handle:
        payload = handle.read()
finally:
    os.close(descriptor)
try:
    document = json.loads(payload.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"manifest {manifest_path} is not parseable JSON: {error}")
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
print(f"verified {len(binaries)} binaries against manifest {manifest_path}", file=sys.stderr)
PY
  else
    # One snapshot, taken once, decides everything. The previous shape read
    # the pathname twice -- per-binary greps, then a fresh open by
    # `sha256sum --ignore-missing`, which does not fail on entries missing
    # from its input -- so a checksums file replaced between the two reads
    # could pass the presence checks and then verify only whatever the
    # replacement still contained. The snapshot is read through a classified
    # descriptor for the same reason the manifest is: the file is
    # operator-supplied, and a FIFO or device swapped in must be refused, not
    # blocked on. The required entries are then selected from the snapshot
    # and that same selection is what sha256sum verifies, with
    # --ignore-missing gone: every line handed over must check.
    local checksum_snapshot required_lines entry_lines
    checksum_snapshot="$(python3 - "${checksums}" <<'SNAPSHOT'
import os
import stat
import sys

path = sys.argv[1]
try:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError as error:
    raise SystemExit(f"cannot open checksums file {path}: {error}")
try:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise SystemExit(f"checksums file {path} is not a regular file")
    os.set_blocking(descriptor, True)
    with os.fdopen(descriptor, "rb", closefd=False) as handle:
        sys.stdout.buffer.write(handle.read())
finally:
    os.close(descriptor)
SNAPSHOT
    )" || deploy_fail "checksums file ${checksums} could not be read"
    required_lines=""
    for binary in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
      entry_lines="$(grep -E "^[0-9a-f]{64}[[:space:]]+\*?${binary}\$" \
        <<<"${checksum_snapshot}")" \
        || deploy_fail "checksums file has no entry for ${binary}"
      required_lines+="${entry_lines}"$'\n'
    done
    (
      cd "${release_dir}"
      sha256sum --check --strict - <<<"${required_lines%$'\n'}" >/dev/null
    ) || deploy_fail "sha256 verification against ${checksums} failed"
    echo "verified ${#MCLOVING_DEPLOY_BINARIES[@]} binaries against checksums ${checksums}" >&2
  fi
}

# copy_regular_file SRC DST MODE
#
# Copy SRC to DST, refusing anything that is not a regular file.
#
# Testing the pathname and then letting `install` open it are two separate
# operations, and a source replaced in between is exactly the case worth
# refusing: `install` reading a FIFO blocks until something writes to it, and
# reading a device such as a symlinked /dev/zero fills the disk -- both before
# any digest verification sees a byte. The classification therefore happens on
# the descriptor that is read, not on the name: O_NONBLOCK so opening a
# writer-less FIFO returns instead of hanging, then fstat, then the copy from
# that same descriptor.
copy_regular_file() {
  python3 - "$1" "$2" "$3" <<'COPY'
import os
import stat
import sys

source, destination, mode = sys.argv[1], sys.argv[2], int(sys.argv[3], 8)
try:
    descriptor = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError as error:
    raise SystemExit(f"cannot open {source}: {error}")
try:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise SystemExit(f"{source} is not a regular file")
    # Cleared of O_NONBLOCK only after the descriptor is known to be regular,
    # for which the flag is meaningless anyway.
    os.set_blocking(descriptor, True)
    staging = f"{destination}.copy.{os.getpid()}"
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as reader:
            with open(staging, "wb") as writer:
                while True:
                    chunk = reader.read(1 << 20)
                    if not chunk:
                        break
                    writer.write(chunk)
        os.chmod(staging, mode)
        os.replace(staging, destination)
    except BaseException:
        try:
            os.unlink(staging)
        except OSError:
            pass
        raise
finally:
    os.close(descriptor)
COPY
}

# release_id RELEASE_DIR -> deterministic 12-hex id over the binary digests
#
# Reads through the same classified descriptors as copy_regular_file, and for
# the same reason: `sha256sum` on a pathname that has become a FIFO blocks
# until something writes to it, and on a device reads without end. This runs on
# a source directory the caller does not control the timing of, so the
# classification has to be part of the read rather than a check before it.
release_id() {
  python3 - "$1" "${MCLOVING_DEPLOY_BINARIES[@]}" <<'ID'
import hashlib
import os
import stat
import sys

release_dir, binaries = sys.argv[1], sys.argv[2:]
combined = hashlib.sha256()
for binary in binaries:
    path = os.path.join(release_dir, binary)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        raise SystemExit(f"cannot open {path}: {error}")
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise SystemExit(f"{path} is not a regular file")
        os.set_blocking(descriptor, True)
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    finally:
        os.close(descriptor)
    combined.update(f"{digest.hexdigest()}\n".encode("ascii"))
print(combined.hexdigest()[:12])
ID
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

# database_url_database URL -> the database name, or empty.
database_url_database() {
  python3 - "$1" <<'DBNAME'
import sys
from urllib.parse import unquote, urlsplit

url = sys.argv[1]
if not url:
    raise SystemExit(0)
name = urlsplit(url).path.lstrip("/")
if name:
    print(unquote(name))
DBNAME
}

# database_url_host URL -> the host, or empty.
database_url_host() {
  python3 - "$1" <<'DBHOST'
import sys
from urllib.parse import urlsplit

url = sys.argv[1]
if not url:
    raise SystemExit(0)
host = urlsplit(url).hostname
if host:
    print(host)
DBHOST
}

# database_url_is_loopback URL -> success when the host is a loopback address.
database_url_is_loopback() {
  python3 - "$1" <<'LOOPBACK'
import ipaddress
import sys
from urllib.parse import urlsplit

host = urlsplit(sys.argv[1]).hostname or ""
if host == "localhost":
    raise SystemExit(0)
try:
    raise SystemExit(0 if ipaddress.ip_address(host).is_loopback else 1)
except ValueError:
    raise SystemExit(1)
LOOPBACK
}

# database_url_endpoint URL -> "host:port/database", or empty.
#
# The identity of the server and database a URL addresses, with the role and
# credentials left out, so two URLs meant to reach one instance can be compared.
database_url_endpoint() {
  python3 - "$1" <<'ENDPOINT'
import sys
from urllib.parse import unquote, urlsplit

url = sys.argv[1]
if not url:
    raise SystemExit(0)
parts = urlsplit(url)
host = parts.hostname or ""
port = parts.port or 5432
database = unquote(parts.path.lstrip("/"))
if host and database:
    print(f"{host}:{port}/{database}")
ENDPOINT
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
# copied bytes are checked against.
#
# Echoes `published <path>` or `existing <path>`. The caller has to be able to
# tell the two apart: on a refusal it may only remove a release this invocation
# created, never one that was already retained -- deleting the `previous`
# target would destroy the rollback release and leave that link dangling.
# Status first, because a home directory may contain spaces and the path may
# not be split.
stage_release() {
  local libexec_root="$1" release_dir="$2" manifest="$3" checksums="$4"
  local binary target staging id
  mkdir -p "${libexec_root}/releases"
  staging="${libexec_root}/releases/.staging.$$"
  rm -rf "${staging}"
  mkdir -p "${staging}"
  # Explicit modes, not whatever the caller's umask happens to be. Under
  # `umask 000` these would be 0777, and a world-writable releases directory
  # lets another local user rename a verified binary out and a chosen one in --
  # code execution as the service account, with every file still mode 0755.
  chmod 0700 "${libexec_root}/releases" "${staging}"
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
    copy_regular_file "${release_dir}/${binary}" "${staging}/${binary}" 0755 \
      || deploy_fail "release ${release_dir} does not provide ${binary} as a readable regular file"
  done
  if ! verify_release_dir "${staging}" "${manifest}" "${checksums}"; then
    deploy_fail "staged copy does not match the supplied digest source"
  fi
  id="$(release_id "${staging}")"
  target="${libexec_root}/releases/${id}"
  local state="published"
  if [[ -d "${target}" ]]; then
    state="existing"
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
  printf '%s %s\n' "${state}" "${target}"
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
