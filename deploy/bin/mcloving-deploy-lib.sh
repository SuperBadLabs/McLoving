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
  local encoded_ancestor
  while IFS= read -r encoded_ancestor; do
    [[ -n "${encoded_ancestor}" ]] || continue
    decode_path_item_into ancestor "${encoded_ancestor}"
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

# require_secure_files HOME FILE...
#
# Judge each EXISTING file -- through its link when it is one -- by the same
# mode and ownership rules the ancestor walk applies to directories: a
# group- or world-writable or foreign-owned contract file is rewritable by
# another local user, which controls the environment systemd loads no matter
# how well its directory chain is secured. Files that do not exist are
# skipped: the installer decides those. The files' ancestor chains --
# including the resolved target chains of every link component -- are the
# caller's job via require_secure_ancestors, which accepts file paths as
# roots (the final component resolves like any other).
require_secure_files() {
  local home_dir="${1%/}" home_owner
  shift
  home_owner="$(stat -Lc '%u' "${home_dir}")" \
    || deploy_fail "cannot stat deployment home ${home_dir}"
  require_secret_files "${home_owner}" "$@"
}

# require_secret_files EXPECTED_UID FILE...
#
# The uid-parametrized core of require_secure_files, callable where no home
# directory is at hand -- mcloving-env-guard runs as the service user at
# ExecStartPre and passes its own EUID. Same rules, same named refusals.
require_secret_files() {
  local home_owner="$1" file mode_owner mode owner offending
  shift
  offending=""
  for file in "$@"; do
    [[ -e "${file}" ]] || continue
    mode_owner="$(stat -Lc '%a %u' "${file}")" \
      || deploy_fail "cannot stat contract file ${file}"
    mode="${mode_owner%% *}"
    owner="${mode_owner##* }"
    # Contracts carry database passwords and API tokens, so ANY group or
    # other bit -- read included -- is refused, not just the write bits the
    # directory walk cares about. The 0700 config root shields in-place
    # contracts, but a preserved contract may be a symlink whose resolved
    # file lives outside that shield entirely; the file's own bits are then
    # the only thing standing between the secrets and every other user on
    # the host. The deployment documentation promises 0600, and this makes
    # the promise a precondition.
    if (( (8#${mode} & 8#077) != 0 )); then
      offending+="${file} (mode ${mode}, expected owner-only) "
    fi
    if [[ "${owner}" != "0" && "${owner}" != "${home_owner}" ]]; then
      offending+="${file} (owned by uid ${owner}, expected uid ${home_owner} or root) "
    fi
    # Readability is the symmetric precondition: writability and ownership
    # guard against SUBSTITUTION, readability guards AVAILABILITY. A
    # root-owned 0600 contract is perfectly secure and perfectly useless --
    # the service user cannot read it, so every dependent unit's
    # EnvironmentFile= fails at start while the install reported success.
    # `-r` judges effective access as the invoking user (the service user in
    # this rootless lane), so ACLs and group paths decide correctly where
    # mode arithmetic would not.
    if [[ ! -r "${file}" ]]; then
      offending+="${file} (unreadable by uid ${EUID}) "
    fi
  done
  if [[ -n "${offending}" ]]; then
    deploy_fail "secret-bearing file(s) not owner-only, foreign-owned, or unreadable: ${offending% }-- an unwritable-by-others AND readable-by-the-service-user contract is required; run chmod go-w (or restore ownership/readability) on them and retry"
  fi
}

# deployment_contract_path_variables SERVICE -> "CLASS LINK-POLICY VARIABLE" lines
#
# The single authority for which contract variables carry filesystem paths
# and which protection class each belongs to, shared by mcloving-env-guard
# (which enforces the classes at service start) and
# mcloving-deployed-digests (which inventories the configured files that
# live outside the walked trees). Two copies of this table is how a
# variable added to one consumer would silently escape the other.
#
# Classes: "secret" -- owner-only, root-or-service-uid owner, readable,
# resolved-chain walk (private keys, identity bindings). "trust" -- public
# to read, critical to write: no group/other write, ownership, chain
# (certificates and CA bundles). "state" -- the integrity class for
# workspace/object roots and journals: no group/other write, ownership,
# chain, absence legal for journals. The migration URL is a network
# address, not a filesystem path, and the postgres/db-init contracts carry
# no path variables.
#
# LINK-POLICY encodes the PARITY PRINCIPLE: wherever the guard validates a
# path a binary enforces its own rules on, the guard mirrors the binary's
# EXACT check -- a guard that accepts what the binary refuses reports a
# contract satisfied and then watches the unit fail after ExecStartPre.
# "follow": the binary opens through the pathname (fs::read,
# read_to_string, store/journal opens), so symlinks are legal and the
# resolved target chain is what the walk judges. "nofollow": the binary
# inspects with symlink_metadata() and refuses every symlink -- today the
# two effect variables -- so the guard refuses the link itself, lstat-based,
# before any generic class check follows it.
deployment_contract_path_variables() {
  case "$1" in
    controller)
      # MCLOVING_EFFECT_RUNTIME_PLAN is secret-class because the controller
      # itself refuses it unless mode & 077 == 0 -- the guard fails at start
      # what the binary would fail at plan load. The mapping catalog is
      # trust-class: the binary requires no group/other WRITE bit and pins
      # the content with MCLOVING_EFFECT_MAPPING_CATALOG_SHA256, so read
      # stays legal. Both are optional; empty means unset here, and the
      # binary refuses set-but-empty on its own.
      printf '%s\n' \
        "secret follow MCLOVING_AGENT_SERVER_KEY_PATH" \
        "secret follow MCLOVING_AGENT_IDENTITY_BINDINGS_PATH" \
        "secret nofollow MCLOVING_EFFECT_RUNTIME_PLAN" \
        "trust follow MCLOVING_AGENT_SERVER_CERT_PATH" \
        "trust follow MCLOVING_AGENT_CLIENT_CA_PATH" \
        "trust nofollow MCLOVING_EFFECT_MAPPING_CATALOG" \
        "state follow MCLOVING_OBJECT_ROOT" \
        "state follow MCLOVING_WORKSPACE_ROOT" \
        "state follow MCLOVING_AGENT_JOURNAL"
      ;;
    agent)
      # The session receipt is an optional durable output the agent writes;
      # state-class like the journal, absence legal before first use.
      printf '%s\n' \
        "secret follow MCLOVING_AGENT_PRIVATE_KEY_PATH" \
        "trust follow MCLOVING_CONTROLLER_CA_PATH" \
        "trust follow MCLOVING_AGENT_CERTIFICATE_PATH" \
        "state follow MCLOVING_AGENT_WORKSPACE_ROOT" \
        "state follow MCLOVING_AGENT_JOURNAL_PATH" \
        "state follow MCLOVING_AGENT_SESSION_RECEIPT_PATH"
      ;;
    postgres | db-init)
      :
      ;;
  esac
}

# require_integrity_files HOME FILE...
#
# The trust-input file rule for the install and transition walks: readable,
# no group/other WRITE bit, owned by root or the home's owner. Unit files,
# drop-ins, and retained release binaries are execution vectors --
# ExecStart lives in the units, and the binaries are what it starts -- but
# are legitimately world-READABLE, unlike contracts; a writable or foreign
# one lets another local user control what the next restart executes.
require_integrity_files() {
  local home_dir="${1%/}" home_owner file mode_owner mode owner offending
  shift
  home_owner="$(stat -Lc '%u' "${home_dir}")" \
    || deploy_fail "cannot stat deployment home ${home_dir}"
  offending=""
  for file in "$@"; do
    [[ -e "${file}" ]] || continue
    mode_owner="$(stat -Lc '%a %u' "${file}")" \
      || deploy_fail "cannot stat trust-input file ${file}"
    mode="${mode_owner%% *}"
    owner="${mode_owner##* }"
    if (( (8#${mode} & 8#022) != 0 )); then
      offending+="${file} (mode ${mode}) "
    fi
    if [[ "${owner}" != "0" && "${owner}" != "${home_owner}" ]]; then
      offending+="${file} (owned by uid ${owner}, expected uid ${home_owner} or root) "
    fi
    if [[ ! -r "${file}" ]]; then
      offending+="${file} (unreadable by uid ${EUID}) "
    fi
  done
  if [[ -n "${offending}" ]]; then
    deploy_fail "trust-input file(s) (unit, drop-in, or retained release binary) group- or world-writable, foreign-owned, or unreadable: ${offending% }-- another local user could control what the next service start executes; run chmod go-w (or restore ownership) on them and retry"
  fi
}

# deployment_config_root HOME / deployment_state_root HOME /
# deployment_cache_root HOME -> the XDG base directories as the user
# manager resolves them, one per line on stdout.
#
# systemd's user instance roots its unit search under $XDG_CONFIG_HOME
# (default ~/.config) and creates StateDirectory=/CacheDirectory= leaves
# under $XDG_STATE_HOME (default ~/.local/state) and $XDG_CACHE_HOME
# (default ~/.cache). A lane that hard-codes the defaults writes units the
# manager cannot find and validates state trees systemd never uses. The
# policy for the variables mirrors systemd exactly: a value that is unset,
# empty, or NOT ABSOLUTE is ignored and the default applies -- the XDG
# spec and systemd's basic/lookup-paths both discard relative values.
# The mcloving contract root is deliberately NOT derived from
# XDG_CONFIG_HOME: the shipped units reference it as %h/.config/mcloving
# literally, and %h expands to the home regardless of XDG -- the lane must
# resolve exactly as systemd resolves the units' own text.
# deployment_xdg_value_applies HOME VALUE -- whether an inherited XDG base
# may speak for the deployment at HOME. It may when the target home IS the
# invoking user's own home (the environment describes that account's
# manager), or when the value lies inside the target home. An absolute
# XDG_CONFIG_HOME inherited from some OTHER account's environment -- the
# GitHub runner exports one, and CI proved the hazard by having the
# installer write a scratch deployment's units into the runner's real
# configuration root -- describes nobody's view of the target tree and is
# ignored like a relative value.
deployment_xdg_value_applies() {
  local home_dir="${1%/}" value="${2%/}" normalized_home normalized_value
  if [[ "${home_dir}" == "${HOME%/}" ]]; then
    return 0
  fi
  # The inside-the-target-home judgment is a lexical prefix test, so BOTH
  # sides are lexically normalized first: an inherited value spelled
  # ${home}/.config/../../elsewhere carries the home as a lexical prefix
  # while naming a tree outside it, and would otherwise be adopted as
  # speaking for the target home. normpath only, never realpath -- the
  # ancestor walk judges every symlink the spelling crosses on its own.
  lexical_normalized_path_into normalized_home "${home_dir}"
  lexical_normalized_path_into normalized_value "${value}"
  if [[ "${normalized_value}" == "${normalized_home}"/* ]]; then
    return 0
  fi
  return 1
}

# lexical_normalized_path_into VARIABLE PATH -- the lexically collapsed
# spelling (python's posixpath.normpath; NEVER realpath -- symlink policy
# belongs to each consumer). The sentinel byte survives the command
# substitution, so a path whose normalized spelling ends in a newline
# round-trips exactly, same discipline as decode_path_item_into.
lexical_normalized_path_into() {
  # shellcheck disable=SC2178  # nameref assignment
  local -n normalize_target_ref="$1"
  normalize_target_ref="$(
    python3 -c 'import posixpath, sys; sys.stdout.write(posixpath.normpath(sys.argv[1]))' "$2" \
      && printf x
  )" || deploy_fail "cannot normalize a path spelling"
  normalize_target_ref="${normalize_target_ref%x}"
}

# encode_path_item PATH -> one base64 line (no wrap).
#
# The single transport token for every internal multi-path protocol: chain
# and declared-roots output, and the wrapper-to-inventory environment
# exports. Chosen over NUL delimiting because bash variables cannot hold
# NUL, and over ad-hoc escaping because the base64 alphabet contains
# neither newline nor NUL, so an item carrying either -- a quoted multiline
# contract value is legal to the parser and to systemd -- CANNOT regress to
# splitting: whatever the bytes, one item is one line. Decoding goes through
# decode_path_item_into, whose sentinel survives command substitution, so a
# trailing newline in a component round-trips too.
encode_path_item() {
  printf '%s' "$1" | base64 -w0
  printf '\n'
}

# decode_path_item_into VARIABLE ENCODED -- the only sanctioned decoder.
#
# A bare $(base64 -d ...) strips the decoded value's trailing newline, so a
# directory NAME ending in one would be examined under a truncated pathname
# and its mode never judged. The sentinel byte survives the substitution
# and is stripped afterwards, so the decoded bytes are exact.
decode_path_item_into() {
  # shellcheck disable=SC2178  # nameref assignment
  local -n decode_target_ref="$1"
  decode_target_ref="$(base64 -d <<<"$2" && printf x)" \
    || deploy_fail "cannot decode a path transport item"
  decode_target_ref="${decode_target_ref%x}"
}

deployment_config_root() {
  local home_dir="${1%/}" value="${XDG_CONFIG_HOME:-}"
  if [[ "${value}" == /* ]] && deployment_xdg_value_applies "${home_dir}" "${value}"; then
    printf '%s\n' "${value%/}"
  else
    printf '%s\n' "${home_dir}/.config"
  fi
}

deployment_state_root() {
  local home_dir="${1%/}" value="${XDG_STATE_HOME:-}"
  if [[ "${value}" == /* ]] && deployment_xdg_value_applies "${home_dir}" "${value}"; then
    printf '%s\n' "${value%/}"
  else
    printf '%s\n' "${home_dir}/.local/state"
  fi
}

deployment_cache_root() {
  local home_dir="${1%/}" value="${XDG_CACHE_HOME:-}"
  if [[ "${value}" == /* ]] && deployment_xdg_value_applies "${home_dir}" "${value}"; then
    printf '%s\n' "${value%/}"
  else
    printf '%s\n' "${home_dir}/.cache"
  fi
}

# deployment_unit_source_files UNIT_FILE... -> encoded items: every file
# the unit parse READS -- the unit files themselves plus <unit>.d/*.conf
# drop-ins. One enumeration for the parser and for source validation, so
# what is parsed and what is judged cannot diverge: everything the parser
# reads is an execution vector (ExecStart lives in these files).
deployment_unit_source_files() {
  local unit_file dropin
  for unit_file in "$@"; do
    [[ -f "${unit_file}" ]] || continue
    encode_path_item "${unit_file}"
    for dropin in "${unit_file}.d"/*.conf; do
      [[ -f "${dropin}" ]] && encode_path_item "${dropin}"
    done
  done
  return 0
}

# deployment_unit_declared_contracts HOME UNIT_FILE... -> encoded items:
# every EnvironmentFile= value the units and their drop-ins declare, with
# the optional "-" prefix stripped and %h expanded, WHEREVER it points --
# an EnvironmentFile IS a contract, and one declared outside the home is
# validated under the same rules as any contract, with its chain walked to
# "/" per the outside-home stop rule. Non-absolute values are dropped here
# because systemd itself refuses them.
deployment_unit_declared_contracts() {
  local home_dir="${1%/}" line value path encoded_source decoded_source
  local source_files=()
  shift
  while IFS= read -r encoded_source; do
    [[ -n "${encoded_source}" ]] || continue
    decode_path_item_into decoded_source "${encoded_source}"
    source_files+=("${decoded_source}")
  done < <(deployment_unit_source_files "$@")
  [[ ${#source_files[@]} -gt 0 ]] || return 0
  while IFS= read -r line; do
    value="${line#EnvironmentFile=}"
    path="${value#-}"
    path="${path//%h/${home_dir}}"
    case "${path}" in
      /*) encode_path_item "${path}" ;;
    esac
  done < <(grep -hE '^EnvironmentFile=' "${source_files[@]}" | sed -e 's/[[:space:]]*$//')
}

# deployment_unit_declared_roots HOME UNIT_FILE... -> the home-relative
# directories the DEPLOYMENT'S OWN unit declarations cause to exist, one per
# line. The installer's managed_roots covers what the installer creates, but
# systemd creates StateDirectory= (and kin) leaves on its own at service
# start -- so those roots are derived from the staged unit files themselves,
# and a directive added later brings its root into the refusal walk without
# anyone remembering a list. Mappings follow systemd's USER-unit bases:
# StateDirectory under ~/.local/state, LogsDirectory under
# ~/.local/state/log, CacheDirectory under ~/.cache. RuntimeDirectory lands
# under $XDG_RUNTIME_DIR -- outside the home on a root-managed tmpfs -- and
# is deliberately skipped. WorkingDirectory=, EnvironmentFile= (with its
# optional "-" prefix), and quadlet Volume= host paths contribute when they
# resolve under the home after %h expansion; named quadlet volumes do not.
deployment_unit_declared_roots() {
  local home_dir="${1%/}" line key value entry path state_base cache_base
  local unit_file dropin source_files=()
  shift
  state_base="$(deployment_state_root "${home_dir}")"
  cache_base="$(deployment_cache_root "${home_dir}")"
  # systemd and Quadlet merge <unit>.d/*.conf drop-ins into the unit, so a
  # drop-in adding a path directive declares a path the transition is about
  # to trust -- the round-12 lesson (drop-in descendants count) applied to
  # this parser. Validation is additive, so the union of path-bearing
  # directives across unit and drop-ins suffices; no precedence resolution.
  # The file list comes from deployment_unit_source_files, the same
  # enumeration source validation judges.
  local encoded_source decoded_source
  while IFS= read -r encoded_source; do
    [[ -n "${encoded_source}" ]] || continue
    decode_path_item_into decoded_source "${encoded_source}"
    source_files+=("${decoded_source}")
  done < <(deployment_unit_source_files "$@")
  [[ ${#source_files[@]} -gt 0 ]] || return 0
  while IFS= read -r line; do
    key="${line%%=*}"
    value="${line#*=}"
    case "${key}" in
      StateDirectory)
        # shellcheck disable=SC2086  # systemd's value is space-separated names
        for entry in ${value}; do
          encode_path_item "${state_base}/${entry}"
        done
        ;;
      LogsDirectory)
        # shellcheck disable=SC2086  # systemd's value is space-separated names
        for entry in ${value}; do
          encode_path_item "${state_base}/log/${entry}"
        done
        ;;
      CacheDirectory)
        # shellcheck disable=SC2086  # systemd's value is space-separated names
        for entry in ${value}; do
          encode_path_item "${cache_base}/${entry}"
        done
        ;;
      RuntimeDirectory)
        :
        ;;
      WorkingDirectory)
        # Declared targets are validated WHEREVER they point: an absolute
        # path outside the home is exactly the one another local user may
        # control, and the outside-home chain rule (walk to "/") already
        # knows how to judge it. EnvironmentFile= is a CONTRACT and is
        # enumerated by deployment_unit_declared_contracts instead.
        path="${value//%h/${home_dir}}"
        case "${path}" in
          /*) encode_path_item "${path}" ;;
        esac
        ;;
      EnvironmentFile)
        :
        ;;
      Volume)
        path="${value%%:*}"
        path="${path//%h/${home_dir}}"
        case "${path}" in
          /*) encode_path_item "${path}" ;;
        esac
        ;;
    esac
  done < <(grep -hE '^(StateDirectory|RuntimeDirectory|LogsDirectory|CacheDirectory|WorkingDirectory|EnvironmentFile|Volume)=' "${source_files[@]}" | sed -e 's/[[:space:]]*$//')
}

# deployment_ancestor_chain HOME ROOT... -> every security-relevant ancestor
# directory of the managed roots, one absolute path per line, sorted. The
# single derivation consumed by BOTH the installer's refusal walk and the
# deployed-digests inventory, so the two cannot drift apart.
#
# Each root contributes chains for every spelling a path has. The LEXICAL
# parent chain up to HOME covers the components an operator sees -- any of
# which may itself be a symlink, checked and recorded through its target.
# The PHYSICAL side is derived COMPONENT BY COMPONENT: every time resolution
# crosses a symlink, the resolved target's own parent chain joins the set,
# recursively, because the target may contain further links. A single
# realpath of the whole root keeps only the FINAL chain: with
# .local -> /srv/a/user-local and user-local/libexec -> /opt/mcloving/libexec,
# it walks /opt/mcloving and never /srv/a -- and a writable /srv/a lets
# another user replace user-local wholesale. The ancestor set is the union
# of every directory encountered in any traversal.
#
# Stop points: a chain inside the (resolved) home stops at the home
# directory, whose own parents are the platform's -- the boundary the
# installer has always drawn. A chain that leaves the home has no such
# anchor and is walked to "/" inclusive. That deliberately refuses a
# deployment routed through a sticky world-writable directory such as /tmp:
# the sticky bit only narrows who may rename, and any attacker-owned
# component inside such a chain defeats it entirely. A looping or dangling
# link on the way to a root is refused by name rather than resolved around,
# with resolution bounded like the kernel bounds ELOOP.
deployment_ancestor_chain() {
  python3 - "$@" <<'CHAIN'
import base64
import os
import sys

# Anchored to the invoking directory FIRST, links resolved later: the two
# are distinct steps, and skipping the first anchored the component walk at
# "/" for a relative --home, so relative-home/.local was inspected as
# /relative-home/.local -- a tree that does not exist -- and none of the
# real deployment's links were ever seen. abspath is purely lexical
# (cwd-join plus normpath); every symlink still goes through the recorded
# component walk below.
home = os.path.abspath(sys.argv[1])
roots = [os.path.abspath(root) for root in sys.argv[2:]]
try:
    resolved_home = os.path.realpath(home, strict=True)
except OSError as error:
    raise SystemExit(f"deployment home {home} does not resolve: {error}")

MAX_LINK_TRAVERSALS = 40

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


def chain_of(resolved):
    inside_home = resolved == resolved_home or resolved.startswith(
        resolved_home + os.sep
    )
    ascend(resolved, resolved_home if inside_home else "/")


def resolve_recording(origin, path, budget):
    """Resolve ``path`` component by component.

    Missing trailing components are appended lexically (mkdir -p will create
    them under the resolved prefix). Each symlink component is resolved
    recursively -- its target may contain further links -- and the resolved
    target's parent chain joins the ancestor set. A dangling link is refused
    by name; a loop exhausts the shared traversal budget and is refused by
    name too.
    """
    resolved = "/"
    for component in [c for c in os.path.normpath(path).split(os.sep) if c]:
        candidate = os.path.join(resolved, component)
        if not os.path.islink(candidate):
            resolved = candidate
            continue
        if budget[0] <= 0:
            raise SystemExit(
                f"deployment path {origin} exceeds the symlink resolution bound at {candidate}"
            )
        budget[0] -= 1
        target = os.readlink(candidate)
        if not os.path.isabs(target):
            target = os.path.join(os.path.dirname(candidate), target)
        target_resolved = resolve_recording(origin, target, budget)
        if not os.path.exists(target_resolved):
            raise SystemExit(
                f"deployment path {origin} crosses a dangling symlink at {candidate}"
            )
        chain_of(target_resolved)
        resolved = target_resolved
    return resolved


for root in roots:
    ascend(root, home)
    resolved_root = resolve_recording(root, root, [MAX_LINK_TRAVERSALS])
    chain_of(resolved_root)
    # The root NODE itself joins the set, not only its parents: a leaf
    # managed root -- helpers, releases -- relaxed to group/world-writable
    # after installation is otherwise invisible to every consumer of this
    # chain, and a writable helpers directory is a helper substitution
    # waiting for the next transition. Consumers skip nodes that are not
    # directories (files are judged by their own classes) and follow a
    # symlinked node to its target, consistent with the ancestor rules;
    # where a root may never legitimately BE a symlink -- retained release
    # directories -- the round-11 lstat refusals still fire first in their
    # own paths.
    found.add(resolved_root)

for path in sorted(found):
    # One item, one line, whatever bytes the path carries: the transport
    # convention shared by every internal multi-path protocol.
    print(base64.b64encode(os.fsencode(path)).decode("ascii"))
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
  # This deployment's own staging only ever publishes REAL directories (the
  # mv -T below), so a symlink at the retained target has no legitimate
  # state -- and -d, cmp, and verify_staged_release would all follow it,
  # adopting a tree beneath whatever external chain the link points at.
  # Refused by name rather than validating an arbitrary external chain for
  # a case that cannot occur legitimately.
  if [[ -L "${target}" ]]; then
    deploy_fail "retained release target releases/${id} is a symlink; stage_release only publishes real directories, refusing to reuse it"
  fi
  if [[ -d "${target}" ]]; then
    state="existing"
    # The retained tree is reused only after its bytes are proven identical
    # to the staging copy that just passed digest verification. The release
    # id truncates the combined digest to 48 bits and verify_staged_release
    # compares that truncated name, so without this a colliding or
    # substituted tree under the same id would be adopted while the newly
    # VERIFIED bytes are deleted -- the name is a claim; the bytes are the
    # evidence, and they are still on disk to check at this moment.
    for binary in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
      cmp -s "${staging}/${binary}" "${target}/${binary}" \
        || deploy_fail "retained release ${id} does not match the newly verified bytes for ${binary}; refusing a colliding or substituted release tree"
    done
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

# require_deployment_integrity HOME
#
# The full shared validation the installer performs, rerun by the
# TRANSITION entry points inside the transition lock and before any
# mutation: an ancestor made writable or foreign-owned after installation
# would otherwise let another local user rename the protected subtree
# between release verification and the service restart. Same derivations,
# same refusal messages as install; the unit-declared roots are parsed from
# the INSTALLED units, because the deployed tree is what the transition is
# about to touch.
require_deployment_integrity() {
  local home_dir="${1%/}" libexec_root config_root xdg_config_base
  local unit_root quadlet_root unit_file
  libexec_root="${home_dir}/.local/libexec/mcloving"
  config_root="${home_dir}/.config/mcloving"
  xdg_config_base="$(deployment_config_root "${home_dir}")"
  unit_root="${xdg_config_base}/systemd/user"
  quadlet_root="${xdg_config_base}/containers/systemd"
  local managed_roots=(
    "${libexec_root}"
    "${libexec_root}/helpers"
    "${libexec_root}/releases"
    "${config_root}"
    "${config_root}/pki"
    "${unit_root}"
    "${quadlet_root}"
  )
  local contract_destinations=(
    "${config_root}/postgres.env"
    "${config_root}/db-init.env"
    "${config_root}/controller.env"
    "${config_root}/agent.env"
  )
  local unit_files=()
  for unit_file in "${unit_root}"/mcloving-*.service \
    "${quadlet_root}"/mcloving-*.container "${quadlet_root}"/mcloving-*.volume; do
    [[ -f "${unit_file}" ]] && unit_files+=("${unit_file}")
  done
  local unit_declared_roots=() declared_contracts=() unit_source_files=()
  local dropin_dirs=() encoded_root encoded_item decoded_item
  if [[ ${#unit_files[@]} -gt 0 ]]; then
    local decoded_declared_root
    while IFS= read -r encoded_root; do
      [[ -n "${encoded_root}" ]] || continue
      decode_path_item_into decoded_declared_root "${encoded_root}"
      unit_declared_roots+=("${decoded_declared_root}")
    done < <(deployment_unit_declared_roots "${home_dir}" "${unit_files[@]}" | sort -u)
    # EVERYTHING the parser reads (sources) and everything it declares
    # (targets) enters validation -- no filtered category. Sources: the
    # unit files themselves and their drop-ins, judged by the integrity
    # file rule, with their .d directories joining the chain roots.
    # Declared EnvironmentFiles are contracts and get the contract file
    # rule, wherever they point.
    while IFS= read -r encoded_item; do
      [[ -n "${encoded_item}" ]] || continue
      decode_path_item_into decoded_item "${encoded_item}"
      unit_source_files+=("${decoded_item}")
    done < <(deployment_unit_source_files "${unit_files[@]}")
    while IFS= read -r encoded_item; do
      [[ -n "${encoded_item}" ]] || continue
      decode_path_item_into decoded_item "${encoded_item}"
      declared_contracts+=("${decoded_item}")
    done < <(deployment_unit_declared_contracts "${home_dir}" "${unit_files[@]}" | sort -u)
    for unit_file in "${unit_files[@]}"; do
      [[ -d "${unit_file}.d" ]] && dropin_dirs+=("${unit_file}.d")
    done
  fi
  # The RETAINED release inventory joins the walk, derived by LISTING
  # releases/ rather than enumerating from the current/previous links: the
  # links name at most two entries, while every retained releases/<id> is
  # executable state the next transition hashes and adopts. The inventory
  # validates the releases PARENT already, but a retained directory (or a
  # binary inside one) gone group/world-writable after publication would
  # otherwise be hashed -- successfully -- and then swapped by another
  # local user between the byte comparison and the service start. Each
  # real directory found joins the validated-node set (its mode and
  # ownership are judged like every managed root); each regular file gets
  # the trust-input file rule below (no group/other write, root-or-home
  # owner; world-readable stays legal -- these are public binaries, not
  # secrets). A symlinked entry is refused by name, the round-11 rule:
  # stage_release only ever publishes real directories and regular files.
  local release_walk=() release_node release_binaries=() walk_index=0
  local dotglob_was_set=0
  shopt -q dotglob && dotglob_was_set=1
  shopt -s dotglob
  if [[ -d "${libexec_root}/releases" ]]; then
    release_walk=("${libexec_root}/releases"/*)
  fi
  while (( walk_index < ${#release_walk[@]} )); do
    release_node="${release_walk[walk_index]}"
    walk_index=$((walk_index + 1))
    # An unmatched glob stays a literal pattern; nothing exists there.
    [[ -e "${release_node}" || -L "${release_node}" ]] || continue
    if [[ -L "${release_node}" ]]; then
      (( dotglob_was_set )) || shopt -u dotglob
      deploy_fail "retained release entry ${release_node} is a symlink; an entry that is itself a symlink is never published by stage_release -- refusing to trust the retained inventory"
    fi
    if [[ -d "${release_node}" ]]; then
      managed_roots+=("${release_node}")
      release_walk+=("${release_node}"/*)
    elif [[ -f "${release_node}" ]]; then
      release_binaries+=("${release_node}")
    fi
  done
  (( dotglob_was_set )) || shopt -u dotglob
  # Unit SOURCE files enter the ancestor walk alongside the declared
  # targets: a top-level unit or drop-in .conf that is a symlink to a
  # securely-owned file passes the trust-input file rule on the target
  # itself, but only this chain derivation (lexical parents plus the
  # recursively resolved target chains) judges the target's OWN parents --
  # a group/world-writable external parent lets another local user replace
  # the accepted unit source wholesale before the next manager start reads
  # it. Same file-chain contract the declared contracts use: the final
  # component resolves like any other, and the resulting file node is
  # skipped by the directory checks while every directory on the way is
  # judged.
  require_secure_ancestors "${home_dir}" "${managed_roots[@]}" \
    "${contract_destinations[@]}" "${unit_declared_roots[@]}" \
    "${declared_contracts[@]}" "${dropin_dirs[@]}" "${unit_source_files[@]}"
  require_secure_files "${home_dir}" "${contract_destinations[@]}" \
    "${declared_contracts[@]}"
  require_integrity_files "${home_dir}" "${unit_source_files[@]}" \
    "${release_binaries[@]}"
}

# open_transition_lock_fd LIBEXEC_ROOT -- open fd 9 on the lockfile, safely.
#
# The lock is legitimately taken BEFORE require_deployment_integrity (the
# integrity walk itself must run under the lock), so this open cannot lean
# on any prior validation -- with libexec_root gone group/world-writable,
# another local user could have swapped .transition-lock for a symlink to
# any service-user-writable file, and a truncating `exec 9>` would follow
# the link and destroy that target before the integrity check ever ran.
# bash cannot open O_NOFOLLOW, and it cannot inherit a descriptor a child
# helper opened (holding one in a coproc for the process lifetime trades a
# closed race for a lock that silently vanishes if the holder dies), so the
# open is made safe by construction instead:
#
#   1. The open uses APPEND mode (O_WRONLY|O_CREAT|O_APPEND) on both the
#      exclusive and shared sides. Nothing is ever written through fd 9 --
#      flock only needs a descriptor -- so this open can never truncate or
#      modify ANY target, whatever the path resolves to. The damage class
#      the truncating open enabled is gone unconditionally.
#   2. A pre-open lstat refuses an existing symlinked lock by name: the
#      deployment only ever creates the lock as a regular file, so a link
#      there is never legitimate.
#   3. A post-open recheck requires the descriptor actually opened to be
#      the very inode the pre-open lstat saw (or, when this open created
#      the file, the non-symlink regular file now at the path). A symlink
#      swapped into the lstat->open window therefore cannot leave the lock
#      held on an attacker-chosen file: the identities disagree and the
#      transition is refused before flock.
#
# Residual window, argued explicitly: between the lstat and the open,
# a swapped-in DANGLING symlink can cause O_CREAT to create an empty file
# at a path its owner could already write -- nothing is truncated, nothing
# is written, and the recheck then refuses the lock. That residue's
# precondition is a group/world-writable libexec_root, which the
# require_deployment_integrity call immediately following every
# acquire_transition_lock (and install's chmod 0700 preceding its lock)
# refuses -- so no transition ever proceeds from inside the window, and a
# host in that state is already fully compromised for the service account
# (the same writability lets helpers and releases be replaced wholesale).
open_transition_lock_fd() {
  local libexec_root="$1" lock_path pre_identity opened_identity post_identity
  lock_path="${libexec_root}/.transition-lock"
  if [[ -L "${lock_path}" ]]; then
    deploy_fail "transition lock ${lock_path} is a symlink; the deployment only ever creates it as a regular file -- refusing to open it"
  fi
  pre_identity=""
  if [[ -e "${lock_path}" ]]; then
    pre_identity="$(stat -c '%d:%i' "${lock_path}")" \
      || deploy_fail "cannot stat the deployment transition lock in ${libexec_root}"
  fi
  # Append mode: this open can never truncate anything, whatever the path
  # resolves to. No content is ever written through fd 9.
  exec 9>>"${lock_path}" \
    || deploy_fail "cannot open the deployment transition lock in ${libexec_root}"
  # fstat of what was actually opened: /proc/self/fd/9 resolves inside the
  # stat process, which inherits the descriptor.
  opened_identity="$(stat -Lc '%d:%i' /proc/self/fd/9)" \
    || deploy_fail "cannot stat the opened transition lock descriptor for ${libexec_root}"
  if [[ -n "${pre_identity}" ]]; then
    [[ "${opened_identity}" == "${pre_identity}" ]] \
      || deploy_fail "transition lock ${lock_path} changed identity while being opened; refusing to lock a substituted file"
  else
    [[ ! -L "${lock_path}" ]] \
      || deploy_fail "transition lock ${lock_path} became a symlink while being opened; refusing to lock a substituted file"
    post_identity="$(stat -c '%d:%i' "${lock_path}")" \
      || deploy_fail "cannot stat the deployment transition lock in ${libexec_root}"
    [[ "${opened_identity}" == "${post_identity}" ]] \
      || deploy_fail "transition lock ${lock_path} changed identity while being created; refusing to lock a substituted file"
  fi
}

# acquire_transition_lock LIBEXEC_ROOT
#
# One deployment-wide advisory lock, held for the remainder of the process
# (the descriptor stays open until exit), across every release state
# transition: snapshot, staging, both symlink writes, and the health gates.
# Two concurrent upgrades otherwise both snapshot the same current release,
# stage different targets, and interleave the previous/current writes --
# the loser then health-checks the winner's release and reports its own as
# installed. Non-blocking on purpose: a queued transition would run against
# a snapshot taken before the winner rewrote the links, so the only honest
# behavior is a named refusal. The open itself goes through
# open_transition_lock_fd: non-truncating, symlink-refusing.
acquire_transition_lock() {
  local libexec_root="$1"
  open_transition_lock_fd "${libexec_root}"
  flock -n 9 \
    || deploy_fail "another deployment transition holds the lock for ${libexec_root}; refusing to interleave release state -- retry when it completes"
}

# acquire_transition_lock_shared LIBEXEC_ROOT
#
# The reader's side of the transition lock: held SHARED for the remainder
# of the process, so concurrent digest reads coexist while any release
# transition -- which holds the lock exclusively across snapshot, staging,
# and both symlink writes -- excludes them. Without this, a digest read
# overlapping an upgrade (previous written before current) or a rollback
# (the opposite order) can capture an impossible pair such as both links
# naming one release: a document describing no deployment that ever
# existed, exactly where a cutover drift snapshot needs a stable one.
# Non-blocking like the exclusive side: a named refusal, never a silent
# queue. The open is the same non-truncating, symlink-refusing
# open_transition_lock_fd as the writer's -- the reader runs as the service
# user against the same swappable path and must not be usable as a
# truncation (or lock-on-foreign-file) oracle either.
acquire_transition_lock_shared() {
  local libexec_root="$1"
  open_transition_lock_fd "${libexec_root}"
  flock -s -n 9 \
    || deploy_fail "a deployment transition is in progress for ${libexec_root}; retry when it completes"
}

# require_release_link_target LIBEXEC_ROOT LINK_NAME -> the link's target
#
# The current/previous links are identity-bearing state the upgrade and
# rollback paths trust: their targets must be releases/<id> entries INSIDE
# the validated releases root (never absolute, never ..-escaping), and the
# named release directory must be a real directory -- stage_release only
# publishes real directories, so a symlink there is never legitimate and
# would route every later read through an unvalidated external chain.
# Diagnostics go to stderr; the validated target is the stdout protocol.
require_release_link_target() {
  local libexec_root="$1" link_name="$2" target
  target="$(readlink "${libexec_root}/${link_name}")" \
    || deploy_fail "cannot read the ${link_name} link"
  [[ "${target}" =~ ^releases/[0-9a-f]{12}$ ]] \
    || deploy_fail "${link_name} points at ${target}, not a releases/<id> entry inside this deployment; refusing to trust it"
  [[ ! -L "${libexec_root}/${target}" ]] \
    || deploy_fail "${link_name} target ${target} is itself a symlink; stage_release only publishes real directories, refusing to trust it"
  [[ -d "${libexec_root}/${target}" ]] \
    || deploy_fail "${link_name} target ${target} is not a directory; refusing to trust it"
  printf '%s\n' "${target}"
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
