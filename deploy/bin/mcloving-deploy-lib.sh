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

# THE ASSET MANIFEST. One list per class, here rather than in the installer,
# because the installer used to carry three hand-maintained copies of the
# same names (the changed-asset comparison, the helper install loop, the
# unit install loop) and every validator carried a fourth implicitly by
# globbing whatever happened to be on disk. A list that is written down
# twice is a list that rots; a list that is only ever globbed cannot notice
# a DELETION at all, which is exactly the gap this round closes.
# shellcheck disable=SC2034  # read by mcloving-install and the smoke suite
MCLOVING_DEPLOY_HELPERS=(
  mcloving-env-guard
  mcloving-health
  mcloving-db-init
  mcloving-deployed-digests
  mcloving-unit-command
  mcloving-rollback
  mcloving-upgrade
)
# Sourced rather than executed, so it is installed 0644 and listed apart.
# shellcheck disable=SC2034  # read by mcloving-install and the smoke suite
MCLOVING_DEPLOY_LIBRARY="mcloving-deploy-lib.sh"
# shellcheck disable=SC2034  # read by mcloving-install and the smoke suite
MCLOVING_DEPLOY_UNITS=(
  mcloving-db-init.service
  mcloving-controller.service
  mcloving-agent.service
)
# shellcheck disable=SC2034  # read by mcloving-install and the smoke suite
MCLOVING_DEPLOY_QUADLETS=(
  mcloving-postgres.container
  mcloving-postgres-data.volume
)
# shellcheck disable=SC2034  # read by mcloving-install and the smoke suite
MCLOVING_DEPLOY_CONTRACTS=(
  postgres.env
  db-init.env
  controller.env
  agent.env
)

deploy_fail() {
  echo "$(basename "$0"): $1" >&2
  exit 1
}

# deploy_notice MESSAGE -- a named OBSERVATION, not a refusal. Reserved for
# facts an operator should learn about a deployment that is nonetheless
# admissible: today, a drop-in for one of this deployment's units found in
# a root-owned system load path. Silence about those would be indefensible
# (systemd merges them) and refusing them would be wrong (an administrator
# placing one is doing their job), so they are validated like every other
# drop-in and additionally SAID OUT LOUD. stderr, so a caller parsing this
# tool's stdout as a protocol is unaffected.
deploy_notice() {
  echo "$(basename "$0"): notice: $1" >&2
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
    # A regular file, through the link when it is one -- mode, owner, and
    # readability all hold for an owner-only 0600 FIFO, but a contract that
    # is a FIFO blocks (or streams another process's bytes into) the next
    # read: systemd loading EnvironmentFile=, the guard's own parse, a key
    # read. Node type is identity, judged here rather than left to
    # whichever consumer happens to open the path first.
    if [[ ! -f "${file}" ]]; then
      offending+="${file} (not a regular file: $(stat -Lc '%F' "${file}" 2>/dev/null || echo "unknown node")) "
      continue
    fi
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
    deploy_fail "secret-bearing file(s) not owner-only, foreign-owned, unreadable, or not regular files: ${offending% }-- an unwritable-by-others AND readable-by-the-service-user contract is required; run chmod go-w (or restore ownership/readability) on them and retry"
  fi
}

# deployment_contract_path_variables SERVICE
#   -> "CLASS LINK-POLICY VARIABLE EXPECTED-KIND" lines
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
#
# EXPECTED-KIND is the same parity principle applied to NODE TYPE: "file"
# when the consumer opens the path as a file, "directory" when it opens or
# creates it as one. Mode and ownership say nothing about node type, so an
# owner-only FIFO passed every class check while the consuming binary
# blocked on it -- MCLOVING_AGENT_SESSION_RECEIPT_PATH reaches
# std::fs::read_to_string() in publish_authenticated_session_receipt()
# (bins/agent/src/lib.rs) behind a bare path.exists(), and a read-only open
# of a writer-less FIFO never returns, so the start probe stalls until
# TimeoutStartSec kills a unit whose contract the guard had just reported
# satisfied. The kinds below were read off the Rust rather than assumed:
#   MCLOVING_OBJECT_ROOT                 directory  FilesystemObjectStore::open
#                                                   (create_dir + is_dir check)
#   MCLOVING_WORKSPACE_ROOT              directory  create_dir_all, then a
#                                                   guard refusing non-directories
#   MCLOVING_AGENT_JOURNAL               file       rusqlite Connection::open
#   MCLOVING_AGENT_WORKSPACE_ROOT        directory  create_dir_all + is_dir
#   MCLOVING_AGENT_JOURNAL_PATH          file       rusqlite Connection::open
#   MCLOVING_AGENT_SESSION_RECEIPT_PATH  file       read_to_string, then rename
# Absence stays legal exactly where it already was: each of these is
# created on demand by its consumer, and the kind rule judges only a node
# that EXISTS. The secret and trust classes are all file-valued and carry
# regular-file refusals of their own already; the column is stated for
# them too, so the authority is complete rather than partial.
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
        "secret follow MCLOVING_AGENT_SERVER_KEY_PATH file" \
        "secret follow MCLOVING_AGENT_IDENTITY_BINDINGS_PATH file" \
        "secret nofollow MCLOVING_EFFECT_RUNTIME_PLAN file" \
        "trust follow MCLOVING_AGENT_SERVER_CERT_PATH file" \
        "trust follow MCLOVING_AGENT_CLIENT_CA_PATH file" \
        "trust nofollow MCLOVING_EFFECT_MAPPING_CATALOG file" \
        "state follow MCLOVING_OBJECT_ROOT directory" \
        "state follow MCLOVING_WORKSPACE_ROOT directory" \
        "state follow MCLOVING_AGENT_JOURNAL file"
      ;;
    agent)
      # The session receipt is an optional durable output the agent writes;
      # state-class like the journal, absence legal before first use.
      printf '%s\n' \
        "secret follow MCLOVING_AGENT_PRIVATE_KEY_PATH file" \
        "trust follow MCLOVING_CONTROLLER_CA_PATH file" \
        "trust follow MCLOVING_AGENT_CERTIFICATE_PATH file" \
        "state follow MCLOVING_AGENT_WORKSPACE_ROOT directory" \
        "state follow MCLOVING_AGENT_JOURNAL_PATH file" \
        "state follow MCLOVING_AGENT_SESSION_RECEIPT_PATH file"
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
    # Same node-type rule as the contract class: every path handed to this
    # rule is a file the next start reads or executes, and a FIFO or
    # device node here blocks or streams foreign bytes into that read.
    # The producers filter with -f already; this keeps the rule total
    # rather than trusting every caller's enumeration.
    if [[ ! -f "${file}" ]]; then
      offending+="${file} (not a regular file: $(stat -Lc '%F' "${file}" 2>/dev/null || echo "unknown node")) "
      continue
    fi
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
    deploy_fail "trust-input file(s) (unit, drop-in, or retained release binary) group- or world-writable, foreign-owned, unreadable, or not regular files: ${offending% }-- another local user could control what the next service start executes; run chmod go-w (or restore ownership) on them and retry"
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

deployment_data_root() {
  local home_dir="${1%/}" value="${XDG_DATA_HOME:-}"
  if [[ "${value}" == /* ]] && deployment_xdg_value_applies "${home_dir}" "${value}"; then
    printf '%s\n' "${value%/}"
  else
    printf '%s\n' "${home_dir}/.local/share"
  fi
}

# deployment_runtime_root HOME -> $XDG_RUNTIME_DIR as the user manager for
# HOME resolves it. Unlike the other bases this one has no in-home default:
# systemd's own fallback is /run/user/$UID, so an inherited value that does
# not speak for HOME (the same rule the other bases use) is replaced by
# /run/user/<the uid that owns HOME> rather than by a path under the home.
# A home whose owner cannot be stat-ed yields nothing at all, and the
# callers treat an empty base as "no such load path" -- the runtime tree is
# a tmpfs that may legitimately not exist.
deployment_runtime_root() {
  local home_dir="${1%/}" value="${XDG_RUNTIME_DIR:-}" home_uid
  if [[ "${value}" == /* ]] && deployment_xdg_value_applies "${home_dir}" "${value}"; then
    printf '%s\n' "${value%/}"
    return 0
  fi
  home_uid="$(stat -Lc '%u' "${home_dir}" 2>/dev/null)" || return 0
  [[ -n "${home_uid}" ]] || return 0
  printf '/run/user/%s\n' "${home_uid}"
}

# deployment_xdg_search_entries HOME VALUE DEFAULT_LIST SEMANTICS -> the
# absolute directories a colon-separated XDG SEARCH LIST contributes, one
# per line.
#
# SEMANTICS is "selection" (what systemd ACTUALLY searches) or "merge" (that
# plus the spec defaults). The distinction is the round-32 distinction one
# level up, and getting it backwards in either direction is a real defect:
#
#   selection -- a nonempty variable REPLACES the default list, exactly as
#     the XDG base directory spec says and as systemd implements. Verified
#     on systemd 255: with XDG_CONFIG_DIRS=/tmp/A,
#     `systemd-analyze --user unit-paths` drops /etc/xdg/systemd/user
#     entirely and puts /tmp/A/systemd/user in its position. A MAIN UNIT
#     FILE is selected by first match, so a union here would resolve to a
#     file systemd would never load -- worse than missing one, because the
#     lane would then report and validate the wrong "effective" unit and
#     miss the real shadow.
#
#   merge -- union with the defaults. DROP-INS are merged rather than
#     selected, so validating a directory systemd would not read costs
#     nothing while missing one it does read is the only outcome that
#     matters. This is the round-31 argument, which stands unchanged for
#     the merge use and was only ever wrong when applied to selection.
#
# The applicability rule is the same in both modes and unchanged: an
# inherited entry speaks for this deployment when the target home is the
# invoking user's own or when the entry lies inside the target home.
# Relative entries are dropped, as the spec and systemd's own lookup do.
# When the variable is set but NO entry applies -- an inherited value
# describing some other account while validating a scratch home -- the
# defaults stand, because the manager for that home would use its own
# environment and the spec default is the only estimate available here.
deployment_xdg_search_entries() {
  local home_dir="${1%/}" value="$2" default_list="$3" semantics="${4:-merge}"
  local set_state="${5:-unset}"
  local entry rest
  local -a adopted=()
  local -A search_seen=()
  rest="${value}"
  while [[ -n "${rest}" ]]; do
    entry="${rest%%:*}"
    if [[ "${entry}" == "${rest}" ]]; then
      rest=""
    else
      rest="${rest#*:}"
    fi
    [[ "${entry}" == /* ]] || continue
    entry="${entry%/}"
    [[ -n "${entry}" ]] || continue
    deployment_xdg_value_applies "${home_dir}" "${entry}" || continue
    [[ -z "${search_seen["${entry}"]:-}" ]] || continue
    search_seen["${entry}"]=1
    adopted+=("${entry}")
  done
  local -a defaults=()
  rest="${default_list}"
  while [[ -n "${rest}" ]]; do
    entry="${rest%%:*}"
    if [[ "${entry}" == "${rest}" ]]; then
      rest=""
    else
      rest="${rest#*:}"
    fi
    [[ "${entry}" == /* ]] || continue
    entry="${entry%/}"
    [[ -n "${entry}" ]] || continue
    defaults+=("${entry}")
  done
  if [[ ${#adopted[@]} -eq 0 ]]; then
    # SET-BUT-EMPTY is an EMPTY LIST to systemd, not "use the default" --
    # verified: XDG_CONFIG_DIRS= drops /etc/xdg/systemd/user from
    # `systemd-analyze --user unit-paths` entirely, where unsetting it keeps
    # the entry. The XDG spec says empty means default; systemd does not,
    # and systemd is what loads the units. This only speaks for the target
    # home when the environment describes that home's manager: an inherited
    # empty value seen while validating somebody else's home says nothing,
    # so the defaults stand there.
    if [[ "${set_state}" == "set" && -z "${value}" ]] \
      && deployment_xdg_value_applies "${home_dir}" "${home_dir}"; then
      return 0
    fi
    printf '%s\n' "${defaults[@]}"
    return 0
  fi
  printf '%s\n' "${adopted[@]}"
  if [[ "${semantics}" == "merge" ]]; then
    for entry in "${defaults[@]}"; do
      [[ -z "${search_seen["${entry}"]:-}" ]] || continue
      search_seen["${entry}"]=1
      printf '%s\n' "${entry}"
    done
  fi
  return 0
}


# The Quadlet source extensions this lane could ship, and the unit each
# generates. Quadlet does not install its sources as units: it GENERATES a
# .service and systemd applies drop-ins to the GENERATED name, so a
# discovery seeded only from the source basenames never sees
# mcloving-postgres.service.d at all.
#
# The mapping was read off the generator, not the manual: podman 4.9.3's
# /usr/libexec/podman/quadlet run over this deployment's own sources plus
# probes writes mcloving-postgres.service, mcloving-postgres-data-volume.service,
# mcloving-net-network.service and mcloving-img-image.service. The rule that
# falls out, and that podman-systemd.unit(5) documents:
#
#   <base>.container -> <base>.service        (no suffix)
#   <base>.kube      -> <base>.service        (no suffix)
#   <base>.volume    -> <base>-volume.service
#   <base>.network   -> <base>-network.service
#   <base>.image     -> <base>-image.service
#   <base>.build     -> <base>-build.service
#   <base>.pod       -> <base>-pod.service
#
# .kube, .build and .pod are stated from the manual rather than observed --
# podman 4.9.3 generates nothing for a .pod, which arrived in 5.0 -- and are
# enumerated anyway so a lane that starts shipping one is not a fresh gap.
# The suffixed names matter twice over: mcloving-postgres-data-volume.service
# also brings mcloving-postgres-data-.service.d and mcloving-postgres-.service.d
# into the dash-truncation forms below, which the source name never did.
MCLOVING_QUADLET_SOURCE_TYPES="container|volume|network|image|build|pod|kube"

# deployment_quadlet_generated_name SOURCE_BASENAME -> the .service name
# Quadlet generates for it, or nothing when the extension is not a Quadlet
# source type.
deployment_quadlet_generated_name() {
  local source_base="${1%.*}" source_type="${1##*.}"
  [[ -n "${source_base}" && "${source_base}" != "$1" ]] || return 0
  case "${source_type}" in
    container | kube) printf '%s.service\n' "${source_base}" ;;
    volume | network | image | build | pod)
      printf '%s-%s.service\n' "${source_base}" "${source_type}" ;;
    *) return 0 ;;
  esac
}

# deployment_unit_names UNIT_FILE... -> encoded items: every unit NAME whose
# drop-ins apply to this deployment. That is the basename of each source --
# a native .service, and a Quadlet source, which takes .container.d style
# drop-ins in the Quadlet search path -- PLUS the name Quadlet GENERATES for
# each Quadlet source, whose drop-ins live in the systemd unit load paths
# under the generated name and were previously enumerated nowhere.
deployment_unit_names() {
  local unit_file unit_base generated
  local -A name_seen=()
  for unit_file in "$@"; do
    [[ -f "${unit_file}" ]] || continue
    unit_base="${unit_file##*/}"
    [[ -n "${unit_base}" && "${unit_base}" == *.* ]] || continue
    if [[ -z "${name_seen["${unit_base}"]:-}" ]]; then
      name_seen["${unit_base}"]=1
      encode_path_item "${unit_base}"
    fi
    generated="$(deployment_quadlet_generated_name "${unit_base}")"
    [[ -n "${generated}" ]] || continue
    [[ -z "${name_seen["${generated}"]:-}" ]] || continue
    name_seen["${generated}"]=1
    encode_path_item "${generated}"
  done
  return 0
}

# require_usable_unit_search_path HOME -- refuse, by name and in the MAIN
# shell, any unit search path this deployment cannot resolve: a UnitPath
# the manager reports that will not split into absolute entries, or a
# relative entry in XDG_CONFIG_DIRS or XDG_DATA_DIRS.
#
# systemd does not drop a relative XDG search entry: it makes it absolute
# against the MANAGER'S WORKING DIRECTORY. Verified by running
# `systemd-analyze --user unit-paths` with XDG_CONFIG_DIRS=relative from
# two directories, which reported /tmp/relative/systemd/user and
# /usr/relative/systemd/user respectively.
#
# That is ambient-context substitution, and this deployment cannot resolve
# it: the validator does not run in the manager's working directory and has
# no way to learn it. Mirroring the behaviour with THIS process's cwd would
# resolve a different directory than systemd will, which for MAIN UNIT
# SELECTION means naming the wrong effective file -- the exact defect this
# round is closing, reintroduced from the other end. So it is refused by
# name, consistent with the guard's refusal of relative class paths, and
# the repair is to spell the entry absolutely.
require_usable_unit_search_path() {
  local home_dir="${1%/}" list_name list_value entry rest offending=""
  # The MANAGER's list first, where it answers: if UnitPath carries a
  # spelling this deployment cannot split into absolute entries, guessing
  # which directories systemd searches is exactly the modelling this round
  # removed. Refused loudly, in the main shell, before any derivation runs.
  if deployment_manager_speaks_for "${home_dir}"; then
    if ! deployment_manager_unit_path "${home_dir}" >/dev/null; then
      deploy_fail "the service manager reported a unit search path this deployment cannot split into absolute entries; refusing to guess which directories systemd searches -- report the UnitPath value ($(systemctl --user show -p UnitPath --value 2>/dev/null 9>&- | head -c 400)) with this failure"
    fi
  fi
  for list_name in XDG_CONFIG_DIRS XDG_DATA_DIRS; do
    [[ -v "${list_name}" ]] || continue
    list_value="${!list_name}"
    rest="${list_value}"
    while [[ -n "${rest}" ]]; do
      entry="${rest%%:*}"
      if [[ "${entry}" == "${rest}" ]]; then
        rest=""
      else
        rest="${rest#*:}"
      fi
      [[ -n "${entry}" ]] || continue
      [[ "${entry}" != /* ]] || continue
      offending+="${list_name} entry ${entry} "
    done
  done
  if [[ -n "${offending}" ]]; then
    deploy_fail "unit search list(s) carry a relative entry: ${offending% }-- systemd resolves a relative XDG search entry against the service manager's working directory, which this deployment cannot observe, so the unit file it would actually load cannot be determined; spell the entry as an absolute path and retry"
  fi
}

# ASKING THE MANAGER RATHER THAN MODELLING IT.
#
# Every derivation in this library reads the INVOKING SHELL's environment.
# The user manager that will actually start the services was started with
# its own, and the two need not agree: a manager whose XDG_CONFIG_DIRS
# includes /srv/units while the operator's shell leaves it unset makes this
# lane validate one tree while systemd loads another. That is the whole
# meta-class of the last several rounds -- validating what the lane
# computes instead of what systemd does -- so the answer is to stop
# computing where systemd will answer.
#
# What is authoritative, established on systemd 255 rather than assumed:
#
#   systemctl --user show -p UnitPath
#     The MANAGER'S OWN computed load path, in its own order. This is the
#     authority. Note what it is NOT: `systemd-analyze --user unit-paths`
#     RECOMPUTES the list from the CALLER's environment, so it agrees with
#     the manager only when the two environments agree. Proven by running
#     both with XDG_CONFIG_DIRS=/tmp/A in the shell -- analyze reported
#     /tmp/A/systemd/user in slot 6, the manager reported
#     /etc/xdg/systemd/user, because the manager never saw that variable.
#     The round-33 parity gate had been asserting against analyze; it now
#     asserts against UnitPath, which is the corrected oracle.
#
#   systemctl --user show UNIT -p LoadState -p UnitFileState -p FragmentPath
#     The manager's ANSWER for one unit: which file it actually loaded, and
#     whether the unit is masked. This sidesteps list derivation entirely
#     for the selection question, including precedence, replacement
#     semantics, and mask handling, none of which have to be modelled when
#     the manager will simply say.
#
#   systemctl --user show-environment
#     The manager's environment. Not needed once UnitPath is available --
#     feeding those variables back into a re-derivation would be modelling
#     again, one step removed -- so it is not used, and is recorded here
#     only because it was the obvious candidate.
#
# WHEN THE MANAGER CANNOT ANSWER -- a --no-systemd install, a container
# build, CI with no session, or simply a target home that is not the
# invoking user's -- the derivation stands as a documented FALLBACK. The
# two are never confused in diagnostics: deployment_unit_path_source
# reports "manager" or "derived", the transition says which it used, and a
# derived answer is never described as authoritative.
# deployment_manager_is_reachable -- 0 when a user manager answers at all.
#
# Deliberately separate from deployment_manager_speaks_for, because the two
# answer DIFFERENT questions. "Do this manager's unit search paths describe
# the deployment at HOME?" needs the identity check. "What environment is
# the unit named X running with?" does not: the answer is about that unit,
# the kernel gates /proc/PID/environ by uid anyway, and requiring a home
# match there would refuse a question the manager can answer perfectly well.
deployment_manager_is_reachable() {
  [[ "${MCLOVING_ASSUME_NO_MANAGER:-}" != "1" ]] || return 1
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl --user show -p UnitPath --value >/dev/null 2>&1 9>&- || return 1
  return 0
}

deployment_manager_speaks_for() {
  local home_dir="${1%/}" manager_home
  [[ "${MCLOVING_ASSUME_NO_MANAGER:-}" != "1" ]] || return 1
  command -v systemctl >/dev/null 2>&1 || return 1
  # WHOSE home does the running manager serve? Not "$HOME" -- that is the
  # CALLER's idea of it, and the caller is exactly whose environment this
  # round stopped trusting. The manager reports its own, so ask: this is
  # the one legitimate use of show-environment, for IDENTITY rather than
  # for path derivation. Feeding its XDG variables into a re-derivation
  # would be modelling again; reading which home it serves is how we learn
  # whether its answers describe THIS deployment at all.
  manager_home="$(systemctl --user show-environment 2>/dev/null 9>&- \
    | sed -n 's/^HOME=//p' | head -1)" || return 1
  [[ -n "${manager_home}" ]] || return 1
  [[ "${home_dir}" == "${manager_home%/}" ]] || return 1
  # 9>&- on every systemctl invocation: this library is called from INSIDE
  # the transition lock, fd 9 is that lock, and a child that inherits it
  # holds the lock for as long as it lives. The lane learned this once
  # already (the flock-inheritance gate leak); the manager probes are new
  # children in the locked region and must not reintroduce it.
  systemctl --user show -p UnitPath --value >/dev/null 2>&1 9>&- || return 1
  return 0
}

# deployment_unit_path_source HOME -> "manager" or "derived"
deployment_unit_path_source() {
  if deployment_manager_speaks_for "${1%/}"; then
    printf 'manager\n'
  else
    printf 'derived\n'
  fi
}

# deployment_manager_unit_path HOME -> encoded items: the manager's own
# ordered load path, or nothing when it cannot answer.
#
# The property is a space-separated string. Every entry systemd reports is
# absolute, so an entry that does not begin with "/" means the value
# carried a spelling this split does not model -- refused loudly rather
# than silently mis-split, the same rule the unit parser follows.
deployment_manager_unit_path() {
  local home_dir="${1%/}" raw entry
  deployment_manager_speaks_for "${home_dir}" || return 0
  raw="$(systemctl --user show -p UnitPath --value 2>/dev/null 9>&-)" || return 0
  [[ -n "${raw}" ]] || return 0
  for entry in ${raw}; do
    [[ -n "${entry}" ]] || continue
    # NOT a refusal here: this function runs inside command substitutions,
    # where deploy_fail would die with the subshell and leave the caller
    # continuing on partial output -- the round-27 lesson. The loud refusal
    # lives in require_usable_unit_search_path, which runs in the main
    # shell; this simply declines to answer so nothing half-parsed escapes.
    if [[ "${entry}" != /* ]]; then
      return 1
    fi
    encode_path_item "${entry}"
  done
  return 0
}

# deployment_manager_unit_answer HOME UNIT_NAME -> "LOADSTATE|UNITFILESTATE|FRAGMENT"
# on one line, or nothing when the manager cannot answer.
deployment_manager_unit_answer() {
  local home_dir="${1%/}" unit_name="$2" line key value
  local load_state="" file_state="" fragment=""
  deployment_manager_speaks_for "${home_dir}" || return 0
  [[ -n "${unit_name}" ]] || return 0
  # COMMAND substitution, not process substitution. Bash waits for the
  # former and does NOT wait for the latter, so a process-substitution child
  # can outlive the read loop -- and inside the transition lock that child
  # still holds fd 9, which makes the very next transition report the lock
  # as held. That is not hypothetical: it failed a suite run.
  local answer_raw
  answer_raw="$(systemctl --user show "${unit_name}" \
    -p LoadState -p UnitFileState -p FragmentPath 2>/dev/null 9>&-)" || answer_raw=""
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    case "${key}" in
      LoadState) load_state="${value}" ;;
      UnitFileState) file_state="${value}" ;;
      FragmentPath) fragment="${value}" ;;
    esac
  done <<<"${answer_raw}"
  printf '%s|%s|%s\n' "${load_state}" "${file_state}" "${fragment}"
  return 0
}

# deployment_manager_config_root HOME -> the XDG configuration base the
# RUNNING user manager uses, or nothing when it cannot be established.
#
# Round 34 made the manager authoritative for what systemd READS. Install
# needs the same authority for where the deployment WRITES, and the failure
# there is worse: a manager started with a different XDG_CONFIG_HOME means
# units land in a directory it never searches, daemon-reload finds nothing,
# and the deployment silently does not exist as far as systemd is concerned.
# No refusal, no error -- just an install that did nothing.
#
# The variable is read from the manager's own environment rather than the
# caller's, and is then GROUNDED in the manager's own UnitPath: the derived
# <base>/systemd/user must actually appear in the list the manager searches.
# That is what keeps this from being round 34's rejected idea of feeding
# show-environment back into a re-derivation -- the variable proposes, the
# manager's list confirms, and a disagreement yields nothing rather than a
# guess.
deployment_manager_config_root() {
  local home_dir="${1%/}" manager_config candidate encoded decoded path_list
  deployment_manager_speaks_for "${home_dir}" || return 1
  manager_config="$(systemctl --user show-environment 2>/dev/null 9>&- \
    | sed -n 's/^XDG_CONFIG_HOME=//p' | head -1)" || return 1
  [[ "${manager_config}" == /* ]] || manager_config="${home_dir}/.config"
  manager_config="${manager_config%/}"
  candidate="${manager_config}/systemd/user"
  # Command substitution, not process substitution: this runs inside the
  # transition lock and a producer left alive would hold fd 9 (round 34).
  path_list="$(deployment_manager_unit_path "${home_dir}")" || return 1
  while IFS= read -r encoded; do
    [[ -n "${encoded}" ]] || continue
    decode_path_item_into decoded "${encoded}"
    if [[ "${decoded}" == "${candidate}" ]]; then
      printf '%s\n' "${manager_config}"
      return 0
    fi
  done <<<"${path_list}"
  return 1
}

# deployment_effective_config_root HOME -> the configuration base this
# deployment should read from and write to: the manager's where it can be
# established, the caller's derivation otherwise.
deployment_effective_config_root() {
  local home_dir="${1%/}" manager_root
  if manager_root="$(deployment_manager_config_root "${home_dir}")" \
    && [[ -n "${manager_root}" ]]; then
    printf '%s\n' "${manager_root}"
    return 0
  fi
  deployment_config_root "${home_dir}"
}

# deployment_config_root_source HOME -> "manager" or "derived"
deployment_config_root_source() {
  if deployment_manager_config_root "${1%/}" >/dev/null 2>&1; then
    printf 'manager\n'
  else
    printf 'derived\n'
  fi
}

# deployment_unit_load_paths HOME CLASS FAMILY [SEMANTICS] -> encoded
# items: the base directories the manager searches, IN SYSTEMD'S OWN
# PRECEDENCE ORDER, whether or not they exist.
#
# CLASS is "user" (writable by the service account), "system" (root-owned),
# or "all". FAMILY is "systemd" or "quadlet". SEMANTICS is "selection" --
# exactly what systemd searches -- or "merge" (the default), which is that
# list plus the XDG spec defaults a nonempty variable replaced.
#
# WHY TWO LISTS. A drop-in is MERGED, so a union costs only the validation
# of a file nothing reads. A MAIN UNIT FILE is SELECTED by first match, so
# a union is actively wrong: it can name a file systemd would never load,
# which is worse than missing one because the lane would then report and
# validate the wrong "effective" unit and miss the real shadow. The merge
# list is a strict superset of the selection list, so nothing that was
# validated before stops being validated.
#
# THE MODEL WAS READ OFF THE MANAGER, not the manual, and reproduces
# `systemd-analyze --user unit-paths` on systemd 255 exactly under the
# default environment, under XDG_CONFIG_DIRS overrides, and under
# XDG_DATA_DIRS overrides:
#
#   * XDG_CONFIG_DIRS is pure replacement. Its entries occupy one slot
#     between the config home and /etc/systemd/user, and a nonempty value
#     removes /etc/xdg/systemd/user entirely.
#   * XDG_DATA_DIRS is replacement TOO, but its spec defaults happen to be
#     re-added by systemd's own hardcoded vendor tail, so membership looks
#     unchanged while the ORDER moves. With XDG_DATA_DIRS=/tmp/D the
#     manager reports /tmp/D, then /usr/local/lib, /usr/local/share,
#     /usr/lib, /usr/share -- not the default's /usr/local/share,
#     /usr/share, /usr/local/lib, /usr/lib. Order decides selection, so the
#     vendor tail is spelled out here and deduplicated FIRST-WINS against
#     everything already emitted, which is what produces both orderings
#     from one derivation.
deployment_unit_load_paths() {
  local home_dir="${1%/}" want_class="$2" family="$3" semantics="${4:-merge}"
  local config_base data_base runtime_base home_uid
  config_base="$(deployment_config_root "${home_dir}")"
  data_base="$(deployment_data_root "${home_dir}")"
  runtime_base="$(deployment_runtime_root "${home_dir}")"
  home_uid="$(stat -Lc '%u' "${home_dir}" 2>/dev/null)" || home_uid=""
  # Two parallel arrays rather than one classified string: a path may carry
  # any byte, and pairing by index keeps the transport convention intact.
  local -a ordered_paths=() ordered_class=()
  local -A load_path_seen=()
  local search_entry

  load_path_add() { # PATH CLASS -- first occurrence wins, as systemd dedups
    [[ -n "$1" ]] || return 0
    [[ -z "${load_path_seen["$1"]:-}" ]] || return 0
    load_path_seen["$1"]=1
    ordered_paths+=("$1")
    ordered_class+=("$2")
  }

  load_path_add_search() { # BASE_DIR -- classified by where it is
    if [[ "$1" == "${home_dir}" || "$1" == "${home_dir}"/* ]]; then
      load_path_add "$1/systemd/user" user
    else
      load_path_add "$1/systemd/user" system
    fi
  }

  # THE MANAGER'S OWN LIST, when it can answer, in place of every rule
  # below. It already reflects that manager's environment, its precedence,
  # and the replacement semantics -- none of which have to be modelled when
  # the authority will simply say. Classification is still ours, because
  # UnitPath carries no notion of who may write where: inside the home or
  # inside the runtime tree is service-account-writable, everything else is
  # root-owned in practice.
  local manager_entry manager_used=0 manager_raw=""
  if [[ "${family}" == "systemd" ]]; then
    # Command substitution for the same reason: a process-substitution child
    # spawned inside the transition lock outlives the loop and keeps fd 9.
    manager_raw="$(deployment_manager_unit_path "${home_dir}")"
    while IFS= read -r search_entry; do
      [[ -n "${search_entry}" ]] || continue
      decode_path_item_into manager_entry "${search_entry}"
      manager_used=1
      if [[ "${manager_entry}" == "${home_dir}" || "${manager_entry}" == "${home_dir}"/* ]] \
        || { [[ -n "${runtime_base}" ]] \
          && [[ "${manager_entry}" == "${runtime_base}" || "${manager_entry}" == "${runtime_base}"/* ]]; }; then
        load_path_add "${manager_entry}" user
      else
        load_path_add "${manager_entry}" system
      fi
    done <<<"${manager_raw}"
  fi
  if (( manager_used )); then
    unset -f load_path_add load_path_add_search
    local manager_index=0
    while (( manager_index < ${#ordered_paths[@]} )); do
      if [[ "${want_class}" == "all" || "${want_class}" == "${ordered_class[manager_index]}" ]]; then
        encode_path_item "${ordered_paths[manager_index]}"
      fi
      manager_index=$((manager_index + 1))
    done
    return 0
  fi
  case "${family}" in
    systemd)
      load_path_add "${config_base}/systemd/user.control" user
      if [[ -n "${runtime_base}" ]]; then
        load_path_add "${runtime_base}/systemd/user.control" user
        load_path_add "${runtime_base}/systemd/transient" user
        load_path_add "${runtime_base}/systemd/generator.early" user
      fi
      load_path_add "${config_base}/systemd/user" user
      while IFS= read -r search_entry; do
        [[ -n "${search_entry}" ]] || continue
        load_path_add_search "${search_entry}"
      done < <(deployment_xdg_search_entries "${home_dir}" "${XDG_CONFIG_DIRS:-}" \
        "/etc/xdg" "${semantics}" "${XDG_CONFIG_DIRS+set}")
      load_path_add "/etc/systemd/user" system
      if [[ -n "${runtime_base}" ]]; then
        load_path_add "${runtime_base}/systemd/user" user
      fi
      load_path_add "/run/systemd/user" system
      if [[ -n "${runtime_base}" ]]; then
        load_path_add "${runtime_base}/systemd/generator" user
      fi
      load_path_add "${data_base}/systemd/user" user
      while IFS= read -r search_entry; do
        [[ -n "${search_entry}" ]] || continue
        load_path_add_search "${search_entry}"
      done < <(deployment_xdg_search_entries "${home_dir}" "${XDG_DATA_DIRS:-}" \
        "/usr/local/share:/usr/share" "${semantics}" "${XDG_DATA_DIRS+set}")
      # systemd's own hardcoded vendor tail, in its order. Under the default
      # environment every share entry here is already present from
      # XDG_DATA_DIRS and is dropped by the first-wins dedup, which is why
      # the default ordering comes out share-then-lib and the overridden one
      # comes out lib-and-share interleaved.
      load_path_add "/usr/local/lib/systemd/user" system
      load_path_add "/usr/local/share/systemd/user" system
      load_path_add "/usr/lib/systemd/user" system
      load_path_add "/usr/share/systemd/user" system
      if [[ -n "${runtime_base}" ]]; then
        load_path_add "${runtime_base}/systemd/generator.late" user
      fi
      ;;
    quadlet)
      # podman-systemd.unit(5) rootless search path, most specific first.
      load_path_add "${config_base}/containers/systemd" user
      [[ -n "${runtime_base}" ]] \
        && load_path_add "${runtime_base}/containers/systemd" user
      [[ -n "${home_uid}" ]] \
        && load_path_add "/etc/containers/systemd/users/${home_uid}" system
      load_path_add "/etc/containers/systemd/users" system
      load_path_add "/etc/containers/systemd" system
      load_path_add "/usr/share/containers/systemd" system
      ;;
    *)
      unset -f load_path_add load_path_add_search
      return 0
      ;;
  esac
  unset -f load_path_add load_path_add_search

  local index=0
  while (( index < ${#ordered_paths[@]} )); do
    if [[ "${want_class}" == "all" || "${want_class}" == "${ordered_class[index]}" ]]; then
      encode_path_item "${ordered_paths[index]}"
    fi
    index=$((index + 1))
  done
  return 0
}

# deployment_effective_unit_file HOME UNIT_NAME -> one encoded item: the
# file systemd would ACTUALLY load for UNIT_NAME, or nothing when no load
# path holds it.
#
# A main unit file is not merged like a drop-in; it is SELECTED. The first
# load path in precedence order that holds the name wins and every lower
# one is ignored entirely. Seeding validation from the installed
# ${unit_root} files alone therefore validated a file systemd may not run:
# a 0666 mcloving-controller.service dropped into ~/.config/systemd/user.control
# -- which outranks ~/.config/systemd/user -- shadows the installed unit
# completely, and its ExecStart is what the next restart executes.
#
# Absence is normal and silent: a Quadlet-generated name has no file on
# disk until the generator runs, and the deployment's own units resolve to
# themselves.
deployment_effective_unit_file() {
  local home_dir="${1%/}" unit_name="$2" family candidate
  local encoded_base decoded_base
  [[ -n "${unit_name}" ]] || return 0
  case "${unit_name}" in
    *.service) family="systemd" ;;
    *) family="quadlet" ;;
  esac
  # ASK, where the manager can answer: FragmentPath IS the selection, with
  # precedence, replacement semantics and masking already applied by the
  # thing that will start the service.
  local manager_answer manager_fragment
  if deployment_manager_speaks_for "${home_dir}" && [[ "${family}" == "systemd" ]]; then
    manager_answer="$(deployment_manager_unit_answer "${home_dir}" "${unit_name}")"
    manager_fragment="${manager_answer##*|}"
    if [[ -n "${manager_fragment}" ]]; then
      encode_path_item "${manager_fragment}"
      return 0
    fi
    # An empty FragmentPath with the manager answering means the manager
    # knows of no file for this name. Falling through to the derivation
    # would contradict the authority, so nothing is emitted.
    return 0
  fi
  while IFS= read -r encoded_base; do
    [[ -n "${encoded_base}" ]] || continue
    decode_path_item_into decoded_base "${encoded_base}"
    candidate="${decoded_base}/${unit_name}"
    # ANY existing candidate, not merely a regular file. A MASK is a
    # symlink to /dev/null: -f follows it, sees a character device, says
    # no, and the resolver used to fall through to a lower-priority file
    # systemd would never load -- reporting a unit as live when it cannot
    # start at all. The node kind is classified by the caller
    # (deployment_unit_file_kind) rather than filtered here, so a mask and
    # a tampered node are both visible instead of invisible.
    if [[ -e "${candidate}" || -L "${candidate}" ]]; then
      encode_path_item "${candidate}"
      return 0
    fi
  done < <(deployment_unit_load_paths "${home_dir}" all "${family}" selection)
  return 0
}

# deployment_unit_file_kind PATH -> "regular", "mask", "absent", or "other"
#
# systemd masks a unit by symlinking its name to /dev/null; the unit then
# cannot start at all. That is not a variant of "shadowed by an override" --
# an override still runs something -- so it is classified apart and its
# consequence is decided by the caller.
deployment_unit_file_kind() {
  local candidate="$1" target
  if [[ -L "${candidate}" ]]; then
    target="$(readlink "${candidate}")"
    if [[ "${target}" == "/dev/null" ]]; then
      printf 'mask\n'
      return 0
    fi
  fi
  if [[ -f "${candidate}" ]]; then
    printf 'regular\n'
  elif [[ -e "${candidate}" || -L "${candidate}" ]]; then
    printf 'other\n'
  else
    printf 'absent\n'
  fi
  return 0
}

# deployment_shadowing_unit_files HOME INSTALLED_UNIT_FILE... -> encoded
# items: for every unit NAME this deployment owns, the file systemd would
# actually load when that file is NOT one of the installed ones.
#
# One derivation for the transition's validation and for the canonical
# digest document, so what is judged and what is recorded cannot drift.
# Names come from deployment_unit_names, so Quadlet-GENERATED names are
# covered too: a planted mcloving-postgres.service shadows a unit that has
# no installed file at all, which is the case an installed-file comparison
# would never notice.
deployment_shadowing_unit_files() {
  local home_dir="${1%/}" unit_file decoded_name effective_unit_file
  local encoded_item encoded_effective
  shift
  [[ $# -gt 0 ]] || return 0
  local -A shadow_seen=()
  for unit_file in "$@"; do
    [[ -f "${unit_file}" ]] || continue
    shadow_seen["${unit_file}"]=1
  done
  while IFS= read -r encoded_item; do
    [[ -n "${encoded_item}" ]] || continue
    decode_path_item_into decoded_name "${encoded_item}"
    encoded_effective="$(deployment_effective_unit_file "${home_dir}" "${decoded_name}")"
    [[ -n "${encoded_effective}" ]] || continue
    decode_path_item_into effective_unit_file "${encoded_effective}"
    [[ -z "${shadow_seen["${effective_unit_file}"]:-}" ]] || continue
    shadow_seen["${effective_unit_file}"]=1
    encode_path_item "${effective_unit_file}"
  done < <(deployment_unit_names "$@")
  return 0
}

# deployment_unit_dropin_dirs HOME [--user|--system|--all] UNIT_FILE...
#   -> encoded items: every drop-in DIRECTORY systemd consults for these
#   units that EXISTS on disk, across every load path, deduplicated.
#
# Two independent enumerations meet here.
#
# WHICH DIRECTORIES are searched: the directory each source file itself
# lives in, plus every user-unit load path (systemd.unit(5) Table 2) for
# .service names and every Quadlet search path for Quadlet source names.
# Restricting the search to the main unit's own directory was the gap: a
# drop-in in /etc/systemd/user or in the service account's own
# $XDG_RUNTIME_DIR/systemd/user is merged by systemd all the same.
#
# WHICH FORMS are built in each of them, for a name spelled NAME.TYPE:
#
#   TYPE.d                 type-wide -- applies to EVERY unit of that type,
#                          so "service.d" applies to all three services
#   PREFIX-.TYPE.d         dash-truncated name prefixes, truncated at EVERY
#                          dash and not just the first: systemd walks
#                          foo-bar-baz.service -> foo-bar-.service.d ->
#                          foo-.service.d, so "mcloving-.service.d" applies
#                          to every unit this deployment ships
#   BASE@.TYPE.d           the template directory of an instantiated
#                          BASE@INSTANCE unit (none are shipped today; the
#                          form is enumerated so adding one is not a gap)
#   NAME.TYPE.d            the exact unit directory
#
# Precedence among paths and among forms is systemd's business and
# irrelevant here: validation is ADDITIVE, so the union is what must be
# secured and parsed. Where a given systemd or podman version consults
# FEWER of these than are enumerated, the cost is validating a file nothing
# reads -- the safe direction; the dangerous direction is one that is
# honoured and never seen.
#
# Only directories that EXIST are emitted. For the deployment's own
# configuration root that is not a gap, because the root is a managed root
# under the ancestor rule and no other local user can create one. For the
# other user-writable load paths the bound is weaker and is stated rather
# than implied: the load path directories THEMSELVES join the ancestor walk
# when they exist (see require_deployment_integrity), which keeps another
# local user from creating a drop-in directory in them, but nothing here
# prevents the SERVICE ACCOUNT from creating one -- that account is the
# deployment's own trust level, and a compromise of it is outside what a
# filesystem-integrity gate can bound.
deployment_unit_dropin_dirs() {
  local home_dir="${1%/}" want_class="all"
  shift
  case "${1:-}" in
    --user | --system | --all) want_class="${1#--}"; shift ;;
  esac
  local unit_file unit_base unit_type unit_name prefix_part rest
  local dropin_candidate base_dir encoded_item decoded_item
  local -A dropin_seen=()
  local -a dropin_forms=()
  local -a service_names=() quadlet_names=()
  local -a systemd_bases=() quadlet_bases=() own_bases=()
  local -A own_seen=()
  while IFS= read -r encoded_item; do
    [[ -n "${encoded_item}" ]] || continue
    decode_path_item_into decoded_item "${encoded_item}"
    case "${decoded_item}" in
      *.service) service_names+=("${decoded_item}") ;;
      *) quadlet_names+=("${decoded_item}") ;;
    esac
  done < <(deployment_unit_names "$@")
  [[ ${#service_names[@]} -gt 0 || ${#quadlet_names[@]} -gt 0 ]] || return 0
  # The directory a source actually lives in is searched as part of the
  # USER class: it is the deployment's own tree, and in a real installation
  # it IS one of the user-writable load paths below. It must NOT join the
  # system class -- a --system query exists to name the drop-ins that come
  # from OUTSIDE the deployment, and reporting the deployment's own config
  # root among them would make that notice meaningless noise.
  if [[ "${want_class}" == "user" || "${want_class}" == "all" ]]; then
  for unit_file in "$@"; do
    [[ -f "${unit_file}" && "${unit_file}" == */* ]] || continue
    base_dir="${unit_file%/*}"
    [[ -z "${own_seen["${base_dir}"]:-}" ]] || continue
    own_seen["${base_dir}"]=1
    own_bases+=("${base_dir}")
  done
  fi
  while IFS= read -r encoded_item; do
    [[ -n "${encoded_item}" ]] || continue
    decode_path_item_into decoded_item "${encoded_item}"
    systemd_bases+=("${decoded_item}")
  done < <(deployment_unit_load_paths "${home_dir}" "${want_class}" systemd)
  while IFS= read -r encoded_item; do
    [[ -n "${encoded_item}" ]] || continue
    decode_path_item_into decoded_item "${encoded_item}"
    quadlet_bases+=("${decoded_item}")
  done < <(deployment_unit_load_paths "${home_dir}" "${want_class}" quadlet)
  systemd_bases+=("${own_bases[@]}")
  quadlet_bases+=("${own_bases[@]}")

  deployment_dropin_forms_for() { # BASE_DIR UNIT_NAME
    local forms_base="${1%/}" forms_name="$2"
    unit_type="${forms_name##*.}"
    unit_name="${forms_name%.*}"
    [[ -n "${unit_type}" && -n "${unit_name}" ]] || return 0
    dropin_forms=("${forms_base}/${unit_type}.d")
    prefix_part="${unit_name%%@*}"
    if [[ "${unit_name}" == *@* ]]; then
      dropin_forms+=("${forms_base}/${prefix_part}@.${unit_type}.d")
    fi
    # Truncate at every dash, right to left, exactly as systemd's
    # unit_name_build_prefixes does. An empty prefix ends the walk:
    # systemd builds no drop-in directory for it.
    rest="${prefix_part}"
    while [[ "${rest}" == *-* ]]; do
      rest="${rest%-*}"
      [[ -n "${rest}" ]] || break
      dropin_forms+=("${forms_base}/${rest}-.${unit_type}.d")
    done
    dropin_forms+=("${forms_base}/${unit_name}.${unit_type}.d")
    for dropin_candidate in "${dropin_forms[@]}"; do
      [[ -d "${dropin_candidate}" ]] || continue
      [[ -z "${dropin_seen["${dropin_candidate}"]:-}" ]] || continue
      dropin_seen["${dropin_candidate}"]=1
      encode_path_item "${dropin_candidate}"
    done
  }

  for base_dir in "${systemd_bases[@]}"; do
    [[ -d "${base_dir}" ]] || continue
    for unit_base in "${service_names[@]}"; do
      deployment_dropin_forms_for "${base_dir}" "${unit_base}"
    done
  done
  for base_dir in "${quadlet_bases[@]}"; do
    [[ -d "${base_dir}" ]] || continue
    for unit_base in "${quadlet_names[@]}"; do
      deployment_dropin_forms_for "${base_dir}" "${unit_base}"
    done
  done
  unset -f deployment_dropin_forms_for
  return 0
}

# deployment_unit_source_files HOME UNIT_FILE... -> encoded items: every
# file the unit parse READS -- the unit files themselves plus the *.conf of
# every drop-in directory systemd consults for them, across every load path
# (deployment_unit_dropin_dirs). One enumeration for the parser and for
# source validation, so what is parsed and what is judged cannot diverge:
# everything the parser reads is an execution vector (ExecStart lives in
# these files).
deployment_unit_source_files() {
  local home_dir="$1"
  shift
  local unit_file dropin dropin_dir encoded_dropin_dir
  for unit_file in "$@"; do
    [[ -f "${unit_file}" ]] || continue
    encode_path_item "${unit_file}"
  done
  while IFS= read -r encoded_dropin_dir; do
    [[ -n "${encoded_dropin_dir}" ]] || continue
    decode_path_item_into dropin_dir "${encoded_dropin_dir}"
    for dropin in "${dropin_dir}"/*.conf; do
      [[ -f "${dropin}" ]] && encode_path_item "${dropin}"
    done
  done < <(deployment_unit_dropin_dirs "${home_dir}" "$@")
  return 0
}

# The path-bearing unit directives this deployment extracts. One list,
# shared by the assignment parser's loud pre-check, both extraction
# consumers, and the suite's parse-coverage gate.
# shellcheck disable=SC2034  # read by the smoke suite's coverage gate too
MCLOVING_UNIT_PATH_DIRECTIVES="EnvironmentFile|StateDirectory|RuntimeDirectory|LogsDirectory|CacheDirectory|WorkingDirectory|Volume"

# The command directives that name an EXECUTABLE the transition runs.
# Separate from the path list above because their VALUE SYNTAX differs --
# a command line, not a bare path -- so extraction and the loud pre-check
# treat them differently, and because they are validated as trust-input
# FILES rather than as contracts. systemd.service(5) documents the family;
# every member is executed by the service manager as the service user, and
# an override resetting any of them to an external path is code the next
# restart runs.
# shellcheck disable=SC2034  # read by the smoke suite's coverage gate too
MCLOVING_UNIT_EXEC_DIRECTIVES="ExecStart|ExecStartPre|ExecStartPost|ExecReload|ExecStop|ExecStopPost|ExecCondition"

# One backslash, named: spelling it inline in a [[ pattern draws
# quoting advisories from the linter, and the continuation check reads better
# against a named constant anyway.
MCLOVING_BACKSLASH=$'\\'

# deployment_unit_assignment_lines FILE... -> "KEY=VALUE" lines, parsed the
# way systemd parses assignments (systemd.syntax(7), config_parse_line):
# leading and trailing whitespace of the line is stripped; empty lines and
# lines starting with '#' or ';' are comments; '[...]' lines are section
# headers; the line splits at the FIRST '='; whitespace immediately before
# and after the '=' is stripped. `EnvironmentFile = /path` and
# `<TAB>StateDirectory =<TAB>name` are therefore the same declarations
# systemd consumes, where the previous exact-prefix greps emitted nothing
# and the declared path escaped validation entirely. This is the ONE
# parsing helper every directive extraction goes through -- per-key
# regexes are how one legal spelling escapes one consumer.
#
# Deliberately NOT modeled, and refused loudly by
# require_parseable_unit_sources instead of silently mis-extracted: line
# continuations (a trailing '\' joins lines in systemd, so a fragment
# parse would validate half a value) and quote characters in path-bearing
# values (systemd's extract_first_word unquotes list-valued path options,
# so "a b" would word-split here into two wrong paths that do not exist
# and silently skip validation). A mid-line '#' is NOT a comment to
# systemd and stays part of the value, mirrored here.
deployment_unit_assignment_lines() {
  local file line key value
  for file in "$@"; do
    [[ -f "${file}" ]] || continue
    while IFS= read -r line || [[ -n "${line}" ]]; do
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line%"${line##*[![:space:]]}"}"
      case "${line}" in
        '' | '#'* | ';'* | '['*) continue ;;
      esac
      [[ "${line}" == *=* ]] || continue
      key="${line%%=*}"
      value="${line#*=}"
      key="${key%"${key##*[![:space:]]}"}"
      value="${value#"${value%%[![:space:]]*}"}"
      [[ -n "${key}" ]] || continue
      printf '%s=%s\n' "${key}" "${value}"
    done < "${file}"
  done
  return 0
}

# require_parseable_unit_sources HOME UNIT_FILE... -- the loud half of the
# parsing contract, run in the MAIN shell (never inside a command
# substitution, where deploy_fail dies with the subshell and the caller
# would continue on partial output): any construct systemd would consume
# but the assignment parser does not model is a NAMED refusal, never a
# silent partial validation. Five constructs qualify: line continuations;
# quote characters in the values of path-bearing directives; C-style
# backslash escapes in EITHER family, which systemd unescapes and this
# parser deliberately does not; a unit
# specifier other than %h in either family (this deployment expands %h and
# nothing else, and an unexpanded %t or %S would either be dropped as
# non-absolute or validated at a literal path nothing ever uses); and any
# Exec* command line whose EXECUTABLE this parser cannot confidently
# extract -- a quoted or backslash-escaped executable, or one that is not
# absolute after %h (systemd searches a bare filename in its own binary
# path, which this deployment has no way to resolve or secure).
#
# The refusal is the class-closing half of the Exec fix: extraction that
# quietly declined to model a spelling is exactly how an execution vector
# escapes the walk, so every spelling is either extracted or named.
require_parseable_unit_sources() {
  local home_dir="${1%/}"
  shift
  local file line key value encoded_source exec_value exec_token specifier_probe
  local source_files=()
  while IFS= read -r encoded_source; do
    [[ -n "${encoded_source}" ]] || continue
    decode_path_item_into file "${encoded_source}"
    source_files+=("${file}")
  done < <(deployment_unit_source_files "${home_dir}" "$@")
  [[ ${#source_files[@]} -gt 0 ]] || return 0
  for file in "${source_files[@]}"; do
    while IFS= read -r line || [[ -n "${line}" ]]; do
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line%"${line##*[![:space:]]}"}"
      case "${line}" in
        '' | '#'* | ';'* | '['*) continue ;;
      esac
      if [[ "${line}" == *"${MCLOVING_BACKSLASH}" ]]; then
        deploy_fail "unit source ${file} ends a line with the continuation backslash; systemd joins continued lines but this deployment's parser does not model that, and validating a fragment of the merged directive would be silent under-validation -- rewrite the directive on one line and retry"
      fi
      [[ "${line}" == *=* ]] || continue
      key="${line%%=*}"
      key="${key%"${key##*[![:space:]]}"}"
      value="${line#*=}"
      value="${value#"${value%%[![:space:]]*}"}"
      if [[ "${key}" =~ ^(${MCLOVING_UNIT_PATH_DIRECTIVES})$ ]]; then
        if [[ "${value}" == *[\"\']* ]]; then
          deploy_fail "unit source ${file} declares ${key} with a quote character in its value; systemd unquotes path values but this deployment's parser does not model quoting, and word-splitting a quoted path would validate paths that do not exist -- spell the path unquoted and retry"
        fi
        # C-style escapes, refused rather than unescaped -- the same rule
        # the Exec family has carried since round 29, now uniform across
        # both families. systemd runs config values through cunescape,
        # which understands the whole C escape set (\n, \t, \\, \s, the
        # hex \xNN, octal \NNN, and \uNNNN / \UNNNNNNNN), so validating the
        # LITERAL backslash spelling means this deployment and systemd
        # disagree about which file is loaded.
        # EnvironmentFile=/srv/secure/evil\x2eenv is the sharp case: the
        # literal does not exist, so the contract rule skipped it, while
        # systemd loaded /srv/secure/evil.env -- attacker-writable and
        # never judged.
        #
        # Refusal beats reimplementation. A PARTIAL unescape that disagrees
        # with cunescape anywhere is WORSE than no unescape at all: it
        # would validate a third path, neither the literal nor the one
        # systemd loads, and the disagreement would be silent. No shipped
        # unit needs an escape, and a path carrying an awkward byte can be
        # spelled literally.
        if [[ "${value}" == *"${MCLOVING_BACKSLASH}"* ]]; then
          deploy_fail "unit source ${file} declares ${key} with a backslash escape in its value (${value}); systemd unescapes C-style escapes before loading the path but this parser deliberately does not model that, so validation and systemd would disagree about which file is loaded -- spell the path without escapes and retry"
        fi
        # %h is the ONE specifier this deployment expands. Any other --
        # %t, %S, %i, or the literal-percent %% -- survives expansion and
        # is then either dropped as non-absolute or judged at a path
        # systemd never uses, both of them silent under-validation.
        specifier_probe="${value//%h/}"
        if [[ "${specifier_probe}" == *%* ]]; then
          deploy_fail "unit source ${file} declares ${key} with a unit specifier other than %h in its value (${value}); this deployment expands %h and nothing else, so the declared path would be validated at a spelling systemd never resolves to -- spell the path with %h or an absolute prefix and retry"
        fi
      fi
      if [[ "${key}" =~ ^(${MCLOVING_UNIT_EXEC_DIRECTIVES})$ ]]; then
        # An EMPTY assignment is systemd's legal reset -- it declares no
        # command at all, so there is nothing to extract and nothing to
        # refuse. This is the spelling a drop-in uses before setting its
        # own ExecStart=, and it must stay accepted.
        if [[ -n "${value}" ]]; then
          # systemd's command-line prefixes: '-' (ignore failure), '@'
          # (argv[0] override), '+' / '!' / '!!' (privilege variants), and
          # ':' (no environment-variable substitution). They may be
          # combined in any order ahead of the executable.
          exec_value="${value}"
          while [[ "${exec_value}" == [-@+!:]* ]]; do
            exec_value="${exec_value#?}"
          done
          exec_value="${exec_value#"${exec_value%%[![:space:]]*}"}"
          if [[ -z "${exec_value}" ]]; then
            deploy_fail "unit source ${file} declares ${key} with command prefixes but no executable (${value}); systemd requires a command after the prefix characters -- spell the executable or use the empty ${key}= reset and retry"
          fi
          if [[ "${exec_value}" == [\"\']* ]]; then
            deploy_fail "unit source ${file} declares ${key} with a QUOTED executable (${value}); systemd unquotes the command line but this deployment's parser does not model quoting, and taking the first whitespace-separated token would secure a path that does not exist -- spell the executable unquoted and retry"
          fi
          exec_token="${exec_value%%[[:space:]]*}"
          if [[ "${exec_token}" == *"${MCLOVING_BACKSLASH}"* ]]; then
            deploy_fail "unit source ${file} declares ${key} with a backslash escape in its executable (${value}); systemd unescapes the command line but this deployment's parser does not model escapes -- spell the executable without escapes and retry"
          fi
          specifier_probe="${exec_token#%h}"
          if [[ "${specifier_probe}" == *%* ]]; then
            deploy_fail "unit source ${file} declares ${key} with a unit specifier other than a leading %h in its executable (${exec_token}); this deployment expands a leading %h and nothing else, so the executable would be secured at a spelling systemd never resolves to -- spell it with a leading %h or an absolute prefix and retry"
          fi
          if [[ "${exec_token}" != /* && "${exec_token}" != %h/* ]]; then
            deploy_fail "unit source ${file} declares ${key} with a non-absolute executable (${exec_token}); systemd resolves a bare filename against its own binary search path, which this deployment cannot enumerate or secure, so the command the next restart runs would be validated nowhere -- spell an absolute path (or %h-relative) and retry"
          fi
        fi
      fi
    done < "${file}"
  done
  return 0
}

# deployment_unit_declared_contracts HOME UNIT_FILE... -> encoded items:
# every EnvironmentFile= value the units and their drop-ins declare, with
# the optional "-" prefix stripped and %h expanded, WHEREVER it points --
# an EnvironmentFile IS a contract, and one declared outside the home is
# validated under the same rules as any contract, with its chain walked to
# "/" per the outside-home stop rule. Non-absolute values are dropped here
# because systemd itself refuses them. Extraction goes through
# deployment_unit_assignment_lines, so every separator spelling systemd
# accepts is the same declaration here.
deployment_unit_declared_contracts() {
  local home_dir="${1%/}" line key value path encoded_source decoded_source
  local encoded_match
  local source_files=()
  shift
  while IFS= read -r encoded_source; do
    [[ -n "${encoded_source}" ]] || continue
    decode_path_item_into decoded_source "${encoded_source}"
    source_files+=("${decoded_source}")
  done < <(deployment_unit_source_files "${home_dir}" "$@")
  [[ ${#source_files[@]} -gt 0 ]] || return 0
  while IFS= read -r line; do
    key="${line%%=*}"
    [[ "${key}" == "EnvironmentFile" ]] || continue
    value="${line#*=}"
    path="${value#-}"
    path="${path//%h/${home_dir}}"
    case "${path}" in
      /*) ;;
      *) continue ;;
    esac
    # The literal spelling is emitted whether or not it is a wildcard.
    # For a plain path it IS the contract. For a wildcard it is what
    # bounds the exposure: the chain derivation walks the pattern's own
    # parent directories, so the directory a match could be ADDED to is
    # judged non-group/world-writable and root-or-home-owned. That
    # bound is the load-bearing half -- systemd expands the glob shortly
    # before exec, long after this validation, so a match created in the
    # interval is not observable here at all; only "who may create one"
    # is. require_secure_files skips a literal that does not exist, so
    # the wildcard spelling itself costs nothing there.
    encode_path_item "${path}"
    # The MATCHES are emitted too, and each is judged under the full
    # contract rule with its own resolved chain. This is not merely
    # defence in depth: a match that ALREADY exists group/world-writable,
    # foreign-owned, or as a special node is invisible to the directory
    # bound above -- a 0666 file inside a 0755 root-owned directory is
    # rewritable by anyone -- and systemd loads every one of them.
    if [[ "${path}" == *[\*\?\[]* ]]; then
      while IFS= read -r encoded_match; do
        [[ -n "${encoded_match}" ]] || continue
        printf '%s\n' "${encoded_match}"
      done < <(deployment_glob_matches "${path}")
    fi
  done < <(deployment_unit_assignment_lines "${source_files[@]}")
}

# deployment_glob_matches PATTERN -> encoded items: every path the pattern
# matches, with the glob(3) semantics systemd itself uses.
#
# systemd.exec documents the EnvironmentFile= argument as "an absolute
# filename OR WILDCARD EXPRESSION", and expands it with
# safe_glob(fn, 0, &pglob) -- plain glob(3), no GLOB_BRACE. python's glob
# implements the same syntax: '*' and '?' (neither crossing '/' nor
# matching a leading '.') and '[...]' classes, with brace expansion
# absent. Verified against libc on this host rather than assumed:
# glob("{a,b}.env", 0, ...) returns GLOB_NOMATCH where a shell would
# expand it, and python's glob likewise returns no match -- so the
# expansion here is neither narrower nor wider than the one systemd
# performs. Being NARROWER would be the dangerous direction: a match
# systemd loads that this never validates.
deployment_glob_matches() {
  python3 - "$1" <<'GLOB'
import base64
import glob
import os
import sys

for match in sorted(glob.glob(sys.argv[1])):
    print(base64.b64encode(os.fsencode(match)).decode("ascii"))
GLOB
}

# deployment_unit_declared_executables HOME UNIT_FILE... -> encoded items:
# the EXECUTABLE named by every Exec* command directive the units and their
# drop-ins declare, with a leading %h expanded.
#
# The path-directive enumeration covers what a unit LOADS. This covers what
# it RUNS. A secured operator drop-in resetting ExecStart= to
# /srv/shared/tool was previously emitted by neither: the transition
# validated the drop-in source itself, saw the file was fine, and then
# restarted the unit into a binary whose mode, owner, and ancestor chain
# nothing had judged -- so another local user able to write /srv/shared
# gained code execution as the service account on that restart. Each
# executable now takes the trust-input file rule (no group/other write,
# root-or-home owner, regular, readable) and joins the shared ancestor
# walk, wherever it points.
#
# Value syntax, per systemd.service(5) and matched exactly by the loud
# pre-check in require_parseable_unit_sources:
#   - an EMPTY assignment is a legal reset and declares no executable;
#   - one or more prefix characters ('-', '@', '+', '!', '!!', ':') may
#     lead, in any order, and are stripped;
#   - the executable is the first whitespace-separated token;
#   - a leading %h expands, and nothing else does.
# Every spelling outside that -- quoted, backslash-escaped, specifier-bearing,
# or non-absolute -- is a NAMED refusal there rather than a quiet skip here,
# so this extractor never has to guess.
#
# Absence is legal and skipped by the file rule, exactly as it is for
# declared contracts: the ancestor chain of the declared path is still
# walked, so the directory an executable would appear in is judged even
# before it exists.
# deployment_exec_argument_paths HOME COMMAND_VALUE -> encoded items: every
# ARGUMENT of an Exec* command line that is an absolute path and exists as a
# regular file.
#
# Round 29 drew the boundary at "the executable is the first token;
# arguments are not validated", and that boundary was wrong. A script handed
# to an interpreter is executed exactly as surely as the interpreter is:
# ExecStartPre=/bin/sh /srv/shared/hook.sh validated /bin/sh and left both
# the script and /srv/shared unjudged, so another local user who could write
# that directory owned what the transition ran.
#
# Deciding WHICH arguments are files is undecidable in general, so this does
# not try. It OVER-VALIDATES instead, which round 31 established is the safe
# direction: anything absolute that is actually there as a regular file is
# judged. The cost of over-validating an argument that merely looks like a
# path is a refusal only when that path is genuinely unsafe, which is the
# direction to err in.
#
# The policy, stated because each case is a judgement:
#
#   ABSOLUTE AND EXISTS AS A REGULAR FILE -- validated. Trust-input file
#     rule plus the shared ancestor walk, exactly like the executable.
#   ABSOLUTE BUT ABSENT -- ignored. systemd passes it to the process as a
#     string; nothing reads it. Walking the ancestors of every path-shaped
#     argument would refuse transitions over directories the deployment
#     never touches, which is a false refusal rather than a caught risk.
#   ABSOLUTE BUT NOT A REGULAR FILE -- ignored. A directory argument is a
#     data root, not executable input, and the classes that own such roots
#     validate them through their own declarations.
#   %h-ANCHORED -- expanded, the same leading-%h grammar the executable uses.
#   RELATIVE -- ignored. systemd does not resolve it against anything this
#     validator can observe, and round 33 settled that guessing a
#     working-directory-relative path resolves somewhere systemd will not.
#
# Tokenization follows systemd's own command-line splitting rather than a
# naive whitespace split, because a quoted argument is exactly where a path
# hides: single and double quotes group, and a backslash escapes the next
# character. Round 29's loud refusals still govern the EXECUTABLE token,
# which is unchanged.
deployment_exec_argument_paths() {
  python3 - "$1" "$2" <<'ARGPATHS'
import base64
import os
import sys

home, value = sys.argv[1], sys.argv[2]


def tokenize(text):
    tokens = []
    current = []
    started = False
    quote = None
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            started = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            else:
                current.append(char)
            continue
        if char in ("'", '"'):
            quote = char
            started = True
            continue
        if char.isspace():
            if started:
                tokens.append("".join(current))
                current = []
                started = False
            continue
        current.append(char)
        started = True
    if started:
        tokens.append("".join(current))
    return tokens


seen = set()
# tokens[0] is the executable, judged by the caller under round 29's rules.
for token in tokenize(value)[1:]:
    if token.startswith("%h/"):
        token = home + token[2:]
    if not token.startswith("/"):
        continue
    if not os.path.isfile(token):
        continue
    if token in seen:
        continue
    seen.add(token)
    print(base64.b64encode(os.fsencode(token)).decode("ascii"))
ARGPATHS
}

deployment_unit_declared_executables() {
  local home_dir="${1%/}" line key value exec_token path
  local encoded_source decoded_source
  local source_files=()
  shift
  while IFS= read -r encoded_source; do
    [[ -n "${encoded_source}" ]] || continue
    decode_path_item_into decoded_source "${encoded_source}"
    source_files+=("${decoded_source}")
  done < <(deployment_unit_source_files "${home_dir}" "$@")
  [[ ${#source_files[@]} -gt 0 ]] || return 0
  while IFS= read -r line; do
    key="${line%%=*}"
    value="${line#*=}"
    [[ "${key}" =~ ^(${MCLOVING_UNIT_EXEC_DIRECTIVES})$ ]] || continue
    [[ -n "${value}" ]] || continue
    while [[ "${value}" == [-@+!:]* ]]; do
      value="${value#?}"
    done
    value="${value#"${value%%[![:space:]]*}"}"
    exec_token="${value%%[[:space:]]*}"
    [[ -n "${exec_token}" ]] || continue
    # A LEADING %h only, matching the pre-check that refused every other
    # specifier spelling: extractor and refusal agree on one grammar.
    path="${exec_token/#%h/${home_dir}}"
    case "${path}" in
      /*) encode_path_item "${path}" ;;
    esac
    # And every ARGUMENT that is actually a file on disk. A script passed to
    # an interpreter is executed as surely as the interpreter, and which
    # arguments are files is not decidable in general -- so this
    # over-validates rather than models. Emitted through the same transport,
    # so the caller judges them under the same rules as the executable.
    deployment_exec_argument_paths "${home_dir}" "${value}"
  done < <(deployment_unit_assignment_lines "${source_files[@]}")
  return 0
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
  done < <(deployment_unit_source_files "${home_dir}" "$@")
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
  done < <(deployment_unit_assignment_lines "${source_files[@]}")
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

# deployment_unit_invocation_is_authoritative -- 0 when THIS PROCESS is the
# one systemd executed for a unit, so its environment IS the environment the
# service receives.
#
# The distinction matters because the same helpers are legitimately run two
# ways, and the correct answer differs:
#
#   INSIDE THE UNIT (ExecStartPre / ExecStart / ExecStartPost). systemd has
#   already composed the environment from the manager environment,
#   Environment= in the unit and its drop-ins, and every EnvironmentFile= in
#   order. That composition is what the binaries will read, so a required
#   variable ABSENT from it will not reach the service no matter what the
#   contract file says.
#
#   BY HAND (the smoke suite, an operator checking a contract before
#   installing it). Nothing has composed anything; the parsed contract is
#   the only statement of intent available and must stand, exactly as it did
#   before round 32.
#
# The marker is systemd's own, and is two-part on purpose. INVOCATION_ID is
# set for every unit invocation but is INHERITED by descendants, so a helper
# a human ran from a shell that happens to sit inside a unit would inherit
# it. SYSTEMD_EXEC_PID names the process systemd actually executed, so
# requiring it to be OUR pid closes that loophole: it is true only for the
# process systemd started, not for anything further down. Verified on
# systemd 255 -- run by hand both are unset; run as ExecStartPre,
# INVOCATION_ID is set and SYSTEMD_EXEC_PID equals the script's own $$.
#
# Where SYSTEMD_EXEC_PID is absent but INVOCATION_ID is present (systemd
# older than v248) the invocation is still treated as authoritative: that is
# the best evidence available, and declining would leave the very gap this
# closes. Only an explicit MISMATCH -- a descendant of the executed process
# -- declines, and it declines to the lenient side, which is the pre-round-32
# behaviour rather than a new refusal.
deployment_unit_invocation_is_authoritative() {
  [[ -n "${INVOCATION_ID:-}" ]] || return 1
  [[ -z "${SYSTEMD_EXEC_PID:-}" || "${SYSTEMD_EXEC_PID}" == "$$" ]] || return 1
  return 0
}

# load_effective_contract ENV_FILE -- the ONE derivation every in-unit
# consumer uses to learn what the service will actually receive.
#
# Parses the contract, then overlays the process environment. Inside a unit
# the environment is authoritative in BOTH directions: a key it carries wins
# (round 32), and a key it does NOT carry is REMOVED from the map, because
# the service will not receive it. The removed names are recorded in
# MCLOVING_CONTRACT_DROPPED so a consumer can say WHY a declared variable is
# missing instead of reporting it as an empty contract value.
#
# Run by hand, nothing is overlaid and nothing is dropped: the parsed
# contract stands unchanged.
# deployment_unit_process_environment UNIT -> the PATH of the running
# service's own environment dump (/proc/PID/environ), NUL-delimited exactly
# as the kernel holds it. Non-zero and nothing on stdout when the manager
# cannot answer. A path rather than the bytes, because bash cannot carry NUL
# through a variable.
#
# This is "ask the manager" carried to its conclusion. `systemctl show UNIT
# -p Environment` is NOT sufficient and was checked rather than assumed: it
# reports only Environment= directives and omits EnvironmentFile= contents
# entirely, which is precisely the override this fix exists for.
# -p EnvironmentFiles returns the file LIST, and recomposing from that is
# modelling again. The manager does, however, name the process it started,
# and /proc/PID/environ is what that process actually received -- not a
# model of it. Readable because the transition runs as the same uid that
# owns the service.
deployment_unit_process_environment() {
  local unit_name="$1" main_pid
  deployment_manager_is_reachable || return 1
  main_pid="$(systemctl --user show "${unit_name}" -p ExecMainPID --value 2>/dev/null 9>&-)" \
    || return 1
  [[ "${main_pid}" =~ ^[0-9]+$ ]] || return 1
  [[ "${main_pid}" -gt 0 ]] || return 1
  [[ -r "/proc/${main_pid}/environ" ]] || return 1
  printf '%s\n' "/proc/${main_pid}/environ"
  return 0
}

# MCLOVING_CONTRACT          the EFFECTIVE value of each contract key
# MCLOVING_CONTRACT_DECLARED the value the contract FILE declares
# MCLOVING_CONTRACT_DROPPED  keys the effective environment does not carry
# MCLOVING_EFFECTIVE_ENV     the effective environment itself, by name
declare -A MCLOVING_CONTRACT_DROPPED=()
declare -A MCLOVING_CONTRACT_DECLARED=()
declare -A MCLOVING_EFFECTIVE_ENV=()
MCLOVING_CONTRACT_SOURCE="declared"

# load_effective_contract ENV_FILE [ENVIRON_BLOB]
#
# BOTH MAPS ARE KEPT. An earlier draft overlaid the effective value straight
# onto MCLOVING_CONTRACT, which destroyed the only copy of the DECLARED
# value -- and the round-32 check that refuses a classified path whose
# ambient value disagrees with the contract was then comparing a value with
# itself and could never fire. Anything that judges what the service will
# DO reads MCLOVING_CONTRACT; anything that compares intent against reality
# reads MCLOVING_CONTRACT_DECLARED.
#
# The effective environment comes from one of two authorities, and the map
# is built the same way from either, so every consumer is source-agnostic:
#
#   ENVIRON_FILE given -- a FILE holding the running service's own
#     environment, NUL-delimited, written by a caller that asked the manager
#     for it. This is how a TRANSITION learns what the service actually got,
#     since the transition process is not the unit and its own environment
#     says nothing. A file rather than a string because bash variables
#     CANNOT HOLD NUL -- the same constraint that made encode_path_item
#     necessary, and passing the dump through a command substitution
#     silently loses every separator.
#
#   otherwise, and only when this process IS the one systemd executed --
#     our own environment, which systemd composed for the unit.
#
# Run by hand with neither, nothing is overlaid and the parsed contract
# stands, exactly as before round 32.
load_effective_contract() {
  local contract_file="$1" environ_file="${2-}" environ_temp=""
  local contract_key environ_entry
  load_environment_file "${contract_file}"
  MCLOVING_CONTRACT_DECLARED=()
  MCLOVING_CONTRACT_DROPPED=()
  MCLOVING_EFFECTIVE_ENV=()
  MCLOVING_CONTRACT_SOURCE="declared"
  for contract_key in "${!MCLOVING_CONTRACT[@]}"; do
    MCLOVING_CONTRACT_DECLARED["${contract_key}"]="${MCLOVING_CONTRACT[${contract_key}]}"
  done
  # THE OBSERVED ENVIRONMENT IS ALWAYS RECORDED, in every mode. The OVERLAY
  # is a different question from the OBSERVATION, and conflating them broke a
  # round-32 gate: the asymmetry refusal -- a classified path that reaches
  # the service from outside the contract, or disagrees with it -- has always
  # fired in both modes, and operators have been told that. Only the overlay
  # is restricted to the mode where the environment is authoritative, which
  # is round 35's rule and is preserved below.
  if [[ -n "${environ_file}" ]]; then
    MCLOVING_CONTRACT_SOURCE="service-process"
  else
    environ_temp="$(mktemp)" \
      || deploy_fail "cannot create a temporary file for the effective environment"
    env -0 > "${environ_temp}"
    environ_file="${environ_temp}"
    if deployment_unit_invocation_is_authoritative; then
      MCLOVING_CONTRACT_SOURCE="unit-invocation"
    else
      MCLOVING_CONTRACT_SOURCE="observed"
    fi
  fi
  while IFS= read -r -d '' environ_entry; do
    [[ "${environ_entry}" == *=* ]] || continue
    MCLOVING_EFFECTIVE_ENV["${environ_entry%%=*}"]="${environ_entry#*=}"
  done < "${environ_file}"
  [[ -z "${environ_temp}" ]] || rm -f "${environ_temp}"
  # "observed" means: seen in THIS process, which is not the service. It is
  # evidence for the asymmetry check and nothing else -- the parsed contract
  # stands as the effective value, exactly as it did before round 32.
  [[ "${MCLOVING_CONTRACT_SOURCE}" != "observed" ]] || return 0
  for contract_key in "${!MCLOVING_CONTRACT[@]}"; do
    if [[ -v "MCLOVING_EFFECTIVE_ENV[${contract_key}]" ]]; then
      MCLOVING_CONTRACT["${contract_key}"]="${MCLOVING_EFFECTIVE_ENV[${contract_key}]}"
    else
      MCLOVING_CONTRACT_DROPPED["${contract_key}"]=1
      unset 'MCLOVING_CONTRACT[${contract_key}]'
    fi
  done
  return 0
}

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

# require_deployment_assets_present HOME -- assert that every file this
# deployment MUST have is actually there, before a transition stops
# anything.
#
# Every walk in this library validates WHAT EXISTS. None of them asserted
# WHAT MUST EXIST, and a glob cannot: delete helpers/mcloving-health and the
# inventory simply collects the remaining entries, integrity succeeds, the
# upgrade stops both services and moves current, and only then does the
# health invocation exit 127 with the release transition half done and the
# agent stopped. The same blindness covered every asset class -- a deleted
# unit file vanished from the mcloving-*.service glob, a deleted contract
# was "skipped, the installer decides those", a release binary missing from
# the CURRENT release was never re-checked after staging.
#
# Called by the TRANSITION entry points, deliberately NOT by the installer:
# install is the tool that RESTORES a missing asset, so refusing it here
# would trap the operator with no repair path. Transitions have no such
# excuse -- they are about to stop running services.
require_deployment_assets_present() {
  local home_dir="${1%/}" libexec_root config_root xdg_config_base
  local unit_root quadlet_root current_target
  local asset missing=""
  libexec_root="${home_dir}/.local/libexec/mcloving"
  config_root="${home_dir}/.config/mcloving"
  xdg_config_base="$(deployment_effective_config_root "${home_dir}")"
  unit_root="${xdg_config_base}/systemd/user"
  quadlet_root="${xdg_config_base}/containers/systemd"
  for asset in "${MCLOVING_DEPLOY_HELPERS[@]}" "${MCLOVING_DEPLOY_LIBRARY}"; do
    [[ -f "${libexec_root}/helpers/${asset}" ]] \
      || missing+="helpers/${asset} "
  done
  for asset in "${MCLOVING_DEPLOY_UNITS[@]}"; do
    [[ -f "${unit_root}/${asset}" ]] || missing+="${unit_root}/${asset} "
  done
  for asset in "${MCLOVING_DEPLOY_QUADLETS[@]}"; do
    [[ -f "${quadlet_root}/${asset}" ]] || missing+="${quadlet_root}/${asset} "
  done
  for asset in "${MCLOVING_DEPLOY_CONTRACTS[@]}"; do
    [[ -f "${config_root}/${asset}" ]] || missing+="${config_root}/${asset} "
  done
  # The CURRENT release must carry every deployed binary. Staging verified
  # the release it published; nothing re-checked the one in use, so a binary
  # deleted from the live release was invisible until the restart failed.
  if [[ -L "${libexec_root}/current" ]]; then
    current_target="$(readlink "${libexec_root}/current")"
    for asset in "${MCLOVING_DEPLOY_BINARIES[@]}"; do
      [[ -f "${libexec_root}/${current_target}/${asset}" ]] \
        || missing+="${current_target}/${asset} "
    done
  fi
  if [[ -n "${missing}" ]]; then
    deploy_fail "deployment asset(s) missing: ${missing% }-- a transition stops running services and then starts them again, so an asset that is absent NOW becomes a half-finished transition later; restore the deployment (mcloving-install repairs a tree in place) before upgrading or rolling back"
  fi
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
  xdg_config_base="$(deployment_effective_config_root "${home_dir}")"
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
  # The installed files are what this deployment WROTE. What systemd RUNS
  # is the first match for each unit NAME across the load paths in
  # precedence order, and a higher-priority path holding the same name
  # shadows the installed file entirely -- its ExecStart is what the next
  # restart executes while the installed one is never read. Both are
  # validated: the shadow because it is what runs, the installed file
  # because it still exists and its own integrity still matters (the shadow
  # may be removed at any time, restoring it).
  local shadowing_units=() effective_unit_file encoded_shadow
  if [[ ${#unit_files[@]} -gt 0 ]]; then
    # COLLECT FIRST, JUDGE AFTER. A deploy_fail raised from inside a loop
    # fed by `< <(...)` exits the shell while the process-substitution
    # PRODUCER is still alive -- and inside the transition lock that
    # producer holds fd 9, so the next transition finds the lock held. The
    # refusals below are the first in this function raised from within such
    # a loop, and they made a suite run fail exactly that way. Command
    # substitution is waited for, so the producer is reaped before anything
    # can refuse.
    local shadow_kind shadow_raw
    shadow_raw="$(deployment_shadowing_unit_files "${home_dir}" "${unit_files[@]}")"
    local -a shadow_candidates=()
    while IFS= read -r encoded_shadow; do
      [[ -n "${encoded_shadow}" ]] || continue
      decode_path_item_into effective_unit_file "${encoded_shadow}"
      shadow_candidates+=("${effective_unit_file}")
    done <<<"${shadow_raw}"
    for effective_unit_file in ${shadow_candidates[@]+"${shadow_candidates[@]}"}; do
      shadow_kind="$(deployment_unit_file_kind "${effective_unit_file}")"
      case "${shadow_kind}" in
        mask)
          # REFUSED, not merely reported. An administrative OVERRIDE still
          # runs something, so validating and reporting it is enough. A MASK
          # runs nothing: the transition would stop both services, move
          # current, and then fail to start a unit the manager refuses to
          # load, leaving exactly the half-finished transition this lane
          # exists to prevent. Refusing before anything is stopped costs an
          # operator one command (systemctl --user unmask) and costs a
          # running deployment nothing.
          deploy_fail "unit ${effective_unit_file} is MASKED (a symlink to /dev/null in a load path that outranks this deployment's own unit of the same name); the service manager will refuse to start it, so a transition that stops the services could not bring them back -- run systemctl --user unmask on the unit, or remove the mask, and retry"
          ;;
        other)
          deploy_fail "unit ${effective_unit_file} is the file the service manager would load for this deployment but is not a regular file ($(stat -Lc '%F' "${effective_unit_file}" 2>/dev/null || echo "unknown node")); this deployment publishes only regular unit files and the manager loads nothing else usefully -- remove the node and retry"
          ;;
      esac
      shadowing_units+=("${effective_unit_file}")
      unit_files+=("${effective_unit_file}")
    done
    # Reported, not refused. systemd's load path exists so an administrator
    # CAN override a unit, and a deployment that refused to upgrade because
    # the host exercised that mechanism would be un-upgradable with no
    # repair it could perform -- the same reasoning that keeps system-path
    # drop-ins reported rather than refused. What closes the hole is that
    # the shadow is now validated and parsed like any other source, so a
    # world-writable one is refused by name on its own merits. The
    # canonical digest document records these too, so an override appearing
    # or changing is drift the re-read can see.
    for effective_unit_file in "${shadowing_units[@]}"; do
      deploy_notice "unit resolution used the $(deployment_unit_path_source "${home_dir}") unit search path"
      deploy_notice "unit file ${effective_unit_file} outranks this deployment's own installed unit of the same name and is what the service manager will load; it is validated under the same rules as the installed sources, and is recorded in the canonical digest document"
    done
  fi
  local unit_declared_roots=() declared_contracts=() unit_source_files=()
  local declared_executables=() load_path_roots=() system_dropin_files=()
  local dropin_dirs=() encoded_root encoded_item decoded_item
  # The load path DIRECTORIES themselves, where they exist, join the chain
  # roots. This is the containing-directory bound for the paths outside the
  # managed set: a group/world-writable $XDG_DATA_HOME/systemd/user is a
  # drop-in directory another local user can create at will, and the
  # drop-in that would be merged does not exist yet at validation time, so
  # only "who may create one" is observable -- the same reasoning that
  # makes wildcard EnvironmentFile= expansion safe. Non-existent paths
  # contribute nothing; the ancestor walk skips what is not a directory.
  local load_path_dir
  while IFS= read -r encoded_item; do
    [[ -n "${encoded_item}" ]] || continue
    decode_path_item_into load_path_dir "${encoded_item}"
    [[ -d "${load_path_dir}" ]] || continue
    load_path_roots+=("${load_path_dir}")
  done < <(
    deployment_unit_load_paths "${home_dir}" all systemd
    deployment_unit_load_paths "${home_dir}" all quadlet
  )
  if [[ ${#unit_files[@]} -gt 0 ]]; then
    # BEFORE anything resolves: a relative XDG search entry makes the
    # effective unit file undeterminable, so it is refused here in the main
    # shell rather than silently resolving to the wrong directory.
    require_usable_unit_search_path "${home_dir}"
    # BEFORE anything parses: constructs systemd would consume that the
    # assignment parser does not model are a loud refusal here in the main
    # shell -- inside the derivation substitutions below a refusal would
    # die with its subshell and validation would continue on partial output.
    require_parseable_unit_sources "${home_dir}" "${unit_files[@]}"
    local decoded_declared_root
    while IFS= read -r encoded_root; do
      [[ -n "${encoded_root}" ]] || continue
      decode_path_item_into decoded_declared_root "${encoded_root}"
      unit_declared_roots+=("${decoded_declared_root}")
    done < <(deployment_unit_declared_roots "${home_dir}" "${unit_files[@]}" | sort -u)
    # EVERYTHING the parser reads (sources) and everything it declares
    # (targets) enters validation -- no filtered category. Sources: the
    # unit files themselves and the *.conf of every drop-in directory
    # systemd consults for them, judged by the integrity file rule, with
    # those drop-in directories joining the chain roots. Declared
    # EnvironmentFiles are contracts and get the contract file rule,
    # wherever they point; declared Exec* executables are trust inputs and
    # get the integrity file rule, wherever they point.
    while IFS= read -r encoded_item; do
      [[ -n "${encoded_item}" ]] || continue
      decode_path_item_into decoded_item "${encoded_item}"
      unit_source_files+=("${decoded_item}")
    done < <(deployment_unit_source_files "${home_dir}" "${unit_files[@]}")
    while IFS= read -r encoded_item; do
      [[ -n "${encoded_item}" ]] || continue
      decode_path_item_into decoded_item "${encoded_item}"
      declared_contracts+=("${decoded_item}")
    done < <(deployment_unit_declared_contracts "${home_dir}" "${unit_files[@]}" | sort -u)
    while IFS= read -r encoded_item; do
      [[ -n "${encoded_item}" ]] || continue
      decode_path_item_into decoded_item "${encoded_item}"
      declared_executables+=("${decoded_item}")
    done < <(deployment_unit_declared_executables "${home_dir}" "${unit_files[@]}" | sort -u)
    while IFS= read -r encoded_item; do
      [[ -n "${encoded_item}" ]] || continue
      decode_path_item_into decoded_item "${encoded_item}"
      dropin_dirs+=("${decoded_item}")
    done < <(deployment_unit_dropin_dirs "${home_dir}" "${unit_files[@]}")
    # System-path drop-ins are validated exactly like every other drop-in
    # -- they are already in unit_source_files and dropin_dirs above -- and
    # are additionally NAMED. An administrator may legitimately drop a
    # /etc/systemd/user/service.d/*.conf on the host, so refusing the
    # transition over one would be wrong; leaving the operator unaware that
    # something outside the deployment tree is merged into its units would
    # be worse. The same list is recorded in the canonical digest document,
    # so appearance or drift of one changes the document too.
    local system_dropin_dir system_dropin_file
    while IFS= read -r encoded_item; do
      [[ -n "${encoded_item}" ]] || continue
      decode_path_item_into system_dropin_dir "${encoded_item}"
      for system_dropin_file in "${system_dropin_dir}"/*.conf; do
        [[ -f "${system_dropin_file}" ]] || continue
        system_dropin_files+=("${system_dropin_file}")
      done
    done < <(deployment_unit_dropin_dirs "${home_dir}" --system "${unit_files[@]}")
    for system_dropin_file in "${system_dropin_files[@]}"; do
      deploy_notice "system-path drop-in ${system_dropin_file} is merged into this deployment's units by the service manager; it is validated under the same rules as the deployment's own sources, and is recorded in the canonical digest document"
    done
  fi
  # The two INSTALLED TREES the transition executes from -- retained
  # releases and installed helpers -- are walked in full by the shared
  # collector below. Each real directory found joins the validated-node
  # set; each regular file joins the trust-input file list.
  local release_binaries=() helper_files=()
  deployment_collect_trust_tree "${libexec_root}/releases" \
    "retained release" managed_roots release_binaries
  # helpers/ holds every executable this transition RUNS -- mcloving-health
  # and mcloving-env-guard run from the units, mcloving-deploy-lib.sh is
  # SOURCED by all of them, and the installed rollback/digests helpers are
  # what the recovery command invokes. The directory being non-writable
  # (0700, or a merely traversable 0755) says nothing about the mode of an
  # individual file inside it: one relaxed helper is arbitrary code
  # executed as the service user during the restart and health gates this
  # very transition is about to run.
  deployment_collect_trust_tree "${libexec_root}/helpers" \
    "installed helper" managed_roots helper_files
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
    "${declared_contracts[@]}" "${declared_executables[@]}" \
    "${load_path_roots[@]}" "${dropin_dirs[@]}" "${unit_source_files[@]}"
  require_secure_files "${home_dir}" "${contract_destinations[@]}" \
    "${declared_contracts[@]}"
  require_integrity_files "${home_dir}" "${unit_source_files[@]}" \
    "${release_binaries[@]}" "${helper_files[@]}" \
    "${declared_executables[@]}"
}

# deployment_collect_trust_tree ROOT LABEL DIRS_ARRAY FILES_ARRAY
#
# Walk one INSTALLED tree this deployment executes or sources from, and
# split it into validated directory nodes (appended to DIRS_ARRAY, judged
# by the managed-root mode and ownership rules) and trust-input files
# (appended to FILES_ARRAY, judged by require_integrity_files). Derived by
# LISTING the tree -- never from an enumerated name list or a symlink
# target -- because enumeration is how this class of gap has repeatedly
# reappeared: what is on disk is what the next transition executes.
#
# Entries that this deployment never legitimately publishes are refused by
# name rather than skipped: a symlinked entry (the round-11 rule -- both
# stage_release and the installer write real directories and regular files
# only) and any other node kind (FIFO, socket, device). Dotfiles are
# included: a hidden entry is executed exactly as readily as a visible one.
# A missing tree is legal and contributes nothing -- the installer creates
# these, and a fresh home has neither.
deployment_collect_trust_tree() {
  local tree_root="$1" tree_label="$2"
  # shellcheck disable=SC2178  # nameref assignment
  local -n collect_dirs_ref="$3"
  # shellcheck disable=SC2178  # nameref assignment
  local -n collect_files_ref="$4"
  local collect_walk=() collect_node collect_index=0 collect_dotglob=0
  shopt -q dotglob && collect_dotglob=1
  shopt -s dotglob
  if [[ -d "${tree_root}" ]]; then
    collect_walk=("${tree_root}"/*)
  fi
  while (( collect_index < ${#collect_walk[@]} )); do
    collect_node="${collect_walk[collect_index]}"
    collect_index=$((collect_index + 1))
    # An unmatched glob stays a literal pattern; nothing exists there.
    [[ -e "${collect_node}" || -L "${collect_node}" ]] || continue
    if [[ -L "${collect_node}" ]]; then
      (( collect_dotglob )) || shopt -u dotglob
      deploy_fail "${tree_label} entry ${collect_node} is a symlink; an entry that is itself a symlink is never published by this deployment, which writes only real directories and regular files there -- refusing to trust the installed tree"
    fi
    if [[ -d "${collect_node}" ]]; then
      collect_dirs_ref+=("${collect_node}")
      collect_walk+=("${collect_node}"/*)
    elif [[ -f "${collect_node}" ]]; then
      collect_files_ref+=("${collect_node}")
    else
      (( collect_dotglob )) || shopt -u dotglob
      deploy_fail "${tree_label} entry ${collect_node} is not a regular file or directory ($(stat -c '%F' "${collect_node}" 2>/dev/null || echo "unknown node")); this deployment never publishes such a node -- refusing to trust the installed tree"
    fi
  done
  (( collect_dotglob )) || shopt -u dotglob
  return 0
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
  # ANY existing non-regular node is refused before the open, not only a
  # symlink: a write-only open of a reader-less FIFO blocks forever, so a
  # FIFO planted at the lock path would hang every transition and every
  # digest read before the post-open identity check or any integrity
  # refusal could run. A directory, socket, or device node has no
  # legitimate state here either. The same lstat->open residual window as
  # the symlink case applies and carries the same argument: its
  # precondition is a writable libexec_root, which the integrity check
  # immediately following every exclusive acquisition refuses.
  if [[ -e "${lock_path}" && ! -f "${lock_path}" ]]; then
    deploy_fail "transition lock ${lock_path} is not a regular file ($(stat -c '%F' "${lock_path}" 2>/dev/null || echo "unknown node")); the deployment only ever creates it as a regular file -- refusing to open it"
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
