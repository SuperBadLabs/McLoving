#!/usr/bin/env bash
# End-to-end smoke test for the systemd + rootless-podman deployment lane.
# Runs without root and without a systemd user session: every invocation is
# DERIVED from the shipped unit definitions by mcloving-unit-command, so the
# test cannot drift from what the units actually declare. The only
# deviations are explicit test overrides (published port, container name,
# volume name), each recorded by the deriving tool.
#
# Proves: verified install -> postgres healthy -> db-init -> controller
# healthy -> agent probe + foreground -> CLI apply/submit -> terminal
# success -> logs -> deterministic digest re-read -> upgrade/rollback
# symlink discipline. Also proves fail-closed behavior: tampered binaries
# refuse to install and placeholder contracts refuse to pass the guard.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tools/versions.env
source "${repo_root}/tools/versions.env"

for tool in podman openssl python3 curl jq cargo sha256sum flock; do
  command -v "${tool}" >/dev/null || {
    echo "missing required tool: ${tool}" >&2
    exit 1
  }
done

# The suite is hermetic against the invoking environment's XDG settings.
# GitHub's runners export XDG_CONFIG_HOME, and an inherited value would --
# and in CI did -- steer the installer's derived unit roots away from the
# tree the harness reads. The inherited values are captured for the
# preserved-workdir artifact (so this class of environmental question
# answers itself), then cleared; the XDG gates set the variables
# explicitly, per command, in subshell-confined prefixes.
invoking_xdg_environment="$(env | grep -E '^XDG_' || true)"
unset XDG_CONFIG_HOME XDG_STATE_HOME XDG_CACHE_HOME

# The test's own directories must not depend on the invoking shell's umask.
# An operator umask of 002 -- the Debian/Ubuntu user-private-group default --
# would create every test home group-writable, and the installer's ancestor
# refusal would then fire for reasons unrelated to what each gate asserts.
# Gates that need a hostile umask set one explicitly in a subshell.
umask 022

suffix="${RANDOM}-${RANDOM}"
container_name="mcloving-smoke-postgres-${suffix}"
volume_name="mcloving-smoke-pgdata-${suffix}"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-smoke.XXXXXX")"
controller_pid=""
agent_pid=""
# Every OTHER process this harness backgrounds. The two services above are
# named variables the trap already reaches; these are not, and each was
# killed only inline at its point of use. Any failure, signal, or `set -e`
# abort between a spawn and that kill left the process running, reparented
# to init. That is not hygiene: the transition-lock holders keep their
# flock on `.transition-lock` for their whole lifetime, so an aborted run
# can refuse the next run its lock. The inline discipline had already
# failed silently -- the held-lock refusal gate below exits without killing
# its holder -- which is why the trap now carries the list instead of every
# exit path having to remember.
background_pids=()

# Record a backgrounded pid so the EXIT trap can reach it.
register_background_pid() {
  background_pids+=("$1")
}

# Kill, reap, and FORGET one registered pid. Deregistering BEFORE the kill
# is what makes the trap's later drain safe: the trap can then never signal
# a pid this function already reaped, and so can never hit an unrelated
# process that inherited the number. Call sites keep using this where the
# process must be gone before the next gate runs -- a transition lock has
# to be released at that point, not at exit -- which leaves the drain as
# purely the abort path.
release_background_pid() {
  local pid="$1"
  local kept=()
  local entry
  for entry in "${background_pids[@]}"; do
    [[ "${entry}" == "${pid}" ]] || kept+=("${entry}")
  done
  background_pids=("${kept[@]}")
  kill "${pid}" >/dev/null 2>&1 || true
  wait "${pid}" 2>/dev/null || true
}

# Drain whatever is still registered. Shared by the EXIT trap and by the
# gate that proves this mechanism works.
drain_background_pids() {
  local pid
  for pid in "${background_pids[@]}"; do
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" 2>/dev/null || true
  done
  background_pids=()
}

cleanup() {
  local status=$?
  # Deaf to further signals from here down. ${status} is captured first,
  # because `trap` would overwrite $?.
  #
  # Teardown is a sequence, and until this line a signal arriving mid-sequence
  # abandoned the rest of it: a second Ctrl-C landing between the agent's reap
  # and the controller's kill left the controller running, which is the leak
  # this whole change exists to close, reintroduced through the very trap that
  # closes it. The window is only as wide as one `wait` -- ~100ms, since both
  # services exit on SIGTERM in about that -- but double-tapping Ctrl-C at an
  # unresponsive-looking run is exactly what an impatient operator does, and
  # the signal traps above are what made that window reachable at all.
  #
  # Ignored rather than reset to default: SIG_IGN cannot terminate the shell,
  # whereas the default disposition can. SIGKILL still ends this, as ever.
  trap '' INT TERM HUP
  local preserved
  if [[ -n "${agent_pid}" ]]; then
    kill "${agent_pid}" >/dev/null 2>&1 || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  if [[ -n "${controller_pid}" ]]; then
    kill "${controller_pid}" >/dev/null 2>&1 || true
    wait "${controller_pid}" 2>/dev/null || true
  fi
  drain_background_pids
  if [[ ${status} -ne 0 ]]; then
    # Capture the container's own account of the failure BEFORE the forced
    # removal below destroys it. Without this, the single most informative
    # log on a runner -- what PostgreSQL itself printed -- exists only inside
    # a container this trap is about to delete, and the preserved ${workdir}
    # never held it. A failure before step [1/9] predates the logs
    # directory, so the trap makes it rather than losing its captures.
    mkdir -p "${workdir}/logs" 2>/dev/null || true
    {
      echo "== podman ps --all"
      podman ps --all 2>&1 || true
      echo "== podman inspect ${container_name}"
      podman inspect "${container_name}" \
        --format 'status={{.State.Status}} exit_code={{.State.ExitCode}} oom_killed={{.State.OOMKilled}} error={{.State.Error}}' 2>&1 || true
      echo "== podman logs ${container_name}"
      podman logs "${container_name}" 2>&1 || true
    } > "${workdir}/logs/postgres-container-state.log" 2>&1 || true
    podman info > "${workdir}/logs/podman-info.log" 2>&1 || true
  fi
  podman rm --force "${container_name}" >/dev/null 2>&1 || true
  podman volume rm --force "${volume_name}" >/dev/null 2>&1 || true
  if [[ ${status} -ne 0 ]]; then
    # Everything below goes to stderr, in full. A CI runner's /tmp does not
    # survive the job, so "logs preserved under ${workdir}" names files
    # nobody can read unless they are printed here and uploaded as a job
    # artifact by the workflow.
    {
      echo "smoke test FAILED with status ${status}; logs preserved under ${workdir}"
      for preserved in "${workdir}"/logs/*; do
        [[ -f "${preserved}" ]] || continue
        printf '===> %s <===\n' "${preserved}"
        cat "${preserved}" || true
      done
    } >&2
  else
    rm -rf "${workdir}"
  fi
  exit "${status}"
}
trap cleanup EXIT
# An EXIT trap alone is not reached when the shell is signalled: bash runs it
# on a normal or `exit`-ed end, but a SIGINT terminates the script without it,
# and the services spawned above then outlive the run. Ctrl-C is the ordinary
# way an operator abandons a run, so that path leaked as reliably as the
# success path did. Converting each signal into an `exit` funnels it through
# the one cleanup already written, with the 128+signo status that says which
# signal ended the run -- and, being non-zero, preserves ${workdir} and its
# diagnostics exactly as any other abnormal end does.
#
# SIGKILL cannot be trapped; a `kill -9` of the suite still strands its
# services, and no in-process discipline can change that.
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# `local` outside a function aborts under `set -e`, and the helpers put their
# service logic in a top-level `case` block where that is easy to do by
# accident -- it has happened twice in this lane, each time rejecting every
# valid contract at ExecStartPre. shellcheck does not flag it, so this does.
python3 - "${repo_root}" <<'LOCALSCOPE'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]) / "deploy" / "bin"
opens = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{")
failures = []
for script in sorted(root.iterdir()):
    if not script.is_file():
        continue
    depth = 0
    for number, line in enumerate(script.read_text().splitlines(), 1):
        code = line.split("#", 1)[0]
        if depth == 0 and opens.match(code.strip()):
            depth = 1
            continue
        if depth:
            depth += code.count("{") - code.count("}")
            continue
        if re.match(r"\s*local\s", code):
            failures.append(f"{script.name}:{number}: `local` outside a function")
for failure in failures:
    print(failure, file=sys.stderr)
raise SystemExit(1 if failures else 0)
LOCALSCOPE

# Every MCLOVING_* environment variable the shipped binaries read must be
# either classified in deployment_contract_path_variables (the guard's and
# the inventory's one authority) or excluded HERE with a reviewed reason --
# so a path-bearing variable added in Rust cannot ship unclassified.
python3 - "${repo_root}" <<'CLASSCOVER'
import pathlib
import re
import subprocess
import sys

repo_root = pathlib.Path(sys.argv[1])
swept = set()
for base in ["bins/agent/src", "bins/controller/src", "bins/cli/src"]:
    for source in (repo_root / base).rglob("*.rs"):
        swept |= set(re.findall(r"MCLOVING_[A-Z0-9_]+", source.read_text()))
if not swept or "MCLOVING_CONTROLLER_CA_PATH" not in swept:
    raise SystemExit("the variable sweep found nothing plausible; the scan went blind")
classified = set()
for service in ["postgres", "db-init", "controller", "agent"]:
    listing = subprocess.run(
        ["bash", "-ec",
         'source "$0" && deployment_contract_path_variables "$1"',
         str(repo_root / "deploy/bin/mcloving-deploy-lib.sh"), service],
        capture_output=True, text=True, check=True,
    ).stdout
    # "CLASS LINK-POLICY VARIABLE EXPECTED-KIND" -- the variable is the
    # third field; the kind column is enforced by the guard, not here.
    classified |= {line.split()[2] for line in listing.splitlines() if line}
if not classified:
    raise SystemExit("the classification enumeration is empty; the authority went blind")
# Reviewed exclusions: value-typed variables that carry no filesystem path.
excluded_patterns = [
    r"^MCLOVING_OIDC_",         # OIDC endpoints, URLs, TTLs, and flags
    r"^MCLOVING_TEST_",         # test-only toggles, never in shipped contracts
    r"_FOR_TESTS$",             # test-only toggles
    r"(_SECONDS|_MILLISECONDS|_HOURS|_EPOCH|_GENERATION|_BYTES|_OBJECTS)$",  # numerics
    r"_TOKEN$",                 # bearer secrets passed by value, not path
    r"(_URL|_URI)$",            # network addresses
    r"_SHA256$",                # digest strings pinning a path variable's content
]
excluded_literals = {
    "MCLOVING_AGENT_CAPABILITIES": "capability name list",
    "MCLOVING_AGENT_ID": "agent identifier",
    "MCLOVING_AGENT_LISTEN": "socket bind address",
    "MCLOVING_LISTEN": "socket bind address",
    "MCLOVING_AGENT_ORGANIZATION_ID": "uuid",
    "MCLOVING_ORGANIZATION_ID": "uuid",
    "MCLOVING_PROJECT_ID": "uuid",
    "MCLOVING_AGENT_TRUST_POOL": "trust pool name",
    "MCLOVING_CONTROLLER_DNS_NAME": "TLS server name, not a path",
    "MCLOVING_ALLOW_INSECURE_LOOPBACK": "boolean flag",
    # RETIRED: the controller refuses any value by name
    # (bins/controller/src/main.rs); deliberately unclassified so setting
    # it stays an error, never a validated configuration.
    "MCLOVING_API_PRINCIPALS_PATH": "retired, refused by the controller",
}
unaccounted = []
for name in sorted(swept - classified):
    if name in excluded_literals:
        continue
    if any(re.search(pattern, name) for pattern in excluded_patterns):
        continue
    unaccounted.append(name)
if unaccounted:
    raise SystemExit(
        "binaries read MCLOVING_* variables that are neither classified in "
        "deployment_contract_path_variables nor excluded with a reviewed "
        "reason: " + " ".join(unaccounted)
    )
CLASSCOVER

# The shipped example contracts are TEMPLATES that mcloving-install renders
# against the real home and the real XDG state root. Rendering rewrites two
# prefixes, so every absolute path an example names has to live under the
# template home -- a value added later that points anywhere else would be
# copied through untouched and name a tree on the deployed host that nobody
# chose. Checked as a class, because the defect this closes was one such
# path nobody noticed.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
  python3 - "${repo_root}" "${MCLOVING_CONTRACT_TEMPLATE_HOME}" <<'TEMPLATEPATHS'
import pathlib
import sys

repo_root, template_home = pathlib.Path(sys.argv[1]), sys.argv[2]
stray = []
seen = 0
for example in sorted((repo_root / "deploy" / "env").glob("*.env.example")):
    for number, line in enumerate(example.read_text().splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        name, separator, value = stripped.partition("=")
        if not separator or not value.startswith("/"):
            continue
        seen += 1
        if value != template_home and not value.startswith(template_home + "/"):
            stray.append(f"{example.name}:{number}: {name}={value}")
if seen < 5:
    raise SystemExit("the template-path sweep found too few absolute values; the scan went blind")
if stray:
    raise SystemExit(
        "shipped example contract(s) name an absolute path outside the "
        f"template home {template_home}, which mcloving-install's rendering "
        "would copy through untouched:\n  " + "\n  ".join(stray)
    )
TEMPLATEPATHS
)
# The trap reaches a backgrounded process only if the spawn registered it
# AND the drain actually kills it. Both halves are asserted here, against
# real processes, because this failure is silent in every other way: the
# suite still reports success while leaving a process at ppid=1 holding
# whatever it took. Two probes, because the two halves are separable -- a
# release must reap on its own (call sites depend on the lock being gone
# before the next gate runs, not at exit) and must deregister, or the trap
# would later signal a pid the kernel has since given to something else.
sleep 120 &
registry_probe_released=$!
register_background_pid "${registry_probe_released}"
sleep 120 &
registry_probe_drained=$!
register_background_pid "${registry_probe_drained}"

release_background_pid "${registry_probe_released}"
if kill -0 "${registry_probe_released}" 2>/dev/null; then
  echo "release_background_pid left a released process running" >&2
  exit 1
fi
if [[ " ${background_pids[*]} " == *" ${registry_probe_released} "* ]]; then
  echo "release_background_pid left the pid registered; the trap would later signal a pid this run no longer owns" >&2
  exit 1
fi

drain_background_pids
if kill -0 "${registry_probe_drained}" 2>/dev/null; then
  echo "drain_background_pids left a registered process running; the EXIT trap cannot reach what the spawns register" >&2
  exit 1
fi
if [[ "${#background_pids[@]}" -ne 0 ]]; then
  echo "drain_background_pids left ${#background_pids[@]} pids registered" >&2
  exit 1
fi

echo "== [0/9] pinned-digest drift guard"
quadlet_image="$(sed -n 's/^Image=//p' "${repo_root}/deploy/podman/mcloving-postgres.container")"
if [[ "${quadlet_image}" != "${MCLOVING_POSTGRES_IMAGE}" ]]; then
  echo "quadlet image ${quadlet_image} drifted from tools/versions.env ${MCLOVING_POSTGRES_IMAGE}" >&2
  exit 1
fi

echo "== [1/9] build deployable binaries"
(cd "${repo_root}" && cargo build --locked \
  -p mcloving-controller -p mcloving-agent -p mcloving-cli)

release_dir="${workdir}/release"
mkdir -p "${release_dir}" "${workdir}/logs"
printf '%s\n' "${invoking_xdg_environment}" > "${workdir}/logs/environment-xdg.log"
for binary in mcloving-controller mcloving-agent mcloving-cli mcloving-identity-admin; do
  cp "${repo_root}/target/debug/${binary}" "${release_dir}/${binary}"
done
(cd "${release_dir}" && sha256sum mcloving-controller mcloving-agent \
  mcloving-cli mcloving-identity-admin > "${workdir}/checksums.sha256")

home="${workdir}/home"
mkdir -p "${home}"
# The harness reads unit and quadlet paths through the SAME library
# derivation the installer writes with -- a hard-coded default here is how
# a runner-exported XDG base made reader and writer disagree in CI.
smoke_config_base="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
  deployment_config_root "${home}"
)"
smoke_unit_root="${smoke_config_base}/systemd/user"
smoke_quadlet_root="${smoke_config_base}/containers/systemd"
# The wrapper-to-payload exports carry base64 items (one per line); the
# race drivers bypass the wrapper and must speak the same transport.
smoke_unit_dirs_env="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
  encode_path_item "${smoke_unit_root}"
  encode_path_item "${smoke_quadlet_root}"
)"

echo "== [2/9] fail-closed install: tampered binary must be refused"
tampered_dir="${workdir}/tampered"
cp -r "${release_dir}" "${tampered_dir}"
printf 'x' >> "${tampered_dir}/mcloving-agent"
if "${repo_root}/deploy/bin/mcloving-install" --home "${home}" \
  --release-dir "${tampered_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install accepted a tampered binary; digest verification is broken" >&2
  exit 1
fi
if [[ -e "${home}/.local/libexec/mcloving/current" ]]; then
  echo "failed install left a current release behind" >&2
  exit 1
fi

echo "== [3/9] verified install"
"${repo_root}/deploy/bin/mcloving-install" --home "${home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd
libexec="${home}/.local/libexec/mcloving"
config_dir="${home}/.config/mcloving"
config="${home}/.config/mcloving"
unit_command="${libexec}/helpers/mcloving-unit-command"

# RENDERED, not copied. Before any of the fixtures below rewrite them, the
# freshly installed contracts must already name this deployment's own home
# and its own state root -- the installer resolved both, so no operator and
# no test fixture has to.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
  # ASSIGNMENTS ONLY. A COMMENT that mentions the example home is
  # documentation about the TEMPLATE and stays true of it -- rendering
  # deliberately leaves comments alone, because rewriting them turned a
  # sentence about the example into a false claim about this deployment.
  if grep -rnE "^[A-Za-z_][A-Za-z0-9_]*=.*${MCLOVING_CONTRACT_TEMPLATE_HOME}" "${config}/"; then
    echo "the assignments listed above still name the example home after installation" >&2
    exit 1
  fi
  # ...and the comment really is still there, so "assignments only" is a
  # narrowed assertion rather than a disabled one.
  grep -qF "example home ${MCLOVING_CONTRACT_TEMPLATE_HOME}" "${config}/agent.env" || {
    echo "the template's explanatory comment did not survive installation" >&2
    exit 1
  }
)
installed_workspace="$(sed -n 's/^MCLOVING_AGENT_WORKSPACE_ROOT=//p' "${config}/agent.env")"
[[ "${installed_workspace}" == "${home}/.local/state/mcloving-agent/workspace" ]] || {
  echo "the installed contract does not name the default state root: ${installed_workspace}" >&2
  exit 1
}
echo "== [4/9] fail-closed contracts: placeholder contract must be refused"
if "${libexec}/helpers/mcloving-env-guard" controller \
  "${config}/controller.env" >/dev/null 2>&1; then
  echo "env guard accepted a placeholder contract" >&2
  exit 1
fi

# reserve_port -> a TCP port on 127.0.0.1 the KERNEL WILL NOT HAND to an
# unrelated process, verified free at selection time.
#
# The previous derivation bound 127.0.0.1:0, read the port the kernel
# assigned, and closed the socket -- then wrote that port into a contract
# the controller, the agent-control listener, or podman bound seconds to
# minutes later. Everything the kernel auto-assigns comes out of
# /proc/sys/net/ipv4/ip_local_port_range, so the interval between "we
# picked it" and "the service binds it" is precisely the interval in which
# the kernel may hand the same port to any other process on the machine.
# On a busy runner it eventually does: CI run 32730559625 job 97441620218
# failed at [6/9] with "bind agent control to 127.0.0.1:60553 / Address
# already in use", and 60553 sits inside this kernel's 32768-60999
# ephemeral range.
#
# Ports are therefore drawn from a band OUTSIDE that range -- above its
# high end where there is room, otherwise below its low end -- so no
# amount of unrelated activity can be given the same number. Selection
# still bind-probes, and retries with a fresh candidate on EADDRINUSE, so a
# port some other process deliberately holds is skipped rather than
# handed out; the band is what removes the race, and the probe is what
# removes a deliberate collision.
#
# The probe deliberately does NOT set SO_REUSEADDR. Rust's std (and
# therefore tokio's) TcpListener::bind does not set it either, so a port in
# TIME_WAIT that a REUSEADDR probe would call free is one the controller
# would fail to bind; the strictest consumer decides what "free" means.
#
# Rejected alternatives, for the record. Having the SERVICE bind port 0 and
# report its own port is the structurally best answer in general, but the
# controller has no such mode -- MCLOVING_LISTEN and MCLOVING_AGENT_LISTEN
# are bound as given (bins/controller/src/main.rs) and the chosen port is
# never reported -- and the contract is filled BEFORE anything starts,
# because the agent's MCLOVING_CONTROLLER_URI, the health helper's probe
# endpoint, and podman's publish override all read it from there. Adding a
# port-0 reporting mode to a production binary to settle a test flake is
# the wrong trade. HOLDING the probe socket open until handoff does not
# work at all: SO_REUSEADDR does not permit two live listeners on one
# address (that is SO_REUSEPORT, which the controller does not set), so the
# socket must be closed before the service binds -- which restores exactly
# the window it was meant to close.
# The reservations MUST accumulate in this shell. An earlier draft called
# this through $( ), which runs the function in a SUBSHELL: the append below
# was discarded every time and every call handed python an EMPTY exclusion
# set, so two reservations could return the same free port -- a fresh
# collision mode introduced while closing the kernel's. The port is
# returned through a NAMEREF instead, so the only command substitution left
# is python's own and the array grows where it is read.
reserved_ports=()
reserve_port() {
  # shellcheck disable=SC2178,SC2034  # nameref assignment, written below
  local -n reserve_target_ref="$1"
  local chosen
  chosen="$(python3 - "${reserved_ports[@]}" <<'PY'
import errno
import random
import socket
import sys

DEFAULT_RANGE = (32768, 60999)


def ephemeral_range():
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range", encoding="ascii") as handle:
            low, high = handle.read().split()[:2]
        return int(low), int(high)
    except (OSError, ValueError):
        # A host that will not report its range is assumed to use the kernel
        # default rather than treated as having none: assuming "no ephemeral
        # range" would put every candidate back inside it.
        return DEFAULT_RANGE


low, high = ephemeral_range()
bands = []
if high < 65535:
    bands.append((high + 1, 65535))
if low > 10240:
    # Below the range, but well clear of the registered-service ports an
    # unrelated daemon is likely to want.
    bands.append((10240, low - 1))
if not bands:
    raise SystemExit(
        "test-deployment: this host's ip_local_port_range "
        f"({low}-{high}) leaves no port band outside the kernel's ephemeral "
        "allocation, so no selection here can avoid racing an unrelated "
        "process; narrow the range or run the suite on a host that has one"
    )

taken = {int(argument) for argument in sys.argv[1:]}
for attempt in range(256):
    # The band above the ephemeral range is preferred and only abandoned
    # after it has been given a real chance: the band BELOW the range,
    # where one exists, shares space with registered services an unrelated
    # daemon may claim at any time, so it is a fallback rather than a
    # coin-flip alternative.
    band_low, band_high = bands[0] if attempt < 128 else random.choice(bands)
    port = random.randint(band_low, band_high)
    if port in taken:
        continue
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as error:
            if error.errno in (errno.EADDRINUSE, errno.EACCES):
                continue
            raise
    print(port)
    sys.exit(0)

raise SystemExit(
    "test-deployment: could not find a free port outside the kernel's "
    f"ephemeral range ({low}-{high}) in 256 attempts; something is holding "
    "the non-ephemeral bands open"
)
PY
  )" || exit 1
  reserved_ports+=("${chosen}")
  # shellcheck disable=SC2034  # the nameref target is the caller's variable
  reserve_target_ref="${chosen}"
}

# require_reserved_ports_free LABEL=PORT... -- re-verify immediately before
# anything binds, and say WHAT holds the port if one is gone.
#
# The band removes the kernel-assignment race; this removes the remaining
# ambiguity. Without it a port taken between selection and start surfaces
# only as "public API did not answer within bound" plus a bind error buried
# in a service log, and the first thing anyone reading that has to work out
# is whether the port was ever free. Failing here says so directly, with
# the holder named where the host will tell us.
require_reserved_ports_free() {
  local entry label port holder offending=""
  for entry in "$@"; do
    label="${entry%%=*}"
    port="${entry##*=}"
    if python3 - "${port}" <<'PY'
import errno
import socket
import sys

with socket.socket() as probe:
    try:
        probe.bind(("127.0.0.1", int(sys.argv[1])))
    except OSError as error:
        if error.errno in (errno.EADDRINUSE, errno.EACCES):
            sys.exit(1)
        raise
sys.exit(0)
PY
    then
      continue
    fi
    holder="$(ss -ltnp "sport = :${port}" 2>/dev/null | tail -n +2)"
    [[ -n "${holder}" ]] || holder="(no listener reported by ss; the port may be held by a non-listening socket or by another namespace)"
    offending+="${label} port ${port} is no longer free: ${holder} "
  done
  if [[ -n "${offending}" ]]; then
    echo "the ports reserved for this run were taken between selection and start: ${offending%% }" >&2
    echo "these are drawn from outside the kernel's ephemeral range ($(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo unknown)), so this is a deliberate binder rather than an ephemeral-allocation race" >&2
    exit 1
  fi
}
reserve_port pg_port
reserve_port api_port
reserve_port agent_port
# The MECHANISM, not the outcome. A natural collision in a 4536-port band is
# so unlikely that a passing suite proves nothing about whether exclusions
# work at all, so each link of the chain is asserted directly: that the
# reservations accumulate in THIS shell, that the accumulated set actually
# reaches the selector and is honoured, and only then that the three ports
# came out distinct.
[[ ${#reserved_ports[@]} -eq 3 ]] || {
  echo "reserve_port did not accumulate its reservations in the calling shell (${#reserved_ports[@]} of 3); the exclusion set is being discarded, so two ports can collide" >&2
  exit 1
}
# shellcheck disable=SC2154 # assigned through reserve_port's nameref
[[ "${pg_port}" != "${api_port}" && "${api_port}" != "${agent_port}"   && "${pg_port}" != "${agent_port}" ]] || {
  echo "the three reserved ports are not pairwise distinct: ${pg_port} ${api_port} ${agent_port}" >&2
  exit 1
}
# Exclusions are honoured, proven by making them decisive: with the whole
# preferred band excluded, a selector that ignored the set would still
# return a port from it. Skipped only where the host's ephemeral range
# leaves no second band to fall back into, which is stated rather than
# silently passing.
(
  port_range_low="$(cut -f1 /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo 32768)"
  port_range_high="$(cut -f2 /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo 60999)"
  if [[ "${port_range_low}" -le 10240 || "${port_range_high}" -ge 65535 ]]; then
    echo "exclusion gate skipped: ip_local_port_range ${port_range_low}-${port_range_high} leaves only one band"
    exit 0
  fi
  reserved_ports=()
  for excluded in $(seq "$((port_range_high + 1))" 65535); do
    reserved_ports+=("${excluded}")
  done
  reserve_port forced_fallback
  # shellcheck disable=SC2154 # assigned through reserve_port's nameref
  [[ "${forced_fallback}" -lt "${port_range_low}" ]] || {
    echo "reserve_port returned ${forced_fallback} from a band every one of whose ports was excluded; the exclusion set is not reaching the selector" >&2
    exit 1
  }
)
# Outcome backstop over repeated triples. With the mechanism above proven
# this cannot fail without one of those assertions failing first, which is
# the point: it would localize a regression to the accumulation rather than
# to chance.
(
  for _ in $(seq 1 50); do
    reserved_ports=()
    reserve_port triple_a
    reserve_port triple_b
    reserve_port triple_c
    # shellcheck disable=SC2154 # assigned through reserve_port's nameref
    [[ "${triple_a}" != "${triple_b}" && "${triple_b}" != "${triple_c}"       && "${triple_a}" != "${triple_c}" ]] || {
      echo "reserve_port returned a duplicate within one triple: ${triple_a} ${triple_b} ${triple_c}" >&2
      exit 1
    }
  done
)

organization_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
project_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
pipeline_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
superuser_password="smoke-superuser-${suffix}"
tenant_password="smoke-tenant-${suffix}"
api_token="smoke-api-bearer-token-32-bytes-minimum-${suffix}"
artifact_token="smoke-artifact-agent-token-32-bytes-${suffix}"
agent_id="smoke-agent"

echo "== [5/9] mTLS material and environment contracts"
pki="${config}/pki"
openssl req -new -newkey rsa:2048 -nodes -x509 -days 1 \
  -subj "/CN=mcloving-smoke-ca" \
  -keyout "${pki}/ca-key.pem" -out "${pki}/ca.pem" >/dev/null 2>&1
printf 'subjectAltName=DNS:controller.internal,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' \
  > "${pki}/server.ext"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=controller.internal" \
  -keyout "${pki}/controller-server-key.pem" -out "${pki}/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "${pki}/server.csr" -CA "${pki}/ca.pem" \
  -CAkey "${pki}/ca-key.pem" -CAcreateserial -extfile "${pki}/server.ext" \
  -out "${pki}/controller-server.pem" >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > "${pki}/agent.ext"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${agent_id}" \
  -keyout "${pki}/agent-key.pem" -out "${pki}/agent.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "${pki}/agent.csr" -CA "${pki}/ca.pem" \
  -CAkey "${pki}/ca-key.pem" -CAcreateserial -extfile "${pki}/agent.ext" \
  -out "${pki}/agent.pem" >/dev/null 2>&1
cp "${pki}/ca.pem" "${pki}/agent-ca.pem"
cp "${pki}/ca.pem" "${pki}/controller-ca.pem"
openssl x509 -in "${pki}/agent.pem" -outform DER -out "${pki}/agent.der" >/dev/null 2>&1
agent_cert_sha256="$(sha256sum "${pki}/agent.der" | awk '{print $1}')"
printf '%s %s trusted-linux %s\n' "${agent_cert_sha256}" "${agent_id}" \
  "${organization_id}" > "${config}/agent-identity-bindings.txt"
# Identity bindings are identity material: the guard requires owner-only.
chmod 0600 "${config}/agent-identity-bindings.txt"

# Fill the installed placeholder contracts. The examples are the contract:
# only placeholder values and endpoints change. The example home prefix used
# to be rewritten here too; mcloving-install renders it now, and the gate
# above asserts nothing is left for this to rewrite.
fill_contract() {
  local file="$1"
  sed -i \
    -e "s/127\.0\.0\.1:5432/127.0.0.1:${pg_port}/g" \
    -e "s/127\.0\.0\.1:8080/127.0.0.1:${api_port}/g" \
    -e "s/127\.0\.0\.1:8443/127.0.0.1:${agent_port}/g" \
    -e "s/__SET_ME_POSTGRES_SUPERUSER_PASSWORD__/${superuser_password}/g" \
    -e "s/__SET_ME_TENANT_PASSWORD__/${tenant_password}/g" \
    -e "s/__SET_ME_API_BEARER_TOKEN_MINIMUM_32_BYTES__/${api_token}/g" \
    -e "s/__SET_ME_DISTINCT_ARTIFACT_TOKEN_MINIMUM_32_BYTES__/${artifact_token}/g" \
    -e "s/__SET_ME_ORGANIZATION_UUID__/${organization_id}/g" \
    -e "s/__SET_ME_ORGANIZATION_SLUG__/smoke-org/g" \
    -e "s/__SET_ME_PROJECT_UUID__/${project_id}/g" \
    -e "s/__SET_ME_PROJECT_SLUG__/smoke-project/g" \
    -e "s/__SET_ME_AGENT_ID__/${agent_id}/g" \
    -e "s/mcloving-postgres$/${container_name}/" \
    "${file}"
  if grep -Eq '__SET_ME_[A-Z0-9_]+__' "${file}"; then
    echo "contract ${file} still carries placeholders" >&2
    exit 1
  fi
}
for contract in postgres db-init controller agent; do
  fill_contract "${config}/${contract}.env"
done

# Mirror what StateDirectory= creates for the real units.
mkdir -p "${home}/.local/state/mcloving-controller" \
  "${home}/.local/state/mcloving-agent/workspace"

# Assert the guard ACCEPTS a valid contract, explicitly. Every other guard
# assertion in this file is a refusal, and a guard that refuses everything
# satisfies all of them; a break in the accepting path would otherwise surface
# much later as a confusing downstream failure. It has to come after the state
# directories above, because the agent contract names a workspace root the
# guard requires to exist -- which is what the units get from StateDirectory=.
for guarded in controller agent; do
  "${libexec}/helpers/mcloving-env-guard" "${guarded}" \
    "${config}/${guarded}.env" >/dev/null || {
    echo "env guard refused a valid ${guarded} contract:" >&2
    "${libexec}/helpers/mcloving-env-guard" "${guarded}" "${config}/${guarded}.env" >&2 || true
    exit 1
  }
done

# Private keys and identity bindings are stealable and replaceable identity
# material: readable-regular-file is not enough, and the guard now applies
# the installer's full secret-file treatment to the configured paths. A
# 0666 key must be refused by name at ExecStartPre; restored to 0600, the
# same contract must satisfy the guard again.
chmod 0666 "${pki}/agent-key.pem"
if "${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" \
  > "${workdir}/logs/guard-key-mode.log" 2>&1; then
  echo "env guard accepted a world-writable agent private key" >&2
  exit 1
fi
grep -q "agent-key.pem (mode 666, expected owner-only)" \
  "${workdir}/logs/guard-key-mode.log" || {
  echo "the guard's key-mode refusal did not name the path and mode:" >&2
  cat "${workdir}/logs/guard-key-mode.log" >&2
  exit 1
}
chmod 0600 "${pki}/agent-key.pem"
"${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" >/dev/null || {
  echo "env guard refused the restored 0600 agent private key" >&2
  exit 1
}
# Group-readable bindings leak nothing secret but invite substitution
# confusion; they are identity material and get the same owner-only rule.
chmod 0640 "${config}/agent-identity-bindings.txt"
if "${libexec}/helpers/mcloving-env-guard" controller "${config}/controller.env" \
  > "${workdir}/logs/guard-bindings-mode.log" 2>&1; then
  echo "env guard accepted group-readable identity bindings" >&2
  exit 1
fi
grep -q "agent-identity-bindings.txt (mode 640, expected owner-only)" \
  "${workdir}/logs/guard-bindings-mode.log" || {
  echo "the guard's bindings-mode refusal did not name the path and mode:" >&2
  cat "${workdir}/logs/guard-bindings-mode.log" >&2
  exit 1
}
chmod 0600 "${config}/agent-identity-bindings.txt"
"${libexec}/helpers/mcloving-env-guard" controller "${config}/controller.env" >/dev/null || {
  echo "env guard refused the restored owner-only bindings" >&2
  exit 1
}

# Trust inputs are public to READ and critical to WRITE: a writable CA lets
# another local user choose what the TLS handshake trusts. The class
# distinction from secret-file is pinned in both directions -- group/other
# READ stays legal for the CA while the same mode is refused for a key.
chmod 0666 "${pki}/controller-ca.pem"
if "${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" \
  > "${workdir}/logs/guard-ca-mode.log" 2>&1; then
  echo "env guard accepted a world-writable controller CA" >&2
  exit 1
fi
grep -q "controller-ca.pem (mode 666)" "${workdir}/logs/guard-ca-mode.log" || {
  echo "the writable-CA refusal did not name the path and mode:" >&2
  cat "${workdir}/logs/guard-ca-mode.log" >&2
  exit 1
}
chmod 0644 "${pki}/controller-ca.pem"
"${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" >/dev/null || {
  echo "env guard refused a world-READABLE 0644 CA; trust inputs are public to read" >&2
  exit 1
}
chmod 0644 "${pki}/agent-key.pem"
if "${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" \
  > "${workdir}/logs/guard-key-read.log" 2>&1; then
  echo "env guard accepted a group/other-readable private key" >&2
  exit 1
fi
grep -q "agent-key.pem (mode 644, expected owner-only)" \
  "${workdir}/logs/guard-key-read.log" || {
  echo "the readable-key refusal did not name the path and mode:" >&2
  cat "${workdir}/logs/guard-key-read.log" >&2
  exit 1
}
chmod 0600 "${pki}/agent-key.pem"
"${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" >/dev/null || {
  echo "env guard refused the restored key/CA pair" >&2
  exit 1
}

# A relative trust path means whatever the runtime working directory says
# it means -- ambient-context substitution. The guard refuses it by name;
# the inventory, which records drift rather than refusing, must SHOW it as
# a named record instead of silently skipping the un-inventoried file.
cp "${config}/agent.env" "${workdir}/agent.env.before-relative"
sed -i "s#^MCLOVING_CONTROLLER_CA_PATH=.*#MCLOVING_CONTROLLER_CA_PATH=relative/ca.pem#" \
  "${config}/agent.env"
grep -q "^MCLOVING_CONTROLLER_CA_PATH=relative/ca.pem\$" "${config}/agent.env" || {
  echo "relative-path gate could not rewrite MCLOVING_CONTROLLER_CA_PATH; contract shape changed" >&2
  exit 1
}
if "${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" \
  > "${workdir}/logs/guard-relative-path.log" 2>&1; then
  echo "env guard accepted a relative trust path" >&2
  exit 1
fi
grep -q "MCLOVING_CONTROLLER_CA_PATH must be an absolute path" \
  "${workdir}/logs/guard-relative-path.log" || {
  echo "the relative-path refusal did not name the variable:" >&2
  cat "${workdir}/logs/guard-relative-path.log" >&2
  exit 1
}
relative_doc="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${relative_doc}" <<'RELREC'
import json
import sys

document = json.loads(sys.argv[1])
records = [
    record
    for record in document.get("configured_paths", [])
    if record.get("kind") == "relative_configured_path"
]
if not records or records[0].get("variable") != "MCLOVING_CONTROLLER_CA_PATH":
    raise SystemExit(f"relative configured path not recorded by name: {records}")
RELREC
cp "${workdir}/agent.env.before-relative" "${config}/agent.env"
chmod 0600 "${config}/agent.env"
"${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" >/dev/null || {
  echo "env guard refused the restored absolute contract" >&2
  exit 1
}

# A directory NAME ending in a newline must still be judged: a bare
# command-substitution decode truncated the pathname, and a 0777 directory
# named "evil\n" holding an owner-only key was examined under the wrong
# name and accepted. The sentinel decoder round-trips the exact bytes.
trailnl_dir="${home}/evil-trail
"
trailnl_inner="${trailnl_dir}/inner"
mkdir -p "${trailnl_inner}"
chmod 0777 "${trailnl_dir}"
chmod 0700 "${trailnl_inner}"
cp "${pki}/ca.pem" "${trailnl_inner}/ca.pem"
chmod 0644 "${trailnl_inner}/ca.pem"
trailnl_env="${home}/trailnl.env"
python3 - "${config}/agent.env" "${trailnl_env}" "${trailnl_inner}/ca.pem" <<'TRAILNL'
import sys
from pathlib import Path

source, target, ca = sys.argv[1], sys.argv[2], sys.argv[3]
lines = []
for line in Path(source).read_text().splitlines():
    if line.startswith("MCLOVING_CONTROLLER_CA_PATH="):
        lines.append("MCLOVING_CONTROLLER_CA_PATH='" + ca + "'")
    else:
        lines.append(line)
Path(target).write_text("\n".join(lines) + "\n")
TRAILNL
chmod 0600 "${trailnl_env}"
if "${libexec}/helpers/mcloving-env-guard" agent "${trailnl_env}" \
  > "${workdir}/logs/guard-trailnl.log" 2>&1; then
  echo "env guard accepted a CA beneath a 0777 trailing-newline directory" >&2
  exit 1
fi
grep -q "(mode 777)" "${workdir}/logs/guard-trailnl.log" || {
  echo "the trailing-newline ancestor refusal did not carry the mode:" >&2
  cat "${workdir}/logs/guard-trailnl.log" >&2
  exit 1
}
chmod 0755 "${trailnl_dir}"
"${libexec}/helpers/mcloving-env-guard" agent "${trailnl_env}" >/dev/null || {
  echo "env guard refused the secured trailing-newline ancestor" >&2
  exit 1
}
rm -f "${trailnl_env}"
rm -rf "${trailnl_dir}"

# Optional variables inherit their class the moment they are set: a
# relative session receipt refused as ambient (state class), a
# group-readable effect plan refused as secret-class (the controller
# itself demands owner-only), a group-readable mapping catalog accepted
# as trust-class (read stays legal), and the unset originals untouched.
receipt_env="${home}/receipt-relative.env"
sed "s#^MCLOVING_AGENT_JOURNAL_PATH=#MCLOVING_AGENT_SESSION_RECEIPT_PATH=relative/receipt.json\nMCLOVING_AGENT_JOURNAL_PATH=#" \
  "${config}/agent.env" > "${receipt_env}"
chmod 0600 "${receipt_env}"
grep -q "^MCLOVING_AGENT_SESSION_RECEIPT_PATH=relative/receipt.json\$" "${receipt_env}" || {
  echo "receipt gate could not add MCLOVING_AGENT_SESSION_RECEIPT_PATH; contract shape changed" >&2
  exit 1
}
if "${libexec}/helpers/mcloving-env-guard" agent "${receipt_env}" \
  > "${workdir}/logs/guard-receipt-relative.log" 2>&1; then
  echo "env guard accepted a relative session receipt path" >&2
  exit 1
fi
grep -q "MCLOVING_AGENT_SESSION_RECEIPT_PATH must be an absolute path" \
  "${workdir}/logs/guard-receipt-relative.log" || {
  echo "the relative receipt refusal did not name the variable:" >&2
  cat "${workdir}/logs/guard-receipt-relative.log" >&2
  exit 1
}
rm -f "${receipt_env}"
# NODE KIND is part of the class, from the table's EXPECTED-KIND column.
# The agent reaches std::fs::read_to_string() on an EXISTING session
# receipt behind a bare path.exists(), so an owner-only FIFO there --
# mode 0600, owned by the service user, passing every mode/ownership
# check -- blocks the read forever and stalls the start probe until
# TimeoutStartSec kills a unit whose contract the guard just called
# satisfied. The timeout is the gate's own regression net: a guard that
# OPENED the path instead of stat-ing it would hang here.
receipt_fifo="${home}/receipt-node.fifo"
receipt_kind_env="${home}/receipt-kind.env"
rm -f "${receipt_fifo}"
mkfifo "${receipt_fifo}"
chmod 0600 "${receipt_fifo}"
sed "s#^MCLOVING_AGENT_JOURNAL_PATH=#MCLOVING_AGENT_SESSION_RECEIPT_PATH=${receipt_fifo}\nMCLOVING_AGENT_JOURNAL_PATH=#" \
  "${config}/agent.env" > "${receipt_kind_env}"
chmod 0600 "${receipt_kind_env}"
grep -q "^MCLOVING_AGENT_SESSION_RECEIPT_PATH=${receipt_fifo}\$" "${receipt_kind_env}" || {
  echo "receipt-kind gate could not add MCLOVING_AGENT_SESSION_RECEIPT_PATH; contract shape changed" >&2
  exit 1
}
receipt_kind_status=0
timeout 60 "${libexec}/helpers/mcloving-env-guard" agent "${receipt_kind_env}" \
  > "${workdir}/logs/guard-receipt-fifo.log" 2>&1 || receipt_kind_status=$?
if [[ "${receipt_kind_status}" -eq 0 ]]; then
  echo "env guard accepted a FIFO session receipt path" >&2
  exit 1
fi
if [[ "${receipt_kind_status}" -eq 124 ]]; then
  echo "the guard hung on a FIFO session receipt instead of refusing it" >&2
  exit 1
fi
grep -q "MCLOVING_AGENT_SESSION_RECEIPT_PATH=${receipt_fifo} (not a regular file: fifo)" \
  "${workdir}/logs/guard-receipt-fifo.log" || {
  echo "the FIFO receipt refusal did not name the variable and node kind:" >&2
  cat "${workdir}/logs/guard-receipt-fifo.log" >&2
  exit 1
}
# Acceptance: the same variable pointing at a regular file is admitted --
# the rule is node kind, not the variable being set at all.
rm -f "${receipt_fifo}"
printf 'session_epoch=0\n' > "${receipt_fifo}"
chmod 0600 "${receipt_fifo}"
"${libexec}/helpers/mcloving-env-guard" agent "${receipt_kind_env}" >/dev/null || {
  echo "env guard refused a regular-file session receipt" >&2
  exit 1
}
# The mirror direction: a state path classified as a DIRECTORY must be one.
# The workspace root is expected-kind directory, and a regular file there
# is refused by name rather than reaching the binary's own failure.
workspace_kind_env="${home}/workspace-kind.env"
workspace_file="${home}/workspace-as-file"
printf 'not a directory\n' > "${workspace_file}"
chmod 0600 "${workspace_file}"
sed "s#^MCLOVING_AGENT_WORKSPACE_ROOT=.*#MCLOVING_AGENT_WORKSPACE_ROOT=${workspace_file}#" \
  "${config}/agent.env" > "${workspace_kind_env}"
chmod 0600 "${workspace_kind_env}"
grep -q "^MCLOVING_AGENT_WORKSPACE_ROOT=${workspace_file}\$" "${workspace_kind_env}" || {
  echo "workspace-kind gate could not rewrite MCLOVING_AGENT_WORKSPACE_ROOT; contract shape changed" >&2
  exit 1
}
if "${libexec}/helpers/mcloving-env-guard" agent "${workspace_kind_env}" \
  > "${workdir}/logs/guard-workspace-kind.log" 2>&1; then
  echo "env guard accepted a regular file as the agent workspace root" >&2
  exit 1
fi
grep -qE "must be an existing directory|not a directory: regular file" \
  "${workdir}/logs/guard-workspace-kind.log" || {
  echo "the non-directory workspace refusal was not named:" >&2
  cat "${workdir}/logs/guard-workspace-kind.log" >&2
  exit 1
}
rm -f "${receipt_fifo}" "${receipt_kind_env}" "${workspace_kind_env}" "${workspace_file}"
# The binaries read the PROCESS ENVIRONMENT, which systemd composes from
# the manager environment, Environment= in the unit and its drop-ins, and
# every EnvironmentFile= in order. A guard that judged only the parsed
# contract validated one input while the service received another. This
# guard runs as ExecStartPre of that very unit, so the composition is
# already in its own environment and is READ rather than re-derived.
ambient_env="${home}/ambient.env"
cp "${config}/agent.env" "${ambient_env}"
chmod 0600 "${ambient_env}"
mkdir -p "${home}/ambient-wide"
printf 'session_epoch=0\n' > "${home}/ambient-wide/receipt"
chmod 0600 "${home}/ambient-wide/receipt"
# (1) A classified path variable supplied ONLY by the environment. The
# digest inventory pins what the CONTRACT declares, so an ambient value is
# validated once and then unwatched -- refused by name.
if MCLOVING_AGENT_SESSION_RECEIPT_PATH="${home}/ambient-wide/receipt" \
  "${libexec}/helpers/mcloving-env-guard" agent "${ambient_env}" \
  > "${workdir}/logs/guard-ambient-absent.log" 2>&1; then
  echo "env guard accepted a classified path supplied only by the environment" >&2
  exit 1
fi
grep -q "MCLOVING_AGENT_SESSION_RECEIPT_PATH (service environment says ${home}/ambient-wide/receipt, ${ambient_env} does not declare it)" \
  "${workdir}/logs/guard-ambient-absent.log" || {
  echo "the ambient classified path was not named:" >&2
  cat "${workdir}/logs/guard-ambient-absent.log" >&2
  exit 1
}
# (2) A classified path set in BOTH but DISAGREEING: the document would pin
# the contract's value while the service opened another.
if MCLOVING_AGENT_WORKSPACE_ROOT="${home}/ambient-wide" \
  "${libexec}/helpers/mcloving-env-guard" agent "${ambient_env}" \
  > "${workdir}/logs/guard-ambient-differs.log" 2>&1; then
  echo "env guard accepted an environment value disagreeing with the contract" >&2
  exit 1
fi
grep -q "MCLOVING_AGENT_WORKSPACE_ROOT (service environment says ${home}/ambient-wide, ${ambient_env} says " \
  "${workdir}/logs/guard-ambient-differs.log" || {
  echo "the disagreeing environment value was not named:" >&2
  cat "${workdir}/logs/guard-ambient-differs.log" >&2
  exit 1
}
# (3) Acceptance: the same variable set in the environment to the SAME
# value the contract declares is no asymmetry at all -- this is what
# ExecStartPre sees in production, where systemd has loaded the contract
# into the environment itself, so refusing it would refuse every real
# start.
ambient_workspace="$(sed -n 's/^MCLOVING_AGENT_WORKSPACE_ROOT=//p' "${ambient_env}")"
[[ -n "${ambient_workspace}" ]] || {
  echo "ambient gate could not read the contract's workspace root; contract shape changed" >&2
  exit 1
}
MCLOVING_AGENT_WORKSPACE_ROOT="${ambient_workspace}" \
  "${libexec}/helpers/mcloving-env-guard" agent "${ambient_env}" >/dev/null || {
  echo "env guard refused an environment value identical to the contract's" >&2
  exit 1
}
# (4) The composition is actually APPLIED, not merely compared: a contract
# whose non-path variable still carries its placeholder is admitted when the
# SERVICE'S environment supplies the real value, because that is what the
# binary receives. Same mechanism, observed from the other side.
#
# The overlay is scoped to the invocation mode where it is TRUE. Run by
# hand, an ambient MCLOVING_AGENT_ID in an operator's shell is not what the
# service will receive -- systemd will hand the binary the contract's value
# through EnvironmentFile= -- so judging the ambient one would report a
# contract satisfied that is not. That is asserted here too, because it is
# the direction that was previously wrong.
placeholder_env="${home}/placeholder-ambient.env"
sed 's/^MCLOVING_AGENT_ID=.*/MCLOVING_AGENT_ID=__SET_ME_AGENT_ID__/' \
  "${config}/agent.env" > "${placeholder_env}"
chmod 0600 "${placeholder_env}"
if "${libexec}/helpers/mcloving-env-guard" agent "${placeholder_env}" >/dev/null 2>&1; then
  echo "env guard accepted a placeholder with nothing overriding it" >&2
  exit 1
fi
if MCLOVING_AGENT_ID=smoke-agent \
  "${libexec}/helpers/mcloving-env-guard" agent "${placeholder_env}" >/dev/null 2>&1; then
  echo "env guard judged an ambient value as though the service would receive it, outside any unit" >&2
  exit 1
fi
( set -a
  # shellcheck disable=SC1090
  . "${placeholder_env}"
  set +a
  export MCLOVING_AGENT_ID=smoke-agent
  INVOCATION_ID=mcloving-smoke bash -c 'SYSTEMD_EXEC_PID=$$ exec "$0" "$@"' \
    "${libexec}/helpers/mcloving-env-guard" agent "${placeholder_env}" \
  ) >/dev/null || {
  echo "env guard judged the contract placeholder rather than the value the service receives" >&2
  exit 1
}
rm -rf "${ambient_env}" "${placeholder_env}" "${home}/ambient-wide"
# EVERY GUARD, IN THE ENVIRONMENT ITS OWN UNIT WILL GIVE IT.
#
# This is the gate whose absence let a total breakage ship: the suite ran
# every guard BY HAND, where nothing is composed and the parsed contract
# stands, so it never exercised the path a real start takes. With the
# invocation markers present the effective-environment rule is
# two-directional, and a unit that does not put its contract into its OWN
# environment makes the guard refuse -- on every start, taking the service
# and its dependents with it. The postgres quadlet did exactly that:
# [Container] EnvironmentFile= becomes podman's --env-file and reaches the
# CONTAINER, while quadlet copies that section into an inert [X-Container]
# record the manager ignores, so ExecStartPre saw none of it.
#
# The environment is derived SECTION-AWARE from each unit, because the whole
# defect is that a declaration in the wrong section looks identical to one
# in the right section.
guard_env_probe="${workdir}/guard-unit-env"
mkdir -p "${guard_env_probe}"
while IFS='|' read -r probe_unit probe_service probe_contract; do
  [[ -n "${probe_unit}" ]] || continue
  probe_env_file="${guard_env_probe}/${probe_service}.env"
  python3 - "${probe_unit}" "${home}" > "${probe_env_file}" <<'UNITENV'
import pathlib
import sys

unit, home = pathlib.Path(sys.argv[1]), sys.argv[2]
section = ""
env_files = []
inline = []
for raw in unit.read_text().splitlines():
    line = raw.strip()
    if line.startswith("[") and line.endswith("]"):
        section = line
        continue
    if section != "[Service]" or "=" not in line or line.startswith(("#", ";")):
        continue
    key, _, value = line.partition("=")
    key = key.strip()
    value = value.strip()
    # ONLY the unit's own [Service] section. A [Container] declaration is
    # podman's, not the manager's, which is precisely the confusion here.
    if key == "EnvironmentFile":
        env_files.append(value.lstrip("-").replace("%h", home))
    elif key == "Environment":
        inline.append(value)
for path in env_files:
    try:
        for raw in pathlib.Path(path).read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith(("#", ";")) and "=" in line:
                print(line)
    except OSError:
        pass
for entry in inline:
    print(entry.replace("%h", home))
UNITENV
  probe_status=0
  ( set -a
    # shellcheck disable=SC1090
    . "${probe_env_file}"
    set +a
    INVOCATION_ID=mcloving-smoke bash -c 'SYSTEMD_EXEC_PID=$$ exec "$0" "$@"' \
      "${libexec}/helpers/mcloving-env-guard" "${probe_service}" "${probe_contract}" \
  ) > "${workdir}/logs/guard-unit-env-${probe_service}.log" 2>&1 || probe_status=$?
  if [[ "${probe_status}" -ne 0 ]]; then
    echo "the ${probe_service} guard refuses in the environment its own unit provides (exit ${probe_status}); a real start of that unit would fail:" >&2
    cat "${workdir}/logs/guard-unit-env-${probe_service}.log" >&2
    exit 1
  fi
  grep -q "contract satisfied" "${workdir}/logs/guard-unit-env-${probe_service}.log" || {
    echo "the ${probe_service} guard did not report the contract satisfied under its own unit environment:" >&2
    cat "${workdir}/logs/guard-unit-env-${probe_service}.log" >&2
    exit 1
  }
  # The gate must be able to FAIL: with the unit's own environment withheld,
  # the same guard must refuse. Otherwise a unit that provides nothing would
  # pass this check for the wrong reason.
  withheld_status=0
  INVOCATION_ID=mcloving-smoke bash -c 'SYSTEMD_EXEC_PID=$$ exec "$0" "$@"' \
    "${libexec}/helpers/mcloving-env-guard" "${probe_service}" "${probe_contract}" \
    > "${workdir}/logs/guard-unit-env-${probe_service}-withheld.log" 2>&1 \
    || withheld_status=$?
  [[ "${withheld_status}" -ne 0 ]] || {
    echo "the ${probe_service} guard accepted an empty effective environment; this gate cannot detect the defect it exists for" >&2
    exit 1
  }
done <<UNITENVPROBE
${smoke_quadlet_root}/mcloving-postgres.container|postgres|${config}/postgres.env
${smoke_unit_root}/mcloving-db-init.service|db-init|${config}/db-init.env
${smoke_unit_root}/mcloving-controller.service|controller|${config}/controller.env
${smoke_unit_root}/mcloving-agent.service|agent|${config}/agent.env
UNITENVPROBE
rm -rf "${guard_env_probe}"
# And the container still gets its own variables: the [Container]
# declaration must survive as podman's --env-file, or the guard fix would
# have traded one break for another.
grep -qE '^\[Container\]' "${smoke_quadlet_root}/mcloving-postgres.container" || {
  echo "the postgres quadlet lost its [Container] section" >&2
  exit 1
}
python3 - "${smoke_quadlet_root}/mcloving-postgres.container" <<'BOTHHALVES'
import pathlib
import sys

section = ""
seen = {}
for raw in pathlib.Path(sys.argv[1]).read_text().splitlines():
    line = raw.strip()
    if line.startswith("[") and line.endswith("]"):
        section = line
        continue
    if line.startswith("EnvironmentFile="):
        seen.setdefault(section, []).append(line.split("=", 1)[1])
for section_name in ("[Container]", "[Service]"):
    if section_name not in seen:
        raise SystemExit(
            f"the postgres quadlet has no EnvironmentFile= in {section_name}; "
            "[Container] feeds the container through podman --env-file and "
            "[Service] feeds the unit's own ExecStartPre guard, and both are "
            "required"
        )
if seen["[Container]"] != seen["[Service]"]:
    raise SystemExit(
        f"the postgres quadlet points its two EnvironmentFile= declarations at "
        f"different files ({seen['[Container]']} vs {seen['[Service]']}); the "
        "container and its guard must validate the same contract"
    )
BOTHHALVES
# THE EFFECTIVE ENVIRONMENT IN BOTH DIRECTIONS. Round 32 taught the guard
# that a variable the environment CARRIES wins over the contract. The other
# half is that a variable the environment does NOT carry will not reach the
# service at all -- which is what a drop-in resetting EnvironmentFile=, or
# replacing it with a file omitting a variable, produces. These gates run the
# helpers with systemd's own markers reproduced exactly (INVOCATION_ID set and
# SYSTEMD_EXEC_PID equal to the helper's own pid, via `exec` so the pid
# survives) rather than through any test-only switch, so what is proven here
# is what systemd will do.
effective_env_file="${home}/effective-agent.env"
cp "${config}/agent.env" "${effective_env_file}"
chmod 0600 "${effective_env_file}"
# (1) ExecStartPre mode, one required variable missing from the effective
# environment: refused by name, and the message must say the variable will
# not REACH the service rather than that it is unset in the file.
if ( set -a
     # shellcheck disable=SC1090
     . "${effective_env_file}"
     set +a
     unset MCLOVING_AGENT_ID
     INVOCATION_ID=mcloving-smoke bash -c 'SYSTEMD_EXEC_PID=$$ exec "$0" "$@"' \
       "${libexec}/helpers/mcloving-env-guard" agent "${effective_env_file}" \
     ) > "${workdir}/logs/guard-effective-missing.log" 2>&1; then
  echo "env guard reported satisfied for a required variable the service will never receive" >&2
  exit 1
fi
grep -q "required variable MCLOVING_AGENT_ID is declared in ${effective_env_file} but will NOT reach this service" \
  "${workdir}/logs/guard-effective-missing.log" || {
  echo "the unreachable required variable was not named:" >&2
  cat "${workdir}/logs/guard-effective-missing.log" >&2
  exit 1
}
# (2) ExecStartPre mode with the full effective environment: satisfied. This
# is what every real start looks like, so a rule that refused here would
# refuse every start.
( set -a
  # shellcheck disable=SC1090
  . "${effective_env_file}"
  set +a
  INVOCATION_ID=mcloving-smoke bash -c 'SYSTEMD_EXEC_PID=$$ exec "$0" "$@"' \
    "${libexec}/helpers/mcloving-env-guard" agent "${effective_env_file}" \
  ) >/dev/null || {
  echo "env guard refused a complete effective environment" >&2
  exit 1
}
# (3) BY HAND, nothing composed: the parsed contract stands, unchanged from
# before round 32. This is how the suite and operators invoke the guard, and
# it is the acceptance case the strict rule must not break.
"${libexec}/helpers/mcloving-env-guard" agent "${effective_env_file}" >/dev/null || {
  echo "env guard refused a hand-run contract that declares everything" >&2
  exit 1
}
# (4) A DESCENDANT of the executed process is not the executed process:
# INVOCATION_ID is inherited, SYSTEMD_EXEC_PID names someone else, so the
# strict rule must not engage and the contract must stand. This is the
# loophole the two-part marker closes.
( set -a
  # shellcheck disable=SC1090
  . "${effective_env_file}"
  set +a
  unset MCLOVING_AGENT_ID
  INVOCATION_ID=mcloving-smoke SYSTEMD_EXEC_PID=1 \
    "${libexec}/helpers/mcloving-env-guard" agent "${effective_env_file}" \
  ) >/dev/null || {
  echo "the strict effective-environment rule engaged for a process systemd did not execute" >&2
  exit 1
}
rm -f "${effective_env_file}"
# The health helper probes the EFFECTIVE listen address. The shipped
# controller unit runs it as ExecStartPost, so a drop-in overriding
# MCLOVING_LISTEN means systemd started the controller somewhere the original
# contract does not name -- and a helper reparsing only that contract kills a
# healthy controller as a startup failure.
health_env="${home}/effective-controller.env"
reserve_port health_stale_port
reserve_port health_live_port
# shellcheck disable=SC2154 # assigned through reserve_port's nameref
printf 'MCLOVING_LISTEN=127.0.0.1:%s\n' "${health_stale_port}" > "${health_env}"
chmod 0600 "${health_env}"
# shellcheck disable=SC2154 # assigned through reserve_port's nameref
python3 - "${health_live_port}" > "${workdir}/logs/health-effective-server.log" 2>&1 <<'HEALTHSRV' &
import http.server
import socketserver
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", int(sys.argv[1])), Handler) as server:
    server.serve_forever()
HEALTHSRV
health_server_pid=$!
register_background_pid "${health_server_pid}"
for _ in $(seq 1 40); do
  curl --silent --fail --max-time 1 --noproxy '*' \
    "http://127.0.0.1:${health_live_port}/openapi.json" >/dev/null 2>&1 && break
  sleep 0.25
done
health_effective_status=0
timeout 20 env INVOCATION_ID=mcloving-smoke \
  MCLOVING_LISTEN="127.0.0.1:${health_live_port}" \
  bash -c 'SYSTEMD_EXEC_PID=$$ exec "$0" "$@"' \
  "${libexec}/helpers/mcloving-health" controller "${health_env}" \
  > "${workdir}/logs/health-effective.log" 2>&1 || health_effective_status=$?
release_background_pid "${health_server_pid}"
if [[ "${health_effective_status}" -ne 0 ]]; then
  echo "the health helper did not probe the address the unit was actually started on (exit ${health_effective_status}):" >&2
  cat "${workdir}/logs/health-effective.log" >&2
  exit 1
fi
grep -q "public API answers on 127.0.0.1:${health_live_port}" \
  "${workdir}/logs/health-effective.log" || {
  echo "the health helper reported success against the wrong address:" >&2
  cat "${workdir}/logs/health-effective.log" >&2
  exit 1
}
rm -f "${health_env}"
# BOTH MAPS. The overlay must not destroy the DECLARED value: round 32's
# refusal for a classified path whose effective value disagrees with the
# contract compares the two, and an overlay written straight onto
# MCLOVING_CONTRACT made it compare a value with itself, so it could never
# fire. Semantics are round 32's, unchanged: refuse by name, both values
# shown.
declared_env_file="${home}/declared-vs-effective.env"
cp "${config}/agent.env" "${declared_env_file}"
chmod 0600 "${declared_env_file}"
declared_workspace="$(sed -n 's/^MCLOVING_AGENT_WORKSPACE_ROOT=//p' "${declared_env_file}")"
[[ -n "${declared_workspace}" ]] || {
  echo "the declared/effective gate could not read the workspace root; contract shape changed" >&2
  exit 1
}
mkdir -p "${home}/effective-elsewhere"
if ( set -a
     # shellcheck disable=SC1090
     . "${declared_env_file}"
     set +a
     export MCLOVING_AGENT_WORKSPACE_ROOT="${home}/effective-elsewhere"
     INVOCATION_ID=mcloving-smoke bash -c 'SYSTEMD_EXEC_PID=$$ exec "$0" "$@"' \
       "${libexec}/helpers/mcloving-env-guard" agent "${declared_env_file}" \
     ) > "${workdir}/logs/guard-declared-mismatch.log" 2>&1; then
  echo "env guard accepted a classified path whose effective value disagrees with the contract" >&2
  exit 1
fi
grep -q "MCLOVING_AGENT_WORKSPACE_ROOT (service environment says ${home}/effective-elsewhere, ${declared_env_file} says ${declared_workspace})" \
  "${workdir}/logs/guard-declared-mismatch.log" || {
  echo "the declared/effective mismatch did not name BOTH values:" >&2
  cat "${workdir}/logs/guard-declared-mismatch.log" >&2
  exit 1
}
# Acceptance: agreement is not a mismatch. This is what every real start
# looks like, since systemd loads the contract into the environment itself.
( set -a
  # shellcheck disable=SC1090
  . "${declared_env_file}"
  set +a
  INVOCATION_ID=mcloving-smoke bash -c 'SYSTEMD_EXEC_PID=$$ exec "$0" "$@"' \
    "${libexec}/helpers/mcloving-env-guard" agent "${declared_env_file}" \
  ) >/dev/null || {
  echo "env guard refused an effective environment that agrees with the contract" >&2
  exit 1
}
rm -rf "${declared_env_file}" "${home}/effective-elsewhere"
# A TRANSITION is not the unit. It must ask the manager what the service is
# actually running with, and refuse rather than probe an address it cannot
# ground -- the release has already moved by then.
if (
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  deployment_manager_is_reachable
); then
  reserve_port transition_stale_port
  reserve_port transition_live_port
  transition_env="${home}/transition-health.env"
  # shellcheck disable=SC2154 # assigned through reserve_port's nameref
  printf 'MCLOVING_LISTEN=127.0.0.1:%s\n' "${transition_stale_port}" > "${transition_env}"
  chmod 0600 "${transition_env}"
  transition_srv="${workdir}/transition-health-server.py"
  cat > "${transition_srv}" <<'TRANSSRV'
import http.server
import os
import socketserver


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


socketserver.TCPServer.allow_reuse_address = True
port = int(os.environ["MCLOVING_LISTEN"].rsplit(":", 1)[1])
with socketserver.TCPServer(("127.0.0.1", port), Handler) as server:
    server.serve_forever()
TRANSSRV
  transition_unit="mcloving-smoke-health-$$.service"
  # shellcheck disable=SC2154 # assigned through reserve_port's nameref
  systemd-run --user --quiet --unit="${transition_unit}" --property=Type=simple \
    --property="Environment=MCLOVING_LISTEN=127.0.0.1:${transition_live_port}" \
    /usr/bin/python3 "${transition_srv}" >/dev/null 2>&1 || {
    echo "the transition-health gate could not start its probe unit" >&2
    exit 1
  }
  for _ in $(seq 1 40); do
    curl --silent --fail --max-time 1 --noproxy '*' \
      "http://127.0.0.1:${transition_live_port}/openapi.json" >/dev/null 2>&1 && break
    sleep 0.25
  done
  transition_health_status=0
  timeout 20 "${libexec}/helpers/mcloving-health" controller "${transition_env}" \
    --unit "${transition_unit}" > "${workdir}/logs/transition-health.log" 2>&1 \
    || transition_health_status=$?
  if [[ "${transition_health_status}" -ne 0 ]]; then
    systemctl --user stop "${transition_unit}" >/dev/null 2>&1 || true
    systemctl --user reset-failed "${transition_unit}" >/dev/null 2>&1 || true
    echo "a transition health check did not probe the address the unit is running on (exit ${transition_health_status}):" >&2
    cat "${workdir}/logs/transition-health.log" >&2
    exit 1
  fi
  grep -q "public API answers on 127.0.0.1:${transition_live_port}" \
    "${workdir}/logs/transition-health.log" || {
    systemctl --user stop "${transition_unit}" >/dev/null 2>&1 || true
    systemctl --user reset-failed "${transition_unit}" >/dev/null 2>&1 || true
    echo "the transition health check reported success against the wrong address:" >&2
    cat "${workdir}/logs/transition-health.log" >&2
    exit 1
  }
  # With the unit stopped the manager cannot say what it was running with, so
  # the verdict is REFUSED rather than derived from the contract. A derived
  # "healthy" here would conclude success for a deployment nobody probed,
  # after the release has already moved.
  systemctl --user stop "${transition_unit}" >/dev/null 2>&1 || true
  systemctl --user reset-failed "${transition_unit}" >/dev/null 2>&1 || true
  transition_unreachable_status=0
  timeout 20 "${libexec}/helpers/mcloving-health" controller "${transition_env}" \
    --unit "${transition_unit}" > "${workdir}/logs/transition-health-gone.log" 2>&1 \
    || transition_unreachable_status=$?
  [[ "${transition_unreachable_status}" -ne 0 ]] || {
    echo "a transition health check rendered a verdict for a unit the manager could not describe" >&2
    exit 1
  }
  grep -q "refusing to render a health verdict from the declared contract alone" \
    "${workdir}/logs/transition-health-gone.log" || {
    echo "the ungroundable health verdict was not refused by name:" >&2
    cat "${workdir}/logs/transition-health-gone.log" >&2
    exit 1
  }
  rm -f "${transition_env}" "${transition_srv}"
else
  echo "transition health gate skipped: no reachable systemctl --user on this host; the --no-systemd path (no --unit, contract stands) is what runs here"
fi
# THE CLASS, not the two instances: a helper that runs INSIDE a unit must
# read the effective contract, never reparse the declared one. Static, so a
# new in-unit consumer cannot reopen this by copying the old idiom.
python3 - "${repo_root}" <<'EFFECTIVE'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]) / "deploy"
# Helpers systemd executes as a unit command, from the shipped unit files.
in_unit = set()
for unit in list((root / "systemd").glob("*.service")) + list((root / "podman").glob("*.container")):
    for line in unit.read_text().splitlines():
        match = re.match(r"\s*Exec[A-Za-z]*\s*=\s*(.*)", line)
        if not match:
            continue
        for token in match.group(1).split():
            name = token.rsplit("/", 1)[-1]
            if name.startswith("mcloving-"):
                in_unit.add(name)
            break
if not in_unit:
    raise SystemExit("the in-unit helper sweep found nothing; the unit shape changed")
for name in sorted(in_unit):
    helper = root / "bin" / name
    if not helper.exists():
        continue
    body = helper.read_text()
    if "load_environment_file" not in body and "load_effective_contract" not in body:
        continue
    if "load_effective_contract" not in body:
        raise SystemExit(
            f"{name} runs inside a unit but parses the declared contract with "
            "load_environment_file; an in-unit consumer must read the effective "
            "environment through load_effective_contract"
        )
    for hit in re.findall(r"^\s*load_environment_file\b.*$", body, re.M):
        raise SystemExit(
            f"{name} runs inside a unit and still calls load_environment_file "
            f"directly ({hit.strip()}); route it through load_effective_contract"
        )
EFFECTIVE
effect_plan="${home}/effect-plan.json"
printf '{}' > "${effect_plan}"
chmod 0644 "${effect_plan}"
effect_env="${home}/effect-plan.env"
sed "s#^MCLOVING_LISTEN=#MCLOVING_EFFECT_RUNTIME_PLAN=${effect_plan}\nMCLOVING_LISTEN=#" \
  "${config}/controller.env" > "${effect_env}"
chmod 0600 "${effect_env}"
grep -q "^MCLOVING_EFFECT_RUNTIME_PLAN=${effect_plan}\$" "${effect_env}" || {
  echo "effect gate could not add MCLOVING_EFFECT_RUNTIME_PLAN; contract shape changed" >&2
  exit 1
}
if "${libexec}/helpers/mcloving-env-guard" controller "${effect_env}" \
  > "${workdir}/logs/guard-effect-plan.log" 2>&1; then
  echo "env guard accepted a group-readable effect runtime plan" >&2
  exit 1
fi
grep -q "effect-plan.json (mode 644, expected owner-only)" \
  "${workdir}/logs/guard-effect-plan.log" || {
  echo "the effect-plan refusal did not name the path and mode:" >&2
  cat "${workdir}/logs/guard-effect-plan.log" >&2
  exit 1
}
chmod 0600 "${effect_plan}"
"${libexec}/helpers/mcloving-env-guard" controller "${effect_env}" >/dev/null || {
  echo "env guard refused an owner-only effect runtime plan" >&2
  exit 1
}
# Parity with the binary: the controller inspects the plan with
# symlink_metadata() and refuses every symlink, so the guard must refuse
# the link itself rather than follow it to a valid target and report a
# contract the unit then fails on after ExecStartPre.
mv "${effect_plan}" "${effect_plan}.real"
ln -s "${effect_plan}.real" "${effect_plan}"
if "${libexec}/helpers/mcloving-env-guard" controller "${effect_env}" \
  > "${workdir}/logs/guard-effect-symlink.log" 2>&1; then
  echo "env guard accepted a symlinked effect runtime plan the controller refuses" >&2
  exit 1
fi
grep -q "MCLOVING_EFFECT_RUNTIME_PLAN must not be a symlink" \
  "${workdir}/logs/guard-effect-symlink.log" || {
  echo "the symlinked-plan refusal did not name the parity rule:" >&2
  cat "${workdir}/logs/guard-effect-symlink.log" >&2
  exit 1
}
rm -f "${effect_plan}"
mv "${effect_plan}.real" "${effect_plan}"
catalog_env="${home}/effect-catalog.env"
sed "s#^MCLOVING_LISTEN=#MCLOVING_EFFECT_MAPPING_CATALOG=${effect_plan}\nMCLOVING_LISTEN=#" \
  "${config}/controller.env" > "${catalog_env}"
chmod 0600 "${catalog_env}"
chmod 0644 "${effect_plan}"
"${libexec}/helpers/mcloving-env-guard" controller "${catalog_env}" >/dev/null || {
  echo "env guard refused a world-READABLE mapping catalog; trust inputs are public to read" >&2
  exit 1
}
# A trust input that exists must be a REGULAR file: mode, owner, and
# readability all hold for a 0644 FIFO, and the consuming binary would
# then block on the read after ExecStartPre reported the contract
# satisfied. The optional trust inputs never pass require_readable_file,
# so the class itself must carry the node-type rule.
rm -f "${effect_plan}"
mkfifo "${effect_plan}"
chmod 0644 "${effect_plan}"
if "${libexec}/helpers/mcloving-env-guard" controller "${catalog_env}" \
  > "${workdir}/logs/guard-catalog-fifo.log" 2>&1; then
  echo "env guard accepted a FIFO mapping catalog" >&2
  exit 1
fi
grep -q "not a regular file: fifo" "${workdir}/logs/guard-catalog-fifo.log" || {
  echo "the FIFO catalog refusal was not named:" >&2
  cat "${workdir}/logs/guard-catalog-fifo.log" >&2
  exit 1
}
rm -f "${effect_env}" "${catalog_env}" "${effect_plan}"

run_with_env() { # ENV_FILE COMMAND...
  local env_file="$1"
  shift
  (
    set -a
    # shellcheck disable=SC1090
    source "${env_file}"
    set +a
    exec "$@"
  )
}

# spawn_with_env ENV_FILE COMMAND... -- the background-only twin of
# run_with_env, for the long-lived services. INVOKE ONLY AS A BACKGROUND JOB.
#
# `run_with_env ... &` forks twice: once for the job, and again for the
# function's own `( ... )`. ${!} therefore names the outer bash wrapper, not
# the service that the inner fork execs. Killing that wrapper -- which is
# all the EXIT trap could ever do -- left the controller and the agent
# running, reparented to init, against a ${workdir} the success path had
# already deleted. Every clean pass leaked a pair.
#
# Exec'ing in the job's own fork makes ${!} the service itself, the same
# single-process discipline the transition-lock holders below rely on.
#
# The BASHPID/$$ comparison is the invocation guard: the two differ only
# inside a subshell, so a foreground call is caught here rather than by
# `exec` silently replacing the running suite.
spawn_with_env() { # ENV_FILE COMMAND...
  local env_file="$1"
  shift
  if [[ "${BASHPID}" == "$$" ]]; then
    echo "spawn_with_env must be invoked as a background job (&): $*" >&2
    exit 1
  fi
  set -a
  # shellcheck disable=SC1090
  source "${env_file}"
  set +a
  exec "$@"
}

# require_service_pid PID LABEL -- assert ${!} named the service, not a shell.
#
# The spawn discipline above is subtle enough to be undone by an edit that
# reads as a simplification, and the regression is silent in the worst way:
# the trap still kills what it was told to kill, `wait` still returns, and
# the run still reports success -- while the service outlives it, reparented
# to init, against a ${workdir} the success path then deletes. That is how a
# pair leaked from every clean pass for two days without one run going red.
# An unasserted invariant is indistinguishable from a broken one, so assert
# it: a wrapper reports `bash` here, the service reports its own name.
#
# The poll covers the window between the fork and its `exec`, which is one
# sourced environment file wide; a service that dies inside that window is
# reported as the failure it is rather than as a wrapper.
require_service_pid() { # PID LABEL
  local pid="$1" label="$2" comm=""
  for _ in $(seq 1 100); do
    comm="$(cat "/proc/${pid}/comm" 2>/dev/null || true)"
    [[ "${comm}" == mcloving-* ]] && return 0
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "${pid}" 2>/dev/null; then
    echo "${label} pid ${pid} is '${comm}', not the service itself: the spawn" \
      "is wrapping it in a shell, so the exit trap would kill the wrapper and" \
      "leak the service to init. Spawn it with spawn_with_env, not" \
      "run_with_env." >&2
  else
    echo "${label} pid ${pid} exited immediately; its log:" >&2
    cat "${workdir}/logs/${label}.log" >&2 || true
  fi
  exit 1
}

derived_argv() { # OUT_ARRAY_NAME JSON_FILE JQ_PATH
  # shellcheck disable=SC2034 # assigned through the nameref
  local -n out_ref="$1"
  # shellcheck disable=SC2034 # assigned through the nameref
  mapfile -d '' -t out_ref < <(jq -j "$3 | join(\"\\u0000\")" "$2")
}

echo "== [6/9] postgres (derived from quadlet) -> db-init -> controller -> agent"
require_reserved_ports_free "postgres-publish=${pg_port}" \
  "controller-public-api=${api_port}" "controller-agent-control=${agent_port}"
"${unit_command}" "${smoke_quadlet_root}/mcloving-postgres.container" \
  --home "${home}" --publish-override "127.0.0.1:${pg_port}" \
  --name-override "${container_name}" --volume-override "${volume_name}" \
  > "${workdir}/postgres.derived.json"
pre_argv=()
derived_argv pre_argv "${workdir}/postgres.derived.json" '.exec_start_pre[0]'
"${pre_argv[@]}" > "${workdir}/logs/postgres-volume.log" 2>&1 || {
  echo "postgres volume creation failed:" >&2
  cat "${workdir}/logs/postgres-volume.log" >&2
  podman info --format '{{.Host.CgroupsVersion}} {{.Host.CgroupManager}}' >&2 2>&1 || true
  exit 1
}
postgres_argv=()
derived_argv postgres_argv "${workdir}/postgres.derived.json" '.exec_start'
# Output captured rather than discarded: when this fails the smoke test has
# nothing else to say about why, and a container that will not start is the
# single most likely thing to differ between an operator's host and a CI
# runner. Podman's host configuration is printed alongside, since rootless
# cgroup and user-namespace setup is what usually differs.
"${postgres_argv[@]}" > "${workdir}/logs/postgres.log" 2>&1 || {
  echo "postgres container failed to start:" >&2
  cat "${workdir}/logs/postgres.log" >&2
  podman info --format '{{.Host.CgroupsVersion}} {{.Host.CgroupManager}} {{.Host.OCIRuntime.Name}}' >&2 2>&1 || true
  exit 1
}
health_argv=()
derived_argv health_argv "${workdir}/postgres.derived.json" '.health_cmd'
echo "postgres container started; waiting for the derived health command"
# Two consecutive successes, exactly like mcloving-db-init's ready() wait:
# the pinned image's entrypoint starts a temporary server during
# initialization and restarts it, and a single success can land in that
# window -- after which the settling re-check below meets a server that is
# gone again.
for _ in $(seq 1 120); do
  if podman exec "${container_name}" "${health_argv[@]}" >/dev/null 2>&1; then
    sleep 0.5
    if podman exec "${container_name}" "${health_argv[@]}" >/dev/null 2>&1; then
      break
    fi
  fi
  sleep 0.5
done
# The settling re-check used to discard its output and had no failure
# handler, so the one failure CI actually produced was pg_isready's exit
# status with every diagnostic thrown away: neither the loop above nor this
# line said which of them gave up, and the container holding the answer was
# force-removed before anything read its logs. Failures on this path must
# describe themselves like the volume-create and container-start paths do.
podman exec "${container_name}" "${health_argv[@]}" || {
  echo "postgres never reported healthy within the wait budget:" >&2
  podman ps --all --filter "name=${container_name}" >&2 || true
  podman logs "${container_name}" >&2 || true
  podman info --format '{{.Host.CgroupsVersion}} {{.Host.CgroupManager}} {{.Host.OCIRuntime.Name}}' >&2 2>&1 || true
  exit 1
}
echo "postgres healthy; deriving db-init"

"${unit_command}" "${smoke_unit_root}/mcloving-db-init.service" \
  --home "${home}" > "${workdir}/db-init.derived.json"
db_init_env="$(jq -r '.environment_files[0]' "${workdir}/db-init.derived.json")"
db_init_pre=()
derived_argv db_init_pre "${workdir}/db-init.derived.json" '.exec_start_pre[0]'
run_with_env "${db_init_env}" "${db_init_pre[@]}"
db_init_argv=()
derived_argv db_init_argv "${workdir}/db-init.derived.json" '.exec_start'
run_with_env "${db_init_env}" "${db_init_argv[@]}" | tee "${workdir}/logs/db-init.log"
# The bootstrap must be idempotent: run it twice.
run_with_env "${db_init_env}" "${db_init_argv[@]}" >> "${workdir}/logs/db-init.log"
# The pre-migration endpoint check must compare the complete published
# host-and-port, not the port alone: a URL reaching another loopback address
# at the same port is a different PostgreSQL server. The accepting direction
# is proven by the two runs above; this is the refusing one, against the same
# live container.
wrong_endpoint_env="${workdir}/db-init-wrong-endpoint.env"
sed 's#^\(MCLOVING_MIGRATION_DATABASE_URL=.*\)@127\.0\.0\.1:#\1@127.0.0.2:#' \
  "${db_init_env}" > "${wrong_endpoint_env}"
if cmp -s "${wrong_endpoint_env}" "${db_init_env}"; then
  echo "endpoint refusal gate could not rewrite MCLOVING_MIGRATION_DATABASE_URL; contract shape changed" >&2
  exit 1
fi
if run_with_env "${wrong_endpoint_env}" "${db_init_argv[@]}" \
  > "${workdir}/logs/db-init-wrong-endpoint.log" 2>&1; then
  echo "db-init migrated through a URL addressing a different loopback endpoint" >&2
  exit 1
fi
grep -q "different PostgreSQL instance" "${workdir}/logs/db-init-wrong-endpoint.log" || {
  echo "db-init refused the mismatched endpoint for the wrong reason:" >&2
  cat "${workdir}/logs/db-init-wrong-endpoint.log" >&2
  exit 1
}
rm -f "${wrong_endpoint_env}"
# A refused bootstrap must not rotate live credentials. Point the contract at
# a project the organization does not have, with a canary password: the
# refusal must fire before ALTER ROLE. Detection compares the role's stored
# password hash rather than attempting logins -- container-internal loopback
# is `trust` in this image's default pg_hba, so any password "authenticates"
# from inside. The detector itself is then proven able to see a rotation, by
# rotating through the accepting path and requiring the hash to change.
tenant_hash() {
  printf "SELECT rolpassword FROM pg_authid WHERE rolname = 'mcloving_tenant';\n" \
    | podman exec --interactive "${container_name}" \
      psql --username mcloving --dbname mcloving \
      --set ON_ERROR_STOP=1 --no-psqlrc --quiet --tuples-only --no-align --file -
}
tenant_hash_before="$(tenant_hash)"
[[ -n "${tenant_hash_before}" ]] || {
  echo "mcloving_tenant has no stored password after a successful bootstrap" >&2
  exit 1
}
stale_project_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
canary_password="rotation-canary-${suffix}"
stale_project_env="${workdir}/db-init-stale-project.env"
sed -e "s#^MCLOVING_PROJECT_ID=.*#MCLOVING_PROJECT_ID=${stale_project_id}#" \
    -e "s#^MCLOVING_TENANT_PASSWORD=.*#MCLOVING_TENANT_PASSWORD=${canary_password}#" \
  "${db_init_env}" > "${stale_project_env}"
grep -q "^MCLOVING_PROJECT_ID=${stale_project_id}\$" "${stale_project_env}" || {
  echo "credential-rotation gate could not rewrite MCLOVING_PROJECT_ID; contract shape changed" >&2
  exit 1
}
grep -q "^MCLOVING_TENANT_PASSWORD=${canary_password}\$" "${stale_project_env}" || {
  echo "credential-rotation gate could not rewrite MCLOVING_TENANT_PASSWORD; contract shape changed" >&2
  exit 1
}
if run_with_env "${stale_project_env}" "${db_init_argv[@]}" \
  > "${workdir}/logs/db-init-stale-project.log" 2>&1; then
  echo "db-init reported success for a project the organization does not have" >&2
  exit 1
fi
grep -q "provision the project explicitly" "${workdir}/logs/db-init-stale-project.log" || {
  echo "db-init refused the missing project for the wrong reason:" >&2
  cat "${workdir}/logs/db-init-stale-project.log" >&2
  exit 1
}
[[ "$(tenant_hash)" == "${tenant_hash_before}" ]] || {
  echo "a refused bootstrap rotated the tenant password" >&2
  exit 1
}
# Prove the detector detects: an ACCEPTED bootstrap carrying the canary
# password must change the stored hash -- without this, a hash comparison
# that always reported "unchanged" would pass the refusal check above even
# against a bootstrap that rotates on every path.
canary_accept_env="${workdir}/db-init-canary-accept.env"
sed "s#^MCLOVING_TENANT_PASSWORD=.*#MCLOVING_TENANT_PASSWORD=${canary_password}#" \
  "${db_init_env}" > "${canary_accept_env}"
run_with_env "${canary_accept_env}" "${db_init_argv[@]}" \
  >> "${workdir}/logs/db-init.log"
[[ "$(tenant_hash)" != "${tenant_hash_before}" ]] || {
  echo "an accepted bootstrap did not rotate the tenant password; the rotation detector is blind" >&2
  exit 1
}
# Restore the contract's password for the controller started below.
run_with_env "${db_init_env}" "${db_init_argv[@]}" >> "${workdir}/logs/db-init.log"
rm -f "${stale_project_env}" "${canary_accept_env}"
# Provisioned identity includes the slugs. UUIDs that exist under different
# slugs are a different deployment identity wearing the configured ids, and
# reporting them as provisioned would silently discard both requested slugs.
slug_mismatch_env="${workdir}/db-init-slug-mismatch.env"
sed "s#^MCLOVING_ORGANIZATION_SLUG=.*#MCLOVING_ORGANIZATION_SLUG=smoke-org-imposter#" \
  "${db_init_env}" > "${slug_mismatch_env}"
grep -q "^MCLOVING_ORGANIZATION_SLUG=smoke-org-imposter\$" "${slug_mismatch_env}" || {
  echo "slug gate could not rewrite MCLOVING_ORGANIZATION_SLUG; contract shape changed" >&2
  exit 1
}
if run_with_env "${slug_mismatch_env}" "${db_init_argv[@]}" \
  > "${workdir}/logs/db-init-slug-mismatch.log" 2>&1; then
  echo "db-init reported provisioned for an organization holding a different slug" >&2
  exit 1
fi
grep -q "refusing to report a different identity as provisioned" \
  "${workdir}/logs/db-init-slug-mismatch.log" || {
  echo "db-init refused the slug mismatch for the wrong reason:" >&2
  cat "${workdir}/logs/db-init-slug-mismatch.log" >&2
  exit 1
}
rm -f "${slug_mismatch_env}"
# Ownership runs the other direction too: fresh UUIDs with a slug that is
# already owned by ANOTHER organization classify as a clean provision and
# then fail on the unique slug constraint -- after rotating credentials.
# The refusal must come first and must leave the stored hash untouched.
slug_owner_env="${workdir}/db-init-slug-owner.env"
owner_gate_org="$(python3 -c 'import uuid; print(uuid.uuid4())')"
owner_gate_project="$(python3 -c 'import uuid; print(uuid.uuid4())')"
sed -e "s#^MCLOVING_ORGANIZATION_ID=.*#MCLOVING_ORGANIZATION_ID=${owner_gate_org}#" \
    -e "s#^MCLOVING_PROJECT_ID=.*#MCLOVING_PROJECT_ID=${owner_gate_project}#" \
  "${db_init_env}" > "${slug_owner_env}"
grep -q "^MCLOVING_ORGANIZATION_ID=${owner_gate_org}\$" "${slug_owner_env}" || {
  echo "slug-ownership gate could not rewrite MCLOVING_ORGANIZATION_ID; contract shape changed" >&2
  exit 1
}
owner_hash_before="$(tenant_hash)"
if run_with_env "${slug_owner_env}" "${db_init_argv[@]}" \
  > "${workdir}/logs/db-init-slug-owner.log" 2>&1; then
  echo "db-init classified an already-owned organization slug as a clean provision" >&2
  exit 1
fi
grep -q "already owned by another organization" "${workdir}/logs/db-init-slug-owner.log" || {
  echo "db-init refused the owned slug for the wrong reason:" >&2
  cat "${workdir}/logs/db-init-slug-owner.log" >&2
  exit 1
}
[[ "$(tenant_hash)" == "${owner_hash_before}" ]] || {
  echo "the owned-slug refusal still rotated the tenant password" >&2
  exit 1
}
rm -f "${slug_owner_env}"
# UUID case is spelling, not identity. PostgreSQL renders uuids in canonical
# lowercase, so a contract whose valid UUIDs use uppercase hex must still
# resolve to the provisioned identity instead of being refused as belonging
# to another organization on every bootstrap after the first.
uppercase_env="${workdir}/db-init-uppercase.env"
uppercase_org="${organization_id^^}"
uppercase_project="${project_id^^}"
sed -e "s#^MCLOVING_ORGANIZATION_ID=.*#MCLOVING_ORGANIZATION_ID=${uppercase_org}#" \
    -e "s#^MCLOVING_PROJECT_ID=.*#MCLOVING_PROJECT_ID=${uppercase_project}#" \
  "${db_init_env}" > "${uppercase_env}"
grep -q "^MCLOVING_ORGANIZATION_ID=${uppercase_org}\$" "${uppercase_env}" || {
  echo "uppercase-UUID gate could not rewrite MCLOVING_ORGANIZATION_ID; contract shape changed" >&2
  exit 1
}
run_with_env "${uppercase_env}" "${db_init_argv[@]}" \
  > "${workdir}/logs/db-init-uppercase.log" 2>&1 || {
  echo "db-init refused a valid uppercase spelling of the provisioned UUIDs:" >&2
  cat "${workdir}/logs/db-init-uppercase.log" >&2
  exit 1
}
grep -q "already provisioned" "${workdir}/logs/db-init-uppercase.log" || {
  echo "the uppercase spelling did not resolve to the provisioned identity:" >&2
  cat "${workdir}/logs/db-init-uppercase.log" >&2
  exit 1
}
rm -f "${uppercase_env}"

"${unit_command}" "${smoke_unit_root}/mcloving-controller.service" \
  --home "${home}" > "${workdir}/controller.derived.json"
controller_env="$(jq -r '.environment_files[0]' "${workdir}/controller.derived.json")"
controller_pre=()
derived_argv controller_pre "${workdir}/controller.derived.json" '.exec_start_pre[0]'
run_with_env "${controller_env}" "${controller_pre[@]}"
controller_argv=()
derived_argv controller_argv "${workdir}/controller.derived.json" '.exec_start'
spawn_with_env "${controller_env}" "${controller_argv[@]}" \
  > "${workdir}/logs/controller.log" 2>&1 &
controller_pid=$!
require_service_pid "${controller_pid}" controller
controller_post=()
derived_argv controller_post "${workdir}/controller.derived.json" '.exec_start_post[0]'
run_with_env "${controller_env}" "${controller_post[@]}"

"${unit_command}" "${smoke_unit_root}/mcloving-agent.service" \
  --home "${home}" > "${workdir}/agent.derived.json"
agent_env="$(jq -r '.environment_files[0]' "${workdir}/agent.derived.json")"
agent_guard=()
derived_argv agent_guard "${workdir}/agent.derived.json" '.exec_start_pre[0]'
run_with_env "${agent_env}" "${agent_guard[@]}"
agent_probe=()
derived_argv agent_probe "${workdir}/agent.derived.json" '.exec_start_pre[1]'
run_with_env "${agent_env}" "${agent_probe[@]}" | tee "${workdir}/logs/agent-probe.log"
agent_argv=()
derived_argv agent_argv "${workdir}/agent.derived.json" '.exec_start'
spawn_with_env "${agent_env}" "${agent_argv[@]}" \
  > "${workdir}/logs/agent.log" 2>&1 &
agent_pid=$!
require_service_pid "${agent_pid}" agent

echo "== [7/9] submit one build through the CLI and require terminal success"
marker="deployment-smoke-ran-${suffix}"
cat > "${workdir}/pipeline.yaml" <<PIPELINE
version: 1
name: deployment-smoke
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf '${marker}\\n'"]
          timeout_seconds: 30
PIPELINE
cli="${libexec}/current/mcloving-cli"
export MCLOVING_URL="http://127.0.0.1:${api_port}"
export MCLOVING_API_TOKEN="${api_token}"
export MCLOVING_ORGANIZATION_ID="${organization_id}"
export MCLOVING_PROJECT_ID="${project_id}"
"${cli}" --output json apply "${pipeline_id}" --slug deployment-smoke \
  --expected-revision 0 "${workdir}/pipeline.yaml" \
  > "${workdir}/logs/apply.json"
"${cli}" --output json submit "${pipeline_id}" \
  --idempotency-key "smoke-${suffix}" \
  --trust-pool trusted-linux --platform linux \
  > "${workdir}/logs/submit.json"
build_id="$(jq -r '.build_id' "${workdir}/logs/submit.json")"
[[ "${build_id}" != "null" && -n "${build_id}" ]] || {
  echo "submission returned no build id" >&2
  exit 1
}
echo "submitted build ${build_id}"

status=""
for _ in $(seq 1 120); do
  status="$("${cli}" --output json status "${build_id}" | jq -r '.status')"
  case "${status}" in
    succeeded | failed | aborted) break ;;
  esac
  sleep 0.5
done
echo "terminal status: ${status}"
[[ "${status}" == "succeeded" ]] || {
  echo "build ${build_id} did not succeed (status: ${status})" >&2
  "${cli}" --output json status "${build_id}" >&2 || true
  "${cli}" --output json logs "${build_id}" >&2 || true
  exit 1
}
"${cli}" --output json logs "${build_id}" > "${workdir}/logs/build-logs.json"
grep -q "${marker}" "${workdir}/logs/build-logs.json" || {
  echo "build logs do not contain the smoke marker" >&2
  exit 1
}
lease_owner="$("${cli}" --output json status "${build_id}" | jq -r '.lease_owner')"
[[ "${lease_owner}" == "${agent_id}" ]] || {
  echo "build was not executed by the remote agent (lease owner: ${lease_owner})" >&2
  exit 1
}

echo "== [8/9] deterministic digest re-read"
"${libexec}/helpers/mcloving-deployed-digests" --home "${home}" \
  > "${workdir}/digests-1.json"
"${libexec}/helpers/mcloving-deployed-digests" --home "${home}" \
  > "${workdir}/digests-2.json"
cmp "${workdir}/digests-1.json" "${workdir}/digests-2.json" || {
  echo "digest re-read output is not deterministic" >&2
  exit 1
}
# Named paths rather than a count: the document grew unit-root and directory
# records, and an exact length asserts the shape of the walker instead of the
# coverage this gate is about.
jq -e '
  . as $document
  | .schema == "mcloving.deployed-digests/v1"
  and (.current_release | startswith("releases/"))
  and (.releases | length >= 4)
  and (["mcloving-db-init.service", "mcloving-controller.service",
        "mcloving-agent.service", "mcloving-postgres.container",
        "mcloving-postgres-data.volume"]
       | all(. as $unit
             | ([$document.units[].path] | any(endswith("/" + $unit)))))
  and (.environment_contracts | length >= 5)
' "${workdir}/digests-1.json" >/dev/null || {
  echo "digest document is missing required coverage" >&2
  exit 1
}
echo "digest re-read summary:"
jq '{schema, current_release, previous_release,
     releases: (.releases | length), units: (.units | length),
     environment_contracts: (.environment_contracts | length)}' \
  "${workdir}/digests-1.json"

echo "== [9/9] upgrade and rollback symlink discipline (--no-systemd)"
release2_dir="${workdir}/release2"
cp -r "${release_dir}" "${release2_dir}"
printf '\n' >> "${release2_dir}/mcloving-cli"
(cd "${release2_dir}" && sha256sum mcloving-controller mcloving-agent \
  mcloving-cli mcloving-identity-admin > "${workdir}/checksums2.sha256")
first_release="$(readlink "${libexec}/current")"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd
second_release="$(readlink "${libexec}/current")"
[[ "${second_release}" != "${first_release}" ]] || {
  echo "upgrade did not change the current release" >&2
  exit 1
}
[[ "$(readlink "${libexec}/previous")" == "${first_release}" ]] || {
  echo "upgrade did not preserve the previous release" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${home}" --no-systemd
[[ "$(readlink "${libexec}/current")" == "${first_release}" ]] || {
  echo "rollback did not restore the first release" >&2
  exit 1
}
"${libexec}/current/mcloving-cli" --help >/dev/null

# A staged release is writable by the service user, so rollback must recompute
# digests rather than trust that a present, executable binary is the one that
# was verified at installation.
# Staging must check the copied bytes against the supplied digest source, not
# against a second measurement of the same mutable directory. A release
# directory whose contents disagree with its checksums file must be refused
# even though the directory is internally self-consistent.
mismatch_dir="${workdir}/mismatch-release"
rm -rf "${mismatch_dir}"
cp -r "${release_dir}" "${mismatch_dir}"
(cd "${mismatch_dir}" && sha256sum mcloving-controller mcloving-agent \
  mcloving-cli mcloving-identity-admin > "${workdir}/mismatch.sha256")
printf '\n' >> "${mismatch_dir}/mcloving-cli"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${home}" \
  --release-dir "${mismatch_dir}" --checksums "${workdir}/mismatch.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "staging accepted bytes that do not match the supplied checksums" >&2
  exit 1
fi

# The manifest is the other first-class digest source and gets both
# directions too: a valid manifest must install, and a digest source that is
# not a regular file must be refused promptly rather than read -- an
# ordinary open blocks forever on a writerless FIFO, and the verification
# would hang exactly when the source has been swapped out from under it.
manifest_home="${workdir}/manifest-home"
rm -rf "${manifest_home}"
mkdir -p "${manifest_home}"
python3 - "${release_dir}" "${workdir}/release-manifest.json" <<'MANIFEST'
import hashlib
import json
import sys
from pathlib import Path

source_dir, out = sys.argv[1], sys.argv[2]
components = []
for name in [
    "mcloving-controller",
    "mcloving-agent",
    "mcloving-cli",
    "mcloving-identity-admin",
]:
    payload = (Path(source_dir) / name).read_bytes()
    components.append(
        {
            "path": f"components/{name}",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        }
    )
Path(out).write_text(
    json.dumps({"manifest": {"components": components}}), encoding="utf-8"
)
MANIFEST
"${repo_root}/deploy/bin/mcloving-install" --home "${manifest_home}" \
  --release-dir "${release_dir}" --manifest "${workdir}/release-manifest.json" \
  --no-systemd >/dev/null
[[ -x "${manifest_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "manifest-verified install did not complete" >&2
  exit 1
}
rm -rf "${manifest_home}"

fifo_source="${workdir}/digest-source.fifo"
for digest_flag in --manifest --checksums; do
  rm -f "${fifo_source}"
  mkfifo "${fifo_source}"
  fifo_digest_home="${workdir}/fifo-digest-home"
  rm -rf "${fifo_digest_home}"
  mkdir -p "${fifo_digest_home}"
  digest_status=0
  timeout 60 "${repo_root}/deploy/bin/mcloving-install" --home "${fifo_digest_home}" \
    --release-dir "${release_dir}" "${digest_flag}" "${fifo_source}" \
    --no-systemd > "${workdir}/logs/fifo-digest-source.log" 2>&1 || digest_status=$?
  if [[ "${digest_status}" -eq 0 ]]; then
    echo "install accepted a ${digest_flag} source that is not a regular file" >&2
    exit 1
  fi
  if [[ "${digest_status}" -eq 124 ]]; then
    echo "install hung reading a FIFO ${digest_flag} source" >&2
    exit 1
  fi
  grep -q "is not a regular file" "${workdir}/logs/fifo-digest-source.log" || {
    echo "the FIFO ${digest_flag} source was refused for the wrong reason:" >&2
    cat "${workdir}/logs/fifo-digest-source.log" >&2
    exit 1
  }
  rm -rf "${fifo_digest_home}"
  rm -f "${fifo_source}"
done

# Every required entry must be present in the SAME snapshot sha256sum
# verifies. --ignore-missing used to make a vanished entry a silent pass, so
# a checksums file missing one binary must now be refused by name.
partial_checksums="${workdir}/partial-checksums.sha256"
grep -v "mcloving-agent" "${workdir}/checksums.sha256" > "${partial_checksums}"
partial_checksums_home="${workdir}/partial-checksums-home"
rm -rf "${partial_checksums_home}"
mkdir -p "${partial_checksums_home}"
if "${repo_root}/deploy/bin/mcloving-install" --home "${partial_checksums_home}" \
  --release-dir "${release_dir}" --checksums "${partial_checksums}" \
  --no-systemd > "${workdir}/logs/partial-checksums.log" 2>&1; then
  echo "install verified against a checksums file missing a required entry" >&2
  exit 1
fi
grep -q "no entry for mcloving-agent" "${workdir}/logs/partial-checksums.log" || {
  echo "the incomplete checksums file was refused for the wrong reason:" >&2
  cat "${workdir}/logs/partial-checksums.log" >&2
  exit 1
}
rm -rf "${partial_checksums_home}"
rm -f "${partial_checksums}"

tampered="${libexec}/${second_release}/mcloving-cli"
cp "${tampered}" "${workdir}/untampered-cli"
printf '\n' >> "${tampered}"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${home}" --no-systemd \
  >/dev/null 2>&1; then
  echo "rollback accepted a modified previous release" >&2
  exit 1
fi
[[ "$(readlink "${libexec}/current")" == "${first_release}" ]] || {
  echo "refused rollback must leave the current release untouched" >&2
  exit 1
}
# Restore the release so the later gates run against an intact tree; the
# refusal above is the assertion, not a lasting state.
cp "${workdir}/untampered-cli" "${tampered}"
chmod 0755 "${tampered}"

# systemd's environment grammar, not Bash's: a partially quoted value is one
# value, and a value that is literal to systemd must not be executed.
guard_env="${workdir}/grammar.env"
cat > "${guard_env}" <<'GRAMMAR'
MCLOVING_CONTROLLER_ENDPOINT=https://controller.example.test:8443
MCLOVING_AGENT_ID=/tmp/'agent id'
MCLOVING_TRUST_POOL=p&ss w$rd
GRAMMAR
(
  # shellcheck source=/dev/null
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  load_environment_file "${guard_env}"
  [[ "$(contract_value MCLOVING_AGENT_ID)" == "/tmp/agent id" ]] || {
    echo "partially quoted value was not concatenated: [$(contract_value MCLOVING_AGENT_ID)]" >&2
    exit 1
  }
  [[ "$(contract_value MCLOVING_TRUST_POOL)" == 'p&ss w$rd' ]] || {
    echo "literal value was altered or executed: [$(contract_value MCLOVING_TRUST_POOL)]" >&2
    exit 1
  }
)

# The guards must accept the contracts this install actually wrote. Every other
# guard assertion here is a refusal, so a regression that broke acceptance —
# an unset variable, a renamed lookup — would pass unnoticed.
"${libexec}/helpers/mcloving-env-guard" controller "${config_dir}/controller.env" >/dev/null || {
  echo "controller guard rejected the contract this install wrote" >&2
  exit 1
}
"${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" >/dev/null || {
  echo "agent guard rejected the contract this install wrote" >&2
  exit 1
}

# Install-time validation proves install-time state only: a contract
# relaxed AFTER install must be refused at service start, before parsing.
chmod 0644 "${config_dir}/agent.env"
if "${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" \
  > "${workdir}/logs/guard-contract-mode.log" 2>&1; then
  echo "env guard parsed a contract that became group-readable after install" >&2
  exit 1
fi
grep -q "agent.env (mode 644, expected owner-only)" \
  "${workdir}/logs/guard-contract-mode.log" || {
  echo "the guard's runtime contract refusal did not name the file and mode:" >&2
  cat "${workdir}/logs/guard-contract-mode.log" >&2
  exit 1
}
chmod 0600 "${config_dir}/agent.env"
"${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" >/dev/null || {
  echo "env guard refused the restored owner-only contract" >&2
  exit 1
}
# Configured state is dereferenced directly by the binaries: a writable
# workspace root or journal must refuse the start, and the agent's own
# 0644 journal must keep passing.
agent_workspace="${home}/.local/state/mcloving-agent/workspace"
chmod 0777 "${agent_workspace}"
if "${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" \
  > "${workdir}/logs/guard-workspace-mode.log" 2>&1; then
  echo "env guard accepted a world-writable agent workspace root" >&2
  exit 1
fi
grep -q "workspace (mode 777)" "${workdir}/logs/guard-workspace-mode.log" || {
  echo "the workspace refusal did not name the directory and mode:" >&2
  cat "${workdir}/logs/guard-workspace-mode.log" >&2
  exit 1
}
chmod 0755 "${agent_workspace}"
agent_journal="${home}/.local/state/mcloving-agent/journal.db"
if [[ -f "${agent_journal}" ]]; then
  journal_mode="$(stat -c '%a' "${agent_journal}")"
  chmod 0666 "${agent_journal}"
  if "${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" \
    > "${workdir}/logs/guard-journal-mode.log" 2>&1; then
    echo "env guard accepted a world-writable agent journal" >&2
    exit 1
  fi
  grep -q "journal.db (mode 666)" "${workdir}/logs/guard-journal-mode.log" || {
    echo "the journal refusal did not name the file and mode:" >&2
    cat "${workdir}/logs/guard-journal-mode.log" >&2
    exit 1
  }
  chmod "${journal_mode}" "${agent_journal}"
fi
"${libexec}/helpers/mcloving-env-guard" agent "${config_dir}/agent.env" >/dev/null || {
  echo "env guard refused the restored state paths" >&2
  exit 1
}

# A file that parses partially must not be accepted. The required assignments
# come first here, so a guard that ignored the parser's status would fill its
# map, report the contract satisfied, and exit 0 on a malformed file.
partial_env="${home}/partial.env"
printf 'POSTGRES_USER=x\nPOSTGRES_DB=y\nPOSTGRES_PASSWORD=z\nthis line has no equals\n' \
  > "${partial_env}"
chmod 0600 "${partial_env}"
if "${libexec}/helpers/mcloving-env-guard" postgres "${partial_env}" >/dev/null 2>&1; then
  echo "guard accepted a contract whose parse failed after the required values" >&2
  exit 1
fi

# A symlink whose target is gone is drift, so the re-read must report it rather
# than fail trying to hash a missing file.
ln -s "${workdir}/definitely-absent" "${config_dir}/dangling.env"
dangling_digests="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")" || {
  echo "digest re-read failed on a dangling symlink instead of recording it" >&2
  exit 1
}
python3 - "${dangling_digests}" <<'DANGLING'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
entry = [item for item in contracts if item["path"].endswith("dangling.env")]
if not entry:
    raise SystemExit("dangling symlink missing from the re-read")
if entry[0].get("kind") != "dangling_symlink":
    raise SystemExit("dangling symlink was not recorded as such")
DANGLING
rm -f "${config_dir}/dangling.env"

# Token length is measured in bytes, as the controller measures it. A
# multi-byte token that satisfies the controller must satisfy the guard, or a
# valid contract stops a service that could have run it.
utf8_env="${home}/utf8-token.env"
utf8_api="$(python3 -c "print('\u00e9' * 16)")"
utf8_artifact="$(python3 -c "print('\u00fc' * 16)")"
sed -e "s|^MCLOVING_API_TOKEN=.*|MCLOVING_API_TOKEN=${utf8_api}|" \
    -e "s|^MCLOVING_ARTIFACT_AGENT_TOKEN=.*|MCLOVING_ARTIFACT_AGENT_TOKEN=${utf8_artifact}|" \
    "${config_dir}/controller.env" > "${utf8_env}"
chmod 0600 "${utf8_env}"
"${libexec}/helpers/mcloving-env-guard" controller "${utf8_env}" >/dev/null || {
  echo "guard rejected a 32-byte token because it counted characters" >&2
  exit 1
}

# Two spellings of one database role are one role. Comparing URL text would
# accept them as distinct and let the controller run as the migration role.
equivalent_env="${home}/equivalent.env"
sed -e 's|^MCLOVING_DATABASE_URL=.*|MCLOVING_DATABASE_URL=postgres://mcloving_migration@127.0.0.1:5432/mcloving|' \
    -e 's|^MCLOVING_MIGRATION_DATABASE_URL=.*|MCLOVING_MIGRATION_DATABASE_URL=postgres://mcloving_migration@127.0.0.1/mcloving|' \
    "${config_dir}/controller.env" > "${equivalent_env}"
chmod 0600 "${equivalent_env}"
if "${libexec}/helpers/mcloving-env-guard" controller "${equivalent_env}" >/dev/null 2>&1; then
  echo "guard accepted two spellings of one database role as distinct" >&2
  exit 1
fi

# Only systemd's ASCII whitespace is padding. A non-breaking space is part of
# the value, so trimming it would validate a different value from the one the
# service receives.
nbsp_env="${workdir}/nbsp.env"
python3 - "${nbsp_env}" <<'NBSP'
import sys
from pathlib import Path

Path(sys.argv[1]).write_text("MCLOVING_NBSP=\u00a0value\u00a0\nMCLOVING_PLAIN=  plain  \n")
NBSP
(
  # shellcheck source=/dev/null
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  load_environment_file "${nbsp_env}"
  expected_nbsp="$(python3 -c "print('\u00a0value\u00a0')")"
  [[ "$(contract_value MCLOVING_NBSP)" == "${expected_nbsp}" ]] || {
    echo "non-ASCII whitespace was trimmed as padding" >&2
    exit 1
  }
  [[ "$(contract_value MCLOVING_PLAIN)" == "plain" ]] || {
    echo "ASCII padding was not trimmed" >&2
    exit 1
  }
)

# A contract-supplied name must not reach a helper's own control variables:
# Bash is dynamically scoped, so an assignment named `service` could otherwise
# rewrite the guard's dispatch selector and validate the wrong service.
hijack_env="${home}/hijack.env"
cat > "${hijack_env}" <<'HIJACK'
service=postgres
POSTGRES_USER=x
POSTGRES_DB=x
POSTGRES_PASSWORD=x
HIJACK
chmod 0600 "${hijack_env}"
if "${libexec}/helpers/mcloving-env-guard" controller "${hijack_env}" >/dev/null 2>&1; then
  echo "a contract assignment hijacked the guard's service dispatch" >&2
  exit 1
fi

# Escaped trailing whitespace is part of the value; unquoted padding is not.
whitespace_env="${workdir}/whitespace.env"
printf 'MCLOVING_TRAIL=/tmp/key.pem\\ \nMCLOVING_PAD=  spaced  \n' > "${whitespace_env}"
(
  # shellcheck source=/dev/null
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  load_environment_file "${whitespace_env}"
  [[ "$(contract_value MCLOVING_TRAIL)" == "/tmp/key.pem " ]] || {
    echo "escaped trailing space was lost: [$(contract_value MCLOVING_TRAIL)]" >&2
    exit 1
  }
  [[ "$(contract_value MCLOVING_PAD)" == "spaced" ]] || {
    echo "unquoted padding was not trimmed: [$(contract_value MCLOVING_PAD)]" >&2
    exit 1
  }
)

# A single-quoted value may span physical lines; systemd loads it, so the
# guard must too rather than refusing a valid contract at ExecStartPre.
multiline_env="${workdir}/multiline.env"
printf "MCLOVING_SPAN='line one\nline two'\nMCLOVING_AFTER=tail\n" > "${multiline_env}"
(
  # shellcheck source=/dev/null
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  load_environment_file "${multiline_env}"
  expected_span="$(printf 'line one\nline two')"
  [[ "$(contract_value MCLOVING_SPAN)" == "${expected_span}" ]] || {
    echo "multiline single-quoted value was not read: [$(contract_value MCLOVING_SPAN)]" >&2
    exit 1
  }
  [[ "$(contract_value MCLOVING_AFTER)" == "tail" ]] || {
    echo "parsing did not resume after a multiline value: [$(contract_value MCLOVING_AFTER)]" >&2
    exit 1
  }
)

# Configuration reached through a symlink is consumed by the services, so the
# drift re-read must cover it.
ln -s "${config_dir}/controller.env" "${config_dir}/controller-linked.env"
linked_digests="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${linked_digests}" <<'LINKED'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
linked = [entry for entry in contracts if entry["path"].endswith("controller-linked.env")]
if not linked:
    raise SystemExit("symlinked contract missing from the deployed-digest re-read")
if "symlink_target" not in linked[0]:
    raise SystemExit("symlinked contract recorded without its target")
LINKED
rm -f "${config_dir}/controller-linked.env"

# A symlinked configuration *directory* is traversed too: rglob would not
# descend it, so every key inside would be consumed by the services and absent
# from the re-read.
mkdir -p "${workdir}/managed-pki"
cp "${config_dir}/pki/"* "${workdir}/managed-pki/" 2>/dev/null || true
mv "${config_dir}/pki" "${config_dir}/pki.real"
ln -s "${workdir}/managed-pki" "${config_dir}/pki"
linked_dir_digests="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${linked_dir_digests}" <<'LINKEDDIR'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
inside = [entry for entry in contracts if "/pki/" in entry["path"]]
if not inside:
    raise SystemExit("symlinked configuration directory was not traversed")
LINKEDDIR
rm -f "${config_dir}/pki"
mv "${config_dir}/pki.real" "${config_dir}/pki"

# A special filesystem node inside a walked tree must not be opened. Hashing a
# FIFO with no writer blocks forever, so CUTOVER-001 would receive no document
# at all precisely when this kind of drift is present.
mkfifo "${config_dir}/stall"
special_digests="$(timeout 60 "${libexec}/helpers/mcloving-deployed-digests" --home "${home}")" || {
  echo "digest re-read stalled or failed on a FIFO instead of recording it" >&2
  rm -f "${config_dir}/stall"
  exit 1
}
rm -f "${config_dir}/stall"
python3 - "${special_digests}" <<'SPECIAL'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
entry = [item for item in contracts if item["path"].endswith("/stall")]
if not entry:
    raise SystemExit("special node missing from the re-read")
if entry[0].get("kind") != "fifo":
    raise SystemExit(f"special node recorded as {entry[0]}")
if "sha256" in entry[0]:
    raise SystemExit("special node was digested as a regular file")
SPECIAL

# --home must be checked against the account home systemd expands %h to, not
# against HOME, which the caller controls. Comparing two copies of HOME always
# agrees, so an install could write a whole deployment under one tree while
# daemon-reload and every later service operation acted on units pointing at
# another.
overridden_home="${workdir}/overridden-home"
mkdir -p "${overridden_home}"
if HOME="${overridden_home}" "${repo_root}/deploy/bin/mcloving-install" \
  --home "${overridden_home}" --release-dir "${release_dir}" \
  --checksums "${workdir}/checksums.sha256" >/dev/null 2>&1; then
  echo "install drove systemd for a tree its units do not describe" >&2
  exit 1
fi
rm -rf "${overridden_home}"

# The staging trap must survive a home containing shell metacharacters. A
# single quote is legal in a directory name and would break a trap body that
# wrapped the path in quotes instead of rendering it.
quoted_staging="${workdir}/"$'o\'h staging'
rm -rf "${quoted_staging}"
mkdir -p "${quoted_staging}/.local/libexec/mcloving/releases"
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  stage_release "${quoted_staging}/.local/libexec/mcloving" "${tampered_dir}" \
    "" "${workdir}/checksums.sha256"
) >/dev/null 2>&1 && {
  echo "staging accepted a tampered release under a quoted home" >&2
  exit 1
}
if compgen -G "${quoted_staging}/.local/libexec/mcloving/releases/.staging.*" >/dev/null; then
  echo "the staging cleanup trap did not run for a home containing a single quote" >&2
  exit 1
fi
rm -rf "${quoted_staging}"

# A directory's permissions are deployment state too. Relaxing the config root
# to 0777 lets another local user replace every contract and key inside it,
# while each file record stays byte-identical.
dir_mode_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod 0777 "${config_dir}"
dir_mode_after="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod 0700 "${config_dir}"
if [[ "${dir_mode_before}" == "${dir_mode_after}" ]]; then
  echo "a world-writable configuration root left the re-read unchanged" >&2
  exit 1
fi
python3 - "${dir_mode_after}" <<'DIRMODE'
import json
import sys

document = json.loads(sys.argv[1])
entry = [
    item
    for item in document.get("environment_contracts", [])
    if item["path"] == ".config/mcloving"
]
if not entry:
    raise SystemExit("configuration root missing from the re-read")
if entry[0].get("mode") != 0o777:
    raise SystemExit(f"configuration root mode not recorded: {entry[0]}")
DIRMODE

# The ANCESTORS of the walked trees are deployment state too. Relaxing
# ${libexec} itself to 0777 leaves every walked child record byte-identical
# while another local user renames current, releases, or helpers aside and
# substitutes deployed code; the same holds for ~/.config over the contract
# trees. The re-read must record the whole chain from ~ down to each walked
# root, and a mode change on any link of it must change the document.
libexec_mode="$(stat -c '%a' "${libexec}")"
ancestor_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod 0777 "${libexec}"
ancestor_after="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod "${libexec_mode}" "${libexec}"
if [[ "${ancestor_before}" == "${ancestor_after}" ]]; then
  echo "a world-writable libexec root left the re-read unchanged" >&2
  exit 1
fi
python3 - "${ancestor_after}" <<'ANCESTORS'
import json
import sys

document = json.loads(sys.argv[1])
records = {item["path"]: item for item in document.get("ancestors", [])}
relaxed = records.get(".local/libexec/mcloving")
if relaxed is None:
    raise SystemExit("libexec root missing from the ancestor records")
if relaxed.get("mode") != 0o777:
    raise SystemExit(f"libexec root mode not recorded: {relaxed}")
# Coverage of the whole chain, not just the directory this gate relaxed:
# every directory between ~ and a walked root is a place where a rename
# swaps a protected subtree aside.
required = {
    ".",
    ".local",
    ".local/libexec",
    ".local/libexec/mcloving",
    ".config",
    ".config/systemd",
    ".config/containers",
}
missing = required - set(records)
if missing:
    raise SystemExit(f"ancestor records missing: {sorted(missing)}")
ANCESTORS

# A chmod landing between a record's fstat and its pathname re-check must
# not survive into the canonical document: the inode is unchanged, so a
# device+inode re-check alone keeps the stale mode. Driven against the
# INSTALLED helper's own code with a hook that fires the chmod exactly
# inside that window (after the record is built, before the pathname
# re-check), this requires the returned document to carry the settled mode.
race_mode_before="$(stat -c '%a' "${libexec}")"
race_status=0
# The driver executes the helper's payload directly, bypassing the shell
# wrapper that normally derives and exports the ancestor set, so it supplies
# the same set through the same library derivation. The drop-in directory
# set comes through the same derivation for the same reason: the payload
# refuses to build a document without it rather than silently omitting the
# type-wide and prefix drop-ins.
race_shadowing_units="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  deployment_shadowing_unit_files "${home}" \
    "${smoke_unit_root}"/mcloving-*.service \
    "${smoke_quadlet_root}"/mcloving-*.container \
    "${smoke_quadlet_root}"/mcloving-*.volume
)"
race_system_dropin_dirs="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  deployment_unit_dropin_dirs "${home}" --system \
    "${smoke_unit_root}"/mcloving-*.service \
    "${smoke_quadlet_root}"/mcloving-*.container \
    "${smoke_quadlet_root}"/mcloving-*.volume
)"
race_dropin_dirs="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  deployment_unit_dropin_dirs "${home}" "${smoke_unit_root}"/mcloving-*.service \
    "${smoke_quadlet_root}"/mcloving-*.container \
    "${smoke_quadlet_root}"/mcloving-*.volume
)"
race_ancestors="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  deployment_ancestor_chain "${home}" \
    "${libexec}/releases" "${libexec}/helpers" \
    "${smoke_unit_root}" "${smoke_quadlet_root}" \
    "${home}/.config/mcloving" "${home}/.config/mcloving/pki"
)"
MCLOVING_ANCESTOR_DIRS="${race_ancestors}" \
MCLOVING_DEPLOY_LIB="${libexec}/helpers/mcloving-deploy-lib.sh" \
MCLOVING_UNIT_DIRS="${smoke_unit_dirs_env}" \
MCLOVING_UNIT_DROPIN_DIRS="${race_dropin_dirs}" \
MCLOVING_UNIT_SYSTEM_DROPIN_DIRS="${race_system_dropin_dirs}" \
MCLOVING_SHADOWING_UNITS="${race_shadowing_units}" \
python3 - "${libexec}/helpers/mcloving-deployed-digests" "${home}" "${libexec}" <<'MODERACE' || race_status=$?
import contextlib
import io
import json
import os
import sys

helper, home, target = sys.argv[1], sys.argv[2], sys.argv[3]
source = open(helper, encoding="utf-8").read()
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
state = {"fd": None, "fired": False}
real_open, real_close = os.open, os.close


def hooked_open(path, flags, *args, **kwargs):
    fd = real_open(path, flags, *args, **kwargs)
    if not state["fired"] and os.fspath(path) == target:
        state["fd"] = fd
    return fd


def hooked_close(fd):
    if fd == state["fd"] and not state["fired"]:
        state["fired"] = True
        os.chmod(target, 0o777)
    return real_close(fd)


os.open, os.close = hooked_open, hooked_close
buffer = io.StringIO()
sys.argv = ["-", home]
try:
    with contextlib.redirect_stdout(buffer):
        exec(compile(payload, helper, "exec"), {"__name__": "__main__"})
finally:
    os.open, os.close = real_open, real_close
if not state["fired"]:
    raise SystemExit("the racing chmod never fired; the hook missed the record window")
document = json.loads(buffer.getvalue())
records = {record["path"]: record for record in document["ancestors"]}
entry = records[".local/libexec/mcloving"]
if entry.get("mode") != 0o777:
    raise SystemExit(f"record kept the pre-chmod mode: {entry}")
MODERACE
chmod "${race_mode_before}" "${libexec}"
if [[ "${race_status}" -ne 0 ]]; then
  echo "digest re-read kept a stale directory mode across a racing chmod" >&2
  exit 1
fi

# The same window, content edition: a write landing between the post-read
# fstat and the pathname re-check leaves inode, mode, and owner untouched
# while the bytes changed. Driven with a hook appending to the probe inside
# that exact window, the returned record must carry the settled bytes.
printf 'probe-content' > "${config_dir}/race-probe.txt"
chmod 0600 "${config_dir}/race-probe.txt"
content_race_status=0
MCLOVING_ANCESTOR_DIRS="${race_ancestors}" \
MCLOVING_DEPLOY_LIB="${libexec}/helpers/mcloving-deploy-lib.sh" \
MCLOVING_UNIT_DIRS="${smoke_unit_dirs_env}" \
MCLOVING_UNIT_DROPIN_DIRS="${race_dropin_dirs}" \
MCLOVING_UNIT_SYSTEM_DROPIN_DIRS="${race_system_dropin_dirs}" \
MCLOVING_SHADOWING_UNITS="${race_shadowing_units}" \
python3 - "${libexec}/helpers/mcloving-deployed-digests" "${home}" \
  "${config_dir}/race-probe.txt" <<'CONTENTRACE' || content_race_status=$?
import contextlib
import hashlib
import io
import json
import os
import sys

helper, home, target = sys.argv[1], sys.argv[2], sys.argv[3]
source = open(helper, encoding="utf-8").read()
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
state = {"fd": None, "fired": False}
real_open, real_close = os.open, os.close


def hooked_open(path, flags, *args, **kwargs):
    fd = real_open(path, flags, *args, **kwargs)
    if not state["fired"] and os.fspath(path) == target:
        state["fd"] = fd
    return fd


def hooked_close(fd):
    if fd == state["fd"] and not state["fired"]:
        state["fired"] = True
        append_fd = real_open(target, os.O_WRONLY | os.O_APPEND)
        os.write(append_fd, b"-appended")
        real_close(append_fd)
    return real_close(fd)


os.open, os.close = hooked_open, hooked_close
buffer = io.StringIO()
sys.argv = ["-", home]
try:
    with contextlib.redirect_stdout(buffer):
        exec(compile(payload, helper, "exec"), {"__name__": "__main__"})
finally:
    os.open, os.close = real_open, real_close
if not state["fired"]:
    raise SystemExit("the racing append never fired; the hook missed the window")
document = json.loads(buffer.getvalue())
records = {
    record["path"]: record
    for record in document.get("environment_contracts", [])
}
entry = records.get(".config/mcloving/race-probe.txt")
if entry is None:
    raise SystemExit("probe file missing from the re-read")
settled = b"probe-content-appended"
if entry.get("sha256") != hashlib.sha256(settled).hexdigest() or entry.get(
    "size_bytes"
) != len(settled):
    raise SystemExit(f"record kept the pre-append content identity: {entry}")
CONTENTRACE
rm -f "${config_dir}/race-probe.txt"
if [[ "${content_race_status}" -ne 0 ]]; then
  echo "digest re-read kept a stale content identity across a racing write" >&2
  exit 1
fi

# mtime alone is forgeable. An in-place rewrite of the SAME size with the
# original mtime restored via utime() slides through the read window unless
# ctime -- which cannot be set back without clock-level privilege -- anchors
# the post-read identity tuple. The hook fires the rewrite exactly at the
# settled fstat, restores the mtime, and the record must still carry the
# settled bytes (or the named instability), never the stale digest.
printf 'ctime-probe-original' > "${config_dir}/ctime-probe.txt"
chmod 0600 "${config_dir}/ctime-probe.txt"
ctime_race_status=0
MCLOVING_ANCESTOR_DIRS="${race_ancestors}" \
MCLOVING_DEPLOY_LIB="${libexec}/helpers/mcloving-deploy-lib.sh" \
MCLOVING_UNIT_DIRS="${smoke_unit_dirs_env}" \
MCLOVING_UNIT_DROPIN_DIRS="${race_dropin_dirs}" \
MCLOVING_UNIT_SYSTEM_DROPIN_DIRS="${race_system_dropin_dirs}" \
MCLOVING_SHADOWING_UNITS="${race_shadowing_units}" \
python3 - "${libexec}/helpers/mcloving-deployed-digests" "${home}" \
  "${config_dir}/ctime-probe.txt" <<'CTIMERACE' || ctime_race_status=$?
import contextlib
import hashlib
import io
import json
import os
import sys

helper, home, target = sys.argv[1], sys.argv[2], sys.argv[3]
source = open(helper, encoding="utf-8").read()
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
original = os.stat(target)
new_bytes = b"ctime-probe-REWRITE!"
state = {"fd": None, "fires": 0}
real_open, real_fstat = os.open, os.fstat


def hooked_open(path, flags, *args, **kwargs):
    fd = real_open(path, flags, *args, **kwargs)
    if state["fd"] is None and os.fspath(path) == target:
        state["fd"] = fd
    return fd


def hooked_fstat(fd):
    if fd == state["fd"]:
        state["fires"] += 1
        if state["fires"] == 2:
            write_fd = real_open(target, os.O_WRONLY)
            os.write(write_fd, new_bytes)
            os.close(write_fd)
            os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
    return real_fstat(fd)


os.open, os.fstat = hooked_open, hooked_fstat
buffer = io.StringIO()
sys.argv = ["-", home]
try:
    with contextlib.redirect_stdout(buffer):
        exec(compile(payload, helper, "exec"), {"__name__": "__main__"})
finally:
    os.open, os.fstat = real_open, real_fstat
if state["fires"] < 2:
    raise SystemExit("the forged rewrite never fired; the hook missed the window")
document = json.loads(buffer.getvalue())
records = {
    record["path"]: record
    for record in document.get("environment_contracts", [])
}
entry = records.get(".config/mcloving/ctime-probe.txt")
if entry is None:
    raise SystemExit("probe file missing from the re-read")
if entry.get("kind") == "unstable_entry":
    raise SystemExit(0)
if entry.get("sha256") != hashlib.sha256(new_bytes).hexdigest():
    raise SystemExit(f"record kept the stale digest behind a forged mtime: {entry}")
CTIMERACE
rm -f "${config_dir}/ctime-probe.txt"
if [[ "${ctime_race_status}" -ne 0 ]]; then
  echo "digest re-read accepted a stale digest behind a forged mtime" >&2
  exit 1
fi

# A listing is a snapshot: a file created right after iterdir() must still
# reach the document (the walk re-lists after processing and retries) or be
# named as an unstable listing -- never silently omitted while present on
# disk when the command returns.
listing_race_status=0
MCLOVING_ANCESTOR_DIRS="${race_ancestors}" \
MCLOVING_DEPLOY_LIB="${libexec}/helpers/mcloving-deploy-lib.sh" \
MCLOVING_UNIT_DIRS="${smoke_unit_dirs_env}" \
MCLOVING_UNIT_DROPIN_DIRS="${race_dropin_dirs}" \
MCLOVING_UNIT_SYSTEM_DROPIN_DIRS="${race_system_dropin_dirs}" \
MCLOVING_SHADOWING_UNITS="${race_shadowing_units}" \
MCLOVING_CONFIGURED_PATHS="" \
python3 - "${libexec}/helpers/mcloving-deployed-digests" "${home}" \
  "${config_dir}" <<'LISTRACE' || listing_race_status=$?
import contextlib
import io
import json
import os
import sys

helper, home, target = sys.argv[1], sys.argv[2], sys.argv[3]
source = open(helper, encoding="utf-8").read()
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
born = os.path.join(target, "race-born.txt")
state = {"fired": False}
real_listdir = os.listdir


def hooked_listdir(path=None):
    result = real_listdir(path)
    try:
        same = path is not None and os.path.samefile(path, target)
    except (OSError, TypeError):
        same = False
    if same and not state["fired"]:
        state["fired"] = True
        with open(born, "w") as handle:
            handle.write("born-in-the-window")
        os.chmod(born, 0o600)
    return result


os.listdir = hooked_listdir
buffer = io.StringIO()
sys.argv = ["-", home]
try:
    with contextlib.redirect_stdout(buffer):
        exec(compile(payload, helper, "exec"), {"__name__": "__main__"})
finally:
    os.listdir = real_listdir
if not state["fired"]:
    raise SystemExit("the racing creation never fired; the hook missed the window")
document = json.loads(buffer.getvalue())
present = any(
    record["path"] == ".config/mcloving/race-born.txt"
    for record in document.get("environment_contracts", [])
)
named_unstable = any(
    record.get("kind") == "unstable_listing"
    for record in document.get("ancestors", [])
)
if not (present or named_unstable):
    raise SystemExit(
        "a file created after the listing snapshot was silently omitted"
    )
LISTRACE
rm -f "${config_dir}/race-born.txt"
if [[ "${listing_race_status}" -ne 0 ]]; then
  echo "digest re-read silently omitted a file created during the walk" >&2
  exit 1
fi

# Identity material configured OUTSIDE the walked trees must be in the
# inventory: the guard validates an external CA at service start, and a
# document that recorded only the path string would stay byte-identical
# across its substitution. Both directions, against the real agent
# contract, restored afterwards.
external_baseline="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${external_baseline}" <<'EXTBASE'
import json
import sys

document = json.loads(sys.argv[1])
if document.get("configured_paths") != []:
    raise SystemExit(
        f"in-tree config produced configured_paths records: {document.get('configured_paths')}"
    )
EXTBASE
mkdir -p "${home}/external-trust"
chmod 0755 "${home}/external-trust"
cp "${pki}/controller-ca.pem" "${home}/external-trust/controller-ca.pem"
chmod 0644 "${home}/external-trust/controller-ca.pem"
cp "${config_dir}/agent.env" "${workdir}/agent.env.before-external"
sed -i "s#^MCLOVING_CONTROLLER_CA_PATH=.*#MCLOVING_CONTROLLER_CA_PATH=${home}/external-trust/controller-ca.pem#" \
  "${config_dir}/agent.env"
grep -q "^MCLOVING_CONTROLLER_CA_PATH=${home}/external-trust/controller-ca.pem\$" \
  "${config_dir}/agent.env" || {
  echo "external-CA gate could not rewrite MCLOVING_CONTROLLER_CA_PATH; contract shape changed" >&2
  exit 1
}
external_doc="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${external_doc}" <<'EXTREC'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("configured_paths", [])}
entry = records.get("external-trust/controller-ca.pem")
if entry is None:
    raise SystemExit(f"external CA missing from configured_paths: {sorted(records)}")
if "sha256" not in entry or "mode" not in entry:
    raise SystemExit(f"external CA record lacks digest or mode: {entry}")
ancestors = {record["path"] for record in document.get("ancestors", [])}
if "external-trust" not in ancestors:
    raise SystemExit(f"external CA ancestor chain missing: {sorted(ancestors)}")
EXTREC
printf 'SUBSTITUTED-TRUST-ROOT-BYTES\n' > "${home}/external-trust/controller-ca.pem"
chmod 0644 "${home}/external-trust/controller-ca.pem"
external_substituted="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
if [[ "${external_doc}" == "${external_substituted}" ]]; then
  echo "substituting the external CA left the digest re-read unchanged" >&2
  exit 1
fi
cp "${pki}/controller-ca.pem" "${home}/external-trust/controller-ca.pem"
chmod 0644 "${home}/external-trust/controller-ca.pem"
cp "${workdir}/agent.env.before-external" "${config_dir}/agent.env"
chmod 0600 "${config_dir}/agent.env"
rm -rf "${home}/external-trust"
external_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
[[ "${external_baseline}" == "${external_restored}" ]] || {
  echo "the re-read did not return to baseline after the external CA was removed" >&2
  exit 1
}

# A configured spelling that carries ".." -- .config/mcloving/../ca.pem --
# has the walked config tree as a LEXICAL prefix while naming a file the
# walk never visits. Unnormalized, the containment test classifies it as
# covered, the record never exists, and substituting the real target leaves
# the canonical document byte-identical. The path must be normalized
# (lexically -- symlink policy stays per-class) before containment, so the
# target is recorded, pinned, and its substitution visible.
dotdot_target="${home}/.config/ca-dotdot.pem"
cp "${pki}/controller-ca.pem" "${dotdot_target}"
chmod 0644 "${dotdot_target}"
cp "${config_dir}/agent.env" "${workdir}/agent.env.before-dotdot"
sed -i "s#^MCLOVING_CONTROLLER_CA_PATH=.*#MCLOVING_CONTROLLER_CA_PATH=${home}/.config/mcloving/../ca-dotdot.pem#" \
  "${config_dir}/agent.env"
grep -q "^MCLOVING_CONTROLLER_CA_PATH=${home}/.config/mcloving/../ca-dotdot.pem\$" \
  "${config_dir}/agent.env" || {
  echo "dotdot gate could not rewrite MCLOVING_CONTROLLER_CA_PATH; contract shape changed" >&2
  exit 1
}
dotdot_doc="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${dotdot_doc}" <<'DOTDOT'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("configured_paths", [])}
entry = records.get(".config/ca-dotdot.pem")
if entry is None:
    raise SystemExit(
        f"the ..-spelled configured CA was not recorded under its normalized "
        f"path: {sorted(records)}"
    )
if "sha256" not in entry or "mode" not in entry:
    raise SystemExit(f"the ..-spelled CA record lacks digest or mode: {entry}")
dotted = [path for path in records if "/../" in path or path.startswith("../")]
if dotted:
    raise SystemExit(f"unnormalized spellings leaked into the document: {dotted}")
DOTDOT
printf 'SUBSTITUTED-DOTDOT-TRUST-BYTES\n' > "${dotdot_target}"
chmod 0644 "${dotdot_target}"
dotdot_substituted="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
if [[ "${dotdot_doc}" == "${dotdot_substituted}" ]]; then
  echo "substituting the ..-spelled CA left the digest re-read unchanged" >&2
  exit 1
fi
cp "${workdir}/agent.env.before-dotdot" "${config_dir}/agent.env"
chmod 0600 "${config_dir}/agent.env"
rm -f "${dotdot_target}"
dotdot_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
[[ "${external_baseline}" == "${dotdot_restored}" ]] || {
  echo "the re-read did not return to baseline after the ..-spelled CA was removed" >&2
  exit 1
}

# A quoted multiline contract value carrying a newline in an absolute path
# is legal to the shared parser and to systemd; the inventory transport
# must carry it as ONE item with the right digest, never split it into
# records that hash unrelated paths.
newline_dir_literal="${home}/nl
dir"
mkdir -p "${newline_dir_literal}"
chmod 0755 "${newline_dir_literal}"
printf 'newline-path-trust-bytes' > "${newline_dir_literal}/ca.pem"
chmod 0644 "${newline_dir_literal}/ca.pem"
cp "${config_dir}/agent.env" "${workdir}/agent.env.before-newline"
python3 - "${config_dir}/agent.env" "${newline_dir_literal}/ca.pem" <<'NLREWRITE'
import sys
from pathlib import Path

contract = Path(sys.argv[1])
target = sys.argv[2]
lines = []
for line in contract.read_text().splitlines():
    if line.startswith("MCLOVING_CONTROLLER_CA_PATH="):
        lines.append("MCLOVING_CONTROLLER_CA_PATH='" + target + "'")
    else:
        lines.append(line)
contract.write_text("\n".join(lines) + "\n")
NLREWRITE
chmod 0600 "${config_dir}/agent.env"
newline_doc="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${newline_doc}" <<'NLCHECK'
import hashlib
import json
import sys

document = json.loads(sys.argv[1])
records = [
    record
    for record in document.get("configured_paths", [])
    if "nl" in record.get("path", "")
]
if len(records) != 1:
    raise SystemExit(f"newline-bearing path did not round-trip as one record: {records}")
expected = hashlib.sha256(b"newline-path-trust-bytes").hexdigest()
if records[0].get("sha256") != expected:
    raise SystemExit(f"newline-bearing path hashed the wrong bytes: {records[0]}")
if "\n" not in records[0]["path"]:
    raise SystemExit(f"the record lost the newline from the path: {records[0]}")
NLCHECK
cp "${workdir}/agent.env.before-newline" "${config_dir}/agent.env"
chmod 0600 "${config_dir}/agent.env"
rm -rf "${newline_dir_literal}"
newline_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
[[ "${external_baseline}" == "${newline_restored}" ]] || {
  echo "the re-read did not return to baseline after the newline path was removed" >&2
  exit 1
}

# Ownership is identity too. An ancestor that changes hands can be re-moded
# by its new owner at will, so the canonical document must change when the
# owner does -- and the change must be visible in the record, both proven
# with a REAL foreign uid via `podman unshare chown` (no root needed). The
# foreign-owned directory is opened to 0755 for the duration: at the
# installed 0700 the invoking user could no longer traverse its own
# deployment to run the helper at all -- which is the attack in miniature,
# but not what this gate measures.
owner_gate_dir="${home}/.local"
owner_gate_mode="$(stat -c '%a' "${owner_gate_dir}")"
owner_doc_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
podman unshare sh -c "chown 1:1 '${owner_gate_dir}' && chmod 0755 '${owner_gate_dir}'"
# Ownership is restored on the failure path too: a workdir preserved with a
# subuid-owned directory inside cannot be removed by the invoking user, and
# the next run's cleanup would fail on it.
owner_doc_after="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")" || {
  podman unshare chown 0:0 "${owner_gate_dir}" || true
  chmod "${owner_gate_mode}" "${owner_gate_dir}" || true
  echo "digest re-read failed while an ancestor was foreign-owned" >&2
  exit 1
}
podman unshare chown 0:0 "${owner_gate_dir}"
chmod "${owner_gate_mode}" "${owner_gate_dir}"
if [[ "${owner_doc_before}" == "${owner_doc_after}" ]]; then
  echo "a re-owned ancestor left the digest re-read unchanged" >&2
  exit 1
fi
python3 - "${owner_doc_after}" <<'OWNERSHIP'
import json
import os
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("ancestors", [])}
entry = records.get(".local")
if entry is None:
    raise SystemExit(f"ancestor .local missing from the re-read: {sorted(records)}")
if entry.get("uid") in (None, os.getuid()):
    raise SystemExit(f"foreign owner not recorded on the ancestor: {entry}")
if entry.get("gid") in (None, os.getgid()):
    raise SystemExit(f"foreign group not recorded on the ancestor: {entry}")
OWNERSHIP
owner_doc_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
if [[ "${owner_doc_before}" != "${owner_doc_restored}" ]]; then
  echo "the re-read did not return to baseline after ownership was restored" >&2
  exit 1
fi

# Nested symlinks discovered by the walk feed their resolved target's
# parent chain into the ancestors too: pki/certs -> ~/depot/certs is
# followed and inventoried, and without this the mode of ~/depot could
# change while the document stayed byte-identical. Both directions, plus
# the totality rule: an unresolvable nested link becomes a RECORD, never a
# failed run.
mkdir -p "${home}/depot/certs"
chmod 0755 "${home}/depot" "${home}/depot/certs"
ln -s "${home}/depot/certs" "${config_dir}/pki/certs-link"
nested_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
python3 - "${nested_before}" <<'NESTED'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("ancestors", [])}
if "depot" not in records:
    raise SystemExit(f"nested link target parent missing: {sorted(records)}")
NESTED
chmod 0777 "${home}/depot"
nested_after="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod 0755 "${home}/depot"
if [[ "${nested_before}" == "${nested_after}" ]]; then
  echo "a relaxed nested-link target parent left the re-read unchanged" >&2
  exit 1
fi
python3 - "${nested_after}" <<'NESTEDMODE'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("ancestors", [])}
if records.get("depot", {}).get("mode") != 0o777:
    raise SystemExit(f"nested target parent mode not recorded: {records.get('depot')}")
NESTEDMODE
nested_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
[[ "${nested_before}" == "${nested_restored}" ]] || {
  echo "the nested-link re-read did not return to baseline" >&2
  exit 1
}
# Totality: an unresolvable nested link is recorded, not fatal.
ln -s "${workdir}/definitely-absent-target" "${config_dir}/pki/broken-link"
nested_unresolvable="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")" || {
  echo "an unresolvable nested link failed the whole re-read" >&2
  rm -f "${config_dir}/pki/broken-link" "${config_dir}/pki/certs-link"
  exit 1
}
python3 - "${nested_unresolvable}" <<'NESTEDBROKEN'
import json
import sys

document = json.loads(sys.argv[1])
entries = [
    record
    for record in document.get("ancestors", [])
    if record.get("kind") == "unresolvable_link_chain"
    and record["path"].endswith("pki/broken-link")
]
if not entries:
    raise SystemExit("unresolvable nested link chain was not recorded")
NESTEDBROKEN
rm -f "${config_dir}/pki/broken-link" "${config_dir}/pki/certs-link"
rm -rf "${home}/depot"

# systemd and Quadlet read every file inside a matching drop-in directory
# regardless of its basename, so the inventory must too: an override.conf
# changing Restart= or ExecStart= alters the real configuration, and a
# basename filter applied below the top level left the canonical document
# byte-identical across it. Both unit trees follow the convention; both are
# gated.
dropin_service_dir="${smoke_unit_root}/mcloving-controller.service.d"
dropin_quadlet_dir="${smoke_quadlet_root}/mcloving-postgres.container.d"
dropin_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
mkdir -p "${dropin_service_dir}" "${dropin_quadlet_dir}"
printf '[Service]\nRestart=always\n' > "${dropin_service_dir}/override.conf"
printf '[Container]\nEnvironment=SMOKE=1\n' > "${dropin_quadlet_dir}/tweak.conf"
dropin_added="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
if [[ "${dropin_before}" == "${dropin_added}" ]]; then
  echo "adding unit drop-ins left the digest re-read unchanged" >&2
  exit 1
fi
python3 - "${dropin_added}" <<'DROPIN'
import json
import sys

document = json.loads(sys.argv[1])
paths = {record["path"] for record in document.get("units", [])}
required = {
    ".config/systemd/user/mcloving-controller.service.d",
    ".config/systemd/user/mcloving-controller.service.d/override.conf",
    ".config/containers/systemd/mcloving-postgres.container.d",
    ".config/containers/systemd/mcloving-postgres.container.d/tweak.conf",
}
missing = required - paths
if missing:
    raise SystemExit(f"drop-in records missing from the unit inventory: {sorted(missing)}")
DROPIN
printf '[Service]\nRestart=no\n' > "${dropin_service_dir}/override.conf"
dropin_changed="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
if [[ "${dropin_added}" == "${dropin_changed}" ]]; then
  echo "changing a drop-in's content left the digest re-read unchanged" >&2
  exit 1
fi
rm -rf "${dropin_service_dir}" "${dropin_quadlet_dir}"
dropin_restored="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
[[ "${dropin_before}" == "${dropin_restored}" ]] || {
  echo "the re-read did not return to baseline after the drop-ins were removed" >&2
  exit 1
}

# Content is not the whole identity. A deployed binary that loses its execute
# bit keeps its digest and size while systemd can no longer run it, and the
# release manifest records executable: true per component, so the re-read has
# to carry the mode or the cutover freeze cannot see that drift.
mode_before="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
current_agent="${libexec}/current/mcloving-agent"
chmod 0644 "${current_agent}"
mode_after="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
chmod 0755 "${current_agent}"
if [[ "${mode_before}" == "${mode_after}" ]]; then
  echo "a deployed binary that lost its execute bit left the re-read unchanged" >&2
  exit 1
fi
python3 - "${mode_after}" <<'MODE'
import json
import sys

document = json.loads(sys.argv[1])
# Scoped to the release that `current` points at. Earlier upgrades leave other
# release directories on disk, and only the current one had its execute bit
# stripped -- asserting across all of them tests the wrong thing.
current = document.get("current_release")
if not current:
    raise SystemExit("re-read has no current release")
suffix = f"/{current}/mcloving-agent"
entry = [
    item for item in document.get("releases", []) if item["path"].endswith(suffix)
]
if not entry:
    raise SystemExit(f"agent of the current release {current} missing from the re-read")
if any(item.get("executable") is not False for item in entry):
    raise SystemExit(f"non-executable agent not recorded as such: {entry}")
MODE

# Changing the active release is the upgrade path's job: it stops the services,
# flips the symlinks, restarts, and gates on health. An installer rerun would
# repoint current under running processes, leaving them on the old binaries
# while the digest re-read reports the new release as current. Run in its own
# home so the assertion does not depend on which release is current here.
rerun_home="${workdir}/rerun-home"
rm -rf "${rerun_home}"
mkdir -p "${rerun_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${rerun_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
rerun_libexec="${rerun_home}/.local/libexec/mcloving"
# Reinstalling the release that is already current is accepted, and must not
# leave the redundant staging copy behind.
"${repo_root}/deploy/bin/mcloving-install" --home "${rerun_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
if compgen -G "${rerun_libexec}/releases/.staging.*" >/dev/null; then
  echo "reinstalling the current release left a redundant staging copy" >&2
  exit 1
fi
# A different release must be refused and must change nothing.
rerun_before="$(readlink "${rerun_libexec}/current")"
rerun_releases_before="$(ls "${rerun_libexec}/releases" | sort | tr '\n' ' ')"
if "${repo_root}/deploy/bin/mcloving-install" --home "${rerun_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install repointed current for a differing existing installation" >&2
  exit 1
fi
[[ "$(readlink "${rerun_libexec}/current")" == "${rerun_before}" ]] || {
  echo "a refused installer rerun still moved the current release" >&2
  exit 1
}
if compgen -G "${rerun_libexec}/releases/.staging.*" >/dev/null; then
  echo "a refused installer rerun left staging behind" >&2
  exit 1
fi
# A refused command must not have published anything either: staging the copy
# before deciding would add a release to disk and to the canonical inventory
# under an operation reported as refused.
[[ "$(ls "${rerun_libexec}/releases" | sort | tr '\n' ' ')" == "${rerun_releases_before}" ]] || {
  echo "a refused installer rerun still published a release" >&2
  exit 1
}
rm -rf "${rerun_home}"

# A release entry that is not a regular file must be refused before it is
# copied: `install` reading a FIFO blocks until something writes, and reading a
# symlinked device fills the disk, both before digest verification runs.
fifo_release="${workdir}/fifo-release"
rm -rf "${fifo_release}"
cp -r "${release_dir}" "${fifo_release}"
rm -f "${fifo_release}/mcloving-cli"
mkfifo "${fifo_release}/mcloving-cli"
fifo_home="${workdir}/fifo-home"
rm -rf "${fifo_home}"
mkdir -p "${fifo_home}"
fifo_status=0
timeout 60 "${repo_root}/deploy/bin/mcloving-install" --home "${fifo_home}" \
  --release-dir "${fifo_release}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1 || fifo_status=$?
if [[ "${fifo_status}" -eq 0 ]]; then
  echo "install accepted a release entry that is not a regular file" >&2
  exit 1
fi
if [[ "${fifo_status}" -eq 124 ]]; then
  echo "install hung reading a FIFO release entry" >&2
  exit 1
fi
rm -rf "${fifo_release}" "${fifo_home}"

# Identical bytes without execute permission still cannot run, so a published
# release that lost its execute bits must be refused rather than reported
# usable.
noexec_home="${workdir}/noexec-home"
rm -rf "${noexec_home}"
mkdir -p "${noexec_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${noexec_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
chmod 0644 "${noexec_home}/.local/libexec/mcloving/current/mcloving-agent"
if "${repo_root}/deploy/bin/mcloving-install" --home "${noexec_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install reported success over a release whose binaries cannot execute" >&2
  exit 1
fi
rm -rf "${noexec_home}"

# A directory where a contract file belongs must be refused. Without -T, GNU
# install copies the example *into* that directory and reports success while
# the unit's EnvironmentFile= still names a directory and startup must fail.
dir_dest_home="${workdir}/dir-dest-home"
rm -rf "${dir_dest_home}"
mkdir -p "${dir_dest_home}/.config/mcloving/agent.env"
if "${repo_root}/deploy/bin/mcloving-install" --home "${dir_dest_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install reported success with a directory where a contract must be" >&2
  exit 1
fi
rm -rf "${dir_dest_home}"

# A refusal must never delete a release it did not publish: the same id can
# already be the retained rollback target.
retain_home="${workdir}/retain-home"
rm -rf "${retain_home}"

# A retained release tree under the SAME truncated id as a newly verified
# release must be byte-compared, never adopted by name: the id keeps only 48
# digest bits, and without the comparison a colliding or substituted tree
# would be reused while the newly verified staging copy is deleted. The
# benign-reuse acceptance direction is the reinstall-the-current-release
# gate above, which still passes with the comparison in place.
collision_home="${workdir}/collision-home"
rm -rf "${collision_home}"

# A symlink where a retained release directory belongs has no legitimate
# state -- stage_release only publishes real directories -- and -d, cmp,
# and the digest re-verification would all follow it into an unvalidated
# external chain. Refused by name at stage time; and the current/previous
# links the upgrade and rollback paths trust are validated the same way:
# targets must be releases/<id> entries, and the entry must be a real
# directory.
linktrap_home="${workdir}/linktrap-home"
rm -rf "${linktrap_home}"

# Release state transitions are serialized by one deployment-wide advisory
# lock across install, upgrade, and rollback. A held lock must produce a
# named refusal -- never a silent queue behind a snapshot that is about to
# go stale -- and the release must be untouched; a released lock must let
# the same transition through.
lock_home="${workdir}/lock-home"
rm -rf "${lock_home}"

# An ancestor relaxed AFTER installation must refuse the next transition --
# upgrade and rollback rerun the full shared validation inside the lock,
# before anything mutates and before rollback stops any service.
transguard_home="${workdir}/transguard-home"
rm -rf "${transguard_home}"

# A drop-in merges into its unit, so a drop-in-declared EnvironmentFile is
# a path the transition trusts: its chain joins the validated set through
# the same parser, and a writable parent refuses the transition by name.
dropin_root_home="${workdir}/dropin-root-home"
rm -rf "${dropin_root_home}"
mkdir -p "${dropin_root_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${dropin_root_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
dropin_root_libexec="${dropin_root_home}/.local/libexec/mcloving"
dropin_root_current="$(readlink "${dropin_root_libexec}/current")"
mkdir -p "${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d"
printf '[Service]\nEnvironmentFile=%%h/dropin-shared/controller-extra.env\n' \
  > "${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d/override.conf"
mkdir -p "${dropin_root_home}/dropin-shared"
chmod 0777 "${dropin_root_home}/dropin-shared"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/dropin-root.log" 2>&1; then
  echo "upgrade proceeded over a writable drop-in-declared environment root" >&2
  exit 1
fi
grep -q "dropin-shared (mode 777)" "${workdir}/logs/dropin-root.log" || {
  echo "the drop-in-declared root refusal did not name the parent:" >&2
  cat "${workdir}/logs/dropin-root.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused drop-in-root upgrade still moved the current release" >&2
  exit 1
}
chmod 0755 "${dropin_root_home}/dropin-shared"
# A drop-in-declared EnvironmentFile IS a contract wherever it points:
# existing at 0644 it must be refused under the contract file rule, and
# admitted at owner-only.
printf 'MCLOVING_EXTRA=1\n' > "${dropin_root_home}/dropin-shared/controller-extra.env"
chmod 0644 "${dropin_root_home}/dropin-shared/controller-extra.env"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/dropin-contract.log" 2>&1; then
  echo "upgrade proceeded over a group-readable drop-in-declared contract" >&2
  exit 1
fi
grep -q "controller-extra.env (mode 644, expected owner-only)" \
  "${workdir}/logs/dropin-contract.log" || {
  echo "the drop-in-declared contract was not held to the contract rule:" >&2
  cat "${workdir}/logs/dropin-contract.log" >&2
  exit 1
}
chmod 0600 "${dropin_root_home}/dropin-shared/controller-extra.env"
# An existing contract must be a REGULAR file: an owner-only 0600 FIFO
# passes every mode/owner/readability check while systemd's later
# EnvironmentFile= load would block or stream another process's bytes --
# after the transition already stopped the services. The timeout is the
# gate's own regression net: a validation that OPENS the node would hang
# here instead of refusing.
rm -f "${dropin_root_home}/dropin-shared/controller-extra.env"
mkfifo "${dropin_root_home}/dropin-shared/controller-extra.env"
chmod 0600 "${dropin_root_home}/dropin-shared/controller-extra.env"
dropin_fifo_status=0
timeout 60 "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/dropin-contract-fifo.log" 2>&1 \
  || dropin_fifo_status=$?
if [[ "${dropin_fifo_status}" -eq 0 ]]; then
  echo "upgrade proceeded over a FIFO drop-in-declared contract" >&2
  exit 1
fi
if [[ "${dropin_fifo_status}" -eq 124 ]]; then
  echo "transition validation hung opening a FIFO contract instead of refusing it" >&2
  exit 1
fi
grep -q "controller-extra.env (not a regular file: fifo)" \
  "${workdir}/logs/dropin-contract-fifo.log" || {
  echo "the FIFO contract refusal was not named:" >&2
  cat "${workdir}/logs/dropin-contract-fifo.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused FIFO-contract upgrade still moved the current release" >&2
  exit 1
}
rm -f "${dropin_root_home}/dropin-shared/controller-extra.env"
printf 'MCLOVING_EXTRA=1\n' > "${dropin_root_home}/dropin-shared/controller-extra.env"
chmod 0600 "${dropin_root_home}/dropin-shared/controller-extra.env"
# systemd strips whitespace around the '=' separator, so
# `EnvironmentFile = path` is the SAME declaration as the exact-prefix
# spelling -- and it must reach the same validation. The spaced contract
# is declared through a second drop-in, left at 0644: a parser that
# extracts the spaced spelling refuses under the contract rule; the old
# per-key grep emitted nothing and the transition proceeded with the
# declared contract entirely unvalidated.
printf '[Service]\nEnvironmentFile = %%h/dropin-shared/spaced-extra.env\n' \
  > "${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d/spaced.conf"
printf 'MCLOVING_SPACED=1\n' > "${dropin_root_home}/dropin-shared/spaced-extra.env"
chmod 0644 "${dropin_root_home}/dropin-shared/spaced-extra.env"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/spaced-contract.log" 2>&1; then
  echo "upgrade proceeded over a spaced-assignment declared contract at 0644" >&2
  exit 1
fi
grep -q "spaced-extra.env (mode 644, expected owner-only)" \
  "${workdir}/logs/spaced-contract.log" || {
  echo "the spaced-assignment contract escaped extraction or the refusal was unnamed:" >&2
  cat "${workdir}/logs/spaced-contract.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused spaced-contract upgrade still moved the current release" >&2
  exit 1
}
# Acceptance direction: secured owner-only, the spaced declaration admits
# the transition; rolled back and removed to restore the section's state.
chmod 0600 "${dropin_root_home}/dropin-shared/spaced-extra.env"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" != "${dropin_root_current}" ]] || {
  echo "the secured spaced-assignment contract did not admit the transition" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the spaced-contract gate" >&2
  exit 1
}
rm -f "${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d/spaced.conf" \
  "${dropin_root_home}/dropin-shared/spaced-extra.env"
# Constructs systemd consumes that the parser deliberately does not model
# must refuse LOUDLY, never silently under-validate: a line continuation
# joins lines in systemd, and quoting unwraps path values -- each is a
# named refusal until spelled plainly.
printf '[Service]\nEnvironmentFile=%%h/dropin-shared/controller-extra.env \\\n' \
  > "${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d/continued.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/continued-dropin.log" 2>&1; then
  echo "upgrade proceeded over a continuation-line drop-in the parser cannot model" >&2
  exit 1
fi
grep -q "ends a line with the continuation backslash" \
  "${workdir}/logs/continued-dropin.log" || {
  echo "the continuation-line refusal was not named:" >&2
  cat "${workdir}/logs/continued-dropin.log" >&2
  exit 1
}
rm -f "${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d/continued.conf"
printf '[Service]\nStateDirectory="quoted name"\n' \
  > "${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d/quoted.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/quoted-dropin.log" 2>&1; then
  echo "upgrade proceeded over a quoted path value the parser cannot model" >&2
  exit 1
fi
grep -q "declares StateDirectory with a quote character" \
  "${workdir}/logs/quoted-dropin.log" || {
  echo "the quoted-value refusal was not named:" >&2
  cat "${workdir}/logs/quoted-dropin.log" >&2
  exit 1
}
rm -f "${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d/quoted.conf"
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused unparseable-source upgrade still moved the current release" >&2
  exit 1
}
# systemd.exec documents EnvironmentFile= as "an absolute filename OR
# WILDCARD EXPRESSION" and loads EVERY match. Validating the pattern
# itself validates nothing -- the literal does not exist, so the contract
# rule skips it -- while a writable match supplies attacker-controlled
# environment to the next restart. Two rules must both hold, and this
# gate proves both plus the acceptance direction.
wild_dir="${dropin_root_home}/wildcard-env"
mkdir -p "${wild_dir}"
chmod 0755 "${wild_dir}"
printf 'MCLOVING_WILD=1\n' > "${wild_dir}/extra.env"
printf '[Service]\nEnvironmentFile=%%h/wildcard-env/*.env\n' \
  > "${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d/wildcard.conf"
# (1) Every MATCH is judged under the contract rule. A match that is
# already group/world-writable is invisible to the directory bound below
# -- a 0666 file inside a 0755 root-owned directory is rewritable by
# anyone -- so per-match validation is load-bearing, not decoration.
chmod 0666 "${wild_dir}/extra.env"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/wildcard-match.log" 2>&1; then
  echo "upgrade proceeded over a world-writable wildcard-matched contract" >&2
  exit 1
fi
grep -q "extra.env (mode 666, expected owner-only)" \
  "${workdir}/logs/wildcard-match.log" || {
  echo "the wildcard match escaped expansion or the refusal was unnamed:" >&2
  cat "${workdir}/logs/wildcard-match.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused wildcard-match upgrade still moved the current release" >&2
  exit 1
}
# (2) The DIRECTORY the pattern expands in must itself be closed to other
# users. This is the half that bounds the interval systemd's own
# expansion opens: the glob is evaluated shortly before exec, long after
# this validation, so a match CREATED in between is never observable
# here -- only who is able to create one is, and that is exactly what
# this refusal enforces.
chmod 0600 "${wild_dir}/extra.env"
chmod 0777 "${wild_dir}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/wildcard-dir.log" 2>&1; then
  echo "upgrade proceeded over a world-writable wildcard expansion directory" >&2
  exit 1
fi
grep -q "wildcard-env (mode 777)" "${workdir}/logs/wildcard-dir.log" || {
  echo "the wildcard expansion directory was not judged:" >&2
  cat "${workdir}/logs/wildcard-dir.log" >&2
  exit 1
}
# Acceptance: owner-only match inside a closed directory admits the
# transition, and the expansion really did happen -- a parser that
# emitted nothing at all would also "pass" here, so the refusals above
# are what prove the extraction, and this proves it is not over-broad.
chmod 0755 "${wild_dir}"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" != "${dropin_root_current}" ]] || {
  echo "the secured wildcard-matched contract did not admit the transition" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the wildcard gate" >&2
  exit 1
}
# The expansion is glob(3)'s, the same one systemd performs: a dotfile is
# NOT matched by '*', so a match set that included it would mean this
# deployment validates paths systemd never loads (and, worse, that the
# two disagree about what the declaration means).
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  printf 'HIDDEN=1\n' > "${wild_dir}/.hidden.env"
  chmod 0600 "${wild_dir}/.hidden.env"
  wild_matches=""
  while IFS= read -r encoded_wild; do
    [[ -n "${encoded_wild}" ]] || continue
    decode_path_item_into decoded_wild "${encoded_wild}"
    # shellcheck disable=SC2154 # assigned through the nameref above
    wild_matches+="${decoded_wild}"$'\n'
  done < <(deployment_glob_matches "${wild_dir}/*.env")
  rm -f "${wild_dir}/.hidden.env"
  grep -q "extra.env" <<<"${wild_matches}" || {
    echo "glob expansion missed the plain match: ${wild_matches}" >&2
    exit 1
  }
  if grep -q ".hidden.env" <<<"${wild_matches}"; then
    echo "glob expansion matched a dotfile that systemd's glob(3) would not" >&2
    exit 1
  fi
)
rm -f "${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d/wildcard.conf"
rm -rf "${wild_dir}"
# systemd.unit(5) consults far more than "<unit>.d". A TYPE-WIDE
# service.d/*.conf applies to every service, and a DASH-TRUNCATED prefix
# directory such as mcloving-.service.d/*.conf applies to every unit whose
# name starts with that prefix -- both of them to this deployment's units.
# Enumerating only the exact directory left those sources unsecured and
# the paths they declare unparsed, which is an ExecStart= or an external
# EnvironmentFile= injected into the next transition's restart.
dropin_unit_root="${dropin_root_home}/.config/systemd/user"
typewide_dir="${dropin_unit_root}/service.d"
prefix_dir="${dropin_unit_root}/mcloving-.service.d"
mkdir -p "${typewide_dir}" "${prefix_dir}"
# (1) The type-wide SOURCE itself takes the trust-input file rule.
printf '[Service]\nRestart=always\n' > "${typewide_dir}/zz-typewide.conf"
chmod 0666 "${typewide_dir}/zz-typewide.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/typewide-source.log" 2>&1; then
  echo "upgrade proceeded over a world-writable type-wide drop-in source" >&2
  exit 1
fi
grep -q "zz-typewide.conf (mode 666)" "${workdir}/logs/typewide-source.log" || {
  echo "the type-wide drop-in source was not judged:" >&2
  cat "${workdir}/logs/typewide-source.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused type-wide-source upgrade still moved the current release" >&2
  exit 1
}
# (2) And the paths the type-wide drop-in DECLARES are parsed. A secured
# source that escapes the parser is the quieter half of the same gap.
chmod 0644 "${typewide_dir}/zz-typewide.conf"
mkdir -p "${dropin_root_home}/dropin-shared"
chmod 0755 "${dropin_root_home}/dropin-shared"
printf 'MCLOVING_TYPEWIDE=1\n' > "${dropin_root_home}/dropin-shared/typewide.env"
chmod 0644 "${dropin_root_home}/dropin-shared/typewide.env"
printf '[Service]\nEnvironmentFile=%%h/dropin-shared/typewide.env\n' \
  > "${typewide_dir}/zz-typewide.conf"
chmod 0644 "${typewide_dir}/zz-typewide.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/typewide-contract.log" 2>&1; then
  echo "upgrade proceeded over a contract declared only by a type-wide drop-in" >&2
  exit 1
fi
grep -q "typewide.env (mode 644, expected owner-only)" \
  "${workdir}/logs/typewide-contract.log" || {
  echo "the type-wide drop-in's declared contract escaped the parser:" >&2
  cat "${workdir}/logs/typewide-contract.log" >&2
  exit 1
}
chmod 0600 "${dropin_root_home}/dropin-shared/typewide.env"
# (3) The dash-truncated PREFIX form, judged the same way. Its declared
# contract sits in a world-writable directory, so the refusal names the
# directory -- proving the chain walk reached a path only this form
# declares.
mkdir -p "${dropin_root_home}/prefix-shared"
printf 'MCLOVING_PREFIX=1\n' > "${dropin_root_home}/prefix-shared/prefix.env"
chmod 0600 "${dropin_root_home}/prefix-shared/prefix.env"
chmod 0777 "${dropin_root_home}/prefix-shared"
printf '[Service]\nEnvironmentFile=%%h/prefix-shared/prefix.env\n' \
  > "${prefix_dir}/zz-prefix.conf"
chmod 0644 "${prefix_dir}/zz-prefix.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/prefix-dropin.log" 2>&1; then
  echo "upgrade proceeded over a contract declared only by a prefix drop-in" >&2
  exit 1
fi
grep -q "prefix-shared (mode 777)" "${workdir}/logs/prefix-dropin.log" || {
  echo "the prefix drop-in's declared contract escaped the parser:" >&2
  cat "${workdir}/logs/prefix-dropin.log" >&2
  exit 1
}
chmod 0755 "${dropin_root_home}/prefix-shared"
# (4) Acceptance: with both forms secured the transition proceeds, and it
# is the refusals above that prove the enumeration reached them -- an
# enumeration that emitted nothing would pass this direction too.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" != "${dropin_root_current}" ]] || {
  echo "the secured type-wide and prefix drop-ins did not admit the transition" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the drop-in-form gate" >&2
  exit 1
}
# Exactness of the enumeration itself, against the forms systemd builds:
# every dash is a truncation point, not just the first, and a directory
# that resembles none of the forms is NOT consulted.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  form_probe="${workdir}/dropin-form-probe"
  rm -rf "${form_probe}"
  mkdir -p "${form_probe}"
  printf '[Service]\nExecStart=/bin/true\n' > "${form_probe}/foo-bar-baz.service"
  mkdir -p "${form_probe}/service.d" "${form_probe}/foo-bar-.service.d" \
    "${form_probe}/foo-.service.d" "${form_probe}/foo-bar-baz.service.d" \
    "${form_probe}/unrelated.d" "${form_probe}/foo-bar.service.d"
  form_seen=""
  while IFS= read -r encoded_form; do
    [[ -n "${encoded_form}" ]] || continue
    decode_path_item_into decoded_form "${encoded_form}"
    # shellcheck disable=SC2154 # assigned through the nameref above
    form_seen+="${decoded_form##*/}"$'\n'
  done < <(deployment_unit_dropin_dirs "${form_probe}" "${form_probe}/foo-bar-baz.service")
  for expected_form in service.d foo-bar-.service.d foo-.service.d \
    foo-bar-baz.service.d; do
    grep -qx "${expected_form}" <<<"${form_seen}" || {
      echo "the drop-in enumeration missed ${expected_form}: ${form_seen}" >&2
      exit 1
    }
  done
  for rejected_form in unrelated.d foo-bar.service.d; do
    if grep -qx "${rejected_form}" <<<"${form_seen}"; then
      echo "the drop-in enumeration claimed ${rejected_form}, which systemd does not consult" >&2
      exit 1
    fi
  done
  rm -rf "${form_probe}"
)
# The canonical digest document must see the type-wide directory too: its
# contents change what the services run, and the mcloving- name filter that
# selects top-level entries out of a shared unit root does not match
# "service.d".
typewide_digests_before="$("${dropin_root_libexec}/helpers/mcloving-deployed-digests" --home "${dropin_root_home}")"
printf '[Service]\nEnvironmentFile=%%h/dropin-shared/typewide.env\nRestart=always\n' \
  > "${typewide_dir}/zz-typewide.conf"
chmod 0644 "${typewide_dir}/zz-typewide.conf"
typewide_digests_after="$("${dropin_root_libexec}/helpers/mcloving-deployed-digests" --home "${dropin_root_home}")"
[[ "${typewide_digests_before}" != "${typewide_digests_after}" ]] || {
  echo "editing a type-wide drop-in left the canonical digest document unchanged" >&2
  exit 1
}
grep -q 'service.d/zz-typewide.conf' <<<"${typewide_digests_after}" || {
  echo "the canonical document does not record the type-wide drop-in at all" >&2
  exit 1
}
rm -rf "${typewide_dir}" "${prefix_dir}" "${dropin_root_home}/prefix-shared"
rm -f "${dropin_root_home}/dropin-shared/typewide.env"
# systemd merges a unit's drop-ins from EVERY user-unit load path, not only
# from the directory the main unit came from. The user-writable ones --
# $XDG_DATA_HOME/systemd/user and $XDG_RUNTIME_DIR/systemd/user -- are not
# managed roots, so a drop-in placed in either was neither secured nor
# parsed while systemd merged it into the units a transition restarts.
loadpath_data_root="${dropin_root_home}/.local/share/systemd/user"
loadpath_dropin="${loadpath_data_root}/mcloving-controller.service.d"
mkdir -p "${loadpath_dropin}"
chmod 0755 "${dropin_root_home}/.local/share" \
  "${dropin_root_home}/.local/share/systemd" "${loadpath_data_root}" \
  "${loadpath_dropin}"
# (1) The SOURCE in another load path takes the trust-input file rule.
printf '[Service]\nRestart=always\n' > "${loadpath_dropin}/zz-loadpath.conf"
chmod 0666 "${loadpath_dropin}/zz-loadpath.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/loadpath-source.log" 2>&1; then
  echo "upgrade proceeded over a world-writable drop-in in another load path" >&2
  exit 1
fi
grep -q "zz-loadpath.conf (mode 666)" "${workdir}/logs/loadpath-source.log" || {
  echo "the other-load-path drop-in source was not judged:" >&2
  cat "${workdir}/logs/loadpath-source.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused load-path-source upgrade still moved the current release" >&2
  exit 1
}
# (2) And the paths it DECLARES are parsed, from that load path too.
mkdir -p "${dropin_root_home}/loadpath-shared"
printf 'MCLOVING_LOADPATH=1\n' > "${dropin_root_home}/loadpath-shared/loadpath.env"
chmod 0600 "${dropin_root_home}/loadpath-shared/loadpath.env"
chmod 0777 "${dropin_root_home}/loadpath-shared"
printf '[Service]\nEnvironmentFile=%%h/loadpath-shared/loadpath.env\n' \
  > "${loadpath_dropin}/zz-loadpath.conf"
chmod 0644 "${loadpath_dropin}/zz-loadpath.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/loadpath-contract.log" 2>&1; then
  echo "upgrade proceeded over a contract declared only in another load path" >&2
  exit 1
fi
grep -q "loadpath-shared (mode 777)" "${workdir}/logs/loadpath-contract.log" || {
  echo "the other-load-path drop-in's declared contract escaped the parser:" >&2
  cat "${workdir}/logs/loadpath-contract.log" >&2
  exit 1
}
chmod 0755 "${dropin_root_home}/loadpath-shared"
# (3) The load path DIRECTORY itself is the containing bound for the paths
# outside the managed set: the drop-in that would be merged does not exist
# yet at validation time, so only who may CREATE one is observable. A
# world-writable load path is refused with no drop-in present at all.
rm -rf "${loadpath_dropin}"
chmod 0777 "${loadpath_data_root}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/loadpath-dir.log" 2>&1; then
  echo "upgrade proceeded over a world-writable user-unit load path" >&2
  exit 1
fi
grep -q ".local/share/systemd/user (mode 777)" "${workdir}/logs/loadpath-dir.log" || {
  echo "the world-writable load path directory was not judged:" >&2
  cat "${workdir}/logs/loadpath-dir.log" >&2
  exit 1
}
chmod 0755 "${loadpath_data_root}"
# (4) Acceptance: secured, the same transition proceeds.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" != "${dropin_root_current}" ]] || {
  echo "the secured other-load-path drop-in did not admit the transition" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the load-path gate" >&2
  exit 1
}
rm -rf "${dropin_root_home}/.local/share/systemd" "${dropin_root_home}/loadpath-shared"
# XDG_CONFIG_DIRS and XDG_DATA_DIRS are part of the user-unit load path --
# systemd's user_dirs() consults both, and `systemd-analyze --user
# unit-paths` reports /etc/xdg/systemd/user between the config home and
# /etc/systemd/user. Round 30 enumerated neither. An entry that resolves
# inside the deployment home is writable by the service account, so it is
# the sharp case and the one this gate can actually create.
xdgconf_root="${dropin_root_home}/xdgconf"
xdgconf_dropin="${xdgconf_root}/systemd/user/mcloving-controller.service.d"
mkdir -p "${xdgconf_dropin}"
chmod 0755 "${xdgconf_root}" "${xdgconf_root}/systemd" \
  "${xdgconf_root}/systemd/user" "${xdgconf_dropin}"
printf '[Service]\nRestart=always\n' > "${xdgconf_dropin}/zz-xdgconf.conf"
chmod 0666 "${xdgconf_dropin}/zz-xdgconf.conf"
if XDG_CONFIG_DIRS="${xdgconf_root}" "${repo_root}/deploy/bin/mcloving-upgrade" \
  --home "${dropin_root_home}" --release-dir "${release2_dir}" \
  --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/xdgconf-source.log" 2>&1; then
  echo "upgrade proceeded over a world-writable drop-in in an XDG_CONFIG_DIRS load path" >&2
  exit 1
fi
grep -q "zz-xdgconf.conf (mode 666)" "${workdir}/logs/xdgconf-source.log" || {
  echo "the XDG_CONFIG_DIRS drop-in source was not judged:" >&2
  cat "${workdir}/logs/xdgconf-source.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused XDG_CONFIG_DIRS upgrade still moved the current release" >&2
  exit 1
}
# And the paths it DECLARES are parsed from there too.
mkdir -p "${dropin_root_home}/xdg-shared"
printf 'MCLOVING_XDG=1\n' > "${dropin_root_home}/xdg-shared/xdg.env"
chmod 0600 "${dropin_root_home}/xdg-shared/xdg.env"
chmod 0777 "${dropin_root_home}/xdg-shared"
printf '[Service]\nEnvironmentFile=%%h/xdg-shared/xdg.env\n' \
  > "${xdgconf_dropin}/zz-xdgconf.conf"
chmod 0644 "${xdgconf_dropin}/zz-xdgconf.conf"
if XDG_CONFIG_DIRS="${xdgconf_root}" "${repo_root}/deploy/bin/mcloving-upgrade" \
  --home "${dropin_root_home}" --release-dir "${release2_dir}" \
  --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/xdgconf-contract.log" 2>&1; then
  echo "upgrade proceeded over a contract declared only from an XDG_CONFIG_DIRS load path" >&2
  exit 1
fi
grep -q "xdg-shared (mode 777)" "${workdir}/logs/xdgconf-contract.log" || {
  echo "the XDG_CONFIG_DIRS drop-in's declared contract escaped the parser:" >&2
  cat "${workdir}/logs/xdgconf-contract.log" >&2
  exit 1
}
chmod 0755 "${dropin_root_home}/xdg-shared"
# The same directory in XDG_DATA_DIRS rather than XDG_CONFIG_DIRS: both
# lists are consulted, so both must be enumerated.
if XDG_DATA_DIRS="${xdgconf_root}" "${repo_root}/deploy/bin/mcloving-upgrade" \
  --home "${dropin_root_home}" --release-dir "${release2_dir}" \
  --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/xdgdata-source.log" 2>&1; then
  : # secured now; the acceptance direction is asserted below
else
  echo "upgrade refused a secured XDG_DATA_DIRS load path:" >&2
  cat "${workdir}/logs/xdgdata-source.log" >&2
  exit 1
fi
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
chmod 0666 "${xdgconf_dropin}/zz-xdgconf.conf"
if XDG_DATA_DIRS="${xdgconf_root}" "${repo_root}/deploy/bin/mcloving-upgrade" \
  --home "${dropin_root_home}" --release-dir "${release2_dir}" \
  --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/xdgdata-relaxed.log" 2>&1; then
  echo "upgrade proceeded over a world-writable drop-in in an XDG_DATA_DIRS load path" >&2
  exit 1
fi
grep -q "zz-xdgconf.conf (mode 666)" "${workdir}/logs/xdgdata-relaxed.log" || {
  echo "the XDG_DATA_DIRS drop-in source was not judged:" >&2
  cat "${workdir}/logs/xdgdata-relaxed.log" >&2
  exit 1
}
# Acceptance: secured, and with neither variable set the same tree is
# simply not a load path at all, so the transition proceeds either way.
chmod 0644 "${xdgconf_dropin}/zz-xdgconf.conf"
XDG_CONFIG_DIRS="${xdgconf_root}" "${repo_root}/deploy/bin/mcloving-upgrade" \
  --home "${dropin_root_home}" --release-dir "${release2_dir}" \
  --checksums "${workdir}/checksums2.sha256" --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" != "${dropin_root_current}" ]] || {
  echo "the secured XDG_CONFIG_DIRS drop-in did not admit the transition" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
rm -rf "${xdgconf_root}" "${dropin_root_home}/xdg-shared"
# A main unit file is SELECTED, not merged: the first load path in
# precedence order holding the name wins and every lower one is ignored
# entirely. ~/.config/systemd/user.control outranks ~/.config/systemd/user,
# so a file planted there shadows the installed unit and its ExecStart is
# what the next restart executes.
shadow_control="${dropin_root_home}/.config/systemd/user.control"
mkdir -p "${shadow_control}"
chmod 0755 "${shadow_control}"
mkdir -p "${dropin_root_home}/shadow-bin"
printf '#!/bin/sh\nexit 0\n' > "${dropin_root_home}/shadow-bin/tool"
chmod 0755 "${dropin_root_home}/shadow-bin/tool" "${dropin_root_home}/shadow-bin"
printf '[Service]\nExecStart=%%h/shadow-bin/tool\n' \
  > "${shadow_control}/mcloving-controller.service"
chmod 0666 "${shadow_control}/mcloving-controller.service"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/shadow-unit.log" 2>&1; then
  echo "upgrade proceeded over a world-writable unit file shadowing the installed one" >&2
  exit 1
fi
grep -q "user.control/mcloving-controller.service (mode 666)" \
  "${workdir}/logs/shadow-unit.log" || {
  echo "the shadowing unit file was not judged:" >&2
  cat "${workdir}/logs/shadow-unit.log" >&2
  exit 1
}
grep -q "notice: unit file .*user.control/mcloving-controller.service outranks" \
  "${workdir}/logs/shadow-unit.log" || {
  echo "the shadowing unit file was not reported to the operator:" >&2
  cat "${workdir}/logs/shadow-unit.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused shadowing-unit upgrade still moved the current release" >&2
  exit 1
}
# A SECURED shadow is validated and REPORTED, not refused: systemd's load
# path exists so an administrator can override a unit, and a deployment
# that refused to upgrade over that mechanism would be un-upgradable with
# no repair it could perform. What closes the hole is that the override is
# judged like any other source, which the refusal above proves.
chmod 0644 "${shadow_control}/mcloving-controller.service"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/shadow-secured.log" 2>&1 || {
  echo "upgrade refused a secured administrative unit override:" >&2
  cat "${workdir}/logs/shadow-secured.log" >&2
  exit 1
}
grep -q "notice: unit file .*user.control/mcloving-controller.service outranks" \
  "${workdir}/logs/shadow-secured.log" || {
  echo "the secured shadowing unit passed without being reported:" >&2
  cat "${workdir}/logs/shadow-secured.log" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
# The canonical document records it, so an override appearing or changing
# is drift the re-read can see.
shadow_digests="$("${dropin_root_libexec}/helpers/mcloving-deployed-digests" \
  --home "${dropin_root_home}")"
printf '%s' "${shadow_digests}" > "${workdir}/shadow-digests.json"
python3 - "${workdir}/shadow-digests.json" <<'SHADOWDOC'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text())
if "shadowing_units" not in document:
    raise SystemExit(
        "the canonical document has no shadowing_units key; a unit override "
        "deciding what actually runs would be invisible drift"
    )
recorded = {record["path"] for record in document["shadowing_units"]}
if not any("user.control/mcloving-controller.service" in entry for entry in recorded):
    raise SystemExit(f"the shadowing unit was not recorded: {sorted(recorded)}")
SHADOWDOC
rm -f "${shadow_control}/mcloving-controller.service" "${workdir}/shadow-digests.json"
# The QUADLET-GENERATED name is the case an installed-file comparison would
# never notice: mcloving-postgres.service has no installed file at all, so
# a planted one shadows a unit this deployment owns and never wrote.
printf '[Service]\nExecStart=%%h/shadow-bin/tool\n' \
  > "${shadow_control}/mcloving-postgres.service"
chmod 0666 "${shadow_control}/mcloving-postgres.service"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/shadow-generated.log" 2>&1; then
  echo "upgrade proceeded over a world-writable shadow of the generated postgres service" >&2
  exit 1
fi
grep -q "user.control/mcloving-postgres.service (mode 666)" \
  "${workdir}/logs/shadow-generated.log" || {
  echo "the shadow of the generated service was not judged:" >&2
  cat "${workdir}/logs/shadow-generated.log" >&2
  exit 1
}
rm -f "${shadow_control}/mcloving-postgres.service"
# Acceptance: with nothing planted the transition proceeds and no notice is
# emitted -- the resolver must not claim the installed file shadows itself.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/shadow-none.log" 2>&1
if grep -q "outranks this deployment" "${workdir}/logs/shadow-none.log"; then
  echo "the resolver reported a shadow where none was planted:" >&2
  cat "${workdir}/logs/shadow-none.log" >&2
  exit 1
fi
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the shadow gate" >&2
  exit 1
}
# First-match precedence, asserted directly rather than inferred from the
# refusals: with the same name in both directories the resolver must pick
# the higher-priority one, and with only the installed file it must pick
# that. systemd 255 was confirmed to agree by planting the same pair under
# a throwaway unit name and reading FragmentPath back from the manager.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  resolved_installed="$(
    encoded="$(deployment_effective_unit_file "${dropin_root_home}" \
      mcloving-controller.service)"
    decode_path_item_into decoded "${encoded}"
    # shellcheck disable=SC2154 # assigned through the nameref above
    printf '%s' "${decoded}"
  )"
  [[ "${resolved_installed}" == "${dropin_unit_root}/mcloving-controller.service" ]] || {
    echo "with no shadow planted the resolver chose ${resolved_installed}, not the installed unit" >&2
    exit 1
  }
  printf '[Service]\nExecStart=%%h/shadow-bin/tool\n' \
    > "${shadow_control}/mcloving-controller.service"
  chmod 0644 "${shadow_control}/mcloving-controller.service"
  resolved_shadow="$(
    encoded="$(deployment_effective_unit_file "${dropin_root_home}" \
      mcloving-controller.service)"
    decode_path_item_into decoded "${encoded}"
    printf '%s' "${decoded}"
  )"
  [[ "${resolved_shadow}" == "${shadow_control}/mcloving-controller.service" ]] || {
    echo "with a shadow in user.control the resolver chose ${resolved_shadow}, not the higher-priority file" >&2
    exit 1
  }
  rm -f "${shadow_control}/mcloving-controller.service"
)
# A shadow reachable ONLY through a configured XDG_CONFIG_DIRS entry. The
# generated mcloving-postgres.service has no file in the config home, so
# the configured entry -- which sits one slot below it -- is what wins.
# This is the end-to-end proof that switching the selection list to
# replacement semantics did not lose coverage of the entries systemd DOES
# search.
xdgshadow_root="${dropin_root_home}/xdgshadow"
mkdir -p "${xdgshadow_root}/systemd/user"
chmod 0755 "${xdgshadow_root}" "${xdgshadow_root}/systemd" \
  "${xdgshadow_root}/systemd/user"
printf '[Service]\nExecStart=%%h/shadow-bin/tool\n' \
  > "${xdgshadow_root}/systemd/user/mcloving-postgres.service"
chmod 0666 "${xdgshadow_root}/systemd/user/mcloving-postgres.service"
if XDG_CONFIG_DIRS="${xdgshadow_root}" \
  "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/xdgshadow.log" 2>&1; then
  echo "upgrade proceeded over a shadow reachable through XDG_CONFIG_DIRS" >&2
  exit 1
fi
grep -q "xdgshadow/systemd/user/mcloving-postgres.service (mode 666)" \
  "${workdir}/logs/xdgshadow.log" || {
  echo "the XDG_CONFIG_DIRS shadow was not judged:" >&2
  cat "${workdir}/logs/xdgshadow.log" >&2
  exit 1
}
# With the variable unset the very same file is not a load path at all, so
# it is neither reported nor validated -- the selection list must not
# invent entries the manager would not search.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/xdgshadow-unset.log" 2>&1 || {
  echo "upgrade refused over a file that is not on any load path:" >&2
  cat "${workdir}/logs/xdgshadow-unset.log" >&2
  exit 1
}
if grep -q "xdgshadow" "${workdir}/logs/xdgshadow-unset.log"; then
  echo "a file outside every load path was reported as shadowing:" >&2
  cat "${workdir}/logs/xdgshadow-unset.log" >&2
  exit 1
fi
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
rm -rf "${xdgshadow_root}"
# A RELATIVE XDG search entry is resolved by systemd against the service
# manager's working directory, which this deployment cannot observe -- so
# the file that would actually be loaded is undeterminable and the entry is
# refused by name rather than resolved against the wrong directory.
if XDG_CONFIG_DIRS="relative-search-entry" \
  "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/xdg-relative.log" 2>&1; then
  echo "upgrade proceeded with a relative XDG_CONFIG_DIRS entry" >&2
  exit 1
fi
grep -q "XDG_CONFIG_DIRS entry relative-search-entry" \
  "${workdir}/logs/xdg-relative.log" || {
  echo "the relative XDG search entry was not refused by name:" >&2
  cat "${workdir}/logs/xdg-relative.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused relative-XDG upgrade still moved the current release" >&2
  exit 1
}
# A MASK is not an override. systemd masks a unit by symlinking its name to
# /dev/null in a load path; the unit then cannot start at all. The old
# resolver's -f test followed the link, saw a character device, said no, and
# fell through to the lower-priority installed file -- reporting as live a
# unit the manager refuses to load. A transition would stop both services,
# move current, and then fail to start anything.
mkdir -p "${shadow_control}"
chmod 0755 "${shadow_control}"
ln -sfn /dev/null "${shadow_control}/mcloving-controller.service"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/mask-unit.log" 2>&1; then
  echo "upgrade proceeded over a masked unit it could never have restarted" >&2
  exit 1
fi
grep -q "is MASKED (a symlink to /dev/null" "${workdir}/logs/mask-unit.log" || {
  echo "the masked unit was not refused by name:" >&2
  cat "${workdir}/logs/mask-unit.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused masked-unit upgrade still moved the current release" >&2
  exit 1
}
# A mask of the Quadlet-GENERATED name is the same fact about a unit this
# deployment owns and never wrote.
rm -f "${shadow_control}/mcloving-controller.service"
ln -sfn /dev/null "${shadow_control}/mcloving-postgres.service"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd > "${workdir}/logs/mask-generated.log" 2>&1; then
  echo "rollback proceeded over a masked generated unit" >&2
  exit 1
fi
grep -q "mcloving-postgres.service is MASKED" "${workdir}/logs/mask-generated.log" || {
  echo "the masked generated unit was not refused by name:" >&2
  cat "${workdir}/logs/mask-generated.log" >&2
  exit 1
}
rm -f "${shadow_control}/mcloving-postgres.service"
# A REFUSED transition must not leave the lock held. deploy_fail exits the
# main shell, but a process-substitution PRODUCER feeding the loop the
# refusal was raised from is not waited for, and inside the transition lock
# that producer still holds fd 9 -- so the very next transition reports the
# lock as held and the real diagnosis is buried. This cost a suite run when
# the mask refusals were first raised from inside such a loop; the loops
# now collect before judging. Ten back-to-back pairs, because the leak was
# intermittent before it was deterministic.
for lock_leak_round in 1 2 3 4 5 6 7 8 9 10; do
  ln -sfn /dev/null "${shadow_control}/mcloving-controller.service"
  "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
    --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
    --no-systemd > "${workdir}/logs/lock-leak-upgrade.log" 2>&1 || true
  rm -f "${shadow_control}/mcloving-controller.service"
  ln -sfn /dev/null "${shadow_control}/mcloving-postgres.service"
  "${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
    --no-systemd > "${workdir}/logs/lock-leak-rollback.log" 2>&1 || true
  rm -f "${shadow_control}/mcloving-postgres.service"
  if grep -q "another deployment transition holds the lock" \
    "${workdir}/logs/lock-leak-rollback.log"; then
    echo "round ${lock_leak_round}: a refused transition leaked the transition lock to a child; the next transition could not run:" >&2
    cat "${workdir}/logs/lock-leak-rollback.log" >&2
    exit 1
  fi
  grep -q "is MASKED" "${workdir}/logs/lock-leak-rollback.log" || {
    echo "round ${lock_leak_round}: the follow-up transition did not reach its own refusal:" >&2
    cat "${workdir}/logs/lock-leak-rollback.log" >&2
    exit 1
  }
done
# A node that is neither a regular file nor a mask is refused too: the
# resolver selects any existing candidate and then classifies, so no node
# kind is invisible.
mkfifo "${shadow_control}/mcloving-controller.service"
mask_fifo_status=0
timeout 60 "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/mask-fifo.log" 2>&1 || mask_fifo_status=$?
if [[ "${mask_fifo_status}" -eq 0 ]]; then
  echo "upgrade proceeded over a FIFO where the manager would load a unit" >&2
  exit 1
fi
if [[ "${mask_fifo_status}" -eq 124 ]]; then
  echo "unit resolution hung on a FIFO instead of refusing it" >&2
  exit 1
fi
grep -q "is not a regular file (fifo)" "${workdir}/logs/mask-fifo.log" || {
  echo "the non-regular unit node was not refused by name:" >&2
  cat "${workdir}/logs/mask-fifo.log" >&2
  exit 1
}
rm -f "${shadow_control}/mcloving-controller.service"
# Acceptance: with the mask removed the same transition proceeds.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the mask gate" >&2
  exit 1
}
# WHAT MUST EXIST, not merely what does. Every walk in this lane validates
# the files it finds; none asserted the complete set, so a DELETED helper,
# unit, contract, or live release binary passed integrity and only surfaced
# after the transition had stopped the services.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  asset_index=0
  for asset_path in \
    "${dropin_root_libexec}/helpers/mcloving-health" \
    "${dropin_root_libexec}/helpers/mcloving-deploy-lib.sh" \
    "${dropin_unit_root}/mcloving-agent.service" \
    "${dropin_root_home}/.config/containers/systemd/mcloving-postgres.container" \
    "${dropin_root_home}/.config/mcloving/agent.env" \
    "${dropin_root_libexec}/${dropin_root_current}/mcloving-cli"; do
    asset_index=$((asset_index + 1))
    [[ -f "${asset_path}" ]] || {
      echo "the asset gate expected ${asset_path} to exist; the deployment shape changed" >&2
      exit 1
    }
    mv "${asset_path}" "${asset_path}.aside"
    if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
      --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
      --no-systemd > "${workdir}/logs/missing-asset-${asset_index}.log" 2>&1; then
      mv "${asset_path}.aside" "${asset_path}"
      echo "upgrade proceeded with ${asset_path} deleted" >&2
      exit 1
    fi
    grep -q "deployment asset(s) missing:" "${workdir}/logs/missing-asset-${asset_index}.log" || {
      echo "the missing asset ${asset_path} was not refused by name:" >&2
      cat "${workdir}/logs/missing-asset-${asset_index}.log" >&2
      mv "${asset_path}.aside" "${asset_path}"
      exit 1
    }
    [[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
      echo "a refused missing-asset upgrade still moved the current release" >&2
      mv "${asset_path}.aside" "${asset_path}"
      exit 1
    }
    mv "${asset_path}.aside" "${asset_path}"
  done
  # And the manifest is the installer's own, not a second list: every helper
  # the installer installs must be one this check requires.
  for manifest_helper in "${MCLOVING_DEPLOY_HELPERS[@]}"; do
    [[ -f "${dropin_root_libexec}/helpers/${manifest_helper}" ]] || {
      echo "the installer's manifest names ${manifest_helper} but the install did not produce it" >&2
      exit 1
    }
  done
)
# Acceptance: with every asset present the transition proceeds.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the asset gate" >&2
  exit 1
}
rm -rf "${shadow_control}" "${dropin_root_home}/shadow-bin"
# The derivation itself, against systemd's own answer where the host can
# give one. `systemd-analyze --user unit-paths` is the authority; every
# path it names must be in this derivation. It is not a hard dependency of
# the suite, so its absence is stated rather than silently passing.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  # SELECTION is what systemd-analyze reports and what a main unit file is
  # resolved over; MERGE is the union used for drop-in enumeration. The two
  # are asserted separately below because confusing them is the defect this
  # round closed.
  loadpath_all=""
  while IFS= read -r encoded_loadpath; do
    [[ -n "${encoded_loadpath}" ]] || continue
    decode_path_item_into decoded_loadpath "${encoded_loadpath}"
    # shellcheck disable=SC2154 # assigned through the nameref above
    loadpath_all+="${decoded_loadpath}"$'\n'
  done < <(deployment_unit_load_paths "${HOME}" all systemd selection)
  loadpath_merge=""
  while IFS= read -r encoded_loadpath; do
    [[ -n "${encoded_loadpath}" ]] || continue
    decode_path_item_into decoded_loadpath "${encoded_loadpath}"
    loadpath_merge+="${decoded_loadpath}"$'\n'
  done < <(deployment_unit_load_paths "${HOME}" all systemd)
  # The merge list must remain a strict superset: drop-in validation must
  # not have shrunk when selection stopped unioning.
  while IFS= read -r selection_path; do
    [[ -n "${selection_path}" ]] || continue
    grep -qx "${selection_path}" <<<"${loadpath_merge}" || {
      echo "the merge load path list lost ${selection_path}, which selection still searches" >&2
      exit 1
    }
  done <<<"${loadpath_all}"
  # The XDG search lists contribute their spec defaults unconditionally,
  # and those are root-owned, so they belong to the system class.
  loadpath_system=""
  while IFS= read -r encoded_loadpath; do
    [[ -n "${encoded_loadpath}" ]] || continue
    decode_path_item_into decoded_loadpath "${encoded_loadpath}"
    loadpath_system+="${decoded_loadpath}"$'\n'
  done < <(deployment_unit_load_paths "${HOME}" system systemd)
  for expected_xdg in /etc/xdg/systemd/user /usr/local/share/systemd/user \
    /usr/share/systemd/user; do
    grep -qx "${expected_xdg}" <<<"${loadpath_system}" || {
      echo "the XDG search-list default ${expected_xdg} is missing from the system load path set" >&2
      exit 1
    }
  done
  # REPLACEMENT vs UNION, asserted where the two genuinely disagree. A
  # nonempty XDG_CONFIG_DIRS removes the /etc/xdg default from what systemd
  # searches; the merge list keeps it, because validating a directory
  # systemd would not read costs nothing for a MERGED drop-in and missing
  # one it does read is the only outcome that matters.
  xdg_probe="${dropin_root_home}/xdg-semantics"
  mkdir -p "${xdg_probe}/systemd/user"
  chmod 0755 "${xdg_probe}" "${xdg_probe}/systemd" "${xdg_probe}/systemd/user"
  selection_overridden=""
  while IFS= read -r encoded_loadpath; do
    [[ -n "${encoded_loadpath}" ]] || continue
    decode_path_item_into decoded_loadpath "${encoded_loadpath}"
    selection_overridden+="${decoded_loadpath}"$'\n'
  done < <(XDG_CONFIG_DIRS="${xdg_probe}" \
    deployment_unit_load_paths "${dropin_root_home}" all systemd selection)
  merge_overridden=""
  while IFS= read -r encoded_loadpath; do
    [[ -n "${encoded_loadpath}" ]] || continue
    decode_path_item_into decoded_loadpath "${encoded_loadpath}"
    merge_overridden+="${decoded_loadpath}"$'\n'
  done < <(XDG_CONFIG_DIRS="${xdg_probe}" \
    deployment_unit_load_paths "${dropin_root_home}" all systemd)
  grep -qx "${xdg_probe}/systemd/user" <<<"${selection_overridden}" || {
    echo "the selection list ignored a configured XDG_CONFIG_DIRS entry" >&2
    exit 1
  }
  if grep -qx /etc/xdg/systemd/user <<<"${selection_overridden}"; then
    echo "the selection list kept the /etc/xdg default while XDG_CONFIG_DIRS was set; systemd REPLACES it, so first-match could name a file systemd never loads" >&2
    exit 1
  fi
  grep -qx /etc/xdg/systemd/user <<<"${merge_overridden}" || {
    echo "the merge list dropped the /etc/xdg default; drop-in validation must stay a union" >&2
    exit 1
  }
  # Set-but-EMPTY is an empty list to systemd, not "use the default".
  selection_empty=""
  while IFS= read -r encoded_loadpath; do
    [[ -n "${encoded_loadpath}" ]] || continue
    decode_path_item_into decoded_loadpath "${encoded_loadpath}"
    selection_empty+="${decoded_loadpath}"$'\n'
  done < <(
    # An intentionally EMPTY value, not a missing one: the distinction is
    # the whole point of this assertion.
    # shellcheck disable=SC1007
    XDG_CONFIG_DIRS= HOME="${dropin_root_home}" \
      deployment_unit_load_paths "${dropin_root_home}" all systemd selection
  )
  if grep -qx /etc/xdg/systemd/user <<<"${selection_empty}"; then
    echo "an empty XDG_CONFIG_DIRS still searched the /etc/xdg default; systemd searches nothing there" >&2
    exit 1
  fi
  # The consequence, on real files: first match over each list. The real
  # spec defaults are root-owned, so this uses writable STAND-INS for the
  # default and configured positions and does the first-match itself --
  # the same loop deployment_effective_unit_file runs.
  xdg_default_standin="${dropin_root_home}/xdg-standin-default"
  xdg_configured_standin="${dropin_root_home}/xdg-standin-configured"
  mkdir -p "${xdg_default_standin}" "${xdg_configured_standin}"
  chmod 0755 "${xdg_default_standin}" "${xdg_configured_standin}"
  printf '[Service]\nExecStart=/bin/true\n' \
    > "${xdg_default_standin}/mcloving-probe.service"
  printf '[Service]\nExecStart=/bin/false\n' \
    > "${xdg_configured_standin}/mcloving-probe.service"
  first_match_over() { # SEMANTICS
    local base
    while IFS= read -r base; do
      [[ -n "${base}" ]] || continue
      if [[ -f "${base}/mcloving-probe.service" ]]; then
        printf '%s' "${base}/mcloving-probe.service"
        return 0
      fi
    done < <(deployment_xdg_search_entries "${dropin_root_home}" \
      "${xdg_configured_standin}" "${xdg_default_standin}" "$1" set)
    return 0
  }
  [[ "$(first_match_over selection)" == "${xdg_configured_standin}/mcloving-probe.service" ]] || {
    echo "selection semantics resolved to the default stand-in, not the configured entry" >&2
    exit 1
  }
  # Merge is a SET, not an order: what it must not do is lose either entry.
  # Its ordering is deliberately unasserted, because nothing resolves a
  # first match over it -- that is exactly the property this round
  # separated out.
  merge_entries="$(deployment_xdg_search_entries "${dropin_root_home}" \
    "${xdg_configured_standin}" "${xdg_default_standin}" merge set)"
  for merge_expected in "${xdg_configured_standin}" "${xdg_default_standin}"; do
    grep -qx "${merge_expected}" <<<"${merge_entries}" || {
      echo "merge semantics dropped ${merge_expected}; the union must keep both" >&2
      exit 1
    }
  done
  selection_entries="$(deployment_xdg_search_entries "${dropin_root_home}" \
    "${xdg_configured_standin}" "${xdg_default_standin}" selection set)"
  if grep -qx "${xdg_default_standin}" <<<"${selection_entries}"; then
    echo "selection semantics kept the replaced default; systemd searches only the configured list" >&2
    exit 1
  fi
  rm -rf "${xdg_probe}" "${xdg_default_standin}" "${xdg_configured_standin}"
  if command -v systemctl >/dev/null 2>&1 \
    && systemctl --user show -p UnitPath --value >/dev/null 2>&1; then
    # THE MANAGER, not systemd-analyze. `systemd-analyze --user unit-paths`
    # RECOMPUTES the list from the CALLER's environment and therefore agrees
    # with the running manager only when the two environments agree -- which
    # is precisely the assumption this round removed. `systemctl --user show
    # -p UnitPath` is the manager's own computed list. Proven by running
    # both with XDG_CONFIG_DIRS=/tmp/A in this shell: analyze reports
    # /tmp/A/systemd/user in slot 6, the manager reports /etc/xdg/systemd/user.
    #
    # ORDER as well as membership: a main unit file is resolved by first
    # match, so a list with the same paths in a different order would
    # resolve a shadow to the wrong file.
    manager_paths="$(systemctl --user show -p UnitPath --value | tr ' ' '\n')"
    # The shell's own XDG view must not move the answer any more.
    shell_perturbed="$(XDG_CONFIG_DIRS=/tmp/mcloving-parity-probe \
      systemctl --user show -p UnitPath --value | tr ' ' '\n')"
    [[ "${manager_paths}" == "${shell_perturbed}" ]] || {
      echo "the manager's UnitPath moved when this shell's XDG_CONFIG_DIRS changed; it is not the manager's own list after all" >&2
      exit 1
    }
    loadpath_manager=""
    while IFS= read -r encoded_loadpath; do
      [[ -n "${encoded_loadpath}" ]] || continue
      decode_path_item_into decoded_loadpath "${encoded_loadpath}"
      loadpath_manager+="${decoded_loadpath}"$'\n'
    done < <(XDG_CONFIG_DIRS=/tmp/mcloving-parity-probe \
      deployment_unit_load_paths "${HOME}" all systemd selection)
    [[ "${manager_paths}" == "${loadpath_manager%$'\n'}" ]] || {
      echo "with a perturbed shell XDG_CONFIG_DIRS the derivation did not return the MANAGER's list:" >&2
      diff <(printf '%s\n' "${manager_paths}") <(printf '%s' "${loadpath_manager}") >&2 || true
      exit 1
    }
    [[ "$(deployment_unit_path_source "${HOME}")" == "manager" ]] || {
      echo "the unit path source is not reported as authoritative where the manager answers" >&2
      exit 1
    }
    [[ "$(deployment_unit_path_source "${dropin_root_home}")" == "derived" ]] || {
      echo "a home the running manager does not serve was reported as manager-backed" >&2
      exit 1
    }
    while IFS= read -r manager_path; do
      [[ -n "${manager_path}" ]] || continue
      grep -qx "${manager_path}" <<<"${loadpath_all}" || {
        echo "systemd searches ${manager_path} for user units and this derivation does not enumerate it" >&2
        exit 1
      }
    done <<<"${manager_paths}"
    [[ "${manager_paths}" == "${loadpath_all%$'\n'}" ]] || {
      echo "the load path order does not match the manager's:" >&2
      diff <(printf '%s\n' "${manager_paths}") <(printf '%s' "${loadpath_all}") >&2 || true
      exit 1
    }
  else
    echo "load-path parity against the running manager skipped: no reachable systemctl --user on this host; the derivation fallback is what runs here"
  fi
)
# System drop-in TREES must feed the shared chain collector like every
# other root the document walks. Their trees were recorded while their
# ancestors were not, so relaxing /etc/systemd/user left every emitted
# system_dropins record byte-identical. Driven through the payload
# directly -- the only way to present a system-path tree without root --
# exactly as the digest race drivers do.
sysdrop_tree="${workdir}/fake-system-dropin/service.d"
sysdrop_link_target="${workdir}/fake-system-link-target"
rm -rf "${workdir}/fake-system-dropin" "${sysdrop_link_target}"
mkdir -p "${sysdrop_tree}" "${sysdrop_link_target}/nested"
printf '[Service]\nRestart=always\n' > "${sysdrop_tree}/zz.conf"
printf '[Service]\nRestart=no\n' > "${sysdrop_link_target}/nested/linked.conf"
ln -s "${sysdrop_link_target}/nested/linked.conf" "${sysdrop_tree}/linked.conf"
sysdrop_dirs_env="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  encode_path_item "${sysdrop_tree}"
)"
sysdrop_ancestors="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  deployment_ancestor_chain "${home}" \
    "${libexec}/releases" "${libexec}/helpers" \
    "${smoke_unit_root}" "${smoke_quadlet_root}" \
    "${home}/.config/mcloving" "${home}/.config/mcloving/pki"
)"
MCLOVING_ANCESTOR_DIRS="${sysdrop_ancestors}" \
MCLOVING_DEPLOY_LIB="${libexec}/helpers/mcloving-deploy-lib.sh" \
MCLOVING_UNIT_DIRS="${smoke_unit_dirs_env}" \
MCLOVING_UNIT_DROPIN_DIRS="${sysdrop_dirs_env}" \
MCLOVING_UNIT_SYSTEM_DROPIN_DIRS="${sysdrop_dirs_env}" \
MCLOVING_SHADOWING_UNITS="${race_shadowing_units}" \
python3 - "${libexec}/helpers/mcloving-deployed-digests" "${home}" \
  > "${workdir}/system-dropin-digests.json" <<'SYSCHAIN'
import sys

helper, home = sys.argv[1], sys.argv[2]
source = open(helper, encoding="utf-8").read()
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
sys.argv = [helper, home]
exec(compile(payload, helper, "exec"), {"__name__": "__main__"})
SYSCHAIN
python3 - "${workdir}/system-dropin-digests.json" "${sysdrop_tree}" \
  "${sysdrop_link_target}" <<'SYSCHECK'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text())
tree, link_target = sys.argv[2], sys.argv[3]
# The ancestor list is RECORDS, not bare strings, and a path outside the
# home carries its absolute spelling (file_record's own rule).
ancestors = {record["path"] for record in document.get("ancestors", [])}
recorded = {record["path"] for record in document.get("system_dropins", [])}
if not any(entry.endswith("zz.conf") for entry in recorded):
    raise SystemExit(f"the system drop-in tree was not recorded at all: {sorted(recorded)}")
# The tree's OWN chain: without it, relaxing the directory that holds the
# active drop-in leaves the document byte-identical.
if tree not in ancestors:
    raise SystemExit(
        f"the system drop-in tree {tree} never reached the ancestor collector; "
        "relaxing it would not change the canonical document"
    )
if str(pathlib.PurePosixPath(tree).parent) not in ancestors:
    raise SystemExit(f"the system drop-in tree's parent is missing from the chain")
# And the chain of what a symlinked .conf inside it points at.
if f"{link_target}/nested" not in ancestors:
    raise SystemExit(
        f"a symlinked .conf inside the system drop-in tree did not contribute "
        f"its target's chain; {link_target}/nested is absent"
    )
SYSCHECK
rm -rf "${workdir}/fake-system-dropin" "${sysdrop_link_target}" \
  "${workdir}/system-dropin-digests.json"
# Quadlet GENERATES a service; systemd applies drop-ins to the GENERATED
# name, which discovery seeded from the source basenames never saw. The
# mapping is verified against podman's own generator in the probe below.
generated_service_dropin="${dropin_unit_root}/mcloving-postgres.service.d"
generated_volume_dropin="${dropin_unit_root}/mcloving-postgres-data-volume.service.d"
mkdir -p "${generated_service_dropin}" "${generated_volume_dropin}"
chmod 0755 "${generated_service_dropin}" "${generated_volume_dropin}"
# (1) .container -> <base>.service
printf '[Service]\nRestart=always\n' > "${generated_service_dropin}/override.conf"
chmod 0666 "${generated_service_dropin}/override.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/generated-service.log" 2>&1; then
  echo "upgrade proceeded over a world-writable drop-in for the generated postgres service" >&2
  exit 1
fi
grep -q "mcloving-postgres.service.d/override.conf (mode 666)" \
  "${workdir}/logs/generated-service.log" || {
  echo "the generated service's drop-in was not judged:" >&2
  cat "${workdir}/logs/generated-service.log" >&2
  exit 1
}
chmod 0644 "${generated_service_dropin}/override.conf"
# (2) .volume -> <base>-volume.service, the suffixed mapping, proven
# through a path only that name's drop-in declares.
mkdir -p "${dropin_root_home}/generated-shared"
printf 'MCLOVING_GENERATED=1\n' > "${dropin_root_home}/generated-shared/generated.env"
chmod 0600 "${dropin_root_home}/generated-shared/generated.env"
chmod 0777 "${dropin_root_home}/generated-shared"
printf '[Service]\nEnvironmentFile=%%h/generated-shared/generated.env\n' \
  > "${generated_volume_dropin}/override.conf"
chmod 0644 "${generated_volume_dropin}/override.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/generated-volume.log" 2>&1; then
  echo "upgrade proceeded over a contract declared only by the generated volume service's drop-in" >&2
  exit 1
fi
grep -q "generated-shared (mode 777)" "${workdir}/logs/generated-volume.log" || {
  echo "the generated volume service's drop-in escaped the parser:" >&2
  cat "${workdir}/logs/generated-volume.log" >&2
  exit 1
}
chmod 0755 "${dropin_root_home}/generated-shared"
# (3) Acceptance.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" != "${dropin_root_current}" ]] || {
  echo "the secured generated-service drop-ins did not admit the transition" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the generated-name gate" >&2
  exit 1
}
# The canonical document sees the generated service's drop-in too.
generated_digests_before="$("${dropin_root_libexec}/helpers/mcloving-deployed-digests" --home "${dropin_root_home}")"
printf '[Service]\nRestart=no\n' > "${generated_service_dropin}/override.conf"
chmod 0644 "${generated_service_dropin}/override.conf"
generated_digests_after="$("${dropin_root_libexec}/helpers/mcloving-deployed-digests" --home "${dropin_root_home}")"
[[ "${generated_digests_before}" != "${generated_digests_after}" ]] || {
  echo "editing the generated service's drop-in left the canonical document unchanged" >&2
  exit 1
}
grep -q 'mcloving-postgres.service.d/override.conf' <<<"${generated_digests_after}" || {
  echo "the canonical document does not record the generated service's drop-in" >&2
  exit 1
}
# The document reflects the system-path reality too, even when empty: an
# absent key would be indistinguishable from a host that has no overrides.
printf '%s' "${generated_digests_after}" > "${workdir}/generated-digests.json"
python3 - "${workdir}/generated-digests.json" <<'SYSDROP'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text())
if "system_dropins" not in document:
    raise SystemExit(
        "the canonical document has no system_dropins key; a root-owned "
        "load-path override would be invisible drift"
    )
if not isinstance(document["system_dropins"], list):
    raise SystemExit("system_dropins is not a list")
SYSDROP
rm -rf "${generated_service_dropin}" "${generated_volume_dropin}" \
  "${dropin_root_home}/generated-shared"
# Exactness of the two new enumerations, against the generator and the
# documented load path table rather than against assumption.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  # Quadlet's generated names. .container and .kube keep the base name;
  # every other source type appends its own type. Verified against
  # /usr/libexec/podman/quadlet's actual output for .container, .volume,
  # .network and .image.
  while IFS='|' read -r quadlet_source quadlet_expected; do
    [[ -n "${quadlet_source}" ]] || continue
    quadlet_actual="$(deployment_quadlet_generated_name "${quadlet_source}")"
    [[ "${quadlet_actual}" == "${quadlet_expected}" ]] || {
      echo "quadlet name mapping: ${quadlet_source} -> ${quadlet_actual}, expected ${quadlet_expected}" >&2
      exit 1
    }
  done <<'QUADLETNAMES'
mcloving-postgres.container|mcloving-postgres.service
mcloving-postgres-data.volume|mcloving-postgres-data-volume.service
mcloving-net.network|mcloving-net-network.service
mcloving-img.image|mcloving-img-image.service
mcloving-bld.build|mcloving-bld-build.service
mcloving-grp.pod|mcloving-grp-pod.service
mcloving-k8s.kube|mcloving-k8s.service
mcloving-controller.service|
QUADLETNAMES
  # The load path table, classified. The user-writable entries are the ones
  # this round closed; the system entries are validated and reported, never
  # silently skipped, and the two classes must not overlap.
  loadpath_user=""
  while IFS= read -r encoded_loadpath; do
    [[ -n "${encoded_loadpath}" ]] || continue
    decode_path_item_into decoded_loadpath "${encoded_loadpath}"
    # shellcheck disable=SC2154 # assigned through the nameref above
    loadpath_user+="${decoded_loadpath}"$'\n'
  done < <(deployment_unit_load_paths "${dropin_root_home}" user systemd)
  loadpath_system=""
  while IFS= read -r encoded_loadpath; do
    [[ -n "${encoded_loadpath}" ]] || continue
    decode_path_item_into decoded_loadpath "${encoded_loadpath}"
    loadpath_system+="${decoded_loadpath}"$'\n'
  done < <(deployment_unit_load_paths "${dropin_root_home}" system systemd)
  for expected_user in "${dropin_root_home}/.config/systemd/user" \
    "${dropin_root_home}/.local/share/systemd/user"; do
    grep -qx "${expected_user}" <<<"${loadpath_user}" || {
      echo "the user-writable load path set is missing ${expected_user}: ${loadpath_user}" >&2
      exit 1
    }
  done
  for expected_system in /etc/systemd/user /run/systemd/user /usr/lib/systemd/user; do
    grep -qx "${expected_system}" <<<"${loadpath_system}" || {
      echo "the system load path set is missing ${expected_system}: ${loadpath_system}" >&2
      exit 1
    }
    if grep -qx "${expected_system}" <<<"${loadpath_user}"; then
      echo "${expected_system} is classified user-writable; the classes must not overlap" >&2
      exit 1
    fi
  done
  # A deployment whose only drop-ins are its own must report NO system-path
  # drop-ins: a classifier that called everything "system" would make the
  # notice above meaningless noise.
  system_found="$(deployment_unit_dropin_dirs "${dropin_root_home}" --system \
    "${dropin_unit_root}"/mcloving-*.service \
    "${dropin_root_home}/.config/containers/systemd"/mcloving-*.container \
    "${dropin_root_home}/.config/containers/systemd"/mcloving-*.volume)"
  [[ -z "${system_found}" ]] || {
    echo "a deployment-owned drop-in was classified as a system-path drop-in" >&2
    exit 1
  }
)
# Exec* directives name the executables the transition RUNS, and an
# override resetting one to an external path was emitted by no
# enumeration: the drop-in source was judged, found fine, and the unit was
# then restarted into a binary whose mode, owner, and ancestor chain
# nothing had validated.
exec_dropin_dir="${dropin_unit_root}/mcloving-controller.service.d"
mkdir -p "${exec_dropin_dir}"
exec_tool_dir="${dropin_root_home}/external-tools"
mkdir -p "${exec_tool_dir}"
printf '#!/bin/sh\nexit 0\n' > "${exec_tool_dir}/tool"
chmod 0755 "${exec_tool_dir}/tool"
printf '[Service]\nExecStart=\nExecStart=%%h/external-tools/tool --serve\n' \
  > "${exec_dropin_dir}/exec.conf"
chmod 0644 "${exec_dropin_dir}/exec.conf"
# (1) The executable's ANCESTOR CHAIN. A world-writable directory holding
# the command is a substitution between validation and restart.
chmod 0777 "${exec_tool_dir}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/exec-chain.log" 2>&1; then
  echo "upgrade proceeded over an ExecStart executable in a world-writable directory" >&2
  exit 1
fi
grep -q "external-tools (mode 777)" "${workdir}/logs/exec-chain.log" || {
  echo "the ExecStart executable's chain was not walked:" >&2
  cat "${workdir}/logs/exec-chain.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused ExecStart-chain upgrade still moved the current release" >&2
  exit 1
}
# (2) The executable's own FILE rule, with the directory left secure -- so
# the refusal comes from the file and not from its parent.
chmod 0755 "${exec_tool_dir}"
chmod 0666 "${exec_tool_dir}/tool"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/exec-file.log" 2>&1; then
  echo "upgrade proceeded over a world-writable ExecStart executable" >&2
  exit 1
fi
grep -q "tool (mode 666)" "${workdir}/logs/exec-file.log" || {
  echo "the ExecStart executable was not judged by the trust-input rule:" >&2
  cat "${workdir}/logs/exec-file.log" >&2
  exit 1
}
# (3) systemd's command prefixes are stripped before the executable is
# taken, and the whole Exec* family is covered -- not just ExecStart.
printf '[Service]\nExecStartPre=-@%%h/external-tools/tool argv0\n' \
  > "${exec_dropin_dir}/exec.conf"
chmod 0644 "${exec_dropin_dir}/exec.conf"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd > "${workdir}/logs/exec-prefix.log" 2>&1; then
  echo "rollback proceeded over a prefixed ExecStartPre naming a writable executable" >&2
  exit 1
fi
grep -q "tool (mode 666)" "${workdir}/logs/exec-prefix.log" || {
  echo "the prefixed ExecStartPre spelling escaped extraction:" >&2
  cat "${workdir}/logs/exec-prefix.log" >&2
  exit 1
}
chmod 0755 "${exec_tool_dir}/tool"
# (4) An EMPTY assignment is systemd's legal reset and declares nothing --
# it must not be mistaken for a command, and it must not refuse.
printf '[Service]\nExecStartPost=\n' > "${exec_dropin_dir}/exec.conf"
chmod 0644 "${exec_dropin_dir}/exec.conf"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null || {
  echo "an empty Exec* reset was treated as a declaration" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
# (5) Acceptance: a SECURED external executable admits the transition. The
# refusals above are what prove the extraction happened, so this only
# proves the rule is not over-broad.
printf '[Service]\nExecStart=\nExecStart=%%h/external-tools/tool --serve\n' \
  > "${exec_dropin_dir}/exec.conf"
chmod 0644 "${exec_dropin_dir}/exec.conf"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" != "${dropin_root_current}" ]] || {
  echo "the secured external ExecStart did not admit the transition" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the Exec gate" >&2
  exit 1
}
# (6) The class-closing half: a command spelling this parser cannot
# confidently reduce to one executable is a NAMED refusal, never a quiet
# skip -- a skipped Exec* is exactly an execution vector outside the walk.
exec_refusal_index=0
while IFS='|' read -r exec_spelling exec_expect; do
  [[ -n "${exec_spelling}" ]] || continue
  exec_refusal_index=$((exec_refusal_index + 1))
  printf '[Service]\n%s\n' "${exec_spelling}" > "${exec_dropin_dir}/exec.conf"
  chmod 0644 "${exec_dropin_dir}/exec.conf"
  if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
    --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
    --no-systemd > "${workdir}/logs/exec-unparseable-${exec_refusal_index}.log" 2>&1; then
    echo "upgrade accepted an Exec* spelling the parser cannot model: ${exec_spelling}" >&2
    exit 1
  fi
  grep -q "${exec_expect}" "${workdir}/logs/exec-unparseable-${exec_refusal_index}.log" || {
    echo "the unparseable Exec* spelling was refused for the wrong reason (${exec_spelling}):" >&2
    cat "${workdir}/logs/exec-unparseable-${exec_refusal_index}.log" >&2
    exit 1
  }
  [[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
    echo "a refused unparseable-Exec upgrade still moved the current release" >&2
    exit 1
  }
done <<'EXECSPELLINGS'
ExecStart="/external tools/tool"|with a QUOTED executable
ExecStart=%t/tool|unit specifier other than a leading %h in its executable
ExecStart=tool --serve|with a non-absolute executable
ExecStart=-|with command prefixes but no executable
ExecStart=/opt/my\ tool|with a backslash escape in its executable
EnvironmentFile=/srv/secure/evil\x2eenv|with a backslash escape in its value
EnvironmentFile=%t/extra.env|unit specifier other than %h in its value
EXECSPELLINGS
rm -f "${exec_dropin_dir}/exec.conf"
rm -rf "${exec_tool_dir}"
# A SCRIPT PASSED TO AN INTERPRETER is executed as surely as the interpreter.
# Round 29 validated only the first token, so ExecStartPre=/bin/sh
# %h/hook-dir/hook.sh left both the script and its directory unjudged. Which
# arguments are files is undecidable in general, so the extractor
# over-validates instead: every absolute argument that EXISTS as a regular
# file takes the trust-input rule and the ancestor walk.
exec_hook_dir="${dropin_root_home}/hook-dir"
exec_hook_dropin="${dropin_unit_root}/mcloving-controller.service.d"
mkdir -p "${exec_hook_dir}" "${exec_hook_dropin}"
chmod 0755 "${exec_hook_dir}" "${exec_hook_dropin}"
printf '#!/bin/sh\nexit 0\n' > "${exec_hook_dir}/hook.sh"
chmod 0755 "${exec_hook_dir}/hook.sh"
printf '[Service]\nExecStartPre=/bin/sh %%h/hook-dir/hook.sh\n' \
  > "${exec_hook_dropin}/hook.conf"
chmod 0644 "${exec_hook_dropin}/hook.conf"
# (1) The script's own file rule.
chmod 0666 "${exec_hook_dir}/hook.sh"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/exec-arg-file.log" 2>&1; then
  echo "upgrade proceeded over a world-writable script passed to an interpreter" >&2
  exit 1
fi
grep -q "hook-dir/hook.sh (mode 666)" "${workdir}/logs/exec-arg-file.log" || {
  echo "the interpreter's script argument was not judged:" >&2
  cat "${workdir}/logs/exec-arg-file.log" >&2
  exit 1
}
chmod 0755 "${exec_hook_dir}/hook.sh"
# (2) The directory holding it, with the script itself secure -- proving the
# argument reached the ancestor walk and not only the file rule.
chmod 0777 "${exec_hook_dir}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/exec-arg-chain.log" 2>&1; then
  echo "upgrade proceeded over an interpreter script in a world-writable directory" >&2
  exit 1
fi
grep -q "hook-dir (mode 777)" "${workdir}/logs/exec-arg-chain.log" || {
  echo "the interpreter script's directory was not walked:" >&2
  cat "${workdir}/logs/exec-arg-chain.log" >&2
  exit 1
}
chmod 0755 "${exec_hook_dir}"
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused exec-argument upgrade still moved the current release" >&2
  exit 1
}
# (3) Acceptance, and the policy boundaries. A path-shaped argument that
# does not exist, one that is a directory, and a relative one are all
# ignored -- systemd passes them as strings and walking every path-shaped
# argument would refuse transitions over trees nothing reads.
printf '[Service]\nExecStartPre=/bin/sh %%h/hook-dir/hook.sh %%h/hook-dir/absent.sh %%h/hook-dir relative/thing\n' \
  > "${exec_hook_dropin}/hook.conf"
chmod 0644 "${exec_hook_dropin}/hook.conf"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the exec-argument gate" >&2
  exit 1
}
# The tokenizer is systemd's, not a whitespace split: a QUOTED path argument
# is exactly where a file hides, and a naive split would miss it.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  arg_seen=""
  while IFS= read -r encoded_arg; do
    [[ -n "${encoded_arg}" ]] || continue
    decode_path_item_into decoded_arg "${encoded_arg}"
    # shellcheck disable=SC2154 # assigned through the nameref above
    arg_seen+="${decoded_arg}"$'\n'
  done < <(deployment_exec_argument_paths "${dropin_root_home}" \
    "/bin/sh --msg=\"hello world\" \"${exec_hook_dir}/hook.sh\"")
  grep -qx "${exec_hook_dir}/hook.sh" <<<"${arg_seen}" || {
    echo "a quoted path argument escaped the command-line tokenizer: ${arg_seen}" >&2
    exit 1
  }
  for ignored_arg in "${exec_hook_dir}/absent.sh" "${exec_hook_dir}" "relative/thing"; do
    if grep -qx "${ignored_arg}" <<<"${arg_seen}"; then
      echo "the argument extractor claimed ${ignored_arg}, which the stated policy ignores" >&2
      exit 1
    fi
  done
)
rm -rf "${exec_hook_dir}" "${exec_hook_dropin}/hook.conf"
# AN ABSENT ARGUMENT STILL HAS A CREATION BOUND. Round 37 ignored absolute
# arguments that do not exist; round 28 had already settled that absence
# means "bound who may create it", not "ignore" -- a wildcard match does not
# exist at validation time either. A user who can write the directory
# creates the script after validation and the interpreter executes it
# during the restart.
absent_hook_dir="${dropin_root_home}/absent-hook"
absent_hook_dropin="${dropin_unit_root}/mcloving-controller.service.d"
mkdir -p "${absent_hook_dir}" "${absent_hook_dropin}"
chmod 0755 "${absent_hook_dir}" "${absent_hook_dropin}"
printf '[Service]\nExecStartPre=/bin/sh %%h/absent-hook/hook.sh\n' \
  > "${absent_hook_dropin}/absent.conf"
chmod 0644 "${absent_hook_dropin}/absent.conf"
[[ ! -e "${absent_hook_dir}/hook.sh" ]] || {
  echo "the absent-argument gate expected no script to exist" >&2
  exit 1
}
chmod 0777 "${absent_hook_dir}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/absent-arg-chain.log" 2>&1; then
  echo "upgrade proceeded although anyone could create the script the interpreter will run" >&2
  exit 1
fi
grep -q "absent-hook (mode 777)" "${workdir}/logs/absent-arg-chain.log" || {
  echo "the absent argument's directory was not walked:" >&2
  cat "${workdir}/logs/absent-arg-chain.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused absent-argument upgrade still moved the current release" >&2
  exit 1
}
# Acceptance: the same absent argument under a secured directory admits the
# transition -- the bound is on WHO MAY CREATE, not on absence itself.
chmod 0755 "${absent_hook_dir}"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the absent-argument gate" >&2
  exit 1
}
# The policy boundaries, asserted directly: an absent bare absolute argument
# IS emitted (creation bound), an existing directory is not (it has an owner
# already), and a flag form is not (it is one token that does not start with
# "/", which is what keeps this from sweeping in every option value).
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  absent_seen=""
  while IFS= read -r encoded_absent; do
    [[ -n "${encoded_absent}" ]] || continue
    decode_path_item_into decoded_absent "${encoded_absent}"
    # shellcheck disable=SC2154 # assigned through the nameref above
    absent_seen+="${decoded_absent}"$'\n'
  done < <(deployment_exec_argument_paths "${dropin_root_home}" \
    "/bin/sh ${absent_hook_dir}/hook.sh ${absent_hook_dir} --out=${absent_hook_dir}/other.sh")
  grep -qx "${absent_hook_dir}/hook.sh" <<<"${absent_seen}" || {
    echo "an absent absolute argument lost its creation bound: ${absent_seen}" >&2
    exit 1
  }
  for ignored_absent in "${absent_hook_dir}" "--out=${absent_hook_dir}/other.sh"; do
    if grep -qx "${ignored_absent}" <<<"${absent_seen}"; then
      echo "the argument extractor claimed ${ignored_absent}, which the stated policy ignores" >&2
      exit 1
    fi
  done
)
rm -rf "${absent_hook_dir}" "${absent_hook_dropin}/absent.conf"
# EXECUTION HOOKS. A shell, language runtime, or the dynamic loader acts on
# these automatically at process start -- BASH_ENV is sourced before the
# first line of a script, an LD_PRELOAD constructor runs before main() --
# so an attacker never has to touch a classified variable. The defence is
# in three layers and each gate below names which layer it exercises.
#
# LAYER 1, validation time: a DECLARATION is refused, in a contract or in a
# unit Environment= directive. This is the layer that works, because it runs
# before the unit is ever started.
hook_env_file="${dropin_root_home}/.config/mcloving/agent.env"
cp "${hook_env_file}" "${workdir}/hook-agent.env.orig"
printf 'BASH_ENV=%%h/hook-payload.sh\n' >> "${hook_env_file}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/hook-contract.log" 2>&1; then
  echo "upgrade proceeded over a contract declaring BASH_ENV" >&2
  exit 1
fi
grep -q "contract(s) declare variable(s) this deployment does not recognise: BASH_ENV in" \
  "${workdir}/logs/hook-contract.log" || {
  echo "the declared execution hook was not refused by name:" >&2
  cat "${workdir}/logs/hook-contract.log" >&2
  exit 1
}
cp "${workdir}/hook-agent.env.orig" "${hook_env_file}"
chmod 0600 "${hook_env_file}"
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused execution-hook upgrade still moved the current release" >&2
  exit 1
}
# A drop-in Environment= reaches the service without passing through any
# contract file, so it is refused on its own path.
hook_dropin_dir="${dropin_unit_root}/mcloving-controller.service.d"
mkdir -p "${hook_dropin_dir}"
chmod 0755 "${hook_dropin_dir}"
printf '[Service]\nEnvironment=LD_PRELOAD=%%h/hook-payload.so\n' \
  > "${hook_dropin_dir}/hook.conf"
chmod 0644 "${hook_dropin_dir}/hook.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/hook-dropin.log" 2>&1; then
  echo "upgrade proceeded over a drop-in setting LD_PRELOAD" >&2
  exit 1
fi
grep -q "unit Environment= directive(s) set variable(s) this deployment does not recognise: LD_PRELOAD" \
  "${workdir}/logs/hook-dropin.log" || {
  echo "the drop-in execution hook was not refused by name:" >&2
  cat "${workdir}/logs/hook-dropin.log" >&2
  exit 1
}
rm -f "${hook_dropin_dir}/hook.conf"
# LAYER 2, the unit level: UnsetEnvironment= is the ONLY thing that can
# protect the pre-start guard itself, since the hook runs before the guard's
# first line. Deleting it must therefore be refused -- validate what must
# exist, not merely what does.
cp "${dropin_unit_root}/mcloving-agent.service" "${workdir}/hook-agent.unit.orig"
grep -v '^UnsetEnvironment=' "${workdir}/hook-agent.unit.orig" \
  > "${dropin_unit_root}/mcloving-agent.service"
chmod 0644 "${dropin_unit_root}/mcloving-agent.service"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/hook-unstripped.log" 2>&1; then
  echo "upgrade proceeded over a unit that no longer strips execution hooks" >&2
  exit 1
fi
grep -q "unit(s) no longer strip execution-hook variables:" \
  "${workdir}/logs/hook-unstripped.log" || {
  echo "the missing UnsetEnvironment= was not refused by name:" >&2
  cat "${workdir}/logs/hook-unstripped.log" >&2
  exit 1
}
cp "${workdir}/hook-agent.unit.orig" "${dropin_unit_root}/mcloving-agent.service"
chmod 0644 "${dropin_unit_root}/mcloving-agent.service"
# EVERY shipped unit strips EVERY hook variable -- derived from the
# denylist, so adding a variable to it without adding it to the units fails
# here rather than shipping a gap.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  for hook_unit in "${MCLOVING_DEPLOY_UNITS[@]}"; do
    hook_unit_path="${dropin_unit_root}/${hook_unit}"
    for hook_var in "${MCLOVING_EXECUTION_HOOK_VARIABLES[@]}"; do
      grep -q "^UnsetEnvironment=.*\b${hook_var}\b" "${hook_unit_path}" || {
        echo "${hook_unit} does not strip ${hook_var}" >&2
        exit 1
      }
    done
  done
  for hook_unit in "${MCLOVING_DEPLOY_QUADLETS[@]}"; do
    hook_unit_path="${dropin_root_home}/.config/containers/systemd/${hook_unit}"
    for hook_var in "${MCLOVING_EXECUTION_HOOK_VARIABLES[@]}"; do
      grep -q "^UnsetEnvironment=.*\b${hook_var}\b" "${hook_unit_path}" || {
        echo "${hook_unit} does not strip ${hook_var}" >&2
        exit 1
      }
    done
  done
)
# LAYER 3, the guard: it cannot protect ITSELF -- the hook has already run
# by the time its first line executes -- but it can refuse to let one reach
# the SERVICE BINARY that starts after it.
if ( set -a
     # shellcheck disable=SC1090,SC1091
     . "${config}/agent.env"
     set +a
     export LD_PRELOAD="${home}/hook-payload.so"
     INVOCATION_ID=mcloving-smoke bash -c 'SYSTEMD_EXEC_PID=$$ exec "$0" "$@"' \
       "${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" \
     ) > "${workdir}/logs/hook-guard.log" 2>&1; then
  echo "the guard admitted an execution hook that would reach the service binary" >&2
  exit 1
fi
grep -q "execution-hook variable(s) reach this service: LD_PRELOAD=" \
  "${workdir}/logs/hook-guard.log" || {
  echo "the guard did not name the execution hook:" >&2
  cat "${workdir}/logs/hook-guard.log" >&2
  exit 1
}
# Acceptance: with no hook anywhere, the transition proceeds.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the execution-hook gate" >&2
  exit 1
}
rm -f "${workdir}/hook-agent.env.orig" "${workdir}/hook-agent.unit.orig"
# DEFAULT-DENY FOR DECLARATIONS. PYTHONUSERBASE proved a denylist cannot be
# relied on for completeness -- it satisfies the round-39 criterion exactly
# and was simply not enumerated -- so declarations are now judged by an
# allowlist, which is enumeration-INDEPENDENT: a hook nobody has heard of is
# refused for not being on the list rather than for being on another one.
allow_env_file="${dropin_root_home}/.config/mcloving/agent.env"
cp "${allow_env_file}" "${workdir}/allow-agent.env.orig"
# (1) The named successor from this round.
printf 'PYTHONUSERBASE=%%h/attacker-tree\n' >> "${allow_env_file}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/allow-pythonuserbase.log" 2>&1; then
  echo "upgrade proceeded over a contract declaring PYTHONUSERBASE" >&2
  exit 1
fi
grep -q "PYTHONUSERBASE in ${allow_env_file}" \
  "${workdir}/logs/allow-pythonuserbase.log" || {
  echo "PYTHONUSERBASE was not refused by name:" >&2
  cat "${workdir}/logs/allow-pythonuserbase.log" >&2
  exit 1
}
cp "${workdir}/allow-agent.env.orig" "${allow_env_file}"
chmod 0600 "${allow_env_file}"
# (2) The point of the inversion: a variable NOBODY has enumerated is
# refused too. If this ever starts passing, the rule has silently reverted
# to a denylist.
printf 'SOME_FUTURE_RUNTIME_HOOK=%%h/attacker-tree\n' >> "${allow_env_file}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/allow-unknown.log" 2>&1; then
  echo "upgrade proceeded over a contract declaring an unrecognised variable; the rule is no longer default-deny" >&2
  exit 1
fi
grep -q "SOME_FUTURE_RUNTIME_HOOK in ${allow_env_file}" \
  "${workdir}/logs/allow-unknown.log" || {
  echo "the unrecognised variable was not refused by name:" >&2
  cat "${workdir}/logs/allow-unknown.log" >&2
  exit 1
}
cp "${workdir}/allow-agent.env.orig" "${allow_env_file}"
chmod 0600 "${allow_env_file}"
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused default-deny upgrade still moved the current release" >&2
  exit 1
}
# (3) The allowlist is DERIVED, not hand-maintained: the foreign names it
# permits must be exactly the non-MCLOVING keys of the shipped example
# contracts, or it has drifted from what the deployment actually ships.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  shipped_foreign="$(grep -hoE '^[A-Za-z_][A-Za-z0-9_]*=' "${repo_root}"/deploy/env/*.env.example \
    | tr -d '=' | grep -v '^MCLOVING_' | sort -u)"
  declared_foreign="$(printf '%s\n' "${MCLOVING_CONTRACT_FOREIGN_VARIABLES[@]}" | sort -u)"
  [[ "${shipped_foreign}" == "${declared_foreign}" ]] || {
    echo "the contract allowlist has drifted from the shipped example contracts:" >&2
    diff <(printf '%s\n' "${shipped_foreign}") <(printf '%s\n' "${declared_foreign}") >&2 || true
    exit 1
  }
  [[ -n "${shipped_foreign}" ]] || {
    echo "the allowlist gate found no foreign keys at all; the sweep went blind" >&2
    exit 1
  }
)
# THE EFFECTIVE UnsetEnvironment=, not the declared base. An applicable
# drop-in with an EMPTY assignment RESETS the list the shipped unit
# declares, and the base file still reads correctly while the stripping is
# gone -- rounds 30 and 32's lesson landing on the safety net itself.
reset_dropin_dir="${dropin_unit_root}/mcloving-agent.service.d"
mkdir -p "${reset_dropin_dir}"
chmod 0755 "${reset_dropin_dir}"
printf '[Service]\nUnsetEnvironment=\n' > "${reset_dropin_dir}/reset.conf"
chmod 0644 "${reset_dropin_dir}/reset.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/unset-reset.log" 2>&1; then
  echo "upgrade proceeded over a drop-in that reset the execution-hook stripping" >&2
  exit 1
fi
grep -q "reset the execution-hook stripping with an empty UnsetEnvironment=" \
  "${workdir}/logs/unset-reset.log" || {
  echo "the UnsetEnvironment= reset was not refused by name:" >&2
  cat "${workdir}/logs/unset-reset.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused UnsetEnvironment-reset upgrade still moved the current release" >&2
  exit 1
}
rm -f "${reset_dropin_dir}/reset.conf"
# Acceptance: with no reset and nothing unrecognised declared, the
# transition proceeds.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the default-deny gate" >&2
  exit 1
}
rm -f "${workdir}/allow-agent.env.orig"
# CHILD SANITIZATION. The unit cannot be given a clean environment (round
# 40), but a child THIS LANE spawns can: its environment is ours to build
# rather than to subtract from. Every interpreter the lane invokes therefore
# gets `env -i` plus exactly what that invocation needs, which is
# enumeration-independent -- PYTHONHOME, PYTHONUSERBASE, PYTHONPATH and
# whatever Python ships next are absent because nothing is inherited, not
# because each was named.
poison_root="${workdir}/python-poison"
poison_py="$(python3 -c 'import sys; print("python%d.%d" % sys.version_info[:2])')"
rm -rf "${poison_root}"
mkdir -p "${poison_root}/lib/${poison_py}/encodings" \
  "${poison_root}/lib/${poison_py}/site-packages"
printf 'raise SystemExit("poisoned interpreter executed")\n' \
  > "${poison_root}/lib/${poison_py}/site-packages/usercustomize.py"
# (1) End to end: a transition must complete with the whole PYTHON* family
# pointing at an attacker tree. Under the pre-fix library the interpreter
# dies loading encodings from there before any payload runs.
PYTHONHOME="${poison_root}" PYTHONUSERBASE="${poison_root}" \
  PYTHONPATH="${poison_root}" PYTHONSTARTUP="${poison_root}/start.py" \
  "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/poisoned-upgrade.log" 2>&1 || {
  echo "a transition could not complete with a poisoned Python environment; its interpreter children are not sanitized:" >&2
  cat "${workdir}/logs/poisoned-upgrade.log" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the poisoned-environment gate" >&2
  exit 1
}
# (2) What the child actually receives. Nothing inherited, and only the
# variables the wrapper sets on purpose.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  child_seen="$(
    PYTHONHOME="${poison_root}" PYTHONUSERBASE="${poison_root}" \
      PYTHONPATH="${poison_root}" LD_PRELOAD="${poison_root}/x.so" \
      BASH_ENV="${poison_root}/hook.sh" \
      deployment_python - <<'CHILDENV'
import os
print(" ".join(sorted(
    name for name in os.environ
    if name.startswith(("PYTHON", "LD_")) or name in ("BASH_ENV", "ENV")
)))
CHILDENV
  )"
  [[ "${child_seen}" == "PYTHONUTF8" ]] || {
    echo "an interpreter child inherited environment it should not have: [${child_seen}]" >&2
    exit 1
  }
  # And the byte-exactness the sanitized locale must preserve: this lane
  # carries arbitrary bytes in paths, so a child that lost surrogateescape
  # round-tripping would corrupt them silently.
  weird_encoded="$(printf '/tmp/we\xffird' | base64 -w0)"
  weird_back="$(deployment_python - "${weird_encoded}" <<'ROUNDTRIP'
import base64
import os
import sys

path = os.fsdecode(base64.b64decode(sys.argv[1]))
sys.stdout.write(base64.b64encode(os.fsencode(path)).decode("ascii"))
ROUNDTRIP
  )"
  [[ "${weird_back}" == "${weird_encoded}" ]] || {
    echo "a sanitized interpreter child lost byte-exact path round-tripping" >&2
    exit 1
  }
)
rm -rf "${poison_root}"
# (3) THE CLASS, not the instances: no helper in this lane may invoke an
# interpreter directly. Every call goes through deployment_python, which is
# where the environment is built, so a new payload cannot reopen this by
# copying the old idiom.
python3 - "${repo_root}" <<'SANITIZED'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]) / "deploy" / "bin"
offenders = []
for helper in sorted(root.iterdir()):
    if not helper.is_file():
        continue
    for number, raw in enumerate(helper.read_text().splitlines(), 1):
        if number == 1 and raw.startswith("#!"):
            continue  # a shebang is not an invocation this lane makes
        code = raw.split("#", 1)[0]
        if (
            "command -v python3" in code
            or "MCLOVING_PYTHON_BIN" in code
            or "MCLOVING_TRUSTED_PATH" in code
        ):
            # The wrapper's own resolution, and its refusal message, which
            # names the interpreter it could not find on the trusted path.
            continue
        if re.search(r"(?<![-\w/])python3(?=[ \t])", code):
            offenders.append(f"{helper.name}:{number}: {raw.strip()}")
if offenders:
    raise SystemExit(
        "helper(s) invoke an interpreter directly instead of through "
        "deployment_python, which is where the child environment is built:\n  "
        + "\n  ".join(offenders)
    )
SANITIZED
# THE UNIT BOUNDARY'S OWN PATH. Round 41 built a clean environment for every
# interpreter this lane SPAWNS and left the units themselves inheriting the
# service manager's -- so a shipped helper's `#!/usr/bin/env bash` still
# resolved bash through that inherited value, and the KERNEL did it before
# the guard's first line, which is too early for the guard to object. Three
# layers close it and each is asserted here in both directions.
#
# (1) THE SHEBANGS, for the helpers a UNIT STARTS. This is the case round
# 41's sanitization gate excludes by name ("a shebang is not an invocation
# this lane makes"), so nothing else covers it.
#
# The set is DERIVED from the shipped units' own Exec directives rather than
# listed here, because the rule follows the threat and not a name: the
# kernel resolves the interpreter of a process SYSTEMD starts, before the
# guard's first line, using whatever PATH the unit hands it. A helper the
# lane installs but no unit starts -- mcloving-unit-command, which round 41
# already recorded as smoke-suite-only, and the operator-invoked
# install/upgrade/rollback -- is reached through the invoking operator's own
# PATH, which is their trust domain and their privileges, not the service
# account's. Pinning those to one absolute location buys no unit-boundary
# protection and costs real hosts: python3 lives in /usr/local/bin on some,
# which MCLOVING_TRUSTED_PATH explicitly accepts and a hard-coded
# /usr/bin/python3 does not. So they may resolve by name, provided the
# interpreter they name is actually FINDABLE on the trusted path.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
  python3 - "${repo_root}" "${MCLOVING_TRUSTED_PATH}" "${MCLOVING_UNIT_EXEC_DIRECTIVES}" <<'SHEBANG'
import os
import pathlib
import re
import shutil
import stat
import sys

repo_root, trusted_path, exec_directives = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
root = repo_root / "deploy" / "bin"

# Which helpers a unit starts, read off the units themselves.
started = set()
directive = re.compile(rf"^({exec_directives})\s*=\s*(\S+)", re.M)
unit_sources = sorted((repo_root / "deploy" / "systemd").glob("*.service")) + sorted(
    (repo_root / "deploy" / "podman").iterdir()
)
for unit in unit_sources:
    if not unit.is_file():
        continue
    for _, command in directive.findall(unit.read_text()):
        started.add(os.path.basename(command))
if not started & {"mcloving-env-guard", "mcloving-health"}:
    raise SystemExit(
        "the unit Exec sweep found no known pre-start helper; the scan went blind"
    )

offenders = []
checked = 0
for helper in sorted(root.iterdir()):
    if not helper.is_file():
        continue
    lines = helper.read_text().splitlines()[:1]
    if not lines or not lines[0].startswith("#!"):
        continue  # the sourced library carries no shebang and is never exec'd
    checked += 1
    words = lines[0][2:].strip().split()
    if not words:
        offenders.append(f"{helper.name}: empty shebang")
        continue
    interpreter = words[0]
    by_name = os.path.basename(interpreter) == "env"
    if helper.name in started:
        if by_name or not interpreter.startswith("/"):
            offenders.append(
                f"{helper.name}: {lines[0]} -- a unit starts this helper, so the "
                "PATH the service manager carries would pick its interpreter"
            )
            continue
    elif by_name:
        # Not a unit's problem, but it still has to be findable, and findable
        # on the list this lane trusts rather than on the caller's.
        named = words[1] if len(words) > 1 else ""
        if not named or shutil.which(named, path=trusted_path) is None:
            offenders.append(
                f"{helper.name}: {lines[0]} names {named or '(nothing)'}, which is "
                f"not on the trusted path {trusted_path}"
            )
        continue
    # An absolute name is only worth having when the file it names is one no
    # other local user can replace -- the rule require_secure_files applies
    # to every other file this deployment's startup depends on.
    try:
        info = os.stat(interpreter)
    except OSError as error:
        offenders.append(f"{helper.name}: {interpreter} cannot be stat-ed: {error}")
        continue
    if not stat.S_ISREG(info.st_mode):
        offenders.append(f"{helper.name}: {interpreter} is not a regular file")
    elif info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        offenders.append(
            f"{helper.name}: {interpreter} is mode {info.st_mode & 0o777:o}"
        )
if checked < 5:
    raise SystemExit("the shebang sweep found too few helpers; the scan went blind")
if offenders:
    raise SystemExit(
        "shipped helper(s) resolve their interpreter in a way this deployment "
        "cannot stand behind:\n  " + "\n  ".join(offenders)
    )
SHEBANG
)
# (2) EVERY SHIPPED UNIT pins PATH, at the library's value and not a copy of
# it that can drift. A unit added later without the directive inherits the
# manager's PATH again, which is how this defect got in.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
  unpinned=""
  pinned_count=0
  for unit_source in "${repo_root}"/deploy/systemd/*.service \
    "${repo_root}"/deploy/podman/*.container "${repo_root}"/deploy/podman/*.volume; do
    if grep -qxF "Environment=PATH=${MCLOVING_TRUSTED_PATH}" "${unit_source}"; then
      pinned_count=$((pinned_count + 1))
    else
      unpinned+="${unit_source##*/} "
    fi
  done
  [[ -z "${unpinned}" ]] || {
    echo "shipped unit(s) do not pin PATH at the library's trusted value: ${unpinned% }" >&2
    exit 1
  }
  [[ "${pinned_count}" -eq 5 ]] || {
    echo "expected five shipped units to pin PATH, found ${pinned_count}; the unit set changed" >&2
    exit 1
  }
)
# (3) THE DEFECT ITSELF, both directions. A writable directory ahead of
# /usr/bin, a `bash` planted in it, and the pre-start helper the unit runs.
# The shipped guard must ignore the plant; the pre-fix spelling must execute
# it, or the assertion above proves nothing at all. The pre-fix helper is
# RECONSTRUCTED from the shipped one rather than fetched out of git, so the
# gate keeps proving itself in a shallow checkout and long after anyone
# remembers which commit this was.
path_attack="${workdir}/path-attack"
rm -rf "${path_attack}"
mkdir -p "${path_attack}/bin"
cat > "${path_attack}/bin/bash" <<'EVILBASH'
#!/bin/bash
printf 'attacker interpreter executed as the service account\n' \
  > "${MCLOVING_PATH_ATTACK_WITNESS}"
exit 0
EVILBASH
chmod 0755 "${path_attack}/bin/bash"
path_attack_witness="${path_attack}/witness"
rm -f "${path_attack_witness}"
# Acceptance: the installed guard still validates a good contract with the
# hostile directory first on PATH, and does not touch the plant.
MCLOVING_PATH_ATTACK_WITNESS="${path_attack_witness}" \
  PATH="${path_attack}/bin:${PATH}" \
  "${libexec}/helpers/mcloving-env-guard" agent "${config}/agent.env" \
  > "${workdir}/logs/path-attack-shipped.log" 2>&1 || {
  echo "the guard could not validate a good contract with a hostile PATH entry:" >&2
  cat "${workdir}/logs/path-attack-shipped.log" >&2
  exit 1
}
[[ ! -e "${path_attack_witness}" ]] || {
  echo "the installed guard resolved its interpreter through a writable PATH entry" >&2
  exit 1
}
# Refusal: the pre-fix shebang, and nothing else about the helper changed.
prefix_guard="${path_attack}/prefix-env-guard"
sed '1s|^#!/bin/bash$|#!/usr/bin/env bash|' \
  "${libexec}/helpers/mcloving-env-guard" > "${prefix_guard}"
chmod 0755 "${prefix_guard}"
head -1 "${prefix_guard}" | grep -qxF '#!/usr/bin/env bash' || {
  echo "the pre-fix guard reconstruction did not restore the by-name shebang" >&2
  exit 1
}
rm -f "${path_attack_witness}"
MCLOVING_PATH_ATTACK_WITNESS="${path_attack_witness}" \
  PATH="${path_attack}/bin:${PATH}" \
  "${prefix_guard}" agent "${config}/agent.env" \
  > "${workdir}/logs/path-attack-prefix.log" 2>&1 || true
[[ -e "${path_attack_witness}" ]] || {
  echo "the pre-fix guard did not run the planted interpreter, so this gate would pass with the defect present" >&2
  exit 1
}
rm -rf "${path_attack}"
# (4) The unit rule admits the pinned PATH by VALUE and refuses any other
# spelling, so permitting the deployment's own directive did not hand every
# drop-in a way to move PATH wherever it likes.
printf '[Service]\nEnvironment=PATH=/srv/writable\n' > "${reset_dropin_dir}/path.conf"
chmod 0644 "${reset_dropin_dir}/path.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/path-dropin.log" 2>&1; then
  echo "upgrade proceeded over a drop-in repointing PATH at a writable directory" >&2
  exit 1
fi
grep -q "set variable(s) this deployment does not recognise: PATH" \
  "${workdir}/logs/path-dropin.log" || {
  echo "the PATH drop-in was not refused by name:" >&2
  cat "${workdir}/logs/path-dropin.log" >&2
  exit 1
}
rm -f "${reset_dropin_dir}/path.conf"
# THE PARSE FAILURE IS A VERDICT, which is the other half of the same
# escalation. A contract of valid assignments, then a line without "=", then
# PATH=/srv/writable: systemd complains about the bad line and loads the
# PATH anyway, while this parser stops there -- and the `|| true` that used
# to stand at the default-deny call turned that stop into "declares nothing
# objectionable". The allowlist that exists to refuse exactly this PATH
# never saw it, and the shebangs above are what would then have resolved
# through it.
parse_env_file="${dropin_root_home}/.config/mcloving/agent.env"
cp "${parse_env_file}" "${workdir}/parse-agent.env.orig"
printf 'THIS LINE HAS NO EQUALS SIGN\nPATH=/srv/writable\n' >> "${parse_env_file}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/parse-failure.log" 2>&1; then
  echo "upgrade proceeded over a contract whose parse failed, so every assignment after the malformed line went unjudged" >&2
  exit 1
fi
grep -q "could not be parsed, so this deployment cannot say which variables it declares" \
  "${workdir}/logs/parse-failure.log" || {
  echo "the parse failure was not refused as a parse failure:" >&2
  cat "${workdir}/logs/parse-failure.log" >&2
  exit 1
}
# BEFORE the services are stopped, which is the whole point of refusing at
# validation time rather than discovering it later.
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused parse-failure upgrade still moved the current release" >&2
  exit 1
}
# And the mechanism, pinned: the parser really does stop, and what the
# pre-fix call site would have read really does omit the injected PATH. If
# either of these stops holding, the refusal above is testing something else.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  if parse_environment_file "${parse_env_file}" >/dev/null 2>&1; then
    echo "the contract parser accepted a line without '='; this gate no longer describes it" >&2
    exit 1
  fi
  # Translate the NUL separators rather than letting command substitution
  # drop them and warn. The INJECTED VALUE is what is looked for, not the
  # name: a real agent contract legitimately declares several variables
  # whose names end in _PATH.
  swallowed="$(parse_environment_file "${parse_env_file}" 2>/dev/null | tr '\0' '\n' || true)"
  [[ "${swallowed}" != *"/srv/writable"* ]] || {
    echo "the swallowed-status reading saw the injected PATH after all; the gate's premise is wrong" >&2
    exit 1
  }
  [[ "${swallowed}" == *MCLOVING_AGENT_ID* ]] || {
    echo "the swallowed-status reading saw nothing at all; a partial parse is what made this dangerous" >&2
    exit 1
  }
)
cp "${workdir}/parse-agent.env.orig" "${parse_env_file}"
chmod 0600 "${parse_env_file}"
rm -f "${workdir}/parse-agent.env.orig"
# Acceptance: the restored contract still completes a transition.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release after the PATH-boundary gates" >&2
  exit 1
}
# THE RENDERED CONTRACT MUST PARSE BACK TO THE PATHS IT WAS RENDERED FOR.
# That is the only property that matters, and this round's two rendering
# findings broke it from opposite sides -- one by letting a substitution
# chew through bytes an earlier substitution had inserted, the other by
# handing the parser its own syntax inside a path. So it is asserted by
# ROUND-TRIP through the lane's own parser, the authority the guard and the
# inventory already read these files with, rather than against a spelling
# written out here that could agree with a wrong renderer.
render_probe="${workdir}/render-probe"
rm -rf "${render_probe}"
mkdir -p "${render_probe}"
chmod go-w "${render_probe}"
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  # Reads one value through the NUL transport, so a path carrying newlines,
  # quotes or backslashes is compared as bytes rather than as a line.
  rendered_value_into() { # VARIABLE FILE NAME
    # shellcheck disable=SC2178,SC2034  # nameref: written here, read by the caller
    local -n rendered_value_ref="$1"
    local file="$2" wanted="$3" key value
    rendered_value_ref=""
    while IFS= read -r -d '' key && IFS= read -r -d '' value; do
      [[ "${key}" == "${wanted}" ]] || continue
      # shellcheck disable=SC2034  # nameref: read by the caller, not here
      rendered_value_ref="${value}"
      return 0
    done < <(parse_environment_file "${file}")
    return 1
  }
  # (1) A STATE ROOT THAT CONTAINS THE TEMPLATE PREFIX. Sequential replaces
  # let the home substitution rewrite the state root the first one inserted.
  nested_state="/mnt/home/mcloving/state"
  render_contract_template "${repo_root}/deploy/env/agent.env.example" \
    "${render_probe}/nested.env" /srv/account "${nested_state}"
  nested_workspace=""
  rendered_value_into nested_workspace "${render_probe}/nested.env" \
    MCLOVING_AGENT_WORKSPACE_ROOT
  [[ "${nested_workspace}" == "${nested_state}/mcloving-agent/workspace" ]] || {
    echo "a state root containing the template prefix was rewritten by the home substitution: ${nested_workspace}" >&2
    exit 1
  }
  # ...and the home substitution still reached the paths that are not state,
  # so preventing the overlap did not simply stop the second substitution.
  nested_cert=""
  rendered_value_into nested_cert "${render_probe}/nested.env" \
    MCLOVING_AGENT_CERTIFICATE_PATH
  [[ "${nested_cert}" == "/srv/account/.config/mcloving/pki/agent.pem" ]] || {
    echo "the home substitution did not reach a non-state path: ${nested_cert}" >&2
    exit 1
  }
  # (2) EVERY CHARACTER THE GRAMMAR GIVES MEANING TO, in one home: backslash
  # (the reported case -- an escape to the parser), both quote kinds, a
  # dollar, a space, and a newline, which a double-quoted run continues onto
  # the next line. This lane carries arbitrary bytes in paths on purpose.
  weird_home='/home/na\me/q'"'"'uo"te/$dollar/with space'"${MCLOVING_BACKSLASH}"'tick`'
  weird_home="${weird_home}"$'\n'"second-line"
  # A NON-UTF-8 BYTE, which is a legal pathname byte and was the one thing
  # the renderer could produce that the parser then refused to read back.
  weird_home="${weird_home}"$'\xff'"tail"
  # The premise, inline so this gate cannot go vacuous if the parser's error
  # handling is ever tightened back: a STRICT decode of that byte does fail.
  printf 'MCLOVING_PROBE=%s\n' "${weird_home}" > "${render_probe}/bytes.env"
  if python3 -c 'import sys; open(sys.argv[1], "r", encoding="utf-8").read()' \
    "${render_probe}/bytes.env" 2>/dev/null; then
    echo "a strict utf-8 read of a non-UTF-8 path byte succeeded; this gate's premise is gone" >&2
    exit 1
  fi
  render_contract_template "${repo_root}/deploy/env/agent.env.example" \
    "${render_probe}/weird.env" "${weird_home}" "${weird_home}/.local/state"
  weird_workspace=""
  rendered_value_into weird_workspace "${render_probe}/weird.env" \
    MCLOVING_AGENT_WORKSPACE_ROOT
  [[ "${weird_workspace}" == "${weird_home}/.local/state/mcloving-agent/workspace" ]] || {
    echo "a rendered path carrying grammar characters did not survive the round trip:" >&2
    printf 'wrote back: %q\nexpected:   %q\n' "${weird_workspace}" \
      "${weird_home}/.local/state/mcloving-agent/workspace" >&2
    exit 1
  }
  # The pre-fix spelling, asserted inline so the check above cannot go
  # vacuous: the reviewer's own example, inserted raw, really is read back
  # as something else -- `/home/na\me` returns as `/home/name`.
  raw_probe_home="/home/na${MCLOVING_BACKSLASH}me"
  printf 'MCLOVING_PROBE=%s\n' "${raw_probe_home}" > "${render_probe}/raw.env"
  raw_back=""
  rendered_value_into raw_back "${render_probe}/raw.env" MCLOVING_PROBE || raw_back=""
  [[ "${raw_back}" != "${raw_probe_home}" ]] || {
    echo "a raw backslash in a value now round-trips intact; this gate's premise is gone" >&2
    exit 1
  }
  # (3) AN ORDINARY PATH STAYS UNQUOTED, so the operator who has to edit
  # this file is not handed quoting they never needed.
  render_contract_template "${repo_root}/deploy/env/agent.env.example" \
    "${render_probe}/plain.env" /home/plain-probe /home/plain-probe/.local/state
  grep -qxF 'MCLOVING_AGENT_WORKSPACE_ROOT=/home/plain-probe/.local/state/mcloving-agent/workspace' \
    "${render_probe}/plain.env" || {
    echo "an ordinary rendered path did not stay unquoted:" >&2
    grep '^MCLOVING_AGENT_WORKSPACE_ROOT=' "${render_probe}/plain.env" >&2
    exit 1
  }
  # (4) A COMMENT ABOUT THE TEMPLATE IS DOCUMENTATION ABOUT THE TEMPLATE.
  # The whole-body replace rewrote comments too, turning a sentence about
  # the example home into a false statement about this deployment.
  grep -qF "example home ${MCLOVING_CONTRACT_TEMPLATE_HOME}" "${render_probe}/plain.env" || {
    echo "the template's own explanatory comment was rewritten by rendering" >&2
    exit 1
  }
)
rm -rf "${render_probe}"
# THE COMPLETE CONTRACT OR NONE OF IT. os.write() is one write(2): it
# reports how many bytes it took, and taking fewer than it was given is a
# SUCCESS rather than an error, so ignoring the result reported a truncated
# contract as an installed one -- and the installer preserves whatever
# contract it finds, so the truncation would be adopted as deliberate on
# every later run.
short_write="${workdir}/short-write"
rm -rf "${short_write}"
mkdir -p "${short_write}"
chmod go-w "${short_write}"
short_template="${repo_root}/deploy/env/controller.env.example"
short_template_bytes="$(stat -c '%s' "${short_template}")"
[[ "${short_template_bytes}" -gt 1024 ]] || {
  echo "the controller template is only ${short_template_bytes} bytes; the file-size limit below no longer truncates it" >&2
  exit 1
}
# THE HAZARD IS REAL, in one line of the same language: under a file-size
# limit a single os.write takes SOME bytes and returns normally. Measured
# rather than assumed, and without hard-coding what `ulimit -f 1` means in
# bytes on this shell.
raw_short="$(
  ( ulimit -f 1
    python3 -c '
import os
import sys

body = b"x" * 8192
descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    print(os.write(descriptor, body), len(body))
finally:
    os.close(descriptor)
' "${short_write}/raw.probe" ) 2>/dev/null
)"
read -r raw_written raw_total <<<"${raw_short}"
[[ -n "${raw_written}" && "${raw_written}" -gt 0 && "${raw_written}" -lt "${raw_total}" ]] || {
  echo "a single os.write under a file-size limit did not return short (${raw_short:-nothing}); this gate's premise is gone" >&2
  exit 1
}
rm -f "${short_write}/raw.probe"
# Refusal direction: the render must fail under that limit, name the byte
# counts rather than raising a traceback, and leave NO partial contract.
short_status=0
( ulimit -f 1
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  render_contract_template "${short_template}" "${short_write}/controller.env" \
    /home/short-write-probe /home/short-write-probe/.local/state
) > "${workdir}/logs/short-write.log" 2>&1 || short_status=$?
[[ "${short_status}" -ne 0 ]] || {
  echo "the render reported success under a file-size limit that cannot hold the contract" >&2
  exit 1
}
grep -q "could not be written in full" "${workdir}/logs/short-write.log" || {
  echo "the short write was not refused as an incomplete write:" >&2
  cat "${workdir}/logs/short-write.log" >&2
  exit 1
}
[[ ! -e "${short_write}/controller.env" ]] || {
  echo "a truncated contract survived the refusal ($(stat -c '%s' "${short_write}/controller.env") of ${short_template_bytes} bytes); the next install would preserve it" >&2
  exit 1
}
# Acceptance direction: with no limit in the way, the same call renders the
# whole template.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  render_contract_template "${short_template}" "${short_write}/controller.env" \
    /home/short-write-probe /home/short-write-probe/.local/state
)
short_rendered_bytes="$(stat -c '%s' "${short_write}/controller.env")"
[[ "${short_rendered_bytes}" -gt 1024 ]] || {
  echo "the unrestricted render produced only ${short_rendered_bytes} bytes" >&2
  exit 1
}
grep -q '^MCLOVING_AGENT_IDENTITY_BINDINGS_PATH=' "${short_write}/controller.env" || {
  echo "the rendered contract is missing its last assignment, so it is still truncated" >&2
  exit 1
}
rm -rf "${short_write}"
# CONTRACTS ARE OPENED THROUGH A CLASSIFIED DESCRIPTOR. Every caller reaches
# the parser after a `-f` test, so the test and the open judge two different
# moments: a contract atomically replaced in between is a different file by
# the time it is read. The window is staged here exactly as the callers open
# it -- check a regular file, replace the name, then parse -- because that
# needs no hook to be deterministic and is precisely what a caller does.
node_probe="${workdir}/contract-node"
rm -rf "${node_probe}"
mkdir -p "${node_probe}"
printf 'MCLOVING_AGENT_ID=fine\n' > "${node_probe}/contract.env"
[[ -f "${node_probe}/contract.env" ]] || {
  echo "the staged contract is not a regular file; the window this gate opens is not the callers'" >&2
  exit 1
}
mkfifo "${node_probe}/swap.fifo"
mv "${node_probe}/swap.fifo" "${node_probe}/contract.env"
ln -s /dev/zero "${node_probe}/zero.env"
printf 'MCLOVING_AGENT_ID=fine\n' > "${node_probe}/regular.env"
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  # Acceptance first: a regular file still parses to the same NUL-separated
  # pairs, so the classification did not change what a contract means.
  parsed_regular="$(parse_environment_file "${node_probe}/regular.env" | tr '\0' ' ')"
  [[ "${parsed_regular}" == "MCLOVING_AGENT_ID fine " ]] || {
    echo "the classified parser changed what a regular contract parses to: [${parsed_regular}]" >&2
    exit 1
  }
  # A FIFO swapped into the name must be refused, and refused WITHOUT
  # blocking -- a refusal that arrives only when the timeout kills it is the
  # defect wearing the right message.
  for node_name in contract zero; do
    node_status=0
    timeout 20 bash -c \
      'source "$1"; parse_environment_file "$2"' _ \
      "${libexec}/helpers/mcloving-deploy-lib.sh" \
      "${node_probe}/${node_name}.env" \
      > "${workdir}/logs/contract-node-${node_name}.log" 2>&1 || node_status=$?
    [[ "${node_status}" -ne 124 ]] || {
      echo "parsing the ${node_name} node blocked until the timeout killed it" >&2
      exit 1
    }
    [[ "${node_status}" -ne 0 ]] || {
      echo "the parser accepted the ${node_name} node as a contract" >&2
      exit 1
    }
    grep -q "is not a regular file" "${workdir}/logs/contract-node-${node_name}.log" || {
      echo "the ${node_name} node was refused, but not as a node-kind refusal:" >&2
      cat "${workdir}/logs/contract-node-${node_name}.log" >&2
      exit 1
    }
  done
)
# THE HAZARD IS REAL, in one line of the same language the parser is written
# in: opening the swapped-in name by pathname BLOCKS, which is what the
# guard would do at ExecStartPre. If this ever stops blocking, the gate
# above is defending against something that no longer exists and should be
# revisited rather than quietly kept.
prefix_open_status=0
timeout 5 python3 -c \
  'import sys; open(sys.argv[1], "r", encoding="utf-8").readline()' \
  "${node_probe}/contract.env" >/dev/null 2>&1 || prefix_open_status=$?
[[ "${prefix_open_status}" -eq 124 ]] || {
  echo "opening the swapped-in FIFO by pathname did not block (status ${prefix_open_status}); this gate's premise is gone" >&2
  exit 1
}
# And the device edition, bounded so proving it costs a second rather than
# the machine's memory: a newline-free device grows one pending line until
# the allocation fails.
zero_open_status=0
( ulimit -v 1000000
  timeout 20 python3 -c \
    'import sys; open(sys.argv[1], "r", encoding="utf-8").readline()' \
    "${node_probe}/zero.env" ) >/dev/null 2>&1 || zero_open_status=$?
[[ "${zero_open_status}" -ne 0 ]] || {
  echo "reading a newline-free device by pathname returned a line; this gate's premise is gone" >&2
  exit 1
}
rm -rf "${node_probe}"
# A MANAGER ROOT OF "/" IS AN ANSWER, NOT A SILENCE. The empty string is
# this lane's spelling for the root directory -- every XDG derivation here
# strips the trailing slash, so XDG_STATE_HOME=/ yields "" and a leaf under
# it comes out /mcloving-agent, which is correct. Deciding whether the
# manager answered by testing that value for non-emptiness therefore read a
# perfectly good "/" as "nobody could say" and fell back to the caller's
# derivation -- rendering contracts outside the tree systemd builds, which
# is the failure these functions exist to prevent. The verdict is the
# helper's EXIT STATUS. Driven through the one seam that can pose as a
# manager, since no test may reach into the real one's environment.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  xdg_root_home="${workdir}/xdg-root-probe-home"
  # The premise, stated inline so this gate cannot go vacuous: the root
  # really is spelled empty by the derivations everything else here uses.
  [[ -z "$(XDG_STATE_HOME=/ deployment_state_root "${HOME}")" ]] || {
    echo "a state root of / is no longer spelled as the empty string; this gate's premise is gone" >&2
    exit 1
  }
  # (1) A manager that answers "/" must be USED. Under the pre-fix
  # emptiness test this fell through to the caller's derivation.
  deployment_manager_xdg_root() { printf '%s\n' ""; }
  answered_root="$(deployment_effective_state_root "${xdg_root_home}")"
  [[ -z "${answered_root}" ]] || {
    echo "a manager answering / was discarded in favour of the caller's derivation (${answered_root})" >&2
    exit 1
  }
  [[ "${answered_root}/mcloving-agent" == "/mcloving-agent" ]] || {
    echo "a manager root of / composed a wrong leaf: ${answered_root}/mcloving-agent" >&2
    exit 1
  }
  # The same for the cache and data derivations, which share the wrapper.
  [[ -z "$(deployment_effective_cache_root "${xdg_root_home}")" ]] || {
    echo "the cache derivation discarded a manager root of /" >&2
    exit 1
  }
  [[ -z "$(deployment_effective_data_root "${xdg_root_home}")" ]] || {
    echo "the data derivation discarded a manager root of /" >&2
    exit 1
  }
  # (2) A manager that CANNOT say must still fall back, or the fix above
  # would have turned every unreachable manager into a root of /.
  deployment_manager_xdg_root() { return 1; }
  fallback_root="$(deployment_effective_state_root "${xdg_root_home}")"
  [[ "${fallback_root}" == "${xdg_root_home}/.local/state" ]] || {
    echo "an unreachable manager did not fall back to the caller's derivation: ${fallback_root}" >&2
    exit 1
  }
)
# INSTALLATION ROOTS come from the running manager where it can say. Writing
# to the wrong root is the one failure that is silent and total: units land
# where the manager never searches and daemon-reload finds nothing.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  # A home no running manager serves must fall back to the caller's
  # derivation, and must still honour an XDG base inside that home.
  [[ "$(deployment_config_root_source "${dropin_root_home}")" == "derived" ]] || {
    echo "a home the running manager does not serve was reported as manager-backed" >&2
    exit 1
  }
  [[ "$(deployment_effective_config_root "${dropin_root_home}")" == "${dropin_root_home}/.config" ]] || {
    echo "the fallback configuration base is not the caller's derivation" >&2
    exit 1
  }
  if deployment_manager_is_reachable; then
    [[ "$(deployment_config_root_source "${HOME}")" == "manager" ]] || {
      echo "the running manager serves this home but was not used for the configuration base" >&2
      exit 1
    }
    manager_base="$(deployment_effective_config_root "${HOME}")"
    # The whole point: this shell's XDG_CONFIG_HOME must not move it.
    perturbed_base="$(XDG_CONFIG_HOME=/tmp/mcloving-install-root-probe \
      deployment_effective_config_root "${HOME}")"
    [[ "${manager_base}" == "${perturbed_base}" ]] || {
      echo "this shell's XDG_CONFIG_HOME moved the installation root away from the manager's (${manager_base} vs ${perturbed_base})" >&2
      exit 1
    }
    # And it is grounded in the manager's own search list, not in the
    # variable alone.
    systemctl --user show -p UnitPath --value | tr ' ' '\n' \
      | grep -qx "${manager_base}/systemd/user" || {
      echo "the derived configuration base is not one the manager actually searches" >&2
      exit 1
    }
    # THE QUADLET FAMILY, which has no UnitPath to ask for and so was left
    # behind. Rounds 34/37 made the installer WRITE quadlets under the
    # manager's base while the load-path derivation kept taking its base
    # from the CALLER -- so a disagreeing shell moved the reader and left
    # the writer where it was, which is the reader/writer split those rounds
    # existed to close. Same perturbation as above, same answer required.
    quadlet_first=""
    decode_path_item_into quadlet_first \
      "$(deployment_unit_load_paths "${HOME}" user quadlet | head -1)"
    [[ "${quadlet_first}" == "${manager_base}/containers/systemd" ]] || {
      echo "the quadlet search base is not the manager's configuration base (${quadlet_first} vs ${manager_base}/containers/systemd)" >&2
      exit 1
    }
    perturbed_quadlet=""
    decode_path_item_into perturbed_quadlet \
      "$(XDG_CONFIG_HOME=/tmp/mcloving-install-root-probe \
        deployment_unit_load_paths "${HOME}" user quadlet | head -1)"
    [[ "${quadlet_first}" == "${perturbed_quadlet}" ]] || {
      echo "this shell's XDG_CONFIG_HOME moved the quadlet search base away from the manager's (${quadlet_first} vs ${perturbed_quadlet})" >&2
      exit 1
    }
    # THE STATE ROOT, which decides where a rendered contract POINTS and so
    # whether the guard can find the workspace systemd made. There is no
    # UnitPath to ground this one against -- systemd publishes no list of
    # where it would create a StateDirectory= leaf -- so the manager's own
    # environment is the authority, and the property asserted is the one
    # that matters: this shell cannot move it.
    [[ "$(deployment_state_root_source "${HOME}")" == "manager" ]] || {
      echo "the running manager serves this home but was not used for the state root" >&2
      exit 1
    }
    manager_state="$(deployment_effective_state_root "${HOME}")"
    perturbed_state="$(XDG_STATE_HOME=/tmp/mcloving-state-root-probe \
      deployment_effective_state_root "${HOME}")"
    [[ "${manager_state}" == "${perturbed_state}" ]] || {
      echo "this shell's XDG_STATE_HOME moved the state root away from the manager's (${manager_state} vs ${perturbed_state})" >&2
      exit 1
    }
    # And the pre-fix derivation, asserted inline so the check above cannot
    # quietly become vacuous: the CALLER's derivation does follow this
    # shell, which is what made rendering from it wrong.
    caller_state="$(XDG_STATE_HOME=/tmp/mcloving-state-root-probe \
      deployment_state_root "${HOME}")"
    [[ "${caller_state}" == "/tmp/mcloving-state-root-probe" ]] || {
      echo "the caller's state derivation no longer follows this shell (${caller_state}); this gate's premise is gone" >&2
      exit 1
    }
    # The declared-root derivation and the rendered contract have to agree,
    # so they are asserted against ONE answer rather than two spellings.
    declared_under_manager=""
    while IFS= read -r encoded_state_root; do
      [[ -n "${encoded_state_root}" ]] || continue
      decode_path_item_into decoded_state_root "${encoded_state_root}"
      # shellcheck disable=SC2154  # set via the nameref above
      [[ "${decoded_state_root}" != "${manager_state}/mcloving-agent/workspace" ]] \
        || declared_under_manager=1
    done < <(XDG_STATE_HOME=/tmp/mcloving-state-root-probe \
      deployment_unit_declared_roots "${HOME}" "${repo_root}"/deploy/systemd/*.service)
    [[ -n "${declared_under_manager}" ]] || {
      echo "the units' declared state roots did not follow the manager's state root (${manager_state})" >&2
      exit 1
    }
  else
    echo "installation-root manager gate skipped: no reachable systemctl --user on this host"
  fi
)
# The installer says which base it used, because the two can only differ
# when something is already surprising.
install_root_home="${workdir}/install-root-home"
rm -rf "${install_root_home}"
mkdir -p "${install_root_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${install_root_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/install-root.log" 2>&1 || {
  echo "the install-root gate could not install:" >&2
  cat "${workdir}/logs/install-root.log" >&2
  exit 1
}
grep -q "unit installation roots came from the derived configuration base (${install_root_home}/.config)" \
  "${workdir}/logs/install-root.log" || {
  echo "the installer did not report which configuration base it used:" >&2
  cat "${workdir}/logs/install-root.log" >&2
  exit 1
}
rm -rf "${install_root_home}"
# Parse coverage, the class-closing check: any installed-source line that
# even LOOKS like a path-bearing directive (sloppy match: optional
# whitespace, key, optional whitespace, '=') must be extracted by the
# shared parser. A future systemd-legal spelling the parser misses fails
# this differential rather than silently escaping validation; the
# spellings the parser deliberately refuses (continuations, quoting)
# never reach an installed tree, because require_parseable_unit_sources
# refuses them at install and at every transition.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  coverage_sources=()
  while IFS= read -r encoded_coverage_source; do
    [[ -n "${encoded_coverage_source}" ]] || continue
    decode_path_item_into coverage_source "${encoded_coverage_source}"
    coverage_sources+=("${coverage_source}")
  done < <(deployment_unit_source_files "${dropin_root_home}" \
    "${dropin_root_home}/.config/systemd/user"/mcloving-*.service \
    "${dropin_root_home}/.config/containers/systemd"/mcloving-*.container \
    "${dropin_root_home}/.config/containers/systemd"/mcloving-*.volume)
  [[ ${#coverage_sources[@]} -gt 0 ]] || {
    echo "parse-coverage gate found no installed unit sources" >&2
    exit 1
  }
  sloppy="$(cat "${coverage_sources[@]}" \
    | grep -cE "^[[:space:]]*(${MCLOVING_UNIT_PATH_DIRECTIVES})[[:space:]]*=")" || true
  parsed="$(deployment_unit_assignment_lines "${coverage_sources[@]}" \
    | grep -cE "^(${MCLOVING_UNIT_PATH_DIRECTIVES})=")" || true
  [[ "${sloppy}" -gt 0 ]] || {
    echo "parse-coverage gate saw no path-bearing directives; the sweep went blind" >&2
    exit 1
  }
  [[ "${sloppy}" -eq "${parsed}" ]] || {
    echo "parse coverage: ${sloppy} path-bearing directive lines in the installed sources but ${parsed} extracted by the parser; a spelling systemd consumes escaped extraction" >&2
    exit 1
  }
  # The same differential over the COMMAND family. It is kept separate
  # because the two lists carry different value grammars and a merged
  # count would let a miss in one be masked by the other; both must
  # balance, and a directive added to either constant is swept here
  # without anyone remembering a third list.
  exec_sloppy="$(cat "${coverage_sources[@]}" \
    | grep -cE "^[[:space:]]*(${MCLOVING_UNIT_EXEC_DIRECTIVES})[[:space:]]*=")" || true
  exec_parsed="$(deployment_unit_assignment_lines "${coverage_sources[@]}" \
    | grep -cE "^(${MCLOVING_UNIT_EXEC_DIRECTIVES})=")" || true
  [[ "${exec_sloppy}" -gt 0 ]] || {
    echo "parse-coverage gate saw no Exec* directives; the command sweep went blind" >&2
    exit 1
  }
  [[ "${exec_sloppy}" -eq "${exec_parsed}" ]] || {
    echo "parse coverage: ${exec_sloppy} Exec* directive lines in the installed sources but ${exec_parsed} extracted by the parser; a command spelling systemd executes escaped extraction" >&2
    exit 1
  }
  # And the executables themselves are actually EMITTED, not merely
  # parsed: the shipped units name their commands with %h, so a
  # deployment home must appear in every extracted executable. An
  # extractor that returned nothing would satisfy the count differential
  # above while validating no command at all.
  exec_emitted=0
  while IFS= read -r encoded_exec; do
    [[ -n "${encoded_exec}" ]] || continue
    decode_path_item_into decoded_exec "${encoded_exec}"
    # shellcheck disable=SC2154 # assigned through the nameref above
    case "${decoded_exec}" in
      "${dropin_root_home}"/*) exec_emitted=$((exec_emitted + 1)) ;;
      *)
        echo "an extracted Exec* executable is not %h-anchored: ${decoded_exec}" >&2
        exit 1
        ;;
    esac
  done < <(deployment_unit_declared_executables "${dropin_root_home}" \
    "${dropin_root_home}/.config/systemd/user"/mcloving-*.service \
    "${dropin_root_home}/.config/containers/systemd"/mcloving-*.container \
    "${dropin_root_home}/.config/containers/systemd"/mcloving-*.volume | sort -u)
  [[ "${exec_emitted}" -gt 0 ]] || {
    echo "the Exec* extractor emitted no executables at all for the installed units" >&2
    exit 1
  }
  # Exactness over the separator spellings systemd permits: spaces and
  # tabs around '=', trailing whitespace, comment lines.
  synthetic="${workdir}/parse-synthetic.conf"
  printf '[Service]\nEnvironmentFile = /srv/spaced.env\n\tStateDirectory =\tspaced-name\nWorkingDirectory=/spaced/work  \n#EnvironmentFile=/commented.env\n; EnvironmentFile=/also-commented.env\n' \
    > "${synthetic}"
  expected_parse=$'EnvironmentFile=/srv/spaced.env\nStateDirectory=spaced-name\nWorkingDirectory=/spaced/work'
  actual_parse="$(deployment_unit_assignment_lines "${synthetic}")"
  [[ "${actual_parse}" == "${expected_parse}" ]] || {
    echo "the assignment parser did not normalize systemd's separator spellings:" >&2
    printf '%s\n' "${actual_parse}" >&2
    exit 1
  }
  rm -f "${synthetic}"
)
# The drop-in SOURCES are execution vectors: a writable .d directory or
# drop-in file must refuse the transition before the restart executes
# whatever was injected -- and the top-level unit file is as much a vector
# as the drop-ins, newly covered by the same rule.
dropin_d_dir="${dropin_root_home}/.config/systemd/user/mcloving-controller.service.d"
chmod 0777 "${dropin_d_dir}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/dropin-dir.log" 2>&1; then
  echo "upgrade proceeded over a world-writable drop-in directory" >&2
  exit 1
fi
grep -q "service.d (mode 777)" "${workdir}/logs/dropin-dir.log" || {
  echo "the writable .d directory refusal was not named:" >&2
  cat "${workdir}/logs/dropin-dir.log" >&2
  exit 1
}
chmod 0755 "${dropin_d_dir}"
chmod 0666 "${dropin_d_dir}/override.conf"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/dropin-file.log" 2>&1; then
  echo "upgrade proceeded over a world-writable drop-in file" >&2
  exit 1
fi
grep -q "override.conf (mode 666)" "${workdir}/logs/dropin-file.log" || {
  echo "the writable drop-in file refusal was not named:" >&2
  cat "${workdir}/logs/dropin-file.log" >&2
  exit 1
}
chmod 0644 "${dropin_d_dir}/override.conf"
chmod 0666 "${dropin_root_home}/.config/systemd/user/mcloving-controller.service"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/unit-file-mode.log" 2>&1; then
  echo "upgrade proceeded over a world-writable unit file" >&2
  exit 1
fi
grep -q "mcloving-controller.service (mode 666)" "${workdir}/logs/unit-file-mode.log" || {
  echo "the writable unit-file refusal was not named:" >&2
  cat "${workdir}/logs/unit-file-mode.log" >&2
  exit 1
}
chmod 0644 "${dropin_root_home}/.config/systemd/user/mcloving-controller.service"
# A unit SOURCE that is a symlink to a securely-owned 0644 file passes the
# trust-input file rule on the target itself; only the resolved ancestor
# walk judges the target's parents, and a group/world-writable external
# parent lets another local user replace the accepted unit wholesale
# before the next manager start reads it. The sources must enter the same
# file-chain derivation the declared contracts use: refusal names the
# writable parent, and the same symlinked source with a secured parent
# stays accepted.
evil_unit_parent="${dropin_root_home}/evil-unit-parent"
symlinked_unit="${dropin_root_home}/.config/systemd/user/mcloving-controller.service"
mkdir -p "${evil_unit_parent}"
mv "${symlinked_unit}" "${evil_unit_parent}/mcloving-controller.service"
chmod 0644 "${evil_unit_parent}/mcloving-controller.service"
ln -s "${evil_unit_parent}/mcloving-controller.service" "${symlinked_unit}"
chmod 0777 "${evil_unit_parent}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/unit-symlink-parent.log" 2>&1; then
  echo "upgrade accepted a unit source symlinked under a world-writable parent" >&2
  exit 1
fi
grep -q "evil-unit-parent (mode 777)" "${workdir}/logs/unit-symlink-parent.log" || {
  echo "the symlinked unit source's writable parent was not named:" >&2
  cat "${workdir}/logs/unit-symlink-parent.log" >&2
  exit 1
}
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "a refused symlinked-unit upgrade still moved the current release" >&2
  exit 1
}
chmod 0755 "${evil_unit_parent}"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" != "${dropin_root_current}" ]] || {
  echo "the secured symlinked unit source did not admit the transition" >&2
  exit 1
}
"${repo_root}/deploy/bin/mcloving-rollback" --home "${dropin_root_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" == "${dropin_root_current}" ]] || {
  echo "rollback did not restore the original release across the symlinked unit" >&2
  exit 1
}
rm -f "${symlinked_unit}"
mv "${evil_unit_parent}/mcloving-controller.service" "${symlinked_unit}"
rm -rf "${evil_unit_parent}"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${dropin_root_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${dropin_root_libexec}/current")" != "${dropin_root_current}" ]] || {
  echo "the secured drop-in root did not admit the transition" >&2
  exit 1
}
rm -rf "${dropin_root_home}"
mkdir -p "${transguard_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${transguard_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
transguard_libexec="${transguard_home}/.local/libexec/mcloving"
transguard_current="$(readlink "${transguard_libexec}/current")"
chmod 0777 "${transguard_home}/.local"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${transguard_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/transguard-upgrade.log" 2>&1; then
  echo "upgrade proceeded over an ancestor relaxed after installation" >&2
  exit 1
fi
grep -q "\.local (mode 777)" "${workdir}/logs/transguard-upgrade.log" || {
  echo "the upgrade transition refusal did not name the ancestor:" >&2
  cat "${workdir}/logs/transguard-upgrade.log" >&2
  exit 1
}
[[ "$(readlink "${transguard_libexec}/current")" == "${transguard_current}" ]] || {
  echo "a refused upgrade transition still moved the current release" >&2
  exit 1
}
chmod 0755 "${transguard_home}/.local"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${transguard_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
transguard_upgraded="$(readlink "${transguard_libexec}/current")"
chmod 0777 "${transguard_home}/.local"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd > "${workdir}/logs/transguard-rollback.log" 2>&1; then
  echo "rollback proceeded over an ancestor relaxed after installation" >&2
  exit 1
fi
grep -q "\.local (mode 777)" "${workdir}/logs/transguard-rollback.log" || {
  echo "the rollback transition refusal did not name the ancestor:" >&2
  cat "${workdir}/logs/transguard-rollback.log" >&2
  exit 1
}
if grep -q "rolling back" "${workdir}/logs/transguard-rollback.log"; then
  echo "the rollback refusal came after the transition had begun" >&2
  exit 1
fi
[[ "$(readlink "${transguard_libexec}/current")" == "${transguard_upgraded}" ]] || {
  echo "a refused rollback transition still moved the current release" >&2
  exit 1
}
chmod 0755 "${transguard_home}/.local"
"${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${transguard_libexec}/current")" == "${transguard_current}" ]] || {
  echo "rollback did not restore the original release after the ancestor was secured" >&2
  exit 1
}
# LEAF managed roots are nodes in the validated set, not only their
# parents: a helpers or releases directory relaxed after install is a
# helper or release substitution waiting for the next transition.
chmod 0777 "${transguard_libexec}/helpers"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${transguard_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/transguard-helpers.log" 2>&1; then
  echo "upgrade proceeded over a world-writable helpers root" >&2
  exit 1
fi
grep -q "helpers (mode 777)" "${workdir}/logs/transguard-helpers.log" || {
  echo "the helpers-root refusal did not name the leaf:" >&2
  cat "${workdir}/logs/transguard-helpers.log" >&2
  exit 1
}
[[ "$(readlink "${transguard_libexec}/current")" == "${transguard_current}" ]] || {
  echo "a refused helpers-root upgrade still moved the current release" >&2
  exit 1
}
chmod 0700 "${transguard_libexec}/helpers"
chmod 0777 "${transguard_libexec}/releases"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd > "${workdir}/logs/transguard-releases.log" 2>&1; then
  echo "rollback proceeded over a world-writable releases root" >&2
  exit 1
fi
grep -q "releases (mode 777)" "${workdir}/logs/transguard-releases.log" || {
  echo "the releases-root refusal did not name the leaf:" >&2
  cat "${workdir}/logs/transguard-releases.log" >&2
  exit 1
}
if grep -q "rolling back" "${workdir}/logs/transguard-releases.log"; then
  echo "the releases-root refusal came after the transition had begun" >&2
  exit 1
fi
chmod 0700 "${transguard_libexec}/releases"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${transguard_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${transguard_libexec}/current")" != "${transguard_current}" ]] || {
  echo "the secured leaf roots did not admit the transition" >&2
  exit 1
}
# RETAINED release directories and the binaries inside them are validated
# nodes, derived by LISTING releases/ -- not from the current/previous
# links: a retained releases/<id> (or a binary in one) gone
# group/world-writable after publication would otherwise be hashed
# successfully and then swapped by another local user between the byte
# comparison and the service start. Refusal names the node; secured, the
# same transitions proceed.
chmod 0777 "${transguard_libexec}/${transguard_current}"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd > "${workdir}/logs/retained-dir-mode.log" 2>&1; then
  echo "rollback proceeded over a world-writable retained release directory" >&2
  exit 1
fi
grep -q "${transguard_current} (mode 777)" "${workdir}/logs/retained-dir-mode.log" || {
  echo "the writable retained release directory was not named:" >&2
  cat "${workdir}/logs/retained-dir-mode.log" >&2
  exit 1
}
[[ "$(readlink "${transguard_libexec}/current")" != "${transguard_current}" ]] || {
  echo "a refused retained-directory rollback still moved the current release" >&2
  exit 1
}
chmod 0700 "${transguard_libexec}/${transguard_current}"
chmod 0775 "${transguard_libexec}/${transguard_current}/mcloving-agent"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd > "${workdir}/logs/retained-binary-mode.log" 2>&1; then
  echo "rollback proceeded over a group-writable retained release binary" >&2
  exit 1
fi
grep -q "mcloving-agent (mode 775)" "${workdir}/logs/retained-binary-mode.log" || {
  echo "the writable retained release binary was not named:" >&2
  cat "${workdir}/logs/retained-binary-mode.log" >&2
  exit 1
}
chmod 0755 "${transguard_libexec}/${transguard_current}/mcloving-agent"
"${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${transguard_libexec}/current")" == "${transguard_current}" ]] || {
  echo "rollback did not restore the original release after the retained nodes were secured" >&2
  exit 1
}
# Same rule on the upgrade entry point: the now-retained second release
# carries a group-writable binary and the transition toward it refuses.
transguard_retained2="$(readlink "${transguard_libexec}/previous")"
chmod 0775 "${transguard_libexec}/${transguard_retained2}/mcloving-cli"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${transguard_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/retained-binary-upgrade.log" 2>&1; then
  echo "upgrade proceeded over a group-writable retained release binary" >&2
  exit 1
fi
grep -q "mcloving-cli (mode 775)" "${workdir}/logs/retained-binary-upgrade.log" || {
  echo "the upgrade's writable retained binary was not named:" >&2
  cat "${workdir}/logs/retained-binary-upgrade.log" >&2
  exit 1
}
chmod 0755 "${transguard_libexec}/${transguard_retained2}/mcloving-cli"
# INSTALLED HELPERS are the other tree this transition executes from:
# mcloving-health and mcloving-env-guard run from the units, and
# mcloving-deploy-lib.sh is SOURCED by all of them. A helpers directory
# that is merely traversable (0755 passes the ancestor rule) says nothing
# about the mode of a file inside it, and one relaxed helper is arbitrary
# code run as the service user during the restart and health gates this
# very transition performs. Every file under helpers/ carries the
# trust-input rule; the sourced library is the sharpest case.
chmod 0664 "${transguard_libexec}/helpers/mcloving-deploy-lib.sh"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${transguard_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/helper-file-mode.log" 2>&1; then
  echo "upgrade proceeded over a group-writable installed helper library" >&2
  exit 1
fi
grep -q "mcloving-deploy-lib.sh (mode 664)" "${workdir}/logs/helper-file-mode.log" || {
  echo "the writable helper file was not named:" >&2
  cat "${workdir}/logs/helper-file-mode.log" >&2
  exit 1
}
chmod 0755 "${transguard_libexec}/helpers/mcloving-deploy-lib.sh"
# An executable helper, on the rollback entry point, with the helpers
# directory left at a traversable 0755 -- proving the refusal comes from
# the FILE rule and not from the directory's own mode.
chmod 0755 "${transguard_libexec}/helpers"
chmod 0775 "${transguard_libexec}/helpers/mcloving-health"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd > "${workdir}/logs/helper-exec-mode.log" 2>&1; then
  echo "rollback proceeded over a group-writable installed helper executable" >&2
  exit 1
fi
grep -q "mcloving-health (mode 775)" "${workdir}/logs/helper-exec-mode.log" || {
  echo "the writable helper executable was not named:" >&2
  cat "${workdir}/logs/helper-exec-mode.log" >&2
  exit 1
}
if grep -q "rolling back" "${workdir}/logs/helper-exec-mode.log"; then
  echo "the helper refusal came after the transition had begun" >&2
  exit 1
fi
chmod 0755 "${transguard_libexec}/helpers/mcloving-health"
chmod 0700 "${transguard_libexec}/helpers"
# A special node planted among the helpers is refused by name rather than
# skipped -- the walk leaves no node class outside validation.
mkfifo "${transguard_libexec}/helpers/rogue.fifo"
helper_fifo_status=0
timeout 60 "${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd > "${workdir}/logs/helper-fifo.log" 2>&1 || helper_fifo_status=$?
if [[ "${helper_fifo_status}" -eq 0 ]]; then
  echo "rollback proceeded over a FIFO planted among the installed helpers" >&2
  exit 1
fi
if [[ "${helper_fifo_status}" -eq 124 ]]; then
  echo "the helpers walk hung on a FIFO instead of refusing it" >&2
  exit 1
fi
grep -q "installed helper entry .*rogue.fifo is not a regular file or directory" \
  "${workdir}/logs/helper-fifo.log" || {
  echo "the helper special node was not refused by name:" >&2
  cat "${workdir}/logs/helper-fifo.log" >&2
  exit 1
}
rm -f "${transguard_libexec}/helpers/rogue.fifo"
# Acceptance: with every helper restored the same rollback proceeds.
"${repo_root}/deploy/bin/mcloving-rollback" --home "${transguard_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${transguard_libexec}/current")" == "${transguard_retained2}" ]] || {
  echo "the secured helpers did not admit the rollback" >&2
  exit 1
}
rm -rf "${transguard_home}"
mkdir -p "${lock_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${lock_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
lock_libexec="${lock_home}/.local/libexec/mcloving"
lock_current="$(readlink "${lock_libexec}/current")"
# The holder is an UNRELATED process, exactly like a real concurrent
# transition: a holder that spawned the upgrade would leak its locked
# descriptor into the child, and inherited-descriptor flock semantics are
# not the case this lock exists for.
# `exec sleep` keeps the holder a single process: `flock -c` would hold
# the lock in a child that survives killing the parent, and the gate could
# never release it.
( exec 200>"${lock_libexec}/.transition-lock" \
  && flock -n 200 \
  && exec sleep 60 ) &
lock_holder=$!
register_background_pid "${lock_holder}"
lock_taken=""
for _ in $(seq 1 50); do
  if ! flock -n "${lock_libexec}/.transition-lock" -c true 2>/dev/null; then
    lock_taken=1
    break
  fi
  sleep 0.1
done
[[ -n "${lock_taken}" ]] || {
  echo "the lock gate's holder never took the transition lock" >&2
  release_background_pid "${lock_holder}"
  exit 1
}
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${lock_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/transition-lock.log" 2>&1; then
  echo "an upgrade proceeded while another transition held the deployment lock" >&2
  release_background_pid "${lock_holder}"
  exit 1
fi
grep -q "another deployment transition holds the lock" \
  "${workdir}/logs/transition-lock.log" || {
  echo "the held-lock refusal did not name the lock:" >&2
  cat "${workdir}/logs/transition-lock.log" >&2
  exit 1
}
[[ "$(readlink "${lock_libexec}/current")" == "${lock_current}" ]] || {
  echo "a lock-refused upgrade still moved the current release" >&2
  release_background_pid "${lock_holder}"
  exit 1
}
# The digest reader participates in the same lock, shared side: while a
# transition holds it exclusively the read is a named refusal -- a document
# captured between the two symlink writes could describe a deployment that
# never existed.
if "${lock_libexec}/helpers/mcloving-deployed-digests" --home "${lock_home}" \
  > "${workdir}/logs/digests-under-lock.log" 2>&1; then
  echo "the digest reader ran while a transition held the lock exclusively" >&2
  release_background_pid "${lock_holder}"
  exit 1
fi
grep -q "a deployment transition is in progress" \
  "${workdir}/logs/digests-under-lock.log" || {
  echo "the under-transition digest refusal was not named:" >&2
  cat "${workdir}/logs/digests-under-lock.log" >&2
  release_background_pid "${lock_holder}"
  exit 1
}
release_background_pid "${lock_holder}"
# Shared holders coexist: a concurrent digest read must not block another.
( exec 200>>"${lock_libexec}/.transition-lock" \
  && flock -s -n 200 \
  && exec sleep 60 ) &
shared_holder=$!
register_background_pid "${shared_holder}"
sleep 0.3
"${lock_libexec}/helpers/mcloving-deployed-digests" --home "${lock_home}" >/dev/null || {
  echo "a shared lock holder blocked a digest read" >&2
  release_background_pid "${shared_holder}"
  exit 1
}
release_background_pid "${shared_holder}"
# The lock is legitimately opened BEFORE the integrity walk, so the open
# itself must be safe against a swapped lockfile: with libexec writable,
# another user replaces .transition-lock with a symlink to any
# service-user-writable file, and a truncating `exec 9>` would destroy
# that target before any validation could refuse the deployment. Both
# sides -- the exclusive transition open and the reader's shared open --
# must refuse a symlinked lock by name, without truncating or modifying
# what it points at.
lock_victim="${workdir}/lock-victim.txt"
printf 'LOCK-VICTIM-BYTES\n' > "${lock_victim}"
ln -sfn "${lock_victim}" "${lock_libexec}/.transition-lock"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${lock_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/lock-symlink.log" 2>&1; then
  echo "an upgrade proceeded over a symlinked transition lock" >&2
  exit 1
fi
grep -q "is a symlink; the deployment only ever creates it as a regular file" \
  "${workdir}/logs/lock-symlink.log" || {
  echo "the symlinked-lock refusal was not named:" >&2
  cat "${workdir}/logs/lock-symlink.log" >&2
  exit 1
}
[[ "$(cat "${lock_victim}")" == "LOCK-VICTIM-BYTES" ]] || {
  echo "opening the symlinked transition lock truncated or modified its target" >&2
  exit 1
}
[[ "$(readlink "${lock_libexec}/current")" == "${lock_current}" ]] || {
  echo "a symlinked-lock refusal still moved the current release" >&2
  exit 1
}
if "${lock_libexec}/helpers/mcloving-deployed-digests" --home "${lock_home}" \
  > "${workdir}/logs/lock-symlink-shared.log" 2>&1; then
  echo "the digest reader opened a symlinked transition lock" >&2
  exit 1
fi
grep -q "is a symlink; the deployment only ever creates it as a regular file" \
  "${workdir}/logs/lock-symlink-shared.log" || {
  echo "the reader's symlinked-lock refusal was not named:" >&2
  cat "${workdir}/logs/lock-symlink-shared.log" >&2
  exit 1
}
[[ "$(cat "${lock_victim}")" == "LOCK-VICTIM-BYTES" ]] || {
  echo "the reader's symlinked-lock open truncated or modified its target" >&2
  exit 1
}
rm -f "${lock_libexec}/.transition-lock" "${lock_victim}"
# A FIFO at the lock path must be refused BY NAME, never opened: the
# write-only open of a reader-less FIFO blocks forever, so an unguarded
# open hangs every transition and every digest read before any identity
# check or integrity refusal can run. The timeout is the gate's own
# regression net -- an open-then-check implementation times out here
# instead of refusing.
mkfifo "${lock_libexec}/.transition-lock"
lock_fifo_status=0
timeout 30 "${repo_root}/deploy/bin/mcloving-upgrade" --home "${lock_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/lock-fifo.log" 2>&1 || lock_fifo_status=$?
if [[ "${lock_fifo_status}" -eq 0 ]]; then
  echo "an upgrade proceeded over a FIFO transition lock" >&2
  exit 1
fi
if [[ "${lock_fifo_status}" -eq 124 ]]; then
  echo "the transition hung opening a FIFO lock instead of refusing it" >&2
  exit 1
fi
grep -q "is not a regular file (fifo)" "${workdir}/logs/lock-fifo.log" || {
  echo "the FIFO-lock refusal was not named:" >&2
  cat "${workdir}/logs/lock-fifo.log" >&2
  exit 1
}
[[ "$(readlink "${lock_libexec}/current")" == "${lock_current}" ]] || {
  echo "a FIFO-lock refusal still moved the current release" >&2
  exit 1
}
lock_fifo_shared_status=0
timeout 30 "${lock_libexec}/helpers/mcloving-deployed-digests" --home "${lock_home}" \
  > "${workdir}/logs/lock-fifo-shared.log" 2>&1 || lock_fifo_shared_status=$?
if [[ "${lock_fifo_shared_status}" -eq 0 ]]; then
  echo "the digest reader opened a FIFO transition lock" >&2
  exit 1
fi
if [[ "${lock_fifo_shared_status}" -eq 124 ]]; then
  echo "the digest reader hung opening a FIFO lock instead of refusing it" >&2
  exit 1
fi
grep -q "is not a regular file (fifo)" "${workdir}/logs/lock-fifo-shared.log" || {
  echo "the reader's FIFO-lock refusal was not named:" >&2
  cat "${workdir}/logs/lock-fifo-shared.log" >&2
  exit 1
}
rm -f "${lock_libexec}/.transition-lock"
# The upgrade below is the acceptance direction: with the symlink and the
# FIFO gone the open recreates a regular lockfile and the same transition
# proceeds.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${lock_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${lock_libexec}/current")" != "${lock_current}" ]] || {
  echo "the released lock did not admit the same transition" >&2
  exit 1
}
rm -rf "${lock_home}"
mkdir -p "${linktrap_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${linktrap_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
linktrap_libexec="${linktrap_home}/.local/libexec/mcloving"
linktrap_current="$(readlink "${linktrap_libexec}/current")"
linktrap_idb="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  release_id "${release2_dir}"
)"
mkdir -p "${linktrap_home}/evil-parent"
cp -r "${release2_dir}" "${linktrap_home}/evil-parent/tree"
chmod 0777 "${linktrap_home}/evil-parent"
ln -s "../../../../evil-parent/tree" "${linktrap_libexec}/releases/${linktrap_idb}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${linktrap_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/linktrap.log" 2>&1; then
  echo "upgrade adopted a symlinked retained release directory" >&2
  exit 1
fi
grep -q "releases/${linktrap_idb} is a symlink" "${workdir}/logs/linktrap.log" || {
  echo "the symlinked retained target was refused for the wrong reason:" >&2
  cat "${workdir}/logs/linktrap.log" >&2
  exit 1
}
[[ "$(readlink "${linktrap_libexec}/current")" == "${linktrap_current}" ]] || {
  echo "a refused symlinked retained target still moved the current release" >&2
  exit 1
}
rm -f "${linktrap_libexec}/releases/${linktrap_idb}"
rm -rf "${linktrap_home}/evil-parent"
# Legitimate upgrade, then tamper with the links rollback trusts.
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${linktrap_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
linktrap_previous="$(readlink "${linktrap_libexec}/previous")"
ln -sfn "../evil-rel" "${linktrap_libexec}/previous"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${linktrap_home}" \
  --no-systemd > "${workdir}/logs/linktrap-rollback.log" 2>&1; then
  echo "rollback followed a previous link pointing outside releases/" >&2
  exit 1
fi
grep -q "not a releases/<id> entry" "${workdir}/logs/linktrap-rollback.log" || {
  echo "the escaping previous link was refused for the wrong reason:" >&2
  cat "${workdir}/logs/linktrap-rollback.log" >&2
  exit 1
}
ln -sfn "${linktrap_previous}" "${linktrap_libexec}/previous"
mv "${linktrap_libexec}/${linktrap_previous}" "${linktrap_libexec}/releases/.aside"
ln -s ".aside" "${linktrap_libexec}/${linktrap_previous}"
if "${repo_root}/deploy/bin/mcloving-rollback" --home "${linktrap_home}" \
  --no-systemd > "${workdir}/logs/linktrap-rollback2.log" 2>&1; then
  echo "rollback followed a symlinked release entry" >&2
  exit 1
fi
grep -q "is itself a symlink" "${workdir}/logs/linktrap-rollback2.log" || {
  echo "the symlinked release entry was refused for the wrong reason:" >&2
  cat "${workdir}/logs/linktrap-rollback2.log" >&2
  exit 1
}
rm -f "${linktrap_libexec}/${linktrap_previous}"
mv "${linktrap_libexec}/releases/.aside" "${linktrap_libexec}/${linktrap_previous}"
"${repo_root}/deploy/bin/mcloving-rollback" --home "${linktrap_home}" \
  --no-systemd >/dev/null
[[ "$(readlink "${linktrap_libexec}/current")" == "${linktrap_previous}" ]] || {
  echo "rollback did not restore the validated previous release" >&2
  exit 1
}
rm -rf "${linktrap_home}"
mkdir -p "${collision_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${collision_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
collision_libexec="${collision_home}/.local/libexec/mcloving"
collision_current="$(readlink "${collision_libexec}/current")"
collision_id="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  release_id "${release2_dir}"
)"
mkdir -p "${collision_libexec}/releases/${collision_id}"
for imposter in mcloving-controller mcloving-agent mcloving-cli mcloving-identity-admin; do
  printf 'imposter %s\n' "${imposter}" \
    > "${collision_libexec}/releases/${collision_id}/${imposter}"
  chmod 0755 "${collision_libexec}/releases/${collision_id}/${imposter}"
done
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${collision_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd > "${workdir}/logs/collision.log" 2>&1; then
  echo "upgrade adopted a retained release tree whose bytes differ from the verified staging" >&2
  exit 1
fi
grep -q "does not match the newly verified bytes" "${workdir}/logs/collision.log" || {
  echo "the colliding retained tree was refused for the wrong reason:" >&2
  cat "${workdir}/logs/collision.log" >&2
  exit 1
}
[[ "$(readlink "${collision_libexec}/current")" == "${collision_current}" ]] || {
  echo "a refused colliding upgrade still moved the current release" >&2
  exit 1
}
grep -q "imposter mcloving-cli" \
  "${collision_libexec}/releases/${collision_id}/mcloving-cli" || {
  echo "the refusal altered the pre-existing tree it refused to adopt" >&2
  exit 1
}
rm -rf "${collision_home}"
mkdir -p "${retain_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${retain_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
retain_libexec="${retain_home}/.local/libexec/mcloving"
retain_id="$(basename "$(readlink "${retain_libexec}/current")")"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${retain_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${retain_libexec}/previous")" == "releases/${retain_id}" ]] || {
  echo "upgrade did not retain the first release as previous" >&2
  exit 1
}
if "${repo_root}/deploy/bin/mcloving-install" --home "${retain_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install accepted a release differing from the current one" >&2
  exit 1
fi
[[ -d "${retain_libexec}/releases/${retain_id}" ]] || {
  echo "a refused install destroyed the retained rollback release" >&2
  exit 1
}
rm -rf "${retain_home}"

# stage_release's stdout is a protocol its callers parse. A diagnostic written
# there is indistinguishable from the result, and was being parsed as one: the
# status came back as "verified" and the path as the rest of that sentence.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  protocol_home="${workdir}/protocol-home"
  rm -rf "${protocol_home}"
  mkdir -p "${protocol_home}/.local/libexec/mcloving"
  line="$(stage_release "${protocol_home}/.local/libexec/mcloving" "${release_dir}" \
    "" "${workdir}/checksums.sha256" 2>/dev/null)"
  [[ "$(printf '%s' "${line}" | wc -l)" -eq 0 ]] || {
    echo "stage_release emitted more than one line on stdout: ${line}" >&2
    exit 1
  }
  [[ "${line%% *}" == "published" ]] || {
    echo "stage_release status parsed as ${line%% *}, not published" >&2
    exit 1
  }
  [[ -d "${line#* }" ]] || {
    echo "stage_release path did not parse to a directory: ${line#* }" >&2
    exit 1
  }
  rm -rf "${protocol_home}"
)

# The bootstrap migrates through MCLOVING_MIGRATION_DATABASE_URL and provisions
# through the container fields, so a URL naming a different database would
# migrate one and modify another.
db_mismatch="${home}/db-mismatch.env"
cp "${config_dir}/db-init.env" "${db_mismatch}"
sed -i "s#^MCLOVING_POSTGRES_DB=.*#MCLOVING_POSTGRES_DB=someotherdb#" "${db_mismatch}"
if "${libexec}/helpers/mcloving-env-guard" db-init "${db_mismatch}" >/dev/null 2>&1; then
  echo "env guard accepted a bootstrap whose URL and container name different databases" >&2
  exit 1
fi
rm -f "${db_mismatch}"

# Deployment directories must not inherit a permissive umask. World-writable
# releases or helpers lets another local user rename a verified binary out and
# a chosen one in -- code execution as the service account with every file
# still 0755.
umask_home="${workdir}/umask-home"
rm -rf "${umask_home}"
mkdir -p "${umask_home}"
( umask 000
  "${repo_root}/deploy/bin/mcloving-install" --home "${umask_home}" \
    --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
    --no-systemd >/dev/null )
for guarded_dir in \
  "${umask_home}/.local/libexec/mcloving" \
  "${umask_home}/.local/libexec/mcloving/helpers" \
  "${umask_home}/.local/libexec/mcloving/releases" \
  "${umask_home}/.local/libexec/mcloving/current" \
  "${umask_home}/.config/mcloving" \
  "${umask_home}/.config/systemd/user" \
  "${umask_home}/.config/containers/systemd"; do
  mode="$(stat -Lc '%a' "${guarded_dir}")"
  case "${mode}" in
    *[2367])
      echo "deployment directory ${guarded_dir} is group- or world-writable (${mode})" >&2
      exit 1
      ;;
  esac
done
rm -rf "${umask_home}"

# A PRE-EXISTING writable ancestor is repaired by neither the umask nor the
# chmods on the managed roots: the install must refuse it by name, create
# nothing under it, and accept the same home once the ancestor is secured.
preexisting_home="${workdir}/preexisting-home"
rm -rf "${preexisting_home}"
mkdir -p "${preexisting_home}/.local"
chmod 0777 "${preexisting_home}/.local"
if "${repo_root}/deploy/bin/mcloving-install" --home "${preexisting_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/preexisting-ancestor.log" 2>&1; then
  echo "install accepted a pre-existing world-writable ancestor" >&2
  exit 1
fi
grep -q "group- or world-writable" "${workdir}/logs/preexisting-ancestor.log" || {
  echo "the writable-ancestor refusal fired for the wrong reason:" >&2
  cat "${workdir}/logs/preexisting-ancestor.log" >&2
  exit 1
}
grep -q "\.local (mode 777)" "${workdir}/logs/preexisting-ancestor.log" || {
  echo "the writable-ancestor refusal did not name the offender and its mode:" >&2
  cat "${workdir}/logs/preexisting-ancestor.log" >&2
  exit 1
}
if [[ -e "${preexisting_home}/.local/libexec" ]]; then
  echo "a refused install still created deployment directories" >&2
  exit 1
fi
chmod 0755 "${preexisting_home}/.local"
"${repo_root}/deploy/bin/mcloving-install" --home "${preexisting_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${preexisting_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete after the ancestor was secured" >&2
  exit 1
}
rm -rf "${preexisting_home}"

# The TARGET of a symlinked ancestor has parents of its own -- the fourth
# instance of the ancestor class. With ~/.local -> stash/dot-local, checking
# the target directory itself while never walking stash leaves the one
# rename that swaps the whole deployment aside unexamined. The install must
# refuse a writable target parent by name, create nothing, and accept the
# same home once it is secured; the digest inventory must record it and
# change when its mode changes.
relocated_home="${workdir}/relocated-home"
rm -rf "${relocated_home}"
mkdir -p "${relocated_home}/stash/dot-local"
ln -s "stash/dot-local" "${relocated_home}/.local"
chmod 0777 "${relocated_home}/stash"
if "${repo_root}/deploy/bin/mcloving-install" --home "${relocated_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/relocated-ancestor.log" 2>&1; then
  echo "install accepted a symlinked ancestor whose target parent is world-writable" >&2
  exit 1
fi
grep -q "stash (mode 777)" "${workdir}/logs/relocated-ancestor.log" || {
  echo "the writable target-parent refusal did not name the offender:" >&2
  cat "${workdir}/logs/relocated-ancestor.log" >&2
  exit 1
}
if [[ -e "${relocated_home}/stash/dot-local/libexec" ]]; then
  echo "a refused install still created directories under the symlink target" >&2
  exit 1
fi
chmod 0755 "${relocated_home}/stash"
"${repo_root}/deploy/bin/mcloving-install" --home "${relocated_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${relocated_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete through a secured symlinked ancestor" >&2
  exit 1
}
# The inventory side of the same class: the resolved target's parent must be
# a recorded ancestor, and relaxing it must change the canonical document.
relocated_before="$("${relocated_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${relocated_home}")"
chmod 0777 "${relocated_home}/stash"
relocated_after="$("${relocated_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${relocated_home}")"
chmod 0755 "${relocated_home}/stash"
if [[ "${relocated_before}" == "${relocated_after}" ]]; then
  echo "a world-writable symlink-target parent left the digest re-read unchanged" >&2
  exit 1
fi
python3 - "${relocated_after}" <<'TARGETPARENT'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("ancestors", [])}
entry = records.get("stash")
if entry is None:
    raise SystemExit(
        f"symlink-target parent missing from the ancestors: {sorted(records)}"
    )
if entry.get("mode") != 0o777:
    raise SystemExit(f"symlink-target parent mode not recorded: {entry}")
TARGETPARENT
rm -rf "${relocated_home}"

# Ownership is the fifth face of the same class: a chain component owned by
# a third user is unsafe at ANY mode, because its owner can chmod it
# writable at will and then rename children like any writable ancestor
# permits. `podman unshare chown` writes a REAL foreign uid (the first
# subuid) to disk without root, and the suite already requires rootless
# podman, so this gate exercises genuine ownership rather than a stub.
foreign_home="${workdir}/foreign-owner-home"
rm -rf "${foreign_home}"
mkdir -p "${foreign_home}/.local"
podman unshare chown 1:1 "${foreign_home}/.local"
if "${repo_root}/deploy/bin/mcloving-install" --home "${foreign_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/foreign-owner.log" 2>&1; then
  echo "install accepted an ancestor owned by a third user" >&2
  exit 1
fi
grep -q "\.local (owned by uid .*, expected uid $(id -u) or root)" \
  "${workdir}/logs/foreign-owner.log" || {
  echo "the foreign-owner refusal did not name the component and uids:" >&2
  cat "${workdir}/logs/foreign-owner.log" >&2
  exit 1
}
if [[ -e "${foreign_home}/.local/libexec" ]]; then
  echo "a refused install still created directories under a foreign-owned ancestor" >&2
  exit 1
fi
podman unshare chown 0:0 "${foreign_home}/.local"
"${repo_root}/deploy/bin/mcloving-install" --home "${foreign_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${foreign_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete after ownership was restored" >&2
  exit 1
}
rm -rf "${foreign_home}"

# systemd, not the installer, creates the StateDirectory= leaves under
# ~/.local/state -- so the validator derives those roots from the staged
# unit declarations themselves, and a pre-existing writable state ancestor
# must refuse the install even though no install command ever touches it.
state_home="${workdir}/state-ancestor-home"
rm -rf "${state_home}"
mkdir -p "${state_home}/.local/state"
chmod 0777 "${state_home}/.local/state"
if "${repo_root}/deploy/bin/mcloving-install" --home "${state_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/state-ancestor.log" 2>&1; then
  echo "install accepted a pre-existing world-writable runtime-state ancestor" >&2
  exit 1
fi
grep -q "\.local/state (mode 777)" "${workdir}/logs/state-ancestor.log" || {
  echo "the state-ancestor refusal did not name the directory and mode:" >&2
  cat "${workdir}/logs/state-ancestor.log" >&2
  exit 1
}
chmod 0755 "${state_home}/.local/state"
"${repo_root}/deploy/bin/mcloving-install" --home "${state_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${state_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete after the state ancestor was secured" >&2
  exit 1
}
rm -rf "${state_home}"

# The user manager honors XDG_CONFIG_HOME (the unit search root moves) and
# XDG_STATE_HOME (StateDirectory leaves are created there), so the lane
# derives every base the same way: units and quadlets land where systemctl
# --user actually looks, the units-declared state roots are validated in
# the tree systemd will actually use, and the inventory walks the same
# dirs. Contracts stay at %h/.config/mcloving -- the literal text of the
# units' EnvironmentFile= lines, which %h-expansion keeps XDG-independent.
# A relative XDG value is ignored exactly as systemd ignores it.
xdg_home="${workdir}/xdg-home"
rm -rf "${xdg_home}"
mkdir -p "${xdg_home}/custom-config" "${xdg_home}/custom-state"
chmod 0777 "${xdg_home}/custom-state"
if XDG_CONFIG_HOME="${xdg_home}/custom-config" \
  XDG_STATE_HOME="${xdg_home}/custom-state" \
  "${repo_root}/deploy/bin/mcloving-install" --home "${xdg_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/xdg-state-ancestor.log" 2>&1; then
  echo "install accepted a world-writable custom XDG state root" >&2
  exit 1
fi
grep -q "custom-state (mode 777)" "${workdir}/logs/xdg-state-ancestor.log" || {
  echo "the custom-state refusal did not name the derived tree:" >&2
  cat "${workdir}/logs/xdg-state-ancestor.log" >&2
  exit 1
}
chmod 0755 "${xdg_home}/custom-state"
XDG_CONFIG_HOME="${xdg_home}/custom-config" \
  XDG_STATE_HOME="${xdg_home}/custom-state" \
  "${repo_root}/deploy/bin/mcloving-install" --home "${xdg_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -f "${xdg_home}/custom-config/systemd/user/mcloving-controller.service" ]] || {
  echo "units were not written under the manager's XDG configuration root" >&2
  exit 1
}
[[ -f "${xdg_home}/custom-config/containers/systemd/mcloving-postgres.container" ]] || {
  echo "quadlets were not written under the manager's XDG configuration root" >&2
  exit 1
}
[[ ! -e "${xdg_home}/.config/systemd/user/mcloving-controller.service" ]] || {
  echo "units were duplicated under the hard-coded default root" >&2
  exit 1
}
[[ -f "${xdg_home}/.config/mcloving/agent.env" ]] || {
  echo "contracts left %h/.config/mcloving, where the units' own text points" >&2
  exit 1
}
xdg_digests="$(XDG_CONFIG_HOME="${xdg_home}/custom-config" \
  XDG_STATE_HOME="${xdg_home}/custom-state" \
  "${xdg_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${xdg_home}")"
python3 - "${xdg_digests}" <<'XDGUNITS'
import json
import sys

document = json.loads(sys.argv[1])
paths = {record["path"] for record in document.get("units", [])}
if not any(p.endswith("custom-config/systemd/user/mcloving-controller.service") for p in paths):
    raise SystemExit(f"inventory did not walk the XDG unit root: {sorted(paths)}")
XDGUNITS
xdg_state_roots="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${xdg_home}/.local/libexec/mcloving/helpers/mcloving-deploy-lib.sh"
  XDG_STATE_HOME="${xdg_home}/custom-state" deployment_unit_declared_roots \
    "${xdg_home}" "${repo_root}"/deploy/systemd/*.service \
    | while IFS= read -r encoded_root; do
        [[ -n "${encoded_root}" ]] || continue
        decode_path_item_into decoded_root "${encoded_root}"
        # shellcheck disable=SC2154  # decoded_root is set via the nameref above
        printf '%s\n' "${decoded_root}"
      done
)"
grep -q "^${xdg_home}/custom-state/mcloving-agent/workspace$" <<<"${xdg_state_roots}" || {
  echo "the declared-roots parser did not follow XDG_STATE_HOME:" >&2
  printf '%s\n' "${xdg_state_roots}" >&2
  exit 1
}
# AND THE CONTRACT NAMES THAT SAME TREE, which is the half that was
# missing. The declared-roots parser has followed XDG_STATE_HOME since round
# 32; the installed contract had not -- so systemd created
# <custom-state>/mcloving-agent/workspace while the contract still named
# ~/.local/state/mcloving-agent/workspace, and the guard refused startup for
# a workspace nothing had ever been asked to create. The two derivations are
# COMPARED rather than each asserted against a spelling written out here,
# because agreeing with each other is the property that matters.
xdg_workspace="$(sed -n 's/^MCLOVING_AGENT_WORKSPACE_ROOT=//p' \
  "${xdg_home}/.config/mcloving/agent.env")"
grep -qxF "${xdg_workspace}" <<<"${xdg_state_roots}" || {
  echo "the contract's workspace root (${xdg_workspace}) is not one of the units' declared state roots:" >&2
  printf '%s\n' "${xdg_state_roots}" >&2
  exit 1
}
[[ "${xdg_workspace}" == "${xdg_home}/custom-state/mcloving-agent/workspace" ]] || {
  echo "the installed contract does not name the workspace systemd creates under XDG_STATE_HOME: ${xdg_workspace}" >&2
  exit 1
}
# The pre-fix content is still on disk to compare against: the example names
# its workspace under the template home, and copying that verbatim is what
# named a tree that was never created.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
  grep -q "^MCLOVING_AGENT_WORKSPACE_ROOT=${MCLOVING_CONTRACT_TEMPLATE_HOME}/\.local/state/" \
    "${repo_root}/deploy/env/agent.env.example" || {
    echo "the shipped example no longer spells its workspace under the template home; this gate no longer describes the defect" >&2
    exit 1
  }
)
# The guard's own verdict, which is where the operator met this: with the
# state tree created where systemd would create it, the rendered contract
# passes; the default tree the pre-fix copy named is not even there.
mkdir -p "${xdg_home}/custom-state/mcloving-agent/workspace"
[[ ! -e "${xdg_home}/.local/state/mcloving-agent/workspace" ]] || {
  echo "the default state tree exists, so this gate cannot tell the two spellings apart" >&2
  exit 1
}
rm -rf "${xdg_home}"
# A relative XDG value is ignored, exactly as systemd ignores it.
relative_xdg_home="${workdir}/relative-xdg-home"
rm -rf "${relative_xdg_home}"
mkdir -p "${relative_xdg_home}"
XDG_CONFIG_HOME="relative-config" XDG_STATE_HOME="also/relative" \
  "${repo_root}/deploy/bin/mcloving-install" --home "${relative_xdg_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -f "${relative_xdg_home}/.config/systemd/user/mcloving-controller.service" ]] || {
  echo "a relative XDG_CONFIG_HOME was not ignored like systemd ignores it" >&2
  exit 1
}
[[ ! -e "${relative_xdg_home}/relative-config" ]] || {
  echo "a relative XDG_CONFIG_HOME was honored as a path" >&2
  exit 1
}
rm -rf "${relative_xdg_home}"
# An absolute XDG base inherited from ANOTHER account's environment -- the
# CI runner's exported XDG_CONFIG_HOME was exactly this -- must be ignored
# for an alternate target home: it describes nobody's view of that tree,
# and honoring it wrote a scratch deployment's units into the runner's
# real configuration root.
foreign_xdg_home="${workdir}/foreign-xdg-home"
rm -rf "${foreign_xdg_home}" "${workdir}/foreign-config"
mkdir -p "${foreign_xdg_home}"
XDG_CONFIG_HOME="${workdir}/foreign-config" \
  "${repo_root}/deploy/bin/mcloving-install" --home "${foreign_xdg_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -f "${foreign_xdg_home}/.config/systemd/user/mcloving-controller.service" ]] || {
  echo "a foreign XDG base kept units out of the target home's default root" >&2
  exit 1
}
[[ ! -e "${workdir}/foreign-config" ]] || {
  echo "an install honored an XDG base belonging to another account's tree" >&2
  exit 1
}
rm -rf "${foreign_xdg_home}"

# One realpath of the whole root keeps only the FINAL chain. With
# .local -> srv-a/user-local and user-local/libexec -> opt-m/libexec, the
# opt-m chain is walked but srv-a is the directory whose writability lets
# another user replace user-local wholesale -- so the derivation resolves
# component by component and every intermediate target's parents join the
# set. Refused writable by name, accepted once secured, and visible to the
# digest inventory in both states.
twohop_home="${workdir}/twohop-home"
rm -rf "${twohop_home}"
mkdir -p "${twohop_home}/srv-a/user-local" "${twohop_home}/opt-m/libexec"
chmod 0755 "${twohop_home}" "${twohop_home}/srv-a" "${twohop_home}/srv-a/user-local" \
  "${twohop_home}/opt-m" "${twohop_home}/opt-m/libexec"
ln -s "srv-a/user-local" "${twohop_home}/.local"
ln -s "${twohop_home}/opt-m/libexec" "${twohop_home}/srv-a/user-local/libexec"
chmod 0777 "${twohop_home}/srv-a"
if "${repo_root}/deploy/bin/mcloving-install" --home "${twohop_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/twohop.log" 2>&1; then
  echo "install accepted a writable intermediate symlink-target parent" >&2
  exit 1
fi
grep -q "srv-a (mode 777)" "${workdir}/logs/twohop.log" || {
  echo "the intermediate target-parent refusal did not name srv-a:" >&2
  cat "${workdir}/logs/twohop.log" >&2
  exit 1
}
if [[ -e "${twohop_home}/opt-m/libexec/mcloving" ]]; then
  echo "a refused install still created directories through the two-hop chain" >&2
  exit 1
fi
chmod 0755 "${twohop_home}/srv-a"
"${repo_root}/deploy/bin/mcloving-install" --home "${twohop_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${twohop_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete through the secured two-hop chain" >&2
  exit 1
}
twohop_before="$("${twohop_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${twohop_home}")"
chmod 0777 "${twohop_home}/srv-a"
twohop_after="$("${twohop_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${twohop_home}")"
chmod 0755 "${twohop_home}/srv-a"
if [[ "${twohop_before}" == "${twohop_after}" ]]; then
  echo "a relaxed intermediate target parent left the digest re-read unchanged" >&2
  exit 1
fi
python3 - "${twohop_after}" <<'TWOHOP'
import json
import sys

document = json.loads(sys.argv[1])
records = {record["path"]: record for record in document.get("ancestors", [])}
entry = records.get("srv-a")
if entry is None:
    raise SystemExit(f"intermediate target parent missing: {sorted(records)}")
if entry.get("mode") != 0o777:
    raise SystemExit(f"intermediate target parent mode not recorded: {entry}")
if "opt-m" not in records:
    raise SystemExit(f"final target parent missing: {sorted(records)}")
TWOHOP
twohop_restored="$("${twohop_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${twohop_home}")"
[[ "${twohop_before}" == "${twohop_restored}" ]] || {
  echo "the two-hop re-read did not return to baseline" >&2
  exit 1
}
rm -rf "${twohop_home}"

# pki heads a subtree of keys and certificates and is created and secured by
# this installer, so it is a managed root in its own right: a pre-existing
# pki symlink must have its target chain judged -- writable parent and
# foreign-owned parent refused by name, secured chain accepted.
pki_home="${workdir}/pki-link-home"
rm -rf "${pki_home}"
mkdir -p "${pki_home}/shared/pki" "${pki_home}/.config/mcloving"
chmod 0755 "${pki_home}" "${pki_home}/shared" "${pki_home}/shared/pki" \
  "${pki_home}/.config" "${pki_home}/.config/mcloving"
ln -s "../../shared/pki" "${pki_home}/.config/mcloving/pki"
chmod 0777 "${pki_home}/shared"
if "${repo_root}/deploy/bin/mcloving-install" --home "${pki_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/pki-link.log" 2>&1; then
  echo "install accepted a pki symlink whose target parent is world-writable" >&2
  exit 1
fi
grep -q "shared (mode 777)" "${workdir}/logs/pki-link.log" || {
  echo "the pki target-parent refusal did not name shared:" >&2
  cat "${workdir}/logs/pki-link.log" >&2
  exit 1
}
chmod 0755 "${pki_home}/shared"
podman unshare chown 1:1 "${pki_home}/shared"
if "${repo_root}/deploy/bin/mcloving-install" --home "${pki_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/pki-link-owner.log" 2>&1; then
  echo "install accepted a pki symlink whose target parent is foreign-owned" >&2
  exit 1
fi
grep -q "shared (owned by uid .*, expected uid $(id -u) or root)" \
  "${workdir}/logs/pki-link-owner.log" || {
  echo "the pki foreign-owner refusal did not name shared and the uids:" >&2
  cat "${workdir}/logs/pki-link-owner.log" >&2
  exit 1
}
podman unshare chown 0:0 "${pki_home}/shared"
"${repo_root}/deploy/bin/mcloving-install" --home "${pki_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -x "${pki_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete with a secured pki symlink" >&2
  exit 1
}
[[ "$(stat -Lc '%a' "${pki_home}/.config/mcloving/pki")" == "700" ]] || {
  echo "the pki symlink target was not secured to 0700" >&2
  exit 1
}
rm -rf "${pki_home}"

# A PRESERVED contract may be a pre-existing symlink: `-f` follows it, the
# preserve branch keeps it, and whoever can write its target chain -- or
# the resolved target file itself -- controls the environment systemd
# loads. The contract destinations are therefore validated as roots (chain)
# and as files (mode/ownership), in both directions.
ctlink_home="${workdir}/contract-link-home"
rm -rf "${ctlink_home}"
mkdir -p "${ctlink_home}/ext" "${ctlink_home}/.config/mcloving"
chmod 0755 "${ctlink_home}" "${ctlink_home}/ext" \
  "${ctlink_home}/.config" "${ctlink_home}/.config/mcloving"
# The marker lives in this project's own namespace, like every variable a
# real contract declares: the contract allowlist is default-deny, so a
# fixture using a foreign name would be refused for the right reason and
# fail this gate for the wrong one.
printf 'MCLOVING_PRESERVED_MARKER=%s\n' "${suffix}" > "${ctlink_home}/ext/agent.env"
chmod 0600 "${ctlink_home}/ext/agent.env"
ln -s "${ctlink_home}/ext/agent.env" "${ctlink_home}/.config/mcloving/agent.env"
chmod 0777 "${ctlink_home}/ext"
if "${repo_root}/deploy/bin/mcloving-install" --home "${ctlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/contract-link.log" 2>&1; then
  echo "install preserved a contract symlink whose target parent is world-writable" >&2
  exit 1
fi
grep -q "ext (mode 777)" "${workdir}/logs/contract-link.log" || {
  echo "the contract target-parent refusal did not name ext:" >&2
  cat "${workdir}/logs/contract-link.log" >&2
  exit 1
}
chmod 0755 "${ctlink_home}/ext"
chmod 0666 "${ctlink_home}/ext/agent.env"
if "${repo_root}/deploy/bin/mcloving-install" --home "${ctlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/contract-file-mode.log" 2>&1; then
  echo "install preserved a world-writable contract file" >&2
  exit 1
fi
grep -q "agent.env (mode 666, expected owner-only)" \
  "${workdir}/logs/contract-file-mode.log" || {
  echo "the writable contract-file refusal did not name the file and mode:" >&2
  cat "${workdir}/logs/contract-file-mode.log" >&2
  exit 1
}
# Read bits are secrets too: 0644 exposes database passwords and API tokens
# to every user on the host even though nobody else can write the file.
chmod 0644 "${ctlink_home}/ext/agent.env"
if "${repo_root}/deploy/bin/mcloving-install" --home "${ctlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/contract-file-read.log" 2>&1; then
  echo "install preserved a group/other-readable secret-bearing contract" >&2
  exit 1
fi
grep -q "agent.env (mode 644, expected owner-only)" \
  "${workdir}/logs/contract-file-read.log" || {
  echo "the readable contract-file refusal did not name the file and mode:" >&2
  cat "${workdir}/logs/contract-file-read.log" >&2
  exit 1
}
chmod 0600 "${ctlink_home}/ext/agent.env"
podman unshare chown 1:1 "${ctlink_home}/ext/agent.env"
if "${repo_root}/deploy/bin/mcloving-install" --home "${ctlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/contract-file-owner.log" 2>&1; then
  echo "install preserved a foreign-owned contract file" >&2
  exit 1
fi
grep -q "agent.env (owned by uid .*, expected uid $(id -u) or root)" \
  "${workdir}/logs/contract-file-owner.log" || {
  echo "the foreign-owned contract-file refusal did not name the file and uids:" >&2
  cat "${workdir}/logs/contract-file-owner.log" >&2
  exit 1
}
# The same subuid-owned 0600 file is genuinely unreadable by this user, so
# the availability annotation must appear beside the ownership one:
# writability and ownership guard substitution, readability guards
# availability, and an install must accept no contract the runtime cannot
# read.
grep -q "agent.env (unreadable by uid $(id -u))" \
  "${workdir}/logs/contract-file-owner.log" || {
  echo "the unreadable contract-file refusal did not name the file and uid:" >&2
  cat "${workdir}/logs/contract-file-owner.log" >&2
  exit 1
}
podman unshare chown 0:0 "${ctlink_home}/ext/agent.env"
"${repo_root}/deploy/bin/mcloving-install" --home "${ctlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
[[ -L "${ctlink_home}/.config/mcloving/agent.env" ]] || {
  echo "install replaced a secured preserved contract symlink" >&2
  exit 1
}
grep -q "MCLOVING_PRESERVED_MARKER=${suffix}" "${ctlink_home}/.config/mcloving/agent.env" || {
  echo "install did not preserve the secured contract's content" >&2
  exit 1
}
rm -rf "${ctlink_home}"

# The managed-roots list stays honest mechanically: an install is traced
# with xtrace, every directory-touching command's path under its home is
# parsed from the trace, and each must be covered by the very root set the
# installer passed to require_secure_ancestors -- itself read from the same
# trace, so there is no second copy of the list to drift.
trace_home="${workdir}/trace-home"
rm -rf "${trace_home}"
mkdir -p "${trace_home}"
bash -x "${repo_root}/deploy/bin/mcloving-install" --home "${trace_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > /dev/null 2> "${workdir}/logs/install-trace.log"
python3 - "${workdir}/logs/install-trace.log" "${trace_home}" <<'TRACECOVER'
import shlex
import sys

trace_path, home = sys.argv[1], sys.argv[2]
home = home.rstrip("/")
prefix = home + "/"
roots = None
touched = set()
commands = {"mkdir", "chmod", "install", "ln"}
for raw in open(trace_path, encoding="utf-8", errors="replace"):
    line = raw.lstrip()
    if not line.startswith("+"):
        continue
    line = line.lstrip("+ ").rstrip("\n")
    try:
        tokens = shlex.split(line)
    except ValueError:
        continue
    if not tokens:
        continue
    if tokens[0] == "require_secure_ancestors":
        # The install now performs its own walk AND the transition-grade
        # revalidation of the installed tree: coverage is the UNION of
        # every validated root set, not whichever call traced last.
        if roots is None:
            roots = []
        roots.extend(token for token in tokens[2:] if token.startswith(prefix))
        continue
    if tokens[0] not in commands:
        continue
    for token in tokens[1:]:
        if token.startswith(prefix):
            touched.add(token.rstrip("/"))
if not roots:
    raise SystemExit("trace never showed require_secure_ancestors with its roots")
if not touched:
    raise SystemExit("trace parsing found no touched paths; the xtrace format drifted")
if not any(path.endswith("/pki") for path in touched):
    raise SystemExit(f"expected core paths missing from the parsed trace: {sorted(touched)}")
if not any("/.local/state/" in root for root in roots):
    raise SystemExit(
        "no units-derived runtime-state root reached the ancestor walk; "
        "the unit-declaration parser has gone blind: " + " ".join(sorted(roots))
    )
uncovered = []
for path in sorted(touched):
    covered = path == home or any(
        path == root or path.startswith(root + "/") or root.startswith(path + "/")
        for root in roots
    )
    if not covered:
        uncovered.append(path)
if uncovered:
    raise SystemExit(
        "installer touches paths not covered by its validated roots: "
        + " ".join(uncovered)
    )
TRACECOVER
rm -rf "${trace_home}"

# A RELATIVE --home must see exactly what the absolute spelling sees. The
# component walk used to anchor resolution at "/", so relative-home/.local
# was inspected as /relative-home/.local -- a tree that does not exist --
# and an install through a relative home accepted a symlinked .local whose
# target parent was world-writable. Refusal through the relative spelling,
# acceptance once secured, and document identity across both spellings.
relative_home_name="relative-home"
relative_home="${workdir}/${relative_home_name}"
rm -rf "${relative_home}"
mkdir -p "${relative_home}/stash/dot-local"
chmod 0755 "${relative_home}" "${relative_home}/stash" "${relative_home}/stash/dot-local"
ln -s "stash/dot-local" "${relative_home}/.local"
chmod 0777 "${relative_home}/stash"
if ( cd "${workdir}" && "${repo_root}/deploy/bin/mcloving-install" \
  --home "${relative_home_name}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd ) > "${workdir}/logs/relative-home.log" 2>&1; then
  echo "a relative --home install accepted a writable symlink-target parent" >&2
  exit 1
fi
grep -q "stash (mode 777)" "${workdir}/logs/relative-home.log" || {
  echo "the relative-home refusal did not name the target parent:" >&2
  cat "${workdir}/logs/relative-home.log" >&2
  exit 1
}
chmod 0755 "${relative_home}/stash"
( cd "${workdir}" && "${repo_root}/deploy/bin/mcloving-install" \
  --home "${relative_home_name}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd ) >/dev/null
[[ -x "${relative_home}/.local/libexec/mcloving/current/mcloving-cli" ]] || {
  echo "install did not complete through a relative --home once secured" >&2
  exit 1
}
relative_doc="$( cd "${workdir}" && "${relative_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${relative_home_name}" )"
absolute_doc="$("${relative_home}/.local/libexec/mcloving/helpers/mcloving-deployed-digests" \
  --home "${relative_home}")"
if [[ "${relative_doc}" != "${absolute_doc}" ]]; then
  echo "the canonical document differs between relative and absolute --home spellings" >&2
  exit 1
fi
rm -rf "${relative_home}"

# The bootstrap's two halves must address one instance, not merely one database
# name: provisioning runs podman exec into the local container.
for bad_url in "postgres://mcloving:pw@remote.example:5432/mcloving" \
  "postgres://someoneelse:pw@127.0.0.1:5432/mcloving"; do
  endpoint_contract="${home}/endpoint.env"
  cp "${config_dir}/db-init.env" "${endpoint_contract}"
  sed -i "s#^MCLOVING_MIGRATION_DATABASE_URL=.*#MCLOVING_MIGRATION_DATABASE_URL=${bad_url}#" \
    "${endpoint_contract}"
  if "${libexec}/helpers/mcloving-env-guard" db-init "${endpoint_contract}" >/dev/null 2>&1; then
    echo "env guard accepted a bootstrap URL addressing ${bad_url}" >&2
    exit 1
  fi
  rm -f "${endpoint_contract}"
done

# The controller migrates through one URL and opens its runtime pool through
# the other, so both must name one database instance, not merely distinct roles.
for endpoint_edit in \
  "s#\(^MCLOVING_DATABASE_URL=.*127.0.0.1\):[0-9]*#\\1:6543#" \
  "s#\(^MCLOVING_DATABASE_URL=.*\)/mcloving\$#\\1/otherdb#"; do
  endpoint_contract="${home}/controller-endpoint.env"
  cp "${config_dir}/controller.env" "${endpoint_contract}"
  sed -i "${endpoint_edit}" "${endpoint_contract}"
  if cmp -s "${endpoint_contract}" "${config_dir}/controller.env"; then
    echo "controller endpoint gate did not modify the contract; shape changed" >&2
    exit 1
  fi
  if "${libexec}/helpers/mcloving-env-guard" controller "${endpoint_contract}" >/dev/null 2>&1; then
    echo "env guard accepted controller URLs addressing different databases" >&2
    exit 1
  fi
  rm -f "${endpoint_contract}"
done

# A readable directory is not a readable file. `-r` alone accepts one, and the
# binary would then fail at startup on a contract the guard called satisfied.
dir_contract="${home}/dir-contract.env"
cp "${config_dir}/agent.env" "${dir_contract}"
sed -i "s#^MCLOVING_AGENT_PRIVATE_KEY_PATH=.*#MCLOVING_AGENT_PRIVATE_KEY_PATH=${config_dir}/pki#" \
  "${dir_contract}"
if "${libexec}/helpers/mcloving-env-guard" agent "${dir_contract}" >/dev/null 2>&1; then
  echo "env guard accepted a directory where a regular file is required" >&2
  exit 1
fi
rm -f "${dir_contract}"

# Staging must not survive a refused install. verify_release_dir exits through
# deploy_fail, which ends the command-substitution subshell, so cleanup has to
# be a trap; otherwise unverified binaries stay under releases/.staging.* and
# the digest re-read reports them as part of the release inventory.
staging_home="${workdir}/staging-home"
rm -rf "${staging_home}"
mkdir -p "${staging_home}"
if "${repo_root}/deploy/bin/mcloving-install" --home "${staging_home}" \
  --release-dir "${tampered_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "install accepted a tampered release" >&2
  exit 1
fi
if compgen -G "${staging_home}/.local/libexec/mcloving/releases/.staging.*" >/dev/null; then
  echo "a refused install left unverified binaries under releases/.staging.*" >&2
  exit 1
fi
rm -rf "${staging_home}"

# Publication must fail loudly. Both callers run stage_release inside command
# substitution, where bash clears errexit, so a failed mv would otherwise fall
# through and report a staged release that is not there -- after the upgrade
# has already stopped the services. Driven through the upgrade path: an
# install into a releases-populated home without a current link is now the
# established-deployment refusal, a different gate.
blocked_home="${workdir}/blocked-home"
rm -rf "${blocked_home}"
mkdir -p "${blocked_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${blocked_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
blocked_libexec="${blocked_home}/.local/libexec/mcloving"
blocked_current="$(readlink "${blocked_libexec}/current")"
blocked_id="$(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  release_id "${release2_dir}"
)"
# A regular file sitting where the release directory must go.
printf 'not a directory\n' > "${blocked_libexec}/releases/${blocked_id}"
if "${repo_root}/deploy/bin/mcloving-upgrade" --home "${blocked_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null 2>&1; then
  echo "upgrade reported success when the release could not be published" >&2
  exit 1
fi
[[ "$(readlink "${blocked_libexec}/current")" == "${blocked_current}" ]] || {
  echo "a failed publication still moved the current release" >&2
  exit 1
}
if compgen -G "${blocked_libexec}/releases/.staging.*" >/dev/null; then
  echo "a failed publication left staging behind" >&2
  exit 1
fi
rm -rf "${blocked_home}"

# An established deployment that lost its current link is refused by name,
# never re-initialized as fresh -- and restoring the link by hand readmits
# the normal paths, which is the only sanctioned repair.
lostlink_home="${workdir}/lostlink-home"
rm -rf "${lostlink_home}"
mkdir -p "${lostlink_home}"
"${repo_root}/deploy/bin/mcloving-install" --home "${lostlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd >/dev/null
lostlink_libexec="${lostlink_home}/.local/libexec/mcloving"
lostlink_target="$(readlink "${lostlink_libexec}/current")"
rm -f "${lostlink_libexec}/current"
if "${repo_root}/deploy/bin/mcloving-install" --home "${lostlink_home}" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --no-systemd > "${workdir}/logs/lostlink.log" 2>&1; then
  echo "install re-initialized an established deployment missing its current link" >&2
  exit 1
fi
grep -q "established (releases are present) but the current link is missing" \
  "${workdir}/logs/lostlink.log" || {
  echo "the lost-link refusal was not named:" >&2
  cat "${workdir}/logs/lostlink.log" >&2
  exit 1
}
grep -q "No sanctioned automated repair exists" "${workdir}/logs/lostlink.log" || {
  echo "the lost-link refusal did not state the repair posture:" >&2
  cat "${workdir}/logs/lostlink.log" >&2
  exit 1
}
[[ -d "${lostlink_libexec}/releases/$(basename "${lostlink_target}")" ]] || {
  echo "the lost-link refusal disturbed the retained releases" >&2
  exit 1
}
ln -s "${lostlink_target}" "${lostlink_libexec}/current"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${lostlink_home}" \
  --release-dir "${release2_dir}" --checksums "${workdir}/checksums2.sha256" \
  --no-systemd >/dev/null
[[ "$(readlink "${lostlink_libexec}/current")" != "${lostlink_target}" ]] || {
  echo "the restored link did not readmit the upgrade path" >&2
  exit 1
}
rm -rf "${lostlink_home}"

# systemd accepts a quoted multiline value that ends in a newline and passes it
# to the service intact. A guard reading contracts through command substitution
# would silently validate the value without it and report a contract satisfied
# that the binary then refuses, so the reader must reproduce the exact bytes.
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  declare -gA MCLOVING_CONTRACT
  MCLOVING_CONTRACT[NEWLINE_PATH]=$'/tmp/key.pem\n'
  contract_into exact NEWLINE_PATH
  # shellcheck disable=SC2154  # contract_into assigns through a nameref
  [[ "${exact}" == $'/tmp/key.pem\n' ]] || {
    echo "contract reader dropped a trailing newline systemd would supply" >&2
    exit 1
  }
)

# Distinct database roles are not enough: the controller requires the runtime
# session role to be exactly mcloving_tenant, so a second privileged role must
# be refused before anything binds a listener.
tenant_swap="${home}/tenant-swap.env"
cp "${config_dir}/controller.env" "${tenant_swap}"
sed -i "s#\(^MCLOVING_DATABASE_URL=.*\)mcloving_tenant#\1mcloving_admin#" "${tenant_swap}"
if grep -q "mcloving_admin" "${tenant_swap}"; then
  if "${libexec}/helpers/mcloving-env-guard" controller "${tenant_swap}" >/dev/null 2>&1; then
    echo "env guard accepted a runtime role other than mcloving_tenant" >&2
    exit 1
  fi
else
  echo "tenant-role gate could not rewrite MCLOVING_DATABASE_URL; contract shape changed" >&2
  exit 1
fi
rm -f "${tenant_swap}"

# `stat()` succeeding does not mean the bytes can be read. A contract whose
# mode or ACL withdrew access is drift, and losing the whole canonical document
# to it would deny CUTOVER-001 the re-read exactly when it matters.
echo "locked" > "${config_dir}/locked.env"
chmod 000 "${config_dir}/locked.env"
if [[ -r "${config_dir}/locked.env" ]]; then
  # Running as root (or under a permissive ACL) defeats mode 000, so the gate
  # cannot be asserted here. Say so rather than passing silently.
  echo "NOTE: ${config_dir}/locked.env is still readable at mode 000; skipping the unreadable-file gate" >&2
  rm -f "${config_dir}/locked.env"
else
  unreadable_digests="$(timeout 60 "${libexec}/helpers/mcloving-deployed-digests" --home "${home}")" || {
    echo "digest re-read failed on an unreadable file instead of recording it" >&2
    rm -f "${config_dir}/locked.env"
    exit 1
  }
  rm -f "${config_dir}/locked.env"
  python3 - "${unreadable_digests}" <<'UNREADABLE'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
entry = [item for item in contracts if item["path"].endswith("/locked.env")]
if not entry:
    raise SystemExit("unreadable file missing from the re-read")
if entry[0].get("kind") != "unreadable":
    raise SystemExit(f"unreadable file recorded as {entry[0]}")
if entry[0].get("reason") != "permission_denied":
    raise SystemExit(f"unreadable file recorded without its reason: {entry[0]}")
if "sha256" in entry[0]:
    raise SystemExit("unreadable file was recorded with a digest it could not compute")
UNREADABLE
fi

# A symlinked unit root must survive the mcloving-* name filter: the root is
# named `user`, so filtering it out would leave the document unchanged while
# systemd read an entirely different tree.
unit_root="${smoke_unit_root}"
cp -a "${unit_root}" "${unit_root}.alias"
mv "${unit_root}" "${unit_root}.real"
ln -s "user.alias" "${unit_root}"
unit_alias_digests="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
rm -f "${unit_root}"
rm -rf "${unit_root}.alias"
mv "${unit_root}.real" "${unit_root}"
python3 - "${unit_alias_digests}" <<'UNITROOT'
import json
import sys

document = json.loads(sys.argv[1])
units = document.get("units", [])
entry = [item for item in units if item["path"] == ".config/systemd/user"]
if not entry:
    raise SystemExit("symlinked unit root missing from the re-read")
if entry[0].get("kind") != "directory_symlink":
    raise SystemExit(f"unit root recorded as {entry[0]}")
if entry[0].get("symlink_target") != "user.alias":
    raise SystemExit(f"unit root recorded without its target: {entry[0]}")
UNITROOT

# The root of a walked tree is configuration too. Repointing ~/.config/mcloving
# itself at another managed directory with identical contents must not leave
# the re-read byte-identical: that substitution redirects every contract, key,
# and certificate the services read.
before_root_swap="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
# The copy is taken before the move so the live configuration path is absent
# for as little as possible: the controller and agent started in step 6 are
# still running against it.
cp -a "${config_dir}" "${config_dir}.alias"
mv "${config_dir}" "${config_dir}.real"
ln -s "$(basename "${config_dir}").alias" "${config_dir}"
after_root_swap="$("${libexec}/helpers/mcloving-deployed-digests" --home "${home}")"
rm -f "${config_dir}"
rm -rf "${config_dir}.alias"
mv "${config_dir}.real" "${config_dir}"
if [[ "${before_root_swap}" == "${after_root_swap}" ]]; then
  echo "a repointed configuration root left the re-read byte-identical" >&2
  exit 1
fi
python3 - "${after_root_swap}" <<'ROOT'
import json
import sys

document = json.loads(sys.argv[1])
contracts = document.get("environment_contracts", [])
entry = [item for item in contracts if item["path"] == ".config/mcloving"]
if not entry:
    raise SystemExit("symlinked configuration root missing from the re-read")
if entry[0].get("kind") != "directory_symlink":
    raise SystemExit(f"configuration root recorded as {entry[0]}")
if "symlink_target" not in entry[0]:
    raise SystemExit("configuration root recorded without its target")
ROOT

# `systemctl start` reaching the started state is not the same as a service
# that is still running: Type=exec reports success once the exec succeeds. The
# agent's health gate reads its journal and an intact journal says nothing
# about the process, so without this an upgrade over a binary that execs and
# exits reports "complete and healthy" while Restart=on-failure cycles. Driven
# against a scripted manager because this test runs no user systemd instance.
stability_shim="${workdir}/stability-shim"
mkdir -p "${stability_shim}"
cat > "${stability_shim}/systemctl" <<'SHIM'
#!/usr/bin/env bash
count="$(cat "${MCLOVING_FAKE_STATE}" 2>/dev/null || echo 0)"
count=$((count + 1))
echo "${count}" > "${MCLOVING_FAKE_STATE}"
case "${MCLOVING_FAKE_MODE}" in
  steady)
    printf 'ActiveState=active\nSubState=running\nMainPID=4242\nNRestarts=0\n' ;;
  flapping)
    printf 'ActiveState=active\nSubState=running\nMainPID=%s\nNRestarts=%s\n' \
      "$((4242 + count))" "${count}" ;;
  restarting)
    printf 'ActiveState=activating\nSubState=auto-restart\nMainPID=0\nNRestarts=3\n' ;;
  *) exit 1 ;;
esac
SHIM
chmod +x "${stability_shim}/systemctl"
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  export PATH="${stability_shim}:${PATH}"
  export MCLOVING_FAKE_STATE="${stability_shim}/count"
  export MCLOVING_FAKE_MODE=steady
  : > "${MCLOVING_FAKE_STATE}"
  require_service_stable 0 mcloving-agent.service 3 >/dev/null || {
    echo "stability check refused a service that stayed active/running" >&2
    exit 1
  }
  for mode in flapping restarting; do
    export MCLOVING_FAKE_MODE="${mode}"
    : > "${MCLOVING_FAKE_STATE}"
    if require_service_stable 0 mcloving-agent.service 3 >/dev/null 2>&1; then
      echo "stability check accepted a ${mode} service" >&2
      exit 1
    fi
  done
)

# The recovery command is printed to be copied and run. A service account home
# containing a space or a shell metacharacter must survive that round trip, so
# the emitted text is evaluated against stub helpers that record their argv.
quoted_home="${workdir}/od d & home"
quoted_libexec="${quoted_home}/.local/libexec/mcloving"
mkdir -p "${quoted_libexec}/helpers"
for stub in mcloving-deployed-digests mcloving-rollback; do
  cat > "${quoted_libexec}/helpers/${stub}" <<STUB
#!/usr/bin/env bash
printf '%s\n' "\$#" > "${quoted_libexec}/${stub}.argc"
printf '%s\n' "\$2" > "${quoted_libexec}/${stub}.home"
STUB
  chmod +x "${quoted_libexec}/helpers/${stub}"
done
(
  # shellcheck source=deploy/bin/mcloving-deploy-lib.sh
  source "${libexec}/helpers/mcloving-deploy-lib.sh"
  eval "$(recovery_command "${quoted_libexec}" "${quoted_home}")"
)
for stub in mcloving-deployed-digests mcloving-rollback; do
  [[ "$(cat "${quoted_libexec}/${stub}.argc")" == "2" ]] || {
    echo "recovery command split the ${stub} arguments: got $(cat "${quoted_libexec}/${stub}.argc")" >&2
    exit 1
  }
  [[ "$(cat "${quoted_libexec}/${stub}.home")" == "${quoted_home}" ]] || {
    echo "recovery command mangled the --home value for ${stub}" >&2
    exit 1
  }
done

# Under --no-systemd the units resolve %h to the invoking user's home, not to
# --home, so telling the operator to start them would start an unrelated
# deployment or fail on units that are not there.
alternate_home="${workdir}/alternate-home"
mkdir -p "${alternate_home}"
alternate_output="$("${repo_root}/deploy/bin/mcloving-install" \
  --release-dir "${release_dir}" --checksums "${workdir}/checksums.sha256" \
  --home "${alternate_home}" --no-systemd)"
if grep -q -- "systemctl --user enable" <<<"${alternate_output}"; then
  echo "install told an alternate-home deployment to start the invoking user's units" >&2
  exit 1
fi
grep -q "did not touch systemd" <<<"${alternate_output}" || {
  echo "install gave no operable next step for --no-systemd" >&2
  exit 1
}
# The prescribed recovery path must carry the reload: a --no-systemd rerun
# replaces assets but cannot reload the manager, so both the changed-assets
# diagnostic and the --no-systemd epilogue must tell the operator to
# daemon-reload before starting units, or the manager starts cached
# previous configuration.
grep -q "daemon-reload" <<<"${alternate_output}" || {
  echo "the --no-systemd epilogue does not prescribe daemon-reload" >&2
  exit 1
}
grep -q "daemon-reload so the manager" "${repo_root}/deploy/bin/mcloving-install" || {
  echo "the changed-assets diagnostic does not prescribe daemon-reload" >&2
  exit 1
}

# The recovery command the upgrade path prints must actually run from where it
# is installed. Checking only that the file exists proved nothing: the helper
# resolved its shared library against the repository layout and exited before
# touching anything.
[[ -x "${libexec}/helpers/mcloving-rollback" ]] || {
  echo "rollback helper is not installed; the printed recovery command would not resolve" >&2
  exit 1
}
"${libexec}/helpers/mcloving-rollback" --home "${home}" --no-systemd >/dev/null || {
  echo "installed rollback helper is not runnable from its installed location" >&2
  exit 1
}
"${libexec}/helpers/mcloving-rollback" --home "${home}" --no-systemd >/dev/null || {
  echo "installed rollback helper is not runnable on the return swap" >&2
  exit 1
}
[[ "$(readlink "${libexec}/current")" == "${first_release}" ]] || {
  echo "paired installed rollbacks did not return to the original release" >&2
  exit 1
}

echo "deployment smoke test passed: install -> bootstrap -> submit ${build_id} -> succeeded -> digest re-read -> upgrade/rollback -> tamper refusal -> env grammar (incl. multiline) -> symlinked contract -> symlinked pki -> special node -> symlinked config root -> service stability -> installed rollback runs"
