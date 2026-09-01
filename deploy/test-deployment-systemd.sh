#!/usr/bin/env bash
# The service-managed arm of the deployment lane.
#
# WHY THIS IS A SEPARATE SCRIPT. `deploy/test-deployment.sh` passes
# `--no-systemd` at every one of its 184 install, upgrade and rollback sites,
# and that is not a flag it chooses -- `require_systemd_home` compares `--home`
# against the passwd database, and the suite installs into `mktemp -d` trees, so
# the flag is forced. Everything systemd would do is instead re-derived in bash:
# `mcloving-unit-command` parses the units and the suite runs their `ExecStart`
# itself. That proves the install, contract, digest and rollback MECHANICS. It
# proves nothing about the lane the units describe, because systemd never
# generates, enables, orders or starts anything in any gate.
#
# `DEPLOY-001`'s acceptance is "a scripted install on a clean host brings up the
# controller and agent", for a lane its own row defines as "systemd units or
# podman quadlets". Closing it on derived-command evidence is the substitution
# the board's receipt rules exist to prevent, which is why the ticket was
# reverted to ACTIVE. This arm is the missing half.
#
# WHAT IT REQUIRES, AND WHY IT REFUSES RATHER THAN SKIPS. It needs a real
# service account: its own passwd home, a running `systemd --user` manager,
# lingering enabled, and working rootless podman. Every one of those is checked
# below and every failure is a refusal by name. A skip here would be worse than
# no arm at all -- the deployable-runtime gate this ticket also names returns
# success when `MCLOVING_TEST_DATABASE_URL` is unset, and a silent skip inside
# an acceptance criterion is exactly the failure this repository is named for.
set -euo pipefail
umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_dir=""
checksums=""
keep=0
reset=0
# Set immediately before the documented command can ask systemd to invoke the
# generated Podman units.  Failure diagnostics may use Podman only after both
# this flag and an on-disk rootless store prove the cold-first boundary was
# crossed; an earlier refusal must remain incapable of creating that state.
service_start_attempted=0
# Set while the deployable-runtime gate is running, because that gate
# deliberately weakens the database and only restores it AFTER its assertion.
database_possibly_weakened=0
runtime_gate=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-dir) release_dir="$2"; shift 2 ;;
    --checksums) checksums="$2"; shift 2 ;;
    --keep) keep=1; shift ;;
    --reset) reset=1; shift ;;
    --runtime-gate) runtime_gate="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

fail() { echo "systemd-arm: $1" >&2; exit 1; }
step() { echo "== $1"; }

# ---------------------------------------------------------------------------
step "[1/10] preconditions -- every one refuses, none skips"

[[ -n "${release_dir}" && -d "${release_dir}" ]] \
  || fail "--release-dir must name a staged release directory"
[[ -n "${checksums}" && -f "${checksums}" ]] \
  || fail "--checksums must name a sha256sum file for that release"
# NOT OPTIONAL. DEPLOY-001's acceptance is "brings up the controller and agent
# AND passes the deployable-runtime gate". Making the gate optional here would
# leave the arm able to report success on half the sentence -- which is the
# shape of the very defect the gate itself had.
[[ -n "${runtime_gate}" && -x "${runtime_gate}" ]] \
  || fail "--runtime-gate must name the prebuilt deployable-runtime test binary (cargo test --no-run -p mcloving-controller --test deployable_runtime)"
# ORDERING THAT BIT ONCE: stage the release from the SAME build that produced
# the gate binary. Building the gate rebuilds the controller in the build tree,
# so a release staged earlier no longer matches what the gate will spawn -- and
# step 10 refuses that rather than testing one binary while running another.

account="$(id -un)"
home_dir="$(getent passwd "$(id -u)" | cut -d: -f6)"
[[ -n "${home_dir}" ]] || fail "this account has no passwd home; the lane resolves %h there"
[[ "${HOME}" == "${home_dir}" ]] \
  || fail "HOME (${HOME}) is not this account's passwd home (${home_dir}); systemd expands %h to the passwd home, so a mismatched HOME would install one tree and manage another"

# The one thing that makes this arm different from the other suite: the install
# must be able to run WITHOUT --no-systemd, and that is exactly the condition
# require_systemd_home enforces.
# shellcheck source=deploy/bin/mcloving-deploy-lib.sh
source "${repo_root}/deploy/bin/mcloving-deploy-lib.sh"
require_systemd_home "${home_dir}" 0 \
  || fail "the deployment home is not this account's passwd home"

# shellcheck source=deploy/systemd-ci-lib.sh
source "${repo_root}/deploy/systemd-ci-lib.sh"
expected_podman_generator="${MCLOVING_PODMAN_USER_GENERATOR:-}"
mcloving_ci_select_podman_generator \
  || fail "Podman and Quadlet do not form one supported, trusted vendor layout"
[[ -z "${expected_podman_generator}" \
  || "${expected_podman_generator}" == "${MCLOVING_CI_PODMAN_GENERATOR}" ]] \
  || fail "the wrapper selected ${expected_podman_generator}, but the service account resolves ${MCLOVING_CI_PODMAN_GENERATOR}"

[[ "$(loginctl show-user "$(id -u)" --property=Linger 2>/dev/null)" == "Linger=yes" ]] \
  || fail "lingering is not enabled for ${account}; without it the user manager stops at logout and a service-managed deployment is not what the runbook describes"

systemctl --user show -p UnitPath >/dev/null 2>&1 \
  || fail "no reachable systemd --user manager for ${account}; this arm exists to exercise the manager and cannot stand in for it"

[[ -x "${MCLOVING_CI_PODMAN_GENERATOR}" ]] \
  || fail "podman's selected Quadlet generator is absent; the postgres quadlet cannot become a unit without it"

if [[ "${MCLOVING_CLEAN_PODMAN_BY_CONSTRUCTION:-0}" != 1 ]]; then
  podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null | grep -qx true \
    || fail "rootless podman is not working for ${account}; the quadlet runs the database as this account"
else
  [[ ! -e "${home_dir}/.local/share/containers" \
    && ! -e "${XDG_RUNTIME_DIR}/containers" \
    && ! -e "${XDG_RUNTIME_DIR}/libpod" ]] \
    || fail "the controlled account already has Podman state; the generated volume unit would not be a cold first operation"
fi

echo "   account=${account} home=${home_dir} manager=$(systemctl --user is-system-running 2>&1) quadlet=${MCLOVING_CI_QUADLET_VERSION} generator=${MCLOVING_CI_PODMAN_GENERATOR}"

# THIS SCRIPT IS DESTRUCTIVE AND CANNOT TELL WHOSE DEPLOYMENT IT IS LOOKING AT.
# Every precondition above passes just as well on a real McLoving service
# account as on a disposable one -- and the teardown removes the deployment tree
# and force-removes the `mcloving-postgres-data` volume, which on a production
# account is somebody's database. So an existing deployment is a REFUSAL, and
# destroying one is something the caller has to ask for by name.
#
# It also has to start from nothing to be meaningful: a surviving data volume
# carries the password baked in at initdb, and this run generates a fresh one,
# so db-init would fail for a reason that has nothing to do with the code under
# test. Measured, after it happened.
# THE STATE TREE COUNTS AS A DEPLOYMENT. A first cut probed only the libexec
# root and the volume, so after a failed run had left `StateDirectory=` trees
# behind, --reset saw "nothing to clean", left them, and step 6's assertion that
# systemd creates the workspace then failed on a directory from the run before.
# What makes a deployment present is any of its parts, not the tidiest one.
state_probe="$(deployment_effective_state_root "${home_dir}")"
config_probe="$(deployment_effective_config_root "${home_dir}")"
existing=""
[[ ! -e "${home_dir}/.local/libexec/mcloving" ]] || existing+="a deployment at ${home_dir}/.local/libexec/mcloving "
# DROP-INS COUNT, for two reasons and the second is the sharper one. A
# `mcloving-agent.service.d/override.conf` is part of somebody's deployment, so
# proceeding over it destroys work this script cannot see. And systemd MERGES
# drop-ins: an unnoticed one changes what the units under test actually do, so
# the arm would exercise something other than the shipped lane while reporting
# on the shipped lane. Units, quadlets and their drop-in directories all count.
# EVERY EFFECTIVE LOAD PATH, ASKED OF THE MANAGER -- not the two roots this
# script happens to know. systemd merges a drop-in from any directory on its
# search path, and `~/.config/systemd/user.control/mcloving-agent.service.d/`
# is one of them: an override there is invisible to a two-root probe, survives
# into the run, and the arm then exercises a CUSTOMISED unit while reporting on
# the shipped lane. `deployment_manager_unit_path` returns the manager's own
# ordered UnitPath, which is the same oracle round 34 made authoritative for
# what systemd reads; modelling the list here would be the "wrong oracle"
# mistake this file has already made three times.
unit_probe_roots=()
quadlet_probe_roots=()
expected_space_path_seen=0
declare -A seen_probe_root=()
declare -A quadlet_probe_root_set=()
while IFS= read -r encoded_root; do
  [[ -n "${encoded_root}" ]] || continue
  decode_path_item_into decoded_probe_root "${encoded_root}"
  [[ -z "${seen_probe_root["${decoded_probe_root}"]:-}" ]] || continue
  seen_probe_root["${decoded_probe_root}"]=1
  unit_probe_roots+=("${decoded_probe_root}")
  if [[ -n "${MCLOVING_EXPECT_UNIT_PATH_WITH_SPACE:-}" \
    && "${decoded_probe_root}" == "${MCLOVING_EXPECT_UNIT_PATH_WITH_SPACE}" ]]; then
    expected_space_path_seen=1
  fi
done < <(deployment_manager_unit_path "${home_dir}")
if [[ -n "${MCLOVING_EXPECT_UNIT_PATH_WITH_SPACE:-}" ]]; then
  (( expected_space_path_seen == 1 )) \
    || fail "the typed UnitPath query did not preserve the exact entry containing whitespace: ${MCLOVING_EXPECT_UNIT_PATH_WITH_SPACE}"
fi
# Quadlet is an independent recursive source namespace. Ask the manager's typed
# QUADLET_UNIT_DIRS replacement when present, otherwise use Podman's complete
# defaults, and snapshot those roots once alongside UnitPath.
while IFS= read -r encoded_root; do
  [[ -n "${encoded_root}" ]] || continue
  decode_path_item_into extra_probe_root "${encoded_root}"
  quadlet_probe_root_set["${extra_probe_root}"]=1
  quadlet_probe_roots+=("${extra_probe_root}")
done < <(deployment_unit_load_paths "${home_dir}" all quadlet)
for extra_probe_root in "${config_probe}/systemd/user" "${quadlet_probe_roots[@]}"; do
  [[ -z "${seen_probe_root["${extra_probe_root}"]:-}" ]] || continue
  seen_probe_root["${extra_probe_root}"]=1
  unit_probe_roots+=("${extra_probe_root}")
done

# WHAT IS OURS TO REMOVE, AND WHAT IS NOT. A stale unit under the home is part
# of a deployment --reset may destroy. One on a SYSTEM path is not this
# script's to delete at all -- and it would still be merged into the units
# under test, so it cannot be ignored either. That is a refusal even with
# --reset, which is the honest answer: this host cannot host a clean-host gate
# until somebody with the authority to remove it does.
# THREE KINDS OF ROOT, and the middle one is why this is not a one-line test.
# Under the home: a deployment --reset may destroy. Under the manager's RUNTIME
# root: systemd's own scratch -- `/run/user/<uid>/systemd/generator` holds the
# unit Quadlet generates from our own `.container`, so treating it as a foreign
# install would hard-refuse a host whose only fault is an interrupted run, and
# refuse it in a way --reset could not clear. Removing the quadlet and
# reloading is what clears those, which --reset already does. Anywhere else is
# a system path this account must not delete in.
runtime_probe_root="$(deployment_runtime_root "${home_dir}")"
foreign_units=""
probe_candidate=""
# Candidate-file view closes forms a top-level mcloving-* glob cannot see:
# service.d/container.d type-wide drop-ins, dash/template forms, and recursive
# Quadlet sources. Type-wide files are never resettable even under this home;
# deleting one would change unrelated units, so they make the host non-clean.
probe_candidate_raw="$(deployment_unit_candidate_files "${home_dir}" \
  "${repo_root}/deploy/systemd/mcloving-db-init.service" \
  "${repo_root}/deploy/systemd/mcloving-controller.service" \
  "${repo_root}/deploy/systemd/mcloving-agent.service" \
  "${repo_root}/deploy/podman/mcloving-postgres.container" \
  "${repo_root}/deploy/podman/mcloving-postgres-data.volume")"
while IFS= read -r probe_candidate_encoded; do
  [[ -n "${probe_candidate_encoded}" ]] || continue
  decode_path_item_into probe_candidate "${probe_candidate_encoded}"
  if [[ "${probe_candidate}" == */service.d/*.conf \
    || "${probe_candidate}" == */container.d/*.conf \
    || "${probe_candidate}" == */volume.d/*.conf ]]; then
    foreign_units+="${probe_candidate} "
  elif [[ "${probe_candidate}" == "${home_dir}/"* ]]; then
    existing+="installed unit, source, or drop-in at ${probe_candidate} "
  elif [[ -n "${runtime_probe_root}" \
    && "${probe_candidate}" == "${runtime_probe_root}/"* ]]; then
    existing+="runtime unit, source, or drop-in at ${probe_candidate} "
  else
    foreign_units+="${probe_candidate} "
  fi
done <<<"${probe_candidate_raw}"
for probe_root in ${unit_probe_roots[@]+"${unit_probe_roots[@]}"}; do
  [[ -d "${probe_root}" ]] || continue
  if [[ -n "${quadlet_probe_root_set["${probe_root}"]:-}" ]]; then
    probe_hit=""
    for quadlet_probe_name in mcloving-postgres.container mcloving-postgres-data.volume; do
      probe_hit_encoded="$(deployment_quadlet_tree_candidates "${probe_root}" \
        "${quadlet_probe_name}" | head -1)"
      [[ -n "${probe_hit_encoded}" ]] || continue
      decode_path_item_into probe_hit "${probe_hit_encoded}"
      break
    done
  else
    probe_hit="$(shopt -s nullglob; printf '%s\n' "${probe_root}"/mcloving-* | head -1)"
  fi
  [[ -n "${probe_hit}" ]] || continue
  if [[ "${probe_root}" == "${home_dir}/"* ]] \
    || { [[ -n "${runtime_probe_root}" ]] && [[ "${probe_root}" == "${runtime_probe_root}/"* ]]; }; then
    existing+="installed units or drop-ins at ${probe_hit} "
  else
    foreign_units+="${probe_hit} "
  fi
done
[[ -z "${foreign_units}" ]] || fail "the service manager loads mcloving unit(s) from outside this account's home: ${foreign_units% }-- systemd MERGES those into the units this gate starts, so the run would exercise a customised lane while reporting on the shipped one. They are not this script's to delete, and --reset does not override that; remove them with the authority that installed them, then re-run"
[[ ! -e "${state_probe}/mcloving-agent" && ! -e "${state_probe}/mcloving-controller" ]] \
  || existing+="service state under ${state_probe} "
[[ ! -e "${home_dir}/.config/mcloving" ]] || existing+="contracts at ${home_dir}/.config/mcloving "
if [[ "${MCLOVING_CLEAN_PODMAN_BY_CONSTRUCTION:-0}" != 1 ]]; then
  podman volume exists mcloving-postgres-data 2>/dev/null \
    && existing+="the mcloving-postgres-data volume "
fi
# THE NAMED CONTAINER IS ONE OF THE PARTS TOO, by the rule stated above. The
# quadlet fixes ContainerName=mcloving-postgres, so a stale container of that
# name collides with the start in step 8 -- and probing only the volume left a
# hole with a specific shape: a container surviving WITHOUT its volume made
# `existing` empty, so --reset ran no cleanup block at all and the run then
# failed at step 8 for a reason that looks like a lane defect and is not.
# `--reset` already removes it; what was missing was noticing it was there.
if [[ "${MCLOVING_CLEAN_PODMAN_BY_CONSTRUCTION:-0}" != 1 ]]; then
  podman container exists mcloving-postgres 2>/dev/null \
    && existing+="the mcloving-postgres container "
fi
if [[ -n "${existing}" ]]; then
  if (( reset == 0 )); then
    fail "refusing to run: ${existing}already exists, and this script would destroy it. Nothing here can tell a disposable test account from a real one. Run it on an account with no deployment, or pass --reset to say you know what is on this one"
  fi
  echo "   --reset: removing ${existing% }"
  systemctl --user disable --now mcloving-db-init mcloving-controller mcloving-agent >/dev/null 2>&1 || true
  # The generated unit is not in that list -- it cannot be disabled -- and while
  # it runs it holds the volume open, so removing the volume underneath it is at
  # best a race. Stop it by name.
  systemctl --user stop mcloving-postgres.service >/dev/null 2>&1 || true
  systemctl --user stop mcloving-postgres-data-volume.service >/dev/null 2>&1 || true
  podman rm -f mcloving-postgres >/dev/null 2>&1 || true
  podman volume rm -f mcloving-postgres-data >/dev/null 2>&1 || true
  if podman volume exists mcloving-postgres-data 2>/dev/null; then
    fail "--reset could not remove mcloving-postgres-data; refusing to install fresh contracts over a cluster that retains the previous initdb password"
  fi
  rm -rf "${home_dir}/.local/libexec/mcloving" "${state_probe}/mcloving-agent" \
         "${state_probe}/mcloving-controller" "${home_dir}/.config/mcloving" \
         >/dev/null 2>&1 || true
  # FROM THE MANAGER'S CONFIG BASE, not the invoking shell's. `mcloving-install`
  # writes units and quadlets under `deployment_effective_config_root`, which
  # asks the running manager; a hard-coded ~/.config would clean a directory the
  # installer never wrote to whenever the two disagree, leave the real units in
  # place, and report a reset that had not happened.
  reset_config_base="${config_probe}"
  reset_candidate=""
  # -rf and a bare mcloving-* glob: `rm -f` on `*.service` leaves the
  # `mcloving-agent.service.d/` drop-in directories standing, and a drop-in that
  # survives a reset is merged into the next run's units.
  rm -rf "${reset_config_base}"/systemd/user/mcloving-* \
         "${reset_config_base}"/systemd/user/default.target.wants/mcloving-* \
         "${reset_config_base}"/containers/systemd/mcloving-* >/dev/null 2>&1 || true
  # AND EVERY OTHER LOAD PATH THE PROBE LOOKED AT, or --reset refuses a
  # deployment it then does not remove: the probe now sees `user.control` and
  # anything else the manager searches, so a reset that cleaned only the two
  # roots above would report a reset that had not happened and run with the
  # drop-in still merged. Bounded to paths under the home or this user's
  # manager runtime root -- a foreign root is already a refusal above and is
  # not ours to delete. The runtime root matters: `systemd/user.control` there
  # is classified as resettable by the probe above, and omitting it here made
  # --reset announce a removal it did not perform.
  for reset_root in ${unit_probe_roots[@]+"${unit_probe_roots[@]}"}; do
    if [[ "${reset_root}" != "${home_dir}/"* ]] \
      && { [[ -z "${runtime_probe_root}" ]] \
        || [[ "${reset_root}" != "${runtime_probe_root}/"* ]]; }; then
      continue
    fi
    if [[ -n "${quadlet_probe_root_set["${reset_root}"]:-}" ]]; then
      for quadlet_reset_name in mcloving-postgres.container mcloving-postgres-data.volume; do
        while IFS= read -r reset_candidate_encoded; do
          [[ -n "${reset_candidate_encoded}" ]] || continue
          decode_path_item_into reset_candidate "${reset_candidate_encoded}"
          rm -f -- "${reset_candidate}" >/dev/null 2>&1 || true
        done < <(deployment_quadlet_tree_candidates "${reset_root}" \
          "${quadlet_reset_name}")
      done
    else
      rm -rf "${reset_root}"/mcloving-* \
             "${reset_root}"/default.target.wants/mcloving-* >/dev/null 2>&1 || true
    fi
  done
  systemctl --user daemon-reload >/dev/null 2>&1 || true
  [[ "$(systemctl --user show -p ActiveState --value mcloving-postgres-data-volume.service 2>/dev/null || true)" != active ]] \
    || fail "--reset left mcloving-postgres-data-volume.service active after removing its volume"
  for reset_root in ${unit_probe_roots[@]+"${unit_probe_roots[@]}"}; do
    if [[ "${reset_root}" != "${home_dir}/"* ]] \
      && { [[ -z "${runtime_probe_root}" ]] \
        || [[ "${reset_root}" != "${runtime_probe_root}/"* ]]; }; then
      continue
    fi
    if [[ -n "${quadlet_probe_root_set["${reset_root}"]:-}" ]]; then
      reset_hit=""
      for quadlet_reset_name in mcloving-postgres.container mcloving-postgres-data.volume; do
        reset_hit="$(deployment_quadlet_tree_candidates "${reset_root}" \
          "${quadlet_reset_name}" | head -1)"
        [[ -z "${reset_hit}" ]] || break
      done
    else
      reset_hit="$(shopt -s nullglob; printf '%s\n' "${reset_root}"/mcloving-* | head -1)"
    fi
    [[ -z "${reset_hit}" ]] \
      || fail "--reset left ${reset_hit} in a manager load path; refusing to exercise a customised unit"
  done
fi

# ---------------------------------------------------------------------------
# The MANAGER's configuration base, which is what mcloving-install writes units
# and quadlets under. `deployment_config_root` answers from the invoking shell's
# environment instead, and the two differ whenever the manager carries its own
# absolute XDG_CONFIG_HOME -- so cleanup would miss the real units entirely.
config_base="${config_probe}"
unit_root="${config_base}/systemd/user"
quadlet_root="${config_base}/containers/systemd"
libexec_root="${home_dir}/.local/libexec/mcloving"
units=(mcloving-db-init.service mcloving-controller.service mcloving-agent.service)
generated=(mcloving-postgres.service mcloving-postgres-data-volume.service)

scratch="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-d001.XXXXXX")"

diagnose_bounded() {
  /usr/bin/timeout --foreground --kill-after=2s 8s "$@"
}

teardown() {
  local status=$?
  trap '' INT TERM HUP
  # When the runtime gate may have left database RLS weakened, teardown must
  # quiesce services and remove the volume immediately.  Diagnostic commands
  # are intentionally skipped on that path: a blocked manager/Podman query may
  # never extend a known authorization-exposure window.
  if (( status != 0 && database_possibly_weakened == 0 )); then
    step "pre-teardown failure evidence"
    for failed_unit in \
      mcloving-postgres-data-volume.service mcloving-postgres.service \
      mcloving-db-init.service mcloving-controller.service \
      mcloving-agent.service; do
      echo "--- ${failed_unit}: manager state"
      diagnose_bounded systemctl --user show "${failed_unit}" \
        -p Id -p LoadState -p ActiveState -p SubState -p Result \
        -p Type -p NotifyAccess -p TimeoutStartUSec -p ExecMainCode \
        -p ExecMainStatus -p NRestarts -p StatusText 2>&1 || true
      diagnose_bounded systemctl --user status "${failed_unit}" \
        --no-pager -n 80 2>&1 || true
      echo "--- ${failed_unit}: journal"
      diagnose_bounded journalctl --user -u "${failed_unit}" \
        --no-pager -n 160 2>&1 || true
    done

    # State is the second half of the permission: setting the flag alone is
    # not enough because systemctl could reject the command before scheduling
    # the generated volume unit.  These observations are deliberately narrow:
    # container State and logs diagnose start/health failure without printing
    # the secret-bearing Config.Env array.
    if (( service_start_attempted == 1 )) \
      && { [[ -e "${home_dir}/.local/share/containers" ]] \
        || [[ -e "${XDG_RUNTIME_DIR}/containers" ]] \
        || [[ -e "${XDG_RUNTIME_DIR}/libpod" ]]; }; then
      echo "--- rootless Podman state after the cold-first boundary"
      diagnose_bounded "${MCLOVING_CI_PODMAN_COMMAND}" \
        ps -a --no-trunc --filter name=mcloving-postgres \
        --format 'container={{.ID}} name={{.Names}} status={{.Status}} image={{.Image}}' \
        2>&1 || true
      if diagnose_bounded "${MCLOVING_CI_PODMAN_COMMAND}" \
          container exists mcloving-postgres 2>/dev/null; then
        diagnose_bounded "${MCLOVING_CI_PODMAN_COMMAND}" inspect \
          --format 'state={{json .State}}' mcloving-postgres 2>&1 || true
        diagnose_bounded "${MCLOVING_CI_PODMAN_COMMAND}" logs \
          --tail 200 mcloving-postgres 2>&1 || true
      fi
      diagnose_bounded "${MCLOVING_CI_PODMAN_COMMAND}" images --no-trunc \
        --format 'image={{.ID}} repository={{.Repository}} tag={{.Tag}} digest={{.Digest}}' \
        2>&1 || true
    fi
  fi
  step "teardown"
  systemctl --user stop mcloving-agent.service mcloving-controller.service \
    mcloving-db-init.service mcloving-postgres.service \
    mcloving-postgres-data-volume.service >/dev/null 2>&1 || true
  systemctl --user disable mcloving-agent.service mcloving-controller.service \
    mcloving-db-init.service >/dev/null 2>&1 || true
  podman rm -f mcloving-postgres >/dev/null 2>&1 || true
  # These are proof-only shadow candidates, not deployment state. Remove both
  # exact files even under --keep so the arm never leaves a manager-active
  # customization behind for the next run.
  if [[ -n "${union_high_dropin:-}" ]]; then
    rm -f -- "${union_high_dropin}" >/dev/null 2>&1 || true
    rmdir --ignore-fail-on-non-empty -- "${union_high_dropin%/*}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${union_low_dropin:-}" ]]; then
    rm -f -- "${union_low_dropin}" >/dev/null 2>&1 || true
    rmdir --ignore-fail-on-non-empty -- "${union_low_dropin%/*}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${negative_load_dropin:-}" ]]; then
    rm -f -- "${negative_load_dropin}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${nnp_proof_dropin:-}" ]]; then
    rm -f -- "${nnp_proof_dropin}" >/dev/null 2>&1 || true
    rmdir --ignore-fail-on-non-empty -- "${nnp_proof_dropin%/*}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${quadlet_volume_root:-}" ]]; then
    chmod 0755 "${quadlet_volume_root}" >/dev/null 2>&1 || true
    rmdir -- "${quadlet_volume_root}" >/dev/null 2>&1 || true
  fi
  rm -f -- "${quadlet_container_contract:-}" >/dev/null 2>&1 || true
  if [[ -n "${nested_quadlet_fixture_files[0]:-}" ]]; then
    rm -f -- "${nested_quadlet_fixture_files[0]}.before-volume" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "${nested_quadlet_dropin:-}" ]]; then
    rm -f -- "${nested_quadlet_dropin}" >/dev/null 2>&1 || true
    rmdir --ignore-fail-on-non-empty -- "${nested_quadlet_dropin%/*}" \
      "${nested_quadlet_dropin%/*/*}" \
      "${nested_quadlet_dropin%/*/*/*}" >/dev/null 2>&1 || true
  fi
  rm -f -- "${fixture_unit:-}" "${fixture_bare_unit:-}" \
    "${fixture_contract:-}" >/dev/null 2>&1 || true
  rm -f -- "${nnp_db_marker:-}" >/dev/null 2>&1 || true
  for nested_fixture_file in ${nested_quadlet_fixture_files[@]+"${nested_quadlet_fixture_files[@]}"}; do
    rm -f -- "${nested_fixture_file}" >/dev/null 2>&1 || true
  done
  if [[ -n "${nested_quadlet_fixture_root:-}" ]]; then
    rmdir --ignore-fail-on-non-empty -- "${nested_quadlet_fixture_root}" \
      "${nested_quadlet_fixture_root%/*}" \
      "${nested_quadlet_fixture_parent:-}" >/dev/null 2>&1 || true
  fi
  # The scratch tree holds a SECOND full copy of the release -- four large
  # binaries -- staged for the upgrade, and is removed on every path. It was
  # lost when a stray `rm -rf "${scratch}"` was deleted from the preconditions,
  # where it never belonged; this is where it does.
  rm -rf "${scratch}" >/dev/null 2>&1 || true
  if (( keep == 0 )); then
    # THE VOLUME TOO, and only here. Removing the container and leaving the
    # volume makes the NEXT run fail in a way that looks like a lane defect and
    # is not: the cluster keeps the password baked in at initdb, this arm
    # generates a fresh one per run, and db-init then fails with "password
    # authentication failed for user mcloving". Measured, after it happened.
    #
    # But it sat OUTSIDE this branch and so ran on --keep too, wiping the
    # database of a deployment the same teardown then announced it had left in
    # place. A deployment kept for inspection without its data is not the thing
    # anyone asked to keep, and the message made it worse by saying otherwise.
    podman volume rm -f mcloving-postgres-data >/dev/null 2>&1 || true
    # CHECKED, exactly as the --keep branch below checks it. `|| true` cannot
    # fail loudly, so a refused removal -- the preceding container removal
    # having failed, say -- left the volume standing while teardown reported
    # success and deleted the deployment files around it. The next run then
    # fails on a password baked into a cluster this run generated, which is
    # documented six lines up as the reason the volume goes at all. Reporting
    # success while leaving the one thing that breaks the next run is the same
    # narrating-instead-of-refusing the --keep branch was already corrected for.
    if podman volume exists mcloving-postgres-data 2>/dev/null; then
      echo "   !! teardown COULD NOT REMOVE mcloving-postgres-data and it is still" >&2
      echo "      present. The next run will generate a fresh password against a" >&2
      echo "      cluster that kept this one's, and fail in db-init looking like a" >&2
      echo "      lane defect. Remove it:  podman volume rm -f mcloving-postgres-data" >&2
      (( status != 0 )) || status=1
    fi
    rm -rf "${libexec_root}" "${home_dir}/.config/mcloving" \
      "${state_probe}/mcloving-agent" "${state_probe}/mcloving-controller" \
      >/dev/null 2>&1 || true
    rm -rf "${unit_root}"/mcloving-* "${quadlet_root}"/mcloving-* \
           "${unit_root}"/default.target.wants/mcloving-* >/dev/null 2>&1 || true
    rm -f "${unit_root}/deploy003-manager-query-fixture.service" \
      "${unit_root}/deploy003-manager-bare-fixture.service" \
      "${home_dir}/.config/deploy003.fixture.env" >/dev/null 2>&1 || true
    systemctl --user daemon-reload >/dev/null 2>&1 || true
  elif (( database_possibly_weakened == 1 )); then
    # --keep asked for the deployment, not for a database whose row-level
    # security may be switched off. The tree stays; the volume does not.
    #
    # AND THE REMOVAL IS CHECKED, not announced. `podman volume rm -f ... || true`
    # cannot fail loudly -- if the volume is still in use the removal is refused
    # and the message below would report a deletion that did not happen, which
    # is the same narrating-instead-of-refusing this whole script keeps being
    # corrected for, inside the correction for it.
    podman volume rm -f mcloving-postgres-data >/dev/null 2>&1 || true
    if podman volume exists mcloving-postgres-data 2>/dev/null; then
      echo "   !! --keep: mcloving-postgres-data COULD NOT BE REMOVED and is still" >&2
      echo "      present. The runtime gate failed while it had deliberately" >&2
      echo "      weakened identity_sessions_tenant_policy and restores it only" >&2
      echo "      after the assertion that failed, so this volume may carry a" >&2
      echo "      database with row-level security switched off. Remove it before" >&2
      echo "      anything starts against it:  podman volume rm -f mcloving-postgres-data" >&2
      (( status != 0 )) || status=1
    else
      echo "   --keep: the deployment under ${home_dir} is left in place, but its"
      echo "           mcloving-postgres-data volume was removed and verified gone:"
      echo "           the runtime gate failed while it had deliberately weakened"
      echo "           identity_sessions_tenant_policy, and restores it only after"
      echo "           the assertion that failed. Keeping that database would keep"
      echo "           row-level security switched off."
    fi
  else
    echo "   --keep: the deployment under ${home_dir} is left in place, its"
    echo "           mcloving-postgres-data volume intact, services stopped."
    echo "           The next run needs --reset, which will destroy all of it."
  fi
  # Honest about what teardown cannot promise: a container the manager started
  # may outlive a SIGKILL of this script, and saying so beats implying otherwise.
  echo "   teardown ran (status ${status}); any surviving mcloving-postgres container is reported, not hidden:"
  podman ps -a --filter name=mcloving-postgres --format '     {{.Names}} {{.Status}}' || true
  # The proof-only union files are removed in both keep modes. Make that
  # removal visible to a retained manager as well.
  systemctl --user daemon-reload >/dev/null 2>&1 || true
  exit "${status}"
}
trap teardown EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# ---------------------------------------------------------------------------
step "[query fixture] manager resolves supported spellings and leaves bare Exec named"

# The retained no-manager parser refuses continuations, quoted/backslash-
# escaped executables, non-%h specifiers, and a bare Exec executable because
# modelling any of them incompletely is unsafe. The manager resolves the first
# four. On systemd 255 its typed ExecStart tuple deliberately leaves a bare
# executable bare, so manager mode retains that one safe refusal. Exercise both
# answers before installation, then remove the fixtures so service-managed
# evidence remains the shipped lane.
fixture_unit="${unit_root}/deploy003-manager-query-fixture.service"
fixture_bare_unit="${unit_root}/deploy003-manager-bare-fixture.service"
fixture_contract="${home_dir}/.config/deploy003.fixture.env"
for fixture_path in "${fixture_unit}" "${fixture_bare_unit}" "${fixture_contract}"; do
  [[ ! -e "${fixture_path}" && ! -L "${fixture_path}" ]] \
    || fail "refusing to replace pre-existing manager-query fixture path ${fixture_path}"
done
mkdir -p "${unit_root}" "${home_dir}/.config"
printf 'FIXTURE=yes\n' > "${fixture_contract}"
cat > "${fixture_unit}" <<'FIXTURE'
[Service]
Type=oneshot
EnvironmentFile=%h/.config/deploy003.fixture.env
WorkingDirectory=%h
ExecStart=-@"/usr/bin/pri\x6etf" fixture-argv0 \
  "%h/a b" "%t/c"
NoNewPrivileges=yes
FIXTURE
systemctl --user daemon-reload
fixture_facts="$(deployment_manager_unit_facts "${home_dir}" \
  deploy003-manager-query-fixture.service)" \
  || fail "the typed manager query did not accept the five resolved spellings"
fixture_unit_b64="$(printf '%s' deploy003-manager-query-fixture.service | base64 -w0)"
fixture_contract_b64="$(printf '%s' "${fixture_contract}" | base64 -w0)"
fixture_working_b64="$(printf '%s' "${home_dir}" | base64 -w0)"
fixture_quoted_arg_b64="$(printf '%s' "${home_dir}/a b" | base64 -w0)"
fixture_runtime_arg_b64="$(printf '%s' "${XDG_RUNTIME_DIR}/c" | base64 -w0)"
printf '%s\n' "${fixture_facts}" \
  | grep -q "^contract|${fixture_unit_b64}|${fixture_contract_b64}$" \
  || fail "the manager did not resolve %h in EnvironmentFile to ${fixture_contract}"
printf '%s\n' "${fixture_facts}" \
  | grep -q "^working|${fixture_unit_b64}|${fixture_working_b64}$" \
  || fail "the manager did not resolve WorkingDirectory=%h to ${home_dir}"
printf '%s\n' "${fixture_facts}" \
  | grep -q "^executable|${fixture_unit_b64}|$(printf '%s' /usr/bin/printf | base64 -w0)$" \
  || fail "the manager did not decode the continued, quoted, escaped, prefixed executable"
printf '%s\n' "${fixture_facts}" \
  | grep -q "^executable|${fixture_unit_b64}|${fixture_quoted_arg_b64}$" \
  || fail "the manager did not unquote and expand the absolute %h argument"
printf '%s\n' "${fixture_facts}" \
  | grep -q "^executable|${fixture_unit_b64}|${fixture_runtime_arg_b64}$" \
  || fail "the manager did not expand the non-%h runtime specifier"
cat > "${fixture_bare_unit}" <<'FIXTURE'
[Service]
Type=oneshot
ExecStart=printf manager-left-this-bare
FIXTURE
systemctl --user daemon-reload
if bare_facts="$(deployment_manager_unit_facts "${home_dir}" \
  deploy003-manager-bare-fixture.service 2>&1)"; then
  fail "the typed manager query accepted a bare executable without an absolute identity: ${bare_facts}"
fi
grep -q 'reported a non-absolute ExecStart executable' <<<"${bare_facts}" \
  || fail "the bare-executable refusal did not name the measured manager answer: ${bare_facts}"
rm -f "${fixture_unit}" "${fixture_bare_unit}" "${fixture_contract}"
systemctl --user daemon-reload
echo "   manager resolved continuation, quoting, C escape, prefixes and specifiers; bare executable refused; fixtures removed"

# Two same-name drop-ins at different precedence levels. The manager reports
# only the active higher one in DropInPaths; DEPLOY-003's additive union must
# still judge and digest the lower file that would become active if the higher
# one were removed later.
union_high_dropin="${unit_root}/mcloving-controller.service.d/90-deploy003-union.conf"
union_low_dropin="${runtime_probe_root}/systemd/user/mcloving-controller.service.d/90-deploy003-union.conf"
mkdir -p "${union_high_dropin%/*}" "${union_low_dropin%/*}"
printf '[Unit]\nDescription=McLoving controller (higher union fixture)\n' > "${union_high_dropin}"
printf '[Unit]\nDescription=McLoving controller (lower union fixture)\n' > "${union_low_dropin}"

nested_quadlet_fixture_root=""
nested_quadlet_fixture_parent=""
nested_quadlet_fixture_files=()
nested_quadlet_dropin=""
nested_quadlet_root=""
quadlet_override_status=0
quadlet_override_raw="$(deployment_manager_quadlet_unit_paths "${home_dir}")" \
  || quadlet_override_status=$?
if [[ "${MCLOVING_CLEAN_PODMAN_BY_CONSTRUCTION:-0}" == 1 ]]; then
  (( quadlet_override_status == 0 )) \
    || fail "the controlled clean arm requires an explicit typed QUADLET_UNIT_DIRS boundary"
  nested_quadlet_root_encoded="${quadlet_override_raw%%$'\n'*}"
  decode_path_item_into nested_quadlet_root "${nested_quadlet_root_encoded}"
  nested_quadlet_fixture_parent="${nested_quadlet_root}/deploy003-ci-fixture"
  [[ ! -e "${nested_quadlet_fixture_parent}" \
    && ! -L "${nested_quadlet_fixture_parent}" ]] \
    || fail "refusing to adopt pre-existing recursive Quadlet fixture root ${nested_quadlet_fixture_parent}"
  nested_quadlet_fixture_root="${nested_quadlet_fixture_parent}/nested/source"
  mkdir -p "${nested_quadlet_fixture_root}"
  cp "${repo_root}/deploy/podman/mcloving-postgres.container" \
    "${nested_quadlet_fixture_root}/mcloving-postgres.container"
  cp "${repo_root}/deploy/podman/mcloving-postgres-data.volume" \
    "${nested_quadlet_fixture_root}/mcloving-postgres-data.volume"
  nested_quadlet_fixture_files+=(
    "${nested_quadlet_fixture_root}/mcloving-postgres.container"
    "${nested_quadlet_fixture_root}/mcloving-postgres-data.volume"
  )
  nested_quadlet_dropin="${nested_quadlet_fixture_parent}/dropin-only/nested/mcloving-postgres.container.d/95-deploy003-volume.conf"
  mkdir -p "${nested_quadlet_dropin%/*}"
  printf '[Container]\n' > "${nested_quadlet_dropin}"
fi

# Kernel-level NNP evidence for db-init, the native oneshot that has no live
# MainPID by the time the arm can inspect it. ExecStartPost inherits the unit
# sandbox and records a marker only after observing NoNewPrivs: 1 in its own
# /proc status. The two Podman services deliberately omit NNP: a fresh-account
# cold probe measured newuidmap failing under that bit before namespace setup.
nnp_db_marker="${XDG_RUNTIME_DIR}/mcloving-deploy003-nnp-db-init"
nnp_proof_dropin="${unit_root}/mcloving-db-init.service.d/80-deploy003-nnp-proof.conf"
[[ ! -e "${nnp_db_marker}" && ! -L "${nnp_db_marker}" ]] \
  || fail "refusing to replace pre-existing NNP proof marker ${nnp_db_marker}"
mkdir -p "${unit_root}/mcloving-db-init.service.d"
cat > "${nnp_proof_dropin}" <<'NNP'
[Service]
ExecStartPost=/bin/sh -c 'grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/self/status && : > %t/mcloving-deploy003-nnp-db-init'
NNP

# ---------------------------------------------------------------------------
step "[2/10] scripted install to the passwd home, WITHOUT --no-systemd"

install_log="${scratch}/install.log"
"${repo_root}/deploy/bin/mcloving-install" --home "${home_dir}" \
  --release-dir "${release_dir}" --checksums "${checksums}" 2>&1 \
  | tee "${install_log}"
grep -q 'deployment integrity used typed manager properties' "${install_log}" \
  || fail "install completed without a typed post-daemon-reload manager verdict; the derived fallback must not satisfy this arm"
grep -q 'complete manager UnitPath fragment union and the independent Quadlet source-path union' "${install_log}" \
  || fail "install completed without the UnitPath and Quadlet source union verdict"
echo "   installed into ${libexec_root}"

# The absent UnitPath entry has its own parent that no installed deployment
# path traverses. Make that parent world-writable and require the integrity
# verdict to refuse the future creation point by name, then restore it. This
# proves absent roots are consumed by the security verdict, not merely decoded.
if [[ -n "${MCLOVING_EXPECT_ABSENT_UNIT_PATH_PARENT:-}" ]]; then
  [[ ! -e "${MCLOVING_EXPECT_UNIT_PATH_WITH_SPACE}" \
    && ! -L "${MCLOVING_EXPECT_UNIT_PATH_WITH_SPACE}" ]] \
    || fail "the absent UnitPath creation-bound fixture unexpectedly exists"
  chmod 0777 "${MCLOVING_EXPECT_ABSENT_UNIT_PATH_PARENT}"
  absent_bound_status=0
  absent_bound_log="$(require_deployment_integrity "${home_dir}" \
    --manager-authoritative 2>&1)" || absent_bound_status=$?
  chmod 0755 "${MCLOVING_EXPECT_ABSENT_UNIT_PATH_PARENT}"
  (( absent_bound_status != 0 )) \
    || fail "manager-authoritative integrity accepted an absent UnitPath below a world-writable creation parent"
  grep -Fq "${MCLOVING_EXPECT_ABSENT_UNIT_PATH_PARENT}" <<<"${absent_bound_log}" \
    || fail "absent-root refusal did not name its writable creation parent: ${absent_bound_log}"
  require_deployment_integrity "${home_dir}" --manager-authoritative >/dev/null
  echo "   absent UnitPath creation bound refused and restored"
fi

# Enumeration is not enough: make a hidden lower-precedence drop-in and a
# recursively selected custom Quadlet source writable in turn. Each must reach
# the final file/ancestor verdict, refuse by exact path, and pass once restored.
adverse_union_files=("${union_low_dropin}")
if (( ${#nested_quadlet_fixture_files[@]} > 0 )); then
  adverse_union_files+=("${nested_quadlet_fixture_files[0]}")
  adverse_union_files+=("${nested_quadlet_dropin}")
fi
for adverse_union_file in "${adverse_union_files[@]}"; do
  chmod 0666 "${adverse_union_file}"
  adverse_union_status=0
  adverse_union_log="$(require_deployment_integrity "${home_dir}" \
    --manager-authoritative 2>&1)" || adverse_union_status=$?
  chmod 0644 "${adverse_union_file}"
  (( adverse_union_status != 0 )) \
    || fail "manager-authoritative integrity accepted writable union candidate ${adverse_union_file}"
  grep -Fq "${adverse_union_file}" <<<"${adverse_union_log}" \
    || fail "writable union refusal did not name ${adverse_union_file}: ${adverse_union_log}"
done
if (( ${#nested_quadlet_fixture_files[@]} > 0 )); then
  # Manager argv carries this as `/host:/container`; treating that whole
  # token as a path misses the actual host ancestor. Put the directive only
  # in an independently nested drop-in with no colocated main source and
  # require the retained Quadlet source classifier to judge its host prefix.
  quadlet_volume_root="${home_dir}/deploy003 writable volume root"
  mkdir -p "${quadlet_volume_root}"
  chmod 0777 "${quadlet_volume_root}"
  printf '[Container]\nVolume=%s:/deploy003-proof:ro\n' "${quadlet_volume_root}" \
    > "${nested_quadlet_dropin}"
  volume_root_status=0
  volume_root_log="$(require_deployment_integrity "${home_dir}" \
    --manager-authoritative 2>&1)" || volume_root_status=$?
  printf '[Container]\n' > "${nested_quadlet_dropin}"
  chmod 0755 "${quadlet_volume_root}"
  rmdir "${quadlet_volume_root}"
  (( volume_root_status != 0 )) \
    || fail "manager-authoritative integrity accepted a writable host path from an independent nested Quadlet Volume= drop-in"
  grep -Fq "${quadlet_volume_root}" <<<"${volume_root_log}" \
    || fail "Quadlet Volume= refusal did not name its writable host root: ${volume_root_log}"

  # [Container] EnvironmentFile= is translated into Podman's --env-file
  # argument, so systemd's typed EnvironmentFiles property never names it.
  # Put one only in the standalone nested Quadlet drop-in and prove that the
  # source-side manager union still applies both contract boundaries: the
  # owner-only file rule and the declaration allowlist.
  quadlet_container_contract="${home_dir}/.config/deploy003-quadlet-container.env"
  printf 'MCLOVING_DEPLOY003_CONTAINER_ONLY=1\n' \
    > "${quadlet_container_contract}"
  chmod 0644 "${quadlet_container_contract}"
  printf '[Container]\nEnvironmentFile=%%h/.config/deploy003-quadlet-container.env\n' \
    > "${nested_quadlet_dropin}"
  quadlet_contract_mode_status=0
  quadlet_contract_mode_log="$(require_deployment_integrity "${home_dir}" \
    --manager-authoritative 2>&1)" || quadlet_contract_mode_status=$?
  (( quadlet_contract_mode_status != 0 )) \
    || fail "manager-authoritative integrity accepted a non-owner-only EnvironmentFile declared only by a Quadlet [Container] drop-in"
  grep -Fq "${quadlet_container_contract} (mode 644, expected owner-only)" \
    <<<"${quadlet_contract_mode_log}" \
    || fail "Quadlet-only contract permission refusal did not name its file: ${quadlet_contract_mode_log}"
  grep -Fq 'deployment integrity used typed manager properties' \
    <<<"${quadlet_contract_mode_log}" \
    || fail "Quadlet-only contract permission refusal did not traverse manager mode: ${quadlet_contract_mode_log}"

  printf 'DEPLOY003_UNRECOGNISED_CONTAINER_VARIABLE=1\n' \
    > "${quadlet_container_contract}"
  chmod 0600 "${quadlet_container_contract}"
  quadlet_contract_variable_status=0
  quadlet_contract_variable_log="$(require_deployment_integrity "${home_dir}" \
    --manager-authoritative 2>&1)" || quadlet_contract_variable_status=$?
  (( quadlet_contract_variable_status != 0 )) \
    || fail "manager-authoritative integrity accepted an unrecognised variable from an EnvironmentFile declared only by a Quadlet [Container] drop-in"
  grep -Fq "DEPLOY003_UNRECOGNISED_CONTAINER_VARIABLE in ${quadlet_container_contract}" \
    <<<"${quadlet_contract_variable_log}" \
    || fail "Quadlet-only contract allowlist refusal did not name its variable and file: ${quadlet_contract_variable_log}"
  grep -Fq 'deployment integrity used typed manager properties' \
    <<<"${quadlet_contract_variable_log}" \
    || fail "Quadlet-only contract allowlist refusal did not traverse manager mode: ${quadlet_contract_variable_log}"

  printf 'MCLOVING_DEPLOY003_CONTAINER_ONLY=1\n' \
    > "${quadlet_container_contract}"
  require_deployment_integrity "${home_dir}" --manager-authoritative >/dev/null

  # Quadlet also accepts EnvironmentFile= relative to the source-unit
  # location. The shared systemd parser intentionally accepts only absolute
  # contracts, so manager mode must loudly refuse this otherwise-unvalidated
  # spelling rather than silently dropping it.
  printf '[Container]\nEnvironmentFile=relative.env\n' \
    > "${nested_quadlet_dropin}"
  quadlet_relative_contract_status=0
  quadlet_relative_contract_log="$(require_deployment_integrity "${home_dir}" \
    --manager-authoritative 2>&1)" || quadlet_relative_contract_status=$?
  (( quadlet_relative_contract_status != 0 )) \
    || fail "manager-authoritative integrity silently dropped a relative Quadlet EnvironmentFile"
  grep -Fq "Quadlet source ${nested_quadlet_dropin} declares a relative EnvironmentFile (relative.env)" \
    <<<"${quadlet_relative_contract_log}" \
    || fail "relative Quadlet contract refusal did not name its source and value: ${quadlet_relative_contract_log}"
  grep -Fq 'deployment integrity used typed manager properties' \
    <<<"${quadlet_relative_contract_log}" \
    || fail "relative Quadlet contract refusal did not traverse manager mode: ${quadlet_relative_contract_log}"

  printf '[Container]\n' > "${nested_quadlet_dropin}"
  rm -f -- "${quadlet_container_contract}"
fi
require_deployment_integrity "${home_dir}" --manager-authoritative >/dev/null
echo "   shadowed drop-in, recursive Quadlet candidates, inactive Volume= roots, and absolute/relative container-only EnvironmentFile= contracts were security-judged, refused, and restored"

# A reachable manager with a negative LoadState is authoritative too. Prove
# that post-reload transitions refuse it rather than silently falling back to
# the derived parser, then restore the exact installed configuration.
negative_load_dropin="${unit_root}/mcloving-controller.service.d/95-deploy003-negative-load.conf"
cat > "${negative_load_dropin}" <<'NEGATIVE_LOAD'
[Service]
ExecStart=
NEGATIVE_LOAD
systemctl --user daemon-reload
if negative_load_log="$(require_deployment_integrity "${home_dir}" \
  --manager-authoritative 2>&1)"; then
  fail "manager-authoritative integrity accepted a negative LoadState"
fi
grep -q 'did not report every expected native and Quadlet-generated service as loaded or masked' \
  <<<"${negative_load_log}" \
  || fail "negative LoadState refusal did not name the authoritative manager boundary: ${negative_load_log}"
rm -f -- "${negative_load_dropin}"
systemctl --user daemon-reload
require_deployment_integrity "${home_dir}" --manager-authoritative >/dev/null
echo "   negative manager LoadState refused authoritatively and clean state restored"

# ---------------------------------------------------------------------------
step "[3/10] the manager knows the installed units"

# `mcloving-install` runs `systemctl --user daemon-reload` only when it is NOT
# given --no-systemd, so this is the first gate anywhere that the reload
# happened at all. Asked of the manager, not of the filesystem: a unit file on
# disk that the manager has not loaded is precisely the state a missing reload
# leaves behind, and `ls` cannot tell the two apart.
for unit in "${units[@]}" "${generated[@]}"; do
  state="$(systemctl --user show -p LoadState --value "${unit}" 2>/dev/null || true)"
  [[ "${state}" == "loaded" ]] \
    || fail "${unit} is ${state:-unknown} to the manager after install; either the unit was not written or daemon-reload did not run"
  echo "   ${unit} LoadState=${state}"
done

# ---------------------------------------------------------------------------
step "[4/10] Quadlet generated the postgres unit, and the library's model agrees"

# THE POINT OF THIS GATE. `deployment_quadlet_generated_name` MODELS podman's
# .container -> .service naming in bash, and the other suite tests that model
# against a hard-coded table whose comment says "verified against
# /usr/libexec/podman/quadlet's actual output" -- verified once, by hand, in a
# comment. Here the generator actually runs, and the model is checked against
# what it produced rather than against a remembered example.
for unit in "${generated[@]}"; do
  state="$(systemctl --user show -p LoadState --value "${unit}" 2>/dev/null || true)"
  [[ "${state}" == "loaded" ]] \
    || fail "${unit} was not generated from the sources under ${quadlet_root}; Quadlet either did not run or named it something else"
  echo "   ${unit} LoadState=${state} (generated)"
done
modelled="$(deployment_quadlet_generated_name mcloving-postgres.container)"
[[ "${modelled}" == "mcloving-postgres.service" ]] \
  || fail "the library models mcloving-postgres.container as ${modelled}, but the generator produced mcloving-postgres.service; the model and the generator disagree"
echo "   library model agrees with the generator: ${modelled}"

union_candidates="$(deployment_unit_candidate_files "${home_dir}" \
  "${unit_root}/mcloving-controller.service" \
  "${quadlet_root}/mcloving-postgres.container" \
  "${quadlet_root}/mcloving-postgres-data.volume")"
for union_fixture in "${union_high_dropin}" "${union_low_dropin}"; do
  union_fixture_b64="$(printf '%s' "${union_fixture}" | base64 -w0)"
  grep -qx "${union_fixture_b64}" <<<"${union_candidates}" \
    || fail "the complete drop-in union omitted ${union_fixture}"
done
if [[ -n "${nested_quadlet_fixture_root}" ]]; then
  for union_fixture in \
    "${nested_quadlet_fixture_root}/mcloving-postgres.container" \
    "${nested_quadlet_fixture_root}/mcloving-postgres-data.volume" \
    "${nested_quadlet_dropin}"; do
    union_fixture_b64="$(printf '%s' "${union_fixture}" | base64 -w0)"
    grep -qx "${union_fixture_b64}" <<<"${union_candidates}" \
      || fail "the recursive custom Quadlet union omitted ${union_fixture}"
  done
fi
echo "   complete drop-in union covered active and shadowed same-name files"

# Typed facts are the acceptance, not merely a notice. Require all five
# composed services, exact sources and executables, and the deliberate NNP
# split proved by the cold-start arm.
manager_facts="$(deployment_manager_unit_facts "${home_dir}" \
  "${units[@]}" "${generated[@]}")" \
  || fail "the typed manager fact query failed after daemon-reload"
selected_podman_b64="$(printf '%s' "${MCLOVING_CI_PODMAN_COMMAND}" | base64 -w0)"
sdnotify_conmon_b64="$(printf '%s' '--sdnotify=conmon' | base64 -w0)"
sdnotify_healthy_b64="$(printf '%s' '--sdnotify=healthy' | base64 -w0)"
sdnotify_container_b64="$(printf '%s' '--sdnotify=container' | base64 -w0)"
for unit in "${units[@]}" "${generated[@]}"; do
  unit_b64="$(printf '%s' "${unit}" | base64 -w0)"
  grep -q "^source|${unit_b64}|" <<<"${manager_facts}" \
    || fail "typed manager facts contained no FragmentPath/DropInPaths source for ${unit}"
  grep -q "^executable|${unit_b64}|" <<<"${manager_facts}" \
    || fail "typed manager facts contained no composed Exec* executable for ${unit}"
  case "${unit}" in
    mcloving-postgres.service | mcloving-postgres-data-volume.service)
      expected_nnp=no
      command_rows="$(grep "^command-executable-ExecStart|${unit_b64}|" <<<"${manager_facts}" || true)"
      [[ -n "${command_rows}" ]] \
        || fail "${unit} reports no typed ExecStart command executable"
      if grep -v -x "command-executable-ExecStart|${unit_b64}|${selected_podman_b64}" \
          <<<"${command_rows}" | grep -q .; then
        fail "${unit} has an ExecStart command other than selected Podman ${MCLOVING_CI_PODMAN_COMMAND}"
      fi
      if [[ "${unit}" == mcloving-postgres.service ]]; then
        grep -qx "command-argument-ExecStart|${unit_b64}|${sdnotify_conmon_b64}" \
          <<<"${manager_facts}" \
          || fail "${unit} does not use Quadlet's version-stable --sdnotify=conmon readiness mode"
        for forbidden_sdnotify_b64 in \
          "${sdnotify_healthy_b64}" "${sdnotify_container_b64}"; do
          if grep -qx "command-argument-ExecStart|${unit_b64}|${forbidden_sdnotify_b64}" \
              <<<"${manager_facts}"; then
            fail "${unit} uses a container/health notification mode the PostgreSQL image does not own"
          fi
        done
      fi
      for stop_property in ExecStop ExecStopPost; do
        command_rows="$(grep "^command-executable-${stop_property}|${unit_b64}|" <<<"${manager_facts}" || true)"
        [[ -n "${command_rows}" ]] || continue
        if grep -v -x "command-executable-${stop_property}|${unit_b64}|${selected_podman_b64}" \
            <<<"${command_rows}" | grep -q .; then
          fail "${unit} has an ${stop_property} command other than selected Podman ${MCLOVING_CI_PODMAN_COMMAND}"
        fi
      done
      ;;
    *) expected_nnp=yes ;;
  esac
  nnp_b64="$(printf '%s' "${expected_nnp}" | base64 -w0)"
  grep -q "^no-new-privileges|${unit_b64}|${nnp_b64}$" <<<"${manager_facts}" \
    || fail "the manager did not report runtime NoNewPrivileges=${expected_nnp} for ${unit}"
done
echo "   typed manager facts covered five services; generated units execute ${MCLOVING_CI_PODMAN_COMMAND}; NNP=yes on native services and measured-incompatible on cold Podman services"

# ---------------------------------------------------------------------------
step "[5/10] systemd resolved the ordering the units declare"

# Ordering is the thing the other suite most conspicuously cannot prove: it
# achieves the sequence by writing the steps one after another in bash, so
# Requires=/After= are asserted by nobody. Read back from the manager.
requires="$(systemctl --user show -p Requires --value mcloving-controller.service)"
after="$(systemctl --user show -p After --value mcloving-controller.service)"
[[ "${requires}" == *"mcloving-db-init.service"* ]] \
  || fail "the manager does not report mcloving-controller.service requiring mcloving-db-init.service; it reported: ${requires}"
[[ "${after}" == *"mcloving-postgres.service"* ]] \
  || fail "the manager does not order mcloving-controller.service after mcloving-postgres.service; it reported: ${after}"
echo "   controller Requires=${requires}"
echo "   controller After=${after}"

agent_after="$(systemctl --user show -p After --value mcloving-agent.service)"
[[ "${agent_after}" == *"mcloving-controller.service"* ]] \
  || fail "the manager does not order mcloving-agent.service after mcloving-controller.service; it reported: ${agent_after}"
echo "   agent After=${agent_after}"

# ---------------------------------------------------------------------------
step "[6/10] contracts, PKI and enrollment"

# NOT ${config_base}/mcloving. `mcloving-install` writes contracts and PKI to
# the LITERAL %h/.config/mcloving and uses the manager's effective XDG base only
# for units and quadlets; on an account with an absolute XDG_CONFIG_HOME those
# are different directories, and reading the contracts from the XDG one would
# find nothing.
config="${home_dir}/.config/mcloving"
pki="${config}/pki"
organization_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
project_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
superuser_password="d001-$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
tenant_password="d001-$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
api_token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
artifact_token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
agent_id="deploy001-agent"

openssl req -new -newkey rsa:2048 -nodes -x509 -days 1 -subj "/CN=mcloving-d001-ca" \
  -keyout "${pki}/ca-key.pem" -out "${pki}/ca.pem" 2>/dev/null
printf 'subjectAltName=DNS:controller.internal,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "${pki}/server.ext"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=controller.internal" \
  -keyout "${pki}/controller-server-key.pem" -out "${pki}/server.csr" 2>/dev/null
openssl x509 -req -days 1 -in "${pki}/server.csr" -CA "${pki}/ca.pem" -CAkey "${pki}/ca-key.pem" \
  -CAcreateserial -extfile "${pki}/server.ext" -out "${pki}/controller-server.pem" 2>/dev/null
printf 'extendedKeyUsage=clientAuth\n' > "${pki}/agent.ext"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${agent_id}" \
  -keyout "${pki}/agent-key.pem" -out "${pki}/agent.csr" 2>/dev/null
openssl x509 -req -days 1 -in "${pki}/agent.csr" -CA "${pki}/ca.pem" -CAkey "${pki}/ca-key.pem" \
  -CAcreateserial -extfile "${pki}/agent.ext" -out "${pki}/agent.pem" 2>/dev/null
cp "${pki}/ca.pem" "${pki}/agent-ca.pem"
cp "${pki}/ca.pem" "${pki}/controller-ca.pem"

openssl x509 -in "${pki}/agent.pem" -outform DER -out "${pki}/agent.der" 2>/dev/null
agent_cert_sha256="$(sha256sum "${pki}/agent.der" | awk '{print $1}')"
printf '%s %s trusted-linux %s\n' "${agent_cert_sha256}" "${agent_id}" "${organization_id}" \
  > "${config}/agent-identity-bindings.txt"
chmod 0600 "${config}/agent-identity-bindings.txt"

# EVERY SHIPPED PORT AND HOST IS KEPT. The other suite rewrites 5432/8080/8443
# to reserved ports because several of its trees run concurrently; this arm is
# the real lane on a dedicated account, so the shipped defaults are what get
# tested -- including that the quadlet's PublishPort and the contracts agree.
for pair in \
  "__SET_ME_POSTGRES_SUPERUSER_PASSWORD__|${superuser_password}" \
  "__SET_ME_TENANT_PASSWORD__|${tenant_password}" \
  "__SET_ME_API_BEARER_TOKEN_MINIMUM_32_BYTES__|${api_token}" \
  "__SET_ME_DISTINCT_ARTIFACT_TOKEN_MINIMUM_32_BYTES__|${artifact_token}" \
  "__SET_ME_ORGANIZATION_UUID__|${organization_id}" \
  "__SET_ME_ORGANIZATION_SLUG__|d001-org" \
  "__SET_ME_PROJECT_UUID__|${project_id}" \
  "__SET_ME_PROJECT_SLUG__|d001-project" \
  "__SET_ME_AGENT_ID__|${agent_id}"; do
  sed -i "s|${pair%%|*}|${pair#*|}|g" "${config}"/*.env
done
! grep -Eq '__SET_ME_[A-Z0-9_]+__' "${config}"/*.env \
  || fail "a placeholder survived contract rendering: $(grep -Eho '__SET_ME_[A-Z0-9_]+__' "${config}"/*.env | sort -u | tr '\n' ' ')"
echo "   contracts rendered, PKI written, ${agent_id} enrolled"

# The guard is the gate the units run at ExecStartPre; ask it now so a contract
# defect is named here rather than as an opaque unit failure.
"${libexec_root}/helpers/mcloving-env-guard" controller "${config}/controller.env" >/dev/null \
  || fail "the controller contract does not satisfy mcloving-env-guard"
echo "   mcloving-env-guard: controller contract satisfied"
# THE AGENT'S GUARD CANNOT BE PRE-FLIGHTED, and that is a finding rather than an
# inconvenience. It requires MCLOVING_AGENT_WORKSPACE_ROOT to already exist, and
# the only thing that creates it is `StateDirectory=mcloving-agent
# mcloving-agent/workspace` on the unit, which systemd materialises at 0700
# BEFORE any Exec* line. So the agent contract is validated by the unit's own
# ExecStartPre, and asserted below by the unit reaching active.
#
# The other suite has to `mkdir -p` that path by hand, with the comment "Mirror
# what StateDirectory= creates for the real units" -- a hand-made stand-in for
# a systemd feature, which is precisely the coupling this arm exists to replace
# with the real thing. Step 8 asserts systemd created it, and that we did not.
state_base="${state_probe}"
[[ ! -e "${state_base}/mcloving-agent/workspace" ]] \
  || fail "the agent workspace root already exists before any unit ran; this arm must not create what StateDirectory= is supposed to"

# ---------------------------------------------------------------------------
step "[7/10] the runbook's own enable command must work"

# THE GATE THAT FOUND A SHIPPED DEFECT. `mcloving-install` prints, and
# docs/operations/DEPLOYMENT_V1.md step 5 documents,
#   systemctl --user enable --now mcloving-postgres mcloving-db-init ...
# and that command FAILS: `mcloving-postgres.service` is generated by Quadlet
# and systemd refuses to enable a generated unit --
#   "Unit .../generator/mcloving-postgres.service is transient or generated."
# Quadlet honours the quadlet's own `[Install] WantedBy=default.target`, so the
# generated unit needs starting, not enabling. Nothing could have found this
# without running systemctl, which is the entire argument for this arm.
#
# So the documented sequence is asserted here, as a command, rather than
# trusted as prose -- AND IN THE DOCUMENTED ORDER. `--now` starts the units, and
# the runbook puts the contracts and the PKI before this step for exactly that
# reason: run it earlier and `mcloving-env-guard` refuses at ExecStartPre,
# correctly, on placeholders nobody has replaced yet. A first cut of this arm
# ran the enable before step 6 and failed that way.
documented=(mcloving-db-init mcloving-controller mcloving-agent)
# `--now` is part of the documented command and part of what it has to prove:
# enabling and starting are different operations and the runbook asks for both.
# Running plain `enable` here and starting the units separately later would have
# left the documented sequence unexercised while claiming to be its gate.
service_start_attempted=1
systemctl --user enable --now "${documented[@]}" \
  || fail "the documented enable --now command failed for ${documented[*]}"
systemctl --user start mcloving-postgres.service \
  || fail "the documented start of the generated postgres unit failed"
for unit in "${documented[@]}"; do
  enabled="$(systemctl --user is-enabled "${unit}.service" 2>&1 || true)"
  [[ "${enabled}" == "enabled" ]] \
    || fail "${unit}.service reports is-enabled=${enabled} after the documented enable"
done
# And the generated one must NOT be enablable -- pinning the reason the runbook
# had to change, so a future edit cannot quietly put it back.
if systemctl --user enable mcloving-postgres >/dev/null 2>&1; then
  fail "systemd accepted 'enable mcloving-postgres'; the runbook's original wording would then have been correct and this gate is now wrong"
fi
echo "   enabled: ${documented[*]}; mcloving-postgres refuses enable (generated), as expected"

# ---------------------------------------------------------------------------
step "[8/10] the lane the documented command started, as the manager reports it"

# Podman 4.9 can initialize its rootless store even for `--version`, so the
# early host resolver must not invoke it. The generated volume service above
# owns the account's first Podman operation; only now compare the command and
# Quadlet versions after manager facts already bound both generated units to
# the selected absolute command path.
actual_podman_version="$(podman --version | awk '{print $NF}')" \
  || fail "the selected Podman command did not report its version after cold start"
[[ "${actual_podman_version}" == "${MCLOVING_CI_QUADLET_VERSION}" ]] \
  || fail "the selected Podman and Quadlet versions differ after cold start (${actual_podman_version} != ${MCLOVING_CI_QUADLET_VERSION})"
echo "   selected Podman/Quadlet version=${actual_podman_version} after cold start"

# Quadlet's conmon notification means the generated unit reports started once
# the container is running.  The dependent db-init oneshot then owns the
# version-stable health barrier: two bounded `pg_isready` successes precede all
# migration/provisioning work, and the controller Requires= its success.
# Nothing is started here: the documented `enable --now` in step 7 did it, which
# is the point of running the documented command rather than a convenient one.
# This step only reads back what the manager made of it.

for unit in mcloving-controller.service mcloving-agent.service; do
  active="$(systemctl --user show -p ActiveState --value "${unit}")"
  sub="$(systemctl --user show -p SubState --value "${unit}")"
  [[ "${active}" == "active" ]] \
    || fail "${unit} is ${active}/${sub} after start; $(systemctl --user status "${unit}" --no-pager -n 20 2>&1 | tail -20)"
  echo "   ${unit} ${active}/${sub} MainPID=$(systemctl --user show -p MainPID --value "${unit}")"
done
# db-init is Type=oneshot RemainAfterExit=yes: active/exited is its success.
db_init="$(systemctl --user show -p ActiveState --value mcloving-db-init.service)/$(systemctl --user show -p SubState --value mcloving-db-init.service)"
[[ "${db_init}" == "active/exited" ]] \
  || fail "mcloving-db-init.service is ${db_init}, not active/exited"
echo "   mcloving-db-init.service ${db_init}"
volume_state="$(systemctl --user show -p ActiveState --value mcloving-postgres-data-volume.service)/$(systemctl --user show -p SubState --value mcloving-postgres-data-volume.service)"
[[ "${volume_state}" == "active/exited" ]] \
  || fail "mcloving-postgres-data-volume.service is ${volume_state}, not active/exited"
for unit in mcloving-controller.service mcloving-agent.service; do
  nnp_pid="$(systemctl --user show -p MainPID --value "${unit}")"
  [[ "${nnp_pid}" =~ ^[0-9]+$ && "${nnp_pid}" -gt 0 ]] \
    || fail "${unit} has no live PID for the kernel NoNewPrivs proof"
  grep -Eq '^NoNewPrivs:[[:space:]]+1$' "/proc/${nnp_pid}/status" \
    || fail "${unit} MainPID ${nnp_pid} does not carry the kernel NoNewPrivs bit"
done
[[ -f "${nnp_db_marker}" ]] \
  || fail "the db-init in-unit probe did not observe kernel NoNewPrivs=1"
echo "   kernel NoNewPrivs=1 observed in controller, agent, and db-init; cold Podman succeeded without the incompatible bit"

# systemd created the agent's state tree, not this script. The other suite
# mkdir -p's this path to stand in for StateDirectory=; here the real directive
# is what made it, at the mode the directive specifies.
# From the manager's effective state root, which is what the installer rendered
# into the contract and what StateDirectory= therefore creates. Hard-coding
# ~/.local/state would inspect a path the services never used on an account with
# a custom XDG_STATE_HOME -- and pass, having looked at nothing.
workspace="${state_base}/mcloving-agent/workspace"
[[ -d "${workspace}" ]] \
  || fail "StateDirectory= did not create ${workspace}; the agent's guard passed on something this arm cannot account for"
mode="$(stat -c '%a' "${workspace}")"
[[ "${mode}" == "700" ]] \
  || fail "${workspace} is mode ${mode}, not the 0700 StateDirectoryMode= specifies"
echo "   StateDirectory= created ${workspace} at ${mode}, unaided"

# THE STABILITY WINDOW, against real units for the first time. The library's
# require_service_stable samples ActiveState/SubState/MainPID/NRestarts to catch
# a Type=exec unit that execs, exits, and is restarted in a loop by
# Restart=on-failure -- a shape that looks "active" at any single instant. The
# other suite skips this entirely under --no-systemd.
require_service_stable 0 mcloving-controller.service \
  || fail "mcloving-controller.service did not hold steady"
require_service_stable 0 mcloving-agent.service \
  || fail "mcloving-agent.service did not hold steady"
echo "   controller and agent held steady across the sampling window"

# ExecStartPost=mcloving-health on the controller unit means a controller that
# never answers fails the UNIT. Ask the manager, from outside, the way a
# transition does.  Give it an unusable inherited TMPDIR too: the running
# environment may contain credentials, so the snapshot must live on a held,
# unlinked descriptor beneath the deployment root rather than in caller-chosen
# temporary storage.
TMPDIR="${scratch}/missing-untrusted-health-tmp" \
  "${libexec_root}/helpers/mcloving-health" controller "${config}/controller.env" \
  --unit mcloving-controller.service \
  || fail "mcloving-health could not reach the controller through the manager"
health_snapshot_residue="$(find "${libexec_root}" -maxdepth 1 \
  -name '.mcloving-health.*' -print -quit)"
[[ -z "${health_snapshot_residue}" ]] \
  || fail "mcloving-health left a named environment snapshot at ${health_snapshot_residue}"
echo "   mcloving-health answered through the manager"

# ---------------------------------------------------------------------------
step "[9/10] service-managed upgrade and rollback"

# Both scripts `exit 0` immediately under --no-systemd, so everything past the
# symlink flip -- stop order, restart order, and the health gates between them --
# has never executed in any gate. Here they run for real.
# A SECOND release, because upgrading to the one already installed is refused
# by name ("release ... is already current; nothing to upgrade") and would prove
# nothing about the transition. A trailing newline on mcloving-cli changes the
# release digest without touching a binary any unit starts -- the same device
# the other suite uses for the same reason.
release2_dir="${scratch}/release2"
cp -r "${release_dir}" "${release2_dir}"
printf '\n' >> "${release2_dir}/mcloving-cli"
( cd "${release2_dir}" && sha256sum mcloving-controller mcloving-agent \
    mcloving-cli mcloving-identity-admin > "${scratch}/checksums2.sha256" )

before_release="$(readlink "${libexec_root}/current")"
"${repo_root}/deploy/bin/mcloving-upgrade" --home "${home_dir}" \
  --release-dir "${release2_dir}" --checksums "${scratch}/checksums2.sha256" \
  || fail "service-managed upgrade failed"
after_release="$(readlink "${libexec_root}/current")"
echo "   upgrade: current ${before_release} -> ${after_release}"
for unit in mcloving-controller.service mcloving-agent.service; do
  active="$(systemctl --user show -p ActiveState --value "${unit}")"
  [[ "${active}" == "active" ]] || fail "${unit} is ${active} after the upgrade"
done
echo "   controller and agent active after a service-managed upgrade"

"${repo_root}/deploy/bin/mcloving-rollback" --home "${home_dir}" \
  || fail "service-managed rollback failed"
rolled_back="$(readlink "${libexec_root}/current")"
[[ "${rolled_back}" == "${before_release}" ]] \
  || fail "rollback left current at ${rolled_back}, not the pre-upgrade ${before_release}"
[[ "${after_release}" != "${before_release}" ]] \
  || fail "the upgrade did not change the current release, so the rollback proved nothing"
for unit in mcloving-controller.service mcloving-agent.service; do
  active="$(systemctl --user show -p ActiveState --value "${unit}")"
  [[ "${active}" == "active" ]] || fail "${unit} is ${active} after the rollback"
done
echo "   rollback: current back to ${rolled_back}, both services active"

# ---------------------------------------------------------------------------
step "[10/10] the deployable-runtime gate, against this installed deployment"

# The other half of the acceptance sentence. The gate spawns a controller whose
# path `CARGO_BIN_EXE_mcloving-controller` baked in at compile time, so it runs
# the BUILD TREE's binary rather than the installed one -- which is checkable
# rather than hand-waved: the installed release was staged from that build and
# digest-verified, so the two are byte-identical, and this asserts it instead of
# assuming it.
installed_controller="${libexec_root}/current/mcloving-controller"
gate_controller="$(dirname "$(dirname "${runtime_gate}")")/mcloving-controller"
[[ -x "${installed_controller}" ]] || fail "no installed controller at ${installed_controller}"
if [[ -x "${gate_controller}" ]]; then
  [[ "$(sha256sum < "${installed_controller}")" == "$(sha256sum < "${gate_controller}")" ]] \
    || fail "the controller the gate will spawn is not byte-identical to the installed one; the gate would be testing a different binary than this deployment runs"
  echo "   the gate's controller is byte-identical to the installed one"
else
  # NOT A NOTE. Printing "identity unasserted" and carrying on is the shape of
  # defect this whole ticket is about: the gate would run, report success, and
  # nobody would know which controller it had exercised. If the identity cannot
  # be established, the claim cannot be made.
  fail "cannot locate the controller beside ${runtime_gate}, so the binary the gate spawns cannot be compared with the installed one; pass the test binary where cargo built it"
fi

# The DATABASE, ROLES and split credentials are this deployment's, read from the
# contract systemd starts the controller with -- not a database the test brought
# up for itself, which is what made this gate and the install two unrelated CI
# jobs sharing no state.
migration_url="$(grep -E '^MCLOVING_MIGRATION_DATABASE_URL=' "${config}/controller.env" | cut -d= -f2-)"
runtime_db_url="$(grep -E '^MCLOVING_DATABASE_URL=' "${config}/controller.env" | cut -d= -f2-)"
[[ -n "${migration_url}" && -n "${runtime_db_url}" ]] \
  || fail "could not read both database URLs from ${config}/controller.env"
[[ "${migration_url}" != "${runtime_db_url}" ]] \
  || fail "the migration and runtime URLs are identical; the split this gate checks does not exist"

# THIS GATE LEAVES THE DATABASE WEAKENED IF IT FAILS.
# `failed_runtime_preflight_does_not_rotate_the_active_api_credential`
# deliberately weakens `identity_sessions_tenant_policy` to
# `USING (true OR ...)`, asserts that startup is REJECTED, and only restores the
# policy after that assertion. A failed assertion unwinds past the restore, so
# the policy stays weakened -- and RLS is then effectively off for reads. Under
# --keep the volume would survive with it, ready for someone to restart.
#
# Fixing the test to restore on unwind is the better repair and is not this
# ticket's file. What this script owes is not to PRESERVE the result: the flag
# below makes teardown destroy the database on a failed gate even under --keep,
# and say so. The deployment tree is still kept, so the failure is inspectable.
database_possibly_weakened=1
gate_log="${scratch}/runtime-gate.log"
if MCLOVING_TEST_DATABASE_URL="${migration_url}" \
   MCLOVING_TEST_RUNTIME_DATABASE_URL="${runtime_db_url}" \
     "${runtime_gate}" --ignored --test-threads=1 2>&1 | tee "${gate_log}"; then
  gate_status=0
else
  gate_status=1
fi
(( gate_status == 0 )) \
  || fail "the deployable-runtime gate failed against this installed deployment"

# EXIT STATUS IS NOT THE ASSERTION. A Rust test binary that runs NOTHING exits
# 0: rename the two tests out of `--ignored`, delete one, or mis-filter them and
# this step would print "gate passed" having checked nothing about the
# deployment. That is the defect DEPLOY-001 was reverted for -- the gate itself
# used to return success when MCLOVING_TEST_DATABASE_URL was unset -- so
# accepting a zero-test run here would rebuild it one level up, inside its own
# fix. Count what actually ran. `>= 2` rather than the two names: a rename still
# proves two behaviours, while a deletion, an un-ignored test or a bad filter
# drops the count and is refused.
gate_passed="$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' "${gate_log}" | tail -1)"
[[ -n "${gate_passed}" ]] \
  || fail "the deployable-runtime gate exited 0 but printed no 'test result: ok' summary; it cannot be shown to have run"
(( gate_passed >= 2 )) \
  || fail "the deployable-runtime gate exited 0 having run only ${gate_passed} test(s); DEPLOY-001's acceptance needs both shipped_controller_uses_split_credentials_and_executes_submissions and failed_runtime_preflight_does_not_rotate_the_active_api_credential to execute against this deployment"
database_possibly_weakened=0
echo "   deployable-runtime gate passed against the installed deployment's database and roles (${gate_passed} tests executed)"

echo
echo "service-managed deployment lane passed: install -> daemon-reload -> quadlet generation ->"
echo "  documented enable -> ordered start -> stability -> health through the manager ->"
echo "  service-managed upgrade -> service-managed rollback -> deployable-runtime gate"
