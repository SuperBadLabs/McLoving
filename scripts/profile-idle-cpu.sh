#!/usr/bin/env bash
set -euo pipefail

if (( $# < 5 )); then
  echo "usage: $0 SECONDS CONTROLLER_PID AGENT_PID POSTGRES_PID PORT_FORWARDER_PID [PID ...]" >&2
  exit 2
fi

seconds="$1"
shift
if [[ ! "${seconds}" =~ ^[1-9][0-9]*$ ]]; then
  echo "SECONDS must be a positive integer" >&2
  exit 2
fi
controller_pid="$1"
agent_pid="$2"
postgres_pid="$3"
forwarder_pid="$4"
input_pids=("$@")
declare -A seen_input_pids
for pid in "$@"; do
  if [[ ! "${pid}" =~ ^[1-9][0-9]*$ || ! -r "/proc/${pid}/stat" ]]; then
    echo "PID is not a readable live process: ${pid}" >&2
    exit 2
  fi
  if [[ -n "${seen_input_pids["${pid}"]:-}" ]]; then
    echo "each profiled stack component must have a distinct PID: ${pid}" >&2
    exit 2
  fi
  seen_input_pids["${pid}"]=1
done

process_identity() {
  local pid="$1"
  <"/proc/${pid}/comm" tr -d '\n'
}

require_component() {
  local role="$1" pid="$2" expected="$3" actual
  actual="$(process_identity "${pid}")"
  if [[ ! "${actual}" =~ ${expected} ]]; then
    echo "${role} PID ${pid} has unexpected process identity: ${actual}" >&2
    exit 2
  fi
}

require_component controller "${controller_pid}" '^mcloving-contro(ller)?$'
require_component agent "${agent_pid}" '^mcloving-agent$'
require_component postgres "${postgres_pid}" '^postgres$'
# The supported deployment port-forwarders are SSH, kubectl, socat, and the
# container-engine proxy processes used by the local proof topology.
require_component port-forwarder "${forwarder_pid}" '^(ssh|kubectl|socat|docker-proxy|rootlessport)$'

list_children() {
  local parent_pid="$1" stat_path stat tail pid_path
  for stat_path in /proc/[0-9]*/stat; do
    if ! stat="$(<"${stat_path}")"; then
      # A process may legitimately disappear while /proc is enumerated. Its
      # CPU is accounted through its waiting parent's cumulative child ticks.
      continue
    fi
    tail="${stat##*) }"
    # shellcheck disable=SC2086
    set -- ${tail}
    if [[ "${2}" == "${parent_pid}" ]]; then
      pid_path="${stat_path#/proc/}"
      printf '%s\n' "${pid_path%%/*}"
    fi
  done
}

collect_tree() {
  local root_pid="$1" index=0 parent child
  local -a tree=("${root_pid}")
  while (( index < ${#tree[@]} )); do
    parent="${tree[${index}]}"
    while IFS= read -r child; do
      tree+=("${child}")
    done < <(list_children "${parent}")
    index=$(( index + 1 ))
  done
  printf '%s\n' "${tree[@]}"
}

declare -a profile_pids profile_roles
declare -A tree_snapshots seen_profile_pids
append_tree() {
  local root_pid="$1" root_role="$2" pid role
  local -a tree
  mapfile -t tree < <(collect_tree "${root_pid}")
  tree_snapshots["${root_pid}"]="${tree[*]}"
  for pid in "${tree[@]}"; do
    if [[ -n "${seen_profile_pids["${pid}"]:-}" ]]; then
      echo "required component process trees overlap at PID: ${pid}" >&2
      exit 2
    fi
    seen_profile_pids["${pid}"]=1
    role="${root_role}"
    if [[ "${pid}" != "${root_pid}" ]]; then
      role="${root_role}-child"
    fi
    profile_pids+=("${pid}")
    profile_roles+=("${role}")
  done
}

append_tree "${controller_pid}" controller
append_tree "${agent_pid}" agent
append_tree "${postgres_pid}" postgres
append_tree "${forwarder_pid}" port-forwarder
for pid in "${input_pids[@]:4}"; do
  append_tree "${pid}" extra
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "$(git -C "${repo_root}" status --porcelain)" ]]; then
  echo "idle-CPU receipt requires a clean source checkout" >&2
  exit 2
fi
ticks_per_second="$(getconf CLK_TCK)"
declare -A starts
declare -A start_times
read_ticks() {
  local pid="$1" stat tail
  stat="$(<"/proc/${pid}/stat")"
  tail="${stat##*) }"
  # shellcheck disable=SC2086
  set -- ${tail}
  # Include cumulative CPU from already reaped children (cutime/cstime) so a
  # descendant born and reaped entirely inside the sample cannot disappear
  # between the two process-tree snapshots. Live descendants are enumerated
  # and counted independently; their CPU is not present in these child fields.
  echo $(( ${12} + ${13} + ${14} + ${15} ))
}

read_start_time() {
  local pid="$1" stat tail
  stat="$(<"/proc/${pid}/stat")"
  tail="${stat##*) }"
  # shellcheck disable=SC2086
  set -- ${tail}
  echo "${20}"
}

for pid in "${profile_pids[@]}"; do
  starts["${pid}"]="$(read_ticks "${pid}")"
  start_times["${pid}"]="$(read_start_time "${pid}")"
done
started_ns="$(date +%s%N)"
sleep "${seconds}"
ended_ns="$(date +%s%N)"

for root_pid in "${input_pids[@]}"; do
  current_tree="$(collect_tree "${root_pid}" | paste -sd ' ' -)"
  if [[ "${current_tree}" != "${tree_snapshots["${root_pid}"]}" ]]; then
    echo "component process tree changed during sample at root PID: ${root_pid}" >&2
    exit 1
  fi
done

echo -e "source_head\t$(git -C "${repo_root}" rev-parse HEAD)"
echo -e "source_tree\t$(git -C "${repo_root}" rev-parse 'HEAD^{tree}')"
echo -e "host\t$(hostname -s)"
echo -e "sample_seconds\t${seconds}"
echo -e "target_percent\t5"
echo -e "process_count\t${#profile_pids[@]}"
echo -e "role\tpid\tcomm\tcpu_percent"
total_ticks=0
for index in "${!profile_pids[@]}"; do
  pid="${profile_pids[${index}]}"
  if [[ "$(read_start_time "${pid}")" != "${start_times["${pid}"]}" ]]; then
    echo "PID identity changed during sample: ${pid}" >&2
    exit 1
  fi
  end="$(read_ticks "${pid}")"
  delta=$(( end - starts["${pid}"] ))
  total_ticks=$(( total_ticks + delta ))
  comm="$(<"/proc/${pid}/comm")"
  role="${profile_roles[${index}]}"
  awk -v role="${role}" -v pid="${pid}" -v comm="${comm}" -v ticks="${delta}" \
    -v hz="${ticks_per_second}" -v elapsed_ns="$(( ended_ns - started_ns ))" \
    'BEGIN { printf "%s\t%s\t%s\t%.3f\n", role, pid, comm, ticks / hz / (elapsed_ns / 1e9) * 100 }'
done
total_percent="$(awk -v ticks="${total_ticks}" -v hz="${ticks_per_second}" \
  -v elapsed_ns="$(( ended_ns - started_ns ))" \
  'BEGIN { printf "%.3f", ticks / hz / (elapsed_ns / 1e9) * 100 }')"
echo -e "total\t-\t-\t${total_percent}"
awk -v total="${total_percent}" \
  'BEGIN { if (total >= 5) { printf "idle CPU %.3f%% is not below 5.000%%\n", total > "/dev/stderr"; exit 1 } }'
