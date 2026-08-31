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
for pid in "$@"; do
  if [[ ! "${pid}" =~ ^[1-9][0-9]*$ || ! -r "/proc/${pid}/stat" ]]; then
    echo "PID is not a readable live process: ${pid}" >&2
    exit 2
  fi
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
  echo $(( ${12} + ${13} ))
}

read_start_time() {
  local pid="$1" stat tail
  stat="$(<"/proc/${pid}/stat")"
  tail="${stat##*) }"
  # shellcheck disable=SC2086
  set -- ${tail}
  echo "${20}"
}

for pid in "$@"; do
  starts["${pid}"]="$(read_ticks "${pid}")"
  start_times["${pid}"]="$(read_start_time "${pid}")"
done
started_ns="$(date +%s%N)"
sleep "${seconds}"
ended_ns="$(date +%s%N)"

echo -e "source_head\t$(git -C "${repo_root}" rev-parse HEAD)"
echo -e "source_tree\t$(git -C "${repo_root}" rev-parse 'HEAD^{tree}')"
echo -e "host\t$(hostname -s)"
echo -e "sample_seconds\t${seconds}"
echo -e "pid\tcomm\tcpu_percent"
total_ticks=0
for pid in "$@"; do
  if [[ "$(read_start_time "${pid}")" != "${start_times["${pid}"]}" ]]; then
    echo "PID identity changed during sample: ${pid}" >&2
    exit 1
  fi
  end="$(read_ticks "${pid}")"
  delta=$(( end - starts["${pid}"] ))
  total_ticks=$(( total_ticks + delta ))
  comm="$(<"/proc/${pid}/comm")"
  awk -v pid="${pid}" -v comm="${comm}" -v ticks="${delta}" \
    -v hz="${ticks_per_second}" -v elapsed_ns="$(( ended_ns - started_ns ))" \
    'BEGIN { printf "%s\t%s\t%.3f\n", pid, comm, ticks / hz / (elapsed_ns / 1e9) * 100 }'
done
total_percent="$(awk -v ticks="${total_ticks}" -v hz="${ticks_per_second}" \
  -v elapsed_ns="$(( ended_ns - started_ns ))" \
  'BEGIN { printf "%.3f", ticks / hz / (elapsed_ns / 1e9) * 100 }')"
echo -e "total\t-\t${total_percent}"
target="${MCLOVING_IDLE_CPU_TARGET_PERCENT:-5}"
awk -v total="${total_percent}" -v target="${target}" \
  'BEGIN { if (total >= target) { printf "idle CPU %.3f%% is not below %.3f%%\n", total, target > "/dev/stderr"; exit 1 } }'
