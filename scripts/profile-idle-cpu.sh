#!/usr/bin/env bash
set -euo pipefail

if (( $# < 2 )); then
  echo "usage: $0 SECONDS PID [PID ...]" >&2
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

ticks_per_second="$(getconf CLK_TCK)"
declare -A starts
read_ticks() {
  local pid="$1" stat tail
  stat="$(<"/proc/${pid}/stat")"
  tail="${stat##*) }"
  # shellcheck disable=SC2086
  set -- ${tail}
  echo $(( ${12} + ${13} ))
}

for pid in "$@"; do
  starts["${pid}"]="$(read_ticks "${pid}")"
done
started_ns="$(date +%s%N)"
sleep "${seconds}"
ended_ns="$(date +%s%N)"

echo -e "pid\tcomm\tcpu_percent"
total_ticks=0
for pid in "$@"; do
  end="$(read_ticks "${pid}")"
  delta=$(( end - starts["${pid}"] ))
  total_ticks=$(( total_ticks + delta ))
  comm="$(<"/proc/${pid}/comm")"
  awk -v pid="${pid}" -v comm="${comm}" -v ticks="${delta}" \
    -v hz="${ticks_per_second}" -v elapsed_ns="$(( ended_ns - started_ns ))" \
    'BEGIN { printf "%s\t%s\t%.3f\n", pid, comm, ticks / hz / (elapsed_ns / 1e9) * 100 }'
done
awk -v ticks="${total_ticks}" -v hz="${ticks_per_second}" \
  -v elapsed_ns="$(( ended_ns - started_ns ))" \
  'BEGIN { printf "total\t-\t%.3f\n", ticks / hz / (elapsed_ns / 1e9) * 100 }'
