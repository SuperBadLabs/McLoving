#!/usr/bin/env bash
# Run the UI-002 executing browser gate against the shipped web client.
#
# The fixture runs on the host because it is a cargo-built binary; the browser
# runs inside the contained image because Chrome's renderer sandbox cannot start
# where AppArmor restricts unprivileged user namespaces. The container joins the
# host network namespace so the fixture can stay bound to loopback rather than
# being exposed on a routable address for the browser's benefit.
#
#   usage: test-ui-browser.sh [--output-dir DIR] [--label LABEL] [--record-only]
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

expected_assertions=18
label="ui-002-browser"
output_dir=""
record_only=()

while (( $# > 0 )); do
  case "$1" in
    --output-dir) output_dir="$2"; shift 2 ;;
    --label) label="$2"; shift 2 ;;
    --record-only) record_only=(--record-only); shift ;;
    --expected-assertions) expected_assertions="$2"; shift 2 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 64 ;;
  esac
done

if [[ -z "${output_dir}" ]]; then
  output_dir="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-ui-browser.XXXXXXXX")"
fi
mkdir -p "${output_dir}"
output_dir="$(cd "${output_dir}" && pwd)"

image="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_tag"])' \
  "${script_dir}/ui-browser/browser-pin.json")"

bash "${script_dir}/ui-browser/build-image.sh"

printf 'Building the UI browser fixture\n' >&2
cargo +1.97.1 build --locked -p mcloving-controller-api --example ui_browser_fixture

# Bind to a caller-chosen loopback port. The gate is the only client, so the
# port is private to this run rather than a service anyone else may reach.
port="${MCLOVING_UI_FIXTURE_PORT:-19090}"
fixture_log="${output_dir}/fixture.log"

fixture_pid=""
cleanup() {
  # Terminate the fixture explicitly. Leaving it running would hold the port
  # against the next run and, worse, would let a later run pass against a
  # process built from different source.
  if [[ -n "${fixture_pid}" ]] && kill -0 "${fixture_pid}" 2>/dev/null; then
    kill "${fixture_pid}" 2>/dev/null || true
    wait "${fixture_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Refuse a port that is already answering. The readiness probe below cannot tell
# our fixture from someone else's: if a fixture left behind by an uncatchable
# kill still holds this port, our own bind loses, the probe connects to the
# stale listener and declares it ready, and the browser then renders the UI
# compiled into THAT binary while the evidence records a source manifest read
# from the current checkout. Falsely bound evidence is worse than no evidence,
# and this gate exists to stop exactly that.
if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
  exec 3<&- 3>&-
  printf 'something is already listening on 127.0.0.1:%s; refusing to run\n' \
    "${port}" >&2
  printf 'a fixture from an interrupted run may have survived -- check with\n' >&2
  printf '  ss -lptn "sport = :%s"\n' "${port}" >&2
  printf 'or set MCLOVING_UI_FIXTURE_PORT to a free port\n' >&2
  exit 70
fi

UI_FIXTURE_ADDRESS="127.0.0.1:${port}" \
  "${repo_root}/target/debug/examples/ui_browser_fixture" >"${fixture_log}" 2>&1 &
fixture_pid=$!

listening=""
for _ in $(seq 1 100); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
    exec 3<&- 3>&-
    listening=yes
    break
  fi
  if ! kill -0 "${fixture_pid}" 2>/dev/null; then
    printf 'UI fixture exited before it listened; log follows\n' >&2
    cat "${fixture_log}" >&2
    exit 70
  fi
  sleep 0.1
done
# The child must still be the one holding the port. It was alive on the last
# iteration of the loop above, but "alive then" is not "alive now".
if [[ -n "${listening}" ]] && ! kill -0 "${fixture_pid}" 2>/dev/null; then
  printf 'the UI fixture exited after the port answered; the listener is not ours\n' >&2
  cat "${fixture_log}" >&2
  exit 70
fi
if [[ -z "${listening}" ]]; then
  # Falling through here and running the gate anyway would report a browser
  # failure for what is really a fixture that never came up.
  printf 'UI fixture did not listen on 127.0.0.1:%s within 10s; log follows\n' \
    "${port}" >&2
  cat "${fixture_log}" >&2
  exit 70
fi

printf 'Running the contained browser gate against 127.0.0.1:%s\n' "${port}" >&2
# The gate has to write its evidence into a directory owned by the invoking
# user, and how a container process reaches that identity differs by podman
# mode. Detect it rather than assuming: `--userns=keep-id` is REJECTED outright
# by a rootful podman, and `--user` alone does the wrong thing under a rootless
# one, so guessing fails either way round.
identity=()
if [[ -n "${MCLOVING_UI_BROWSER_IDENTITY:-}" ]]; then
  # Escape hatch for a host neither branch below describes.
  read -r -a identity <<<"${MCLOVING_UI_BROWSER_IDENTITY}"
else
  rootless="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)"
  case "${rootless}" in
    true)
      # Rootless maps container UID 1000 to a subordinate host UID that cannot
      # write the mount; keep-id maps the invoking user onto the image's
      # runtime UID instead.
      identity=(--userns=keep-id:uid=1000,gid=1000)
      ;;
    false)
      # Rootful applies no remapping, so name the invoking user directly rather
      # than inheriting the image's USER 1000.
      identity=(--user "$(id -u):$(id -g)")
      ;;
    *)
      printf 'cannot determine whether podman is rootless (got %q); set\n' \
        "${rootless}" >&2
      printf 'MCLOVING_UI_BROWSER_IDENTITY to the podman flags to use\n' >&2
      exit 69
      ;;
  esac
fi

podman run --rm \
  --network=host \
  "${identity[@]}" \
  --volume "${script_dir}/ui-browser/gate.py:/gate/gate.py:ro,Z" \
  --volume "${repo_root}/crates/controller-api/ui:/gate/ui:ro,Z" \
  --volume "${output_dir}:/gate/out:rw,Z" \
  "${image}" \
  /gate/gate.py \
  --base-url "http://127.0.0.1:${port}" \
  --output-dir /gate/out \
  --ui-source-dir /gate/ui \
  --label "${label}" \
  --expected-assertions "${expected_assertions}" \
  "${record_only[@]}"
status=$?

printf 'Browser gate evidence written to %s\n' "${output_dir}" >&2
exit "${status}"
