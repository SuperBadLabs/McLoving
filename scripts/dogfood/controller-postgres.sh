#!/usr/bin/env bash
# Foundation `controller-postgres`, run on the host as the lane runs it on
# the runner: a PostgreSQL service container from the pinned image, then
# the lane's steps in order with the same environment, including
# MCLOVING_TEST_PODMAN=1 so the container-stage tests run against this
# host's rootless podman rather than skipping. (The repository's own local
# mirror, scripts/test-controller-postgres.sh, runs the suites inside the
# pinned Rust image, where podman is not available; the dogfood mirrors
# the lane, not the mirror.)
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
dogfood_lane controller-postgres

container_name="mcloving-dogfood-postgres-${RANDOM}-${RANDOM}"
port="$(python3 -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
cleanup() { podman rm --force "${container_name}" >/dev/null 2>&1 || true; }
trap cleanup EXIT
podman run --detach --rm --name "${container_name}" --publish "127.0.0.1:${port}:5432" \
  --env POSTGRES_USER=mcloving --env POSTGRES_HOST_AUTH_METHOD=trust --env POSTGRES_DB=mcloving \
  "${MCLOVING_POSTGRES_IMAGE}" >/dev/null
for _ in $(seq 1 60); do
  if podman exec "${container_name}" pg_isready --username mcloving --dbname mcloving >/dev/null 2>&1; then
    sleep 0.5
    podman exec "${container_name}" pg_isready --username mcloving --dbname mcloving >/dev/null 2>&1 && break
  fi
  sleep 0.5
done
podman exec "${container_name}" pg_isready --username mcloving --dbname mcloving >/dev/null
export MCLOVING_TEST_DATABASE_URL="postgres://mcloving@127.0.0.1:${port}/mcloving"

cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-store --test postgres_truth
cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-store --test pipeline_operational_state -- --test-threads=1
cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-store --test trigger_ingress -- --test-threads=1
cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-store --test discovery -- --test-threads=1
cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-api --test route_denials -- --test-threads=1
cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-api --test scm_webhook --test notifications -- --test-threads=1
cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-store --test identity_lifecycle
cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-store --test authorization_mapping
cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-store --test external_read_consumers
cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-store --test external_admin_clients
cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-api --test oidc_flow
bash scripts/run-verified-rust-test.sh 1 unsupported-spec --require-postgres \
  cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-api --test unsupported_spec_gate
bash scripts/run-verified-rust-test.sh 30 real-spine --require-postgres \
  cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-execution-spine --test real_spine -- --test-threads=1
bash scripts/run-verified-rust-test.sh 2 deployable-runtime --require-postgres \
  cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller --test deployable_runtime -- --ignored
bash scripts/run-verified-rust-test.sh 1 controller-differential --require-postgres \
  cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller --test diff_001
bash scripts/run-verified-rust-test.sh 2 capability-vocabulary --require-postgres \
  cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller --test capability_vocabulary
cargo "+${RUST_TOOLCHAIN}" build --locked -p mcloving-controller -p mcloving-cache -p mcloving-input-adapter
export MCLOVING_CONTROLLER_BINARY="${dogfood_repo}/target/debug/mcloving-controller"
export MCLOVING_TEST_PODMAN=1
bash scripts/run-verified-rust-test.sh 9 remote-work --require-postgres \
  cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-agent --test remote_work -- --test-threads=1
bash scripts/run-verified-rust-test.sh 1 identity-collision --require-postgres \
  cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-agent --test identity_collision -- --test-threads=1
bash scripts/run-verified-rust-test.sh 8 long-step-lease --require-postgres \
  cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-agent --test long_step_lease -- --test-threads=1
unset MCLOVING_TEST_PODMAN
MCLOVING_CACHE_BINARY="${dogfood_repo}/target/debug/mcloving-cache" bash scripts/test-cache-product.sh
MCLOVING_INPUT_ADAPTER_BINARY="${dogfood_repo}/target/debug/mcloving-input-adapter" bash scripts/test-input-product.sh
bash scripts/test-sequential-runtime.sh
