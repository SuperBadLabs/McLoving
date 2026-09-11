# PAR-011 closure receipt: container stages

Ticket: `PAR-011`. Merged as PR #146, squash commit
`0eb949baaf86fde35003fc985d101d8e46a10168` on 2026-09-11.

## What merged

- `Stage.image` in pipeline-ir schema minor 6: a digest-pinned reference
  (`name@sha256:<64 hex>`) only; a tag is refused at compile, admission and
  execution. Container stages ride the version-5 envelope with an `image`
  key, require scheduler capability `container-podman-v1`, and are
  Linux-only at admission; a version-1 payload carrying an image is refused,
  as is a multiline or `=`-bearing environment entry on a container stage.
- The agent advertises `container-podman-v1` only when
  `MCLOVING_AGENT_PODMAN_PATH` (absolute; trust-class in the deployment
  contract) answers `--version` within ten seconds under the pinned
  environment, reported once per process otherwise.
- Each step runs as `podman run --rm --name mcloving-<attempt>-<ordinal>
  --cidfile <spool>/container.cid --userns=keep-id --volume
  <workspace>:/workspace:Z --workdir /workspace --env-file /proc/self/fd/N
  --entrypoint <program> <image> <args>`; the environment reaches podman
  through a memfd so no value enters the argument vector; the podman client
  receives a fixed minimal environment; both host paths are made absolute.
- Teardown: after the client group is proven empty on every arm, the
  executor runs `rm --force --time 0 --ignore` (15 s bound) and accepts only
  a `container exists` exit status of 1 (5 s bound) as proof; anything else
  is `ContainerUnverified`, which parks the attempt reconciliation-required.
  A failed group proof still attempts the reap before its error propagates.
  Container attempts reserve the 20 s teardown inside the lease on top of the
  termination grace, and an agent whose lease cannot hold cadence, grace and
  reserve with a runtime configured refuses to start.
- Journal schema 4 records `container_name` and a byte-exact hex-encoded
  `container_context` (runtime path, `HOME`, `XDG_RUNTIME_DIR`) before the
  spawn; recovery reaps only under the same context, retries parked rows
  every session, keeps a discharged or retired attempt parked while its
  container is unproven, and reaps even when the client group itself was
  unverifiable. The sequential (Jenkins) planner refuses container stages
  rather than lowering them to host processes. Windows refuses containers.

## Review

Twenty-nine findings across twelve Codex and Copilot rounds (3,3,3,2,3,3,1,
2,3,2,1,2); twenty-six fixed in the PR. At the ten-round cap the three
remaining were filed as `AGENT-009`: pin the effective podman store identity
into launch and reap; launch under an agent-owned containers configuration
with an empty mounts file so implicit `mounts.conf` binds cannot widen the
mount set; refuse `#`-prefixed environment names for container stages.

## Verification

| Check | Result |
|---|---|
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | clean |
| `cargo test -p mcloving-agent --lib` | 92 passed |
| `cargo test -p mcloving-agent-runtime --lib` | 40 passed |
| `cargo test -p mcloving-controller-api --lib` | 43 passed |
| `cargo test -p mcloving-controller-api --test sequential_planner` | 7 passed |
| `cargo test -p mcloving-agent --test remote_work` (PostgreSQL, shipped binaries, `MCLOVING_TEST_PODMAN=1`) | 7 passed, including the Alpine os-release step with the host root invisible and the timed-out step whose container is proven gone |
| `deploy/test-deployment.sh` (local) | passed |
| PR head Foundation and Windows | success |
| Exact-main Foundation | run 34584499133, success |
| Exact-main Windows Agent | run 34584499144, success |

Proof fixture: `examples/parity/container-os-release.pipeline.yaml`.

## Threat model

Boundaries reviewed: TM-003, TM-005, TM-006, TM-016, TM-023, TM-052 and
`SEC-005` (partial: plain process steps remain on the host); the closure
section in `docs/threat-model/README.md` records the review and its residuals
(`AGENT-009`, `SEC-005`). No production authority is granted.
