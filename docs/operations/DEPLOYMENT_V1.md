# Deployment v1: single-host systemd + rootless podman (DEPLOY-001)

This runbook covers the first real deployment lane for McLoving: one Linux
host, one dedicated unprivileged service user, PostgreSQL in rootless
podman, and the controller and agent as native systemd user services
running digest-verified release binaries. It exists so that a future
authoritative cutover (CUTOVER-001) has concrete deployed-implementation
digests to re-read — not so that anyone can claim production authority.
Read the [Limitations](#limitations) section before relying on it.

The whole lane is exercised end to end, without root, by
`deploy/test-deployment.sh`, which derives every invocation from the unit
files via `deploy/bin/mcloving-unit-command` so documentation, units, and
test cannot drift apart.

## Topology

| Service | Unit | Runs as | Health gate |
| --- | --- | --- | --- |
| PostgreSQL | `mcloving-postgres.service` (quadlet `deploy/podman/mcloving-postgres.container`) | rootless podman container, image digest-pinned from `tools/versions.env` | `pg_isready` health check; `Notify=healthy` means the unit only reports started when healthy |
| DB bootstrap | `mcloving-db-init.service` (oneshot) | native | exits non-zero unless migrate + tenant login + organization provisioning all succeed |
| Controller | `mcloving-controller.service` | native | `ExecStartPost` requires the public API to answer `/openapi.json` |
| Agent | `mcloving-agent.service` | native | `ExecStartPre` runs `mcloving-agent probe` (one authenticated mTLS session + journal reconciliation) |

Startup order (enforced by `Requires=`/`After=`): postgres healthy →
db-init → controller → agent.

Durable state:

- `mcloving-postgres-data` — named podman volume with the database.
- `~/.local/state/mcloving-controller/` — artifact object root plus the
  disabled embedded worker's journal/workspace (`StateDirectory=`).
- `~/.local/state/mcloving-agent/` — agent journal and workspace root
  (`StateDirectory=mcloving-agent mcloving-agent/workspace`; the agent
  refuses work if the workspace root does not exist).

Both state paths are shown at their default location. systemd creates
`StateDirectory=` leaves under the service manager's `XDG_STATE_HOME`, so a
manager started with a custom absolute value puts them there instead; the
installer renders the contracts against that same root.

## Environment contracts

Each service reads exactly one environment file under `~/.config/mcloving/`
(mode 0600). Templates live in `deploy/env/*.env.example`; the installer
RENDERS them into place once and never overwrites them. Rendering resolves
the absolute paths against the deployment being created: the example home
becomes the installed home, and the runtime-state paths become the XDG state
root the service manager creates `StateDirectory=` leaves under. That root is
`~/.local/state` only while `XDG_STATE_HOME` is unset or relative -- with a
custom absolute value, systemd builds the state tree there, and a contract
copied verbatim would name a workspace that was never created. Every unit runs
`mcloving-env-guard <service> <file>` as `ExecStartPre` and **fails closed**:
a missing file, a missing or empty variable, or a value still carrying a
`__SET_ME…__` placeholder stops the unit before the binary starts. The
guard also enforces cross-variable rules the binaries require:

- `controller.env` — migration and runtime database URLs must differ
  (distinct PostgreSQL roles); `MCLOVING_API_TOKEN` and
  `MCLOVING_ARTIFACT_AGENT_TOKEN` must each be at least 32 bytes and
  mutually distinct; all mTLS paths and the agent identity bindings file
  must be readable.
- `agent.env` — CA/certificate/key paths must be readable and the
  workspace root must already exist.
- `db-init.env` — organization/project ids must be UUIDs.
- `postgres.env` — superuser credentials must be set.

The full variable lists are in the templates; they mirror
`bins/controller/src/main.rs` and `AgentConfig::from_values` in
`bins/agent/src/lib.rs` exactly. The deployed controller keeps its
mandatory embedded worker inert by giving it the capability string
`disabled`, which no submission requests; real work executes only on the
mTLS-enrolled remote agent.

## Install

1. Create the service user and let its manager linger:

   ```sh
   sudo useradd --create-home --shell /bin/bash mcloving
   sudo loginctl enable-linger mcloving
   ```

2. As that user, verify and install a release (digest verification is
   mandatory; there is no bypass flag):

   ```sh
   deploy/bin/mcloving-install \
     --release-dir /path/to/release/binaries \
     --manifest /path/to/release-envelope.json   # or --checksums FILE
   ```

   `--manifest` accepts the REL-001 release-provenance document (either the
   `SignedReleaseEnvelope` JSON or the bare `ReleaseManifest`) and checks
   every binary's sha256 and size against `manifest.components[]`.
   `--checksums` accepts a plain `sha256sum` file. Either way, all four
   binaries (`mcloving-controller`, `mcloving-agent`, `mcloving-cli`,
   `mcloving-identity-admin`) must verify or nothing is installed.

   **Verification gap (deliberate, documented):** this checks artifact
   digests only. It does not verify the Ed25519 release signature,
   transparency evidence, or audit anchor; for that, run
   `mcloving-release-provenance verify-chain` against the full evidence set
   before handing the bundle to the installer. The installed layout is:

   ```text
   ~/.local/libexec/mcloving/releases/<id>/   verified binaries
   ~/.local/libexec/mcloving/current          active release (symlink)
   ~/.local/libexec/mcloving/previous         rollback release (symlink)
   ~/.local/libexec/mcloving/helpers/         operational scripts
   ~/.config/systemd/user/mcloving-*.service  service units
   ~/.config/containers/systemd/mcloving-*    quadlet units
   ~/.config/mcloving/*.env                   environment contracts
   ```

3. Fill in the four contracts under `~/.config/mcloving/` (the guard blocks
   startup until every placeholder is gone).

4. Provision mTLS material under `~/.config/mcloving/pki/` and enroll the
   agent certificate in `~/.config/mcloving/agent-identity-bindings.txt`
   (`<sha256-of-DER-leaf> <agent-id> <trust-pool> <organization-uuid>`).
   `deploy/test-deployment.sh` shows a complete openssl recipe.

5. Start everything:

   ```sh
   systemctl --user enable --now mcloving-postgres mcloving-db-init \
     mcloving-controller mcloving-agent
   ```

   First boot order matters and is enforced by the units: db-init applies
   migrations with the migration role, gives the migration-created
   `mcloving_tenant` role a constrained LOGIN (never SUPERUSER, CREATEDB,
   CREATEROLE, REPLICATION, or BYPASSRLS), and provisions the configured
   organization/project. The bootstrap is idempotent; if the organization
   exists but the project does not, it refuses rather than improvising.

## Health verification

```sh
~/.local/libexec/mcloving/helpers/mcloving-health controller ~/.config/mcloving/controller.env
~/.local/libexec/mcloving/helpers/mcloving-health agent ~/.config/mcloving/agent.env
```

- Controller: the public API must answer `GET /openapi.json` on
  `MCLOVING_LISTEN` (bounded retry; also the unit's startup gate).
- Agent (running): journal opens, integrity passes (`journal-check` is safe
  concurrently).
- Agent (stopped): `mcloving-agent probe` performs the strongest check — a
  full authenticated session plus reconciliation replay. It takes the
  journal instance lock, so it cannot run while the service is active; the
  unit runs it automatically on every start.

## Upgrade

```sh
deploy/bin/mcloving-upgrade --release-dir DIR (--manifest FILE | --checksums FILE)
```

Verifies the new binaries **before** stopping anything, then: stop agent →
stop controller → stage release → flip `previous`/`current` → start
controller → controller health gate → start agent → agent health gate.
PostgreSQL keeps running. On any failed gate the script exits non-zero and
prints the rollback command; it does not roll back on its own — reverting
is an explicit operator decision.

## Rollback

```sh
deploy/bin/mcloving-rollback
```

Swaps `current` back to `previous` (those binaries were digest-verified at
install time and are still on disk), restarts in the same order as an
upgrade, and requires the same health gates. Refuses to run if no previous
release is recorded or any previous binary is missing.

## Digest re-read

```sh
~/.local/libexec/mcloving/helpers/mcloving-deployed-digests [--home DIR]
```

Emits one canonical JSON document (`mcloving.deployed-digests/v1`) with the
sha256 and size of every staged release binary, every helper script, every
installed unit/quadlet file, and every file under `~/.config/mcloving`
(environment contracts, identity bindings, PKI — committed to by hash, not
revealed), plus the `current`/`previous` symlink targets. Output is
deterministic — sorted keys, sorted home-relative paths, no timestamps —
so two invocations over an unchanged deployment are byte-identical and any
byte of drift is visible. This is the document a future CUTOVER-001 freeze
re-reads; producing it grants no cutover authority.

**The home's whole ancestor chain is judged, up to `/`.** Every directory on
the way must be free of group and other WRITE bits and owned by root or the
service account. A directory the lane only walks *through* may be
world-writable when it is sticky — `/tmp` and `/var/tmp` are — but only while
every entry the walk enters inside it already exists and is owned by root or
the account, so a managed root that does not exist yet is refused until it is
created. **A shared-group deploy root is not supported**: a `root:apps 2775`
parent is refused, because any member of that group can rename the deployment
aside, and re-moding a directory with other tenants in it is not something an
installer may do on your behalf. Run the lane AS the service account — the
expected uid is the invoking one, so `sudo mcloving-install` refuses a tree it
does not own; `sudo -u <account>` is the documented form.

The `ancestors` section reaches `/` (`DEPLOY-004`), so it now contains
directories the deployment shares with the rest of the host. A directory the
lane merely TRAVERSES is recorded by mode, uid and gid alone: no entry-listing
hash, and its size, mtime and ctime take no part in either the record or the
stability retry. That is what keeps the document byte-identical while unrelated
processes churn `/tmp` — without it, a shared ancestor's mtime moving between the
open-time `fstat` and the pathname re-check exhausts all three attempts and
degrades the record to `kind: unstable_entry`, which fails a freeze exactly as
loudly as drift in the deployment itself. Directories whose CONTENTS the lane
enumerates — the home, the managed roots, and external unit load paths such as
`/etc/systemd/user` — are recorded in full, entry hash included, wherever they
live. A symlink **component** of the chain carries its own record — its
`lstat` owner and its target, and nothing else — because that owner is what the
ancestor walk judges it on, and a document blind to it would report no drift
across a change the next transition refuses.

## Smoke test

```sh
deploy/test-deployment.sh
```

Runs without root and without a systemd user session: it builds the
binaries, refuses a tampered install (negative test), installs into a
throwaway home, generates mTLS material the way
`bins/agent/tests/remote_work.rs` does, derives every service invocation
from the installed unit files (`mcloving-unit-command`; the only overrides
are the published port, container name, and volume name, each recorded by
the deriving tool), brings up postgres → db-init → controller → agent,
submits one pipeline through `mcloving-cli`, requires terminal
`succeeded` executed by the remote agent, checks the digest re-read for
byte-determinism, exercises upgrade/rollback symlink discipline, and tears
everything down.

The teardown covers the interrupted run as well as the finished one. The
controller and the agent are killed and reaped by the exit trap, and
`SIGINT`, `SIGTERM`, and `SIGHUP` are converted into an exit so that trap
is reached -- Ctrl-C leaves nothing behind. `SIGKILL` is the one exception,
because it cannot be trapped: `kill -9` of the suite strands the controller
and the agent, still running against a throwaway home the run may already
have deleted, and leaves its postgres container and volume behind too. The
services are orphans (parent PID 1) named by their install path, so list
them and clear them by PID rather than by pattern:

```sh
ps -eo pid,ppid,args |
  awk '/mcloving-smoke.*mcloving-(controller|agent)/ && !/awk/ {print}'
podman ps -a  --format '{{.Names}}' | grep mcloving-smoke
podman volume ls --format '{{.Name}}' | grep mcloving-smoke
```

## Limitations

Named honestly; none of these are hidden behind defaults:

- **Single host, no HA.** One controller, one agent, one PostgreSQL
  container, loopback networking in the shipped contracts. No failover, no
  replication, no load balancing.
- **No Kubernetes.** `deploy/kubernetes/` remains a stub by design;
  Kubernetes is an optional future target, not a dependency.
- **Not a cutover-certified path.** Nothing here satisfies CUTOVER-001's
  gates. This lane only makes the deployed-digest re-read possible.
- **Release signature not verified at install.** The installer checks
  sha256 digests against the manifest or a checksums file; the
  cryptographic chain (signature, transparency, audit anchor) must be
  verified separately with `mcloving-release-provenance verify-chain`.
- **Database bootstrap trusts the container boundary.** `mcloving-db-init`
  runs `psql` via `podman exec` as the PostgreSQL superuser; host-level
  PostgreSQL hardening (pg_hba beyond the image defaults, TLS to the
  database) is not configured by this lane. The database listens on
  loopback only.
- **Workload processes are not isolated from deployment credentials.**
  This is the sharpest limitation in this document. A submitted process step
  is spawned by the agent as the *same* service user, with no user
  transition and no filesystem sandbox, so it can read every 0600 file under
  `~/.config/mcloving` — controller, API, and database credentials, and the
  agent's mTLS private key — and can write the user-owned current release and
  helpers. `UMask=` and `StateDirectoryMode=` do not help: they are
  discretionary controls against *other* users, and the workload is this
  user. Nothing in the deployment layer can close this, because a rootless
  user-level lane has no privilege to transition away from; it requires
  per-workload containment in the agent executor. **Until that exists, treat
  the right to submit a pipeline as equivalent to the right to read this
  host's deployment credentials**, and do not run untrusted submissions on a
  host whose credentials you are not willing to disclose. Tracked as
  `SEC-005` on the execution board.
- **Release integrity is bound to install-time identity, not tamper-proof.**
  `verify_staged_release` recomputes the release identity and requires it to
  match the directory name assigned at installation, which catches
  corruption, partial writes, and in-place substitution. It is not a defence
  against a compromised service user, who owns those files and can rewrite
  them; that boundary is the isolation limitation above.
- **Secrets live in 0600 environment files.** No secret manager
  integration; contract files and PKI are protected by file permissions and
  committed to (by hash) in the digest re-read.
- **Single organization/project bootstrap.** Additional projects are
  operator actions via `mcloving-identity-admin`, not this lane.
- **systemd sandboxing directives are NOT available to this lane, and fail
  OPEN if added.** Measured on systemd 255 under `systemctl --user`: thirteen
  directives are enforced, **thirteen are accepted and silently ignored while
  the unit still starts and reports success**, and three fail closed. The silent
  thirteen fall into FOUR classes with DIFFERENT causes and different
  remediations -- do not treat them as one:

  *Class 1, nine mount-namespace directives:* `ProtectSystem=`, `ProtectHome=`,
  `ReadOnlyPaths=`, `InaccessiblePaths=`, `BindReadOnlyPaths=`, `PrivateTmp=`,
  `ProtectKernelTunables=`, `ProtectControlGroups=`, and `ProtectProc=`.

  *Class 2, one network-namespace directive:* `PrivateNetwork=`. It is NOT a
  mount-namespace case and must not be remediated as one: `systemd.exec(5)`
  defines it as creating a new network namespace, and the probe recorded a
  different journal message -- *"PrivateNetwork=yes is configured, but the
  kernel does not support or we lack privileges for network namespace,
  proceeding without"* -- against the mount case's *"Failed to set up
  namespace"*. A mount-namespace fix would leave this one still failing open.

  *Class 3, one BPF directive:* `IPAddressDeny=`, which this build cannot
  enforce: note `-BPF_FRAMEWORK` in `systemctl --version`.

  Every one of the nine in class 1 needs a mount namespace: systemd's executor forks
  `(sd-userns)`, Ubuntu's AppArmor `unprivileged_userns` profile denies it
  `CAP_SYS_ADMIN`, `unshare(CLONE_NEWNS)` returns `EPERM`, and systemd logs
  *"Failed to set up namespace, assuming containerized execution and ignoring"*
  **at debug level only** before starting the unit anyway. Observed:
  `ProtectHome=tmpfs` left a home fully readable including
  `.ssh/authorized_keys`, and a `ReadOnlyPaths=` target was overwritten.
  **`systemd-analyze --user security` is not evidence** — it reported
  `✓ ProtectSystem=` and `✓ PrivateTmp=` for that same run, because it scores
  declared configuration rather than achieved state, exactly as
  `systemd-analyze --user unit-paths` recomputes from the caller's environment
  instead of reporting the manager's own list. The units shipped here declare
  only directives that work (`UnsetEnvironment=`, `Environment=PATH=`,
  `StateDirectoryMode=`, `UMask=`, `NoNewPrivileges=`). **Do not add a
  filesystem hardening directive to this lane without a runtime proof that it
  is in effect**; the model is `require_shadow_apparmor_enforcement()` in
  `crates/external-connector/src/standalone.rs`, which reads
  `/proc/self/attr/current` and refuses to run unconfined.

  *Class 4, two cgroup directives:* `IOReadBandwidthMax=` and `AllowedCPUs=`.
  (`IOWriteBandwidthMax=` shares the missing `io` controller and will behave the
  same way, but it was NOT probed, so it is deliberately outside the measured
  denominator of thirteen rather than assumed into it.) These fail for an unrelated reason -- the user manager is
  delegated only the `cpu`, `memory` and `pids` controllers, so `io` and
  `cpuset` are simply absent. **A user-namespace fix would not make these
  work**, which is why they are listed apart: the remediation is a root-side
  change to controller delegation, not an AppArmor or sysctl change. The
  delegated three do work, so `MemoryMax=`, `TasksMax=` and `CPUQuota=` are
  real bounds here.
- **Agent probe is start-time only while the service runs.** Runtime agent
  health is journal-level; the full session probe requires a service stop.
