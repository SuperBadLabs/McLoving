# Agent runtime contract

Status: implemented through Wave 2-C

## Authority and transport

- The agent initiates HTTPS gRPC connections to the controller.
- The outbound endpoint requires an explicit controller CA, DNS identity,
  agent certificate, and agent private key.
- Enrollment bootstrap tokens are retained only as SHA-256 digests and are
  consumed once.
- Protocol major versions must match. Minor ranges must overlap, and only the
  highest common minor plus intersected features are admitted.
- Production work polling requires the negotiated `work-delivery-v1` feature;
  an older peer fails compatibility negotiation before either side relies on
  the work-delivery RPC set.
- Session and certificate epochs increase monotonically. Only the exact current
  session may act; reconnecting with a newer epoch fences the previous session.

The generated controller service is a contract surface. The agent crate does
not expose a listener.

The controller serves that contract when `MCLOVING_AGENT_LISTEN` is set. It
requires `MCLOVING_AGENT_SERVER_CERT_PATH`,
`MCLOVING_AGENT_SERVER_KEY_PATH`, and `MCLOVING_AGENT_CLIENT_CA_PATH`; the
listener refuses plaintext and requires a client certificate rooted in the
configured agent CA. `MCLOVING_AGENT_IDENTITY_BINDINGS_PATH` is also required
when that listener is enabled. It names a root-owned, whitespace-delimited file
whose non-comment rows contain four whitespace-delimited fields: the client
leaf-certificate SHA-256, exact agent ID, exact trust pool, and exact
organization UUID. Every session, reconciliation, and cancellation completion
verifies the claims against the authenticated peer certificate.
Possession of another certificate under the same CA cannot select a different
agent identity or trust class. Session epochs are advanced atomically in
PostgreSQL so a second controller replica cannot admit stale authority.
Every executable node also persists one non-empty required trust pool.
Scheduling uses the trust pool from the authenticated certificate binding,
not an agent-reported capability, and claims only an exact pool match.

The organization UUID is a required W2-C identity-binding migration. Before
upgrading a controller from the earlier three-column format, append the
organization UUID authorized for each agent:

```text
# sha256 agent-id trust-pool organization-uuid
0123...cdef windows-1 trusted-windows 00000000-0000-0000-0000-000000000123
```

Legacy three-column rows fail startup with an explicit migration error. The
controller never infers a tenant because doing so could turn a certificate
rotation or configuration mistake into cross-tenant authority.

## Acceptance and reconciliation

The local SQLite journal uses WAL, `synchronous=FULL`, foreign keys, strict
tables, and a bounded busy timeout. An acceptance acknowledgement is created
only after the immediate transaction commits.

Idempotent replay must match organization, attempt, fence, session, payload
digest, and workspace exactly. Any mismatch fails closed. Workload payloads and
credentials are not stored in the journal.

Before any log or result publication, one immediate SQLite transaction records
the terminal phase, original work-versus-cancellation completion protocol, and
complete checksummed log/result descriptors. On restart, reconciliation reports
every non-terminal attempt plus its platform process identity and that durable
spool metadata. Terminal attempts remain durable history but are excluded from
active reconciliation.
Before the first reconciliation RPC, the agent fail-closed quiesces every
recovered accepted or running execution. It either proves the recorded
containment identity has terminated and durably records that outcome, or keeps
the attempt in `reconciliation_required`; controller unavailability can
therefore never extend recovered execution authority.
The controller compares each report with current PostgreSQL lease, fence,
restore epoch, owner, and cancellation state. Rejected attempts are returned
as cancellation directives. A retained accepted or running attempt is also
settled before the reconnected agent may poll again: the agent cannot recover
the original wait handle and therefore must prove termination or move the work
to `reconciliation_required`. Before terminalizing either kind of record, a
reconnecting Unix agent terminates the recorded process group; recovered
Windows Jobs that were successfully assigned have already been killed by the
previous service process's kill-on-close handle. The agent then sends a fenced
cancellation-completion RPC. PostgreSQL atomically terminalizes the attempt,
node, build, event, and outbox before the local SQLite record becomes terminal.
A lost response leaves the local record reconcilable and the controller
completion is idempotent.
Once finalization and its result descriptor commit atomically, they also serve
as durable proof that the executor already observed empty containment. A stale
fence may retire that exact evidence without re-probing a now-missing Unix
leader. Conversely, any post-spawn executor error that cannot prove the process
group empty is recorded as `reconciliation_required`, with its original
process identity retained; it is never converted into a processless terminal
failure.

Lease renewal continues through durable result creation, bounded log upload,
and the terminal controller acknowledgement. It stops only after the
acknowledgement is received (or authority is rejected). Recovered finalization
replay follows the same rule, rather than relying only on the controller's
initial bounded recovery lease.
Acceptance and initial lease RPCs are bounded by the configured lease window;
`StartWork` must complete inside the exact initial lease-minus-one-second
budget. Renewal configuration must leave that same one-second safety margin.
If renewal, session, or fence authority is lost, in-flight log and terminal
publication are interrupted rather than being allowed to complete under stale
authority.

## Portable execution boundary

- Each attempt receives one new normalized workspace beneath a configured
  canonical root.
- Existing destinations, absolute paths, traversal, non-directory parents, and
  symlink or reparse-point components are rejected.
- Standard output and error are written directly to files, fsynced, and hashed
  before the outcome is returned. Replay verifies each descriptor in a bounded
  first pass and publishes one-MiB chunks in a second streaming pass. A single
  attempt may retain at most 64 MiB of logs across at most 66 chunks and a
  64 KiB result. Both the agent and controller independently reject excess
  chunk cardinality.
- Once the controller acknowledges terminal truth and the local terminal
  transition commits, the agent immediately deletes the controller-owned log
  and result spools and atomically retires their journal descriptors. A crash
  between file deletion and metadata retirement is idempotently completed on
  startup or at periodic reconciliation; terminal attempt history remains
  durable.
- Terminal result evidence is written beneath the agent-owned
  `.agent-results` root, outside the workload workspace namespace, under a
  cryptographically random path created only after containment has ended. A
  workload cannot predict, pre-create, or replace the authoritative result
  path.
- Execution timeouts are validated before process creation and must be between
  one second and seven days. Unbounded `u64` durations never reach platform
  deadline arithmetic.
- On POSIX systems, every new directory entry is followed by a parent-directory
  fsync. Win32 exposes directory handles for metadata operations but does not
  provide a least-privilege equivalent of POSIX directory fsync:
  `FlushFileBuffers` requires `GENERIC_WRITE`, which ordinary directory handles
  do not receive. Windows therefore flushes each payload file and the
  authoritative SQLite transaction, validates every directory boundary, and
  leaves directory-entry power-loss survival to the persistent-host reboot
  gate. This limitation is explicit rather than silently promoted to parity.

### Linux

- The direct child starts a new process group.
- Timeout and cancellation signal the whole group with `SIGTERM`, wait for the
  configured grace period, then use `SIGKILL`.

### Windows

- The agent runs as a native Windows service and uses the same outbound mTLS
  session and SQLite WAL reconciliation contract as Linux.
- Direct process, `cmd.exe`, and PowerShell modes are explicit rather than
  inferred from input.
- `cmd.exe /S /C` receives one outer-quoted command string so script paths and
  arguments containing spaces remain intact. Shell metacharacters with
  expansion semantics are rejected rather than interpolated.
- A child is created suspended with an anonymous kill-on-close Job Object in
  its `PROC_THREAD_ATTRIBUTE_JOB_LIST`, so Job membership is atomic with
  `CreateProcessW`. Only the intended standard handles are inherited. The
  process identity is durably recorded before the child is resumed.
- Timeout, cancellation, and service loss terminate the entire Job Object.
- The Win32 `unsafe` boundary is isolated in the `mcloving-windows-job` crate;
  the rest of the runtime remains safe Rust.

Process groups and Job Objects are lifecycle containment. They are not hostile
multi-tenant security boundaries. Untrusted multi-tenant workloads still
require a VM or equivalent isolation; cgroup/resource quotas and Windows ACLs
remain deployment hardening.

## Current external proof gap

The hosted Windows CI campaign proves native compilation, service
install/start/stop/uninstall, journal reopen, Job Object descendant cleanup,
hard service-process termination, and no duplicate accepted execution after
restart. A signed package on a persistent Windows host still must prove
machine-reboot reconciliation, payload-directory survival, and cross-host
controller/network interruption before full Windows parity is closed.

The executor creates the workload suspended with atomic Job membership in the
Win32 creation attribute list. Native forced-crash tests cover every
pre-resume boundary plus a live descendant and prove kill-on-close cleanup
without an uncontained-child window. Bare program names are resolved through
the effective `PATH` before the explicit application path is passed to
`CreateProcessW`; the workspace is never searched implicitly.

The outbound production service polls and executes tenant-bound fenced work
over mutual TLS. Acceptance is journaled before acknowledgement; renewal
failure cancels local execution before authority can be reused. Finalization
authority and complete spool evidence are committed atomically before bounded
streaming upload, and replay is exact and idempotent after response loss or a
post-controller-commit crash. On Linux, journal schema v2 binds the process
group leader to the machine boot ID and `/proc` start ticks; restart
reconciliation revalidates that non-reusable identity before both TERM and
KILL. A missing leader is not proof that the process group is empty and remains
reconciliation-required until containment is verified. Full Windows parity
still depends on the hosted persistent-machine gates.
