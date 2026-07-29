# Agent runtime contract

Status: implemented Wave 1-B baseline

## Authority and transport

- The agent initiates HTTPS gRPC connections to the controller.
- The outbound endpoint requires an explicit controller CA, DNS identity,
  agent certificate, and agent private key.
- Enrollment bootstrap tokens are retained only as SHA-256 digests and are
  consumed once.
- Protocol major versions must match. Minor ranges must overlap, and only the
  highest common minor plus intersected features are admitted.
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
whose non-comment rows contain the client leaf-certificate SHA-256, exact agent
ID, and exact trust pool. Every session, reconciliation, and cancellation
completion verifies the claims against the authenticated peer certificate.
Possession of another certificate under the same CA cannot select a different
agent identity or trust class. Session epochs are advanced atomically in
PostgreSQL so a second controller replica cannot admit stale authority.

## Acceptance and reconciliation

The local SQLite journal uses WAL, `synchronous=FULL`, foreign keys, strict
tables, and a bounded busy timeout. An acceptance acknowledgement is created
only after the immediate transaction commits.

Idempotent replay must match organization, attempt, fence, session, payload
digest, and workspace exactly. Any mismatch fails closed. Workload payloads and
credentials are not stored in the journal.

On restart, reconciliation reports every non-terminal attempt plus its
platform process identity and checksummed log/result spool metadata. Terminal
attempts remain durable history but are excluded from active reconciliation.
The controller compares each report with current PostgreSQL lease, fence,
restore epoch, owner, and cancellation state. Rejected attempts are returned
as cancellation directives. Before terminalizing a cancelled record, a
reconnecting Unix agent terminates the recorded process group; recovered
Windows Jobs that were successfully assigned have already been killed by the previous service process's
kill-on-close handle. The agent then sends a fenced cancellation-completion
RPC. PostgreSQL atomically terminalizes the attempt, node, build, event, and
outbox before the local SQLite record becomes terminal. A lost response leaves
the local record reconcilable and the controller completion is idempotent.

## Portable execution boundary

- Each attempt receives one new normalized workspace beneath a configured
  canonical root.
- Existing destinations, absolute paths, traversal, non-directory parents, and
  symlink or reparse-point components are rejected.
- Standard output and error are written directly to files, fsynced, and hashed
  before the outcome is returned.
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
- A child is created suspended, durably recorded, assigned to an anonymous
  kill-on-close Job Object, and only then resumed. This removes the
  spawn-before-containment race.
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

The current executor creates the workload suspended and assigns it to a
kill-on-close Job before resuming it. This prevents untrusted workload code
from running before containment, but a hard service crash between
`CreateProcess` and `AssignProcessToJobObject` can leave an inert suspended
child outside the Job. `WIN-004` replaces that two-step sequence with atomic
Job membership and is required before `WIN-002` closes.

The outbound production service polls and executes tenant-bound fenced work
over mutual TLS. Acceptance is journaled before acknowledgement, log and result
spools are checksummed, and finalization replay is exact and idempotent after a
post-controller-commit crash. On Linux, journal schema v2 binds the process
group leader to the machine boot ID and `/proc` start ticks; restart
reconciliation revalidates that non-reusable identity before both TERM and
KILL, and a missing, mismatched, or legacy identity has an explicit
fail-closed outcome. Windows production parity still depends on `WIN-004`
atomic Job membership and the hosted persistent-machine gates.
