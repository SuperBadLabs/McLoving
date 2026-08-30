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
PostgreSQL so a second controller replica cannot admit stale authority. Every
production claim and subsequent work mutation locks that exact session epoch
through the same PostgreSQL transaction as the fenced state change, so an
already-authorized old RPC cannot mutate work after the epoch advances.
Every executable node also persists one non-empty required trust pool.
Scheduling uses the trust pool from the authenticated certificate binding,
not an agent-reported capability, and claims only an exact pool match.

The node trust-pool schema migration has no global default and never infers a
historical node pool from the current agent session. Agent sessions retain only
the latest pool for an agent ID, so that inference could silently transfer old
work authority after re-enrollment. Before upgrading any database that contains
nodes, create and populate the exact per-node mapping table below for every
existing node. Migration fails and rolls back while any node remains unmapped,
and consumes the table only after every node has an explicit trust pool:

```sql
CREATE TABLE node_trust_pool_migration_map (
    organization_id uuid NOT NULL,
    node_id uuid NOT NULL,
    required_trust_pool text NOT NULL
        CHECK (
            required_trust_pool <> ''
            AND btrim(required_trust_pool) = required_trust_pool
        ),
    PRIMARY KEY (organization_id, node_id),
    FOREIGN KEY (node_id, organization_id)
        REFERENCES nodes(id, organization_id)
);

INSERT INTO node_trust_pool_migration_map
    (organization_id, node_id, required_trust_pool)
VALUES
    ('00000000-0000-0000-0000-000000000123',
     '00000000-0000-0000-0000-000000000456',
     'trusted-build');
```

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
When `accept-carries-lease-state-v1` is negotiated, the accept receipt itself
carries the cancellation state read under the accepting transaction's row
lock and the serialized initial lease RPC is skipped entirely: the claim-time
lease keeps its window minus the offer-to-accept latency, and the periodic
renewal task re-arms it on its ordinary cadence, which the
renewal-inside-the-lease-window invariant above already guarantees reaches
the server in time. A peer without the feature keeps the explicit initial
renewal, because the receipt field is default-false noise from such a
controller.
If renewal, session, or fence authority is lost, in-flight log and terminal
publication are interrupted rather than being allowed to complete under stale
authority.

## Identity-collision diagnostics

`agent_sessions` is keyed by agent ID alone, so two executors misconfigured
with one identity fight a session-epoch war: each successful `OpenSession`
fences the other, and the loser's next fenced RPC is rejected with
`stale agent session epoch`. The rejection itself is never weakened; both
sides name the suspected cause instead:

- The controller tracks committed session-epoch advances per agent identity
  in a sliding window (three or more advances within sixty seconds). While
  churn is that high, every stale-epoch rejection — enrollment and fenced
  RPCs alike — carries and logs
  `agent identity collision suspected for <agent_id>: session epoch advanced
  N times in 60 seconds; a second executor may be sharing this agent
  identity`.
- The agent counts consecutive sessions that ended with a stale-epoch
  rejection. From the second one onward the retry log adds
  `agent identity collision suspected: N consecutive stale session epoch
  rejections for agent <agent_id>; a second executor may be sharing this
  agent identity (verify MCLOVING_AGENT_ID and its certificate binding are
  unique)`.

A single healthy agent never triggers either diagnostic: a stale-epoch
`OpenSession` rejection carries the controller's stored epoch in the
`mcloving-current-session-epoch` response metadata, and the agent reserves
past that floor in one durable step and re-offers once, silently. A journal
that lags the controller (for example after a documented journal
replacement) therefore enrolls without emitting the stale-epoch retry line;
only a competitor that keeps advancing the epoch can produce repeated
rejections.

## Recovered-attempt discharge

A journal attempt parked in `reconciliation_required` fail-closed stops the
agent from polling: every reconciliation reports it, and while it is
unresolved the session ends with
`agent has an unresolved recovered attempt and will not poll for more work`.
The agent never self-discharges that record on suspicion (AGENT-005/006
discipline). Discharge requires an explicit fenced controller confirmation,
delivered through the existing reconciliation machinery:

1. Each reconciliation reports the parked attempt with its
   `reconciliation_required` phase, and the directive returns it as retained
   or cancelled; either way the agent sends a fenced
   `CompleteCancellation` with the `reconciliation_required` outcome.
2. The controller, under the exact current agent session, answers with the
   `CANCELLATION_DISPOSITION_DISCHARGE_RECOVERED` disposition only when that
   fence is disowned in durable truth: the attempt was requeued under a newer
   fence, is terminal, was superseded by an explicit operator retry, is
   unknown to this controller, or belongs to a fenced-out restore epoch.
   While the controller-side attempt is itself still parked in
   `reconciliation_required` with no successor, the report stays parked. A
   stale session always receives `RETIRE_STALE` and never a discharge.
3. On discharge the agent transitions the journal attempt
   `reconciliation_required -> aborted` (an ordinary validated journal
   transition — no schema change), which preserves the attempt row as
   terminal history together with its log/result spool descriptors; the
   existing terminal spool reclaim then removes the spool files and retires
   the descriptors. The agent resumes polling in the same session.

Both sides record the decision: the controller appends one idempotent
`attempt.recovered_discharge_authorized` build event (when the attempt maps
to a build) plus an `agent-control:` log line, and the agent logs
`discharged recovered attempt <org>/<attempt> fence <fence>: the controller
confirmed its fenced authority is disowned; ...`.

### Operator runbook: a build parked in `reconciliation_required`

Symptoms: the build reports `reconciliation_required`, the owning agent
loops with `agent has an unresolved recovered attempt and will not poll for
more work`, and CLI cancellation is refused with HTTP 409
`build_reconciliation_required` naming this exact state (cancellation cannot
discharge a parked reconciliation).

1. If the collision diagnostic above is present, first fix the identity
   misconfiguration: exactly one executor may use each `MCLOVING_AGENT_ID`
   and certificate binding. The war must stop before reconciliation can
   settle.
2. Confirm any uncertain external effects for the parked attempt
   (`confirm_uncertain_effect`), then resolve it controller-side with an
   explicit operator decision: schedule a retry of the attempt (the public
   retry API accepts `failed` and `reconciliation_required` attempts) or
   finalize the reconciled attempt to a terminal outcome
   (`finalize_reconciled_attempt`).
3. No agent-side action is required. On its next reconciliation cycle the
   owning agent's parked report receives the discharge disposition, retires
   the journal record with its evidence, and resumes polling. Journal
   replacement is no longer part of this procedure.

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
- When `inline-terminal-logs-v1` is negotiated, a stream that fits one chunk
  is verified identically and then carried in the terminal publication's
  `inline_log_chunks` instead of its own `PublishLog` round trip; the
  controller appends each inline chunk through the same bounded, redacting,
  idempotent store path before finalizing. Larger streams, recovery replay,
  and peers without the feature keep the streaming pass — a controller that
  never negotiated it would silently ignore the field, so the agent must not
  inline for such a peer.
- Once the controller acknowledges terminal truth and the local terminal
  transition commits, the agent immediately deletes the controller-owned log
  and result spools and atomically retires their journal descriptors. A crash
  between file deletion and metadata retirement is idempotently completed on
  startup or at periodic reconciliation; terminal attempt history remains
  durable.
- Terminal result evidence is written beneath the agent-owned
  `.agent-results` root, outside the workload workspace namespace, under a
  cryptographically random path created only after containment has ended. A
  component-wise no-follow directory walk and canonical-root check reject
  symlinks, reparse escapes, and non-directory parents before creation. A
  workload cannot predict, pre-create, or replace the authoritative result
  path.
- Workloads never inherit the agent service environment wholesale. Unix starts
  from a fixed `PATH`/locale baseline. Windows copies a fixed allowlist of
  standard operating-system and user-profile variables required by native
  shells from a fixed allowlist. Missing standard values are seeded from the
  service token and then the same allowlist from the actual agent process takes
  precedence, preserving the environment SCM or the operator deliberately gave
  that service. The standard PATH is normalized to absolute entries and
  prepended with canonical `System32`, `Wbem`, and Windows PowerShell
  directories so LocalSystem does not depend on an interactive profile.
  `TEMP`/`TMP` are redirected into the attempt workspace, and the exact
  per-drive current-directory entry required by a custom Unicode
  `CreateProcessW` environment is synthesized. Explicit overrides are accepted
  except for reserved `TEMP`/`TMP`, which remain attempt-scoped; controller
  URLs, journal paths, credentials, CI controls, and arbitrary process-local
  variables remain excluded.
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

## Persistent-host proof closure

The hosted Windows CI campaign and persistent NucBoxG3 `WIN-001` through
`WIN-003` closures prove native compilation, service lifecycle, monotonic
session epochs, atomic Job Object containment, cancellation, hard
service-process termination, journal reconciliation, stale-authority denial,
controller-loss retry, and physical-machine reboot using an exact signed
qualification package. Controller loss expires the old lease and permits only
a higher-fence retry. During the observed machine reboot, SCM shutdown let the
agent publish an ordinary failed terminal before connectivity disappeared, so
the controller neither expired nor retried that already-terminal attempt. A
separate post-reboot build proves restored service health. These outcomes are
intentionally distinct and are bound in the versioned parity receipt.

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
reconciliation-required until containment is verified. Production release
still depends on `REL-001` signing and the later versioned war campaign; those
are provenance and release gates, not missing Windows runtime evidence.
