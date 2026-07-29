# McLoving threat model

Status: Approved Wave 0 baseline
Reviewed: 2026-07-28
Owner: McLoving security architecture

This threat model covers the approved architecture before runtime
implementation. Each implementation ticket must update the affected threats,
tests, and residual risk.

## Security objectives

- Preserve tenant isolation and authorization.
- Prevent stale or forged execution authority.
- Keep protected credentials away from untrusted workloads.
- Make external side effects attributable and reconcilable.
- Preserve provenance from source through artifact and deployment.
- Contain compromised agents and connectors to their authorized scope.
- Fail closed when compatibility or execution behavior is unknown.

## Actors

| Actor | Trust and capability |
|---|---|
| Installation operator | Controls deployment, database, storage, and root policy |
| Organization administrator | Manages organization projects, roles, and policies |
| Project maintainer | Changes project pipelines and approved integrations |
| Developer | Triggers and inspects authorized builds |
| External contributor | Supplies untrusted fork or pull-request content |
| Controller replica | Holds scoped database and object-storage authority |
| Execution agent | Runs leases belonging to one configured trust pool |
| Compatibility worker | Parses untrusted Jenkins inputs without runtime authority |
| Connector/provisioner | Performs explicitly scoped external operations |
| External identity/SCM/secret service | Supplies authenticated identity or data |
| Network attacker | Can observe, delay, replay, or interrupt reachable traffic |
| Compromised dependency | Attempts supply-chain or runtime privilege escalation |

## Protected assets

- PostgreSQL execution state and tenant ownership.
- Pipeline source, canonical IR, and provenance.
- Credentials, signing keys, and secret grants.
- Agent, connector, and controller identities.
- Logs, artifacts, caches, test evidence, and audit records.
- Environment approval and deployment authority.
- Release packages, dependency locks, and toolchain digests.
- Availability of scheduling, reconciliation, and cleanup.

## Trust boundaries

1. Browser/CLI to public Rust API.
2. SCM webhook to controlled ingress.
3. Compatibility worker to Rust IR validator.
4. Controller to PostgreSQL and object storage.
5. Controller to outbound-connected agents.
6. Agent control process to untrusted workload process.
7. Controller to connectors, secret brokers, and provisioners.
8. Trusted, untrusted, release, deployment, and signing agent pools.
9. Build source and dependencies to produced artifacts.
10. Backup/restore environment to live recovery epoch.

Process groups, cgroups, containers, and Windows Job Objects are lifecycle and
resource controls. They are not treated as hostile multi-tenant isolation.

## Assumptions

- Production PostgreSQL and object storage are authenticated and privately
  reachable.
- Host and cloud administrators remain outside application-level containment.
- Untrusted multi-tenant execution uses VM or equivalent isolation.
- System clocks have bounded skew and certificate validation remains enabled.
- KMS and external secret managers enforce their own authenticated policies.
- Operators preserve at least one independently protected recovery credential.

## Threat register

| ID | Scenario | Primary mitigations | Required verification | Owner | Residual risk |
|---|---|---|---|---|---|
| TM-001 | Cross-tenant object ID is substituted in an API call | Tenant IDs in keys, centralized authz, PostgreSQL RLS | Generated authz matrix and negative integration tests | SEC | Privileged DB operator |
| TM-002 | Fork pipeline requests protected credentials | Immutable trust class, grant policy, restricted pool | Fork/fork-to-trusted transition tests | SEC/AGENT | Malicious trusted maintainer |
| TM-003 | Stale lease or certificate holder publishes as another agent after fencing | Epoch and lease token checked transactionally; agent session epochs advanced in PostgreSQL across replicas; exact leaf-certificate digest binds agent ID and trust pool on every agent RPC | TLC model, DB race tests, durable agent-session epoch tests, binding parser tests, reconnect E2E | ARCH/CTRL | CA or binding-file compromise |
| TM-004 | Lost connection triggers duplicate deployment | Reconciliation and effect idempotency class | Partition and ambiguous-effect war test | CTRL/EXT | External API lacking reconciliation |
| TM-005 | Controller restart loses accepted work | PostgreSQL transaction plus outbox | Kill-after-each-transition fault injection | CTRL | Correlated DB failure |
| TM-006 | Agent restart loses process identity or result | Local SQLite WAL, FULL synchronous commits, durable session epochs, one-transaction terminal phase plus complete spool descriptors, no-follow canonical result hierarchy, Linux boot/process-birth identity, and fail-closed legacy-row migration | Forced response-loss and post-terminal-commit crash/replay; atomic finalization rollback; result-parent symlink/reparse rejection; matching, missing, mismatched, and legacy process-identity cancellation tests; persistent-host machine reboot follows | AGENT | Host disk corruption; non-Linux Unix recovery requires an equivalent birth identity |
| TM-007 | Workload escapes process-tree cancellation | Linux process groups with explicit missing-leader reconciliation; atomic `PROC_THREAD_ATTRIBUTE_JOB_LIST` assignment to kill-on-close Windows Job Objects; VM boundary for hostile tenants | Destructive Linux/Windows timeout and cancellation; live missing-leader descendant; forced Windows crash at every process-creation boundary and after descendant spawn | AGENT/WIN | Kernel, Job Object, container-runtime flaw |
| TM-008 | Parser input consumes unbounded CPU or memory | Strict YAML subset, compiler sandbox, resource limits | Continuous fuzzing and timeout corpus | IR/COMPAT | Novel parser vulnerability |
| TM-009 | Unknown step is reported successful | Typed IR and fail-closed mapping | Negative corpus and unknown-effect property tests | IR/COMPAT | Incorrect approved mapping |
| TM-010 | Connector gains scheduler or DB authority | Out-of-process scoped identity and protocol | Permission-negative integration suite | EXT/SEC | Host administrator |
| TM-011 | Agent impersonates a more privileged pool or a stale session mutates current work | One-time enrollment, mTLS identity, transaction-bound session/certificate epochs, measured capabilities, and exact scheduling match between the node's durable required pool and the certificate-bound agent pool | Token replay, stale-session mutation, rotation, revocation, and mismatched-pool claim tests | AGENT/SEC | CA compromise |
| TM-012 | Cache poisoning crosses trust boundary | Trust-classed immutable cache generations | Untrusted-write/trusted-read negative tests | OPS/SEC | Compromised trusted producer |
| TM-013 | Secret appears in workload environment, logs, traces, SQLite, or artifacts | Cleared/allowlisted child environment, explicit execution environment, attempt-scoped grants, no persistence, redaction defense | Parent-environment negative tests and marker-secret scan across every sink | SEC/OPS | Transformed secret not recognized |
| TM-014 | Artifact is substituted after successful build | Staged digest verification and immutable metadata | Tamper, partial-upload, and restore tests | OPS | Storage administrator |
| TM-015 | Webhook is forged or replayed | Provider signature, body limits, immutable event ID | Invalid signature/replay/rate tests | EXT/SEC | Provider credential theft |
| TM-016 | Dependency or action is replaced through mutable reference | Lockfiles, signed releases, digest-pinned images/actions | Provenance and substitution gates | FOUND/REL | Upstream signing compromise |
| TM-017 | Database restore resurrects old authority | New recovery epoch and full agent reconciliation | Catastrophic restore drill | OPS/ARCH | Lost agent journals |
| TM-018 | Log/artifact volume exhausts controller or agent disk or memory | 64 MiB attempt-log and 64 KiB result quotas, bounded two-pass streaming, explicit backpressure | Oversize rejection, streaming digest-mismatch, disk-full, and quota war tests | OPS/AGENT | Operator misconfiguration |
| TM-019 | Approval is reused after pipeline or artifact changes | Approval binds build, IR, artifact, environment, action | Stale-approval negative tests | SEC/UX | Approver account compromise |
| TM-020 | Compatibility worker executes untrusted Groovy with authority | No secrets/network/DB/agent access; isolated limits | Sandbox escape and authority-negative tests | COMPAT/SEC | JVM/container escape |
| TM-021 | Malformed protocol message crashes controller or agent | Protobuf contract and fail-closed major/minor negotiation; message bounds at transport integration | Version/range tests now; protocol fuzzing and oversize E2E next | AGENT/CTRL | Runtime-library vulnerability |
| TM-022 | Audit history is silently altered | Append-only API, hash segments, external export | Mutation denial and export verification | SEC/OPS | DB and external sink collusion |
| TM-023 | Unauthorized tool version enters validation or release | Versioned downloads, SHA-256 verification, OCI digests | Empty-cache validation and manifest check | FOUND/REL | Compromised upstream plus digest update |
| TM-024 | UI or CLI hides uncertain or degraded state | Server-authoritative typed states and explicit gaps | User-journey and API contract tests | UX/CTRL | Client compromise |

## Data-flow rules

- Compatibility workers receive source and metadata, never execution secrets.
- Pipeline IR contains secret references, never plaintext.
- Agents obtain grants only after accepting a current lease.
- Connector results cannot directly mutate scheduler tables.
- Object uploads remain invisible until digest metadata commits.
- Audit and telemetry cannot publish build success.
- Untrusted work cannot raise its trust class during a build.

## Security verification ownership

| Area | First implementation ticket |
|---|---|
| Authorization and RLS | SEC-002 |
| Strict YAML and expression resource bounds | IR-001 |
| Lease, fencing, and attempt finalization | ARCH-001 / CTRL-001 |
| Agent enrollment and mTLS | AGENT-001 |
| Agent journal and process containment | AGENT-002 / AGENT-003 |
| Secret grants and protected environments | SEC-003 |
| Connector identity and external ambiguity | EXT-001 |
| Artifact integrity, retention, and restore | OPS-001 / OPS-002 |
| Windows service, journal, and Job Object containment | WIN-001 / WIN-002 |
| Supply-chain release evidence | REL-001 |

## Residual-risk policy

A ticket cannot mark a threat “eliminated” merely because a design mitigation
exists. Closure requires executable evidence. Accepted residual risk must name
the affected scope, owner, review date, and user-visible limitation.

Threat-model review is required for changes to authentication, authorization,
protocols, persistence, execution, secrets, connectors, agent pools, supply
chain, or deployment boundaries.
