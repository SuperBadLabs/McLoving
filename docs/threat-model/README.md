# McLoving threat model

Status: Approved Wave 0 baseline
Reviewed: 2026-08-04
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
| TM-020 | Compatibility worker executes untrusted Groovy, forges compiler output, or imports mutable/secret-bearing authority | Groovy is parsed only to a CONVERSION-phase AST and never evaluated; exact-source/profile/compiler binding; no secrets/network/DB/agent/controller access; rootless read-only limits and all-false authority ledger; separate disabled state record; independent Rust canonical-EDN, strict-YAML, canonical-IR, provenance, authority, state, host-path, and secret-substitution validation | Deterministic exact-oracle compile; sandbox/mount/symlink/limit/environment authority-negative gates; malformed/noncanonical/profile/authority/state/host-path/secret adversarial worker-output tests; working-tree marker scan | COMPAT/SEC | JVM/container escape or a jointly flawed worker and independent validator |
| TM-026 | A floating or substituted Jenkins step/plugin mapping silently falls back, reads an undeclared host input, or turns a compile-only construct into execution or external-effect authority | Versioned strict-YAML catalog; exact plugin/profile/corpus/source/target bindings; detached byte and semantic lock; deny-unknown schema; explicit unsupported policy; all-false authority; connector-only production effects; unearned local-input/shared-resource/cache semantics are not admitted | Mapping-catalog golden, strict-YAML, bundle, authority, policy, profile/plugin/corpus substitution, unknown-field, and coverage-inflation tests; sealed successor corpus | COMPAT/SEC | Only one literal `sh` mapping is earned; execution equivalence, local input, shared resources, cache behavior, and production effects remain uncertified |
| TM-027 | An attacker substitutes an OIDC provider, redirect, key, subject, group claim, code, state, nonce, or replayed token to obtain or retain another principal's authority | Tenant/provider-keyed exact configuration and JWKS generations/digests; HTTPS-only production endpoints; exact redirect allowlist; authorization code with PKCE S256; one-time state, nonce, ID-token and refresh evidence; strict issuer/audience/signature/time/subject/group validation; immutable external-subject and source-provenance binding; group and lifecycle generation fencing; absolute refresh deadline; refresh-reuse family revocation | Contained generated-key OIDC end-to-end test, malformed/substituted/replayed state and token tests, real PostgreSQL cross-tenant/group/lifecycle/refresh/logout tests, OpenAPI route contract, independent security and restore receipt in `docs/evidence/IDP-001_SECURITY_REVIEW.md` | IDP/SEC | Compromised target identity provider, trusted migration operator, or browser endpoint remains authoritative within its granted scope |
| TM-028 | Service credential rotation, lifecycle administration, or legacy-human migration silently preserves stale authority or rebinds identity | Digest-exact generation idempotence; atomic old-generation revocation; audited offline migration-role admin binary; compare-and-swap lifecycle transitions; one-way trigger-guarded legacy provenance binding; tenant RLS and immediate generation fencing | Same-generation substitution and next-generation rotation tests, revocation/authentication denial, strict admin-input tests, legacy quarantine/binding/activation test, audit-chain verification, identity-specific logical restore canary | IDP/SEC | Migration-role database compromise can administer identities and requires independent operational controls |
| TM-029 | Anonymous OIDC starts or retained session/replay/group history exhaust controller or PostgreSQL capacity | Per-source 60/minute start limiter with bounded client index; per-tenant/provider bounded live attempts with oldest-attempt eviction; 30-day expired replay/session retention and 128-generation group-history bound; tenant-scoped transactional pruning | Rate-bound unit/integration checks, PostgreSQL least-privilege pruning path, saturation and retention war tests before hostile multi-tenant exposure | IDP/OPS | Source-address aggregation and distributed-replica rate-limit coordination require an upstream authenticated edge for hostile Internet exposure |
| TM-030 | A Jenkins ACL is broadened to fit a coarse target role, a mutable principal name is rebound, or stale group/policy truth retains authority | Imported-project mode disables lattice fallback; immutable canonical policy generations bind exact source realm/inventory/ACL and target identity/provenance/generations; explicit action decisions default deny; deny wins; optimistic current pointer; privileged writes, forced RLS, hash-chained audit | Non-broadening and scheduler-negative tests; positive/negative/missing and deny-conflict decisions; source substitution, live group/session staleness, service rotation/revocation, update conflict, complete revocation, monotonic rollback, deployable-runtime preflight, and authorization-specific logical restore canary; bounded receipt in `docs/evidence/AUTHZ-001_SECURITY_REVIEW.md` | AUTHZ/SEC | Trusted inventory/reviewer, target IdP, or migration-role compromise; exact production-population parity remains DIFF-002 |
| TM-031 | A Jenkins reader is declared migrated while it still reads Jenkins, uses a substituted caller/tenant/endpoint, loses pagination state, or cannot restore source authority during outage | Immutable canonical per-consumer authority generations bind sealed inventory, caller/target identity, tenant/project, API/query/cursor/rate/retention/URL contract, evidence digests and observation window; a stable binding digest cannot change across authority transitions; target authority requires zero observed Jenkins reads; exact-source rollback is a new monotonic generation; migration-only writes, forced RLS, hash-chained audit | Authenticated API-only CLI journeys; missing/cross-tenant authorization matrix; real-PostgreSQL stale and independently redigested source/target/tenant/contract substitution, concurrent writer, residual-read, rollback, audit, RLS, and privilege-negative tests; bounded receipt in `docs/evidence/CONSUMER-001_SECURITY_REVIEW.md` | CONSUMER/SEC | Trusted inventory, evidence collector/reviewer, target IdP, and migration DB operator remain authoritative; production zero-read observation occurs only at real caller cutover |
| TM-021 | Malformed protocol message crashes controller or agent | Protobuf contract and fail-closed major/minor negotiation; message bounds at transport integration | Version/range tests now; protocol fuzzing and oversize E2E next | AGENT/CTRL | Runtime-library vulnerability |
| TM-022 | Audit history is silently altered | Append-only API, hash segments, external export | Mutation denial and export verification | SEC/OPS | DB and external sink collusion |
| TM-023 | Unauthorized tool version enters validation or release | Versioned downloads, SHA-256 verification, OCI digests | Empty-cache validation and manifest check | FOUND/REL | Compromised upstream plus digest update |
| TM-024 | UI or CLI hides uncertain or degraded state | Server-authoritative typed states and explicit gaps | User-journey and API contract tests | UX/CTRL | Client compromise |
| TM-025 | Mixed-epoch, tampered, incomplete, stale, or secret-bearing Jenkins inventory is admitted as migration truth | Four typed strict-YAML families, byte-identical snapshot binding, detached SHA-256 sealing, mandatory owner-trusted external digest over both the complete binding and four-manifest filename/content-digest map at reconciliation/verification, independently sourced controller/direct-child/principal/ACL/client, per-job dependency/state-class, and per-state-class instance counts; every count/set commitment domain-separated and bound to the complete snapshot binding (controller/core/plugin/global configuration, collection time, exporter identity/version/content, and provenance) plus applicable owner identity; complete deterministic job, security-realm, principal, ACL, client, runtime-dependency, and state-record semantic commitments with distinct empty-group bindings; closed canonical runtime-dependency taxonomy whose credential/secret-parameter kinds force typed secret reference and consumer/taint evidence; mandatory runtime and state coverage for every job including retired jobs; referential and coverage reconciliation; exactly-once typed compatibility evidence for every declared library/trigger/platform/agent/toolchain requirement; workload-visible secrets forced unsupported; forward/rollback state-transform classification; create-new publication; and no execution authority | Digest tamper, strict-YAML alias, mixed-epoch, complete stale-bundle or same-binding semantic replay, cross-epoch or cross-configuration subgroup replay, stale semantic payload replay, unknown identity or dependency kind, secret-kind confidentiality downgrade, population omission and count mismatch, dependent count/set collector, same-cardinality identity, cross-domain empty-evidence replay, parent-edge, job-scope/owner/operational-state, principal lifecycle/mapping, ACL-permission/generation, client-contract, dependency-owner, state-owner, or state-instance-count substitution, retired/out-of-scope runtime or state omission, understated state instances, missing/duplicate/undeclared requirement evidence, incomplete coverage, unclassified secret/state behavior, workload-visible-secret downgrade, and secret-reference negative tests | COMPAT/SEC/OPS | Compromised trusted snapshot coordination state, Jenkins administrator/exporter, or false owner attestation |

`WIN-002` threat-model review closes TM-007 for the supported Windows agent
lifecycle: explicit mode admission cannot infer a shell, every child starts in
an atomic kill-on-close Job Object, cancellation and service crash leave no
descendant, and the workspace root ACL grants only `SYSTEM` and Administrators.
The accepted residual risk is unchanged: Job Objects and ACL ownership are not
a hostile multi-tenant isolation boundary. The deployment owner must use a VM
or equivalent boundary before admitting mutually untrusted Windows workloads.
`WIN-003` supplied the signed-package interruption and graceful-reboot evidence;
abrupt-power-loss directory-entry durability remains unclaimed.

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
| Jenkins inventory integrity and reconciliation | INV-001 / INV-002 / INV-003 / INV-004 / MIG-000 |
| Human and service authentication lifecycle | IDP-001 |
| Jenkins authorization mapping lifecycle | AUTHZ-001 |

## Residual-risk policy

A ticket cannot mark a threat “eliminated” merely because a design mitigation
exists. Closure requires executable evidence. Accepted residual risk must name
the affected scope, owner, review date, and user-visible limitation.

Threat-model review is required for changes to authentication, authorization,
protocols, persistence, execution, secrets, connectors, agent pools, supply
chain, or deployment boundaries.
