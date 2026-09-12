# McLoving threat model

Status: Approved Wave 0 baseline
Reviewed: 2026-08-14
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
| Local host user | Holds a uid on a deployment host that is neither the service account nor root, and no deployment authority |

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
11. Deployment host filesystem to the service account's deployed tree.

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
| TM-010 | An external connector gains scheduler, controller database/filesystem, agent, unrelated-secret, observer, or shadow authority; a stale/substituted request, payload, credential, runtime image, implementation, endpoint, account, resource, response, observer, or receipt executes or unfreezes the wrong effect; shared authority keys or secret material permit cross-role forgery; retry, restart, clock rollback, generation rotation, a new request ID, or exhausted evidence capacity duplicates or permanently freezes a non-idempotent effect; ambiguous completion is guessed; or the shadow reaches production, backdates replay, or fabricates downstream truth | Standalone one-action connector with a short-lived signed attestation bound to the executing inode, runtime image, complete config, and live Linux boot/mount-namespace/cgroup evidence; nonempty exact generation, endpoint/account/resource/effect/action/grant/key bindings and closed typed scalar request and public-output schemas; pairwise-distinct request, destination, outcome, observer, and runtime-attestation keys, disjoint raw/standard-Base64/URL-safe-Base64/hex credential and signing material, and pairwise-distinct shadow connector/replay/attestation keys; distinct credential, operator, runtime, and deployment identities; owner-private no-follow authority files, FULL-synchronous SQLite claim/evidence ledger with crash-durable reconciliation-capacity reservations, bounded exact-digest runtime history, in-place monotonic cutover/rollback with independently bound active source and historical target, permanent single-use physical effect scope preservation, rotation denial until every pending or ambiguous claim settles under its original signing generation, and a fixed cross-process lineage lease; durable pre-dispatch marker and timestamp with backward-clock-safe recovery; trusted-clock resampling at connector dispatch/capture and shadow replay boundaries plus idempotency-class-aware bounded retry; signed typed bounded outcomes with public values, protected secret references/taint, external IDs, control-flow/later-intent digests and complete representation scanning after every fixed-point percent-decoding generation; every unverifiable non-idempotent post-dispatch result freezes until independently signed fresh completely deployment-bound OBS-001 positive-presence evidence, while point-in-time absence remains frozen without a destination-signed causal terminal barrier; separate runtime-attested, fully connector-mapping-pinned, no-endpoint/no-credential shadow-replay process with a canonical-configuration-fenced exactly-once signed ledger and AppArmor-enforced network denial | Contained success/failure/retry/timeout/ambiguity, exact replay/restart including caller-time backdating denial, malformed/substituted/secret-bearing/stale/replayed/permission-negative response and request, closed scalar request/output-schema and nonempty-mapping denial, raw and encoded credential/signing-role collision, selectively percent-encoded raw and encoded secret leakage, causally unfenced absence denial with unchanged ambiguity, exact historical-target rollback and invalid-target denial, bounded runtime history, final-attempt pre-dispatch and timestamped post-dispatch crash including backward-clock recovery, crash-persistent reconciliation-capacity reservation, pending/ambiguous generation-rotation denial, cross-generation and cross-request scope freeze, public/secret cross-role shared-key denial, full observer substitution/freshness denial, shadow configuration/mapping/key-substitution/restart/dedup, signed live-runtime evidence tamper, fixed-lease contention, private/symlink state denial, protected feature-gated contracts, live AppArmor network-denial probe, and sealed zero-effect Mario inventory; protocol in `docs/architecture/EXTERNAL_CONNECTOR_V1.md` | EXT/SEC | Trusted Linux kernel/host and containing directories, runtime-attestation signer, connector/configuration/credential/destination authorities, independent observer and clocks; production connector mappings, credential classifications, live non-collusion, canary, cutover, rollback, and decommission remain unclaimed |
| TM-011 | Agent impersonates a more privileged pool or a stale session mutates current work | One-time enrollment, mTLS identity, transaction-bound session/certificate epochs, measured capabilities, and exact scheduling match between the node's durable required pool and the certificate-bound agent pool | Token replay, stale-session mutation, rotation, revocation, and mismatched-pool claim tests | AGENT/SEC | CA compromise |
| TM-012 | Cache poisoning crosses trust boundary | Trust-classed immutable cache generations | Untrusted-write/trusted-read negative tests | OPS/SEC | Compromised trusted producer |
| TM-013 | Secret appears in workload environment, logs, traces, SQLite, or artifacts | Cleared/allowlisted child environment, explicit execution environment, attempt-scoped grants, no persistence, redaction defense | Parent-environment negative tests and marker-secret scan across every sink | SEC/OPS | Transformed secret not recognized |
| TM-014 | Artifact is substituted after successful build | Staged digest verification and immutable metadata | Tamper, partial-upload, and restore tests | OPS | Storage administrator |
| TM-015 | Webhook is forged or replayed | Provider signature, body limits, immutable event ID | Invalid signature/replay/rate tests | EXT/SEC | Provider credential theft |
| TM-016 | Dependency or action is replaced through mutable reference | Lockfiles, signed releases, digest-pinned images/actions | Provenance and substitution gates | FOUND/REL | Upstream signing compromise |
| TM-017 | Database restore resurrects old authority | New recovery epoch and full agent reconciliation | Catastrophic restore drill | OPS/ARCH | Lost agent journals |
| TM-018 | Log/artifact volume exhausts controller or agent disk or memory | 64 MiB attempt-log and 64 KiB result quotas, bounded two-pass streaming, explicit backpressure | Oversize rejection, streaming digest-mismatch, disk-full, and quota war tests | OPS/AGENT | Operator misconfiguration |
| TM-019 | Approval is reused after pipeline or artifact changes | Approval binds build, IR, artifact, environment, action | Stale-approval negative tests | SEC/UX | Approver account compromise |
| TM-020 | Compatibility worker executes untrusted Groovy, forges compiler output, or imports mutable/secret-bearing authority | Groovy is never evaluated; v1 retains exact-source admission, while v2 performs bounded PARSING and original-source recognition before CONVERSION and requires independent Rust source-to-output agreement; exact source/context/profile/contract/compiler binding; no secrets/network/DB/agent/controller access; rootless read-only limits and all-false authority ledger; separate disabled state record; independent Rust canonical-EDN, strict-YAML, canonical-IR, provenance, authority, state, host-path, and secret-substitution validation | Deterministic exact-oracle and declared sequential-fixture compilation; sandbox/mount/symlink/limit/environment authority-negative gates; malformed/noncanonical/profile/authority/state/host-path/secret adversarial worker-output tests; working-tree marker scan | COMPAT/SEC | JVM/container escape or a jointly flawed worker and independent validator |
| TM-026 | A floating or substituted Jenkins step/plugin mapping silently falls back, reads an undeclared host input, or turns a compile-only construct into execution or external-effect authority | Versioned strict-YAML catalog; exact plugin/profile/corpus/source/target bindings; detached byte and semantic lock; deny-unknown schema; explicit unsupported policy; all-false authority; connector-only production effects; unearned local-input/shared-resource/cache semantics are not admitted | Mapping-catalog golden, strict-YAML, bundle, authority, policy, profile/plugin/corpus substitution, unknown-field, and coverage-inflation tests; sealed successor corpus | COMPAT/SEC | Only one literal `sh` mapping is earned; execution equivalence, local input, shared resources, cache behavior, and production effects remain uncertified |
| TM-027 | An attacker substitutes an OIDC provider, redirect, key, subject, group claim, code, state, nonce, or replayed token to obtain or retain another principal's authority | Tenant/provider-keyed exact configuration and JWKS generations/digests; HTTPS-only production endpoints; exact redirect allowlist; authorization code with PKCE S256; one-time state, nonce, ID-token and refresh evidence; strict issuer/audience/signature/time/subject/group validation; immutable external-subject and source-provenance binding; group and lifecycle generation fencing; absolute refresh deadline; refresh-reuse family revocation | Contained generated-key OIDC end-to-end test, malformed/substituted/replayed state and token tests, real PostgreSQL cross-tenant/group/lifecycle/refresh/logout tests, OpenAPI route contract, independent security and restore receipt in `docs/evidence/IDP-001_SECURITY_REVIEW.md` | IDP/SEC | Compromised target identity provider, trusted migration operator, or browser endpoint remains authoritative within its granted scope |
| TM-028 | Service credential rotation, lifecycle administration, or legacy-human migration silently preserves stale authority or rebinds identity | Digest-exact generation idempotence; atomic old-generation revocation; audited offline migration-role admin binary; compare-and-swap lifecycle transitions; one-way trigger-guarded legacy provenance binding; tenant RLS and immediate generation fencing | Same-generation substitution and next-generation rotation tests, revocation/authentication denial, strict admin-input tests, legacy quarantine/binding/activation test, audit-chain verification, identity-specific logical restore canary | IDP/SEC | Migration-role database compromise can administer identities and requires independent operational controls |
| TM-029 | Anonymous OIDC starts or retained session/replay/group history exhaust controller or PostgreSQL capacity | Per-source 60/minute start limiter with bounded client index; per-tenant/provider bounded live attempts with oldest-attempt eviction; 30-day expired replay/session retention and 128-generation group-history bound; tenant-scoped transactional pruning | Rate-bound unit/integration checks, PostgreSQL least-privilege pruning path, saturation and retention war tests before hostile multi-tenant exposure | IDP/OPS | Source-address aggregation and distributed-replica rate-limit coordination require an upstream authenticated edge for hostile Internet exposure |
| TM-030 | A Jenkins ACL is broadened to fit a coarse target role, a mutable principal name is rebound, or stale group/policy truth retains authority | Imported-project mode disables lattice fallback; immutable canonical policy generations bind exact source realm/inventory/ACL and target identity/provenance/generations; explicit action decisions default deny; deny wins; optimistic current pointer; privileged writes, forced RLS, hash-chained audit | Non-broadening and scheduler-negative tests; positive/negative/missing and deny-conflict decisions; source substitution, live group/session staleness, service rotation/revocation, update conflict, complete revocation, monotonic rollback, deployable-runtime preflight, and authorization-specific logical restore canary; bounded receipt in `docs/evidence/AUTHZ-001_SECURITY_REVIEW.md`; `DIFF-002` exact two-sided active/renamed and deleted-name-reuse identity cases, eight view/trigger/cancel/configure decisions, group-generation fencing, five disabled-ingress paths, zero-build proof, and immutable receipt `10fbbaed1d819ad9ec6962710de3f557e35c834fb6741f7cb08b085526a81786` | AUTHZ/SEC | Trusted inventory/reviewer, target IdP, or migration-role compromise; the synthetic contract denominator does not migrate a production realm or ACL population, so exact live production-population mapping, drift reconciliation, and per-job eligibility remain mandatory `MIG-007`, `SHADOW-001`, and `CANARY-001` gates before authority |
| TM-031 | A Jenkins reader is declared migrated while it still reads Jenkins, uses a substituted caller/tenant/endpoint, loses pagination state, or cannot restore source authority during outage | Immutable canonical per-consumer authority generations bind sealed inventory, caller/target identity, tenant/project, API/query/cursor/rate/retention/URL contract, evidence digests and observation window; a stable binding digest cannot change across authority transitions; target authority requires zero observed Jenkins reads; exact-source rollback is a new monotonic generation; migration-only writes, forced RLS, hash-chained audit | Authenticated API-only CLI journeys; missing/cross-tenant authorization matrix; real-PostgreSQL stale and independently redigested source/target/tenant/contract substitution, concurrent writer, residual-read, rollback, audit, RLS, and privilege-negative tests; bounded receipt in `docs/evidence/CONSUMER-001_SECURITY_REVIEW.md` | CONSUMER/SEC | Trusted inventory, evidence collector/reviewer, target IdP, and migration DB operator remain authoritative; production zero-read observation occurs only at real caller cutover |
| TM-032 | A Jenkins administrative writer is declared migrated while it still writes Jenkins, omits a configuration or run-control path, substitutes its caller/target/contract, uses stale or duplicate requests, or receives broadened target authority | Closed 15-operation denominator; exact versioned API/CLI mappings; unsupported operations require owner evidence and pending operations block cutover; stable source/target/operation binding; per-action runtime authorization under the shared policy lock; zero-write target gate; monotonic exact-source rollback; immutable forced-RLS ledger and hash-chained audit | API-only pipeline convergence; existing build idempotency and control-path tests; real-PostgreSQL omission, mapping, retirement, residual-write, least-authority, substitution, stale-generation, rollback, RLS, immutability, and audit tests; bounded receipt in `docs/evidence/ADMIN-001_SECURITY_REVIEW.md` | ADMIN/SEC | Trusted inventory, evidence collector/reviewer, target IdP, owner-retirement attestation, and migration DB operator; real zero-write and retirement evidence exist only at a later caller transition |
| TM-033 | A mutable external runtime read is sampled twice, substituted, replayed, stale, oversized, secret-bearing, overprivileged, or allowed to mutate its source while influencing control flow or effects | Standalone GET-only adapter; exact executable/configuration/endpoint/data-source/grant/schema/generation binding; content-pinned bearer token, HMAC key, and full private CA bundle; authorization/grant-header and Unix directory-durability preflight before spool/claim publication; unsupported platforms fail closed at construction; bounded regular-file reads with symlink denial; canonical allowlisted query; TLS and no redirect/proxy inheritance; disabled client-library retry; freshness/cursor/type/size/rate/timeout/retry bounds; matching-claim convergence then serialized rate admission before new claims; synchronized private claim staging and atomic no-overwrite publication; claim-file and directory synchronization before source access; no-overwrite signed receipt plus directory synchronization before success; secret-label denial and independent full-header/body marker scanning; identical receipt replay to both runners | Sealed zero-input Mario inventory test; contained valid/branch/stale/missing/malformed/oversized/auth/replay/outage/retry/restart/cutover/rollback fixture matrix; standalone-process journey; invalid authorization/grant-header pre-spool denial; low-rate and cross-adapter concurrent one-read convergence plus zero-write assertions; source-header/body marker denial; rate-denial no-claim assertion; bounded-file oversize/symlink denial; bounded receipt in `docs/evidence/INPUT-001_SECURITY_REVIEW.md` | INPUT/SEC | Trusted Unix host and containing directories, endpoint/CA, grant issuer, adapter/marker operator, and shared-key verifier; transformed secrets outside the marker set; real production input remains unclaimed |
| TM-034 | A dynamic-agent request creates duplicate, substituted, overprivileged, stale, orphaned, or escaped compute, or reports cleanup while an instance remains | Standalone provisioner with one provider/account/region/agent-class identity; exact executable/configuration/generation/request/fence binding; durable pre-create intent and provider idempotency key; cross-process receipt convergence; global/tenant/project quotas; closed create/get/list/delete routes; short-lived prevalidated grant; no redirects/proxies/implicit retry; pinned private CA and Ed25519 provider attestation; bounded fresh duplicate-free typed responses; exact immutable template/image/bootstrap/toolchain/platform/capability/trust/network/volume/workspace/cache equality; short-lived instance IAM identity; FULL-synchronous closed-state ledger; cleanup only after signed delete plus fresh signed absence; complete-inventory orphan cleanup and explicit escaped-compute truth | Sealed zero-dynamic-agent Mario inventory; real contained provider and standalone-process matrix covering exact replay/concurrency, stale/reordered fences, quotas, substitution and least-authority policies, pending/ready/failure/timeout/cancel, ambiguous create restart, agent loss, orphan cleanup, scale-down, generation cutover/rollback, duplicate JSON, invalid-config pre-state denial, and authority-material non-disclosure; protocol in `docs/architecture/DYNAMIC_PROVISIONER_V1.md` | PROV/SEC | Trusted Unix host and containing directories, provider/CA and cloud administrator, grant issuer, provisioner operator, and shared-key receipt verifier; real provider behavior, live dynamic-agent canary, cutover, and rollback remain unclaimed |
| TM-035 | A mutable, substituted, untrusted, oversized, credential-leaking, or incorrectly attested workload dependency enters a build or a completed resolution is replayed with different bytes | Standalone non-executing resolver; dedicated Ed25519 source-provenance signature over the complete request; exact source/lock/plan/graph/repository/grant/adapter/resolver/toolchain/configuration/generation binding; closed fail-closed ecosystem adapters; exact versions and complete graph; no redirect/proxy/implicit retry; pinned private CA; Ed25519 repository attestation; continuous size/digest/marker verification across response chunks, adjacent transport slices, and the complete generated archive serialization; authenticated untrusted-source credential denial; path-only/nonblocking pinned-inode inspection for configuration, executable, authority, and transport-lock inputs; kernel-bounded dedicated transport filesystem; one deadline-bounded serialized fetch slot with poison recheck after acquisition, a four-state atomic compare-and-swap success/pending-poison handshake before slot release, immediate non-cancelable pending poison, and caller-deadline-bounded final external poison fencing through that same slot; absolute monotonic deadline; one exclusive contiguous transport archive with sync failures routed through exact cleanup or poisoned ambiguity and every post-create pre-identity inspection failure poisoning later use; durable claim-first atomic sealed publication archive with bounded strict header, closed manifest, exact payload and whole-file digests, final-link revalidation, HMAC receipt, authenticated permanent publication commit, and exact replay | Sealed zero-workload-dependency Mario inventory; real contained npm/PyPI/Maven repositories and standalone-process matrix covering forged trust/source/receipt/lock/scope provenance, mutable/unsupported locks, omission/cycle/substitution, compromised mirror, wrong artifact/digest/size/key/attestation, missing/offline/timeout, credential disclosure including markers crossing real response-chunk, adjacent-artifact, header-to-payload, and payload-to-payload boundaries, final archive-sync failure and exact cleanup, archive/root metadata plus real non-file/device-mismatch/zero-inode validation, second real-fetch denial, overlapping-fetch internal and external poison fencing including both atomic orders, prompt caller-deadline expiry, active-success denial, and post-verification-barrier two-worker queued-fetch no-creation proof, trust-class denial, FIFO/device and namespace substitutions at startup, transport, publication, cleanup, and replay boundaries, sparse lock substitution, unmanifested archive bytes, quotas/disk full, concurrent replay/restart/cutover/rollback, late-publication denial, zero network for forged trust, and zero artifact execution; protocol in `docs/architecture/DEPENDENCY_RESOLUTION_V1.md` | DEP/SEC | Trusted Linux host and containing directories, source-provenance signer that verifies SCM acquisition evidence, repository/CA and attestation-key owner, grant issuer, resolver operator, and shared-key receipt verifier; ecosystem exporter correctness and upstream signer compromise; no real Mario dependency authority is claimed |
| TM-036 | A cache hit crosses tenant, project, pipeline, trust, generation, or restore boundaries; returns substituted or corrupt bytes; lets a stale caller or process regain authority; exhausts state or discards committed evidence; mixes receipt keys; launders fabricated stale rows into signed provenance; or lets concurrent writers replace immutable content | Standalone non-executing cache process; exact executable, owner-private read-only configuration, caller-presented generation digest, key/policy/generation/restore binding; persisted immutable receipt-key digest; monotonic active-generation/restore transaction fence; canonical domain-separated keys; no trust promotion; private FULL-synchronous strict SQLite state; per-policy byte/count/TTL and audit-event quotas; atomic insert-or-idempotent-replay; byte-length, digest, and original signed-publication revalidation before every hit or normal cleanup disposition; deterministic LRU eviction; response-bounded stale cleanup including removed policies; controller restore-epoch fencing; same-transaction HMAC-signed hash-chained receipts verified against an independently retained count/head; bounded newline-complete strict NDJSON and no network, repository, secret, scheduler, agent, shell, or effect authority | Sealed zero-cache Mario inventory; contained cold/hit, scope/principal/trust denial, stale-caller/process fencing, untrusted-write/trusted-read, key/metadata/content and publication-provenance corruption, concurrent convergence/conflict, receipt-key rotation rejection, quota/audit exhaustion/expiry/eviction/cleanup, removed-policy cleanup, under-lock TTL, generation/restore cold-state, retained-head and audit-tamper rejection, immutable private authority, executable substitution, duplicate/unknown/oversized/unterminated frame, and standalone-process tests; protocol in `docs/architecture/CACHE_SERVICE_V1.md` | CACHE/SEC | Trusted Unix host and containing directories, controller restore-epoch owner, cache policy/operator, supervising transport-denial auditor, and shared HMAC verifier; production cache mappings, live performance, canary, cutover, rollback, and decommission remain unclaimed |
| TM-037 | A runner or effectful connector fabricates, suppresses, reorders, substitutes, or credentials its own destination observation; a stale observer, cursor, grant, endpoint, configuration, or response is accepted as independent effect truth | Independently deployed GET-only Linux observer per destination/effect class; production-only HTTPS loader and feature-gated literal-loopback test boundary; executing-inode digest through `/proc/self/exe`; distinct deployment, runtime, service, issuance, configuration, request, destination-attestation, and receipt-signing authorities; revocable non-self-referential configuration identity; exact signed request/destination/receipt bindings; private FULL-synchronous durable claim/cursor and outbound-attempt ledger with atomic persisted reservation-reached state; fixed state-lineage lease serializes cutover/rollback with in-flight reads even across destination-scope changes; independently quota-bounded durable phase heads, pending head-slot reservations with non-mutating admission-time expiry filtering and post-lease cleanup, and physical cursor high-water across receipt pruning; one pending read per destination scope; strict pre/post/reconciliation predecessor chain; canonical allowlisted query; pinned CA, no redirects/proxies/implicit retry; transport-boundary authority resampling; bounded headers/body/time/freshness/rate/retry/evidence, schema-sizing startup work, and transactional terminal-evidence retention pruning; typed closed state; whole-value encoded and nested-encoding marker scan including bounded canonical-padding plus interior start/end phase probes that restart across concatenated or mixed-alphabet Base64 tokens; terminal-denial release and canonical tombstone convergence with bounded transport retry; no scheduler, controller, agent, workload-secret, connector-control, write, or effect authority | Protected standard validation enables the complete literal-loopback observer contract suite; contained signed pre/post/reconciliation and exact replay; durable outage/restart, retry rate budget, pre-reservation-crash release, pre-read evidence exhaustion, retained-chain and retained-cursor denial after evidence pruning, no-read expired replay, pending head-slot reservation, expired-reservation release without in-flight invalidation, and scope-head quota after receipt pruning, scope-changing cutover/read serialization, permanent 401/403 stream-reset classification, and success/terminal-response races against concurrent expiry; forged request/receipt, replay mismatch, phase reorder, cursor rollback, stale/malformed/oversized/substituted/secret-bearing response, concatenated padded encoding, alphabet-prefixed and alphabet-suffixed encoding, benign padding-heavy response, timeout/outage, destination permission, grant expiry, credential/config substitution and revocation, production loopback denial, temporally admissible request-envelope, bounded schema-sizing work, and exact response/receipt frame bounds; sealed zero-authority Mario inventory; protocol in `docs/architecture/DESTINATION_OBSERVER_V1.md` | OBS/SEC | Trusted Linux host, deployment/configuration/credential operators, destination/CA/attestation and request authorities, destination implementation and clock; transformed secrets outside marker set; production mappings and live non-collusion remain unclaimed |
| TM-038 | A disabled pipeline, stale operational generation, raw-source compatibility route, trigger/disable race, or already-offered attempt mints new work, retry, approval, credential, or effect authority after the disable fence | Operational state is append-only PostgreSQL truth separate from immutable IR; monotonic generation and optimistic concurrency; per-pipeline advisory plus definition-row locking; build binding to saved revision/digest/generation; parameters-only saved-pipeline admission; state re-read at scheduler claim/accept, lease, retry, approval, credential delivery, and effect checkpoints; raw-source build ingress removed; hash-chained transition audit | Real-PostgreSQL v26-to-v27 migration/backfill, immutable history, disabled import, rollback provenance, exact/divergent/stale transition, active-active/restart, wrong-digest admission, concurrent trigger/disable and scheduler/disable, post-fence offer replay, authorization-denial, API/CLI/UI route, and authority-boundary tests; protocol in `docs/architecture/PIPELINE_OPERATIONAL_STATE_V1.md`; `DIFF-002` exact enabled/disabled/re-enabled generation comparison, five distinct source and target disabled-ingress paths, pre-queue denial, zero build/grant/approval/effect proof, and immutable receipt `10fbbaed1d819ad9ec6962710de3f557e35c834fb6741f7cb08b085526a81786` | CTRL/SEC | A database or deployment operator can alter application truth; pre-v27 unbound active builds are deliberately frozen; future trigger types remain ineligible until they use the same transaction fence |
| TM-039 | A forged, substituted, duplicated, reordered, delayed, stale-generation, or unaudited trigger event mints duplicate work; a crash skips a schedule slot; invalid stored parameters strand a claim or starve retries; controller-clock skew or audit-head contention advances/delays acceptance, TTL, due work, retry, claim, or DAG-admission authority, kills a live delivery, steals a claim, creates an already-expired claim, or commits an expired runnable build; a no-op empty SCM path filter rejects a pathless valid event or accepts malformed supplied paths; an oversized parameter name creates an unpersistable poison failure; accepted schedule text cannot fit the watermark; a normal build preclaims a trigger-derived idempotency key; admission or failure crosses delivery or claim expiry, spends retry budget, or leaves an orphaned runnable build; a crashed claim strands paused handoff; a stale worker completes another claim; conflicting redrives leak a uniqueness failure; inconsistent trigger/pipeline or pipeline/audit lock order deadlocks; or a plugin/source class gains authority without an implementation | Kind-discriminated closed trigger/configuration/filter, exact Rust-width integer, bounded parameter-name/value, and event-payload schemas; unordered unique bounded filter arrays with order-independent runtime membership and empty-filter no-op semantics while supplied paths remain schema-validated; pre-capture plus post-claim parameter validation with bounded canonical failure reasons and terminal lease-releasing failure; exact authenticated event-source identity and generation; canonical payload/configuration/filter/implementation digests; common organization/trigger advisory scope before every mixed trigger/delivery/pipeline transaction; lock-serialized unique delivery/event/redrive ledger; audit-head-before-clock ordering for acceptance/redrive/claim/failure, and pipeline-before-audit-before-clock ordering for DAG admission matching ordinary admission and pipeline transitions; PostgreSQL-clock acceptance/redrive timestamps and TTL, replay/skew window, due enumeration, failure retry/TTL/lease decisions, claim due/TTL/ownership decisions, DAG-admission TTL/lease decisions, and derived expiry; reserved trigger-DAG idempotency namespace rejected by ordinary API and store admission; bounded replay/skew/TTL/retry; pipeline-and-audit-locked savepoint-staged DAG plus delivery binding in one transaction, with database-clock delivery-TTL and claim-lease predicates, complete DAG rollback before expiry handling, and typed lease-lost outcomes outside failure accounting; configuration-time schedule text bounds equal watermark bounds; paused handoff reaps only database-clock-expired claims and rejects live leases; PostgreSQL claim fences; atomic saved-pipeline admission; immutable dead-letter redrive lineage; schedule slot-set digest plus atomic delivery/watermark transaction and exact generation/slot delivery linkage; exact exported-ledger digest committed in a handoff audit event whose hash must be supplied from an independently retained audit export or chain head; forced RLS and hash-chained audit; unimplemented plugins and incomplete Jenkins `H` inputs fail closed | Real-PostgreSQL concurrent first acceptance/redrive/configuration/claim, controller-clock-skew acceptance/redrive TTL, due/retry/claim ownership, deterministic audit-head-contention acceptance TTL, claim TTL/lease issuance, expired-failure lease loss, and DAG-admission lease loss with no runnable build, deterministic pipeline-before-audit DAG-admission ordering, pathless SCM acceptance plus malformed supplied-path denial under an empty path-prefix filter, bounded parameter-name/failure and schedule-watermark configuration denial, reserved trigger-key ordinary API/store denial, configuration-versus-claim lock order, different-source redrive identity conflict, pre-capture and corrupt-store parameter denial, atomic completion-time delivery/claim expiry with no build replay binding or retry-budget spend, expired-claim handoff reaping, exact/divergent replay, skew/delay, retry/exhaustion/redrive, caller rotation, pause/resume, disable, restart, schedule reorder/substitution and handoff-link tamper, fully recomputed ledger/audit/snapshot substitution against the independent anchor, upstream status, unsupported-plugin, API authorization/filter/generation-replay, kind-discriminated configuration, exact integer widths, unordered unique filters with order-independent store revalidation, and payload OpenAPI, exact deployable runtime-policy preflight, and route tests; protocol in `docs/architecture/TRIGGER_INGRESS_V1.md` | TRIG/SEC | Trusted trigger configuration reviewer, identity provider/event-source credential, scheduler resolver and clock, independently retained audit head/export, PostgreSQL/deployment operator; sealed Mario schedule hash inputs remain incomplete, so production TimerTrigger and plugin authority remain ineligible |
| TM-040 | A substituted implementation, parent configuration, provider/repository, authz policy, trigger, source-acquirer binding, revision, Jenkinsfile, child identity, fork trust result, orphan disposition, duplicate/reordered webhook, stale recovery scan, immutable history, or accumulated child population creates, updates, retires, transfers, or exhausts reconciliation for the wrong multibranch/organization child | Immutable digest-bound parent generations; closed providers, parent/ref/scan/trust/orphan strategies; structural ref-identity validation before policy filters; exact current authz and enabled SCM-trigger re-read under a per-parent advisory lock; canonical request and observation digests; unique scan/event/cursor ledger; one immutable uniquely key/UUID-indexed identity-registry row per child; atomic immutable observations plus monotonic child state; constant-work identity-substitution denial; untrusted-fork quarantine; complete-snapshot-only set-based orphan retirement using the bounded reported-key set; forced RLS and exact runtime grant preflight; quiesced deterministic transfer ledger committed into a hash-chained event verified against an independent audit anchor; no build/effect authority | Real-PostgreSQL new/update/delete branch and PR, malformed filtered-branch identity, trusted/untrusted fork, filter, exact/divergent replay, retained/materialized key and UUID substitution, reordered cursor, periodic/recovery catch-up, set-based complete-snapshot orphan retirement, parent/authz drift, quiescence, rollback, complete transfer and independent-anchor tamper tests; typed route and OpenAPI tests; protocol in `docs/architecture/DISCOVERY_V1.md` | DISC/SEC | Trusted provider and source-acquisition attestations, discovery/config/authz reviewers, independently retained audit head/export, PostgreSQL/deployment operator; no Mario production discovery mapping, canary, or cutover is claimed |
| TM-041 | A missing, forged, stale, replayed, cross-tenant, cross-attempt, misclassified, overbroad, rotated, revoked, or secret-disclosing Jenkins credential mapping grants authority to a runner, wrong consumer, or later fence | Exact sealed-inventory reconciliation; closed consumer/taint types with controller/workload visibility permanently ineligible; startup-pinned nonempty and unambiguous Ed25519 owner-key registry plus owner approval over tenant/scope/provider/consumer/classification truth; exact provider and consumer implementation/configuration digests; monotonic mapping generations; trusted-time fifteen-minute grants; permanent per-generation attempt/fence/consumer scope uniqueness; atomic one-time redemption; rotation and emergency-revocation fencing; nonserializable zeroizing secret material; raw/Base64/Base64URL/hex/percent public-evidence scan; owner-private single-link SQLite and hash-chained audit; runners and shadows receive only SCM or connector receipts | Exact/missing inventory, owner registry/payload/key/expiry, taint/disposition, provider-version, cross-tenant/project/build/attempt/fence/consumer, trusted-time, renamed-grant, replay, rotation, emergency-revocation, public-evidence encoding, audit-tamper, state-path, typed connector/source binding, and sealed zero-authority Mario tests; protocol in `docs/architecture/SECRET_MAPPING_V1.md` | SECRET/SEC | Trusted host/deployment operator, owner signing key and owner decision, provider adapter/service and clock; transformed secrets beyond scanned representations; no production provider, credential, canary, cutover, rollback, or decommission authority is claimed |
| TM-042 | A source, dependency, builder, toolchain, policy result, component, bundle, signer, final-envelope binding, transparency proof, evidence manifest, timestamp anchor, deployment configuration, or rollback target is substituted before a production deployment | Exact protected source archive; digest-pinned isolated networkless read-only builder with ephemeral dependency reconstruction; canonical lock-derived SBOM; deterministic self-hashing bundle; signer-side recomputation of every build output; owner-private Ed25519 signing key; independently pinned source, builder, gate and signer policy; predeclared secondary-key/log/anchor requirements; post-sign Rekor evidence bound to the canonical envelope digest; canonical evidence-manifest join across release/policy/Rekor/SBOM/bundle/lock; independent timestamp proof bound to the canonical evidence-manifest digest; exact verified rollback ancestry; private `VerifiedRelease` deployment capability and create-new synchronized receipts | Source/archive/lock, builder/epoch, policy, SBOM/bundle/component, signer/signature, envelope digest, valid and malformed Rekor evidence, evidence-manifest and independent-anchor substitution, rollback ancestry, bundle traversal/trailing data, canonical repository SBOM, generated/private/symlink signing-key and overwrite-denial tests; protected-main isolated build and external ceremony defined in `docs/architecture/RELEASE_PROVENANCE_V2.md`; REL-001 closure receipt `094276689d6cec9fbb63b1abd51f5b9a3f9b588c52e32be5e264fb20822af237` | REL/SEC | Trusted kernel, Docker and signer hosts, protected-branch/workflow administrators, image/dependency reviewers, signer operator, transparency validator, independent policy/audit store and deployment operator; upstream compromise at an approved digest and joint builder-policy compromise remain possible; v0.1.0 private-release provenance is verified, while binary placement, production deployment, canary, cutover, and public binary publication remain unclaimed |
| TM-043 | A forward or reverse migration omits, substitutes, reorders, prematurely deletes, or incorrectly rebinds build numbers, prior results, SCM baselines/changelogs, cross-build artifacts, retained workspace or state, retention deadlines, legal holds, approvals, retry lineage, or first-authoritative-run truth | Versioned deterministic idempotent forward/reverse transforms bound to immutable source and target identities; exact record-level digests and provenance; contiguous build and SCM/change baselines; artifact/workspace/state content binding; retention never weakened and active-hold union preserved with explicit release authority; approval identity/value/expiry and retry lineage binding; restart and rollback digests; effect-free first-authoritative run | `MIG-005A` seeded four-build forward/reverse rehearsal and `DIFF-002` two-sided build 1-4, next-number, prior-result, four-SCM-revision and false/true/true/false predicate sequence, artifact/workspace/state digest, retention/three-hold, unauthorized release, approval-expiry, retry/fail-fast lineage, restart/rollback, reverse-reconciliation, history-gap/hold-omission mutation, and immutable receipt `10fbbaed1d819ad9ec6962710de3f557e35c834fb6741f7cb08b085526a81786`; exact admitted-case corrective proof over one retained aborted build, actual pinned process execution with two ordered durable log streams, idempotent PostgreSQL forward/reverse retrieval, effect-free McLoving build 2, reverse-imported Jenkins build 2, restart, native `Build` workflow retrieval, and exactly-once Jenkins build 3 under two owner-only manifest-verified evidence packages retained only on HeMan | MIG/OPS/SEC | The synthetic denominator and the exact recorded `corpus-052-cinqict_jenkinsdev` dependency are closed. Live-population drift reconciliation and packaging of the exact bounded objects remain mandatory `MIG-007`, `SHADOW-001`, and `CANARY-001` gates before authority |
| TM-044 | A static external-boundary certificate, colluding component and test, missing public receipt, stale or substituted receipt identity, replayed owner client, residual Jenkins access, shadow endpoint, secret disclosure, ambiguous effect, or duplicate effect falsely claims DIFF-003 parity | Fail-closed certificate and runtime verifiers; exact component source manifests and implementation identities; isolated Jenkins and target stacks; physically separate no-network connector and observer containers with disjoint writable mounts; main runner restricted to disjoint receipt, scenario-observation, and runner-output mounts rather than the evidence root; exact 15-suite ledger; ephemeral-key Ed25519 authentication of 13 exact public receipt files; 48 scenario-specific observed-condition runtime outcomes with nonempty structured observations; 11 pair-specific compatibility rules over projections independently derived from each live receipt, each with at least one cross-receipt binding; rootless isolated resolver alias negatives; owner client remains `jenkins_source`; raw/Base64/Base64URL/nested plus case-insensitive hex/percent marker scanning in contents and pathnames; nonregular and multiply-linked evidence rejection; exact clean-head seal | `DIFF-003` feature-enabled observer, exact-capacity and authority-alias resolver suites, 13 authenticated live receipts, 48 assertion-derived scenarios, 11 validated two-receipt joins, zero production mappings/effects/cutover claims/duplicates/marker disclosures, and post-merge repository indexing of the accepted head, tree, evidence-manifest, and receipt-authentication public-key digests in `docs/evidence/DIFF-003_SECURITY_REVIEW.md` | DIFF/SEC | A jointly flawed boundary implementation, focused test, and runtime rule can still agree; contained fixtures are not live production observation. `MIG-006`, `MIG-007`, `SHADOW-001`, `CANARY-001`, cutover, rollback, and decommission gates remain mandatory before authority |
| TM-045 | A migration aggregate substitutes an input, races an intermediate directory alias, hides a symlink component behind lexical parent traversal, redirects a validated root through a writable ancestor, changes a file between authentication and semantic verification, silently reruns alternate logic, mixes source/profile/compiler/mapping/component/release identities, omits or duplicates a case, borrows a favorable denominator, promotes legacy parser/model reach into runnable coverage, changes a fail-closed disposition, or implies production authority | Two-file detached and compiled digest seal with immediate unexpected/third-entry rejection; original root-component no-follow traversal before normalization; retained final root handles anchoring descendant opens; direct canonical roots with ancestor-alias denial; Windows ordinal Unicode case-insensitive spelling plus opened-directory identity comparison; twelve fixed bounded singly linked regular-file inputs with traversal denial; Unix no-follow directory-relative traversal from the retained root descriptor and Windows retained no-reparse directory handles without delete sharing; one no-follow file handle used for reparse/link validation and bounded reading on Linux and Windows; nonblocking Unix opens reject FIFOs without waiting; pre-read and streaming byte ceilings; exact authenticated in-memory DIFF-001 manifest map and DIFF-002/003 evidence byte slices consumed directly by the three canonical differential verifiers without a temporary filesystem or post-authentication path reopen; exact cross-receipt image, source, compiler, mapping, state-transform, component-manifest, and release joins; 230-job/228-source set equality; one admitted plus 227 stable-rejection classification; seven ordered metric contracts with named populations and units; explicit non-authoritative legacy `ranvil_native` annotation; closed aggregate/regression taxonomies; all-false authority ledger; MIG-007 package explicitly absent from inputs | Exact aggregate positive test; input, evidence, identity, denominator, taxonomy, authority, extra/missing/nonregular/symlink/hardlink/FIFO/oversize/root-alias/root-replacement/canceling-parent-alias/intermediate-alias/source-replacement and Windows Unicode root-spelling tests; full canonical DIFF-001/002/003 verifier execution against authenticated in-memory bytes; architecture contract in `docs/architecture/DIFFERENTIAL_AGGREGATE_V1.md` | MIG/SEC | The aggregate verifies the exact committed evidence and its joins; it cannot detect a flaw shared by an upstream implementation and its accepted verifier, and it grants no live migration, shadow, production, canary, cutover, rollback, or decommission authority |
| TM-046 | A migration package substitutes source/YAML/job state/compiler/mapping/differential/state-transfer/release truth, cites unavailable digest-only objects, hides a retained state dependency, omits a rejected case, invents a state dependency or rehearsal, carries credential bytes, or promotes a disabled certified case into production authority | Single bounded canonical JSON envelope with compiled and detached SHA-256; exact embedded artifact digests; canonical in-memory compiler admission, mapping, state-policy, and MIG-006 verifier composition; exact source/configuration/profile/compiler/IR/release bindings; authenticated parsing of the sealed eligibility and persistent-state inventories; complete sorted 228-case ledger with zero packaged cases and 228 deterministic rejections; exact one-record `build-history` dependency with unsupported forward/rollback disposition and `E_STATE_TRANSFER_EVIDENCE_UNAVAILABLE`; empty case-specific-rehearsal and packaged-artifact sets; explicit package, shadow, cutover, and rollback ineligibility; no credential-material field; all-false authority ledger. A later package may claim a state-transfer object only when it carries the bounded bytes or requires an immutable content-addressed source and verifies the retrieved bytes | Deterministic generation equality; canonical seal and positive composition tests; artifact, authority, disposition, state-inventory, state-dependency, state-artifact/eligibility, presentation, digest, atomic-publication, and cross-platform mutation denial; architecture contract in `docs/architecture/MIGRATION_PACKAGE_V1.md` | MIG/SEC | The currently merged package truthfully binds one retained build-history dependency and remains incomplete. MIG-005A has now produced the exact corrective objects and receipts, but they are not package inputs until active MIG-007 embeds or immutably retrieves and verifies them; no case-specific shadow, canary, effect, cutover, rollback, or decommission authority exists |
| TM-047 | An owner-private migration package leaks private Jenkins bytes, trusts another account's file or a redirectable parent as an owner anchor, trusts a substituted evidence tree or package, mixes forward and reverse ceremonies, changes an implementation/configuration binding, corrupts a completed-build stream or retained XML record, drops a continuity receipt or Jenkins sidecar, loses the restarted source build, retains a stale build cursor/permalink, substitutes public topology for the private network, follows an alias, accepts a multiply-linked or overbroad input, leaves a second publication link, or converts shadow eligibility into production authority | Separate bounded canonical `private-v1` envelope retained only on HeMan; embeds the exact canonical public baseline plus complete forward and reverse archives; independent owner-held manifest, transform-implementation, and package pins never printed or committed; exact reviewed MIG-005A and MIG-006 heads; effective-user ownership and owner-only modes on every sealed-source/evidence/package directory, file, and immediate parent; descriptor-relative no-follow traversal of private package/pin paths from `/`; every writable ancestor must belong to the effective user or be root-owned and sticky; no-follow, single-link, bounded regular-file reads; exact filesystem and manifest denominators; canonical state-bundle reconstruction through the canonical forward and reverse APIs; exact Jenkins retained-build, reverse-import receipt, and native-provenance sidecar joins; retained build-2/build-3 manifest-path identities and XML result/timing joins to imported/restarted/continued API receipts; ordered completed-build LogState sequence/digest/byte/retrieval/media joins to both captured stream chunks and their aggregate; cross-check of pinned transform implementation/configuration identities against the rehearsal summary and both Jenkins binding receipts; semantic validation and cross-file joining of imported, restarted, continued, and serialization-template workflow/stage/shell receipts including mandatory workflow-to-stage identifiers; restarted build-1 result/log joined to the authenticated source; retained next-build cursor and exact build-3 permalink set; captured internal-network flag and exclusive forward/reverse container membership joined to exact `public-network-denied`; private atomic publication requires staging-link removal and a second held-parent sync; one packaged plus 227 rejected cases; explicit package-complete and deny-authority shadow eligibility with every later authority bit false | Focused canonical state-transfer and migration-package tests; ancestor-alias/writable-parent, traversal, duplicate-manifest, content-substitution, retained-XML, log-state, sidecar-authority, sealed-source-mode, workflow-ID, cursor/permalink, private-topology, and publication-cleanup denial; complete owner-private generation and independent verification against the final MIG-005A forward and reverse evidence packages; architecture contract in `docs/architecture/MIGRATION_PACKAGE_V1.md` | MIG/SEC | Trusted HeMan kernel and owner account, retained owner pins, reviewed source and exact private evidence. Package bytes remain private, and exact-head review, CI, protected-main merge, `SHADOW-001`, and `CANARY-001` remain mandatory; no production credential, trigger, scheduler, effect, canary, cutover, rollback, or decommission authority is granted |
| TM-048 | A shadow session substitutes the MIG-007 package, source/target state, release, runtime, authorization, clock, entropy, input, event, trace, or isolation truth; fabricates or transplants captures; reuses or substitutes signing identities; omits, duplicates, reorders, or mutates an ingress observation; follows a private-path alias; publishes a partial session; reaches production; or converts denial parity into production authority | Separate bounded canonical owner-private SHADOW-001 session; independent session, source-capture public-key, live authorization-generation, and exact verifier-binary pins; direct in-memory MIG-007 verification; exact protected-main, source/target, release/runtime, authorization, and empty-input freeze; distinct precommitted Ed25519 source-capture and shadow-replay identities; authorization resampling before source capture and immediately before template preparation; exact Jenkinsfile/job-configuration re-hash and restoration; dynamic credential-lookup, all-interface outbound-network including loopback, and recursive Jenkins-home effect monitoring; exact compiler-v1 target pipeline and job-state retrieval from PostgreSQL; isolated read-only target/peer containers on a fresh internal-only network; authenticated source signatures over a canonical binding that includes every paired unsigned receipt and both audit digests; shadow-only sealing; five ordered API/manual/schedule/upstream/webhook receipts; exact paired trace; complete teardown; zero production endpoint, credential, request, host-mount, cross-fixture, or effect counts; all-false authority ledger; descriptor-relative no-follow owner-private reads; create-new synced publication and rollback; digest-free bounded output | Canonical positive and mutation suites for package/runtime/authorization/verifier/input/trace/isolation drift, event and signature substitution, cross-session transplantation, shared/replaced keys, caller-supplied shadow signatures, replay-audit mutation, every authority bit, aliases/hardlinks/modes/create-new publication, noncanonical/oversize/redacted failure; live Mario five-path probe with source/configuration restoration and dynamic zero-effect monitoring; exact PR head `b8f422ce2deaa9640a863ff2730373ebd242781e` review and nine observed workflow outcomes under the pre-CI-003 protection configuration; protected-main commit `dbc3bad735bc45241ee048e1d364ed478eae7e3c` post-merge Foundation and Windows verification; owner-private HeMan ceremony authenticated five captures, five replays, one trace, zero mismatches, one packaged case, and 227 rejections with `shadow_qualified=true` and `production_authority=false`; architecture closure in `docs/architecture/SHADOW_QUALIFICATION_V1.md` | MIG/SEC | Trusted HeMan kernel and owner account, independent pin owners, distinct signing-key operators, runtime/effect/reachability collectors, and reviewed exact package/session inputs. The accepted session covers only the exact disabled deny-authority case; it grants no production execution, credential, trigger, scheduler, connector, effect, canary, cutover, rollback, or decommission authority |
| TM-049 | A canary action uses a stale or forged threat review, inventory, runtime freeze, quiescence, history transfer, intent, grant, connector outcome, shadow replay, or destination observation; substitutes an unrelated source inventory for the relinquishing runner; substitutes unsigned signer metadata to impersonate the downstream release authority; dispatches before the grant; backdates shadow replay; lets an unsigned release time widen the authority window; shares signing authority across roles; grants before exact intent match; overlaps old and new effect authority; omits a client or state record; widens a quota; releases downstream flow before replay; treats ambiguity as success; duplicates an effect; or promotes an unsupported job | Bounded canonical owner-private CANARY-001 session plus independently held session and eleven pairwise-distinct role-key pins; domain-separated signatures over a length-delimited signer key identity and canonical body; common exact-head/package/MIG-006/SHADOW/action context on every signed gate; current threat-model and residual-risk review; live inventory/client reconciliation plus a domain-separated source-controller/relinquishing-runner binding repeated in the signed inventory, quiescence, and final ledger; exact 20-component atomic freeze; zero-count relinquishing-runner quiescence; complete fresh certified state transform with retention/hold and secret-scan assertions; exact one-to-one buffered intent match; one-action, bounded-window, first-failure-abort grant binding the exact request, pre-action observation, and expected result; authenticated EXT-001 outcome with a connector-signed single dispatch timestamp no earlier than grant issuance; effect-free shadow replay with replayer-sampled signed time before downstream release; independently authenticated chained OBS-001 pre/post-action receipts; connector/observer identity separation; Windows persistent-host proof; final independently signed ledger binding the post-evidence effect freeze plus actual downstream-release event, authority, and timestamp; verifier has no production endpoint, credential, connector, state mutation, or authority-grant capability | Canonical positive test plus signed inventory-ineligibility, source-controller/runner substitution, signer-identity substitution, partial-freeze, request/precondition/result, pre-grant/missing/multiple dispatch, shadow caller-time backdating, unsigned release-time, release-before-freeze, outcome-replay substitution, shared-role-key, and noncanonical-session denial; sealed Mario scenario and 230-job eligibility negative fixture; architecture contract in `docs/architecture/CANARY_QUALIFICATION_V1.md` | MIG/SEC/EXT | Trusted signing operators, HeMan kernel/account, live collectors, certified transforms and external systems. No current Mario job is canary-eligible, so an actual production proof remains impossible until one effectful case completes fresh MIG-002 through MIG-007 and SHADOW-001 certification plus an explicit one-action owner grant |
| TM-050 | Another local user on a deployment host substitutes what a deployment transition or service start will read or execute -- a release or helper binary, an interpreter resolved by name, a unit file, a merged drop-in, an `Exec*` argument, a CA bundle or identity binding, or an environment contract -- or renames a subtree aside to redirect any of them, on a host whose directory chain permits it | ONE positive invariant established before every transition -- and, at service start, established only PARTIALLY, which a pre-canary or pre-cutover review must not credit as the whole invariant: systemd has already loaded the unit before any `ExecStartPre` runs, and `mcloving-env-guard` walks only the environment file and the configured secret and state paths, never the unit, the guard executable itself, or the selected release binary, so an ancestor that became writable since the last transition is not caught at start and a substituted unit can omit the guard; a start-time verifier rooted outside the service-owned tree is PENDING under `DEPLOY-003` -- rather than derived per case: every path the transition or start will read or execute is unwritable by any uid other than root or the service account along its resolved ancestor chain TO `/`, the home's own chain included -- it used to stop AT the deployment home, so a home beneath a foreign-owned or writable-without-sticky parent could be renamed aside and the substituted home became its own trust anchor; the walk now resolves every path component by component in filesystem order so `..` cannot be collapsed ahead of a symlink, judges each intermediate symlink's own inode by `lstat`, judges the directory holding it, and pins the expected uid to `${EUID}` rather than reading it from `stat` of the home. A directory the lane merely TRAVERSES is excused the mode rule alone, and only where it carries `S_ISVTX` and every entry the walk enters inside it already exists and is owned by root or the service account -- which keeps a deployment under /tmp installable without trusting /tmp -- while a directory whose CONTENTS the lane enumerates is never excused, because `S_ISVTX` does not restrict creating a previously absent drop-in -- and every path that does not yet exist sits in a directory carrying that same property so it cannot be created either; symlinked components are judged through the link with the resolved target's own chain joined to the walk; the invariant is re-established inside an exclusive transition lock for upgrade and rollback, and the transition REFUSES where it cannot be established -- but `mcloving-install` establishes it BEFORE it acquires that lock, and `mcloving-env-guard` re-walks ancestors at every `ExecStartPre` holding no lock at all, so a concurrent transition can change what install inspected between the check and the lock; taking the install verdict inside mutual exclusion is PENDING under `DEPLOY-003` and must not be credited as a current mitigation. The service manager is asked for part of its own state today -- `systemctl --user show -p UnitPath`, `-p LoadState`, `-p UnitFileState`, `-p FragmentPath`, and `-p ExecMainPID` with `/proc/PID/environ` -- and where the manager does not serve the target home -- the common `--no-systemd` and test path -- the answer is DERIVED, which THREE of seven hybrid sites label as derived and four do not: `deployment_effective_cache_root`, `deployment_effective_data_root` (which feeds the O1 load-path derivation), the quadlet branch of `deployment_effective_unit_file`, and `require_unit_hook_stripping`, whose fallback has DIFFERENT SEMANTICS rather than being an approximation. Until those four are labelled -- PENDING under `DEPLOY-003` -- an evidence consumer can mistake an unannounced modelled answer for manager-reported state. **PENDING, NOT YET IMPLEMENTED, and not creditable as evidence by any pre-canary or pre-cutover review until `DEPLOY-003` lands:** querying `-p DropInPaths`, `-p Exec*` and `-p EnvironmentFiles` rather than re-deriving drop-in enumeration, unit grammar and `Exec*` parsing in shell; and judging the whole UNION of locations the load path could serve a fragment or drop-in from so that precedence, replacement, masking and XDG ordering stop being load-bearing. Until then those four obligations are modelled, the derived model is the security-critical path, and the residual risk column applies. Pre-`main()` execution hooks are removed at the unit boundary by `UnsetEnvironment=` and `PATH` is pinned to a fixed trusted value by three independent layers -- unit directive, absolute interpreter shebangs, and a default-deny contract allowlist -- because `EnvironmentFile=` overrides `Environment=` regardless of declaration order on systemd 255 | `deploy/test-deployment.sh` drives install, health, upgrade, rollback and digest re-read end to end without root and runs as the `Deployment lane` job on every pull request; 600 named refusal sites (`rg -c '^\s*exit 1'` at this head), covering group- and world-writable and foreign-owned ancestors, symlinked components and their resolved chains, non-existent-path creation bounds, contract mode and ownership, unit-source parseability, declared-variable default-deny including a refused `PATH`, and hook-stripping reset refusal; the manager-reported load-path union was measured judgeable in 2.6 ms over 43 nodes on systemd 255, which is what makes the pending union check affordable on every transition -- that measurement is a feasibility result for `DEPLOY-003`, NOT evidence of a control now in place; **and only about 20 of them (3.3%) exercise a real manager query, because every ask is gated on the manager serving the target home while the suite installs into `mktemp -d` trees, so the suite currently specifies the DERIVED path** -- closing that gap is `DEPLOY-003`'s first task; boundary decision and per-obligation determinations in `docs/architecture/DEPLOYMENT_TRUST_BOUNDARY_V1.md`, closure receipt in `docs/evidence/DEPLOY-001_SECURITY_REVIEW.md`; the walk above the deployment home, its component-by-component resolution, the `lstat` rule for symlink inodes and the scoped sticky exemption were verified by `DEPLOY-004`, whose closure receipt is `docs/evidence/DEPLOY-004_SECURITY_REVIEW.md` and whose twelve gates in `deploy/test-deployment.sh` carry ten of twelve fixtures measured against five library baselines, counting a refusal only where it names its own offender, since six of those twelve fixtures refuse on the pre-ticket library for a wholly unrelated reason | DEPLOY/SEC | Trusted Linux kernel, root, and the host's own directory configuration -- the lane refuses to install onto a misconfigured host but cannot repair one; no TOCTOU-freeness, the guarantee is the containing-directory bound rather than the instant of the check; the deployment layout, unit files, helper scripts and release identity are world-readable by design and only the secret class is confidential; namespace-based systemd enforcement is silently unavailable under a user manager on Ubuntu 24.04+ at default settings, so no filesystem hardening directive may be relied on without a runtime proof it is in effect; and nothing here bounds the SERVICE ACCOUNT itself -- a submitted workload runs as that account and owns every contract, the mTLS private key, and the release and helper trees, so release-identity verification detects corruption, partial writes and in-place substitution but is not a defence against a compromised service user. That boundary is `SEC-005`, and until it ships the right to submit a pipeline equals the right to read that host's deployment credentials |
| TM-051 | A pipeline bypasses the certified connector through a native process, supplies its own endpoint or credential, dispatches before durable intent/grant state, substitutes the observer's pre-action predecessor, loses ambiguity or evidence-completion authority across lease loss or restart, accepts a substituted connector/observer outcome, duplicates an effect, or releases downstream work before independent observation and shadow replay are durable | Typed connector-intent IR with no arbitrary command, endpoint, or credential fields; controller-owned fenced state machine; immutable deployment-selected EXT-001/OBS-001 identities and configuration; four pairwise-distinct signing roles; durable prepared/applied/uncertain/confirmed transitions in PostgreSQL; fresh one-action grant and runtime freeze before dispatch; exact frozen-predecessor validation before dispatch; fail-closed ambiguity and write-once receipt completion only while the exact effect is explicitly fenced for reconciliation without an execution lease; exact signed outcome/observer/shadow joins before downstream release; native-process network, credential, and connector-RPC denial | Canonical/mutation tests; real-PostgreSQL frozen-predecessor, restore-epoch substitution, no-lease receipt-completion, lease-loss, cancellation, crash-point, restart, duplicate-delivery, timeout, configuration-drift, response-substitution, reconciliation, and zero-duplicate-effect integration tests; effect-free Mario fixture rehearsal; architecture contract in `docs/architecture/RUNTIME_EFFECT_INTEGRATION_V1.md` | CTRL/AGENT/EXT/MIG/SEC | Trusted controller/deployment operator, database, signing authorities, connector, observer, shadow replayer, and external destination remain in the TCB. No production action is authorized by EXT-002; the first action still requires complete CANARY-001 gates and fresh owner authority |
| TM-052 | Branch protection accepts a partial, skipped, cancelled, stale, or spoofable check set; a Foundation child or required Windows lane reports failure without blocking merge; classifier failure or missing output becomes an implicit Windows waiver; or a workflow edit silently omits a child from aggregation | Stable `Foundation` aggregate with `if: always()` and literal-success checks over every reported terminal Foundation job conclusion; stable `Windows` aggregate enforcing the exact successful-classification/executed-or-explicitly-skipped truth table; six granular Foundation checks plus exact GitHub-Actions-bound `Foundation` and `Windows` aggregates; strict branch synchronization; admin enforcement and conversation resolution; one shared fail-closed verifier; exact aggregate-job schema and fail-open mutation tests; version- and digest-verified hosted actionlint; independent exact-head source review | Exhaustive 390,625-state Foundation decision test; complete Windows result matrix; malformed, missing, duplicate, and unexpected-field denial; exact workflow membership, dependency, `always()`, environment, and invocation assertions; actionlint; before/after live protection documents; exact-head and protected-main aggregate runs; closure review in `docs/evidence/CI-003_SECURITY_REVIEW.md` | FOUND/SEC | GitHub and GitHub Actions control-plane compromise; an authorized writer weakening candidate-controlled merge-authority workflows, classifier, verifier, or their oracles, including skipping or softening a child step before GitHub computes its job conclusion; or an authorized administrator mutating external protection settings. App binding authenticates the reporter, not its workflow definition; this single-member repository cannot enforce a second human approval without deadlocking owner-authored changes, so authority-sensitive merges must re-read the live rule and independently review every exact merge-authority workflow, classifier, verifier, and oracle change |
| TM-053 | An interface claim closes against a check that cannot observe what it asserts: console cleanliness, rendered layout, focus behaviour or accessible structure asserted by reading served HTML as text, or validation asserted against a fixture whose validator always accepts | Executing browser gate over a pinned, digest-verified engine in a contained namespace; the assertion count is pinned and a mismatch fails; every assertion is mutation-proved to turn a named test red; the strict-YAML refusal is driven through the production compiler rather than a stubbed verdict; the pre-repair baseline is retained so a repaired successor cannot be read as the original passing | `scripts/test-ui-browser.sh` and `scripts/test-ui-browser-mutations.py` in the `ui-browser` Foundation lane, scoped by `scripts/ui-browser-impact.py` and admitted by `require_foundation` only as an executed success or a literal classified skip, never an implicit one (TM-052); `scripts/verify-ui-browser-gate.py` runs unconditionally and refuses drift between the pinned count, the emitted assertions, the mutation set and the paths the classifier watches | UX/CTRL | One rendering engine is the whole population; assistive-technology announcement is not observed and is recorded as a manual convention rather than a gate |
| TM-054 | A build notification credential acts outside its mapping: a pipeline steers the GitHub token to another repository or the signing key to an internal or attacker-chosen destination through a name that resolves privately, a redirect or a rebinding between attempts; or a terminal outcome is delivered never, twice, or by two controllers at once | Deployment-owned digest-pinned mapping catalog resolved at admission (kind, organization, project, repository or destination), the pipeline naming only a mapping id and the resolved target recorded with the build; resolve-check-bind on every attempt against the loopback, private, link-local, shared, benchmarking, documentation, multicast, reserved and IPv6 embedded ranges with the connection pinned to the checked addresses, no redirects, no proxy; ledger rows written in the terminal transaction, claimed `FOR UPDATE SKIP LOCKED` under a lease past the delivery deadline, backoff scheduled at settlement, settled by attempt count, bounded attempts | `crates/controller-api/tests/notifications.rs`, `crates/controller-api/src/notifications.rs` unit tests, `postgres_truth` terminal-ledger test, PAR-004 HeMan proof | CTRL/SEC | Network routes a public address privately after the check; system roots trusted; a pipeline reports on any commit of its mapping's repository |
| TM-021 | Malformed protocol message crashes controller or agent | Protobuf contract and fail-closed major/minor negotiation; message bounds at transport integration | Version/range tests now; protocol fuzzing and oversize E2E next | AGENT/CTRL | Runtime-library vulnerability |
| TM-022 | Audit history is silently altered | Append-only API, hash segments, external export | Mutation denial and export verification | SEC/OPS | DB and external sink collusion |
| TM-023 | Unauthorized tool version enters validation or release | Versioned downloads, SHA-256 verification, OCI digests | Empty-cache validation and manifest check | FOUND/REL | Compromised upstream plus digest update |
| TM-024 | UI or CLI hides uncertain or degraded state | Server-authoritative typed states and explicit gaps | User-journey and API contract tests | UX/CTRL | Client compromise |
| TM-025 | Mixed-epoch, tampered, incomplete, stale, or secret-bearing Jenkins inventory is admitted as migration truth | Four typed strict-YAML families, byte-identical snapshot binding, detached SHA-256 sealing, mandatory owner-trusted external digest over both the complete binding and four-manifest filename/content-digest map at reconciliation/verification, independently sourced controller/direct-child/principal/ACL/client, per-job dependency/state-class, and per-state-class instance counts; every count/set commitment domain-separated and bound to the complete snapshot binding (controller/core/plugin/global configuration, collection time, exporter identity/version/content, and provenance) plus applicable owner identity; complete deterministic job, security-realm, principal, ACL, client, runtime-dependency, and state-record semantic commitments with distinct empty-group bindings; closed canonical runtime-dependency taxonomy whose credential/secret-parameter kinds force typed secret reference and consumer/taint evidence; mandatory runtime and state coverage for every job including retired jobs; referential and coverage reconciliation; exactly-once typed compatibility evidence for every declared library/trigger/platform/agent/toolchain requirement; workload-visible secrets forced unsupported; forward/rollback state-transform classification; create-new publication; and no execution authority | Digest tamper, strict-YAML alias, mixed-epoch, complete stale-bundle or same-binding semantic replay, cross-epoch or cross-configuration subgroup replay, stale semantic payload replay, unknown identity or dependency kind, secret-kind confidentiality downgrade, population omission and count mismatch, dependent count/set collector, same-cardinality identity, cross-domain empty-evidence replay, parent-edge, job-scope/owner/operational-state, principal lifecycle/mapping, ACL-permission/generation, client-contract, dependency-owner, state-owner, or state-instance-count substitution, retired/out-of-scope runtime or state omission, understated state instances, missing/duplicate/undeclared requirement evidence, incomplete coverage, unclassified secret/state behavior, workload-visible-secret downgrade, and secret-reference negative tests | COMPAT/SEC/OPS | Compromised trusted snapshot coordination state, Jenkins administrator/exporter, or false owner attestation |

## DEPLOY-003 threat-model closure amendment

The `PENDING under DEPLOY-003` clauses in TM-050 above are historical inputs
to the ticket and are superseded by this amendment and
`docs/evidence/DEPLOY-003_SECURITY_REVIEW.md`. Service-managed transitions now
obtain typed composed unit facts from the user manager, consume mask/load
answers directly, validate the complete manager `UnitPath` fragment union and
independent Quadlet source union, and label every derived fallback. Install
repeats the complete integrity verdict under the exclusive transition lock and
again after `daemon-reload`. Service-environment capture pins the process with
a pidfd and an opened `/proc/<pid>` directory, verifies control-group
membership, and rechecks the manager invocation/PID/control-group tuple after
copying directly from the held descriptor.
Typed manager facts are supplemented by source-side classification where
Quadlet's generated Podman argv loses the original policy class: `Volume=`
contributes the real host ancestor, and `[Container] EnvironmentFile=`
contributes an owner-only, default-deny environment contract, including from
standalone recursive Quadlet drop-ins. Quadlet's relative `EnvironmentFile=`
grammar is refused by source and value because the retained parser models only
absolute contract paths; that refusal applies in manager and derived/offline
modes, is limited to `[Container]`, and treats a leading dash as Quadlet does
rather than importing systemd's optional-file syntax. No accepted Quadlet
spelling is silently omitted.
The protected deployment job proves this path under a disposable account with
controlled unit and generator inputs. The generator is selected only from the
version-matched `/usr` distro layout or image-provided `/usr/local` hosted
bundle, with its exact target, ownership, modes, and version checked and its
hashes recorded without invoking Podman before the generated volume unit;
known root-owned writable package ancestors on the disposable hosted image are
normalized on the exact `/usr/share` and `/usr/local` input chains before that
unchanged validator runs, together with only the two expected regular static
bundle executables after their image-provider digests match reviewed pins, while
any symlink, foreign owner, or new drift is refused;
the short-lived service account receives only a temporary search bit on the
exact owner/mode-checked hosted runner home needed to reach its inputs, and the
job restores the original mode on every exit path;
the disposable manager receives exact account-local HOME/XDG and identity
values while every account command starts from an empty environment through a
direct UID/GID transition that cannot re-import variables through PAM; the
disposable manager's drop-in also replaces `ExecStart` with a direct
`/usr/bin/env -i` invocation carrying the exact block plus systemd's expanded
notify socket, with no shell or inherited executable lookup before the clear;
its PATH is required to equal the manager's compiled default so generator input
does not change when systemd normalizes it; every installed user
environment-generator basename is masked before startup so manager reloads
cannot repopulate host variables; the account is created without a skeleton
home, then its empty disposable home has inherited access and default ACLs
removed and its exact 0755 three-entry ACL proved before any account-owned child
is created; before
D-Bus starts, the manager's private socket is used to install and prove an
exact fourteen-entry identity/path/locale/unit/Quadlet/D-Bus allowlist so the
daemon inherits only that block; the typed manager environment is then
atomically replaced over D-Bus and read back by exact count and value before
the cold Podman operation;
property-labelled typed manager command-tuple facts then bind every generated
start and present stop command to that selected Podman executable, whose
version is compared with Quadlet after cold start; runtime and administrator
overrides and mixed
vendor layouts are refused. It requires
and kernel-proves
`NoNewPrivileges=yes` on the controller, agent, and database-init services,
while deliberately requiring it absent on the two generated Podman services:
an implementation-time fresh-account probe measured the bit preventing
rootless `newuidmap`/`newgidmap`
namespace creation. The generated volume unit performs the fresh account's
first Podman operation, and the complete cold rootless lifecycle passes.

The typed systemd 255 `ExecStart` tuple was measured not to resolve a bare
executable. The lane therefore retains the named non-absolute refusal instead
of guessing the manager's internal search path. Two residuals remain explicit:
the point-in-time ancestor check is not TOCTOU-free, and a service-owned unit
cannot make its own start-time verifier mandatory. `DEPLOY-002` now owns the
external trust anchor required to detect unit, guard, selected-release, and
permission drift on ordinary or crash restart. Until it closes, transition
integrity is proved but restart-time integrity after drift is not, and no
production qualification may claim otherwise. Workload authority over the
service account remains the separate `SEC-005` boundary.

## DIFF-002 threat-model closure review

Reviewed: 2026-08-14
Reviewer: McLoving security architecture, with independent exact-head review on
PR #56
Binding: exact implementation `f0b3f6dced45f33e9ef6d0ea88af013912cb76bd`,
protected-main merge `5e02566ac3f76d8261b6578f71ccb438bd51bda3`, and
receipt manifest
`10fbbaed1d819ad9ec6962710de3f557e35c834fb6741f7cb08b085526a81786`.

The closure review changed TM-030 for the identity/authorization differential,
changed TM-038 for operational-state and disabled-ingress parity, and added
TM-043 for the persistent-history, retention, hold, approval, retry, restart,
and reverse-reconciliation boundary.

The following affected threats were reviewed with no change required:

- TM-027 and TM-028: DIFF-002 reuses and differentially checks immutable
  identity, rename, deletion/reuse, lifecycle, and group-generation semantics;
  it does not change OIDC protocol, token/session validation, service-credential
  rotation, or migration-administration controls. Their existing IDP receipts
  remain authoritative, while TM-030 carries the new differential evidence.
- TM-005, TM-014, TM-017, TM-019, TM-022, and TM-025: the accepted fixture
  compares restart truth, artifact digests, reverse reconciliation, approval
  identity/value/expiry, audit implementation identity, and exact prerequisite
  inventory/state-transform bindings. It does not replace the outbox, artifact
  storage, catastrophic restore epoch, stale-approval binding, audit export, or
  four-manifest inventory controls already recorded by those threats. TM-043
  carries the new cross-system persistent-history differential and its scoped
  residual risk.

No reviewed threat-model change grants production identity, data, trigger,
scheduler, credential, effect, canary, cutover, rollback, or decommission
authority. Live population mapping and case-specific rehearsals remain later
pre-authority gates as stated in TM-030 and TM-043.

For TM-037, config v5 adds an independently enforced `max_runtime_history`
quota: a new cutover or rollback generation cannot grow the durable ancestry
table past its certified bound, while an exact-generation restart remains
available. Request sizing also uses the signed cursor range the ledger can
persist and the accepted compact syntax of all six request UUIDs; response sizing
accounts for the same accepted compact UUID syntax. Successfully parsed error
envelopes receive the complete reversible-encoding marker scan on every typed
field except the opaque destination signature, closing retry-based disclosure
through otherwise valid non-200 bodies.

`WIN-002` threat-model review closes TM-007 for the supported Windows agent
lifecycle: explicit mode admission cannot infer a shell, every child starts in
an atomic kill-on-close Job Object, cancellation and service crash leave no
descendant, and the workspace root ACL grants only `SYSTEM` and Administrators.
The accepted residual risk is unchanged: Job Objects and ACL ownership are not
a hostile multi-tenant isolation boundary. The deployment owner must use a VM
or equivalent boundary before admitting mutually untrusted Windows workloads.
`WIN-003` supplied the signed-package interruption and graceful-reboot evidence;
abrupt-power-loss directory-entry durability remains unclaimed.

## REL-001 threat-model closure review

Reviewed: 2026-08-15
Reviewer: McLoving security architecture
Binding: protected-main implementation `8d2519afcf29a82fa813fcddc8e131ddb7e83935`,
release UUID `3d38cc2c-a88b-4fac-aae2-7d9459c36ee5`, and retained evidence-package
manifest `094276689d6cec9fbb63b1abd51f5b9a3f9b588c52e32be5e264fb20822af237`.

The closure review updates TM-042 from an implementation-only state to a
verified private-release-provenance claim. The exact protected source and
builder receipts, primary signature, public Rekor secondary attestation,
canonical evidence-manifest join, independently verified RFC 3161 anchor, and
final verifier receipt are bound together. The HeMan signing directory is mode
`0700`; both private keys are owner-only, mode `0600`, single-link files. The
retained package's private-key marker and hard-link scans are clean.

TM-016 and TM-023 were reviewed with no mitigation change. Their lockfile,
digest-pinned image/action, checksummed tool, and protected-policy controls are
now exercised by the REL-001 exact-head builder and ceremony evidence. Their
residual upstream-plus-approved-digest compromise remains unchanged.

The verified receipt is intentionally scoped to
`private-release-verification` and binds a context that states no binary
placement occurred. Production deployment, canary and cutover authority,
public binary publication, and the later release-readiness decision remain
separate gates.

## DIFF-003 threat-model closure review

Reviewed: 2026-08-15
Reviewer: McLoving security architecture
Binding: the exact final reviewed PR head/tree and independently rechecked
receipt metadata came from the unchanged exact-head HeMan run. Committing those
values in PR #59 would have changed its reviewed tree, so PR #60 copies the
already accepted head, tree, evidence-manifest, and receipt-authentication
public-key digests into the repository only after PR #59 merged and protected
main passed. This post-merge audit index does not alter or replace the accepted
PR #59 source binding.

The closure review adds TM-044 for the cross-component external-boundary
differential: a static certificate alone is insufficient. The accepted gate
executes the exact 15-suite ledger, Ed25519-authenticates 13 actual public
boundary receipts, derives all 48 outcomes from completed test assertions, and
compares every compatibility projection from both live receipts in all 11
joins. The contained client retains
Jenkins source authority; the target side reports zero production mappings,
production effects, duplicate effects, production cutover claims, and marker
disclosures.

TM-010, TM-037, TM-039, TM-040, TM-041, and TM-042 were reviewed with no
mitigation change. Their connector ambiguity, independent observation, trigger,
discovery, credential, and provenance controls are exercised or compared by the
new boundary gate, but remain authoritative within their existing scopes.
TM-016, TM-023, TM-025, TM-030, TM-038, and TM-043 were also reviewed with no
mitigation change: DIFF-003 binds exact sources and prerequisite evidence, but
does not replace dependency locking, tool pinning, inventory reconciliation,
authorization, operational-state, or persistent-history migration controls.

No reviewed threat-model change grants production identity, data, trigger,
scheduler, credential, effect, deployment, canary, cutover, rollback, or
decommission authority. Live inventory reconciliation, migration packaging,
shadow replay, per-job canary, and later authority gates remain mandatory.

### ALPHA-001 Mario product-demo review

Reviewed: 2026-08-16

ALPHA-001 exposes no new production boundary. Its operator script refuses any
host other than Mario, requires a clean exact source head, uses digest-pinned
build and PostgreSQL images, assigns a unique loopback-only database container
and random ports, and removes only that exact container. It never addresses or
mutates Mario's existing `jenkins-oracle-228` or `chengis-canary` containers.
Fresh high-entropy API and artifact-agent credentials remain only in process
environment, are never written to evidence, and the retained run directory is
created owner-only. The controller starts from an explicit allowlisted
environment, so ambient optional `MCLOVING_*` configuration cannot enable an
extra listener or partially configure an identity provider. Fixed workload
commands emit public markers and have no network, credential, Jenkins,
connector, trigger, or external-effect authority.

The demo's claims are bounded to native product usability, durable execution,
public API/CLI/UI observability, controller restart, and idempotent submission.
It does not prove hostile multi-tenant deployment, production secret handling,
Jenkins compatibility, or authority transfer. Existing TM-002, TM-005, TM-006,
TM-014, TM-016, TM-023, TM-025, and TM-030 mitigations remain unchanged; the
acceptance run directly exercises their applicable authentication, persistence,
execution, supply-chain, audit, and operational-state surfaces without waiving
their production residual risks.

### EXT-002 Mario runtime-effect review

Reviewed: 2026-08-18

The bundle-backed rehearsal at head
`6f737080cf7546e1982fd45c2283663d941f4448` exercises TM-051's complete
real-PostgreSQL effect spine — 17 tests at that head — on a fresh
internal-only network. The branch has since advanced past `6f73708` with,
among other changes, the independent-review fixes; the owner-only rehearsal
was not re-run at the final head, whose grown 24-test real-spine suite passed
the complete local pinned-container PostgreSQL gate instead. The
connector, independent observer, and deny-authority shadow fixture remain
process-isolated with pairwise-distinct signing roles. Exact source, fixture,
and test-binary digests are retained owner-only, every manifest entry was
independently recomputed, and teardown left neither the exact database
container nor network. Result receipt SHA-256
`733f870961474d0be581d9aba46b244a0fc767b4c680bd4aac96c115d39163ac`
records zero production endpoint, credential, effect, canary, or cutover
authority.

The preceding truthful `complete:false` receipt exposed a host-harness race in
which PostgreSQL's temporary initialization server could satisfy
`pg_isready` immediately before its intentional restart. The corrected gate
also requires the pinned container's PID 1 to be the final `postgres` server,
so evidence publication cannot treat temporary initialization readiness as
runtime readiness. This correction changes no product effect authority. The
first production action remains separately gated by complete `CANARY-001`
inputs and a fresh explicit one-action owner grant.

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
| Repository merge authority | CI-003 |
| External-boundary differential and non-collusion | DIFF-003 |
| Jenkins inventory integrity and reconciliation | INV-001 / INV-002 / INV-003 / INV-004 / MIG-000 |
| Human and service authentication lifecycle | IDP-001 |
| Jenkins authorization mapping lifecycle | AUTHZ-001 |
| External runtime input capture and replay | INPUT-001 |
| Dynamic-agent provisioning and cleanup | PROV-001 |
| Workload dependency resolution and provenance | DEP-001 |
| Independent destination-state observation | OBS-001 |
| Pipeline operational-state authority | JOBSTATE-001 |
| Typed authenticated trigger ingress | TRIG-001 |
| Multibranch and organization-folder discovery | DISC-001 |
| Deny-authority production shadow qualification | SHADOW-001 |

## CI-004 smoke-fixture implementation review

CI-004 implementation acceptance is complete at exact corrected head
`3880043226f54b35984defc0d09957e5ff1d26ac`, independently reviewed and verified
by full Foundation and classified Windows gates. The review and evidence are
in `docs/evidence/CI-004_SECURITY_REVIEW.md`. TM-050 and TM-052 retain every
existing deployment-integrity assertion and merge-authority condition. The
failed precursor is retained: systemd fixture transformation was removed, and
the original exact byte-identity oracle then passed with both runtime tests.
TM-016 and TM-023 retain the explicit host-binutils trust residual for the
smoke harness's unpinned `strip` executable; CI maintainers own that fixture
trust assumption. TM-042's production release/signing boundary is unchanged.
Final reviewed head `7ff7d726632cb1f0ee128b78a5cb92ec5432839a` passed all
protected checks and resolved its premature-closure review item before PR #125
merged as `1d81127c7913a92a43402e377eb62289897356e0`. Exact post-merge
Foundation `34293282546` and native Windows Agent `34293282632` passed.
CI-004 now closes on those observed receipts; no production authority is granted.

## JCOMP-001 preregistered contract review

The syntax/profile/fixture and comparison contract is reviewed in
`docs/evidence/JCOMP-001_SECURITY_REVIEW.md`. TM-008's compiler resource bounds
and TM-020's isolated, parse-only worker and independent Rust admission remain
unchanged; future generalized admission must independently bind source semantics
to output. This change adds repository-owned expectation data and a read-only
Groovy CONVERSION authoring check, not a new untrusted-input execution service.
The contract separates authored fixtures from the 228-source historical corpus
and permits no model output or local authoring result to become Jenkins evidence.

TM-052's protected checks remain mandatory. Local and hosted Foundation both
run the shared fixture gate, whose fixed 17-test population rejects missing,
zero, skipped, and incomplete execution; independent negative controls passed.
JCOMP-001 closes in this subsequent update after PR #127 merged as
`533dbff671b5a2d58e4d92339708375601d5b7d2` and exact-main Foundation
`34306662841` and native Windows `34306662842` passed. The review receipt
records final head `f78dc5d` and resolution of all three actionable threads. The contract's dedicated disposable M1 environments grant no production
containment claim; hostile same-UID workload isolation remains SEC-005.

## JCOMP-002 sequential compiler review

JCOMP-002 adds the explicit internal protocol-v2 compiler and Rust admission
boundary described in `docs/architecture/JENKINS_SEQUENTIAL_COMPILER_V2.md`.
TM-008 retains source, response, process and container resource bounds. TM-020
now requires independent recognition of original source semantics, exact
canonical lowering and typed IR checks, caller context binding, and a separate
disabled logical-definition artifact. Existing v1 admission and imported job
state remain unchanged. Groovy is parsed but never evaluated.

The launcher snapshots source and context once, uses a private copy of the
admission executable, and launches a caller-pinned immutable worker image.
Trusted receipts bind both implementation digests outside the worker. Failed
or disagreeing classifications cannot become corpus coverage. The contained
compiler campaign executes no workload shell and contacts no controller or
agent. Runtime execution, workspace continuity and paired evidence remain
separate successor tickets; hostile same-UID isolation remains SEC-005.

TM-052's local and hosted Foundation gates include the closed Clojure and
mocked-launcher suites; Rust boundary and CLI tests remain in workspace CI.
The completed review is `docs/evidence/JCOMP-002_SECURITY_REVIEW.md`. This
subsequent update records closure after PR #128 merged as `904fd1f`, with tree
`26240208f51f6028bf6bb6e619a2dcd5d19555f0` matching final reviewed head
`3d9ca5f`, and exact-main Foundation `34317917356` and native Windows
`34317917395` succeeded. Receipt and retained-evidence review confirm the
compile-only boundary and residuals above; no runtime claim is added.

## JCOMP-002A contained sequential execution review

The completed receipt in `docs/evidence/JCOMP-002A_SECURITY_REVIEW.md` reviews the
authority-free planner, validated immutable layout, atomic saved-digest-bound
admission/replay, coherent result projection and sequential lease-expiry rule.
Affected boundaries are TM-001, TM-003, TM-005, TM-006, TM-007, TM-008, TM-009,
TM-011, TM-016, TM-017, TM-018, TM-022, TM-023, TM-024, TM-026, TM-038 and
TM-052. The architecture and receipt state the required evidence and residuals.
Actual shell freshness, failure/skipping, cancellation and replay are tested in
disposable fixtures; workspace continuity remains JCOMP-002B, hostile same-UID
isolation SEC-005 and paired Jenkins execution JCOMP-003. JCOMP-002A closes
after independent review and protected PR #130 merge `c2aaa0d`, whose tree
`77bc88fa006123ab72ae497334c1733dc0ac749b` matches final head `d7be0f7`.
All eight final-head app-bound checks passed; exact-main Foundation
`34351767851` and actual native Windows `34351767843` succeeded. The receipt
records the bounded independent audit and retained-source/evidence bindings.

## JCOMP-002B contained workspace transfer review (completed)

The candidate design `docs/architecture/BUILD_WORKSPACE_TRANSFER_V1.md` and
completed record `docs/evidence/JCOMP-002B_SECURITY_REVIEW.md` cover the new
internal checkpoint-transfer mode. A controller-owned unique build namespace,
monotonic generation, typed bounded snapshot and digest bind the input to each
fresh attempt workspace. Completion must retain existing session/restore/fence
authority, compare current checkpoint ownership, and atomically publish output
before successor readiness. Exact replay compares content and metadata receipts
without retaining raw bytes in terminal history. Terminal cleanup closes the
namespace and removes the controller checkpoint; uncertain StartWork remains
reconciliation-required. Manual retries are refused for this mode.

Affected boundaries are TM-001, TM-003, TM-005, TM-006, TM-007, TM-008, TM-009,
TM-011, TM-016, TM-017, TM-018, TM-022, TM-023, TM-024, TM-038 and TM-052.
Focused unit and PostgreSQL observations are recorded separately from the
source-qualified actual shipped-runtime campaigns and final exact-main verification. The transfer byte bounds do
not impose a production filesystem quota, ordinary file transfer cannot identify
workload-written secrets, and hostile same-UID sibling access remains SEC-005.
JCOMP-003 retains paired Jenkins and original-corpus claims. JCOMP-002B closes
only contained transfer implementation on the exact-source receipts; no production authority is granted.

## AGENT-007 bounded renewal outage review (completed)

`docs/evidence/AGENT-007_SECURITY_REVIEW.md` records the corrected-source review and closure evidence for TM-003 and the existing cancellation/reconciliation boundaries. Unanswered renewal replies preserve only already-held authority; answered refusals still cancel immediately, and validated request-start anchored receipts alone advance the term. The response allowance is fixed per renewal cycle to the smaller of one second and half the initially remaining cancellation budget; retry cadence is capped by that fixed allowance, and each ask remains bounded by the held deadline, which reserves configured termination grace and a margin. Actual controller/agent gates and native Windows execution support the bounded implementation claim. No protocol or fencing authority changes. Host scheduling and process-supervision assumptions, hostile same-UID containment under SEC-005, agent-death recovery and JCOMP-003 paired evidence remain outside this closure. Existing threat rows were reviewed and need no semantic change because their ownership and enforcement boundaries are unchanged.

## JCOMP-002C negative diagnostic correction (earned closure)

`docs/evidence/JCOMP-002C_SECURITY_REVIEW.md` records the six original-source compiler/admission disagreements and the bounded correction acceptance for TM-008 and TM-020. Independent negative diagnostic agreement must be earned from original bytes; unknown or unproved forms remain unverified. Lexical exclusion does not certify whole-source Groovy validity. Potentially admitted documents still require full parsing, bounded lexical/AST agreement and independent Rust output validation. The correction adds no runnable syntax, runtime effect or production authority. Independent review of exact candidate `2326a63` verified the bounded source change, build pins, 46 preregistered fixture admission replays and all 228 historical corpus classifications (1 admitted, 216 unsupported, 11 rejected, zero unverified; 226 exact originals plus two retained redacted representations). Ten reduced regressions and two failing mutations support the diagnostic boundary. The retained security review qualifies the tested source and bounded public evidence. Final corrected source c94d232 earned closure on signed PR #135 merge `01137b54b8fbefdc0deb0214a5d4d8979a773575` and successful exact-main Foundation 34450761533 / native Windows 34450761576, both attempt 1. The linked security review separates this corrected evidence from historical 2326 observations.

## JCOMP-003 contained paired evidence (earned closure)

[The JCOMP-003 review](../evidence/JCOMP-003_SECURITY_REVIEW.md) attributes review of existing compiler/admission, execution ordering, lease and workspace boundaries to the exact f263ad4 runtime and fresh contained observations. Independent source/build/input/boundary and corpus reviews, graph-linked stage-body verification, exact shell/log comparison, workspace inventories and owned-container cleanup support the bounded fixture result. Network-none Jenkins and product containment, disabled imported definitions and explicit contained submissions preserve authority boundaries. The 228-source compiler classification remains separate from the 11 positive paired executions. Host/container and observer trust assumptions remain; no production eligibility or hostile same-UID isolation is claimed. Protected PR #136 merge and exact-main Foundation/native Windows verification earned closure; exact identities remain in the JCOMP-003 security review and byte-preserved post-merge receipt.

JCOMP-003 reviewed TM-008 and TM-020 (bounded parse-only compilation and independent admission), TM-009 (explicit negative outcomes), and the existing sequential-execution/workspace boundaries attributed to JCOMP-002A and JCOMP-002B above. Those mitigations and threat-row semantics remain unchanged: this campaign exercises the pinned implementation through contained submissions and does not add runtime authority. The zero-work negatives, paired stage/step, stream and workspace observations, source-bound retention verification and exact-main receipts provide the evidence for this review. Existing lease, restart and isolation guarantees continue to rely on their predecessor receipts; the fixture campaign does not replace their fault-injection coverage.

## Closure attribution

Machine-readable, and read by `scripts/verify-ticket-closure-receipts.py` as the
ONLY thing that attributes a threat-model review to a closed ticket. Two columns:
a ticket id, and the path to the document that records the review. Both are
matched whole, so neither cell can hold a sentence -- which is the point, because
every previous version of this rule inferred attribution from English and every
one of them was defeated by a denial written in an affirmative shape.

**This table is not the review.** The register above is, and the prose there is
still where a reader learns what was examined and what risk remains. This table
only records, in a form a program can check, that the review happened and where
its evidence lives.

**Do not add a row for a ticket whose evidence you have not read.** A row here is
an assertion that a specific document records a specific ticket's review. The
table it replaced was `Area | First implementation ticket`, which asserts who
BUILT an area -- and the gate read that as a review for twenty-five tickets that
had never claimed one.

| Ticket | Evidence |
|---|---|
| ADMIN-001 | `docs/evidence/ADMIN-001_SECURITY_REVIEW.md` |
| AUTHZ-001 | `docs/evidence/AUTHZ-001_SECURITY_REVIEW.md` |
| CANARY-000 | `docs/evidence/CANARY-000_SECURITY_REVIEW.md` |
| CI-002 | `docs/evidence/CI-002_SECURITY_REVIEW.md` |
| CI-003 | `docs/evidence/CI-003_SECURITY_REVIEW.md` |
| CI-004 | `docs/evidence/CI-004_SECURITY_REVIEW.md` |
| CONSUMER-001 | `docs/evidence/CONSUMER-001_SECURITY_REVIEW.md` |
| DEP-001 | `docs/evidence/DEP-001_SECURITY_REVIEW.md` |
| DEPLOY-001 | `docs/evidence/DEPLOY-001_SYSTEMD_LANE.md` |
| DEPLOY-003 | `docs/evidence/DEPLOY-003_SECURITY_REVIEW.md` |
| DEPLOY-004 | `docs/evidence/DEPLOY-004_SECURITY_REVIEW.md` |
| DIFF-002 | `docs/architecture/STATE_POLICY_DIFFERENTIAL_V1.md` |
| DIFF-003 | `docs/evidence/DIFF-003_SECURITY_REVIEW.md` |
| DISC-001 | `docs/evidence/DISC-001_SECURITY_REVIEW.md` |
| EXT-001 | `docs/evidence/EXT-001_SECURITY_REVIEW.md` |
| EXT-002 | `docs/evidence/EXT-002_SECURITY_REVIEW.md` |
| EXEC-001 | `docs/evidence/EXEC-001_SECURITY_REVIEW.md` |
| EXEC-002 | `docs/evidence/EXEC-002_SECURITY_REVIEW.md` |
| EXEC-003 | `docs/evidence/EXEC-003_SECURITY_REVIEW.md` |
| EXEC-004 | `docs/evidence/EXEC-004_SECURITY_REVIEW.md` |
| HYG-001 | `docs/evidence/HYG-001_SECURITY_REVIEW.md` |
| HYG-002 | `docs/evidence/HYG-002_SECURITY_REVIEW.md` |
| IDP-001 | `docs/evidence/IDP-001_SECURITY_REVIEW.md` |
| INPUT-001 | `docs/evidence/INPUT-001_SECURITY_REVIEW.md` |
| JCOMP-001 | `docs/evidence/JCOMP-001_SECURITY_REVIEW.md` |
| JCOMP-002 | `docs/evidence/JCOMP-002_SECURITY_REVIEW.md` |
| JCOMP-002A | `docs/evidence/JCOMP-002A_SECURITY_REVIEW.md` |
| JCOMP-002B | `docs/evidence/JCOMP-002B_SECURITY_REVIEW.md` |
| JCOMP-002C | `docs/evidence/JCOMP-002C_SECURITY_REVIEW.md` |
| JCOMP-003 | `docs/evidence/JCOMP-003_SECURITY_REVIEW.md` |
| AGENT-007 | `docs/evidence/AGENT-007_SECURITY_REVIEW.md` |
| JOBSTATE-001 | `docs/evidence/JOBSTATE-001_SECURITY_REVIEW.md` |
| OBS-001 | `docs/evidence/OBS-001_SECURITY_REVIEW.md` |
| OUTBOX-001 | `docs/evidence/OUTBOX-001_SECURITY_REVIEW.md` |
| PROV-001 | `docs/evidence/PROV-001_SECURITY_REVIEW.md` |
| REL-001 | `docs/evidence/REL-001_RELEASE_CEREMONY.md` |
| SHADOW-001 | `docs/architecture/SHADOW_QUALIFICATION_V1.md` |
| TRIG-001 | `docs/evidence/TRIG-001_SECURITY_REVIEW.md` |
| UI-002 | `docs/evidence/UI-002_SECURITY_REVIEW.md` |
| PAR-000 | `docs/evidence/PAR-000_SECURITY_REVIEW.md` |
| PAR-010 | `docs/evidence/PAR-010_SECURITY_REVIEW.md` |
| PAR-011 | `docs/evidence/PAR-011_SECURITY_REVIEW.md` |
| PAR-012 | `docs/evidence/PAR-012_SECURITY_REVIEW.md` |
| PAR-001 | `docs/evidence/PAR-001_SECURITY_REVIEW.md` |
| PAR-013 | `docs/evidence/PAR-013_SECURITY_REVIEW.md` |
| PAR-014 | `docs/evidence/PAR-014_SECURITY_REVIEW.md` |
| PAR-004 | `docs/evidence/PAR-004_SECURITY_REVIEW.md` |
| EXEC-005 | `docs/evidence/EXEC-005_SECURITY_REVIEW.md` |

## Residual-risk policy

A ticket cannot mark a threat “eliminated” merely because a design mitigation
exists. Closure requires executable evidence. Accepted residual risk must name
the affected scope, owner, review date, and user-visible limitation.

Threat-model review is required for changes to authentication, authorization,
protocols, persistence, execution, secrets, connectors, agent pools, supply
chain, or deployment boundaries.

PR #135 follow-up review identified an earlier malformed interpolation prefix hidden by a later lexical exclusion. The bounded Clojure precheck now follows the existing independent Rust proof before entering dynamic syntax; unknown nested expressions are not guessed. Original `2326a63` receipts remain historical, and fresh exact-source evidence plus protected verification are required for the follow-up. The V2 contract and runtime authority are unchanged; no closure attribution is added.

## EXEC-005 review — bounded cache product integration (earned closure)

The cache slice reviews TM-036 and TM-012 across submitted intent, operator
mapping, controller context, sealed process and authenticated response. Closed
read/publish types exclude operator maintenance, paths, principals and trust
promotion. Exact scoped startup catalogs and a context-bound journal digest
prevent cross-pipeline/attempt/fence substitution. Pure cache admission and
receipt verification share the existing store's canonical key policy without
opening its database. Config identity is checked before state open; executable
bytes are sealed and verified through Linux `/proc/self/exe`; special-file opens
are nonblocking and refused. Every returned event is authenticated and the final
operation/key/content binding is checked. Conflict/corruption never imply success.

TM-007 and TM-011 are reviewed for the new private IO path: existing mTLS,
capability/pool matching, lease renewal/reserve, process identity journaling and
whole-group cleanup remain mandatory. Scheduling prevents incompatible claims
through exact mapping/digest/operation capabilities in
addition to the generic protocol and pool requirements. The actual mixed-agent
gate requires mismatched agents to leave the attempt unclaimed before a matching
agent completes it. Concurrent bounded input/output avoids
pipe deadlock; no request precedes durable spawn journaling. Raw output remains
memory-only until containment and successful protocol verification; failure,
overflow or incomplete input emits no raw spool. Actual post-helper/pre-result
and post-terminal crash gates distinguish unresolved operation truth from
replayable terminal evidence. No new sidecar journal or blind retry authority is
introduced. A post-helper/pre-result crash can park the agent pending operator
recovery; automatic terminal completion is not promised. Test crash hooks are absent from release builds.

The API/compiler boundary is reviewed under TM-008/TM-026: literal cache intents
use IR 1.4 and envelope 3, retain existing scalar bounds, require deployment
catalog approval and an actual pipeline scope, reject unsupported platforms and
operator forms before queueing, and do not broaden the literal-shell Jenkins
migration planner or any earlier differential claim. TM-005/TM-014/TM-051 are
reviewed unchanged for PostgreSQL durability, artifact mediation and production
effect authority: this slice creates no artifact/workspace restoration, connector
or production authority. Actual gate and residual-scope details are recorded in
`docs/architecture/CACHE_PRODUCT_PATH_V1.md` and the ACTIVE implementation review
`docs/evidence/EXEC-005_SECURITY_REVIEW.md`.

Residual trust includes the controller/agent, deployment owner, kernel, selected
cache producer and shared HMAC verifier. Same-UID hostile workload containment
remains SEC-005, startup catalogs do not promise hot revocation, and cached bytes
are not restored to a downstream workspace. At the cache review, four other
helper product paths remained refused; the input successor review follows.
This section reviewed the cache slice as a partial implementation boundary.
`EXEC-005` closed with `PAR-012` on PR #147: the cache and input slices
merged with their own gates, the source slice is the checkout step reviewed
in the `PAR-012` section, and the dependency-resolver and provisioner slices
were dropped on 2026-09-10 because their helpers require a McLoving-private
attestation no public registry or cloud provides. Three of the five helper
gates exist; the two dropped helpers earn none. No production, canary or
cutover authority follows from the closure.

## EXEC-005 input capture integration review (earned closure)

The bounded input contract is `docs/architecture/INPUT_PRODUCT_PATH_V1.md`.
TM-008/TM-026 are reviewed for closed literal input intents, canonical IR 1.5
and envelope 4. Default-deny startup catalogs bind exact tenant/project/pipeline,
mapping digest, Linux platform and trust pool across submission routes. Exact
mapping capabilities prevent incompatible same-pool agents from consuming an
otherwise eligible attempt; agent-side checks remain mandatory.

TM-012/TM-033 are reviewed for operator-owned query,
cursor, endpoint, public confidentiality, grant and immutable configuration.
Provider tokens remain helper-owned. Pure verification creates no adapter,
network client or spool. The helper checks the same parsed config pin before
credential/state creation; sealed execution hashes the actual running image.
Special-file access is bounded, nonblocking and checked on the opened file.

TM-005/TM-007/TM-011 are reviewed for authoritative assignment hashing,
original durable acceptance time, deterministic capture UUIDv8 and full-digest
audit lineage. Expiry uses checked arithmetic capped by grant expiry; recovery
cannot mint fresh identity or time. Closed cache/input dispatch retains private
IO, spawn journaling, lease renewal and containment. Pure receipt verification
authenticates the full request, scope, configuration, schema/content, cursor,
provenance, grant, confidentiality and observed timing before public completion.
Raw helper output and provider contents do not enter public attempt spools.
Unresolved post-capture recovery parks/refuses without blind redispatch;
terminal replay remains a distinct durable-result path.

Review found and corrected a non-Unicode optional config pin being ignored,
general symlink refusal blocking `/proc/self/exe` hashing, and missing completion
deadline checks. Focused and actual-product verification receipts are tracked
in `docs/evidence/EXEC-005_SECURITY_REVIEW.md`; source review alone earns no gate.
The counted provider, native receipt/journal linkage, private-output checks and
both crash windows require real API/controller/remote-agent/helper execution.

TM-014/TM-051 retain existing artifact and effect-authority semantics: captured
values do not feed downstream workspaces or branching, and no production grant
is added. Controller/agent, deployment owner, kernel, producer and shared HMAC
verifier remain trusted. Same-UID workload isolation remains SEC-005; hot
revocation, generalized input consumption, other helper integrations, release
qualification and JCOMP-003 recertification are unearned. EXEC-005 remains ACTIVE.


## EXEC-005 standalone source custody prerequisite review

TM-012/TM-033 are reviewed for the normal acquisition entrypoint's optional
canonical-config pin before credential, key, marker or state access. Internal
askpass/resolver/transport admission remains separate. TM-005/TM-007 are reviewed
for actual running-image identity, original-hash-verified constructor snapshot,
and preserved derived ELF interpreter/runtime custody. Ordinary file paths
retain bounded nofollow/nonblocking reads and same-opened-object checks.

The real standalone fixture must execute the sealed source helper under the
externally selected existing source profile and exact transport filesystem,
with authenticated read-only Git protocol, native receipt/retained-tree joins
and adverse pin/file cases. Evidence is tracked in the ACTIVE EXEC-005 review.
This does not connect source acquisition to an agent or controller. Nested
process groups require a separate whole-lifetime integration proof; current
agent outer-group emptiness is insufficient evidence for those descendants.
No process escape is claimed observed, no profile or process-group authority is
changed, and retained-root/retention ownership remains separate future work.
SCM-001's historical isolated boundary and frozen JCOMP-003 evidence are not
recertified or expanded by this prerequisite.

## EXEC-005 pure source receipt authentication review

TM-001/TM-002/TM-014/TM-016 are reviewed for receipt reuse across acquisition, tenant, build,
attempt, repository, trust, generation, grant and audit context. Pure verification
commits the complete original request and separately compares repeated fields,
exact repository/submodule graph and acquisition-derived output identity before
native replay can accept stored evidence. A valid HMAC from the configured key
is necessary but insufficient for a context match. Strict bounded stored-frame
parsing rejects duplicate/unknown/trailing data (TM-008/TM-018). Historical authentication checks
the original acquisition/publication window; present-time native admission is
preserved and remains separate from historical evidence authentication.

TM-013/TM-016 are reviewed for verifier authority construction: explicit config,
implementation, key and marker snapshots reuse native pure shape/hash validation
without runtime-path or provider IO. Native runtime canonicalization remains in
the native constructor. Key-bearing verifier state has no debug formatter and
markers are not retained. Seven focused pure-verifier tests cover signed-field,
complete-request, repository/submodule/time, frame and authority substitution.
They are unit evidence, separate from the actual native acquisition fixture.

Residual risks remain the trusted native issuer/key/configuration and kernel,
size-controlled typed authority inputs, writable same-UID retained contents,
pathname-based tree traversal, unbounded aggregate retention and unwired product
source dispatch. This review does not close EXEC-005 or recertify historical
SCM-001/JCOMP-003 claims. Held-directory custody, retention ownership and actual
submitted-job crash/replay proof remain required before source product support.


## EXEC-005 closed standalone source lifetime review

TM-006/TM-007 are reviewed for independently grouped source descendants,
outer cancellation/death, lost caller identity and premature success. The fixed
source-only launcher uses a namespace PID1 lifetime boundary while preserving
native process-group cancellation. Private staged admission withholds the worker
until the caller pins the exact init identity. The caller must join that init
pidfd after outer death; a snapshot of observed descendants or an empty outer
process group is insufficient. Restarted agents have no retained kernel FD and
must park unresolved work, with no reused-PID signaling or refetch shortcut.
These are standalone protocol obligations; agent durable adoption remains open.

TM-013/TM-016 are reviewed for the fixed profile/image/runtime handoff. The named
profile is explicitly unconfined and grants user-namespace creation; it is not a
filesystem/network sandbox. The fixed source image selects the exact label,
clears internal child environments and closes unrelated descriptors. Runtime
root ownership is checked in the original full UID/GID identity context before
namespace UID translation. Bounded same-opened files and a sealed manifest are
consumed through verified live parent pidfds, exact sealed parent/child image
identity, unique initial containment modes and parent-held manifest identity.
Ordinary native construction retains its root-owner check. An unsigned claim,
sealed manifest alone, remapped namespace-root identity or generic environment
flag cannot authorize the exception.

TM-008/TM-018 are reviewed for bounded setup and authority parsing: monotonic
lifetime deadlines, bounded config/manifest/runtime totals and complete native
resource checks remain. Held proc-root/task descriptors with same-mount
`openat2` reads reject static proc bind overlays used to fake UID maps, parent
identity or environment. Genuine final proc magic links are checked before and
after following; active same-UID mount substitution between those checks is not
claimed prevented. A trusted operator launcher must clear the first loader
environment before execution; checking it after `main` cannot repair injected
code. Compromised same-UID ptrace/mount actors, privileged host administrators
and the trusted kernel/issuer remain residual authorities.

Actual fixture outcomes are recorded in the ACTIVE EXEC-005 security receipt.
No result here closes source product support, held retained-tree custody, finite
retention/crash reconciliation, general workload containment or EXEC-005 itself.
The source/native and frozen compatibility denominators remain separate.

## PAR-000 product-parity re-orientation review (earned closure)

`docs/evidence/PAR-000_SECURITY_REVIEW.md` records the docs-only
re-orientation merged as PR #143. No runtime, protocol, persistence, identity,
secret, connector, compiler, deployment or migration boundary changed; the
board's `DEFERRED` moves and verifier pins alter which tickets are dispatched,
not what any executable does. Every threat row was reviewed and needs no
semantic change. Residual: the parity tickets that follow each carry their own
review before closure.

## PAR-010 multi-step stage execution review (earned closure)

The version-5 envelope runs one to sixteen ordered process steps of one stage
inside one attempt. Boundaries touched: TM-003 (agent runtime and lease: one
lease, one journal row, `Running -> Running` rebinds the leader identity per
step and `attempts.current_step` is durable before every spawn); TM-005/TM-006
(execution and log evidence: per-step spools under `spool/step-N/`, journal
sequences `2N` and `2N+1`, the wire and store `step_ordinal` bounded below
65536, the 96-chunk cap enforced on both sides); TM-023 (workspace: later
steps re-enter the workspace by `lstat`-checked components with symlinks
refused; steps share the workload's own identity, so a step may alter what a
later step sees exactly as a single process could alter its own workspace, and
hostile same-UID isolation remains SEC-005); TM-052 (routing: the
`multi-step-v1` capability keeps the envelope away from agents that cannot run
it, and an agent that receives it without the negotiated feature refuses
terminally). Crash between a step's exit and its finalization parks the attempt
reconciliation-required naming the step; nothing is re-run or skipped. Focused
unit tests and the shipped controller/agent integration tests cover the ordered
run, the first-failure stop, the capability requirement and the exact crash
point. Review on PR #145 added: attempt terminals and exit codes derived from
the last step record, Linux-only admission for multi-step stages, ordinal-0
records for a first step that never spawned, controller cancellation kept
distinct from lease loss, finished-step spools relocated by rename into one
deterministic agent-owned directory that terminal reclaim removes, per-step
descriptors journaled in one transaction before the next spawn, redaction
against the union of attempt credentials with the union bounded at eight,
version-5 work declined rather than refused for a session that did not
negotiate the feature, and byte-identical initial and replayed summaries.
Closed on squash merge `cca42de59271820826248c35ed195e8e81e637a6` with
exact-main Foundation `34571458905` and Windows Agent `34571458894`; receipt
`docs/evidence/PAR-010_SECURITY_REVIEW.md`. Residual: journaled step logs are
not published when recovery completes a cancellation (`AGENT-008`), and
hostile same-UID access to the relocated spools remains `SEC-005`.

## PAR-011 container stage execution review (earned closure)

A stage that names a digest-pinned image runs every step under rootless podman
through the version-5 envelope. Boundaries touched: TM-003 (agent runtime: the
podman client is the process-group leader, so lease, cancellation and timeout
keep the existing group teardown proof); TM-005/TM-006 (execution and log
evidence: the container's stdout and stderr are the step's spools; environment
reaches the container by name only, so no secret value enters the podman
argument vector); TM-023 and SEC-005 (workspace and host: only the attempt
workspace is bind-mounted, at `/workspace`, and the host root, the service
account's configuration directory, the journal and the mTLS key are not
visible inside the container; this is partial containment because plain
process steps still run on the host as the service account); TM-016 and
TM-023 (supply chain: a tag reference is refused at compile, admission and
execution, so only the exact image digest ever runs); TM-052 (routing: the
`container-podman-v1` capability is advertised only when the deployment-pinned
podman answers, and admission refuses container stages for Windows). After the
group is empty the executor removes the named container and accepts only a
`container exists` exit status of 1 as proof; anything else is unverified
containment, and a group-teardown failure on any arm still attempts the reap
before its error propagates. A container attempt reserves that bounded reap
inside its lease on top of the termination grace (TM-003: a pre-expiry
cancellation finishes the teardown before the attempt is reclaimable, and an
agent whose lease cannot hold the reserve refuses to start with a runtime
configured). Residual: `--userns=keep-id` maps the service account into the
container, so a workload that escapes the container runtime holds the same
identity as today; image pulls reach the registry the reference names under
the deployment's network policy. Shipped-binary tests cover a step reading the
image's os-release with the host root invisible, and a timed-out step whose
container is proven gone. Closed on PR #146 (`0eb949ba`), exact-main
Foundation `34584499133` and Windows Agent `34584499144`; receipt
`docs/evidence/PAR-011_SECURITY_REVIEW.md`. Residual, filed as `AGENT-009`:
the podman store identity is not yet pinned into launch and reap, implicit
`mounts.conf` binds are not yet disabled by an agent-owned containers
configuration, and `#`-prefixed environment names are not yet refused for
container stages; plain process steps remain uncontained (`SEC-005`).

## PAR-013 live log streaming review (earned closure)

A step's output reaches the controller while the step runs and a reader
follows it by one global cursor. Boundaries touched: TM-003 (agent runtime:
live chunks travel the existing fenced, session-bound `PublishLog` path with
the same lease, fence, restore-epoch and session checks, redaction to a fixed
point and idempotent append, so a stale or fenced-out agent cannot publish
and a duplicate is a no-op; the per-attempt chunk bound rises to 262 144 only
for a session that negotiated `live-log-stream-v1`, read from the durable
session record, the live tail stops 128 sequences short of it, paces its
flushes so the budget lasts the step's timeout with the budget shared
across the attempt's remaining steps, and never streams past the aggregate
output limit, and the 64 MiB byte quota is unchanged, TM-018); TM-013 (a credential-bearing step is never tailed: its output is
captured and redacted after it exits, as before, so nothing unredacted
leaves the agent early); TM-006
(durable evidence: every chunk's sequence and byte range are journaled before the
chunk is sent, so a crash at any point cannot renumber or duplicate a range;
the terminal pass verifies the executor's durable spool and re-hashes every
streamed range against its reservation, refusing by name a spool the
workload rewrote after a range was streamed (the executor's quota cut keeps
every streamed byte through per-stream retention floors it reads under the
same lock the tail raises them under, within the same aggregate limit, so a
quota-terminated step passes the same checks), and
reads the live spool files
through descriptors opened without following links or blocking and judged
regular files after the open, so a renamed, unlinked or swapped visible
path cannot redirect or stall the tail; recovery replays from the same
reservations and sends only ranges without a receipt); TM-052 (API: follow
mode reads through the same authorization, tenant and fence filters as the
paged read, holds a request at most 30 seconds re-reading at 200 ms, reads
the chunks once more after observing a terminal status so the drained end
is exact, answers from the ledger only, so a follower observes committed
chunks and nothing in flight, and names positions within the build's own
commit order, stored with the build identity at commit under the per-build
log lock and unique-indexed on (organization, build, position) so a page
after a position is one ordered range scan rather than a re-ranking of the
ledger or a merge across attempts, rather than the store's table-wide
identity, so a tenant cannot
measure another's activity from cursor gaps). Capacity under TM-018: at
most 262 144 chunk rows per attempt for a live-streaming session, each
bounded by the 64 MiB per-attempt byte quota, the row count itself bounded
by the tail's one-second flush floor and pacing. Residual: a workload can still write anything into its
own stdout, as before; the live tail opens the spool by path after the
executor created it, so a workload that swaps the path in that window
streams other content it could have printed anyway and then fails its
attempt at the terminal check; a crash while a step runs is followed, on
restart, by restoration of the agent's own access to the interrupted step's spool
chain (a workload-revoked permission is restored, never read as an absent
stream), the executor's aggregate quota cut applied to the spool pair
with its reservations as floors and then publication of that
spool from its reservations under the renewed lease before the
cancellation completes (a
failed publication keeps the attempt cancelling for the next session
rather than reclaiming the spool), and the interrupted attempt is reported
as such (a lease definitively lost in the meantime retires it with the
accepted chunks exactly once). Tests cover the journal reservations (uniqueness,
coverage, stale authority, retirement, schema migration), the store follow
read and both chunk bounds, and two shipped-binary gates: the first line
visible while the step runs with the paged read agreeing with the follow,
and a crash after the first acknowledged terminal chunk replayed under the
journaled sequences with every chunk exactly once. Closed on PR #149
(`0e2cf213`), exact-main Foundation `34636714250` and Windows Agent `34636714092`; receipt
`docs/evidence/PAR-013_SECURITY_REVIEW.md`. The review added, before the
merge, build-scoped follow positions stored at commit under the per-build
lock with an ADR 0012 compatibility trigger for a pre-v39 writer, the
executor's retention floors shared with the tail, recovery of an
interrupted step's spool with access restored, the quota cut applied and
an emptied stream with a reservation outstanding refused rather than
dropped, the attempt's live log mode journaled (schema 7) so a session
with an older peer defers its replay, and the follower writing exact bytes.
Residuals carried as tickets: a spool the workload unlinks, renames,
truncates or overwrites under a reservation strands or pins that sequence
until reserved chunks are kept in agent custody (`AGENT-011`); the byte
quota's per-append sum over prior chunks is cost, not exposure
(`CTRL-005`).

## PAR-014 artifact upload review (earned closure)

A stage declares the files it publishes and the agent uploads them after its
steps over its own channel. Boundaries touched: TM-003 (agent runtime: the
upload stream rides the existing session-bound, fenced work authority with
the same lease, fence and restore-epoch checks as log publication and the
session epoch re-checked inside the registration and availability
transactions themselves, so a session superseded during a long stream cannot
register after its replacement,
is accepted only for a session that negotiated `artifact-upload-v1`, and
the scheduling capability is kept only for such a session, so an older
agent or peer is never offered a stage that declares artifacts, an artifact
node that reaches a session without the feature in a mixed rollout is
declined before a step runs, and never
strands its files); TM-013 (credential and host exposure: the collector
resolves the agent-owned workspace root from the filesystem root one
component at a time without following a link in any of them, so a writable
ancestor swapped for a link cannot redirect the walk, reaches the attempt
workspace from it one component at a time `O_NOFOLLOW`
so a step that swaps its workspace for a link is refused by name rather
than followed, opens every directory and file below `O_NOFOLLOW` and
re-identifies each against the entry it was reached by, never visits the
agent's own spool, enters a directory only when a pattern can match below
it, refuses an entry whose name is not UTF-8 when a declaration would
collect or enter it rather than naming an object by a lossy spelling,
refuses a matching path holding a control character by name before any
upload rather than letting the controller's refusal end the session, and
refuses the whole set by name when a link stands where a declaration would
collect or descend, so a step that plants a link to a service-account file
gets a named refusal and no upload; a Windows agent has no collector and is not
routed such work); TM-006 (durable evidence: the controller stages each
object into the same content-addressed store the public upload routes use,
with the declared length and the object itself charged against the
attempt's byte and object quotas in an in-process ledger of streams in
flight and then reserved against the store quota before the first byte (an exact retry of an available object is
answered without receiving a byte, so retries cannot stage; a pending one is
charged once), the header and the receive phase bounded so a
stream opened and never written or stalled mid-way releases the reservation,
and a short or mismatching upload discarded, registers it through the
same fenced `register_artifact` predicate under an attempt-scoped
artifact lock shared by every name (so concurrent uploads cannot each fit
the quota and together exceed it) and then the per-name lock, and commits
it into the immutable digest namespace, so an artifact is either registered
with its digest and length or absent); TM-018 (capacity: sixteen
declarations of thirty-two patterns per stage, pattern matching a table
over pattern and path segments so a pattern of many `**` segments costs
their product rather than a combinatorial search, a walk bounded at depth
32 and 65 536 entries, at most 1 024 objects and 256 MiB per attempt
counted by the agent before the first upload and both enforced by the store
at every registration under the attempt-scoped lock, so a custom peer
cannot register unbounded rows under one lease, the agent's reads bounded by the length identified at open so a writer the
step left behind cannot keep it reading, one-MiB frames, the upload budget both
sides share (thirty seconds plus one second per MiB, bounded at fifteen
minutes) under a lease the agent keeps renewing, and the attempt's
cancellation ending collection and any upload in flight);
TM-052 (API: no new public route; the existing authorized artifact listing
and download routes serve the objects). Residual: an attempt's own steps
choose the bytes, as before; a crash between the steps and the durable
terminal leaves the objects already committed registered under the
interrupted attempt and recovery does not resume the rest, so a partial
set is visible with the attempt reported interrupted; artifacts of a
failed step are collected like a succeeded step's, since a failing build's
logs are what a reader wants. Tests cover the pattern dialect and
declaration bounds, the canonical encoding and version gate, the execution
envelope and required capabilities, the collector's refusals by name (a
link the declarations would collect or enter, a non-regular entry, an
object name past the bound), and two shipped-binary gates: a step's files
listed under the declared name and downloaded with a matching digest, and
a planted link refusing the set with nothing uploaded. Residual: the
in-flight ledger is per controller process, so replicas of an HA deployment
each admit streams against the committed figure alone until registration,
where the quota is authoritative; the walk's aggregate matching work is
bounded per pattern-and-path pair but not across the walk, a zero-length
file is not probed for growth before its header-only stream closes, the
collector holds every collected file open at once so a set near the object
bound needs a descriptor limit above the default 1 024, the controller
finalizes a staging writer (its fsync) on a runtime worker thread, a set
is published one object at a time, so a file that changes under a later
upload fails the attempt by name with the earlier objects of the set already
visible rather than none, the digest pass does not check cancellation
between reads, so a cancellation that lands while a large file is hashed on
a slow filesystem takes effect only after the read, the client's upload
deadline equals the server's receive budget with no headroom for the commit,
the streaming reader's join is unbounded on a stalled read, the controller
writes each frame on a runtime worker, an upload's in-flight ledger
charge overlaps its registered row until the stream ends, so two uploads
that exactly fill the quota can see the second refused, and a file larger
than the controller's per-object limit (64 MiB by default, below the 256 MiB
attempt quota) is refused by the controller with an answer the agent treats
as a session error rather than a named refusal, and an exact retry of a
`pending` object stages a second full copy rather than resuming the first,
so near the store's total quota such a retry cannot recover the pending
metadata (`AGENT-012`); the sequential planner, which no pipeline with declarations reaches today,
would plan such a stage with its declarations dropped rather than refuse it
(`CTRL-006`). Closed on PR #150 (`9208e4e2`), exact-main Foundation `34652565336` and
Windows Agent `34652565410`; receipt `docs/evidence/PAR-014_SECURITY_REVIEW.md`.
The review added, before the merge, the workspace root and the attempt
workspace resolved component by component without following a link, the
matchers as bounded tables, one object per matching declaration with its
own file description, non-UTF-8 and control-character names refused,
entries the walk cannot read and a workspace the step made unreadable
refused by name, a file that runs short, grows or is rewritten under either
read refused by name, cancellation ending collection, the session epoch
re-checked inside registration and availability, an attempt-scoped
registration lock with byte and object quotas, an in-flight ledger of
streams charged before staging, header and receive deadlines, exact retries
answered from the ledger, and the Windows admission refusal. The residuals
above are carried as `AGENT-012` and `CTRL-006`.

## PAR-005 dogfood review, ticket ACTIVE

McLoving runs its own Foundation lanes on the owner's host for every push
to `main` and writes the outcome back to the commit. Boundaries touched:
TM-013 (credential and host exposure: the dogfood deployment holds the
GitHub token that writes statuses, the sealed source binding for this
repository and the webhook key, all as owner-private files under one state
directory rendered by `scripts/dogfood/heman-up.sh`; the lanes run as
process steps with the agent's cleared environment and derive the
toolchain from the running user, never from the pipeline, and the pipeline
file carries no credential, URL or executable, only mapping ids and a
digest placeholder rendered at apply time); TM-003 (agent runtime: the
checkout is the sealed acquirer entered through the AppArmor launcher under
the host's user-namespace restriction, bounded by the deployment's
transport tmpfs and file limits, and the lanes that need PostgreSQL or a
container provision them themselves through rootless podman as the
Foundation mirror script already does); TM-039 (trigger ingress: without
public ingress the host cannot receive GitHub's deliveries, so
`scripts/dogfood/bridge.sh` posts each new `main` head to the controller's
own public hook route as a push delivery signed with the trigger's derived
secret, so the receiver, filter, idempotency on the delivery id and the
admission path are the ones GitHub exercises, and a delivery id is the
GitHub push event's own id, so one push is one build whichever side
delivers it and a branch pushed away from a commit and back is two pushes
and two builds, as at GitHub; the bridge records every delivery with its
event and build so the evidence pairs each build with its own push);
TM-052 (verification integrity: `scripts/dogfood/verify-lanes.py` names the
commands each lane mirrors and fails when Foundation or the lane stops
carrying one, and the evidence table is written by
`scripts/dogfood/verdicts.sh` from `gh run list` and `mcloving status`, not
by hand). Residual: the bridge synthesizes the push payload from the
commit record rather than receiving GitHub's, so path filters see the
commit's changed files and nothing else; the deployment runs debug
binaries under the owner's own user rather than the service-user install
of `DEPLOYMENT_V1`; the lanes Foundation runs under the user-namespace
policy, the contained browser, the deployment fixture and the TLA+ tools
are not mirrored and the compared verdict is Foundation's whole run. The
ticket closes on ten consecutive matching verdicts recorded in
`docs/evidence/PAR-005_DOGFOOD.md`; closure additionally requires the
reviewed merge, exact-main Foundation and native Windows runs, and a
receipt in `docs/evidence/PAR-005_SECURITY_REVIEW.md`.

## PAR-003 human role grants review, ticket ACTIVE

Human project roles are granted and revoked at runtime: the offline
identity admin tool bootstraps a project's first Owner and manages any
role; a project principal manages roles through
`PUT`/`DELETE /projects/{project_id}/memberships/{identity_id}` under
`ProjectConfigure`. Boundaries touched: TM-001 (cross-tenant substitution:
memberships stay under the forced tenant policy from `0002`, every write
runs in a tenant transaction and the identity and the project are both
required in the caller's organization before a row is written); TM-027 and
TM-028 (session fencing and the admin boundary: a revocation or a demotion
bumps the identity's lifecycle generation inside the same transaction, the
fence a lifecycle transition applies, so every bearer issued under the
earlier generation answers 401 at once; the runtime role gained column
`UPDATE` on `identities.lifecycle_generation` and row writes on
`project_memberships` in migration `0041`, pinned in the least-privilege
matrix, and the store's rules are tested as that role); TM-030 (ACL
broadening: the API cannot mint a project's first Owner, only an Owner
grants Owner or changes or revokes an Owner, an Admin manages the roles
below, a Developer or Viewer manages nothing, and the last Owner of a
project cannot be revoked or demoted by either authority, so a project
never loses its Owner and an Admin never becomes one through the API; the
caller's identity row is locked for the write transaction, the row a
lifecycle transition and a fence also lock, and the identity must be active
at the authenticated generation with its session and service credential
unrevoked, then its role in the project is read under the same locks, so a
demotion, revocation or fence that committed after authentication is
applied to the write; a service principal or a mapped-policy principal is
revalidated the same way and acts as an Admin, never as an Owner, and a
static credential, which names no identity, acts as an Admin without
revalidation); every change is one
`identity` audit record (`project_role_granted`, `project_role_changed`,
`project_role_revoked`) naming the authority, the actor's role, the
previous role, the reason and the fenced generation. Residual: a mapped-policy
grant is decided at authorization time and not read again in the store
(the identity, session and credential are); a promotion
does not fence, so a session issued before it carries the new role at its
next authentication without re-login, which is the intended direction; the
Owner count is read under a per-project advisory lock, so two concurrent
revocations cannot both see a second Owner; memberships written before
`0041` carry `granted_by = 'unrecorded'`. Closure requires the reviewed
merge, exact-main Foundation and native Windows runs, the HeMan proof in
the pull request body, and a receipt in
`docs/evidence/PAR-003_SECURITY_REVIEW.md`.


## PAR-004 build notification review (earned closure)

A build's terminal outcome is delivered to the targets its pipeline names: a
GitHub commit status under the deployment's token, or a signed HTTPS
webhook. Boundaries touched: TM-054 (a notification credential acting
outside its mapping: the pipeline names only a mapping id; the deployment's
startup-frozen, digest-pinned catalog binds each mapping to one repository
or one `https` destination and to one organization and project; admission
resolves every target against it at save, validate, plan and submission and
records the resolved target with the build, so the worker never chooses
where a credential acts, a named repository must be the mapping's, and a
kind whose credential the deployment lacks is refused rather than queued
undeliverable; at delivery the destination host is resolved, every address
is checked against loopback, private, link-local, shared, benchmarking,
documentation, multicast and reserved ranges, IPv6 allowed only inside
global unicast less the IETF protocol-assignment, documentation and
segment-routing blocks with 6to4, well-known NAT64 and IPv4-mapped forms
decided by the embedded address and local-use NAT64 refused, the connection
is pinned to
exactly those addresses with the name kept for TLS and `Host`, redirects are
not followed and no proxy is used, and the sequence is repeated on every
attempt so a name that changes its answer between attempts is re-decided;
the answer is read to a bound and kept printable and bounded in the
ledger); TM-039 (terminal delivery: the deliveries are inserted in the
transaction that derives the terminal status with one `dag.build_terminal`
event, re-derivation on the retry paths inserts nothing new, rows are
claimed `FOR UPDATE SKIP LOCKED` under a lease longer than the delivery
deadline so two controllers hold disjoint rows even after the lock is
released, the backoff scheduled when a failed attempt is settled so the row
is off every scan until due, settlement is keyed on the claim's terminal
generation and attempt count so an overtaken worker's answer, or one from
before an operator retry made the build terminal again, is dropped and the
newer generation is posted once more (re-queued if delivered, marked for a
re-post if in flight) so its outcome is written last, and an attempt is
recorded in flight before its request is sent and stays recorded through a
failed settlement (a request that timed out after its body was sent may
still be applied), so a build that becomes terminal again meanwhile delays
its new outcome past that attempt's deadline whether or not the controller
lives to settle it, the resolved targets are part of
the build's replay contract so catalog drift between controllers is an
idempotency conflict rather than a race, a commit status is held by the
latest build for its repository, commit and context so an earlier build's
delayed delivery is abandoned as superseded rather than written over it, the
in-flight mark and the later build's terminal record are serialized under
the status key's lock so the later build delays its first post past an
in-flight earlier attempt's deadline (durably, before any request), a scan
abandons a pending row whose attempts are spent rather than claiming it
again, and attempts are bounded at twelve per generation with the backoff
capped at an hour); TM-013 (credentials and host exposure: the token
and signing key are owner-private secret-class files opened without
following links, never logged, never in a link, and the public base URL is
the only thing a notification carries about the controller; the UI reads
the linked organization, project and build from the query and still asks
for the token). Residual: a request the target applies after the local deadline can
still become the latest status, since the quiet interval bounds the
worker's wait and not the target's (`CTRL-007` reconciles the status
against the target after the interval); a network-specific NAT64 prefix
inside global unicast synthesizes addresses whose embedded IPv4 address is
not examined, since only the well-known prefix is decodable without
configuration (`CTRL-007` lets the operator name the deployment's
prefixes); the destination's certificate is
checked against the system roots, so a private authority is not supported
(the ticket's CA pin is not shipped); the status-key fence is
tenant-partitioned like every store read, so two organizations of one
deployment that map the same repository, commit and context race at GitHub
(an operator gives each organization its own context, or maps a repository
in one organization); a 4xx that will never succeed is retried to the
attempt bound rather than abandoned at once; GitHub's answer to the commit
status is trusted as delivery; the `revision` a status is written for comes
from the pipeline's parameter, so a pipeline can report on any commit of the
mapping's repository. Tests cover catalog validation, the address policy
across every range and embedded form, destination URL shape, the terminal
ledger and its idempotence under a second terminal, admission refusals for
unknown, foreign, mismatched and uncredentialed mappings, a sink that
refuses twice then accepts with the error kept and cleared, a signed webhook
verified under the key, two concurrent workers claiming one row once, and a
private-resolving destination refused before any connection. Closed on PR
#151 (`bf47e751`), exact-main Foundation `34666100980` and Windows Agent `34666100983`;
receipt `docs/evidence/PAR-004_SECURITY_REVIEW.md`. The review added,
before the merge, the claim lease past the delivery deadline, concurrent
delivery inside it, the terminal generation fence, the IPv6 allowlist,
credential-scoped claims, the resolved targets in the replay contract,
re-posting after a stale settlement, supersession by the latest build, the
in-flight mark before any request under the status key's lock, full
validation of resolved targets, the dead-letter terminal path notifying
once, and the refusal of targets in components and sequential admission;
the items above are carried as `CTRL-007`.

## PAR-001 GitHub webhook receiver review (earned closure)

A public route lets GitHub feed an SCM webhook trigger directly. Boundaries
touched: TM-039 (trigger ingress: the receiver admits through the same
durable delivery ledger, replay and conflict rules as the bearer route, with
the trigger's own event-source identity as the caller, so nothing about
uniqueness, redrive or dead-lettering is bypassed; the delivery is
receipt-timed, the event time being the database clock read inside the
serialized acceptance so one delivery id gets one time across controllers
and no controller clock can reject a legitimate delivery, and a redelivery is
matched on the authenticated delivery alone rather than on the trigger
generation or parameters current at redelivery, and ahead of the trigger's
current pause state and filter, so it replays rather than conflicts, refuses
or acknowledges as filtered after a configuration change); TM-002/TM-011
(authentication: no bearer, the raw body's `X-Hub-Signature-256` is verified
in constant time under a per-trigger secret derived by HMAC from the
controller's webhook key file and the trigger's identity and
`source_generation`, never stored, rotated by event-source rotation, and
verified before any byte of the body is interpreted, so a forged delivery
leaves no receipt; deliveries in flight are bounded to eight, the permit
taken before the body is buffered and released at a 30-second deadline, so
an unauthenticated sender pins at most eight bodies of the 25 MiB bound in
memory and none past the deadline, a saturated route answers 503 without
reading and a stalled body 408; the key file is secret-class and nofollow in
the deployment contract, opened without following symlinks, and refused
unless owner-private; the secret-bearing read answer is `no-store`); TM-052 (routing: the receiver answers
only enabled-or-paused `scm_webhook` triggers whose configuration names
provider `github`, and a controller without a key answers not-found so the
route cannot be probed for triggers); TM-039 again for the mapping: the
delivery is reduced to the closed SCM payload (repository `full_name`,
`after`, branch, bounded paths) and every other field is dropped, an
oversized or truncated change set (more paths than the bound, or fewer
commits listed than the push advertises) is admitted pathless so a path
filter cannot be bypassed by volume or by omission, a delivery id's first
authenticated decision is durable (admitted ids in `trigger_deliveries`,
unadmitted ids in the indexed `webhook_receipts` with their event header and
body digest, both written under the trigger lock and each refusing the
other's ids; a repeat with the same authenticated input answers its recorded
acknowledgement without a second audit record, a repeat with different input
or an admitted id re-sent under an inadmissible event is a conflict; an
admitted delivery replays under its recorded caller identity across
event-source rotation), and unadmitted deliveries are acknowledged with 202 and
recorded as audit events so GitHub keeps delivering. Residual: the operator
reads the secret over the authenticated API and pastes it into GitHub, so
the secret's confidentiality in transit and at GitHub is the operator's and
GitHub's; the receiver trusts GitHub's delivery id as the idempotency key,
which is what GitHub's own redelivery contract guarantees; `revision` and
`branch` reach a pipeline only as parameters it declares, never implicitly.
Tests cover admission, exact redelivery with one build, reused-id conflict,
forged signature without receipt, missing headers, the unkeyed controller,
filtered and ignored acknowledgements with their audit records, and the
pull-request mapping. Closed on PR #148 (`327a032a`), exact-main Foundation
`34612940947` and Windows Agent `34612940719`; receipt
`docs/evidence/PAR-001_SECURITY_REVIEW.md`. The review added, before the
merge, receipt-timed acceptance on the database clock, durable indexed
receipts for unadmitted deliveries serialized with acceptance and redrive
under the trigger lock, replay ahead of the current filter and pause state
under the recorded caller identity, the body digest in the canonical
payload, generation revalidation for receipts, receipts in the transfer
snapshot, a permit bound with a deadline ahead of body buffering, and
`no-store` on the secret-bearing read. Residual: the operator carries the
secret to GitHub; GitHub's delivery id is trusted as the idempotency key;
an event filtered under a narrower filter is not re-decided on redelivery
(push again or use the bearer route).

## PAR-012 checkout step execution review (earned closure)

A `checkout` step puts the sealed source acquirer on the product path: a
submitted pipeline names a deployment source binding, a ref, an exact commit
and a workspace destination, and the steps that follow in the same stage build
in the checkout. Boundaries touched: TM-003 (agent runtime: the acquirer is a
helper step at its own ordinal inside the version-5 envelope, prepared before
the first spawn from startup-frozen bindings, entered as a sealed memory file
and, under the user-namespace restriction, through the `aa-exec` launcher and
its profile, never inside a stage image); TM-005/TM-006 (execution and log
evidence: the acquirer's answer is authenticated against the configured
signing key, configuration, implementation and runtime-closure digests and the
request the agent wrote, and only a typed public summary reaches the log; the
acquirer's message is dropped and unknown failure codes collapse to one);
TM-016/TM-023 (source and workspace: the repository, credential and executable
come from the binding and never from the job; the ref must be inside the
binding's allowed prefixes and must resolve to exactly the requested commit,
so a moved branch is refused rather than checked out at its new tip; the tree
is published by a descriptor-relative `RENAME_NOREPLACE` move with the
destination checked absent before and by inode after, so a preceding untrusted
step cannot pre-create or race-replace the destination with a link and write
through it into agent-owned files; the output root must share the workspace's
filesystem or publication is refused); TM-052 (routing: `sealed-source-v1`
plus the exact binding capability keeps the node away from agents without the
mapping, and admission refuses checkout stages for Windows and for any scope,
digest or trust pool the controller's startup-frozen source catalog does not
name). Residual: the acquirer's transport containment and its retained-tree
custody are unchanged and remain the acquirer's own reviewed boundaries; the
published tree is owner-writable by design, so a later step in the stage can
modify it, exactly as it can modify anything else in the workspace; the
commit reaches the pipeline as a literal or a typed parameter until `PAR-001`
supplies it from a delivery. Shipped-binary tests cover an ineligible agent
leaving the checkout queued, the branch head landing with a following step
building in it, a planted symlink destination refused by name, and five API
refusals. Closed on PR #147 (`e22a94ed`), exact-main Foundation
`34598819224` and Windows Agent `34598819193`; receipt
`docs/evidence/PAR-012_SECURITY_REVIEW.md`. The review added, before the
merge, pre-publication verification of the retained tree with the acquirer's
own routine, a sealed launcher, journaled acquisition directories reclaimed
by recovery, and deadline-bounded publication. Residual, filed as
`AGENT-010`: verification opens the acquisition by pathname while the move
uses a held descriptor, the manifest bound is the acquirer's tool-output
bound rather than the admitted limits, the final syncs and the recovery walk
bound are not deadline- or journal-bound, and the zero-budget checkout record
does not carry its termination through finalization. The published tree is
owner-writable by design, and plain process steps remain uncontained
(`SEC-005`).

