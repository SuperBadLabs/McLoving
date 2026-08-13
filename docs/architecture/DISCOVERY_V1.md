# Multibranch and organization-folder discovery v1

Status: implemented by `DISC-001`.

## Scope

Discovery v1 converts authenticated SCM observations into durable McLoving
child-pipeline truth for Jenkins Multibranch Pipeline and Organization Folder
parents. It does not execute a Jenkinsfile, acquire source bytes, mint a build,
or transfer production authority. Source acquisition, trigger capture,
authorization, pipeline admission, canary, cutover, and rollback retain their
own independently fenced contracts.

The controller supports two closed parent kinds:

- `multibranch_pipeline`; and
- `organization_folder`.

The only admitted providers are GitHub, GitLab, Bitbucket, and Gitea. A new
provider, discovery strategy, Jenkinsfile selection mode, or orphan behavior is
ineligible until its protocol, schema, implementation, and contained evidence
ship together.

## Immutable parent generations

Every parent generation binds all authority-bearing inputs:

- deployed discovery executable or image SHA-256 and protocol version;
- canonical complete parent-configuration SHA-256;
- provider service identity, optional provider organization, and exact
  repository allowlist;
- branch include/exclude prefixes, pull-request discovery policy, fork trust
  policy, and any named trusted fork repositories;
- one normalized exact Jenkinsfile path and the closed `exact_path` selection
  policy;
- child-configuration policy digest and `retain` or `retire` orphan policy;
- exact current project authorization generation and policy digest;
- exact enabled SCM-webhook trigger identity, generation, configuration digest,
  provider, and provider identity;
- source-acquirer implementation, protocol, and configuration digests; and
- actor, reason, idempotency key, optional retained rollback generation, and
  hash-chained audit event.

The canonical configuration digest uses sorted set representations, making
caller order irrelevant while duplicate entries remain invalid. Generations
advance exactly once under a per-parent PostgreSQL advisory lock. Exact
idempotent replay returns the retained generation even after a bound dependency
has advanced, because it creates no new authority. Divergent reuse, stale
preconditions, missing saved pipelines, missing authorization policy, and
trigger/configuration/provider substitution fail closed.

Repository, branch-filter, and trusted-fork sets are bounded both by item count
and by the exact 65,536-byte PostgreSQL JSONB text limit. Oversized sets fail
request validation before a transaction begins rather than surfacing as a
database constraint error.

`enabled` admits reconciliation. `quiesced` denies every new scan and is the
only state eligible for transfer export. Quiescence must be a state-only
transition from an enabled generation whose scan completed after that generation
was installed; configuration and quiescence cannot be combined. A rollback is a
new immutable generation that identifies a retained earlier generation; history
is never rewritten.

## Scan and observation ledger

A scan is one atomic reconciliation transaction. Its canonical request digest
binds tenant/project/pipeline/parent and parent generation, scan and optional
event identities, source kind, monotonic source cursor, complete-snapshot flag,
provider snapshot digest, and every typed observation in stable child-key
order.

The source shapes are closed:

- `webhook` requires an event identity and is a delta; and
- `periodic` and `recovery` have no event identity and are complete snapshots.

Scan IDs, event IDs, and source cursors are durable uniqueness boundaries.
Exact scan replay is read-only. Divergent ID/event replay and duplicate or
reordered cursors fail closed. A later periodic or recovery cursor therefore
catches up missed webhook activity after a controller or provider outage
without allowing older events to overwrite newer truth.

Before committing a scan, the transaction locks and re-reads the current parent,
authorization policy, and SCM trigger. Parent generation, enabled state,
authorization generation/digest, and trigger
generation/kind/state/digest/provider/provider identity must still match. The
audit event, scan row, immutable observations, materialized
children, and orphan transitions commit or roll back together.

Every reported observation is retained with an explicit `active`,
`quarantined`, `filtered`, or `absent` disposition and binds:

- stable child key and child pipeline UUID;
- base and head repository identities;
- branch or pull-request identity and optional pull-request number;
- present/fork/trusted/authorized dispositions;
- exact hexadecimal revision and provenance SHA-256;
- exact Jenkinsfile path and content SHA-256; and
- child-configuration SHA-256.

Repository, branch, PR, and Jenkinsfile filters are evaluated before admission.
An origin ref is trusted. A fork is trusted only under the configured closed
policy; an admitted but untrusted fork becomes `quarantined`, never `active`.
Filtered observations remain immutable audit/transfer evidence but create no
child. Neither an existing child key nor its pipeline UUID can be rebound; a
key/UUID cross-pair or any change to repository, ref, PR, head-repository, or
fork identity aborts the whole scan as a domain conflict before an insert.

## Child and orphan state

Current child truth has three closed states:

- `active` — present, policy-matching, trusted, and authorized;
- `quarantined` — present and policy-matching but untrusted; and
- `retired` — explicitly absent or missing from a complete snapshot under the
  `retire` orphan policy, or explicitly reported but filtered by the current
  parent policy.

State generations and source cursors advance monotonically. A delta never
retires an omitted child. A complete snapshot with `retain` also preserves
omitted children. `retain` never preserves a reported child that is known to
violate the current repository, ref, trust, or Jenkinsfile selection policy.
No discovery path physically deletes a child or creates a runnable build, so
retention and rollback evidence remain available.

## API and tenant boundary

The public v1 API exposes:

- `GET/PUT .../pipelines/{pipeline}/discovery/{parent}`;
- `POST .../discovery/{parent}/scans`; and
- `GET .../discovery/{parent}/children`.

Parent writes require `If-Match`, an idempotency key, and project-configure
authority. Scan reconciliation requires project-configure authority. Reads
require project-view authority. Request objects reject unknown fields and use
closed enums and bounded exact-width integers. Digests use canonical lowercase
64-character hexadecimal strings at the HTTP boundary.

All six discovery tables use forced tenant row-level security. The deployable
runtime preflight enumerates their exact least-privilege grants and policies;
schema or privilege drift prevents startup.

## Quiesced transfer and rollback evidence

Transfer export holds the parent advisory lock and requires the latest immutable
generation to be `quiesced`. It exports, in deterministic order, the complete
parent lineage, scan ledger, observation ledger, and current child set including
orphan state. A domain-separated ledger digest is committed into a new
`discovery.handoff.exported` hash-chained audit event. A second snapshot digest
binds that ledger commitment and the complete audit event.

Verification requires the handoff event hash from an independently retained
audit export or chain head. It rejects a missing generation, non-quiesced tail,
non-state-only quiescence, a missing scan for the enabled predecessor,
duplicate or reordered scan, mismatched observation count, orphaned observation,
duplicate/substituted child identity, recomputed ledger substitution, invalid
audit hash, or wrong independent anchor. A later authority-transfer ticket must
install exactly one verified discovery owner/generation before resuming scans.

## Required evidence

The real-PostgreSQL contract suite covers new and updated branches and PRs,
trusted and untrusted forks, filtering, exact/divergent replay, child-identity
substitution, reordered cursors, periodic and recovery catch-up, parent and
authorization drift, quiescence, orphan retirement, rollback restoration, and
independently anchored transfer tamper denial. Controller API tests cover route
and OpenAPI closure. Protected validation must also run the repository-wide
format, lint, unit, integration, security, and platform matrices before merge.

The Mario inventory contains no admitted production discovery parent mapping.
Consequently this ticket establishes implementation eligibility but grants no
production parent, child, trigger, credential, canary, cutover, or rollback
authority.
