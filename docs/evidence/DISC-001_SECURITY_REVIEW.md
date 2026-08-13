# DISC-001 security and closure review

Date: 2026-08-12

Verdict: PASS. The versioned multibranch and organization-folder discovery
implementation is bound to exact reviewed head
`f02eddfffbc295dd86eef0a8a000f3f3b6a10554` and closed against protected
`main` commit `41248d7dd4f1a694494ddec7a22fd51eed1f1987` after exact-head and
post-merge Foundation and Windows verification.

## Scope

DISC-001 adds immutable, tenant-scoped discovery-parent generations and atomic
scan reconciliation for the closed GitHub, GitLab, Bitbucket, and Gitea
provider set. Parent generations bind the deployed discovery implementation,
protocol, complete configuration, provider and repository scope, branch and
pull-request strategy, fork trust, Jenkinsfile selection, child policy,
authorization generation, SCM trigger, source acquirer, orphan policy,
rollback lineage, and hash-chained audit provenance.

Authenticated webhook deltas and periodic or recovery snapshots become one
durable scan, event, cursor, observation, child-state, and audit transaction.
Exact replay is read-only; divergent or reordered identity, event, cursor,
authority, or configuration truth fails closed. Untrusted forks are
quarantined. Filtered first sightings retain immutable identity, reported
policy violations retire an existing child, and omitted children retire only
under a complete snapshot with the reviewed `retire` policy.

The implementation retains one immutable key/UUID identity-registry row per
child, uses constant-work identity checks, performs complete-snapshot orphan
retirement as one set-based update, carries receipt state totals incrementally,
and exposes accumulated children through a stable bounded cursor. The scan
route has a dedicated documented 128 MiB ceiling sufficient for all 4,096
maximally bounded observations; unrelated JSON and artifact routes retain
their narrower limits.

Quiesced transfer exports the complete deterministic parent, scan,
observation, current-child, and identity lineage. Its ledger digest is
committed into a hash-chained audit event and verification requires an
independently retained audit anchor. Discovery creates no runnable build and
grants no trigger, source, credential, connector, canary, or authority-transfer
capability.

## Exact evidence

- Pull request: `#47` (`DISC-001: implement versioned multibranch discovery`).
- Protected-main base:
  `cc4148ed3b0ea45477f9830044d36f4dfee6f6f7`.
- Exact reviewed implementation head:
  `f02eddfffbc295dd86eef0a8a000f3f3b6a10554`.
- Focused local gates passed: real-PostgreSQL discovery 2/2; complete
  controller-store 86 passed with six isolated backup/restore-only ignores;
  controller API 35/35; execution-board tests 9/9; changed-crate strict
  Clippy, formatting, diff hygiene, board verification, architecture
  documentation, and threat-model alignment.
- Seventeen actionable review threads were repaired and resolved. A refreshed
  GraphQL snapshot reported zero unresolved threads, and the final independent
  exact-head review reported no major issues on `f02eddfffb`.
- Exact-head protected checks: Foundation run `31660629787` and Windows Agent
  run `31660629779` passed all nine required checks.
- Squash merge: `41248d7dd4f1a694494ddec7a22fd51eed1f1987`.
- Post-merge verification: Foundation run `31662448088` and Windows Agent run
  `31662448074` passed on that exact protected-main commit. The serialized
  Rust/AppArmor job completed in 34m22s.

## Review-driven hardening

The resolved review chain established the following closure properties:

- canonical lowercase digest admission, typed present audit commitments,
  stored-digest length checks, exact trigger-provider and provider-identity
  binding, and pre-transaction JSONB set-size bounds;
- retirement of reported children that violate changed policy, plus
  state-only quiescence from a reconciled enabled generation;
- explicit stable-key/UUID conflict handling for materialized and
  filtered-only first sightings, followed by a one-row immutable registry that
  keeps successful identity verification independent of observation history;
- least-privilege registry reads without `FOR UPDATE`, proved under the exact
  runtime role that has no `UPDATE` grant;
- structural branch/head-repository validation before filters can retain an
  identity;
- set-based complete-snapshot orphan retirement with no accumulated-child
  materialization or per-child update loop;
- exclusive-key cursor pagination with a default of 50 and maximum of 200;
- incrementally carried active, quarantined, and retired receipt totals rather
  than an aggregate over all retained children; and
- a route-specific 128 MiB scan-body cap, documented in OpenAPI and exercised
  with all 4,096 maximally sized valid observations while other routes retain
  their existing smaller limits.

## Threat-model review

`docs/threat-model/README.md` records DISC-001 as TM-040. Review covered
authentication and authorization drift, trigger and source-acquirer
substitution, provider/repository/ref identity, fork trust, child identity,
replay and cursor ordering, immutable history, orphan disposition,
resource-exhaustion bounds, tenant RLS and grants, audit anchoring, rollback,
and transfer verification. No other threat-model boundary changed.

## Residual boundary

Trusted provider and source-acquisition attestations, discovery/configuration
and authorization reviewers, the independently retained audit head/export,
and PostgreSQL/deployment operators remain authoritative within their granted
scope. Mario's sealed inventory contains no admitted production discovery
parent mapping. This closure therefore grants no production parent, child,
provider credential, trigger, source acquisition, build, effect, canary,
cutover, rollback, recutover, or Jenkins decommission authority. Those actions
remain gated by their named execution-board tickets and fresh pre-action
receipts.
