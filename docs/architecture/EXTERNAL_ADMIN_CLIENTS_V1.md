# External administrative clients v1

Status: ADMIN-001 implementation complete; production write authority remains
explicitly Jenkins-source until a later real zero-write receipt.

The sealed MIG-000 identity/client manifest is the complete source denominator.
For the Mario oracle it contains one `read-write` client, `owner-operator`,
authenticated as Jenkins principal `oracle-admin` through a private-realm
session at `http://100.127.170.90:18080`. Its scope is the owner-designated
oracle controller and its observed use is corpus-oracle administration. The
unchanged manifest is
`migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/identity-clients.yaml`
with SHA-256
`a4227af8021c7d5fb6f7cc72be84af756ce1f95d33cd2ec9bad721beab587549`.
CONSUMER-001 owns this client's read slice; ADMIN-001 owns its write slice.

## Closed operation denominator

Every source generation classifies these 15 operation families exactly once:

- pipeline create/update, disable, and delete;
- folder, node, credential-reference, and controller-global mutation;
- build submit, cancel, terminate, retry, and pause/resume;
- queue reorder; and
- input/protected-environment approval submission.

An operation is `mcloving_v1`, `owner_retired`, or `pending`. The v1 replacement
currently admits five exact authenticated contracts:

| Operation | Contract | Precondition and idempotency |
|---|---|---|
| Pipeline create/update | `PUT .../pipelines/{pipeline}`; `mcloving apply` | quoted `If-Match`; desired-state digest plus revision |
| Build submit | `POST .../builds`; `mcloving submit` | pipeline digest; caller `Idempotency-Key` |
| Build cancel | `POST .../builds/{build}/cancel`; `mcloving cancel` | durable build-state fence; build ID plus cancellation state |
| Build retry | `POST .../builds/{build}/attempts/{attempt}/retry`; `mcloving retry` | attempt fence; attempt ID plus request digest |
| Protected-environment approval | `POST .../builds/{build}/approvals`; `mcloving approve` | environment/action/expiry; caller-stable approval UUID |

The ledger rejects an invented endpoint, method, schema, precondition, or
idempotency rule. An unsupported operation cannot claim v1 support.
`owner_retired` carries no target endpoint and requires a non-zero, separately
reviewed owner-retirement evidence digest. `pending` carries neither a target
contract nor retirement evidence. Target authority is impossible while any
operation remains pending. This repository contains only synthetic retirement
fixtures; it does not claim that the Mario owner has retired a real operation.

`mcloving apply PIPELINE_ID --slug SLUG --expected-revision N PIPELINE` reads
the desired strict-YAML source, sends only the public API request, and exposes
the same deterministic create/update/unchanged and stale-revision behavior as
the Rust client. A negative revision fails locally. The CLI has no database or
migration-role shortcut.

## Authority ledger

Migration 0026 creates immutable `external_admin_client_versions` and a
monotonic `external_admin_client_current` pointer under forced tenant RLS. A
stable binding digest covers tenant/project, sealed source inventory,
generation, endpoint, caller, authentication and scope, target identity,
subject and API version, and the complete sorted operation denominator. Each
authority generation separately binds every disposition and its exact target
or retirement contract, allowing a pending source plan to become a fully
classified target plan without substituting either endpoint or omitting an
operation. An authority generation additionally binds the bounded observation
window and source-write count, positive and negative authorization evidence,
create/update/delete convergence, duplicate/reordered/stale handling,
partial-failure retry, conflict denial, reviewer, and rollback evidence.

Generation one retains `jenkins_source`. A `mcloving_target` generation must
immediately follow it, preserve the stable binding, classify all operations as
v1 or owner-retired, and record exactly zero residual Jenkins writes. In the
same transaction, the store takes the shared AUTHZ-001 project-policy advisory
lock, locks and loads the exact active target identity through the runtime
principal path, and authorizes every admitted operation's distinct action.
Authentication or an active identity alone is insufficient. A project admin
that lacks build trigger or cancellation authority cannot cut over the mixed
client.

Rollback is a new Jenkins-source generation naming the immediately preceding
target generation and independent evidence. The pointer never moves backward;
source and target authority cannot be repeated or skipped. A per-client
transaction lock serializes simultaneous writers. Registration, cutover, and
rollback append hash-chained tenant audit events. The runtime role has only
RLS-constrained reads of the ledger and cannot manufacture a transition.

## Operational boundary

Mario remains Jenkins-write-authoritative. ADMIN-001 supplies the executable
contract and fail-closed gate; it does not fabricate a caller cutover, an owner
retirement, or a zero-write observation. Before an affected canary, cutover, or
decommissioning action, a privileged reviewed generation must bind the real
caller observation and either the real supported mapping or real owner-approved
retirement for every operation. Rollback keeps the exact Jenkins source
available until the later rollback window closes.

## Verification

`crates/controller-store/tests/external_admin_clients.rs` uses real PostgreSQL
to cover the sealed denominator, exact operation coverage, mapping and
retirement contract validation, residual-write and pending-operation denial,
least-authority denial, stable source/target binding, stale generations,
concurrent first-generation and lifecycle-transition serialization, rollback,
immutable history, constrained-role RLS, and hash-chained audit.
`bins/cli/tests/api_only.rs` proves `mcloving apply` sends the bearer token,
quoted revision precondition, desired source, slug, and typed parameters to the
public route without a privileged shortcut. Existing PostgreSQL/API suites
retain concurrent pipeline convergence, stale-revision conflict, build
idempotency, cancel/retry/approval durability, privilege denial, and audit.
