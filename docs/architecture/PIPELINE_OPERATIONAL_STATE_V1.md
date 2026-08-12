# Pipeline operational state v1

Status: JOBSTATE-001 implementation contract. Production migration, canary,
cutover, rollback, and effect authority remain gated by their own execution-board
tickets and evidence.

## State is not pipeline source

Pipeline source and compiled IR remain immutable, revisioned product records.
Whether a pipeline may create or advance work is a separate operational record.
Each tenant/project/pipeline has exactly one current operational generation and
an append-only history whose values are `enabled` or `disabled`.

Every history row binds:

- tenant, project, and immutable pipeline identity;
- a strictly increasing target generation and state;
- a reviewed reason and authenticated actor;
- the source system/operation identity, source generation, source effective
  time, and non-zero provenance digest;
- a caller-stable idempotency key;
- the database effective time; and
- the exact hash-chained tenant audit sequence and event hash.

The source generation is intentionally text. Jenkins job-state imports carry
the immutable source export generation rather than pretending that a source
identifier is a McLoving counter. McLoving's numeric generation is the sole
optimistic-concurrency and runtime-fence value.

Migration 0027 synthesizes generation one, `enabled`, for every existing
pipeline. Those rows are visibly sourced from `migration:v27`, use one fixed
reviewable provenance digest, and are the only operational-history records
without a runtime audit event. A newly created pipeline receives its enabled
generation one in the same transaction as its revision and creation audit
event. Existing builds remain readable, but an active pre-0027 build without a
pipeline/generation binding is fail-closed and cannot be newly claimed.

## Transition contract

State changes require project-configure authorization, a quoted current
generation precondition, a bounded reason, source identity/generation/effective
time and provenance digest, plus a bounded idempotency key. The store serializes
writers on the existing per-pipeline transaction lock and locks the current
definition row.

The idempotency key is checked before the generation precondition after the
transaction lock is held. An exact retry returns the original history row even
if later generations exist. Reusing the key for different content is a
conflict. A stale or future expected generation is a precondition failure.
Repeating the current state under a fresh key is rejected rather than minting a
false generation. A valid transition toggles state and advances exactly one
generation; re-enable is therefore a separately authorized transition, never a
pointer rollback or implicit side effect.

The state-history row, hash-chained audit event, and current-generation pointer
commit atomically. Database effective time is authoritative for target runtime
ordering. Source effective time is retained as provenance and cannot schedule a
future enable or retroactively erase a committed disable fence.

## Admission and execution fence

Public build admission names a saved pipeline, not caller-supplied executable
source. Validation and planning may still accept unpersisted source, but they
mint no work. In one tenant transaction, admission locks and re-reads the saved
pipeline's current revision and operational history, rejects `disabled`,
compiles the saved revision with the submitted typed parameter values, and
persists the exact pipeline ID, revision, saved-revision semantic digest,
instantiated-build semantic digest, and enabled operational generation on the
build before creating any node or attempt. The two digests are intentionally
distinct when invocation parameters materialize different IR.

An admission idempotency lookup precedes current pipeline resolution. Exact
replays compile the original bound revision and return its durable admission
even after a later revision, disable, or re-enable. Reusing the key with
different parameters, platform, trust pool, or pipeline identity remains an
explicit conflict.

All manual, API, upstream, webhook, schedule, retry, replay, and administrative
trigger implementations must enter through that admission/fence primitive.
Future trigger classes cannot claim JOBSTATE-001 coverage merely by validating
state in an API handler.

The same definition row is the disable linearization fence for every later
authority boundary:

- scheduler claim and offer acceptance;
- automatic and manual retry materialization;
- protected-environment approval creation and consumption;
- credential-grant issue and delivery/redeem; and
- new external-effect checkpoint authority.

Each path locks and re-reads the current operational generation in the same
transaction that would mint or advance authority. It requires `enabled` and an
exact match with the generation recorded on the build. A disable that commits
first therefore yields no new queue row, offer acceptance, retry attempt,
approval, grant, or effect. An operation that holds the pipeline row lock first
must commit before the disable can become effective; this is the only allowed
race ordering. Schedulers exclude disabled, stale-generation, and unbound
builds before selection and repeat the check while claiming.

Disabling does not delete immutable history or pretend that already-observed
external reality did not occur. Reconciliation may record bounded evidence for
an effect that was authoritative before the fence, but it cannot create a new
intent, grant, approval, attempt, or effect authority after the fence.

## Public surfaces

The v1 API exposes current state and transitions under the saved pipeline:

- `GET .../pipelines/{pipeline_id}/state`;
- `PUT .../pipelines/{pipeline_id}/state`, with quoted `If-Match` generation and
  `Idempotency-Key`; and
- `POST .../pipelines/{pipeline_id}/builds`, with parameters only.

Pipeline reads include the current state summary. The CLI and browser UI use
only these public routes. Raw-source `POST .../projects/{project}/builds` is not
an admission compatibility alias; accepting it would preserve a state-bypass
path. API clients receive stable disabled, stale-generation, idempotency,
authorization, and not-found outcomes.

## Migration and rollback

The forward migration proves every pre-existing pipeline is enabled at
generation one and every old build is explicitly unbound. A package/canary
freeze records the exact current source revision and operational generation.
Import preserves the reviewed Jenkins state, source generation, effective time,
and provenance while advancing the McLoving generation monotonically.

Rollback is an explicit later transition whose provenance binds the exact
reviewed rollback package and source state. It never rewinds or deletes
McLoving history. A restored controller must reproduce the same current
generation and denial behavior before trigger or effect authority returns.
Active-active replicas rely only on PostgreSQL row/advisory locks and committed
history, not process-local caches.

## Required proof

Real-PostgreSQL tests cover existing-row backfill, new-pipeline generation one,
enabled and disabled imports, exact duplicate and divergent idempotency,
reordered/stale/future transitions, concurrent trigger/disable and
scheduler/disable orderings, restart and active-active reads, authorization
denial, audit linkage and immutability, unbound-build freeze, package/canary
generation drift, and exact rollback restoration. API, CLI, and UI tests prove
that no shipped client or route retains raw-source admission or a privileged
database shortcut.
