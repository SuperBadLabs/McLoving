# Typed trigger ingress v1

Status: TRIG-001 implementation contract. Production trigger authority, canary,
cutover, rollback, and decommissioning remain gated by their own execution-board
tickets and exact population evidence.

## Boundary and eligibility

Every non-manual trigger enters through one authenticated, tenant-scoped public
API and one PostgreSQL delivery state machine. A trigger generation binds the
organization, project, saved pipeline, trigger kind, implementation digest,
canonical configuration and filter digests, exact event-source identity, source
generation, replay/deduplication window, delivery expiry, retry budget, actor,
reason, idempotency key, and hash-chained audit event.

The closed trigger-kind schema is:

- `scm_webhook`, with an exact configured provider and repository identity plus
  revision, branch, path, and event filtering;
- `schedule`, with timezone, calendar/tzdata identity, expression, exact
  resolver and schedule identities, a bounded pre-resolved slot set, and a
  durable watermark;
- `upstream`, with exact upstream pipeline/build identity and result filtering;
- `remote_api`, with exact authenticated caller, audience, request identity,
  method, and event filtering; and
- `plugin`, which is typed but currently always rejected because no
  plugin-specific source implementation in the sealed production denominator
  has earned an admission receipt.

Unknown fields, filter classes, kinds, and plugin sources fail closed. The
generated trigger request contract declares the exact Rust `int32` or `int64`
transport width and runtime bounds for every integer field. Filter arrays
accept any ordering while requiring unique, bounded string values. The
sealed Mario inventory names `hudson.triggers.SCMTrigger` and
`hudson.triggers.TimerTrigger`, but does not preserve the schedule expressions,
Jenkins hash inputs, algorithm/version, timezone, or resolved slots required to
prove `H` equivalence. Those production TimerTrigger declarations remain
ineligible. Trigger ingress v1 unconditionally rejects expressions containing
`H`; even supplied metadata cannot substitute for an installed, differentially
certified Jenkins hash resolver. It does not invent a stable-but-different hash.

## Configuration generations

Configuration writes require project-configure authorization, quoted
`If-Match`, and `Idempotency-Key`. Writers serialize on the saved pipeline row.
An exact concurrent retry returns the original generation; divergent key reuse
is a conflict; stale/future generation is a precondition failure. Every revision
is append-only and the current pointer advances exactly one generation.

`paused` is a trigger state, not deletion. It rejects new delivery capture and
new delivery claims. Resume is a separately authorized monotonic generation.
Event-source rotation changes the exact caller identity and immediately rejects
new input from the old identity. An already accepted event remains immutable and
can be exactly replayed against its original trigger generation after later
configuration, filter, pause, or caller changes.

## Durable delivery state machine

An event request names its exact trigger generation, delivery ID, event ID,
event kind/time, typed source payload, parameters, platform, and trust pool.
Capture canonicalizes and hashes the payload, rechecks the configured source
identity and filter, enforces bounded past-replay/future-skew windows, locks the
current trigger and pipeline operational state, and inserts one `pending`
delivery plus its audit event. Delivery and event IDs are each unique per
trigger. Exact response-loss replay returns the original record; either ID
reused for different input is a conflict. Every configuration, acceptance,
claim, redrive, and quiesced-export transaction first takes the same
organization/trigger advisory lock. That common outer scope makes trigger,
delivery, and pipeline row-lock ordering acyclic and supplies missing-key
serialization before a delivery or event identity exists. First acceptance
then repeats the ID lookup, so concurrent active-active acceptance returns one
creation plus one exact replay rather than leaking a database uniqueness
failure. Signed integers are explicitly limited to the complete `int64` range
in both the generated contract and runtime.

Parameter names are limited to 1-256 ASCII letters, digits, underscores, or
hyphens. Values are limited to 128 bounded booleans, signed integers, or strings,
and both names and values are rejected before durable HTTP capture. Processing
repeats that closed validation after claim so legacy or corrupt stored values
consume one terminal failed attempt, release their lease, and cannot abort a
bounded retry scan or starve valid work. Any resulting persisted failure reason
is control-free and truncated on a UTF-8 boundary to the store's 2,048-byte
limit. The generated API contract exposes the same name pattern, value union,
count, and string bound.

Each kind also has a closed payload field set. SCM repository identity must
equal the configured repository, not merely share an installation credential.
An explicitly empty path-prefix list is a no-op and does not require the
optional SCM `paths` payload; a non-empty list requires paths and at least one
prefix match. When `paths` is supplied under either filter form, both the API
and durable store still require at most 128 canonical, non-empty, bounded string
entries; a no-op filter never turns malformed payload data into accepted truth.
For remote API ingress, the signed/request payload's `request_id` must equal the
durable `event_id`, so the caller cannot mint duplicate work for one logical
request by rotating transport identifiers.

New acceptance and explicit redrive acquire every later blocking row lock,
including the organization-wide audit head, before sampling PostgreSQL time.
The acceptance timestamp and delivery TTL are derived from that authority, and
the replay/skew window compares event time with the same sample; neither a
controller clock nor audit-head contention can create an already-expired
delivery or extend its lifetime.

Processing requires a bounded PostgreSQL lease with a monotonically increasing
claim fence. Claiming acquires the delivery, trigger, pipeline, and audit-head
locks before sampling PostgreSQL time to decide durable due time, delivery TTL,
and whether the current lease is live, and derives the new expiry from that
same clock plus the bounded requested duration. Due-work enumeration uses
PostgreSQL time as well.
Active-active workers converge
on one claim even when controller wall clocks differ. A stale worker cannot
complete or fail a newer claim. Failure transitions hold both the delivery and
later audit-head lock before resampling PostgreSQL time, derive retry due time
from the requested bounded delay, and return typed lease loss without failure
accounting when the claim has expired. Admission conditionally binds only while
the matching claim lease is still live according to the PostgreSQL clock.
Atomic DAG admission enters the shared pipeline advisory scope before the
exact enabled pipeline-definition row and organization audit head. This matches
ordinary admission, pipeline-state transitions, and different-trigger paths
that read the definition before auditing. It then performs its final
delivery-TTL and claim-lease sample before staging any DAG row. This avoids both
advisory-pipeline/audit and definition-row/audit lock cycles, and a later audit
append cannot introduce a blocking interval after the last authority decision.
Processing enters the JOBSTATE-001 saved-pipeline
admission primitive using a controller-derived safe idempotency key. DAG rows,
attempts, outbox publication, and the immutable delivery/build binding commit in
one PostgreSQL transaction. DAG construction runs inside a savepoint; the store
samples the database clock after all DAG rows are staged. If the delivery TTL
or claim lease is then expired, the savepoint rolls back every runnable build
row. Delivery expiry is terminally dead-lettered; claim expiry leaves the
delivery retryable for a newly fenced worker and returns a typed lease-lost
outcome that does not enter admission-failure accounting or spend retry budget.
A crash therefore leaves either
no build and a retryable claim transaction, one expired dead letter and no
build, or one admitted delivery bound to its exact build—never an orphaned
runnable build or an unbound duplicate-redrive path.

Trigger DAG keys occupy the reserved `mcloving-trigger-v1-` namespace. The
ordinary build API rejects that prefix and the ordinary store admission method
enforces the same reservation; only the trigger transaction can enter the
internal DAG primitive with such a key. The replay path can only validate and
return an already-existing exact trigger DAG; it cannot create one. A caller
therefore cannot pre-create a normal build that trigger delivery processing
later mistakes for its replay.

The durable states are:

- `pending` — captured and immediately claimable;
- `retry_wait` — a retryable failure with a future due time;
- `admitted` — terminal and immutably bound to one build; and
- `dead_lettered` — terminal with a bounded reason.

Attempt count, retry due time, expiry, and the original trigger generation are
durable. The shipped controller continuously enumerates bounded due work for its
organization from PostgreSQL; active-active scans may overlap, but claim fences
converge them on one worker. It samples the clock again before each claim, so a
slow batch cannot admit a later delivery using a stale pre-expiry timestamp or
write an already-expired lease. A failed admission samples the clock again when
deciding expiry and the next retry time, so admission latency cannot shorten the
retry delay or preserve already-expired work. Thus an upstream 202 does not make
source-side redelivery responsible for controller retries. Expired or exhausted work
dead-letters. A dead letter is never mutated back to pending. Project-configure
redrive creates a new delivery/event identity with immutable lineage and
ordinal, then enters the same claim, admission, and operational-state fence.
The common trigger scope serializes all first-redrive identity decisions and
repeats the new-ID lookup, so concurrent exact redrive returns one creation plus
one replay, while different source dead letters racing to reuse an identity
return one creation plus one explicit conflict. A paused trigger or disabled
pipeline rejects recovery before work is minted.

## Schedule capture and restart

The authenticated scheduler submits one exact resolved slot. The request binds
timezone, calendar/tzdata identity, original expression, schedule identity,
expected prior watermark, and resolved Unix-millisecond slot. The slot must be a
member of the digest-verified configured slot set. Configuration-time timezone
and calendar values use the same 128-byte canonical bound as the durable
watermark, so an accepted generation cannot become unusable only at capture.
The generated contract marks `resolved_slots_unix_ms` with the machine-visible
`x-mcloving-ordering: strictly_increasing` extension and a matching description;
the slot digest binds that exact ordered array.

Watermark advancement and delivery insertion commit in the same transaction.
A deferred foreign key requires the watermark's delivery ID to exist at commit,
so a crash cannot skip a slot by persisting only the cursor. The watermark is
strictly monotonic per trigger generation; duplicate, reordered, substituted,
or stale-expected slots fail closed. A restarted or active-active controller
reads the same PostgreSQL watermark. A new schedule configuration gets a new
generation-specific watermark while older generations remain immutable for
replay and transfer evidence.

## Operational-state and authority fence

Capture and every later claim lock and re-read the current saved-pipeline
operational state. A committed disable rejects webhook, schedule, upstream,
remote, retry, replay-to-new-work, and redrive paths before queue or build
materialization. Exact replay of an already terminal admission remains readable
and cannot mint a second build. Trigger pause and pipeline disable are distinct,
audited fences.

The trigger controller holds no connector, deployment, workload-secret, or
production-effect grant merely because it captured an event. Downstream build
and effect authority remains governed by its own tickets and fences.

## Public API and transfer truth

The generated OpenAPI contract exposes:

- `GET/PUT .../pipelines/{pipeline}/triggers/{trigger}`;
- `POST .../triggers/{trigger}/events`;
- `POST .../triggers/{trigger}/deliveries/{delivery}/redrive`;
- `GET .../triggers/{trigger}/webhook`, the GitHub hook path and its derived
  secret (project configuration authority); and
- `POST /api/v1/webhooks/github/{organization}/{project}/{pipeline}/{trigger}`,
  the public GitHub receiver described below.

## GitHub webhook receiver (PAR-001)

A GitHub-provider SCM webhook trigger may be fed directly by GitHub. The
controller holds one webhook key (`MCLOVING_WEBHOOK_KEY_FILE`, an
owner-private file of at least 32 bytes, secret-class in the deployment
contract); each trigger's hook secret is `HMAC-SHA256(key, organization ||
project || pipeline || trigger || source_generation)` under a domain
separator, derived on demand and never stored, so rotating the trigger's
event source rotates the secret and nothing retains it. The key file is
opened without following symlinks and the deployment guard refuses a
symlinked path ahead of the binary. An operator reads the
path and secret from `GET .../triggers/{trigger}/webhook` and pastes them
into GitHub; a controller without a key answers not-found on both routes.

The receiver takes no bearer. It requires `X-GitHub-Delivery`,
`X-GitHub-Event` and `X-Hub-Signature-256`, resolves the trigger (which must
be an enabled or paused `scm_webhook` trigger whose configuration names
provider `github`), and verifies the signature over the raw body in constant
time before it interprets anything; a forged or unsigned delivery is refused
with 401 and leaves no receipt. The body is bounded at GitHub's own 25 MiB
payload maximum, so no delivery GitHub can send is refused unread, and the
route holds at most eight deliveries in flight, the permit taken before any
body is buffered, so an unauthenticated sender can pin at most eight bodies
in memory; a saturated route answers 503 `webhook_busy` with `Retry-After`
and reads nothing, and the refused delivery is redeliverable. The OpenAPI
operation `receiveGithubDelivery` declares the three headers, the
`GithubDelivery` body and the 200/201/202/422 answers. The secret-bearing
`GET .../webhook` answer is marked `Cache-Control: no-store`. A `push` to a
branch maps to the SCM payload `repository_identity` (the repository's
`full_name`, which the trigger's `repository_identity` must equal),
`revision` (`after`), `branch` (the ref without `refs/heads/`) and `paths`
(the union of the commits' added, modified and removed paths, omitted when it
exceeds the 128-path payload bound or when the payload lists fewer commits
than the push's advertised `size`, so a path filter can match neither an
unbounded nor a partially known change); a `pull_request` `opened`,
`synchronize` or `reopened` maps the head sha and head ref the same way. The
delivery id is both the delivery and the event identity. When the saved
pipeline declares public string parameters named `revision` or `branch`, the
delivery supplies them, which is how a checkout step takes its commit from a
push.

Admission then runs the same path as the bearer route with the trigger's own
`event_source_identity` as the caller, but receipt-timed: the ledger assigns
the event time from the database clock inside its serialized acceptance, so
one delivery id gets one time however many controllers receive it and no
controller clock can push a legitimate delivery outside the skew window; and
a redelivery is matched on the authenticated delivery alone (ids, kind,
caller, canonical `{event_kind, payload}`, platform, trust pool), never on
the trigger generation or the parameters current at redelivery, so a trigger
revision or a pipeline parameter change after acceptance does not turn an
exact redelivery into a conflict. For the same reason a delivery id the
ledger already holds is replayed before the trigger's current pause state
and filter are applied: those describe new input, and a paused trigger or a
narrowed branch filter must not turn an accepted delivery's redelivery into
a refusal or a `filtered` acknowledgement. Created deliveries answer 201 with the
build admission, exact redeliveries answer 200 with the same build and mint
nothing, and a reused delivery id with a different authenticated body is a
409 `trigger_ingress_conflict`. Deliveries that authenticate but are not
admitted, a tag push, a branch deletion, a `ping`, an unsupported event or
action, or an event the trigger's filter refuses, answer 202 with
`{"status": "ignored" | "filtered", "reason", "delivery_id"}` so GitHub
reports the hook healthy, and each is recorded as a
`trigger.delivery_unadmitted` audit event under the event-source identity
and as a `webhook_receipts` row (event header, body digest, status, reason)
rather than as a delivery row. A delivery id's first authenticated decision
is durable: admitted ids live in `trigger_deliveries`, unadmitted ids in
`webhook_receipts`, both written under the trigger lock with each write
refusing an id the other holds across both the delivery and the event
identifier namespaces (acceptance checks receipts on every path and timing,
the bearer route included), so two concurrent first deliveries cannot be
decided twice; a receipt carries the trigger generation whose filter and
state decided it and is refused under the lock if the trigger was revised
meanwhile, so a stale decision never bars an id from admission under the new
filter; a repeat of an unadmitted delivery with the same event header
and body answers the recorded acknowledgement again without a second audit
record, and a repeat with a different header or body, or an admitted id
re-sent under an inadmissible event (the signature covers the body, not the
event header), is a 409 `trigger_ingress_conflict`. An admitted delivery
replays under the caller identity it was recorded with, so rotating the
trigger's event-source identity does not turn its redelivery into a
conflict. To run an event that was filtered under a narrower filter, push
again or use the bearer route.

Trigger configuration is a `kind`-discriminated union with separate closed SCM,
schedule, upstream, and remote API variants and their exact required fields.
Event payload is likewise a four-variant closed union with the exact required
SCM, schedule, upstream, or remote API shape. The rejected plugin class is not
advertised as an admitted request variant. Event and redrive operations bind
200, 201, 202, and terminal 422 responses to the same closed
`TriggerEventResponse`, so a generated client retains the durable delivery,
dead-letter reason, and optional build admission for every normal outcome.

The database ledger is the transferable source of truth: append-only trigger
versions, unique event/delivery deduplication records, pending/retry/dead-letter
sets, admitted build bindings, claim fences, redrive lineage, and
generation-specific schedule watermarks, and the webhook receipts of
deliveries authenticated but not admitted (schema 2), so a delivery id
decided at the source stays decided at the destination. The quiesced transfer
snapshot also binds every trigger version's actor, reason, idempotency key,
audit sequence and event hash; every accepted delivery's audit sequence and
event hash; every webhook receipt's audit sequence; and the handoff export
audit event into one domain-separated state digest. Verification
recomputes a separate exact-ledger digest and requires it in the hash-verified
handoff audit event. Its caller must also supply that event hash from an
independently retained audit export or chain head; the snapshot cannot establish
its own trust anchor. Therefore, changing ledger state and recomputing the
ledger, audit-event, and snapshot hashes cannot preserve the independent audit
commitment. Verification
rejects missing lineage, duplicate identifiers, active claims, unlinked
watermarks, watermarks linked to a delivery from the wrong generation or
resolved slot, stripped provenance, or any state substitution. A later CUTOVER-001
or ROLLBACK-001 transaction must quiesce ingress and transfer/reconcile that
complete set under the exact implementation/configuration digests. This ticket
does not itself switch any production authority.

Quiesced export holds the common trigger scope and paused definition lock. It
clears only claims whose lease is already expired according to the PostgreSQL
clock, then rejects any genuinely live claim. Thus a crashed worker cannot
strand handoff forever, while pause cannot steal an active lease.

## Required proof

Real-PostgreSQL tests cover concurrent configuration idempotency, configuration
versus claim lock ordering, active-active claims, exact/divergent delivery
replay, delayed/future input, bounded outage retry, attempt exhaustion,
exact-source and conflicting-source dead-letter redrive, stale claim denial,
parameter pre-capture and corrupt-store terminal failure, completion-time
delivery/claim expiry with zero persisted DAG and unchanged retry budget,
database-clock acceptance/redrive TTL, claim TTL/lease issuance, and expired
failure-claim rejection under deterministic audit-head contention, atomic DAG
admission lease loss under the same contention, pathless SCM events plus
malformed supplied-path denial under an empty path-prefix filter, schedule
watermark configuration bounds, bounded parameter names and failure reasons,
pipeline-advisory/audit and cross-trigger pipeline-definition/audit ordering,
due/retry/claim ownership under
controller-clock skew, reserved
trigger-DAG idempotency namespace denial, unordered filter
membership, expired-claim handoff reaping, caller rotation,
pause/resume, disable fencing, restart, atomic schedule
watermark, slot reorder/substitution, upstream success/failure, unsupported
plugin denial, RLS/forced-RLS migration, and audit linkage. Public API tests
cover missing and cross-tenant authorization, configuration preconditions, SCM branch/path
filtering, durable admission, generation-bound replay after configuration
rotation, stale-generation denial, kind-discriminated generated schemas, and
the generated route contract. Concurrent first-acceptance coverage proves one
created delivery and one replay rather than a uniqueness error; the handoff
tamper test changes ledger content and recomputes the ledger, embedded audit
event, and snapshot digests, but is still rejected by the independently retained
audit hash. Concurrent first redrive proves one creation plus one replay, and
different dead letters racing to reuse the same new identity prove one creation
plus one conflict. The deployable-controller suite also
proves the runtime role's exact least-privilege and 60-table forced-RLS policy
surface before accepting traffic.
