# AGENT-007 security review

Date: 2026-09-09

Status: **ACTIVE**. This is an implementation/review record. Protected final-head
checks, independent final review, normal merge and exact-main Foundation/native
Windows verification remain required before closure. Earlier measurements below
identify historical candidates; they do not certify the subsequent corrections.

`AGENT-007` makes the agent ride out a controller outage its own lease already
covers. This receipt records what was reviewed, what was measured, what is
proved by which gate, and what residual risk is accepted.

## The defect

`renew_lease` in `bins/agent/src/worker.rs` treated a renewal it could not get
an ANSWER to exactly as it treated one the controller REFUSED. A transport
error and an RPC timeout both recorded a lease loss, cancelled the running
execution, cancelled `authority_lost`, and ended the session. At shipped
defaults — a 30-second lease renewed every 5 seconds — that discarded about 25
seconds of authority the agent still held, on the first failure.

Measured on HeMan, 2026-09-09, against protected main `84705da`, production
remote-agent lane over mTLS. A single-step build was interrupted by `SIGKILL`
to the controller 4 s into a roughly 25-second step, with the agent process and
the step's own process untouched, and the controller restarted 3 s later. The
agent held a 300-second lease, so 296 s of it remained.

| Engine | Result | Runs | Step completions |
|---|---|---|---|
| McLoving `84705da` | `aborted` | 2/2 | 0 |
| Jenkins 2.568.3 | `SUCCESS` | 2/2 | 1 |

The agent named its own cause on stderr:
`lease_lost_during_execution: renewal_transport_failure; cancelling the running
step`. Because a controller restart is the ordinary shape of an upgrade, every
upgrade destroyed in-flight work.

`EXEC-004`'s receipt already recorded controller/database partition as an
accepted residual risk that "remains fail-closed and operator-visible". It was
fail-closed and it was visible; what it was not is necessary. This ticket
retires that residual.

## Candidate implementation (historical observations)

One distinction, applied in one place.

A renewal the controller ANSWERED still withdraws authority immediately and
keeps the cause it already reported: a session-epoch mismatch, an `accepted`
of false, a `renewal_rejected` or `renewal_session_stale` refusal. None of that
weakens by one case, and gate two of `bins/agent/tests/long_step_lease.rs` —
which denies a renewal at the controller — is unchanged in meaning and still
passes.

A renewal that produced no usable answer is retried instead, at the smaller of
one second and the agent's own renewal cadence, until the lease the agent holds
runs out. If it runs out, the step is cancelled under a cause distinct from
every answered refusal: `renewal_unanswered_until_expiry`.

`renew_lease` has four call sites — the executing path, the two
cancelled-before-spawn paths, and the recovered-finalization replay — and all
four get the same behaviour, each bounded by the lease window it was given
(`config.lease_seconds` for work, `RECOVERED_FINALIZATION_LEASE_SECONDS`, 30,
for replay). A finalization replay therefore also rides out a brief outage
instead of ending its session, which is the same property applied to the same
predicate rather than a second decision.

`renewal_went_unanswered` deliberately reuses `retryable_authority_transition`,
the predicate every other authority-bearing RPC in the same file already uses
to decide whether a status is worth another ask. The renewal task was the only
caller in the file that disagreed with it, and because the renewal task owns
`authority_lost`, its disagreement also tore down the retry loops of the log
publication and start-work paths. One vocabulary now covers all of them: those
paths are bounded by `authority_lost`, and the renewal task is bounded by the
lease.

## Termination reserve correction under review

Review of candidate `79107ee` found that its one-second margin bounded only the
cancellation signal, while Unix termination waits configured grace before SIGKILL.
Default grace is two seconds. Its gate timestamped a log emitted before the token
was cancelled; that observation did not prove process death. The former universal
no-duplication claim is withdrawn. Historical measurements remain below.

The correction reserves the entire configured termination grace plus one second
in the executing renewal deadline and clamps the periodic wake to that deadline.
Configuration must leave a positive usable interval before that reserve. Each
runnable assignment explicitly renews before spawning to establish the requested
term duration, since acceptance does not extend or report the controller's claim
lease. This adds one RPC even with folded acceptance negotiated; unsupported processless
refusals retain folded acceptance. Request-start anchoring and the shortened
acceptance-renewal timeout prevent a delayed receipt from manufacturing time.
The executor checks cancellation immediately before spawning, and Windows also
checks before resuming its suspended process; a native test cancels inside the
spawn hook and requires both absent workload output and terminated suspended child. Already-cancelled work is refused
without an executable workload and maps to a processless aborted outcome.

The corrected gates use a TERM-ignoring shell and descendant, default two-second
and configured four-second grace. They identify actual PIDs and Linux birth times,
read expiry from PostgreSQL after stopping the controller, and require both
process identities absent before expiry. Inspection errors fail the proof; the
absence timestamp follows inspection. Reclamation then requires a higher-fence
relief runtime to actually start, with the original workload already gone.
The returning runtime must report the actual validated `RetireStale` or
`DischargeRecovered` reply under `recovered_fence_refused`; which reply is
appropriate depends on the journal's durable containment proof. The old
`fenced authority is disowned` diagnostic was conditional on local
`ReconciliationRequired`, making its use as a universal return gate racy.
The original diagnostic is retained, and no protocol or state transition changes.
Fixture cleanup guards target only observed identities, including assertion
unwind, and relief work is cancelled and observed quiescent before agent stop.

These are bounded Linux process-supervision observations, not hard real-time
promises under arbitrary host scheduling, uninterruptible kernel I/O or hostile
same-UID interference. SEC-005 containment remains separate. Validation results
for the corrected source will be recorded after execution; historical green
checks below do not verify this correction.

## What a controller cancellation costs during an outage

A cancellation the controller issues while it is unreachable is learned through
a later renewal receipt; if none arrives, the agent begins termination at the
reserved execution deadline. Its delay remains bounded by the held term, with
termination grace reserved before expiry rather than added after it. This is not a new contract:
the store already resolves a cancellation whose lease expired through
`requeue_one_expired`'s `cancellation_lease_expired` path, so cancellation
taking until lease expiry was already a state the controller handles. The
`cancel` scenario with a live controller is unaffected and still converges.

## Historical gate observations before the termination-reserve correction

Two integration gates were added to `bins/agent/tests/long_step_lease.rs`.
Both deny the NETWORK — the controller process is killed outright while the
step's own process keeps running — rather than denying the renewal, because
denying the renewal exercises the answered path this ticket does not change.

- Gate three: an outage shorter than the held lease changes nothing. The build
  succeeds, the step's output survives, there is exactly one terminal outcome,
  and no `attempt.lease_expired` or `attempt.lease_renewal_rejected` event is
  recorded. It also asserts the MECHANISM and not only the outcome: the agent's
  stderr must show that the renewal task saw the outage (`renewal_unanswered:`)
  and recovered on the same lease (`renewal_answered_again:`), and must not name
  a lease loss. Asserting success alone would pass equally well if the outage
  had never reached the renewal task.
- Gate four: an outage the controller never returns from cancels the step,
  names `renewal_unanswered_until_expiry`, does so no sooner than five seconds
  into a ten-second lease — the defect cancelled at about one second — and no
  later than the lease itself, and finishes at or before the controller's
  recorded `lease_expires_at`.
- Gate five, added on review: what happens on the far side of that instant.
  The controller returns only after the lease has lapsed, a SECOND enrolled
  runtime claims the requeued attempt at a higher fence, and the original agent
  then comes back with its journal still holding the work at the fence it lost.
  It must move nothing — same fence, same lease owner, no terminal event — and
  it must be told why: its recovered-attempt report is answered with the
  `EXEC-003` discharge disposition and it records `fenced authority is
  disowned`. Asserting only that nothing bad happened would pass equally well
  if the agent had never come back at all.

Four unit tests cover the pure decisions: which statuses are answers, how an
answered refusal is named, the retry cadence bound, and the retry deadline.

The earlier candidate reported the following mutation runs. They predate the
termination-reserve correction; the timing-log assertion was insufficient to
prove process death and is replaced above. These historical observations do
not certify the current source:

| Mutation | Red |
|---|---|
| The whole fix reverted to its pre-ticket state | gates three and four |
| `next_renewal_retry` drops the lease bound | `a_renewal_retry_never_outlives_the_held_lease`; gate four then never cancels and times out at 40 s |
| Every status treated as unanswered | `only_an_answered_renewal_withdraws_authority` |
| An answered refusal keeps the old `renewal_transport_failure` name | `an_answered_refusal_is_named_as_one` |
| The retry cadence loses its one-second cap | `the_renewal_retry_cadence_is_bounded_on_both_sides` |
| The retry deadline drops the one-second margin | gate four's reclamation-ordering assertion, by 124 ms |
| `next_renewal_retry` drops the lease bound (again, against gate five) | gate five, which then never sees the lease lost and times out at 40 s |

The reverted-tree run is the strongest of these: it reproduces the campaign's
finding exactly, gate three failing with `"aborted"` and a terminal summary of
`lease_lost_during_execution:renewal_transport_failure`, and gate four failing
because the agent cancelled about a second into the outage under a cause naming
a refusal the controller never made.

The measured scenario was then re-run against the fix with release binaries,
using the same campaign harness that produced the original finding:

| Scenario | Before | After |
|---|---|---|
| Controller killed mid-step, agent and step survive | `aborted`, 0 step completions, 2/2 | `succeeded`, 1 step completion, 4/4 |
| Controller and agent both killed | `aborted` in 8.4 s | `aborted` in 8.3 s, unchanged |
| Cancellation with a live controller | `aborted` | `aborted`, unchanged |

The controller-killed cell was run twice on the fix alone and twice more after
`JCOMP-002B` was merged in, because that change rewrote much of the same file;
all four succeeded, in 24.5 to 24.7 s against Jenkins' 25.4 s on the same
scenario.

`step_starts` is 1 and `step_completions` is 1 in the repaired controller
scenario: the step ran exactly once. Riding out the outage did not re-run it.

## A second defect, found by review, in the anchor the bound rests on

The retry's whole safety argument is that the agent's deadline falls before the
controller's `lease_expires_at`. Review found the anchor that deadline is
measured from was not conservative enough to guarantee it.

The controller stamps `lease_expires_at` while a request is IN FLIGHT —
measured in `crates/controller-store/src/scheduler.rs`, at the claim and again
on each renewal, and **never on accept**. The agent was re-anchoring each term
at the instant the ANSWER arrived. Anchoring on receipt puts the agent's
deadline later than the controller's by the round trip, so a round trip longer
than the one-second margin makes the deadline fall AFTER the attempt becomes
reclaimable. Before this ticket that gap was mostly theoretical because a
failed renewal cancelled at once; the retry is exactly what turns it into
running time.

Two anchors moved. Each renewed term is now measured from the instant its own
request left, carried out of the retry loop with the receipt. And because
accepting does not extend the lease, the accept path now anchors on the branch
that actually re-stamped it: where the negotiated accept receipt answered
without a renewal, the term is still the claim's and the anchor is
`claimed_no_later_than` — captured before the poll RPC was sent, which the
codebase's own `accept_consumed_claim_lease` already treats as the true claim
anchor; where the serialized renewal did run, the anchor is the instant before
that RPC.

`recover_finalizations` already took its anchor before its renewal RPC and is
unchanged.

**This one is not mutation-proved, and that is stated rather than papered
over.** The anchor is a call-site choice, so no unit test here fails if a call
site picks the wrong instant, and the integration ordering assertion only
catches it when a round trip exceeds one second — which it does not on this
host or on a CI runner. Injecting that latency would need a controller test
hook, which is a controller change this ticket excludes. What is committed
instead is the arithmetic, as an executable test
(`a_lease_term_anchored_on_receipt_can_outlive_the_controller`) that fails if
the numbers stop supporting the reasoning, plus the reasoning recorded at both
call sites.

## One harness defect found and fixed here

The first draft of both gates waited for `lease_owner` before killing the
controller. `lease_owner` is set when the attempt is OFFERED, which is before
the agent has accepted the work and started renewing it, so the kill landed in
the accept path rather than the renewal path and the attempt then sat
leased-but-unaccepted until its claim lease expired. Gate three failed on an
`attempt.lease_expired` event that had nothing to do with the property under
test, while the build still succeeded — a gate that was red for the wrong
reason, one edit away from being green for the wrong reason. Both gates now
wait for the `attempt.running` event, and the reason is recorded beside the
helper.

## Threat-model review

Reviewed against `TM-003`, "stale lease or certificate holder publishes as
another agent after fencing", which owns this boundary, and against the
cancellation and reconciliation boundaries the renewal task participates in.

No register row changes and no new row is required. The change adds no
authority, no protocol field, no schema, and no trust
relationship. It narrows when the agent CEASES to use authority it already
holds, and narrows it towards, never past, the instant the controller's own
predicate would let that authority be taken away. The fencing checks
themselves — session epoch, fence token, certificate binding, and the
`accepted` refusal — are untouched, and a renewal that is answered with any of
them still cancels immediately.

The window in which the agent will keep executing without a fresh answer grew
from one renewal interval to at most one lease term. That is the intended
change and it is bounded by the same value the controller uses, but it is
stated here plainly because it is the property a reviewer should attack.

## Corrections to the record

`renewal_transport_failure` can no longer be a lease-loss cause: every status
it named is now retried. The name was also inaccurate for the answered
refusals it covered — a `PermissionDenied` is not a transport failure — so
answered refusals other than the stale-session one are now named
`renewal_refused`. The separate `renewal_timeout` cause is likewise gone; a
renewal that hangs until the lease deadline now ends in
`renewal_unanswered_until_expiry` alongside repeated unreachability, because
an operator cannot act differently on the two.

The board ticket for `AGENT-007` quotes the old `renewal_transport_failure`
string as the observed symptom. That quotation remains correct as a record of
what was measured on `84705da`.

## Residual risks

A controller that answers with `Internal` — a controller-side store failure
rather than a refusal — is now retried rather than treated as lost authority.
This is deliberate and consistent with every other RPC in the file, and it is
bounded by the lease, but it does mean a step survives a controller whose
database is failing for up to one lease term.

A cancellation issued during an outage lands up to one lease later, as recorded
above.

The first-term controller/agent lease-length mismatch found in `79107ee` is
corrected for runnable assignments by explicit pre-spawn renewal. Gate four
uses a five-second controller claim and ten-second agent term to exercise this
boundary. Unsupported processless refusals spawn no workload and retain the
folded acceptance path. Configuration now rejects a renewal cadence that
cannot leave the configured termination reserve.

The lease deadline is computed from the agent's monotonic clock against a
controller expiry stamped from the database clock. The one-second margin
is additional to request-start anchoring and termination grace; it does not
absorb a pathological clock or unbounded host scheduling delays. That margin predates this ticket and is unchanged by it.

The measured Jenkins comparison that motivated this work is exploratory: its
arms have no sealed provenance, and it is input to this ticket rather than a
receipt for it. Nothing here grants production or Jenkins authority.

## Working-source correction validation

These observations describe the uncommitted correction based on PR132 head
`79107eeda8a02ceddad52329c9b677986f2474a7`; they do not invent an executing
commit or substitute for final exact-head CI. The chief retains raw logs,
source patches and SHA-256 inventory in the local mission evidence directory.

The agent's 63 unit tests, the new Unix already-cancelled spawn regression,
focused agent/runtime clippy with warnings denied, formatting, and the four
board/closure verifiers and parser tests passed. The board remains at 116
tickets, 90 DONE, 26 remaining, 35 receipted, 34 reviewed and historical debt
37. AGENT-007 remains ACTIVE without closure attribution.

An initial five-test real PostgreSQL controller/agent run passed. A subsequent
run passed both actual-process death checks but failed the old returned-agent
diagnostic assertion. Repeated runs also exposed globally reused session IDs;
adding UUIDs exposed OpenSSL's common-name length limit. The final harness uses
short independent UUID identities and waits for the actual validated recovery
reply. Source inspection establishes the old diagnostic's dependency on local
reconciliation outcome; session reuse alone was not proven to cause its failure.
Those failed runs are retained rather than relabeled as successful evidence.

The final isolated five-test run passed in 57.23 seconds, including actual
leader/descendant quiescence about 0.99 seconds before stored expiry for both
two-second and four-second grace, the five-second controller/ten-second agent
term mismatch, explicit recovery refusal and relief cleanup. Removing only the
active execution grace reserve made the actual-process expiry gate fail as
expected (exit 101). The corrected working-source patch SHA-256 is
`0e887e4e7679da1ac6bc5726427effca2786b873debdda935f65ccff4deaddba`;
the mutation patch SHA-256 is
`c7768647dfdffc2710b6329e31fdfe03b83696f22ea69d9132c9691b1fdab12b`.
Both apply to the stated base and are retained with the raw logs. The final
isolated run also fixed a hardcoded old agent-name assertion exposed by UUID
identities; its earlier failed run remains retained. The new Windows
suspended-child test remains pending actual native execution; a Linux compile
or source review does not certify it.

## Reconciliation with the concurrent PR correction

The integration is based on author head
`83a70538d74eb609e7fed1a50e13f829f639f86c`, which independently added
termination-grace reservation and configuration checks. It retains the author's
named `lease_cancellation_deadline` helper and focused grace/configuration
regressions, using the same shared budget arithmetic as configuration and
pre-spawn admission. Processless replay/refusal controls reserve zero process
termination grace because no workload runs; their finite authority window is
unchanged. The actual-death, initial-term, pre-spawn cancellation, recovery
diagnostic and truthful ACTIVE bookkeeping corrections supplement that commit.
The isolated working-source observations above are inputs to review, not
exact-head validation of this reconciled source.

The reconciled working source passed 64 agent unit tests (including the author's
retained grace test), focused agent/runtime clippy with warnings denied, and all
four board/closure verifiers and parser suites. An independent reviewer found no
actionable issue in either the isolated correction or its integration delta.
Full Foundation and actual native Windows remain required on the final head.

## Pending-response correction after e9f257f review

The `e9f257f` candidate passed local Foundation and the separately profiled
source-acquirer suite; its native Windows CI also executed both newly added
cancellation tests successfully. Those observations bind that historical head.
A subsequent independent P1 review found a renewal RPC could remain pending
until the entire held cancellation deadline, preventing another ask from
observing controller recovery. Those green checks did not cover this case.

That correction made each periodic renewal RPC expire at the earlier of its request-start time
plus the retry interval and the unchanged held cancellation deadline. Time
spent awaiting that RPC counts toward the retry cadence; timeout does not add
another full sleep. Only a validated successful receipt establishes a new term.
Deadline-exhaustion branches honor a concurrent stop of already-finalized work,
consistent with the existing failure paths.

Two real tonic transport tests call the production renewal loop. One peer
leaves its first HTTP/2 request unanswered and accepts its next request; the test
requires that next request before the original deadline and preserved authority
after that deadline. The other peer leaves every response pending and requires
multiple requests, eventual cancellation at the original bound, the distinct
unanswered-expiry cause, and no request after that bound. These are transport
regressions, separate from the five actual PostgreSQL/controller/agent gates;
they do not claim actual process containment by themselves. Final corrected-head
local and protected CI evidence must be earned separately before closure.

## Healthy response allowance follow-up after main aaa3778

PR132 merged as `aaa3778` with the reviewed tree and successful exact-PR-head
checks. The subsequent main Controller PostgreSQL job failed the existing
`remote_work` transaction budget: the trivial build succeeded, but its measured
tenant transaction starts were 33 against the unchanged limit of 25. The job
logged pending-response timeouts and recovery after six unanswered requests.
The fixture configures a 100ms renewal cadence; using that cadence as the RPC
response allowance cancels healthy replies taking longer than 100ms and can
create unnecessary transaction starts. The log does not identify which of the
extra starts occurred inside the measured window, so it is not an exact
per-request attribution or evidence of a fencing failure. The five lease gates
were not reached in that failed main job. Closure and JCOMP-003 remain blocked.

The bounded follow-up gives every renewal ask a one-second response allowance,
still capped by the unchanged held cancellation deadline. Retry scheduling
continues to count elapsed RPC time toward the configured cadence. A fast
cadence therefore does not imply an equally short allowance for an otherwise
healthy response; a genuinely stalled ask still cannot consume the whole term.
The 25-transaction budget is unchanged.

A new real tonic test configures 100ms cadence and a healthy 200ms response.
It requires exactly one request before that first response and continued
validated authority beyond the original term. The existing actually stalled
recovery and all-stalled expiry tests remain in place. Final follow-up source
review, exact-head local/CI validation and successful exact-main Foundation plus
actual native Windows execution must be earned before closure.
