# AGENT-007 security review

Date: 2026-09-09

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

## What shipped

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

## Why retrying cannot duplicate work

The whole safety argument is the bound, and it is structural rather than
statistical.

The controller can hand this attempt to another runtime only through
`requeue_one_expired`, whose predicate is `lease_expires_at <=
clock_timestamp()`; the renewal statement in the same store requires
`lease_expires_at > clock_timestamp()`. While the lease stands, nothing else
can take the attempt. The agent's retry deadline is
`lease_started_at + lease_rpc_budget(lease_window)` — a term start taken
BEFORE the RPC that opened it was sent, plus the window less this codebase's
one-second margin — so it falls strictly before the instant the controller
could reclaim. `next_renewal_retry` never returns an instant past it and
returns `None` at it.

Two properties follow, and both are gated rather than asserted: the step never
outlives the lease that covered it, and the agent has stopped before the
controller could reclaim. The second is measured against the controller's own
`lease_expires_at`, read from the database so it survives the controller.

Agent sessions are a database table, so a session epoch survives a controller
process restart; that is what lets a renewal after the outage be accepted at
all, and it is pre-existing rather than introduced here.

## What a controller cancellation costs during an outage

A cancellation the controller issues while it is unreachable now reaches the
agent up to one lease later than it did before this change, because the agent
learns of cancellation through a renewal receipt. This is not a new contract:
the store already resolves a cancellation whose lease expired through
`requeue_one_expired`'s `cancellation_lease_expired` path, so cancellation
taking until lease expiry was already a state the controller handles. The
`cancel` scenario with a live controller is unaffected and still converges.

## What is proved, and by which gate

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

Every check is mutation-proved. Each mutation below was applied to a clean tree
and turned exactly the named test red, and no other:

| Mutation | Red |
|---|---|
| The whole fix reverted to its pre-ticket state | gates three and four |
| `next_renewal_retry` drops the lease bound | `a_renewal_retry_never_outlives_the_held_lease`; gate four then never cancels and times out at 40 s |
| Every status treated as unanswered | `only_an_answered_renewal_withdraws_authority` |
| An answered refusal keeps the old `renewal_transport_failure` name | `an_answered_refusal_is_named_as_one` |
| The retry cadence loses its one-second cap | `the_renewal_retry_cadence_is_bounded_on_both_sides` |
| The retry deadline drops the one-second margin | gate four's reclamation-ordering assertion, by 124 ms |
| `next_renewal_retry` drops the lease bound (again, against gate five) | gate five, which then never sees the lease lost and times out at 40 s |
| The deadline stops reserving the termination grace | `the_termination_grace_is_reserved_inside_the_lease` |
| The configuration rule stops counting the grace | `configuration_is_strict_and_does_not_embed_tls_material` |

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

## A third defect, also from review: cancelling is not stopping

The deadline reserved the one-second RPC margin and nothing else. But cancelling
an execution does not stop it: `terminate_and_prove_group_empty` in
`crates/agent-runtime/src/executor/unix.rs` signals the process group with
`SIGTERM`, sleeps the configured termination grace, and only then sends
`SIGKILL`. A workload that ignores `SIGTERM` therefore kept executing for that
whole grace AFTER the agent decided to cancel — at the shipped default, two
seconds past a deadline one second before expiry, so a full second past the
instant `requeue_one_expired` may hand the attempt to another runtime. The
setting has no upper bound, so the overrun is as large as an operator makes it.

This was reachable before the ticket only by accident, when a refused renewal
happened to land near expiry. The retry is what puts the cancellation
deliberately at the end of the lease every time, which is what turns an
incidental window into a structural one, so it is this ticket's to close.

The term now reserves the grace as well as the margin:
`lease_cancellation_deadline` subtracts both, so a workload signalled at the
deadline is dead before the lease expires even if it ignores `SIGTERM`. `SIGKILL`
cannot be ignored, so the executor's later bounded waits — for the leader to be
reaped, and for anchored descendants — are reaping time rather than time the
workload is still executing, and are not reserved.

Reserving the grace could otherwise leave no room for the renewal itself, so the
agent's configuration now refuses one where the renewal cadence plus the grace
does not fit inside the lease. The shipped defaults — a 30-second lease, a
5-second cadence, a 2-second grace — sit far inside it, and every configuration
in this repository was checked against the new rule before it landed: the
Windows persistent-agent lane (5 s, 500 ms, 250 ms), the deploy example, and
every test harness all fit. Both halves are mutation-proved: dropping the
reservation turns `the_termination_grace_is_reserved_inside_the_lease` red, and
dropping it from the configuration rule turns
`configuration_is_strict_and_does_not_embed_tls_material` red. That test also
asserts the accepting case, so the rule refuses a configuration rather than a
cadence.

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
authority, no protocol field, no schema, no configuration, and no trust
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

The first lease term is granted by the controller for the CONTROLLER's
`MCLOVING_LEASE_SECONDS`, while the agent measures that term against its own
`MCLOVING_AGENT_LEASE_SECONDS`; every later term is the agent's own value,
because the renewal request carries it. Where an operator configures the agent
a longer lease than the controller grants, the first term's deadline overshoots
by the difference. Both default to 30 seconds, the anchor fix above removes the
other half of the same error, and closing it properly needs either a protocol
field carrying the authoritative expiry or a configuration invariant — both
outside this ticket. It is recorded here so it is not rediscovered as a
surprise.

The lease deadline is computed from the agent's monotonic clock against a
controller expiry stamped from the database clock. The one-second margin
absorbs the round trip and ordinary skew; it does not absorb a pathological
clock. That margin predates this ticket and is unchanged by it.

The measured Jenkins comparison that motivated this work is exploratory: its
arms have no sealed provenance, and it is input to this ticket rather than a
receipt for it. Nothing here grants production or Jenkins authority.
