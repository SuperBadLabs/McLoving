# EXEC-001 retrospective security review

Date: 2026-08-30

`EXEC-001` closed in protected-main commit `5f9aa31` (PR #79). This review
examines the boundary exposed by the original failure: validation admitted a
100-step single stage that the execution spine could not run, then the agent
treated the permanent claim refusal as transient while the build appeared
`running` indefinitely.

The implemented control makes the compiler/admission choke point reject every
execution specification the spine cannot execute. The public validate and
admission paths share that compilation path, while claim-time unsupported
specifications produce a named terminal refusal rather than a retryable
session error. The regression gate constructs the original hundred-step shape
and a smaller two-step shape, verifies `unsupported_execution_spec`, and keeps
the one-step executable form admitted. This prevents a syntactically accepted
request from masquerading as durable progress when no executor can honor it.

The threat-model review covered parser/admission divergence, unbounded event
growth, scheduler denial of service, and ambiguous operator state. These are
instances of the existing compiler, controller-truth, scheduling, and agent
runtime boundaries; no new authority or secret path was introduced, so this is
an explicit reviewed no-change result for the threat register. The durable
terminal event and outbox copy remain transactionally coupled to the state
transition.

Residual risk remains bounded by the shared compiler: a future execution mode
added to only one path could recreate admission/runtime divergence. Tests must
continue to enter through the shared compile choke point, and claim-time
refusal remains a defense-in-depth terminal path. This receipt records a
retrospective security review of `EXEC-001`; it does not broaden supported
execution shapes or production authority.
