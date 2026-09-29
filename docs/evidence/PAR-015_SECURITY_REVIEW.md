# PAR-015 closure receipt: build workspace affinity

Ticket: `PAR-015`. Implementation lands workspace affinity for product
multi-stage builds so later stages pin to the agent that ran the first stage
and reuse that build's on-disk workspace.

## What merged

- Migration `0043` adds `builds.workspace_affinity_agent_id`.
- Product multi-stage admission requires `workspace-affinity-v1` on every
  stage; Windows multi-stage submissions are refused at admission.
- Scheduler offers affinity successors only to the pinned agent; ready
  successors whose agent has no live affinity-capable session fail the build
  with `workspace_affinity_agent_gone` rather than being offered blind.
- First-stage success pins the agent. Work assignments carry
  `WorkspaceAffinityGrant` (`create` / `reuse`, `retain_on_success`).
- Linux agents negotiate `build-workspace-affinity-v1`, materialize
  `{organization}/{build}/workspace`, retain on success while later stages
  remain, and strip only `spool/` on reuse.
- Bounded checkpoint transfer keeps its caps and stays mutually exclusive with
  affinity. Contract: `docs/architecture/BUILD_WORKSPACE_AFFINITY_V1.md`.
- Proof fixture: `examples/parity/two-stage-checkout.pipeline.yaml`.

## Review

Reviewed against TM-003 / TM-006 / TM-011 (session fencing and agent identity),
workspace path confinement, and the affinity-gone fail-closed path. Residual:
a crashed agent that still has an `agent_sessions` row leaves successors
waiting for that agent rather than failing until the session is gone or loses
the affinity capability; that is sticky placement, not blind reschedule.
`SEC-005` still owns hostile same-UID isolation.

## Verification

| Check | Result |
|---|---|
| `cargo test -p mcloving-domain --lib workspace::affinity_tests` | passed |
| `cargo test -p mcloving-controller-store --lib affinity::tests` | passed |
| `python3 scripts/verify-execution-board.py` | ok |
| `python3 scripts/verify-ticket-closure-receipts.py` | ok (debt unchanged) |
| PR head Foundation and Windows | recorded after protected merge |

## Threat model

Boundaries reviewed: agent session fencing, workspace path identity, affinity
pinning and the agent-gone failure. Closure attribution is recorded in
`docs/threat-model/README.md`. No production authority beyond the reviewed
affinity surface is granted.

## Residual: agent presence vs enrollment

`workspace_affinity_agent_gone` treats a missing `agent_sessions` row (or one
that no longer advertises `workspace-affinity-v1` / the required trust pool) as
gone. `agent_sessions` is an enrollment/epoch registry updated on open, not a
heartbeat presence signal; a crashed agent that never re-enrolls under a new
epoch can leave a stale row and a pinned successor queued until an operator
clears it. A presence lease or session heartbeat is follow-up work outside this
ticket; PAR-015 does not blind-reschedule to a different agent.

## Residual: rolling-upgrade capability strip

`workspace-affinity-v1` is advertised by Linux agents and stripped on work
poll by controllers that negotiated `build-workspace-affinity-v1`, matching
`multi-step-v1` and `artifact-upload-v1`. An older controller replica that
neither negotiates the feature nor strips the capability can still claim a
node requiring affinity and omit `workspace_affinity_json` / the pin. Full
protection is completing the controller rollout before admitting multi-stage
affinity builds; this ticket does not add a separate fleet-version gate.

