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
