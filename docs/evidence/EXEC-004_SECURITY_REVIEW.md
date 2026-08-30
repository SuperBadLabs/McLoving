# EXEC-004 retrospective security review

Date: 2026-08-30

`EXEC-004` closed in protected-main commit `8fb8ac5` (PR #74). The initial
field diagnosis blamed a short lease, but code and repeated Luigi evidence
showed that renewal already ran concurrently with work. The actual fault was a
second executor using the same `agent_id`, advancing the session epoch and
causing the first executor's mid-step renewal to lose authority.

The shipped control keeps lease renewal concurrent with process execution and
makes authority loss observable on both sides. One regression runs a single
step for more than three lease terms and reaches terminal success; another
blocks renewal deliberately and proves lease-loss cancellation. These tests
separate “work lasted longer than one lease” from “the executor lost its
fenced session,” preventing a longer lease from being mistaken for a safety
fix. The executor still cancels on real renewal loss and cannot finalize under
stale authority.

The threat-model review covered stale session epochs, identity collision,
unbounded work under an expired lease, lost cancellation, and misleading
reconciliation state. These risks are already represented by the agent lease,
session authority, cancellation, and recovery boundaries, so the register
requires no new threat row. The later stop-versus-renewal race correction in
PR #107 further ensures a completed attempt is not torn down by a concurrent
renewal failure.

Residual risks include controller/database partition and deliberate duplicate
identity configuration; both remain fail-closed and operator-visible. This
receipt authenticates the retrospective review of `EXEC-004` and does not
authorize production effects or weaken reconciliation requirements.
