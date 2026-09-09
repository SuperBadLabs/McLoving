# Briefing for the next Master Chief

You are taking custody of McLoving's Jenkins compatibility M1. Start by reading
[this handoff](README.md), the [execution board](../../EXECUTION_BOARD.md), and
[current custody instructions](../CURRENT.md). Refresh live GitHub state before
acting; historical green checks do not verify a new head.

JCOMP-001 is complete. JCOMP-002 merged through PR #128 at `904fd1f`; its exact
post-main Foundation and actual native Windows checks subsequently passed.
The board still leaves JCOMP-002 ACTIVE because earned closure has not yet been
recorded. Make that reviewed bookkeeping transition first, then take JCOMP-002A.
Do not report general runnable Jenkins support: step execution, workspace
continuity and paired execution evidence are still outstanding.

Use subagents for independent store/planner review and actual runtime fixture
work. Keep a single serial JCOMP implementation PR at a time. Preserve the
three-mutable-PR ceiling, all eight app-bound protected checks, exact-head review,
zero actionable review items, guarded merge and exact post-main verification.
Check the current owner's authorization before any action outside repository
custody; this document supplies context, not new operational authority.

Implement the [settled step-node design](sequential-steps-design.md) with all
[threat and evidence obligations](threat-review-plan.md). Preserve fresh shells,
step/stage identity, first/middle/last failure and skipping, cancellation,
lease/fence/session/restore checks, retry lineage and recovery. Use the real
controller and agent in disposable contained tests; neither a concatenated shell
nor a removed admission guard satisfies this ticket.

Read the historical [local preflight](local-runtime-preflight.md) before building
the test environment; verify current tool/image/binary identities again. Qwen's
[reviewed static draft](qwen-corpus-draft.md) can help future corpus planning after
model/connectivity checks, but model output is never Jenkins evidence. The
[gate-cost study](merge-gate-followup.md) is a separate optimization proposal,
not permission to remove checks or delay M1 by changing scope.

Leave a similarly factual handoff: what merged, what passed on exact main,
what remains unearned, next dispatch and artifact identities. Preserve user
workspace changes and existing historical receipts.
