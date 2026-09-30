# PAR-002 closure receipt: native cron schedules

Ticket: `PAR-002`. Merged as PR #168, squash commit
`83e9efeb4e33bb0f0e5d9a5f0b8feed95a8042b4` on 2026-09-28.

## What merged

- Native five-field calendar with Jenkins-style `H` / `H/n` / `H(m-n)` under
  `jenkins-core-2.516.1:cron-hash-v1`.
- Migration `0042` adds mutable, generation-bound `trigger_schedule_slots`.
  Trigger version rows no longer embed resolved slots.
- Watermark membership reads the slot table. Controllers claim due open slots
  under the trigger lock; after downtime only the latest missed slot fires.
- Controller schedule delivery worker runs beside trigger retry and
  notification delivery.

## Review

Review rounds on PR #168 fixed due-selection against the enabled generation,
prior-generation skip on revise, stale claimed-slot reopen, civil-time search
window, and forced-RLS preflight counts. Residual: Mario TimerTrigger production
authority remains ineligible while sealed hash inputs stay incomplete; native H
resolution does not admit it (TM-039).

## Verification

| Check | Result |
|---|---|
| `cargo test -p mcloving-controller-store --lib schedule_calendar` | passed |
| `cargo test -p mcloving-controller-store --test trigger_ingress` | passed |
| PR head Foundation and Windows | success on merge |

## Threat model

Boundaries reviewed: TM-039 (schedule capture, watermark monotonicity,
dual-controller exactly-once, post-downtime catch-up). Closure attribution is
recorded in `docs/threat-model/README.md`. No production TimerTrigger authority
is granted.
