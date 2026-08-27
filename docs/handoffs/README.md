# Custodian handoff packs

Each shift ends with a dated pack: what landed, what is still open, and what the
outgoing custodian got wrong. Read the newest one's `§0` before touching the
board.

| Pack | Shift | Headline |
|---|---|---|
| [`2026-08-26/`](2026-08-26/) | closure integrity | Closure and dependency gaps made mechanical; PRs #94, #95, #96, #97 merged; `HYG-002` filed |

## Why these are in the repository

Packs used to live only in `/sn8100/work/forge/McLoving-handoff-*` on one
workstation. That is a single copy on scratch, with nothing enforcing its
survival — and a pack that quietly disappears looks exactly like a shift that
never wrote one, which is this project's signature failure applied to its own
handover record.

Committing them makes the record survive a sweep, a reimage, or a machine, and
makes "was a handoff written?" answerable by `git log` instead of by trusting a
directory listing.

## Convention

- One directory per shift, named for its end date: `docs/handoffs/YYYY-MM-DD/`.
- `HANDOFF.md` is the pack; `README.md` is a one-page entry to it. Anything else
  is working evidence, kept so the next custodian can check the claims rather
  than inherit them.
- **State supersession explicitly.** A dated directory carries no forward link,
  so a stale pointer to an old pack is indistinguishable from a current one.
  Two people walked into exactly that during the 2026-08-26 shift.
- Add the new pack's row to the table above in the same change. A pack nobody
  can find from the index is a pack nobody reads.

## Earlier packs, not yet imported

These predate the convention and exist **only** on the workstation at
`/sn8100/work/forge/`. They are still accurate for project rules, host state and
worktree inventory, and `-2026-08-25b` in particular carries substantial working
evidence — 17 files including the systemd enforcement probes, the trust-boundary
costing, and the `SEC-005` decomposition.

```text
McLoving-handoff-2026-08-22   McLoving-handoff-2026-08-23
McLoving-handoff-2026-08-25   McLoving-handoff-2026-08-25b
```

**They are one `rm -rf` from gone.** Importing them is a bounded, mechanical
job for whoever next has an idle slot; nothing in them needs re-deriving, only
copying. Do it before reclaiming anything under `/sn8100/work/forge/`.
