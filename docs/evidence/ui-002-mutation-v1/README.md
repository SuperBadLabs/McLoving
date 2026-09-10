# UI-002 mutation proof

`UI-002` acceptance clause (4): *every gate is mutation-proved to `HYG-002`'s
standard — removed, it turns a named test red.*

An assertion that cannot fail is not a gate, and a gate asserting an unobservable
property is the exact defect this ticket corrects. So each of the sixteen
assertions has, in `scripts/ui-browser/mutations.json`, a named client defect
that breaks precisely what that assertion claims.
`scripts/test-ui-browser-mutations.py` introduces each one against the shipped
client, runs the full browser gate, and requires that named assertion to turn
red.

**Result: 16 of 16 caught. Nothing escaped.**

## Why the run starts with a clean baseline

The harness first runs the gate against the **unmutated** client and requires all
sixteen to pass. Without that step a mutation could "fail correctly" for a reason
that had nothing to do with the mutation — a flaky fixture, a port collision, a
stale container image — and the proof would be worthless while looking perfect.

## Collateral failures are recorded, not hidden

Three mutations turned a second assertion red as well. Each is honest coupling
rather than an imprecise assertion, and each is recorded in
`mutation-results.json` under `collateral_failures`:

| Mutation | Also red | Why |
|---|---|---|
| `dashboard-rows-never-appended` | `focus_survives_repeated_live_updates` | With no build row rendered there is no control to put focus on, so the focus assertion cannot be evaluated and reports failure rather than passing vacuously. That is the intended behaviour — a focus check that passes when there is nothing to focus is the vacuous-success shape. |
| `validate-button-unwired` | `strict_yaml_refusal_surfaced_to_user` | Both assertions travel through the same button. Unwiring it removes the accepted case and the refused case together. |
| `live-region-not-announced` | `landmarks_present_in_rendered_dom` | The landmark assertion requires at least two `[role=status][aria-live]` regions, so stripping `aria-live` from the connection-state region is visible to both. |

The requirement is that the **named** assertion goes red, not that it is the only
one. A mutation whose named assertion stayed green would be a harness failure and
the run would exit non-zero.

## Reproducing

```bash
python3 scripts/test-ui-browser-mutations.py --output-dir OUT
```

Roughly 20 minutes: seventeen full gate runs, each rebuilding the fixture because
the client is compiled in with `include_str!`.

**The harness mutates tracked files in the working tree** and restores them on
every normal, exceptional and signalled exit. If it is killed outright
(`SIGKILL`, host loss) the client is left mutated; `git checkout --
crates/controller-api/ui/` restores it, and `git status` will show it plainly.

## Files

- `mutation-results.json` — per mutation: the file, the assertion expected red,
  whether it was caught, and the full failing set.
- `run.log` — the run's console output.

Per-mutation gate output (screenshots and verdicts, ~19MB) is not retained here;
it is reproducible from the command above and adds nothing the summary lacks.
