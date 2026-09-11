# UI-002 mutation proof

`UI-002` acceptance clause (4): *every gate is mutation-proved to `HYG-002`'s
standard — removed, it turns a named test red.*

An assertion that cannot fail is not a gate, and a gate asserting an unobservable
property is the exact defect this ticket corrects. So each of the eighteen
assertions has, in `scripts/ui-browser/mutations.json`, at least one named client
defect that breaks precisely what that assertion claims. An assertion may carry
more than one: requiring exactly one was itself a way to leave a surface
unproved, because it forbade covering a second call site.
`scripts/test-ui-browser-mutations.py` introduces each one against the shipped
client, runs the full browser gate, and requires that named assertion to turn
red.

**Result: 21 of 21 caught. Nothing escaped.**

### One escaped first, and that is the point

An earlier run of this harness reported **18 of 19**, with
`artifact-focus-key-ignores-fence` escaping. The mutation drops the fence from
the artifact focus key; the assertion compared the focused row's key before and
after a live refresh — and under that mutation *both* artifact rows carry the
same key, so a key-only comparison could not distinguish "restored to the row I
was on" from "restored to the first row that looked like it". The assertion now
compares the row's identity (its index among the artifact rows and its rendered
label) as well as its key.

This is the harness working. A mutation that escapes is not a harness failure to
be tuned away — it is the only mechanism here that can tell a real assertion from
one that merely looks like it holds.

## Why the run starts with a clean baseline

The harness first runs the gate against the **unmutated** client and requires all
eighteen to pass — the count `mutation-results.json` records as
`expected_assertions`, read back from that baseline verdict rather than requested
on the command line. Without that step a mutation could "fail correctly" for a reason
that had nothing to do with the mutation — a flaky fixture, a port collision, a
stale container image — and the proof would be worthless while looking perfect.

## Collateral failures are recorded, not hidden

6 of the 21 mutations turned a second assertion red as well. Each is honest coupling rather than an imprecise assertion, and each is recorded in `mutation-results.json` under `collateral_failures`. This table is derived from that file, and `scripts/verify-ui-browser-gate.py` refuses a README that does not match it.

| Mutation | Also red | Why |
|---|---|---|
| `dashboard-rows-never-appended` | `focus_survives_repeated_live_updates` | With no build row there is no control to put focus on, so the focus assertion reports failure rather than passing vacuously. That is intended: a focus check that passes when there is nothing to focus is the vacuous-success shape. |
| `validate-button-unwired` | `strict_yaml_refusal_surfaced_to_user` | Both assertions travel through the same button. Unwiring it removes the accepted case and the refused case together. |
| `focus-not-preserved-across-refresh` | `focus_survives_build_view_live_refresh` | This disables the shared `preserveFocusAcross` helper, which both live surfaces call, so both go red. The build-view assertion has its own mutations that touch only the `renderArtifacts` call site, which is what proves it binds independently rather than by borrowing the dashboard's coverage. |
| `live-region-not-announced` | `landmarks_present_in_rendered_dom` | The landmark assertion requires at least two `[role=status][aria-live]` regions, so stripping `aria-live` from the connection-state region is visible to both. |
| `artifact-rows-never-rendered` | `artifact_download_delivers_content`, `focus_survives_build_view_live_refresh` | With no artifact row there is nothing to focus and nothing to download, so both artifact assertions fail rather than passing vacuously. |
| `artifact-download-requests-the-wrong-artifact` | `console_has_no_unexpected_resource_failures` | The fixture answers 404 for an artifact it does not have, and a 404 is precisely what the console assertion calls an unexpected resource failure. Honest coupling, not an imprecise assertion. |

The requirement is that the **named** assertion goes red, not that it is the only
one. A mutation whose named assertion stayed green would be a harness failure and
the run would exit non-zero.

## Reproducing

```bash
python3 scripts/test-ui-browser-mutations.py --output-dir OUT
```

Roughly 28 minutes: twenty-two full gate runs, each rebuilding the fixture because
the client is compiled in with `include_str!`. The harness refuses to read a
verdict from a gate that exited non-zero for any reason other than the assertion
failures it expected — a pinned-count mismatch or a fixture that never listened
would otherwise have been read as a caught mutation.

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
