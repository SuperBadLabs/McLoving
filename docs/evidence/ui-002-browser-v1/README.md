# UI-002 initial rendered baseline (pre-repair)

This is the **initial** baseline required by `UI-002` acceptance clause (3):
every view of the shipped web client as a real browser rendered it, and every
assertion that failed, captured **before any repair was made**. It is retained
unchanged. Do not regenerate it — a later run against repaired source would
destroy the only record of what the original client actually did, which is the
`UI-001` failure this ticket exists to correct.

The accepted post-repair baseline is a separate directory,
[`ui-002-browser-v2`](../ui-002-browser-v2/README.md). `UI-006` compares against
that one; this one establishes what was true before.

## Bound source

These renders belong to one exact client, not to "the UI":

| File | SHA-256 | Lines |
|---|---|---|
| `index.html` | `da6c958c81d591e5851d089d765cff4f3b9ea93ada641540b0110838f1d1081d` | 161 |
| `app.js` | `4c4072f388fd52de9954de7d5df89313d044ba39ade20a099f2f7eb57faeef6d` | 424 |
| `app.css` | `4233a50bbc9eee1a27629b3fdc857074345ae0aea7d9ed0f5e17d71ffc1c6194` | 54 |

Combined client digest: **`83966def6a24e6bfbcae1354e422784ff09b20f37a6f71524fcfdf078f68826c`**

`gate-results.json` carries the per-file digests, byte counts and line counts,
along with the exact Chrome and chromedriver versions that produced the renders.

## Verdict

**13 of 17 assertions passed. Four failed**, each one a claim `UI-001`'s closure
record asserted and no check in the repository could support:

| Failing assertion | What the browser observed |
|---|---|
| `focus_survives_repeated_live_updates` | Focus was on a build row's **Open** button; after three dashboard refreshes the active element was `<body>`. `refreshBuilds` rebuilds the table body with `replaceChildren`, discarding the focused control. A keyboard user loses their place on every refresh. |
| `focus_survives_build_view_live_refresh` | The same defect on the surface that refreshes **without being asked**: focus was placed on an artifact's **Download** button and the build view's own two-second timer, going through `renderArtifacts`, discarded it. This assertion did not exist in the first version of this gate; review pointed out that asserting only the clicked path left the automatic one uncovered, and adding it found a fourth pre-existing defect rather than confirming three. |
| `viewport_390_has_no_horizontal_overflow` | At an inner width of exactly 390px the document overflowed horizontally on two views: **dashboard** `scrollWidth=510` (the recent-builds table) and **pipeline** `scrollWidth=437` (the non-wrapping `.actions` button row). |
| `console_has_no_unexpected_resource_failures` | `GET /favicon.ico` → **404**, logged SEVERE on every page load. The client declares no icon and the controller serves no such route. |

The fourth failure is why the count here is 17 and not 16: the artifact surface
was outside the first version of this gate entirely, so `renderArtifacts` and the
focus behaviour of the build view's own timer were asserted by nothing.

The console assertion is split in two so that neither failure can hide the
other. `console_has_no_script_errors` **passed**: the client logged no
uncaught exceptions or script errors across every journey. The single 422 from
`/pipelines/validate` is classified in `console.json` as a *provoked* failure —
the gate submits knowingly invalid YAML to prove the refusal reaches the user,
and a correct 422 is the point of that probe rather than a defect.

## Files

- `gate-results.json` — the machine-readable verdict: every assertion, its
  pass/fail state and its observed detail, the bound source manifest, and the
  browser identity.
- `console.json` — every SEVERE console entry, separated into script errors,
  deliberately provoked network failures, and unexpected ones.
- `screenshots/` — 21 renders: each of the five views at desktop width, each at a
  390px viewport, the accepted and refused validation results, the keyboard-focus
  state per view, and the focus loss after both a manual dashboard refresh and
  the build view's automatic one.
- `fixture.log` — the mock controller's own output for the run.
- `ARTIFACTS.sha256`, `SCREENSHOTS.sha256` — digests of everything above.

## Reproducing

The gate is deterministic given the pinned browser
(`scripts/ui-browser/browser-pin.json`) and the client source named above:

```bash
bash scripts/test-ui-browser.sh --output-dir OUT --label LABEL
```

`--record-only` writes the verdict without failing the process, which is how
this pre-repair baseline was captured. CI never passes that flag; see
`docs/architecture/UI_BROWSER_GATE_V1.md`.
