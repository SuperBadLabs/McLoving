# UI-002 accepted rendered baseline (post-repair)

This is the **accepted** baseline required by `UI-002` acceptance clause (3):
every view as a real browser rendered it after the minimal served-client repairs,
with all sixteen assertions passing. **`UI-006` and every later comparison use
this one.**

The pre-repair baseline is a separate directory,
[`ui-002-browser-v1`](../ui-002-browser-v1/README.md), retained unchanged. Read
the two together: this directory says what the repaired client does, and says
nothing about what `UI-001` shipped.

## Bound source

| File | SHA-256 | Lines |
|---|---|---|
| `index.html` | `035c77205d6a9d9209edfa62fcdea7fe3c0330437eae29f647423de81b7b319c` | 164 |
| `app.js` | `4102f00b64349c5db5a66271a4add7d76501afcdaad6436ffbecc6dde17cfa53` | 454 |
| `app.css` | `1d59977bd9140381e3d732dd7f80f3c8f5863e9cc67760e356343c139cf9a1e0` | 56 |

Combined client digest: **`5fe7ee2b3e38219606422ce888dc1ed0c66c23cc84f9f5d745063e0e59f09939`**

Rendered by Google Chrome for Testing 153.0.8010.36 with the matching
ChromeDriver, both pinned by SHA-256 in `scripts/ui-browser/browser-pin.json`.

## Verdict

**17 of 17 assertions passed.**

## What changed from v1, and why

Three repairs, all served-client only. No route, CSP, authorization or
threat-boundary change; the shipped CSP already permitted `img-src 'self' data:`,
so nothing about the policy moved.

| v1 failure | Repair |
|---|---|
| `focus_survives_repeated_live_updates` | `app.js` gained `preserveFocusAcross`, which records the focused row's stable key before a rebuild and restores focus to the same logical row afterwards. Applied to **both** live-rebuilt lists — `refreshBuilds` where the failure was observed, and `renderArtifacts`, which re-renders on every live tick and had the identical defect. |
| `focus_survives_build_view_live_refresh` | The same repair, but this row is the one that *proves* it on the automatic surface. The artifact row's key is `attempt_id/fence/name`: fence is part of the identity because one attempt can carry records with the same name from different fences — `ArtifactResponse` carries `fence` — and a key without it restores focus to the first match rather than the row the user was on. The assertion focuses the **second** of two same-named fixture artifacts, so a key that ignored the fence fails it. |
| `viewport_390_has_no_horizontal_overflow` | The recent-builds table moved inside a labelled, keyboard-focusable `.table-scroll` container (`overflow-x: auto`), so the table scrolls instead of the page; `.actions` gained `flex-wrap: wrap` so the four pipeline buttons wrap rather than overflowing. `app.css` gained a `:focus-visible` outline for the new focusable region so it does not become a keyboard stop without a focus ring. |
| `console_has_no_unexpected_resource_failures` | `index.html` declares `<link rel="icon" href="data:,">`, so the browser stops requesting `/favicon.ico` and 404ing on every page load. |

Verification after repair was not a screenshot. The full browser gate was rerun
(17/17), the existing static contract suite
`cargo test -p mcloving-controller-api --test route_denials` was rerun (7/7), and
every assertion was mutation-proved (`../ui-002-mutation-v1/`).

The fixture was changed to serve two real artifact records rather than an empty
list. That is not cosmetic: with `[]` the artifact rows never rendered, so
`renderArtifacts` and its focus behaviour were exercised by nothing and asserted
by nothing, and the repair claimed for it had no evidence behind it.

## The one line here that is not a client property

`console.json` records one *provoked* network failure: a 422 from
`/pipelines/validate`. The gate deliberately submits a source with a duplicate
mapping key to prove the strict-YAML refusal reaches the user, and the browser
logs that correct refusal as a SEVERE console entry. It is enumerated by URL and
status rather than excused by category, so a genuine script error cannot hide
behind the allowance — `console_has_no_script_errors` is a separate assertion and
admits nothing.

## Files

- `gate-results.json` — every assertion with its observed detail, the bound
  source manifest, and the browser identity.
- `console.json` — script errors, provoked network failures, unexpected ones.
- `screenshots/` — 21 renders across the five views at desktop and 390px widths,
  including the focus state after the build view's automatic refresh.
- `fixture.log`, `ARTIFACTS.sha256`, `SCREENSHOTS.sha256`.

## Reproducing

```bash
bash scripts/test-ui-browser.sh --output-dir OUT --label LABEL
```

Exits non-zero on any failing assertion, and on any assertion count other than
the pinned 17.
