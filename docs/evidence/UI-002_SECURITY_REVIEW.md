# UI-002 security review

Ticket: `UI-002` — make the current web UI provable before anything replaces it.
Date: 2026-09-10.

## What was reviewed

The introduction of a browser into a repository that had none, and the minimal
client repairs needed to earn the claims `UI-001` had already asserted. Three
things carry security weight here: what the new dependency is and how it is
pinned, what boundary the browser runs inside, and whether the gate can fail.

## The new dependency, and why it is bounded

`UI-002` adds Chrome for Testing 153.0.8010.36 and its matching chromedriver,
pinned by URL and SHA-256 in `scripts/ui-browser/browser-pin.json`. The archives
are fetched and verified by `scripts/ui-browser/build-image.sh` **before** they
enter the container build context; the `Containerfile` itself downloads nothing.
On a digest mismatch the script exits 66 **and deletes the offending archive**,
so a later run cannot inherit trust in a file that already failed once.

The base image is referenced by manifest digest, not by tag, and its image id is
checked after the pull. The image is rebuilt whenever the browser digests **or
the SHA-256 of the Containerfile itself** differ from what the cached image's
labels record. That last check was added after the omission bit during
development: an edit to the Containerfile left a cached image that still carried
matching browser digests, and the gate ran against an environment the repository
no longer described.

No package manager, language runtime or third-party library was added for the
driver. `scripts/ui-browser/gate.py` speaks WebDriver classic over loopback HTTP
using only the Python standard library. The alternative considered and rejected
was Playwright or Puppeteer, which would pull a `node_modules` tree into a
repository with no JavaScript toolchain; the full argument is in
`docs/architecture/UI_BROWSER_GATE_V1.md`.

## The boundary the browser runs inside

Chrome's renderer sandbox requires unprivileged user namespaces, which AppArmor
restricts on Ubuntu 23.10+ — both the development hosts and the CI runners.
Chrome refuses to start rather than degrading quietly.

The browser therefore runs inside a rootless podman container and `--no-sandbox`
is passed **only inside it**. This is a deliberate trade, not an oversight:

- The renderer sandbox defends against hostile page content. The gate loads
  exactly one origin — a fixture it starts itself, serving this repository's own
  client — so it removes a defence against a threat the gate does not face.
- The container still bounds the process, filesystem, user and PID namespaces.
- The alternative that keeps Chrome's own sandbox is a named AppArmor profile
  granting `userns create,`, the shape `deploy/apparmor/mcloving-source-acquirer`
  already uses. It was rejected because it requires a root profile load on every
  host and runner before the gate can run at all. The owner selected the
  contained option.

`--network=host` is used so the fixture stays bound to `127.0.0.1` rather than
being published on a routable address for the browser's benefit. Loopback-only
binding is the stronger of the two properties available. `--userns=keep-id` maps
the invoking user onto the image's runtime UID so the gate writes its evidence as
itself rather than as a subordinate UID that cannot write the mount.

**No production code path changed.** `static_ui_router`, the CSP, every route and
every authorization check are untouched. The CSP already permitted
`img-src 'self' data:`, which is why the favicon repair needed no policy change
and no new route.

## Whether the gate can fail

This is the crux, because the defect `UI-002` corrects is a claim asserted by a
check that could not observe it.

- **The assertion count is pinned.** `--expected-assertions` is required and a
  mismatch exits 65, including under `--record-only`. A gate that silently stops
  running assertions fails rather than reporting success.
- **`--record-only` cannot reach CI.** It exists solely to capture the pre-repair
  baseline, where the failures are the evidence.
  `scripts/verify-ui-browser-gate.py` refuses the workflow if it ever appears
  there uncommented.
- **Every assertion is mutation-proved.** `scripts/ui-browser/mutations.json`
  names, for each of the eighteen assertions, at least one client defect that
  breaks exactly what that assertion claims.
  `scripts/test-ui-browser-mutations.py` introduces each one and requires that
  named assertion to turn red; it first requires the unmutated client to pass
  everything, so a mutation cannot "fail correctly" for an unrelated reason, and
  it refuses to read a verdict from a gate run that exited non-zero for any
  reason other than the expected assertion failures — without that check a
  pinned-count mismatch or a fixture that never listened would have been read as
  a caught mutation. The record is `docs/evidence/ui-002-mutation-v1/`.
- **The pins cannot drift apart.** `scripts/verify-ui-browser-gate.py` checks
  that the count pinned in the runner, the assertions `gate.py` emits, and the
  mutation set all agree, that no mutation's find-text is absent from the client
  it targets, and that the Containerfile's base image is the pinned digest.
- **The lane gates merge, and its waiver is explicit.** `ui-browser` is in
  `FOUNDATION_JOBS` and in the `foundation` aggregate's `needs`, so a failure
  blocks. It is also the one Foundation lane that does not always execute: the
  mutation proof is twenty-two browser runs, so `scripts/ui-browser-impact.py`
  classifies whether the change can affect the interface. That is the `TM-052`
  hazard — a skipped required check reads as a pass — so the waiver is wired on
  the Windows-agent pattern rather than as a `paths:` filter. `ui-impact` is
  itself unconditional, so its failure is caught before its decision is read; the
  decision must be one of two literal strings; `true` demands `success` and
  `false` demands `skipped`, and every other pairing is refused. A push with no
  usable predecessor, and a classifier that cannot classify, both run the full
  lane rather than guessing. The complete decision-by-result cross product is
  enumerated in `scripts/test-workflow-aggregate.py`.
- **The cheap half of the mutation guarantee still runs on every push.** A
  client change below the threshold does not re-run the twenty-minute proof, but
  `verify-ui-browser-gate.py` runs unconditionally in the Architecture records
  lane and fails if any mutation's find-text is absent from the client, so the
  mutation set cannot rot into targeting nothing. The residual exposure is named
  under Residual risk below.

## The validation claim

The fixture's `/pipelines/validate` previously answered `valid: true`
unconditionally and so could not prove strict-YAML rejection at all. It now
compiles the submitted source through
`mcloving_pipeline_ir::compile_strict_yaml_with_parameters` — the same entry
point the shipped `validate_pipeline` handler uses — and reproduces that
handler's rejection envelope (422, `pipeline_rejected`, the compiler's own
message). The refusal the gate asserts is therefore the production parser's
verdict and wording, not an error the fixture invented. The probe is a duplicate
mapping key, chosen because a permissive YAML parser accepts it silently, so the
refusal is evidence that the strict parser answered.

That correct 422 is logged by the browser as a SEVERE console entry. Rather than
excuse it wholesale, the console assertion is split: `console_has_no_script_errors`
admits nothing, and `console_has_no_unexpected_resource_failures` enumerates the
excused failure by URL and status and writes it into `console.json`. A genuine
script error cannot hide behind the allowance.

## Findings

Four defects in the shipped client, all repaired. Three were found by the gate on
its first run; the fourth was found only after review showed the gate was not
looking at the surface that matters most:

1. **Keyboard focus destroyed on every live refresh.** `refreshBuilds` rebuilt the
   table body with `replaceChildren()`, so a keyboard user on a build row's
   **Open** button was returned to `<body>`. Fixed with `preserveFocusAcross`,
   which restores focus by a stable row key rather than by position.
2. **The same defect on the surface that refreshes without being asked.** The
   build view re-renders its artifact rows on a two-second timer through
   `renderArtifacts`. The repair above was applied there at the same time — but
   **no assertion covered it**, because the fixture served an empty artifact
   list, so those rows never rendered. The repair was real and the evidence for
   it did not exist, which is precisely the defect class this ticket exists to
   correct, reproduced inside the work that corrects it. Review caught it. The
   fixture now serves two real artifact records, a further assertion drives
   the client's own timer rather than a clicked refresh, and two further
   mutations prove it binds. Running the completed gate against the original
   client then showed this failing there too: the shipped client lost focus on
   **both** live surfaces, not one.
3. **Horizontal overflow at a 390-pixel viewport** on the dashboard
   (`scrollWidth=510`, the recent-builds table) and pipeline (`scrollWidth=437`,
   the non-wrapping `.actions` row). Fixed by giving the table its own labelled,
   focusable horizontal scroller and letting the button row wrap.
4. **A `favicon.ico` 404 on every page load**, logged SEVERE. Fixed by declaring
   an empty `data:` icon, permitted by the existing CSP.

A second coverage gap of the same shape was found by review after the first was
fixed: the artifact assertion proved rows and Download controls *rendered* but
never activated one, and the fixture exposed no `/artifacts/content` route at
all — so the click listener, the URL `downloadArtifact` builds and the response
handling were outside the gate. The fixture's artifact table is also resolved the way production resolves it:
`ArtifactQuery` carries only `attempt_id` and `name`, and `find_artifact` takes
the **first** match with no fence in the predicate or the ordering. An earlier
revision answered a fence-specific record for that query, which manufactured
behaviour the shipped controller does not have and would have kept a green
delivery baseline while production served a different fenced artifact. The
delivery journey now drives a uniquely named row, and the deliberately ambiguous
`report.txt` pair is kept only for the client-side focus key.

`artifact_download_delivers_content` clicks
the control and reads **the bytes that actually arrived on disk** — Chrome is
given a download directory the gate inspects — requiring the file to be named
`report.txt` and to hold exactly the 34 bytes the fixture serves. Asserting the
client's reported byte count alone proved nothing, because the client reports
`artifact.bytes` straight from the listing it already rendered: that stays true
if the click never fires, if the endpoint answers empty, or if it answers
something else. The fixture also validates the request query and 404s on a
mismatch, so a client that builds the wrong URL fails rather than receiving the
same bytes regardless. Two mutations cover it: removing the click listener, and
requesting the wrong artifact name. It passes on
the original client too: that listener was never broken, so this one is coverage
gained rather than a defect found. Twice now an assertion here stopped one step
short of the behaviour it implied; when adding one, ask what it would still
report green through.

A fifth defect was latent rather than observed: the viewport helper folded its
correction back into the value it compared against, so on any browser with window
chrome it would never converge on 390 CSS pixels and the assertion would fail on
a viewport it had in fact reached. It passes here because headless Chrome has no
chrome to correct for. It fails closed, but it was wrong, and it is fixed.

None is a privilege, authorization or data-exposure defect. The security-relevant
finding is the one the ticket names: a closure record asserted five properties
that no check in this repository could evaluate, and two of them were false —
and, on the evidence of the artifact surface above, the honest count of what the
shipped client got wrong was higher than the first version of this gate could
see.

## Residual risk

- **One rendering engine.** A pinned Chromium is the whole population; a
  Chromium-specific pass is not a cross-browser pass.
- **Assistive-technology announcement is not observed.** The gate asserts the
  structures a screen reader consumes, not what one says. This is recorded as a
  manual convention in `docs/EXECUTION_BOARD.md` rather than presented as
  evidence, and the corresponding `UI-001` claim is qualified rather than
  restated.
- **The browser runs without its own renderer sandbox inside the container.**
  Argued above and in `docs/architecture/UI_BROWSER_GATE_V1.md`. If the gate is
  ever pointed at content this repository does not author, that argument stops
  holding and the boundary must be revisited.
- **`--network=host`** means the gate's browser shares the host network
  namespace. It is the price of keeping the fixture on loopback.
- **A client change below the 20-line mutation threshold ships without the
  assertions being re-proved.** This is a deliberate cost trade made by the
  owner, not an oversight. What still holds in that window: the gate itself runs
  (so the client is still rendered and checked), and every mutation is still
  verified to target real client text on every push. What does not: nobody
  re-demonstrates that each assertion *fails* when its property breaks. A small
  client change that made an assertion vacuous without moving any mutation's
  find-text would survive until the next above-threshold change. The threshold
  is the dial; `docs/architecture/UI_BROWSER_GATE_V1.md` argues its value and
  says to lower it before raising it.

## Evidence

- `docs/evidence/ui-002-browser-v1/` — initial baseline, pre-repair, retained
  unchanged; client `83966def…`, 14 of 18 passed, four named failures.
- `docs/evidence/ui-002-browser-v2/` — accepted baseline bound to the repaired
  client `5fe7ee2b3e38219606422ce888dc1ed0c66c23cc84f9f5d745063e0e59f09939`;
  18 of 18. **This digest is what `UI-006` and later work compare against.**
- `docs/evidence/ui-002-mutation-v1/` — mutation proof, 21 of 21 caught across
  18 assertions.
- `docs/architecture/UI_BROWSER_GATE_V1.md` — the driver and boundary argument.
