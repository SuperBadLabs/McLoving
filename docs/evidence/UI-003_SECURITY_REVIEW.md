# UI-003 decision-record source review

Ticket: UI-003. Date: 2026-10-08.
Original decision author: the UI-003 child agent, `/root/milestone_m4/ui_003`.
Exact-pin successor author: Root, 2026-10-08. Independent source reviewer of
earlier corrected V2 and htmx 4 fidelity V4: `/root/milestone_m3`.
Independent exact-pin V5 source reviewer: `/root/milestone_m1/dogfood001`,
2026-10-08; no findings; document validation and authorized draft publication only.
Preparatory pin disposition: recorded by Root under the user's authorized
full-goal work and recorded htmx 4 direction; acquisition and rollout DEFERRED.
Final integration: pending. Each attribution refresh requires independent source
review and document validation; current candidate observations are recorded in PR #189.
Separately claimed human risk acceptance: not recorded. UI-003 remains DEFERRED.
Scope: authored decision records in an isolated copy of
`7e5de0785a0ac5b1f98bd28dbcf50980806cf871`; no runtime changes or execution.

## Material examined

The review read the complete UI-003 acceptance, existing public OIDC route and
response shapes, client token handling, session persistence/rotation/revocation,
the shipped CSP and threat-register/attribution conventions. It authored ADR
0017 and prospective TM-055. It did not run a compiler, test, browser, formatter,
network request or deployment, read credentials, mutate Git, or establish any
production effect, session rollout, real-team qualification or ticket closure.

| Evidence in the bound source | Observation and decision consequence |
|---|---|
| `crates/controller-api/ui/index.html:25-28`; `ui/app.js:304-309` | Existing password input is retained in the DOM after copying to JavaScript, despite the memory-only hint. Future entry must clear it synchronously; this review does not repair the shipped page or label it conformant. |
| `crates/controller-api/ui/app.js:59-64, 293` | Access authority is explicitly attached as bearer to Fetch, including artifact downloads; header attachment needs script. |
| `crates/controller-api/src/lib.rs:661-674` | Start/callback GET and session refresh/logout POST are existing public operations; their existence is not a browser session decision. |
| `crates/controller-api/src/oidc.rs:207-219, 382-456, 491-496` | Both access and refresh are returned as no-store JSON. Callback renders neither an authenticated document nor a browser sign-in ceremony. |
| `crates/controller-api/src/oidc.rs:29-30, 114-119, 767-806` | Configured access duration is at most one hour; refresh is longer, at most 24 hours. Digests and expiries are issued server-side; no browser lifetime is invented. |
| `crates/controller-store/src/identity.rs:1105-1223` | Refresh checks current identity/provider/session generations, retires the replaced session, rotates both credentials, preserves the absolute family deadline and handles refresh reuse. ADR requires single-flight, no replay after ambiguity and atomic pair replacement. |
| `crates/controller-api/src/oidc.rs:459-488`; `crates/controller-store/src/identity.rs:1274-1389` | Logout authenticates access bearer and invokes session revocation. Browser clearing alone is not server revocation; unconfirmed logout must be displayed truthfully. |
| `crates/controller-api/src/oidc.rs:251-310, 314-381` | Start exact-allowlists redirect URIs and binds state/nonce/PKCE. Proposed opener/popup shell handling carries code/state only; existing callback consumes them via Fetch. Exact allowlisting and browser/server correlation remain prerequisites and downstream proof obligations. |
| `crates/controller-api/src/lib.rs:7275-7358` | Resource authentication/authorization is centralized; the decision requires its reuse for HTML, not view-local checks. No new HTML path was built or qualified. |
| `crates/controller-api/ui/app.js:164-171, 244-248, 280-282` | Present client writes public text using DOM APIs. Server HTML introduces parser/context encoding risks that JSON or current text sinks cannot prove away. |
| `crates/controller-api/src/lib.rs:845, 859-864`; `crates/controller-api/tests/route_denials.rs` | Exact shipped header and existing structural/text assertions remain unchanged. Textual checks are not successor browser evidence. |
| `docs/architecture/UI_BROWSER_GATE_V1.md:190-210`; retained `docs/evidence/ui-002-browser-v1/` and `ui-002-browser-v2/` | Historical initial/accepted browser observations are source-bound to UI-002, not current rendered-session or SSR proof. Their files are preserved unchanged. Screen-reader announcements and cross-engine claims are explicitly limited. |
| `docs/EXECUTION_BOARD.md:111-117, 1135-1140`; `docs/adr/0016-product-parity-before-migration-authority.md:36-40` | UI-003 is DEFERRED; UI-004 records owner-selected htmx 4 and permits only a reviewed future no-library disposition; closure and real-team gates remain. Record authoring makes neither gate true. |
| `docs/threat-model/README.md`, `## Closure attribution`; `scripts/verify-ticket-closure-receipts.py:1063-1103` | Closure attribution means a reviewed closed ticket and rejects attribution to a non-DONE ticket. Decision-review attribution below is deliberately distinct and does not create a machine closure row. |

## Decision assessment

ADR 0017 chooses tab-local memory for both credentials, explicit bearer resource
requests, JSON refresh and the roadmap-selected htmx 4 acquisition direction. It evaluates cookie sessions and
persistent storage, rejects them for this lane, and records their benefits and
the costs accepted by the chosen model. Ordinary initial navigation is public
shell only; reload loses authority, authenticated no-script behavior is unavailable,
and popup blocking/loss makes sign-in fail explicitly. OIDC UI implementation uses
the existing public routes and one credential store, not a second credential path.

CSRF is decided now: no ambient cookie authority; no fallback, JSON-only refresh,
no permissive cross-origin credential access, exact same-origin request destinations
with cookies omitted and redirects refused. Login additionally correlates the
browser-initiated state/provider/organization and retains server state/nonce/PKCE
checks. Access and refresh XSS exposure, transient input DOM residence, JavaScript
copies, expiry, rotation/reuse, revocation and all persistence prohibitions are
separate decisions in the credential table. Long-lived refresh is not left
unresolved by moving only access into memory.

The V2 record also resolves a Root-relayed independent V1 finding about retained
protected displays and late resource/login/refresh results. Stale content may
remain only in the same still-active organization/project/credential generation.
Context change, reset, authority loss and sign-out invalidate that generation and
clear protected DOM and pending work before new authority is installed. Every
asynchronous operation captures its context generation before starting and checks
it again before DOM, popup or pair-refresh commit; best-effort abort is insufficient.
The present mutable client lacks these guards and is not described as conformant.
This records the author's correction; the later V2 and exact-pin V5 independent
source reviews are attributed below. It is not a passing browser race test;
downstream implementation must prove those refusal and clearing cases.

TM-055 names every rendered value as an injection site and requires context
encoding for documents and fragments, inert hostile-value proofs per field,
separate log/failure cases, authorized public-field disclosure parity and common
JSON/HTML denial parity. These are distinct **unexecuted** UI-005 obligations.
Untrusted URI values need scheme/origin validation as well as escaping. CSP is
unchanged; neither this review nor the htmx direction permits inline handlers,
evaluated strings or a later silent policy relaxation.

The roadmap retains owner-selected htmx 4. The prior no-library proposal has
not received owner approval and is now a future reviewed alternative only.
Root privately obtained and inertly inspected the exact public npm 4.0.0
release after V4. Tarball integrity and the public registry signature were
actually verified; the classical artifact version AND SHA-256 are recorded
below and in ADR 0017. The exact-pin V5 record received independent source review.
Root now records that concrete preparatory pin under the user's authorized
full-goal work and recorded htmx 4 direction, without separately claiming human
risk acceptance. Clause (5)'s version/digest, upgrade and withdrawal decisions
remain intact; acquisition and rollout remain DEFERRED. UI-004 still owns reviewed
project-tree acquisition, digest verification, embedding and compatibility
gates. No library bytes were vendored and no JavaScript or browser test ran. ADR 0017 records a reviewed 4.x
upgrade direction/triggers and the named withdrawal fallback of retaining the
shipped static UI while suspending rollout; it does not silently select htmx 2,
a CDN, weaker policy or a no-library replacement.

Library integration must mediate every request and DOM insertion through the
same explicit credential/context contract and documented public operations.
Access header, JSON DTO transport, same-origin checks, cookie omission and
redirect refusal cannot be delegated to unchecked defaults. Refresh has no
attribute/global/default or second credential path. All inline/evaluated
features and protected browser-history persistence/restoration must be disabled
or rejected. Inert artifact inspection found same-origin cookie credentials,
enabled history and indicator CSS defaults, a request-context event/dispatch
path and evaluated hx-on handlers. Those source facts require explicit future
guards; they do not prove a working wrapper or CSP-compatible integration.
If any guard cannot be enforced, refuse acquisition and rollout. This source
review does not execute or qualify those future gates.

## Residual risks and proof still owed

The author/source review records the session decision and htmx acquisition
constraints and exact artifact pin. Independent exact-pin V5 source review is
complete and Root records the preparatory pin disposition. Final integration,
separately claimed human risk acceptance and runtime proof remain unearned.
A same-origin script compromise can steal either credential or make authorized
requests; memory-only reduces persistence, not the authority of injected script.
Extensions, developer tools, browser internals and garbage collection prevent a
promise of physical erasure. Loss or ambiguity of refresh forces reauthentication.
No-script and popup failure costs remain visible user limitations. These are
proposed tradeoffs for independent/owner review, not invented owner risk acceptance.

UI-005 must execute and mutation-prove same-path denial, route counterpart,
disclosure, hostile-value and both-credential handling gates, preserving all
existing route denial assertions. UI-006 must compare each migrated view against
unchanged accepted baselines and prove CSP and ordinary no-script/script-failure
behavior. UI-007 must prove this exact sign-in/refresh/logout shape. No such
implementation or browser result is claimed here.

## Decision-review attribution and later closure mapping

This document records the actual UI-003 author/source review and is the evidence
cited by TM-055. The independent source reviewer `/root/milestone_m3` examined the full V1/V2
decision and actual public API on 2026-10-08. V1 findings were the exact ADR
count mismatch and missing protected-display/late-result context rules. V2
resolved both; its 2,215 file bytes and modes and all five clauses were checked.
The reviewer approved the earlier V2 records and count maintenance for required checks;
no tests, runtime, browser, owner acceptance or closure were credited by that
source-only review. That approval covered the earlier no-library proposal,
not the later exact-pin successor. The htmx 4 fidelity V4 source was separately
reviewed by that reviewer, approved for a draft proposal update, and published
at PR #189 head `ca60ac6fe9f51b09890c77ce7e0baa1263a8df3d`. Its Foundation
run `37753884063` completed successfully with all 15 jobs passing; its 18 checks
were 17 successes and the classified native Windows job skipped. Those checks
cover that unchanged-runtime draft and do not qualify a future rendered
interface. These ca60/V4 observations are historical. The exact-pin V5 successor
was independently source-reviewed by `/root/milestone_m1/dogfood001`, with no
findings, for required document validation and authorized draft publication only.
Root subsequently joined all 2,215 frozen V5 source files to PR #189 head
`b35682b552a103140f963a491c6ba13b79ad1e11`. At Root's readback that draft was
OPEN/CLEAN with 18 checks: 17 SUCCESS and the classified Windows-agent job
SKIPPED; the UI browser gate was SUCCESS. The head-bound run references were
Foundation `37763692793` and Windows `37763692786`. These observations cover
b356, not this attribution refresh, protected merge, post-merge verification,
successor browser/session compatibility, real-team qualification or closure.
`/root/milestone_m4` also audited all five literal decision clauses and their
separation from downstream implementation. Root records the exact preparatory
pin under existing full-goal authorization and the recorded htmx 4 direction;
no separately claimed human risk acceptance is recorded. Each attribution refresh requires its own source review and required validators;
final integration remains pending. Current candidate observations are recorded in PR #189.

Required eventual machine attribution, after observed normal closure gates:

```text
| UI-003 | `docs/evidence/UI-003_SECURITY_REVIEW.md` |
```

Do not insert that row into `## Closure attribution` while UI-003 is DEFERRED or
before exact-head checks, independent review, protected merge and required
post-merge Foundation/native Windows verification and closure receipts. This
review and the separate decision-review attribution are not a waiver of those
rules. No board status or existing closure attribution is changed here.

## Observed V2 document validation

Root ran the required execution-board and ticket-closure verifiers on the
corrected V2 source; both returned zero. The exact ADR count and its retained
Foundation assertion were both 17. The closure verifier reported 37 existing
debt entries; board statuses and the existing Closure attribution were unchanged.
All 2,215 source file bytes and modes were preserved. These are document checks,
not an executing session, encoding, CSRF, browser or closure result. This final
review-attribution edit still needs its own candidate checks and review.

## Htmx 4 fidelity successor author review

The original UI-003 child authored this separate successor after Root identified
that the proposal's selected no-library branch departed from UI-004's recorded
owner-selected htmx 4 without owner approval. The successor preserves the full
access/refresh lifecycle, current-client nonconformance, context-generation and
protected-display rules, CSRF/login/popup/no-script costs, common public DTO and
authorization boundary, every-field encoding/disclosure denials and exact CSP.
It restores htmx 4 as the acquisition direction and preserves no-library only as
a future owner-reviewed alternative. At V4 authoring time exact pin/provenance,
acquisition, library configuration support and compatibility remained unearned;
that source-only author performed no registry, network or execution checks.
The later Root artifact observations below supersede only the private upstream
acquisition and integrity/signature status, leaving adoption and compatibility
open.

Earlier independent and Root document validations describe their exact V2/V3
sources; the separate V4 review/check observations cover only V4. The later
exact-pin V5 source review and b356 checks are separately attributed above;
none validates this attribution refresh. Separately claimed human risk acceptance,
the real-team condition, rollout, DEFERRED resumption, browser/session proof and
closure remain unearned.


## Exact htmx 4 artifact observations for the preparatory pin

Root inspected the fixed public release on 2026-10-08 in a private `/tmp`
directory. No package script, JavaScript, Node import or browser executed, and
the release was not placed in the project tree. The tarball response was HTTP
200 without redirects; the observed SHA-1 and SHA-512 matched the published
version metadata before the inert archive inspection. Root verified the
registry signature with the matching public npm key and OpenSSL (`Verified OK`).

| Observed item | Exact value |
|---|---|
| Package/version | `htmx.org@4.0.0` |
| Fixed tarball URL | `https://registry.npmjs.org/htmx.org/-/htmx.org-4.0.0.tgz` |
| Selected artifact | `package/dist/htmx.js` (`package.main`, classical entry) |
| Selected artifact bytes | 102,533 |
| Selected artifact SHA-256 | `5d0833e3b435d357221955566f46fa378cb653c4f119c0a8533b4bb4098cf9ad` |
| Published tarball SHA-1 | `72323bd24261364fe3111803c46b80da1fb33445` |
| Published/observed tarball integrity | `sha512-T/171FUY93Kdfp8t+DnHdk45QvKRiBhVhhrwSzrXgUi4pHKvhp77dUA/qg8FAjsFWPIHNbmUuIdCrcVHuiZWng==` |
| Registry signature key ID | `SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U` |
| Public metadata receipt SHA-256 | `545cb7084863f560a0fe90389d8c3b437623c4c23ff9244f182a3211803e0342` |
| Inert artifact/integrity receipt SHA-256 | `01d5b03df927e2352c0ef33dc3c7de19eb092a8ae2e21db8cfb67b8bfceb19b0` |
| Public registry signature receipt SHA-256 | `30fd2c29542b892f02a3f5340df0eb51f3f3f1ff90912b37d0a2280fe7ebc0e0` |

The registry metadata claims upstream Git head
`4195bc0dc26b612ea5bea46f5914c6386eadeba3`; Git tag/source equivalence has not
been independently reconciled. Registry integrity/signature verification is
specific to these downloaded package bytes. It does not prove upstream source
equivalence, maintainer identity beyond the observed registry chain, future
maintenance, vulnerability absence, CSP compatibility or owner adoption.

Raw inspection of this exact source found `credentials: "same-origin"` in
the request defaults, `history: true`, `includeIndicatorCSS: true`, an
`htmx:before:request` event with `{ctx}`, dispatch through
`ctx.fetch(ctx.request.action, ctx.request)` and hx-on evaluated handlers.
The defaults do not satisfy the proposed cookie-free/unchanged-CSP contract
without a separately reviewed integration and actual browser/mutation proofs.
All access/refresh context checks, public JSON transport, redirect refusal,
protected-DOM clearing, every-field encoding/disclosure, history exclusion and
inline/evaluated-feature exclusion remain required. Older 2.x option names
are not evidence of those properties in 4.0.0.

This record preserves UI-003's exact version/digest, upgrade and withdrawal
fallback and observed registry provenance. Independent exact-pin V5 source review
is complete. Root records the preparatory pin under existing full-goal
authorization and the recorded htmx 4 direction, without separately claiming
human risk acceptance. Each attribution refresh requires separate source review and validators. Final
integration, UI-004 project acquisition/embedding, compatibility gates, ADR 0016
real-team evidence and normal ticket closure remain open. Acquisition
and rollout remain DEFERRED. No closure-attribution row or board state is changed.
