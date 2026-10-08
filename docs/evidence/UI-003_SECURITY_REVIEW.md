# UI-003 decision-record source review

Ticket: UI-003. Date: 2026-10-08.
Author/source reviewer: the original UI-003 child agent, `/root/milestone_m4/ui_003`.
Independent source review of earlier corrected V2: `/root/milestone_m3`,
2026-10-08. Independent review of this htmx 4 fidelity successor: pending.
Final integration/owner review: pending. Owner acceptance: not recorded.
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
This records the author's correction, not completed independent V2 review or a
passing browser race test; downstream implementation must prove those refusal and
clearing cases.

TM-055 names every rendered value as an injection site and requires context
encoding for documents and fragments, inert hostile-value proofs per field,
separate log/failure cases, authorized public-field disclosure parity and common
JSON/HTML denial parity. These are distinct **unexecuted** UI-005 obligations.
Untrusted URI values need scheme/origin validation as well as escaping. CSP is
unchanged; neither this review nor the htmx direction permits inline handlers,
evaluated strings or a later silent policy relaxation.

The roadmap retains owner-selected htmx 4. The prior no-library proposal has
not received owner approval and is now a future reviewed alternative only.
No asset was acquired, no exact version/digest provenance was verified and no
library compatibility test ran. UI-003 clause (5) remains open pending an exact
reviewed version AND SHA-256; the conditional pin obligation is not inapplicable
now that the library direction is retained. UI-004 still owns acquisition,
digest verification and compatibility gates. ADR 0017 records a reviewed 4.x
upgrade direction/triggers and the named withdrawal fallback of retaining the
shipped static UI while suspending rollout; it does not silently select htmx 2,
a CDN, weaker policy or a no-library replacement.

Library integration must mediate every request and DOM insertion through the
same explicit credential/context contract and documented public operations.
Access header, JSON DTO transport, same-origin checks, cookie omission and
redirect refusal cannot be delegated to unchecked defaults. Refresh has no
attribute/global/default or second credential path. All inline/evaluated
features and protected browser-history persistence/restoration must be disabled
or rejected; required support or specific option names are not claimed without
verified upstream bytes. If any guard cannot be enforced, refuse acquisition
and rollout. This source review does not execute or qualify those future gates.

## Residual risks and proof still owed

The author/source review records the session decision and htmx acquisition
constraints, **not** a passing runtime or a fulfilled exact library pin clause.
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
not this htmx 4 fidelity successor. Fresh independent source review and final
integration/owner review remain pending.

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
a future owner-reviewed alternative. Exact pin/provenance, acquisition, library
configuration support and compatibility remain unearned; none was checked via
network, registry, code parsing or executing tools in this authoring task.

Earlier independent and Root document validations above describe their exact
V2/V3 sources only. They do not validate this changed successor. No new
independent reviewer, owner risk acceptance, real-team condition, rollout,
DEFERRED resumption, browser/session proof or closure is asserted.
