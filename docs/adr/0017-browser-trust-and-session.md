# ADR 0017: Browser trust and bearer session for rendered representations

Status: Independently source-reviewed preparatory decision; rollout DEFERRED.
UI-003 remains DEFERRED. Final integration of this attribution refresh is pending;
no separately claimed human risk acceptance, implementation, deployment or closure
is recorded.
Ticket: UI-003. Recorded 2026-10-08 against source revision
`7e5de0785a0ac5b1f98bd28dbcf50980806cf871`.
Exact-pin V5 source binding: PR #189 head
`b35682b552a103140f963a491c6ba13b79ad1e11`; Root joined all 2,215 frozen
V5 source files to that Git tree. This attribution refresh is a new candidate,
not that head's checks or a new protected-main result.

## Scope and present facts

This record decides the model for a later rendered interface. It does not change
the served UI, API, schema, routes, assets, session implementation or CSP. UI-002
is DONE; its retained initial and accepted browser baselines remain unchanged.
UI-003 remains DEFERRED and this record does not close it. ADR 0016's real-team
condition for resuming the rewrite remains in force: authoring decision records
does not prove a real team runs real pipelines, resume UI-004 through UI-009, or
grant production, migration, CASE, credential or deployment authority.

The present static client copies `#token.value` to `context.token` and leaves the
input populated (`crates/controller-api/ui/app.js:304-309`). The password input
and the memory-only hint are at `ui/index.html:25-28`. Password masking and
`autocomplete="off"` do not remove the DOM copy; the current client is not a
memory-only implementation. Its API helper attaches a bearer header
(`app.js:59-64`) and artifact download does the same (`app.js:293`).

OIDC start, callback, refresh and logout are already public routes. Callback and
refresh return JSON `SessionResponse`, containing **both** access and refresh
tokens and their expiries (`src/oidc.rs:207-219, 382-456, 787-806`). Responses
use `no-store` (`491-496`). Access TTL is configured, at most one hour; refresh
TTL is configured, longer than access and at most 24 hours (`29-30, 114-119`).
These backend mechanisms do not decide browser storage or rendering. Existing
rotation preserves the family's absolute refresh deadline, revokes the replaced
session, and rejects reuse; authorization checks live identity/provider/session
generations (`crates/controller-store/src/identity.rs:1105-1223`).

## Decision and rejected alternative

Choose **bearer transport with one tab-local JavaScript credential store**. Both
OIDC credentials reside only in that store and unavoidable bounded transient
request/response objects. Resource requests attach access via `Authorization`;
refresh uses the documented JSON body, not a cookie. Use same-origin external
script, the roadmap-selected **htmx 4 acquisition direction**, and explicit
browser Fetch/DOM integration for the credential lifecycle. No credential
may be embedded or reflected by the controller into a document or attributes.
The successor must implement the contract below; this ADR is not evidence that
the present token field conforms.

Reject a cookie session for this lane. Secure, HttpOnly, appropriately scoped
cookies could reduce direct credential reading by JavaScript and support normal
authenticated navigation. They also introduce ambient browser authority and
require explicit CSRF protection for both resource changes and refresh/logout,
a decided refresh-cookie lifecycle, and an adaptation of the bearer public API.
SameSite alone would not settle login CSRF, XSS-driven authorized requests or
rotation. We choose the explicit existing bearer boundary and accept that a
successful same-origin script injection can steal either memory credential and
act with the victim's authority. This residual risk is recorded for review,
not claimed to have received owner risk acceptance.

Persistent browser storage is also rejected, including a refresh-only storage
exception. Persistence would make reload convenient but extend recoverable
credential lifetime and leave the longer-lived credential exposed after the
page was gone. Neither CSP nor header transport alone makes memory safe from XSS.

## Credential contract

| Concern | Access credential | Refresh credential |
|---|---|---|
| Entry | OIDC JSON installs it in the one credential store. Until UI-007 replaces manual sign-in, the existing user-entered API token may populate that same store; it never creates a parallel session mechanism. | Only the OIDC JSON response supplies it. No user-entered refresh field, second login mechanism or refresh cookie is introduced. |
| JavaScript copies | Tab-local closure state, the response parsing object and short-lived header/request objects only; do not attach to globals, UI models, telemetry or errors. | Tab-local closure state, parsing object and short-lived JSON refresh request only; never attach to normal resource requests. |
| DOM and token entry | A user typing/pasting into an input necessarily creates a transient DOM value. On submit, read it, immediately clear the field before awaiting any operation, and clear on context reset/page exit; do not repopulate after success or failure. Masking is not erasure. UI-007 removes manual token entry in favor of OIDC in the same store. | Never put it in an input, text node, attribute, serialized HTML or DOM-bound object. |
| Persistent storage | No local/session storage, IndexedDB, cookie, URL/query/fragment, history state, cache entry, service worker, filesystem export or browser-managed credential saving by the application. | Same prohibitions, with no persistent-refresh exception. |
| Lifetime | Honor returned `expires_in_seconds`; do not extend it or treat a client clock as authorization. A manually supplied API token has no invented expiry or refresh behavior: the server decides and refusal clears it. | Honor returned `refresh_expires_in_seconds` and the server's absolute family deadline, at most the configured 24-hour cap; refresh does not renew that deadline. |
| Rotation | Replace with the new access token together with the new refresh token after a successful refresh; retire old references. | One refresh in flight per tab, never parallel/replayed refresh or automatic retry with the old token after an ambiguous result. Install the new pair atomically only on a valid successful JSON response; otherwise clear both and require sign-in. |
| Revocation | Use documented bearer-authenticated logout while access is valid. A refusal clears local authority; provider/identity/session-generation changes and server revocation remain authoritative. | Logout and reuse handling must preserve the server's session/family revocation rules; clearing browser memory is not server revocation. If logout cannot complete or access already expired, clear both and report local sign-out with server revocation unconfirmed; no false revoked claim or hidden refresh solely to log out. |
| XSS | Same-origin malicious script can read the live token or issue requests; no claim that memory, masking or CSP eliminates this. Minimize DOM residence and copy lifetimes; output encoding below is required. | Same-origin malicious script can steal the longer-lived token; memory-only limits persistence, not live-page access. Treat loss of either credential as loss of the pair. |
| CSRF | Require an explicit header from the tab, with no cookie fallback or credential-bearing navigation. Cross-origin requests receive no bearer authority implicitly. | Send JSON with `Content-Type: application/json` from same-origin script, no cookie/authentication fallback, no form or URL transport and no permissive cross-origin credential access. |

All credential-bearing Fetch operations use `credentials: "omit"`, fixed
same-origin public paths and refusal of redirects; no caller-supplied remote
destination is allowed. Never include credentials in logs, exception text,
download URLs, rendered errors, fragment markup or `postMessage`. Context changes
and page teardown discard both credentials, pending refresh work and token
fields. Clearing references is not a guaranteed physical wipe: browser internals,
extensions, developer tools, password managers and garbage collection are residual
risks, outside an application's promise of zero memory copies. Resource responses
must not expose credentials through their authorized DTOs either.

The credential store also owns a monotonically advancing **context generation**,
bound to organization, project and the current credential/session pair (or manual
token slot). Capture that generation and context **before** each asynchronous
resource, login or refresh operation. Immediately before any protected DOM update,
popup-message acceptance or credential/refresh commit, require the same captured
generation and still-active context; discard late or mismatched results even if
their HTTP request succeeded. A refresh may install its pair only against its
captured active generation, then advances the generation so outstanding old-session
resource results cannot become current content. Client generation is a race guard,
not an authorization claim; the server still makes every authorization decision.

Context change, reset, sign-out and loss/refusal of authority first invalidate the
generation and clear prior protected displays, downloaded-object handles, token
fields, pending login and refresh work, before installing any new context or
authority. Abort pending requests where possible, but response/commit generation
checks remain required even when cancellation loses a race. A late popup message
or successful refresh cannot resurrect a signed-out context. Logout can use its
captured credential for the existing server operation; its eventual confirmation
must not reinstall credentials or repopulate protected content. This is a successor
contract: the present mutable `context` client has neither this protected-DOM
clearing nor a response-generation guard, and is not claimed to conform.

This is the CSRF decision now: there is **no ambient cookie session**. Keep
resource authentication explicit, refresh JSON-only and non-simple, and the
controller origin closed to untrusted CORS callers. Cross-site forms/navigation
must not authorize a mutation, refresh or logout; cross-site scripts must not
obtain a credential-bearing response. Do not add a cookie fallback or call a
transport choice a substitute for those checks. Login CSRF separately requires
the existing state/nonce/PKCE validation plus correlation of the browser's initiated
login to its exact organization, provider and returned state. Downstream forged
request and login-mismatch cases must prove refusal; their execution is still owed.

## Navigation, sign-in and progressive behavior

Ordinary initial navigation serves only an unauthenticated static shell: the
browser cannot add the chosen Authorization header to that navigation. Tenant
data and authenticated fragments arrive only via same-origin script requests.
Links never carry credentials. Full reload, browser restart, duplicate/new tab,
or loss of tab memory requires sign-in again. Cross-tab credential sharing,
background persistence and a cookie that silently restores authority are refused.

The UI-007 OIDC journey must use the same credential store. A concrete compatible
shape is an opener-owned login popup: call existing start with an explicitly
configured, exact-allowlisted **same-origin static-shell** redirect URI; correlate
the returned authorization URL's state with the pending login; navigate the popup
to the provider. The returning shell reads and immediately removes code/state
from its URL before displaying content, passes only that one-use code/state to
its initiating opener using exact-origin `postMessage`, and the opener validates
both message origin and source window plus expected state/org/provider. The opener
calls the existing callback API with code/state and consumes its no-store JSON
into the one store. Access/refresh tokens never pass via URL, popup messaging or
HTML. Close the popup and discard pending login on completion, cancellation,
mismatch, timeout or opener loss. The server still validates stored state, nonce,
PKCE and the original redirect URI; a client match is not authorization.

This uses the existing static shell and public OIDC operations, not a privileged
HTML callback or a new route. A deployment that has not exact-allowlisted that
shell URI cannot use this journey until its separate configuration authority
allows it. Direct navigation to the present callback API displays JSON and is
not the proposed UI journey. Popup blocking or an isolated/lost opener yields an
explicit sign-in failure, never token-in-document fallback. Provider navigation
is not a cross-origin credential Fetch and must not cause a `connect-src` relaxation.

With scripting unavailable the shell may show public structural content and an
explicit limitation, but no authenticated tenant reads, fragment navigation,
mutations, artifact downloads, refresh or sign-in. There is no claimed no-script
authenticated progressive mode and no separately invented session path. With
external script unavailable, the same limitation applies; on an individual
fragment failure keep the last authorized display labelled stale/refused and
do not apply an unverified response **only while that display remains bound to
the same still-active captured context and generation**. Authority loss, context
change, reset or sign-out clears it instead; content from a prior tenant/project
or session may never survive under a replacement context. UI-006 must state and
gate these costs per
view. If the htmx asset is unavailable or incompatible, do not issue an
authenticated library request or apply a fragment. Show an explicit limitation;
retain only an already authorized display in the same still-active context, as
above. UI-006 must gate absent/refused-library behavior as well as no-script
behavior. There is no automatically selected no-library replacement interface.

## Public API and common authorization invariant

Restate UI-001 for this model: **the browser obtains authority and all resource
data through documented public operations; the controller is the sole
authorization authority. A rendered representation is a documented presentation
of an existing authorized public resource/method, authenticated by the same
bearer credential, and derived only from its public response DTO or an equivalent
field-by-field authorized projection.** There is no privileged backend path,
embedded secret, client-side grant or view-layer authorization decision.

Representation selection occurs after the same shared authentication and
authorization path as JSON; a view never calls the store directly to assemble
unfiltered tenant records or independently decides access. Every HTML resource
must join mechanically to its existing public route/method. If a required public
operation does not exist, file/complete its separate API work first. Presentation
derived from authorized values is allowed; internal fields, for example
`BuildSnapshot.execution_spec` absent from `BuildResponse`, are not.

These are obligations for UI-005 and each later added representation, not claims
that HTML/JSON parity already passes. UI-005 owes the route/method applicability
matrix, same-denial tests (unauthenticated, wrong tenant/project, stale fence,
retired epoch, absent object with explicit policy-based not-applicable reasons),
mechanical counterpart/shared-path joins, per-field disclosure parity and an
internal-field mutation. Existing `route_denials.rs` assertions remain intact.
Sharing a function name or reviewing a template is insufficient proof.

## Output-encoding boundary and CSP

Every value rendered into HTML is an injection site, including names, slugs,
log lines, failure reasons, audit payloads and artifact paths. Present JSON-to-DOM
code generally uses `textContent`; HTML parsing creates a new boundary whose
failure modes include tags, attributes and parser context. JSON encoding alone
does not make HTML safe. Treat all public values as untrusted even after
authorization. Use context-appropriate HTML text/attribute encoding; avoid raw
HTML insertion, executable contexts and dynamically authored style or handler
attributes. Validate URL schemes and keep resource URLs same-origin; escaping
alone does not make a `javascript:` URL safe. Never interpolate data into scripts
or CSS. Fragment HTML and complete documents need the same encoding discipline.

Register TM-055 records this prospective boundary. UI-005 owes hostile-value
corpora through **every field of every rendered view**, with separately named
log and failure cases, inert parsed-document/browser assertions and mutation
proofs. Authorization parity, disclosure parity and encoding are distinct gates.

Preserve exactly the shipped `UI_CSP` (`src/lib.rs:845`):

```text
default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
```

No inline script, style, handler attribute or evaluated string is permitted;
external script/styles remain same-origin. No CDN, `eval`, string timer,
`Function` constructor or inline fallback is allowed. UI-004 and UI-006 keep the
same policy for htmx and for any later owner-reviewed alternative. Existing
textual CSP/structural contracts and
historical UI-002 browser results do not prove the successor works under it;
unchanged-header browser, no-handler and no-evaluated-string gates with named
mutation proofs remain owed. A proposed relaxation requires a **separate explicit
owner decision and coordinated board revision before implementation**; UI-003
does not authorize it.

## Library direction, acquisition gates and review attribution

Retain the roadmap's owner-selected **htmx 4** direction. UI-004 explicitly
records that selection; the earlier proposed no-library branch did not receive
owner approval and is not the current disposition. The allowed no-library
branch remains a **future owner-reviewed alternative** requiring a revised
decision and coordinated UI-004 disposition under its normal closure gates.
It is not a withdrawal fallback silently chosen by this record.

The supported-upgrade direction is the 4.x line, with each move separately
reviewed and pinned by exact version and SHA-256, never a floating registry tag.
The preparatory exact pin is **htmx.org 4.0.0, `package/dist/htmx.js`**, the
classical entry declared by that release's `package.main`: **102,533 bytes**,
SHA-256 **`5d0833e3b435d357221955566f46fa378cb653c4f119c0a8533b4bb4098cf9ad`**.
Root obtained the fixed public npm release in a private inspection directory,
verified its tarball SHA-1 and SHA-512 against the version metadata, and verified
the npm registry ECDSA signature using the registry's public key. The exact
receipt hashes and acquisition URL appear in the security review. This records
a concrete version AND digest for UI-003 clause (5). The exact-pin V5 source
received independent source review by `/root/milestone_m1/dogfood001`, with no
findings, for required document validation and authorized draft publication only.
Root records this exact pin as the preparatory decision under the user's
authorized full-goal work and recorded htmx 4 direction. This is not a separately
claimed human risk acceptance; acquisition and rollout remain DEFERRED.
Upstream Git tag/source equivalence, maintenance promises and integration
compatibility have not been established.

The private upstream inspection did not place library bytes in the project or
execute JavaScript. UI-004 owns subsequent reviewed tree acquisition, digest
verification and same-origin embedding with no runtime toolchain, retaining
the existing CSP and repository dependency gates. UI-004 acquisition into the
tree and library compatibility tests remain unrun. UI-004's filing facts about
early adoption, registry tags and inheritance costs remain recorded claims;
the artifact observation does not newly verify those claims.

Upgrade triggers are a reviewed security advisory, upstream maintenance or
withdrawal notice, or a required compatibility fix demonstrated against the
pinned asset and unchanged policy. The named withdrawal fallback is **retain
the existing shipped static UI and suspend the rendered rollout/acquisition**
until a reviewed exact replacement pin passes all gates. Do not automatically
move to htmx 2, a CDN, a weaker CSP or a no-library interface. A pin's withdrawal
or inability to satisfy the contract keeps the lane open. Any new line or
no-library fallback requires the separate owner-reviewed decision, not an
inferred approval or a registry-tag change.

The library confers no independent authority. External same-origin integration
must mediate **every** request and insertion: capture the active context before
async work; recheck it and the allowed public route/method/origin immediately
before dispatch; attach access only as an Authorization header; use the
documented JSON DTO and Content-Type for JSON operations instead of converting
them to forms, query credentials or a second transport. Refresh/logout/OIDC
continue through the one explicit credential store and documented operations;
refresh is never a library attribute, global default or resource-request token.
Recheck captured context before any response commit or DOM insertion, including
late/error responses and cached/history restoration; no library-managed swap
can bypass protected-DOM clearing or stale-result refusal. Credentials may
exist only in the store and bounded transient request objects, never DOM
configuration, library-global defaults, attributes, history snapshots or logs.

Disable or reject **all** inline script/style/handler and evaluated-string
features, including scripting-prefixed values, event filters and scripting
extensions; do not rely on CSP blocking them after a partial interaction.
Disable or reject library browser-history persistence and restoration of
protected HTML, context or credentials; no local/session storage or history
cache exception is permitted. The adapter must preserve cookie omission,
same-origin destination checks, redirect refusal and current-context checks
for every request. Inert inspection of the pinned source found default request
`credentials: "same-origin"`, configuration `history: true` and
`includeIndicatorCSS: true`, an `htmx:before:request` event carrying `{ctx}`,
and dispatch through `ctx.fetch(ctx.request.action, ctx.request)`. It also
found `hx-on` handlers invoking the JavaScript evaluator. These are source
observations, not verified enforcement mechanisms. The integration must prove
actual cookie omission, complete request/response mediation, disabled protected
history, absence of injected indicator styles and every inline/evaluated
feature under the unchanged CSP. Older-library option names must not substitute
for proof against this artifact. If this version cannot enforce any required
guard or prohibition, refuse acquisition and rollout instead of weakening the
contract.

UI-004 owes unchanged-header operation, separately named absence of every
inline/evaluated feature, exact digest validation and mutation proofs. UI-005
owes common authorization, per-field disclosure/encoding and both-credential
handling; UI-006 owes migrated-view/library-unavailable/no-script behavior.
Actual supported integration points and their proofs must be recorded against
the exact pinned bytes before implementation. This is an acquisition direction
and contract, not a claim of htmx compatibility or rendered-browser behavior.

The actual records review is in `docs/evidence/UI-003_SECURITY_REVIEW.md`, cited
by TM-055 and its decision-review attribution. It records the author review and
separate independent exact-pin V5 source review; neither is human risk acceptance,
runtime qualification or a closure receipt. Each attribution refresh requires its own independent review and required
validation; current candidate observations are recorded in PR #189. The normal Closure attribution
table must acquire `UI-003 | docs/evidence/UI-003_SECURITY_REVIEW.md` only after
exact-head checks, independent review, protected merge and post-merge required
verification are observed and UI-003 is legitimately DONE. Adding that machine
row now would falsely assert closure and violates its existing convention.
