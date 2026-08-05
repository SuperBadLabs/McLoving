# INPUT-001 security and implementation closure

Date: 2026-08-05

Verdict: PENDING for the implementation gate. The latest reservation-lifetime
fix must pass all nine protected checks and independent exact-head review before
this receipt can certify a specific implementation head. Prior reviewed heads
are historical evidence only and do not close INPUT-001.

The final squash-merge commit is necessarily unknowable from inside its own
pre-merge contents; the immutable PR #32 exact-head checks plus post-merge
protected-main verification will form the final closure attestation.

This receipt does not claim a Mario production input, canary, cutover,
rollback, or Jenkins decommissioning event.

## Inventory denominator

The accepted MIG-000 runtime-dependency manifest SHA-256 is
`238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4`.
The executable inventory test proves that all 230 entries are the sealed
`opaque-cps-runtime`, `controller-global`, `scripted` dependency and that the
manifest declares no admitted live external input. No synthetic fixture is
represented as Mario production truth.

## Implemented boundary

- standalone NDJSON adapter process with self-hashed executable and canonical
  immutable configuration binding;
- one exact GET-only endpoint, no redirects, no ambient proxies, HTTPS/private
  CA production policy, and double-gated loopback fixture mode;
- scoped bearer grant identity/version/scope/expiry/content digest, pinned
  HMAC-key and private-CA content digests, and canonical query allowlist;
- authorization and grant headers validated and cached before spool creation,
  plus fail-closed Unix directory-durability admission before capture service;
- effective-user-owned `0700` spool admission and `0600` coordination, rate,
  claim, and receipt state, with foreign-owned, permissive, non-directory, or
  relative spools rejected;
- bounded regular-file reads for configuration, credentials, full CA bundle,
  executable, claims, and receipts, with symlink and oversize denial;
- tenant/project/pipeline/build/attempt/input, generation, cursor, expiry,
  confidentiality, and audit-lineage binding;
- bounded timeout, retry, response size, rate, freshness, and typed JSON schema,
  with request/grant expiry fenced before each outbound attempt, source
  freshness checked before body sampling, and both rechecked after the complete
  response is captured;
- checked source-age arithmetic denying future, stale, and overflowing
  Unix-millisecond timestamps;
- secret-labelled response denial plus marker-set non-disclosure scanning;
- marker denial across the complete source header set, raw response body, and
  decoded JSON keys and strings before any source-derived value can enter a
  receipt;
- exact singleton cardinality for content type, cursor, provenance, observation
  time, confidentiality, and ETag, with conflicting duplicates denied;
- atomic durable capture claims, no-overwrite receipt publication, restart
  replay, substituted-replay denial, directory durability before source access
  and after receipt publication, matching-claim convergence before admission,
  and serialized rate denial before new claim creation;
- one cross-process exclusive transaction spanning duplicate-claim recheck,
  durable rate reservation, and claim publication so matching callers converge
  without consuming another source-read budget;
- synchronized private claim staging and atomic no-overwrite publication so a
  second adapter process cannot observe a partial request digest;
- disabled client-library retries so every source read is owned by the explicit
  bounded retry counter, with the complete possible outbound-attempt budget
  atomically reserved in a durable spool-scoped ledger before claim publication
  across adapter processes, each charged slot held as non-prunable in-flight
  state across the corresponding GET, and its historical timestamp recorded
  conservatively after send completion;
- spool-scoped shared/exclusive filesystem coordination preventing receipt
  readers from returning before publisher file and directory synchronization;
- duplicate waiters bounded to the claimant's complete retry plus publication
  window; and
- complete signed response receipt with source provenance and canonical value
  digest for identical dual-runner consumption.

## Current executable receipt

The latest suite proves eight contained end-to-end journeys, eleven unit
contracts, and one sealed-inventory denominator check. Focused pinned-Rust,
complete locked workspace, clippy, and all nine protected checks remain pending
on the next pushed exact implementation candidate.

The independent review has produced forty-six actionable implementation
findings across the implementation-head sequence to date: implicit client
retries; pre-read claim-directory
durability; rate denial leaving a claim; duplicate capture admission at low
rate; post-receipt directory durability; secret-marker leakage through response
headers; visibility of a partially written claim across adapter processes;
Windows directory-sync failure after claim publication; authorization-header
validation after claim publication; overflowing source freshness arithmetic;
secret-marker evasion through JSON escaping; and freshness capture before a
delayed response body completed; and request/grant expiry during response-body
capture; ambiguous duplicate source-policy headers; and retries not individually charged against the
source-read rate ceiling; it was fixed with conservative atomic attempt-budget
reservation before claim publication and a no-stranded-claim regression.
The final three findings showed that independent adapter processes did not share
rate state, duplicate waiters used only one attempt timeout, and waiters could
observe a linked receipt before directory synchronization. Durable spool-level
rate state and advisory coordination plus a full retry/publication wait window
now close those races.
The last two findings identified a gap between spool-rate reservation and claim
publication plus ambient-umask exposure of internal receipts. Admission now
holds one exclusive spool transaction through claim durability, and private
directory/file modes are verified by executable fixtures.
The final finding identified relative spool identities that could resolve to
different state after a working-directory change; configuration now rejects
them before creating any state.
The final ownership finding showed that mode checks alone cannot protect state
inside a `0700` spool owned by another UID. Spool admission now binds directory
ownership to the adapter's effective UID before accepting or creating state.
The last two findings identified a retry starting after request or grant expiry
and a restarted reader accepting a linked receipt before its directory entry
was proven durable. Every outbound attempt is now deadline-fenced, and every
stored-receipt replay exclusively synchronizes the spool before returning.
The final two findings identified an unsynchronized first-time spool entry and
blank required source provenance. Creation now synchronizes an existing
canonical parent before admission, and required headers reject empty or
whitespace-only values.
The final ordering finding showed that an expected-cursor mismatch could be
masked by later body processing. Cursor admission now fails before reading any
body bytes, while freshness remains fenced after complete capture.
The final freshness-ordering finding showed the same precedence gap for an
already stale or future observed timestamp. Source age now fails before body
processing and is rechecked after complete capture for delay-induced staleness.
The final rate-window finding showed that stamping every reserved retry slot at
admission could let a later retry age out before its GET began. Durable
per-capture reservations now retain capacity across rate windows and convert
one slot to its actual start timestamp immediately before each outbound attempt;
unused slots release only after the terminal fetch result, and legacy timestamp
ledgers remain readable.
The last rate-timing finding showed that durable ledger I/O or scheduling could
still age a timestamp before the GET started. A charged slot is now durable,
non-prunable in-flight state until send completion and only then becomes a
conservative historical timestamp. The paired documentation finding corrected
`timeout_ms` to a per-attempt bound and records the retry-expanded network
ceiling.
The final retry-boundary finding showed that a successful status followed by a
body-stream reset escaped the per-attempt loop. Header policy and precedence
checks still run before body sampling, while bounded body transport now remains
inside the loop and may consume the next reserved attempt only for a transport
failure; a reset-then-success fixture proves the behavior.
The final in-flight recovery finding showed that a process exit could otherwise
consume rate capacity forever. Each charge now carries the checked
authority-expiry-plus-timeout bound; a stranded charge reconciles into the
one-minute historical ledger at that deadline and then ages out automatically.
The last two findings bounded adversarial marker-scan work and removed a
first-boot race between shared-spool peers. Marker sets must be unique and fit a
fixed aggregate response-scan budget before state creation; a losing directory
creator re-reads, validates, and synchronizes the peer-created private spool.
The final work-bound review required marker length, not only marker count, in
the adversarial comparison ceiling and required in-flight expiry arithmetic to
be proven before claim publication. Admission now uses checked
response-by-total-marker-byte work and checked authority-expiry-plus-timeout;
overflow and excess work fail without state or source access.
The last two findings charged only one of the raw/decoded marker scans and found
that a trailing slash could make final-component symlink metadata follow its
target. The work ceiling now explicitly charges both scans, and existing or
new spool paths must themselves canonicalize exactly before admission.
The final reservation-cleanup finding showed that a claim publication error
could return after durable rate reservation without releasing that unused
capacity. Claim failure now removes and durably records release of the matching
reservation before returning, while the successful and duplicate-claim paths
retain their existing accounting semantics.
The first duplicate-wait finding showed that deriving the complete wait from a
very small source timeout could exhaust the wait during normal local receipt
processing and durable publication. A follow-up showed that any unfenced fixed
allowance could still expire before a paused or slow publisher later succeeded.
Claims now durably bind an absolute authority- and work-bounded publication
deadline; outbound reads and publication are fenced by it, and the signed
receipt binds it. A final ordering review moved receipt absence and deadline
expiry into one transaction under the same exclusive spool lock used by the
publisher. A waiter can no longer return unavailable before a late receipt
appears.
The separate closure-documentation review corrected timing language so the
receipt states the pre-GET expiry fence, pre-body freshness check, and both
post-capture rechecks instead of implying that validation occurred only after
body capture.
The latest JSON-boundary review found that duplicate object members could hide
an escaped secret marker when deserialization retained only the later value and
that default JSON-number parsing could round a high-precision value before
receipt signing. The parser now rejects duplicate members recursively before
building a value and preserves arbitrary-precision number text through the
signed receipt; contained fixtures prove both properties.
Each prior finding was corrected with a regression fixture or explicit
fail-closed platform admission where applicable and resolved only after its fix
was present on the reviewed head. The latest JSON-boundary fixes remain open
until the next exact candidate passes the complete gates and independent review.

## Residual risk and authority boundary

V1 validates top-level JSON field types rather than an arbitrary schema
language. Secret-labelled inputs are unsupported, and marker scanning cannot
prove non-disclosure of every transformed secret. The adapter and verifier
share an HMAC key, so their collusion could forge a receipt. Host, endpoint,
private-CA, read-grant issuer, adapter operator, and marker-set operator remain
trusted within their explicit scopes. DIFF-003, SHADOW-001, CANARY-001,
CUTOVER-001, ROLLBACK-001, and SEC-004 remain mandatory for any later real
input and authority transition.
