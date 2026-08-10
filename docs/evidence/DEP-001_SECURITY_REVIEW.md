# DEP-001 security and implementation closure

Date: 2026-08-10

Verdict: LOCAL PASS for the architecture-repair candidate at exact
implementation head `075634f6ce6ee6f1ef5e371cbad313dddab4aaf3`.
The focused gate passes 123 dependency-resolution tests: 78 unit tests, 44
ordinary integration tests, and one real exact-capacity
tmpfs/HTTP/standalone-process test. Strict all-target resolver Clippy,
formatting, and `git diff --check` also pass on HeMan. This head replaces both
dynamic per-resolution directory hierarchies with exclusive regular archives,
closing the two repeated `mkdirat`/`openat` creation windows that blocked the
prior candidate. Documentation closure head
`8d15ca537db6ccaea91fe041514f4b6de76bdbf7` additionally passes workspace-wide
strict Clippy, the complete locked non-source workspace, the exact-capacity
resolver journey, execution-board verification, and the serialized 19-case
AppArmor-confined source-acquirer matrix on HeMan. Protected workflows and fresh
independent exact-head review remain mandatory before this receipt may return to
a final PASS verdict, before fixed threads may be resolved, and before merge.

The DEP-001-to-CACHE-001 post-merge execution-board transition entered PR #35 at
`02a0fac42c94b6624d3874338c23eb09bd319238` and was already present at an
earlier implementation head. Closure
commits update this receipt and recertify those existing board rows; they
do not introduce the transition. The complete PR #35 diff against protected
`main` includes the resolver implementation, tests, protected workflow change,
architecture documentation, receipt, board transition, and recertification. The
complete exact PR head must independently pass protected checks and review before
merge. The final squash-merge commit is necessarily unknowable from inside its
own pre-merge contents; immutable complete-PR exact-head checks plus post-merge
protected-main verification are the final closure attestation.

This receipt does not claim a Mario production dependency repository,
credential, resolution, cache, canary, cutover, rollback, or Jenkins
decommissioning event.

## Inventory denominator

The accepted MIG-000 Mario runtime-dependency inventory contains exactly 230
`opaque-cps-runtime`, `controller-global`, or `scripted` records and zero
`workload-dependency` records. The executable inventory proof preserves that
zero denominator. The separately sealed 228-file historical Jenkins corpus is
provenance evidence and is not substituted for live dependency authority.

## Implemented boundary

- standalone strict-NDJSON process with closed frames, recursive duplicate JSON
  denial, bounded pre-allocation input, static errors, and exact executable and
  configuration identity;
- strict closed Maven, npm, and PyPI adapters that admit exact canonical versions
  and complete transitive graphs without online solving, install scripts,
  alternate origins, local/VCS inputs, mutable ranges, snapshots, or metadata
  discovery;
- content-derived node identities and a canonical graph digest binding ecosystem,
  adapter, source tree, lock, resolver/toolchain, repositories, coordinates,
  versions, paths, sizes, content, attestations, edges, and roots;
- certified repository origins, coordinate prefixes, source-trust rules,
  credential grants, private CA and Ed25519 key digests, generation/rollback
  lineage, resource ceilings, and one absolute nanosecond-preserving monotonic
  request/publication deadline;
- a dedicated Ed25519 source-provenance authority whose certified identity,
  path, and content digest are loaded through the same private no-follow
  boundary as every other authority; its canonical signature covers the
  complete request, including trust class, acquisition receipt, source tree,
  lock path/digest, scope, graph, repositories, configuration/generation, and
  lifetime, before a claim or credentialed repository policy can be reached;
- componentwise no-follow authority loading that requires resolved, single-link
  regular files outside every mutable resolver root and a unique device/inode
  for each receipt key, marker set, repository credential, attestation key, and
  private CA role, plus unique verified content digests across all roles; every
  final authority path is pinned with `O_PATH|O_NOFOLLOW`, rejected unless
  regular before data open, reopened only from `/proc/self/fd` with
  `O_NONBLOCK`, and device/inode rechecked; certified configuration and
  executable reads use the same pinned-inode pattern, with single-link policy
  also enforced for configuration; every opened authority-path component
  identity is compared with bounded,
  non-symlink-following, path-distinct FIFO scans of the mutable roots whose
  entries are counted before worklist insertion; bidirectional secret-role
  containment trims HTTP optional whitespace, expands case-insensitive Basic
  credentials through padded/unpadded standard-Base64 decoding, compares raw
  and decoded views, matches hexadecimal ASCII-case-insensitively, and checks
  exact standard/URL-safe Base64 forms;
- exact-path GET transport with redirects, ambient proxies, decompression,
  credential helpers, alternate origins, and every explicit or client-library
  implicit retry disabled, including HTTP/2 protocol-NACK retries;
- bounded response headers and streaming bodies verified for status, type,
  repository, generation, length, SHA-256, Ed25519 attestation, and every
  independently configured credential or receipt-key marker;
- a canonical private resolver-owned Linux transport mount whose exact block
  capacity equals the aggregate ceiling, differs from parent/output devices,
  is exclusively locked, and denies residual state before claims or requests;
  existing lock inspection first pins the path with `O_PATH|O_NOFOLLOW`, rejects
  non-regular type, owner, link, or mode before device open behavior, reopens
  only the pinned inode through `/proc/self/fd` with `O_NONBLOCK`, and rechecks
  identity; logical metadata length is rejected beyond the exact constant
  before allocation, reads are capped at that length plus one, and owner, link,
  mode, length, and directory-entry identity are rechecked after initialization
  so sparse files, FIFOs, devices, replacements, growth races, and other
  substituted state fail closed without blocking or unbounded allocation;
- durable first-writer claims, in-process concurrent convergence, explicit
  restart ambiguity, one exclusive contiguous transport archive bound by its
  retained descriptor identity, one strict-header sealed publication archive,
  atomic no-overwrite publication, and fail-closed exact-inode cleanup, with
  archive verification and transient cleanup completed before the durable
  completion record becomes visible;
- HMAC-SHA-256 receipts binding the exact request, configuration, executable,
  source/lock/plan/graph, repositories/grants, artifacts/attestations, complete
  retained archive, marker set, generation, rollback, and deadline, with
  constant-time verification, direct delivery of the worker-verified committed
  receipt, and durable ambiguity when rollback or post-commit delivery cannot
  be proven;
- exact equality between the repository identities used by graph nodes and the
  request repository/grant bindings, so unused repository or credential
  authority cannot enter a signed resolution receipt;
- exact offline replay that revalidates receipt HMAC, request and runtime
  bindings, the strict bounded archive header, closed manifest and entry table,
  owner/mode/type/link/size/fingerprint policy, every payload digest, final
  pathname identity, and the complete archive digest without repository access;
  and
- one stateful stdout guard across the complete standalone process lifetime that
  detects configured markers within or across serialized response frames before
  emission, acknowledges new completion only after a safe frame is flushed,
  bounds and poisons ambiguous post-flush acknowledgement, and installs silent
  fatal and panic handling before Tokio runtime construction.

The governing contract is `docs/architecture/DEPENDENCY_RESOLUTION_V1.md`.

## Executable evidence

The ordinary focused suite proves:

- canonical Maven, npm, and PyPI topology plus exact later-version graph change;
- unknown, duplicate, mutable, noncanonical, ranged, snapshot, encoded-traversal,
  unsupported, cyclic, missing-node, and resource-exhaustion denial;
- exact configuration, UUID, lock, source, adapter, toolchain, repository,
  coordinate prefix, trust, credential grant, generation, rollback, graph,
  attestation, and request-time binding;
- canonical source-provenance signature, public-key digest, authority identity,
  lifetime, trust-class, acquisition-receipt, source-tree, lock, and tenant
  scope binding before repository policy;
- private authority owner/mode/no-follow/digest policy, resolved separation from
  mutable roots, single-link, cross-role device/inode and content-digest
  uniqueness, raw, structured-Basic, mixed-case-hex, and Base64
  secret-bearing-role content-overlap denial, minimum receipt-key strength, and
  exact credential/receipt-key marker membership;
- prompt real-FIFO and device denial before data-open behavior for certified
  configuration and every authority role, including pinned-inode identity
  revalidation;
- correct transport plus wrong mirror, content, size, signature, key, repository,
  generation, missing, offline, timeout, and cross-chunk marker denial;
- sparse oversized, FIFO, and real-device transport-lock denial before
  unbounded allocation, blocking reads, or device open behavior, plus exact
  lock-length and identity verification after initialization;
- claim-first concurrency, request substitution, restart ambiguity, exact replay,
  generation cutover, explicit rollback lineage, late withdrawal, foreign
  transient-path denial, retained-archive substitution, receipt-HMAC tampering,
  pre-claim secret-marker denial, archive verification before completion,
  pre-completion transient cleanup, post-commit delivery ambiguity, and cleanup
  truth; and
- standalone config mode/symlink/schema, bounded frame, static response, and
  sealed Mario zero-authority behavior, including stateful cross-frame marker
  denial, replay/convergence acknowledgement ownership, and silent startup,
  fatal, and pre-runtime panic paths;
- standalone configuration FIFO/device denial before blocking startup open;
- strict archive-schema, exact-length, closed-path, contiguous-offset,
  unmanifested-byte, payload-substitution, and final-link-replacement denial;
  and
- a focused 100,000-node linear-graph regression that directly exercises
  iterative reachability and cycle validation without recursive stack growth.

The protected contained journey uses the real standalone executable, a live
credentialed HTTP Maven repository, Ed25519 attestations, and a disposable
`nosuid,nodev,noexec` tmpfs whose measured capacity is written into the certified
configuration. It proves a real bind-mounted alias from the mutable receipt tree
is rejected by filesystem identity; a self-bind of the mutable root with an
authority directory mounted only beneath that alias is independently traversed
and rejected; two concurrent identical requests converge on one GET; an
untrusted request signed by the source authority and then forged to `Trusted`
is denied by provenance verification with zero repository GETs; an
exact-capacity artifact fails closed and cleans up; wrong-graph and untrusted
requests cause zero GETs; a valid request publishes; a later exact version under
the same resolution identity is denied offline; restart with the repository
offline returns byte-equivalent JSON; and neither the repository credential nor
receipt key appears in stdout, stderr, or the receipt.

Exact implementation head `075634f6` passes strict resolver all-target Clippy,
formatting, `git diff --check`, all 122 ordinary focused tests, and the real
exact-capacity contained journey on HeMan. Documentation head `8d15ca5` passes
workspace-wide strict Clippy, the complete locked non-source workspace, the
same contained resolver journey, board verification, and the complete
serialized AppArmor source-acquirer suite. Protected Foundation and Windows
checks plus fresh exact-head review remain open.

Foundation run 31327583362 completed on unchanged-head attempt 2. Attempt 1's
only failures were three unrelated provisioner timing assertions under shared
runner load; the exact three tests immediately passed individually on HeMan in
0.15, 0.07, and 0.31 seconds, and the unchanged rerun then passed the complete
provisioner and Foundation gates. No DEP-001 code or evidence claim changed in
response to that runner-only failure.

## Review-driven hardening

Pre-closure review and repeated contained execution exposed and repaired 140
actionable findings across 145 important seams. Five comments repeated an
already counted underlying seam and are not double-counted:

1. A concurrent reader could observe a receipt after create but before its final
   read-only mode. JSON state now becomes visible only through a fully written,
   sealed, synchronized temporary file and atomic no-overwrite rename.
2. Whole-millisecond wall sampling could extend authority by almost one
   millisecond, and publication retained only the wall deadline. Resolution now
   preserves a one-nanosecond remainder and carries the same absolute monotonic
   deadline through every publication/withdrawal decision.
3. Caller-controlled audit or package fields could contain a known credential
   and launder it into a signed receipt. Canonical request, plan, and final
   receipt bytes are marker-scanned before claim or publication.
4. Failed transport or output-stage cleanup could be silently discarded in
   favor of the original error. Cleanup ambiguity now dominates and remains
   explicitly fail-closed.
5. Receipt verification used an ordinary string comparison and lacked a direct
   HMAC-mutation proof. Verification now uses the HMAC implementation's
   constant-time check over canonical lowercase bytes, with an adversarial
   sealed-receipt regression.
6. The certified path ceiling was not applied to logical lock and artifact
   paths. Request and plan admission now enforce the signed ceiling, while
   configuration prevents a value above the protocol's 4096-byte maximum.
7. A certified frame ceiling could be smaller than the standalone process's
   static fallback response. Configuration now requires at least 128 bytes,
   which contains both fallback objects and their line terminator.
8. Blocking publication I/O could pin the async request beyond its absolute
   deadline. Publication now runs in a bounded copy of the exact verified
   executable, receives the same absolute Linux monotonic deadline, verifies
   the exact durable parent claim, and is killed at expiry. Any termination
   ambiguity retains the claim and transient slot for explicit reconciliation.
9. Response marker scanning covered header values but not source-derived header
   names. Header admission now scans both normalized names and values before it
   parses any repository binding.
10. Separate publication workers could otherwise overlap or be invoked outside
    the verified production executable path. The parent serializes publication,
    each worker verifies the exact durable claim, and alternate worker paths are
    limited to signed loopback test mode.
11. A worker's instantaneous probe of the parent's output lock did not preserve
    exclusivity if the parent exited while the worker remained in kernel I/O.
    The parent now delegates a duplicate of its already locked file description;
    the worker verifies its owner, mode, device, inode, and existing exclusive
    flock, then retains it for its entire process lifetime without writing it.
12. Killing a publication worker at its deadline did not prove that blocked
    kernel I/O had been reaped before the serial slot reopened. Timeout now
    atomically poisons publication before releasing the slot; queued and later
    requests fail closed and a resolver restart is mandatory.
13. Transport failure cleanup could itself block past the absolute deadline.
    Cleanup now runs under that deadline; expiry preserves transient ambiguity,
    atomically poisons transport, returns promptly, and rejects every later frame
    until restart instead of overlapping an unfinished filesystem operation.
14. A near-limit marker document could drive synchronous repeated scans across
    large canonical state. Authority admission now rejects more than 256 sorted
    unique markers before allocating or decoding the marker vector.
15. A successful receipt could exceed a small certified response frame only
    after its bundle became durable. Admission now serializes a conservative
    complete success response before claim creation, rejects an oversized result,
    and rechecks the absolute deadline before any durable mutation.
16. A concurrent waiter could continue polling after its claim owner failed.
    Waiters now distinguish active, completed-and-verified, and
    inactive-incomplete owner state, surfacing durable ambiguity immediately.
17. Parent claim, replay, and completion I/O could block the NDJSON loop. Those
    operations now run through one serialized blocking supervisor under the
    absolute deadline; timeout poisons parent store I/O before the slot reopens.
18. Private transport directory and file creation were outside the surrounding
    deadline wrappers. Both creation futures now preserve typed transport errors
    while enforcing the exact request deadline.
19. A normally reaped worker could return a typed late error while leaving
    transient state without poisoning the resolver. Every publication failure
    now poisons both publication and transport before releasing active ownership.
20. Publication-queue expiry could abandon a fetched transient directory before
    any worker started. Queue timeout now enters the same publication/transport
    poison transition before the serial guard and active claim are released.
21. A receipt rename followed by parent-directory sync failure could leave a
    signed receipt after its bundle was deliberately removed. Failure withdrawal
    now durably removes any visible receipt before bundle removal is permitted.
22. Final claim-directory sync failure could strand a ghost in-process owner.
    That error now deactivates the owner while retaining the durable claim for
    explicit restart reconciliation.
23. A stalled resolution-root creation could finish after its deadline while
    transport remained available. Setup timeout now atomically poisons transport
    before returning and requires restart.
24. One near-document-limit marker could force repeated scans over a very large
    retained tail. Individual markers and their corresponding secret authorities
    are capped at 4096 bytes in addition to the 256-marker set limit.
25. Receipt visibility probing converted metadata errors into absence and could
    remove a bundle while a receipt remained visible. Every state-presence check
    is now fallible, and uncertainty retains the bundle.
26. Post-receipt deadline withdrawal removed the bundle before receipt deletion
    was durably synchronized. Every such path now syncs receipt removal before
    bundle withdrawal begins.
27. Offline replay could interpret receipt metadata errors as absence and mint a
    replacement claim. Receipt lookup now propagates uncertainty into the
    supervised parent-store poison boundary.
28. A matching receipt could be replayed while a durable claim still marked the
    identity incomplete. Claim lookup and validation now precede replay, and a
    claim always dominates any apparent completion.
29. Failed late-claim restoration could leave an otherwise replayable receipt and
    bundle without an ambiguity marker. Replay now requires a separate sealed
    completion record written only after claim removal and the final late branch.
30. JSON escaping could split a configured marker containing a quote or backslash.
    Admission now traverses raw semantic strings and object keys before encoding,
    while retaining the encoded-byte scan.
31. Completion could become visible after its claim was removed but before the
    completion record was durably synchronized. Completion is now written and
    synchronized while the claim remains authoritative, and failed claim removal
    rolls the completion state back or leaves explicit ambiguity.
32. Authority files could reside beneath mutable resolver roots. Admission now
    requires every resolved authority target to remain outside transport,
    resolution, output, claim, receipt, and completion trees.
33. Separately configured mutable roots could nest and thereby collapse their
    intended authority boundaries. Configuration now rejects every such nesting.
34. Lexically safe authority paths could traverse symlinked ancestors. Authority
    loading now resolves each ancestor component through no-follow descriptors
    and binds the resulting canonical target before reading it.
35. A worker could commit completion without rechecking the exact retained tree
    that the receipt binds. It now verifies the complete retained tree immediately
    before completion publication.
36. Transient cleanup could occur after completion became visible. Every successful
    path now removes and verifies transient state before publishing completion.
37. A second failure while rolling back an incomplete completion transition could
    erase the distinction between absent and committed state. That double failure
    now retains a durable ambiguity blocker that requires reconciliation.
38. A committed receipt could be delivered through an unproven second store read.
    The worker now returns its verified committed receipt directly.
39. A receipt could be lost after the worker committed it but before the parent
    safely transmitted it. The parent now retains a durable delivery-ambiguity
    blocker until safe response transmission is acknowledged.
40. Two authority paths could hard-link the same underlying inode. Every authority
    file must now be a single-link regular file.
41. A configured marker could enter the serialized response rather than its source
    values. The complete encoded response frame is now scanned before any byte is
    written, and a collision fails silently.
42. Replay and concurrent convergence could acknowledge completion owned by an
    earlier request. Only the request that creates new completion may clear its
    delivery blocker after a successful flush.
43. Post-flush acknowledgement could block the NDJSON loop without a deadline.
    Acknowledgement is now bounded by a fixed one-second timeout and poisons
    parent-store service on uncertainty.
44. Startup or fatal diagnostics could disclose a configured marker on stderr.
    The standalone process now fails those paths silently.
45. Distinct authority roles could alias one underlying inode despite different
    paths. Admission now rejects device/inode reuse across all authority roles.
46. A panic in the parent path could bypass the worker's silent error protocol.
    The parent installs a silent panic hook.
47. Tokio runtime construction itself could panic before an async-installed hook
    existed. Synchronous `main` now installs the hook before runtime construction.
48. A marker split at a stdout response boundary could evade per-frame scanning.
    One stateful guard now retains the bounded suffix needed to scan every admitted
    frame against the preceding emitted stream, and it advances that suffix only
    after a frame is admitted so rejected bytes never perturb the emitted-stream
    model.
49. Response admission bounded the serialized JSON object but emitted its newline
    afterward. Both conservative pre-claim sizing and final output admission now
    include the line terminator, with an exact-boundary regression.
50. Distinct single-link authority files could contain identical bytes, allowing
    one secret value to serve multiple roles despite different inodes. Authority
    loading now rejects reused verified content digests across every authority
    role, with a copied receipt-key-as-credential regression.
51. A distinct repository credential could embed the receipt key while retaining
    a different whole-file digest, allowing the repository to extract receipt
    signing authority. Authority loading now rejects byte containment in either
    direction across the receipt key and every credential, with an exact
    `Bearer <receipt-key>` regression.
52. The receipt and execution board still certified the implementation head from
    before the embedded-authority repair. Both now bind the new implementation
    head, its seventy-two focused tests, protected workflow runs, review evidence,
    and complete hardening chronology.
53. The receipt described the closure candidate as receipt-and-board-only while
    using the complete PR head as its attestation boundary. It now distinguishes
    the documentation-only closure commits from PR #35's complete diff against
    protected `main`, and requires review and checks over that complete exact head.
54. That distinction still attributed the DEP-001-to-CACHE-001 transition to the
    post-implementation closure commits even though the transition entered the PR
    earlier and was already present at the implementation head. The receipt now
    identifies the transition commit and describes later board changes as
    recertification only.
55. The execution board's separate Dependencies lane still certified the
    pre-containment implementation head and its obsolete test, finding, and seam
    totals after the authoritative ticket row was recertified. Both board views
    now bind the same post-repair implementation evidence.
56. A repository credential could losslessly encode the receipt key as hex or
    Base64 and evade raw-byte containment, allowing the repository to recover
    receipt-signing authority. Secret-role separation now denies canonical
    lower/uppercase hex and standard/URL-safe Base64 forms, padded and unpadded,
    in both containment directions.
57. An alternate bind mount could place an authority filesystem identity beneath
    a mutable resolver root while preserving an apparently separate canonical
    pathname and single link. Every opened authority-path component identity is
    now compared with bounded, non-symlink-following scans of both mutable trees,
    and a real bind-mount regression requires fail-closed denial.
58. The receipt and both execution-board views still certified the implementation
    head from before the encoded-authority and bind-mount repairs. All three now
    bind the repaired exact head, its focused tests, protected runs, review
    evidence, and complete finding chronology.
59. The architecture contract attributed mutable-root identity separation solely
    to the single-link invariant, which cannot exclude bind mounts. It now records
    the opened-path identity comparison, both mutable-tree scans, their combined
    one-million-entry bound, and fail-closed scan behavior.
60. A Basic credential could wrap a username prefix plus the receipt key in one
    Base64 payload, changing block alignment and evading whole-secret candidates.
    Case-insensitive Basic credentials are now decoded in padded or unpadded
    standard Base64 before the bidirectional representation checks.
61. A directory with more than one million children could allocate every child
    path before the mutable-tree bound was checked. Entries are now counted and
    rejected during directory enumeration before worklist insertion, with a unit
    regression proving an over-cap path is not queued.
62. Leading HTTP optional whitespace could hide a valid Basic scheme from the
    structured decoder even though a recipient strips that whitespace. Space and
    horizontal tab are now trimmed before scheme recognition, with an exact
    wrapped-secret regression.
63. The receipt and board still certified the implementation head preceding the
    Basic decoder and enumeration-bound repair. They now bind the final exact
    implementation head, seventy-three focused tests, protected runs, and the
    complete hardening chronology.
64. The architecture contract omitted structured Basic expansion. It now records
    optional-whitespace normalization, case-insensitive scheme recognition, and
    padded/unpadded standard-Base64 decoding before cross-role comparison.
65. Hexadecimal separation generated only all-lowercase and all-uppercase
    candidates, so an arbitrary per-digit case mixture could evade matching.
    Hex runs are now compared ASCII-case-insensitively, with an alternating-case
    regression.
66. Device/inode directory deduplication could skip a second bind path whose child
    mount topology differed from the first. Every encountered mount path is now
    traversed independently through the bounded FIFO worklist, and a real
    self-bind/nested-authority-mount regression requires denial.
67. The architecture contract described only canonical lower/uppercase hex after
    the implementation accepted arbitrary per-digit mixtures. It now states that
    hexadecimal containment is ASCII-case-insensitive for every mixed-case form.
68. Reqwest's implicit HTTP/2 protocol-NACK retry policy remained enabled even
    though explicit application retries were absent. Both production and
    contained repository clients now install `reqwest::retry::never()` so one
    credential-bearing request maps to at most one transport attempt.
69. A request could bind a configured and granted repository that no graph node
    used, placing unnecessary credential authority into the signed receipt. Plan
    admission now requires exact set equality between distinct node repository
    identities and request repository bindings before grant validation.
70. Retained-tree verification could recurse without a depth ceiling and queue
    more work than its entry limit before denial. It now uses a path-distinct
    iterative FIFO, counts the one-millionth-entry boundary before insertion,
    and enforces depth 4,096 before descent.
71. Graph reachability and cycle validation recursed once per node even though
    the signed node ceiling is 100,000. It now uses an iterative enter/exit color
    worklist, with a full 100,000-node linear-graph regression.
72. The receipt, architecture contract, and both board views still certified the
    pre-repair implementation head and its obsolete test, run, finding, and seam
    totals. The first closure head bound exact implementation head
    `111df309ed6e850fdffc182010346f0344035f24`, seventy-six focused tests, the
    current protected runs, sixty-seven actionable findings, and seventy-two
    important seams; exact closure review then exposed the three documentation
    defects below.
73. The receipt called the 100,000-node linear-graph regression fully admitted,
    but the test directly exercises only the private iterative reachability and
    cycle validator. The evidence now states that focused scope without implying
    full plan or request admission.
74. The hardening heading still claimed sixty-seven seams while the numbered
    chronology already ended at seventy-two. It now distinguishes seventy
    actionable findings across the complete seventy-five-seam chronology.
75. The architecture contract attributed depth 4,096 to the mutable-root
    authority scan, which is bounded by entries but does not track depth. The
    depth guarantee now appears only on the iterative retained-tree verifier
    that enforces it before descent.
76. Transport-root lock inspection used unbounded `read_to_end` before checking
    content. A malicious sparse file could therefore advertise huge logical
    length without consuming the signed filesystem capacity and exhaust memory
    before denial. Inspection now rejects oversized metadata before allocation,
    caps the read at the exact content length plus one, and rechecks exact length
    after initialization; a sparse 1 TiB regression fails closed.
77. The bounded lock reader still checked regular-file type only after reading.
    An existing FIFO opened read/write could keep the resolver's own writer alive
    and block forever outside the request deadline. Descriptor type is now
    required to be regular before any seek or read, with a real FIFO regression
    proving prompt denial.
78. The receipt and both board views still certified implementation head
    `111df309ed6e850fdffc182010346f0344035f24` after the sparse-lock repair at
    `77af5e0db13364ebb9625bfee1ff3470411d4ecc`. Review correctly required a new
    exact-head recertification, which remained deferred while the FIFO defect was
    repaired rather than certifying another superseded head.
79. After the FIFO repair, the receipt and board still necessarily described the
    predecessor pending exact-head gates. They now bind implementation head
    `60fd72f8bb6c0c4f737dbb080660741c33f651e8`, seventy-eight focused tests,
    current protected runs, seventy-four actionable findings, and seventy-nine
    important seams.
80. A caller-controlled `source_trust_class` was copied into the canonical plan,
    while the acquisition receipt was only syntax-checked. A forged `Trusted`
    request could therefore reach credentialed repository policy. A dedicated,
    digest-pinned Ed25519 source-provenance authority now signs the complete
    request and admission verifies the key digest and signature before claim or
    credentialed policy; field-substitution tests and the contained zero-GET
    regression cover the full trust/source/receipt/lock/scope binding.
81. Transport lock type validation still followed an ordinary potentially
    blocking `open(2)`, so a substituted device could block before the regular
    file check outside the request deadline. Existing paths are now inspected
    through `O_PATH|O_NOFOLLOW`, reopened only from the pinned regular inode with
    `O_NONBLOCK`, and identity-rechecked; real FIFO and `/dev/null` regressions
    prove prompt denial.
82. Authority final components still used blocking `O_RDONLY` before regular
    file validation, so a substituted FIFO or device could stall synchronous
    startup. Componentwise ancestor traversal remains no-follow, while the final
    component is now path-only pinned, type-checked, reopened nonblocking from
    its pinned identity, and device/inode rechecked; full-loader FIFO/device
    regressions prove prompt denial.
83. Certified configuration loading had the same ordinary-open-before-type-check
    gap. Configuration and executable reads now share a path-only/no-follow,
    nonblocking pinned-inode helper with identity revalidation, configuration
    additionally requires one link, and real FIFO/device configuration tests
    prove prompt startup denial.
84. After the authority/configuration startup repairs, the receipt and both board
    rows still deliberately certified predecessor `60fd72f8...` while exact-head
    gates and review ran. They now bind implementation head
    `d0901a1dfe987321d2088ab4d4897e156262fa57`, eighty-three focused tests, the
    current protected runs, and the complete seventy-nine-finding/eighty-four-seam
    chronology.
85. A shared local-key validator returned Maven-specific code and prose when npm
    or PyPI invoked it. The shared function is now a pure bounded-key predicate;
    each ecosystem owns its typed error surface, and focused npm/PyPI regressions
    prove that invalid local identifiers cannot leak a Maven classification.
86. The Mario zero-dependency test incremented a workload counter immediately
    before directly requiring every dependency record to be `controller-global`,
    making the later zero assertion redundant. The counter is removed while the
    stronger per-record kind, identity, disposition, and absent-credential
    assertions remain.
87-145. Subsequent thread-aware exact-head review covered 59 important seams and
    produced 59 additional actionable findings. Five comments in the complete
    chronology repeated the same already counted underlying race or execution
    prediction. The repairs bind
    executable verification to the running `/proc/self/exe` inode, serialize on
    stable output and transport root inodes, pin every fixed root, make cleanup
    descriptor-relative with atomic quarantine and unlink postconditions, carry
    exact receipt/completion fingerprints through parsing and final admission,
    and authenticate a permanent publication commit before claim removal. They
    also close receipt/blocker admission races, bound receipt-lock contention,
    deny absent expected links, bind the worker to the parent's exact roots,
    reject unmanifested retained bytes, and add deterministic replacement,
    special-file, contention, and hosted contained regressions. The final fresh
    review correctly observed that Linux `mkdirat` followed by `openat` cannot
    bind the directory created in the intervening namespace window, even when
    both calls share a pinned parent. Implementation head `f602618e` resolves
    both repeated dynamic-directory findings architecturally: fetch uses one
    exclusive regular transport archive returned by `open(O_CREAT|O_EXCL)`, and
    durable publication uses one exclusive regular stage archive that is sealed
    and atomically renamed. Exact descriptor identity, contiguous offsets,
    bounded strict headers, closed manifests, per-slice and whole-archive
    digests, exact-inode cleanup, and final link revalidation replace the former
    transient, stage, artifacts, and bundle directory trees. The final seam
    found that the authenticated publication commit itself could persist a
    configured numeric or hexadecimal marker through its fingerprints or HMAC.
    Head `b6f9a013` marker-scans the complete signed commit both before
    persistence and after replay loading; a decimal-fingerprint regression
    proves rejection before any commit file becomes visible. Review of the
    first atomic-archive head then found that per-artifact scanners reset at
    slice boundaries and that generated header/offset/payload bytes were never
    scanned as one serialization. Head `0f4da19b` carries one scanner across the
    entire transport plan and one stateful guard across the exact archive prefix
    and every payload byte before writing or sealing. Regressions prove a marker
    spanning body chunks or adjacent artifact slices and a marker introduced by
    the generated archive header are denied before publication. Exact-head
    review then found that final transport-archive synchronization errors could
    bypass exact cleanup, and that the two marker regressions exercised scanner
    helpers rather than the real cross-artifact and header-to-payload wiring.
    Head `dd04d614` routes synchronization failure through exact cleanup before
    the deadline or poisons ambiguous state at expiry, and replaces both proofs
    with production-path boundary fixtures. A deterministic synchronization
    failure proves the exact archive is removed and the transport remains
    available; real two-artifact HTTP fetch and generated-header-to-payload
    fixtures prove the stateful scanners cannot be reinitialized unnoticed.
    Fresh review then found that archive or pinned-root metadata inspection
    could fail after exclusive creation but before the archive identity was
    established, leaving residual state without poisoning later requests. Head
    `e287eca2` makes every such post-create inspection or identity-validation
    failure poison transport state; a production-path injected metadata failure
    proves the unknown file is retained for restart reconciliation and every
    subsequent request is denied. Review then found that an already admitted
    concurrent fetch could overlap the poison transition, and that the proof
    reached only archive metadata plus the internal availability predicate.
    Head `456cf29a` serializes complete fetches through a deadline-bounded async
    slot and rechecks poison state only after acquisition. Production-path
    regressions exercise archive metadata, pinned-root metadata, and invalid
    identity failures; each then issues a fresh `fetch_plan` and proves no new
    archive is created. A delayed overlapping fetch proves it cannot return
    success after another fetch establishes poisoned ambiguity. Fresh review
    then found that publication failure could still set the transport poison
    outside the fetch slot, and that the invalid-identity injection returned
    before the real predicate. Head `9e3235ce` makes every external transport
    poison transition await the same slot while internal fetch-held poison calls
    remain non-recursive. A delayed active fetch proves the external transition
    cannot complete until that fetch returns and every later fetch is denied.
    The identity fixture now mutates the actual scalar inputs to the production
    validator and separately proves non-file, device mismatch, and zero-inode
    rejection, alongside archive- and root-metadata failures. Review of the
    complete documentation head then found that an external poison caller could
    wait behind an active fetch whose later deadline exceeded the caller's own
    deadline. Head `9d305145` establishes a non-cancelable pending-poison state
    before awaiting anything, denies every later fetch immediately, and attempts
    the slot-fenced final transition only until the caller's absolute deadline.
    A delayed active fetch proves the poison caller returns promptly at expiry,
    the earlier fetch may finish its I/O, and every subsequent production fetch
    remains denied for restart reconciliation. Fresh review then found a
    separate completion gap: a fetch that returned to the service just after its
    deadline released the slot before the service established pending poison, so
    a queued fetch could pass the only availability check. Head `772baead`
    performs the final deadline and poison checks while the fetch still owns the
    slot and removes the later service-only transition. Pending external poison
    now also denies the active fetch's success. A two-worker production-path
    regression delays final completion through expiry, proves the expired fetch
    poisons before releasing the slot, and proves the queued fetch creates no
    archive and returns restart-required denial. Review of that head found two
    remaining proof/protocol gaps: an external pending-poison store could still
    occur after the final availability load but before slot release, and the
    millisecond-delay regression could pass through an earlier timeout branch.
    Head `075634f6` replaces the boolean/load protocol with a closed four-state
    atomic handshake: available, success-committing, poison-pending, and
    success-committing-with-poison-pending. Fetch success and external poison
    compete through compare-and-swap, so either poison wins and denies success
    or success linearizes first and the combined state preserves pending poison
    for every subsequent fetch. A direct state-transition proof covers the
    success-first order. The deadline regression now stops after successful
    archive verification at an explicit three-party barrier, expires the real
    absolute deadline, and only then releases completion while the queued fetch
    waits on the same slot; earlier timeout paths cannot satisfy the barrier.

Independent GitHub review produced twenty-four initial actionable implementation findings: the
signed path ceiling, fallback-frame minimum, blocking-publication deadline,
header-name marker scan, inherited-lock lifetime, and post-timeout publication
poison, transport-cleanup deadline, marker-count bound, pre-claim response sizing,
failed-owner waiter exit, parent-store deadline, transient-creation deadline, and
typed-publication-error poison, publication-queue poison, receipt/bundle failure
ordering, final-claim-sync deactivation, resolution-root timeout poison,
individual-marker-length bound, fallible receipt visibility during withdrawal,
durable receipt-before-bundle late withdrawal, and fallible replay receipt lookup.
Durable claim precedence, explicit completion-record replay admission, and raw
semantic marker scanning before JSON escaping complete the reviewed set.
The next seventeen findings required completion-write claim preservation,
authority-file root separation, mutable-root nesting denial, authority-ancestor
symlink resolution with componentwise no-follow access, rollback double-failure
ambiguity, retained-tree verification before completion, transient cleanup before
completion, a post-commit receipt delivery blocker, authority hard-link denial,
serialized-response marker collision denial, replay/convergence acknowledgement
ownership, bounded post-flush acknowledgement, silent startup and fatal
diagnostics, cross-role authority inode-alias denial, parent panic silence,
pre-runtime panic silence, and cross-frame marker state. Together the forty-one
findings were fixed and independently re-reviewed at exact implementation heads.
Closure review added four actionable findings: newline-inclusive response-frame
admission, accurate fixed acknowledgement-timeout wording, and explicit
classifier-pass/Windows-agent-skip evidence, plus copied authority values across
roles. All forty-five actionable findings were addressed before merge.
The final implementation and closure review added two further actionable
findings: embedded secret authority across roles and stale receipt/board
certification after that repair. All forty-seven findings were addressed before
merge. A final closure review added one actionable scope-description finding: the
receipt conflated documentation-only closure commits with the complete PR diff.
A later exact-head review added one actionable history finding: the board
transition preceded the post-implementation closure commits, which only
recertified the existing rows. All forty-nine findings were addressed before
merge. Final review found one additional actionable drift: the duplicate
Dependencies lane still carried the pre-repair certification. All fifty findings
were addressed before merge. A subsequent exact-head review added two
implementation findings: reversible encoded receipt-key forms and bind-mounted
mutable-root aliases. Both were repaired and independently re-reviewed without a
further implementation defect. That review added two documentation closure
findings: re-certification of the new implementation evidence and an accurate
architecture description of the identity scan. All fifty-four actionable
findings were addressed before merge. The next closure review added Basic-wrapped
credential decoding and pre-allocation mutable-entry counting. Exact-head review
then added leading-OWS normalization plus receipt/board recertification and an
explicit Basic-decoding architecture contract. A further review added arbitrary
mixed-case hexadecimal matching and path-distinct bind-topology traversal. Final
exact-head implementation review found no further implementation defect and
required the architecture to state the mixed-case guarantee. All sixty-two
actionable findings were addressed. A final thread-aware audit then recovered two
older unresolved implementation findings: client-library protocol-NACK retries
and unused repository/grant authority. The next exact-head review found unbounded
recursive retained-tree and graph validation. After those four repairs, fresh
exact-head review found no implementation defect and required only documentation
recertification. This recertification is the sixty-seventh actionable finding
across seventy-two important reviewed seams. Exact closure review then corrected
the maximum-graph test scope, the chronology heading, and the location of the
retained-tree depth guarantee. Those three documentation findings brought the
then-current audit to seventy actionable findings across seventy-five important
seams;
exact closure review then found unbounded sparse transport-lock inspection. The
first bounded repair exposed a pre-read FIFO type gap and a deliberately deferred
recertification; fresh review of the FIFO-safe head found no implementation
defect and required only final recertification. Those four findings bring the
audit to seventy-four actionable findings across seventy-nine important seams;
complete-PR review of that recertification then found the unauthenticated source
trust assertion and potentially blocking device open. Their exact-head repairs
bring the audit to seventy-six actionable findings across eighty-one important
seams; fresh review then found the same open-before-type-check pattern in
authority and configuration loading. Their pinned-inode repairs bring the audit
to seventy-eight actionable findings across eighty-three important seams; the
only subsequent finding was this exact-head receipt and board recertification,
bringing the closure audit to seventy-nine actionable findings across
eighty-four important seams; ready-transition Copilot review then found the
ecosystem-crossed adapter error and redundant Mario counter. Their exact-head
repairs and focused regressions brought that audit stage to eighty-one
actionable findings across eighty-six important seams. The later thread-aware
review, archive conversion, and final exact-cleanup/proof repairs summarized in
seams 87-145 bring the current audit to 140 actionable findings across 145 important
seams;
every fixed thread must be replied to and resolved only after the complete
closure head passes protected checks and fresh review.

One additional review thread predicted that exact-capacity transport pressure
would return an I/O error rather than the asserted content-mismatch result. The
exact protected contained job at implementation head `779fad5fbd3f2bef4866ab0635d9946ef8c1b54e`
and the replacement-head HeMan run both passed that assertion and the subsequent
cleanup/reuse proof. The thread was therefore closed with contradictory
execution evidence rather than an unsupported code change.

## Residual risk and authority boundary

The source-provenance signer that verifies SCM acquisition evidence, repository
operator, grant issuer, resolver operator and host, private CA, repository
attestation signer, configuration authority, secret-marker collector, and
receipt-signing key remain trusted within their declared scopes. The resolver
and receipt verifier share signing authority, so their collusion can forge
resolution evidence. The closed v1 adapters intentionally reject ecosystem
features outside their documented exact-lock subsets rather than weakening the
canonical graph.

No real Mario dependency repository or credential is admitted by this ticket.
CACHE-001, SECRET-001, REL-001, DIFF-003, SHADOW-001, and CANARY-001 remain
mandatory at their board-defined points before cache, credential-dependent,
release, differential, shadow, or production-effect authority. CUTOVER-001,
ROLLBACK-001, RECUTOVER-001, DECOM-001, and MIG-009 remain mandatory for the
later authority-transfer chain. This receipt waives none of those gates.
