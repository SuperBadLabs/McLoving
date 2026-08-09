# DEP-001 security and implementation closure

Date: 2026-08-09

Verdict: PASS for the implementation gate at exact implementation head
`2809377a5132cdd385b87a647bec02848ee01305`. All nine protected checks passed
across [Foundation run 31299617628](https://github.com/SuperBadLabs/McLoving/actions/runs/31299617628)
and [Windows Agent run 31299617591](https://github.com/SuperBadLabs/McLoving/actions/runs/31299617591).
The focused gate passed sixty-nine dependency-resolution tests: thirty-four unit
tests, thirty-four ordinary integration tests, and one real exact-capacity
tmpfs/HTTP/standalone-process test. Clean at [independent exact-head
review](https://github.com/SuperBadLabs/McLoving/pull/35#issuecomment-5230243150),
and every actionable implementation review thread was resolved only after its
fix was pushed.

The later PR #35 closure candidate adds only this receipt and the execution-board
transition from DEP-001 to CACHE-001. Its exact head must independently pass the
protected checks and review before merge. The final squash-merge commit is
necessarily unknowable from inside its own pre-merge contents; the immutable PR
#35 exact-head checks plus post-merge protected-main verification are the final
closure attestation.

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
- componentwise no-follow authority loading that requires resolved, single-link
  regular files outside every mutable resolver root and a unique device/inode
  for each receipt key, marker set, repository credential, attestation key, and
  private CA role;
- exact-path GET transport with redirects, ambient proxies, decompression,
  retries, credential helpers, and alternate origins disabled;
- bounded response headers and streaming bodies verified for status, type,
  repository, generation, length, SHA-256, Ed25519 attestation, and every
  independently configured credential or receipt-key marker;
- a canonical private resolver-owned Linux transport mount whose exact block
  capacity equals the aggregate ceiling, differs from parent/output devices,
  is exclusively locked, and denies residual state before claims or requests;
- durable first-writer claims, in-process concurrent convergence, explicit
  restart ambiguity, transport-path-bound verified inputs, private staging,
  synchronized read-only content, atomic no-overwrite publication, and
  fail-closed cleanup ambiguity, with retained-tree verification and transient
  cleanup completed before the durable completion record becomes visible;
- HMAC-SHA-256 receipts binding the exact request, configuration, executable,
  source/lock/plan/graph, repositories/grants, artifacts/attestations, complete
  retained tree, marker set, generation, rollback, and deadline, with
  constant-time verification, direct delivery of the worker-verified committed
  receipt, and durable ambiguity when rollback or post-commit delivery cannot
  be proven;
- exact offline replay that revalidates receipt HMAC, request and runtime
  bindings, manifest, owner/mode/type/size, content digests, ancestor topology,
  and the complete retained-tree digest without repository access; and
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
- private authority owner/mode/no-follow/digest policy, resolved separation from
  mutable roots, single-link and cross-role device/inode uniqueness, minimum
  receipt-key strength, and exact credential/receipt-key marker membership;
- correct transport plus wrong mirror, content, size, signature, key, repository,
  generation, missing, offline, timeout, and cross-chunk marker denial;
- claim-first concurrency, request substitution, restart ambiguity, exact replay,
  generation cutover, explicit rollback lineage, late withdrawal, foreign
  transient-path denial, retained-tree substitution, receipt-HMAC tampering,
  pre-claim secret-marker denial, retained-tree verification before completion,
  pre-completion transient cleanup, post-commit delivery ambiguity, and cleanup
  truth; and
- standalone config mode/symlink/schema, bounded frame, static response, and
  sealed Mario zero-authority behavior, including stateful cross-frame marker
  denial, replay/convergence acknowledgement ownership, and silent startup,
  fatal, and pre-runtime panic paths.

The protected contained journey uses the real standalone executable, a live
credentialed HTTP Maven repository, Ed25519 attestations, and a disposable
`nosuid,nodev,noexec` tmpfs whose measured capacity is written into the certified
configuration. It proves two concurrent identical requests converge on one GET;
an exact-capacity artifact fails closed and cleans up; wrong-graph and untrusted
requests cause zero GETs; a valid request publishes; a later exact version under
the same resolution identity is denied offline; restart with the repository
offline returns byte-equivalent JSON; and neither the repository credential nor
receipt key appears in stdout, stderr, or the receipt.

The exact implementation head also passes strict resolver Clippy, formatting,
`git diff --check`, the complete locked non-source workspace, and the complete
serialized source-acquirer suite beneath the activated repository-owned
AppArmor profile on HeMan. Foundation CI independently repeats strict workspace
Clippy, the complete non-source workspace, the real dependency contained
journey, and the AppArmor-confined source suite.

## Review-driven hardening

Pre-closure review and repeated contained execution exposed and repaired forty-eight
important seams:

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
    Acknowledgement is now bounded by the request deadline and poisons parent-store
    service on uncertainty.
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
Each fix was pushed, replied to with
exact-head evidence, and its thread was resolved before closure.

One additional review thread predicted that exact-capacity transport pressure
would return an I/O error rather than the asserted content-mismatch result. The
exact protected contained job at implementation head `779fad5fbd3f2bef4866ab0635d9946ef8c1b54e`
and the replacement-head HeMan run both passed that assertion and the subsequent
cleanup/reuse proof. The thread was therefore closed with contradictory
execution evidence rather than an unsupported code change.

## Residual risk and authority boundary

The repository operator, grant issuer, resolver operator and host, private CA,
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
