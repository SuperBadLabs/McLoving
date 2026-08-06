# SCM-001 security and implementation closure

Date: 2026-08-05

Status: REOPENED. The earlier implementation candidate
`d1bfbfab6fea9261090e74f441ebbb1a0d7e7a93` passed all nine protected checks and
nineteen focused tests after ten findings were fixed, but later exact-head
review correctly identified additional executable/helper binding,
authority-snapshot immutability, credential-marker, retained-directory, and
test-readiness gaps. The replacement implementation has twenty-three focused
source-acquisition tests: two boundary unit tests, four protocol tests,
fifteen contained end-to-end tests, and two sealed-inventory tests. This receipt
cannot return to PASS until its replacement exact head independently passes
review and every protected check.

PR #34 now keeps SCM-001 active and DEP-001 blocked while the reopened findings
are verified. A later closure-only head may restore the execution-board
transition only after the replacement implementation head passes protected
checks and independent review. The final squash-merge commit is
necessarily unknowable from inside its own pre-merge contents; the immutable PR
#34 exact-head checks plus post-merge protected-main verification are the final
closure attestation.

This receipt does not claim a Mario production source credential, live source
checkout, dependency resolver, source-dependent canary, cutover, rollback, or
Jenkins decommissioning event.

## Inventory denominator

The accepted MIG-000 Mario inventory grants no live SCM or credential authority.
The executable inventory tests preserve that zero denominator. The separately
sealed 228-file historical Jenkins corpus remains provenance evidence and is
not substituted for a live source-acquisition denominator.

## Implemented boundary

- standalone strict NDJSON source-acquisition process with recursive duplicate
  JSON-member denial and bounded frames;
- self-, configuration-, Git-executable-, CA-bundle-, credential-, signing-key-,
  and secret-marker-set digests plus an explicit deployment generation;
- provider, repository, authenticated full ref, exact SHA-1 or SHA-256 commit,
  object format, source identity, trust class, fork policy, submodule graph,
  sparse roots, depth, tenant/build/attempt identities, expiry, and audit lineage;
- sealed immutable Git, HTTPS-helper, askpass, and CA snapshots, a private-only
  Git child-command path, a content/inode-bound root-owned dynamic-runtime
  closure exposed through a descriptor-backed library directory, plus
  credential and runtime revalidation before every Git invocation;
- exact primary, fork, and submodule repository allowlists, including
  fail-closed untrusted-fork and repository-substitution denial;
- smart-HTTP askpass delivery that preserves credential bytes exactly while
  clearing ambient helpers, prompts, proxy and redirect policy, hooks, filters,
  maintenance, and inherited environment authority;
- non-executing `ls-tree` and `cat-file` materialization with traversal, `.git`,
  case-fold collision, special-file, unsafe-symlink, mode, path, file, byte,
  submodule, network, and command-time bounds;
- durable first-writer claims, a cross-process output-root lock, private staging,
  deadline-fenced atomic publication with late-path withdrawal, deterministic
  claim-first replay, retained-output verification, and fail-closed ambiguity
  retention; and
- HMAC-signed receipts binding the exact request, authority, implementation,
  configuration, repository trees, full retained tree inventory, content
  digests, generation, and rollback lineage.

The governing contract is `docs/architecture/SOURCE_ACQUISITION_V1.md`.

## Review and executable evidence

Independent review has produced thirty-three actionable threads so far. The
first two found that request sparse-path and submodule URL/path validation
returned configuration-oriented codes instead of typed request mismatch codes.
Later exact-head review found that zero depth admitted unbounded history, a
credential-bearing fetch could outlive the publication deadline, gitlinks could
escape the global file count, an otherwise valid stale request used the wrong
typed error, askpass could be substituted at its executable path, and case-fold
checks did not reserve ancestor prefixes. Final exact-head review found that
askpass reopened a credential path without hashing the exact prompted bytes and
that a gitlink-only sparse result recorded, but did not materialize, its
directory boundary. The fixes require positive bounded depth,
deadline-bounded process-group containment, gitlink count enforcement, typed
expiry, implementation-bound askpass revalidation, exact prompted-credential
digest validation, ancestor-aware case-fold reservation, and materialized
gitlink boundaries. Focused regressions cover every finding. Every thread was
resolved only after its fix was pushed.

The later closure review found that a certified marker set could omit the
credential itself, Git was still spawned by a separately verified pathname,
replay did not validate every nested-directory mode, and the short deadline
test synchronized before process initialization was complete. Its fifth thread
correctly kept SCM-001 open while those root findings remained. The replacement
requires the exact credential in the marker set, validates owner and mode for
every retained directory, and emits a test-only readiness event only after
standalone process initialization. The open-inode substitution proof and
extended marker, directory, and deadline proofs passed at `da3ca2805bcd56f2811adc550d5d5e7dd7c0c2ae`;
all five threads were replied to and resolved only after that head was pushed.

The next exact-head review found that Git's separately executed HTTPS remote
helper remained ambient and that an ordinary retained descriptor did not stop
same-inode writes after verification. The replacement now binds the helper path
and digest in configuration, request, and receipt; copies Git, helper, askpass,
and CA bytes into anonymous memory-backed files; applies kernel write, grow,
shrink, and further-seal locks; and exposes only the sealed HTTP/HTTPS helper
through a private descriptor-bound `GIT_EXEC_PATH`. The smart-HTTP proof mutates
the configured helper inode in place after process readiness and still proves
successful authenticated acquisition with no substituted-helper execution or
credential disclosure.

Review of that exact head found one remaining internal-child seam: Git can
re-execute `git` and `git-upload-pack` through `PATH`, so its otherwise sealed
top-level process could still hand credential-bearing environment variables to
an ambient Git image. The replacement now uses the descriptor-bound private
command directory as the sole `PATH`, exposes only the sealed Git snapshot as
`git` and `git-upload-pack`, and verifies those links alongside the sealed
HTTP/HTTPS helper links before every invocation. Both contained file transport
and credentialed smart-HTTP now pass with no ambient command directory in
`PATH`. The eighteenth thread was replied to and resolved after the replacement
head was pushed and its focused and full-workspace tests passed.

Review of that replacement found that ancestor collision keys still used
lowercasing instead of normalization plus full Unicode case folding, and that
the acquisition root remained owner-writable after publication even though its
retained children were read-only. The next replacement derives every ancestor
key with compatibility normalization and full default case folding, sets the
complete acquisition root to mode `0500` before atomic publication, and requires
that exact root mode during replay. Focused proofs cover both `Straße`/`STRASSE`
and composed/decomposed ancestor collisions plus published-root mode drift. The
nineteenth and twentieth findings cannot contribute closure until the
replacement exact head is independently reverified.

Review of that replacement found that positive history depth did not bound the
reachable blob pack, failed read-only stages restored only their root mode, and
final child mode changes were not individually fsynced. The next replacement
uses a `blob:none` promisor fetch, lazily retrieves only selected blobs and
required `.gitmodules`, checks configuration-bound allocated transport storage
after every Git command, and records the admitted transport bytes in the signed
receipt. A proof admits a small sparse selection while omitting an incompressible
four-MiB blob under a 512-KiB transport ceiling, then proves selecting that blob
fails the quota and leaves no stage. A forced final-path collision separately
proves a fully read-only stage recursively restores write authority and is
removed after rename failure. Final file and directory chmods are fsynced before
atomic publication. The twenty-first through twenty-third
findings cannot contribute closure until the replacement exact head is
independently reverified.

Review of that exact head found that post-command transport measurement still
allowed a selected promisor object to consume private-volume space before the
quota check ran. The replacement now measures allocated repository storage
throughout every credential-bearing Git fetch and lazy object request and kills
the complete Git process group as soon as the configured ceiling is observed to
be exceeded. The one-millisecond monitor tolerates only entries that disappear
during Git's atomic temporary-file replacement, while every other traversal
error fails closed; post-command and pre-receipt measurements remain as
independent checks. The four-MiB selected-blob/512-KiB ceiling proof now exercises
the live command monitor and still proves typed quota denial plus complete stage
cleanup. The twenty-fourth finding cannot contribute closure until the
replacement exact head is independently reverified.

Review of that replacement found that a long allocation traversal serialized
deadline and child-exit handling, and that treating an entry which disappeared
during Git's atomic rename as absent could certify a partial measurement. The
next replacement selects child exit and the exact command/request deadline
concurrently with every allocation traversal, so neither a slow scan nor a
contended filesystem can extend credential-bearing authority. Any directory or
entry disappearance now discards the entire measurement and restarts it from
the repository root; three failed restarts produce a fail-closed state error
which also terminates the complete Git process group. The twenty-fifth and
twenty-sixth findings cannot contribute closure until this replacement exact
head is independently reverified.

Review of that replacement found three remaining fail-open seams. First,
dynamically loaded Git/helper runtime files were not part of the executable
attestation. Second, a server could report success while warning that it ignored
`blob:none`. Third, final rename and root synchronization could cross the signed
publication deadline before the existing last check. The replacement now binds
the strictly ordered complete loader/library closure into configuration and
receipts, retains root-owned non-writable runtime files by descriptor, traces
the sealed Git/helper/askpass images through an exact descriptor-backed library
directory, and revalidates every file and directory link before each command.
An omitted closure member is denied at construction. Any credential-bearing
command that reports the server ignored filtering is source-unavailable and
leaves no publication. Final publication now checks the deadline after rename
and root synchronization and again after claim removal; a late path is
atomically moved out of its public name under the root lock while an ambiguity
claim remains. The focused final-publication proof forces the post-rename
expired case and verifies that neither a public nor quarantine path remains.
The twenty-seventh through twenty-ninth findings cannot contribute closure
until this replacement exact head is independently reverified.

The first protected run of that replacement exposed test-load amplification,
not an authority bypass: re-hashing the complete runtime closure before every
Git command made three parallel contained fixtures cross their test-only
readiness or request windows on the slower hosted runner. Construction still
hashes every configured runtime file. Per-command verification compares the
canonical-path device, inode, size, mode, owner, modification time, and
kernel-maintained change time plus sealed-memory state and the exact private
directory topology; atomic replacement and in-place mutation still fail closed
without repeatedly reading every library byte. Contained tests cache identical
closure discovery
and use ten-minute fixture authority windows plus a one-minute readiness bound;
the production request, grant, command, and publication bounds are unchanged.
The complete focused and locked workspace gates pass with that repair on HeMan.

Review of the first runtime-closure head found two final descriptor/durability
gaps. Runtime-directory links still targeted the original library paths, and
claim recreation could fail before a late public path was withdrawn. The
replacement copies every attested loader/library into a sealed memory file,
keeps those descriptors inherited by Git and its internal children, points the
private library directory only at those descriptors, and rewrites the sealed
Git/helper/askpass ELF interpreter field to the retained loader descriptor.
Neither an OS-rollout rename in the verification/spawn interval nor initial ELF
startup can reopen ambient runtime bytes. Late withdrawal now renames the public
path to quarantine and synchronizes its absence before it attempts claim
recreation; the claim and its parent are then synchronized before hidden cleanup.
The focused final-publication proof covers both an already-present claim and the
post-removal claim-recreation path. The thirtieth and thirty-first findings
cannot contribute closure until the replacement exact head is independently
reverified.

Review of that exact head found one remaining dynamic-loader input outside the
attested runtime image: glibc can read `/etc/ld.so.preload` independently of the
descriptor-backed library directory. The replacement creates an inherited,
kernel-sealed empty preload file before snapshotting the runtime, rewrites the
retained loader's sole system-preload pathname to that descriptor, and verifies
the descriptor's seals, content, and non-close-on-exec state before every Git
command. A Linux unit proof applies the rewrite to the real loader image,
verifies that the ambient pathname is absent and the exact empty descriptor is
present, while every contained Git/helper/askpass proof executes through the
patched loader. The thirty-second finding cannot contribute closure until the
replacement exact head is independently reverified.

Review of that exact head found that the shared sparse-selection predicate
treated ordinary file and symlink leaves as ancestors of requested sparse
roots. A request for a nonexistent descendant below a leaf could therefore
materialize and sign the entire out-of-scope leaf. The replacement selects
ordinary leaves only when equal to or below a sparse root and reserves
reverse-prefix ancestor selection exclusively for gitlink directory boundaries.
The exact-revision contained proof now requests a descendant below an ordinary
blob and verifies typed empty-result denial with no publication, the durable
ambiguity claim retained, and no leaf disclosure; the existing submodule proofs
preserve selected ancestor gitlinks. The
thirty-third finding cannot contribute closure until the replacement exact head
is independently reverified.

The first Ubuntu protected run exposed a portable-test defect: the bare child
repository's symbolic `HEAD` inherited the runner's default branch while the
fixture pushed `main`. The fixture now sets the bare `HEAD` explicitly to
`refs/heads/main`; the previously failing submodule proof, full locked workspace
suite, strict Clippy, formatting, and the rerun protected checks pass.

The replacement implementation currently passes `git diff --check`, Rust
formatting, strict source-acquirer Clippy, and all twenty-three focused
source-acquisition tests plus the complete locked workspace suite on HeMan.
Protected checks and independent exact-head verification remain required before
closure.

## Residual risk and authority boundary

The repository provider, grant issuer, source-acquirer operator and host,
private CA, Git executable, credential store, and receipt-signing key remain
trusted within their declared scopes. The source acquirer and receipt verifier
share signing authority, so their collusion can forge acquisition evidence.
No real Mario repository or credential is admitted by this ticket. DEP-001,
SECRET-001, DISC-001, DIFF-003, SHADOW-001, and CANARY-001 remain mandatory at
their board-defined points before dependency-resolving, credential-dependent,
discovered, source-dependent, or production-effect authority. CUTOVER-001,
ROLLBACK-001, RECUTOVER-001, DECOM-001, and MIG-009 remain mandatory for the
later authority-transfer chain. This receipt waives none of those gates.
