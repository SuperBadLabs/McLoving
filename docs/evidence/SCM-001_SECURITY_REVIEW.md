# SCM-001 security and implementation closure

Date: 2026-08-05

Verdict: PASS for the implementation gate at exact implementation head
`d1bfbfab6fea9261090e74f441ebbb1a0d7e7a93`. All nine protected checks passed,
and the focused gate passed with nineteen source-acquisition tests: four
protocol tests, thirteen contained end-to-end tests, and two sealed-inventory
tests. Independent exact-head review found no further actionable issue after
ten implementation findings were fixed and their threads resolved.

The later PR #34 closure candidate adds only this receipt and the execution-board
transition from SCM-001 to DEP-001. Its exact head must independently pass the
protected checks and review before merge. The final squash-merge commit is
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
- runtime Git, credential, and CA revalidation before every Git invocation;
- exact primary, fork, and submodule repository allowlists, including
  fail-closed untrusted-fork and repository-substitution denial;
- smart-HTTP askpass delivery that preserves credential bytes exactly while
  clearing ambient helpers, prompts, proxy and redirect policy, hooks, filters,
  maintenance, and inherited environment authority;
- non-executing `ls-tree` and `cat-file` materialization with traversal, `.git`,
  case-fold collision, special-file, unsafe-symlink, mode, path, file, byte,
  submodule, network, and command-time bounds;
- durable first-writer claims, a cross-process output-root lock, private staging,
  atomic publication, deterministic replay, retained-output verification, and
  fail-closed ambiguity retention; and
- HMAC-signed receipts binding the exact request, authority, implementation,
  configuration, repository trees, full retained tree inventory, content
  digests, generation, and rollback lineage.

The governing contract is `docs/architecture/SOURCE_ACQUISITION_V1.md`.

## Review and executable evidence

Independent review produced ten actionable implementation findings. The
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

The first Ubuntu protected run exposed a portable-test defect: the bare child
repository's symbolic `HEAD` inherited the runner's default branch while the
fixture pushed `main`. The fixture now sets the bare `HEAD` explicitly to
`refs/heads/main`; the previously failing submodule proof, full locked workspace
suite, strict Clippy, formatting, and the rerun protected checks pass.

The final implementation head passed `git diff --check`, Rust formatting,
`clippy -D warnings`, the full locked workspace suite, all nineteen focused
source-acquisition tests, all nine protected checks, and independent exact-head
review.

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
