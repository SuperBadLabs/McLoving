# CI-003 merge-authority security review

Date: 2026-09-01
Pull request: #116
Implementation baseline: `5e91009`

`CI-003` closes a repository-governance failure: branch protection could admit
a commit even when recovery, deployment, or Windows validation was red. It
changes no shipped runtime code, API, protocol, credential, persistence schema,
deployment unit, migration evidence, or production authority.

## Finding

The live pre-ticket protection document had `strict: true`, admin enforcement,
linear history, and conversation resolution, but required only these contexts:

- `Rust`
- `Dependencies and licenses`
- `Secret scan`
- `Architecture records`
- `Formal model`
- `Controller PostgreSQL`

It omitted `Backup and restore`, `Deployment lane`, `Classify Windows impact`,
and `Windows agent`. A failed omitted job did not block merge. In addition,
`Rust`, `Dependencies and licenses`, `Secret scan`, and `Architecture records`
had `app_id: null`; an identically named status from another integration could
satisfy those slots. Only `Formal model` and `Controller PostgreSQL` were bound
to GitHub Actions application id `15368`.

This also corrects historical language in the board and earlier receipts.
"All nine protected checks" meant nine observed successful workflow outcomes,
not nine branch-required contexts. The successful runs remain valid test
evidence, but they were not proof that GitHub would reject a merge when an
omitted job failed.

App binding is deliberately scoped: it proves that GitHub Actions reported a
context, not that a particular reviewed workflow definition produced it. The
workflows, classifier, verifier, and their oracles are candidate-controlled
source. The repository has one
organization member and one CODEOWNER, so requiring a second human approval
would deadlock owner-authored maintenance rather than create an operational
control. `CI-003` therefore retains the six granular contexts, adds the two
aggregates, requires independent exact-head source review by process, and
records malicious authorized-writer merge-authority mutation as residual risk.

## Live protection transition

The post-change GitHub API readback on 2026-09-01 reports `strict: true` and
these eight required checks, each bound to GitHub Actions app id `15368`:

- `Rust`
- `Dependencies and licenses`
- `Secret scan`
- `Architecture records`
- `Formal model`
- `Controller PostgreSQL`
- `Foundation`
- `Windows`

The same readback reports admin enforcement, linear history, and conversation
resolution enabled, with force pushes and branch deletion disabled. The six
granular contexts remain required as defense in depth; the two aggregates add
complete coverage of reported terminal-job outcomes without pretending that
app identity binds a candidate-controlled workflow definition.

## Implementation

The `Foundation` job is an `if: always()` aggregate over the terminal `Rust`,
dependency, secret-scan, architecture, formal, PostgreSQL, recovery, and
deployment lanes. It accepts only the exact eight-field state in which every
result is the literal string `success`; missing, unexpected, failed, cancelled,
skipped, or unknown results fail.

The `Windows` job is an `if: always()` aggregate over classification and native
execution. It accepts exactly two states:

1. classification succeeded, `run-windows=true`, and native Windows execution
   succeeded; or
2. classification succeeded, `run-windows=false`, and native Windows execution
   was skipped.

A failed classifier, missing or invalid decision, required execution that did
not succeed, or a non-impact execution that did not skip fails closed. Both
jobs invoke the same checked-out `scripts/verify-workflow-aggregate.py` rather
than carrying divergent shell predicates.

The Windows classifier resolves changed paths before exporting either revision
and immediately requires Windows for every Cargo/gate configuration path,
case-folded to match the target Windows filesystem. Windows-unsafe components
(including non-ASCII names whose NTFS invariant casing differs from Python,
trailing-dot/space, reserved names, and Git-protected NTFS short-name aliases)
and case-colliding changed paths also require the native gate; a complete
trusted `git ls-tree` inventory
detects collisions between changed and unchanged head paths before revision
export. It therefore never loads changed candidate Cargo configuration.
Metadata runs from
the exported tree with absolute Cargo/Rust compiler paths resolved first,
command-line overrides disabling compiler wrappers, and inherited compiler
override variables and GitHub command-file paths removed. A candidate
`build.rustc-wrapper` cannot execute or mutate workflow outputs before the
authoritative decision.

`scripts/test-workflow-aggregate.py` exhausts all 390,625 combinations of five
possible results across the eight Foundation lanes, the complete Windows
classifier/decision/result matrix, malformed and duplicate inputs, and the
exact workflow job, dependency, `always()`, environment, and verifier wiring.
The hosted Architecture job and the local Foundation validator run this suite.

The hosted Architecture job now downloads actionlint at the version pinned in
`tools/versions.env`, verifies its repository-pinned SHA-256 before extraction,
and lints every workflow. This makes malformed workflow expressions and DAG
edits a hosted failure instead of a local-only check.

Independent review found that the first structural test allowed an aggregate
verifier step to add `if: false` or `continue-on-error: true`; both mutations
were actionlint-valid and left the seven tests green. The exact aggregate job
schema is now allowlisted: only `name`, `runs-on`, `needs`, `if`, and `steps`
are permitted at job level; exactly the pinned checkout and verifier steps are
permitted; the verifier step may contain only `env` and `run`; and
`continue-on-error` and verifier-step `if` are forbidden. Fourteen negative
mutations cover plain, quoted, and spaced job controls; plain and quoted step
controls; a skipped verifier; named and unnamed extra steps; plain and quoted
extra environment authority; checkout-pin spoofing; shell-level failure
suppression; and plain or quoted duplicate aggregate job IDs.

The workflow parser also allowlists the semantic top-level keys before `jobs`
and rejects top-level keys after it, so workflow-level `env` or `defaults`
cannot inject shell authority into the otherwise exact aggregate steps. The
Architecture job's controls, six-step order,
checkout, immediately following aggregate-suite step, and digest-verifying
actionlint step are pinned as the first three steps, leaving no mutable
predecessor before either hosted structural gate; the local suite command is
pinned as a complete shell line. Two additional negative mutations cover shell
failure suppression at both suite invocation sites. Noncanonical GitHub-valid
job-key spellings are deliberately rejected instead of partially parsed.
All authority-bearing Python invocations—including Windows classification—use
isolated mode (`python3 -I`), so candidate files named after standard-library
modules cannot intercept oracle, classifier, or verifier startup through the
script directory. Hosted authority uses the absolute trusted interpreter path;
the complete Windows impact job is byte-pinned with classification before its
candidate test, and PATH-override and mutable-predecessor mutations are denied.

## Threat-model review

`TM-052` records the branch-protection and aggregate boundary. `TM-016` and
`TM-023` were reviewed: actions remain commit-pinned, hosted actionlint is
version- and digest-pinned, and the accepted upstream-plus-reviewed-digest
compromise residual is unchanged. `TM-050` was reviewed: the deployment lane's
product mitigations and two accepted residuals are unchanged, but its result is
now transitively merge-blocking through `Foundation`.

`TM-003` through `TM-007`, `TM-009`, `TM-010`, `TM-017`, and `TM-020` were
reviewed with no mitigation change. `CI-003` changes whether their existing
workflow evidence blocks merge; it does not replace those contracts. `TM-048`
is corrected to describe its historical nine workflow outcomes accurately.

Residual authority remains with GitHub and GitHub Actions. An authorized
repository writer can weaken candidate-controlled merge-authority workflows,
classifier, verifier, or their oracles;
an authorized administrator can additionally mutate protection outside the
source tree. App binding prevents a different app from impersonating a check
but does not bind its workflow definition. Authority-sensitive merges therefore
re-read the live rule and independently review every exact merge-authority
workflow, classifier, verifier, and oracle change.
The aggregates consume reported job conclusions; they cannot independently
prove that an authorized workflow edit did not skip a child step with `if`,
soften it with `continue-on-error`, or mask a shell failure before GitHub
calculates that conclusion. Those edits are part of the candidate-workflow
residual and the exact-head source-review obligation, not a property claimed by
the aggregate. A compromised GitHub control plane or authorized account can
still subvert the gate.

## Verification in progress

- ten mutation-oriented aggregate tests pass locally;
- all 390,625 Foundation states have exactly one accepting state;
- the full Windows truth table has exactly two accepting states;
- the fifteen Windows-impact classifier tests pass, including proof that
  changed Cargo configuration short-circuits before revision export or
  metadata and that metadata pins compiler/wrapper controls;
- pinned actionlint 1.7.12 accepts all workflows;
- board, closure-receipt, and Rust-denominator tests and verifiers pass;
- `bash -n scripts/validate-foundation.sh` and `git diff --check` pass.

Closure additionally requires exact-head `Foundation` and `Windows` success,
an independent exact-head review, zero unresolved threads, the after-state
branch-protection readback with all six granular contexts plus both aggregates
bound to GitHub Actions app id `15368`, merge, and protected-main verification.
Until those receipts exist, the ticket remains `ACTIVE`.

This review grants repository merge gating only. It grants no migration,
runtime, deployment, production, credential, connector, canary, cutover,
rollback, recutover, or decommission authority.
