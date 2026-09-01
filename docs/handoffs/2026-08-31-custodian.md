# Custodian handoff — 2026-08-31

## Executive state

The repository is healthy at the authoring baseline:

| Item | Identity or result |
|---|---|
| Protected main | `e7eefb6d66cf0886f4c9198fc88cbec757e80fd2` |
| Protected tree | `65b2d78d099bd209e9a4ff247181f0be21da9009` |
| GitHub verification | `verified=true`, `reason=valid` |
| Open pull requests | none at authoring time |
| Board | 106 tickets; 22 remaining; selected pending slot `DEPLOY-003` |
| Historical closure debt | 37 admitted and ratcheted items |
| Production authority | none |
| Release readiness | not ready |

The latest protected-main workflows at this baseline are green:

- Foundation run `33447506668`.
- Windows Agent run `33447506665`.
- Release Builder run `33448990553`.

PR #112 is the last implementation merge in this snapshot. Exact source
`06e3ab28f8541513e0fc2aa22ddde029a36ad5ad` squash-merged as verified main
`e7eefb6d66cf0886f4c9198fc88cbec757e80fd2`. It closes `CI-002` by preventing
zero-test and partial-test Foundation success, requiring exact Rust test
denominators, making every backup/restore canary execute a test, and repairing
the remote-agent terminal-observation race. Its admitted residuals are
configuration rather than network isolation for the test trust-auth service,
and fetched installer/Maven artifacts that are not repository-content-locked.

## Work closed during this tenure

### Residual event-wait implementation

PR #109 had already replaced the principal fixed polling regime and merged as
`4f77485d9ac3ee3506779d318d56c133bcf72a64`. QA found a residual fixed poll in
the reconciliation-only controller profile and insufficiently bound
performance evidence.

PR #110 closed that bounded dimension:

| Item | Identity |
|---|---|
| Reviewed signed source | `e57f7c9c6dcd8a1f45bc41393780d90fdbf7c13a` |
| Reviewed/evidenced tree | `b4d4b86b06666fd9bae9f85b8e44f426a9b227dd` |
| Protected-main squash | `0f6499ff082f7d7dd7c85831ed4659bc3923dce6` |

The shipped 500 ms compatibility setting no longer drives a fixed idle loop.
Schedulable embedded, disabled/reconciliation-only, and remote work paths use
subscribe-before-state event waits, authoritative lease deadlines, and a
20-second lost/coalesced-hint fallback. Shortening an active lease wakes
existing waiters; routine extensions remain quiet. Reconciliation failures
back off rather than spinning on an already-expired deadline.

Review-driven hardening made notifications hints rather than counters, sampled
the complete controller/agent/PostgreSQL/forwarder process trees, counted CPU
from fully reaped descendants, eliminated the silent `pgrep` dependency,
validated role identities and distinct PIDs, fixed the idle target at 5%, and
bound live binaries and the PostgreSQL container image to the reported source.
Controller and agent now expose embedded build provenance.

The final exact-head PostgreSQL regression proves queued admission, no-op
suppression, first-active-lease wake, shorter-active-lease wake, and quiet lease
extension. Exact-head Codex reported no major issues, Copilot verified the
shorter-deadline behavior, every review thread was resolved, and all protected
checks passed before merge.

### Immutable accounting

PR #111 published the receipts separately so an implementation commit was not
asked to contain evidence for its own not-yet-known merge identity:

| Item | Identity |
|---|---|
| Definitive reviewed head | `014b9c4c75669cecaf5e6dc51e7863f90af9de19` |
| Reviewed tree | `cfff9fb1583d8d8391118add2b73ca149b39a3dd` |
| Protected-main squash | `a7113736df94c9fe267eebb9b6e2c100d6b36785` |

Copilot correctly requested an explicit distinction between the stage JSON's
idle metadata and the strict complete-stack idle measurement. Verified commit
`5a993047321039565f74959e4f686e2063c2f83f` added that clarification. Because a
bot-authored push did not trigger protected workflows, signed empty commit
`014b9c4` triggered exact-tree gates. Both reviewers then reviewed that exact
head, all checks passed, and no unresolved thread remained.

Canonical evidence:

- `docs/evidence/PERF-001_EVENT_WAIT_QA_2026-08-31.md` — scope, identity map,
  rejected/superseded measurements, and explicit non-claims.
- `docs/evidence/PERF-001_EVENT_WAIT_QA_2026-08-31.json` — five-heat stage
  receipt, SHA-256
  `c909d227d1cffc6df3ac19d155454637e3137ab078356e62679665e2d65a7a35`.
- `docs/evidence/PERF-001_EVENT_WAIT_QA_2026-08-31_IDLE.tsv` — strict idle
  receipt, SHA-256
  `043c5e485f92a310e81c4e59556b4fd8ee238fa7cc6dd417d7a822bc70e3bf77`.

Accepted Mario measurements:

- 71.2018 ms/stage median, 61.0326 ms/stage minimum, and 14.3% estimator gap
  against the 183 ms/stage target.
- 1.099% complete-stack idle CPU across 14 processes against the fixed 5%
  target. This number comes from the TSV, not the JSON's stage-run idle
  metadata.

Earlier raw-minimum runs on review heads were rejected for exceeding the fixed
15% estimator-agreement bound. An admissible receipt at `66a04d8` was
superseded after exact-head review found the shorter-lease edge case. Both facts
are retained in the canonical narrative; neither was silently discarded or
relabeled.

`PERF-001` deliberately remains `PENDING`. Do not turn these measurements into
a saturation, backpressure, storage-sensitivity, recovery-time, full multi-host
margin, or Windows performance claim.

## Current priority and dependency shape

The execution board selects one honest pending dispatch slot: `DEPLOY-003`.
Its objective is to bound the deployment validation surface against the decided
trust boundary in `docs/architecture/DEPLOYMENT_TRUST_BOUNDARY_V1.md` and
`TM-050`.

Important constraints for its next custodian:

- Ask systemd for post-parse truth instead of maintaining another model.
- Validate the complete manager `UnitPath` union rather than reasoning from
  precedence alone.
- Make the real manager-query path executable in the suite before relying on
  it; the historical suite mostly exercised fallback logic.
- Preserve the retained non-systemd obligations: glob/ancestor invariants and
  artifact identity.
- Prefer a clean ephemeral systemd-capable host whose global paths are
  controlled. A lingering account on a shared host does not make global unit
  paths clean.
- Do not add a hardening directive without a runtime proof that it is enforced;
  user managers have accepted directives that were silently ineffective.
- Update the affected threat-model boundary and produce the required closure
  receipt before marking the row `DONE`.

The formal ticket rows, not prose shorthand, define dependencies. In
particular, `SECRET-002` depends on `EXEC-005`, and `SEC-005` depends on
`DEPLOY-003`, `EXEC-005`, and `SECRET-002`. Do not dispatch a downstream
certification whose runtime or containment those tickets will replace.

## Standing risks and non-authority

- No production effect, credential, connector, observer, trigger, discovery,
  cache, provisioning, source, dependency-repository, canary, cutover,
  rollback, recutover, or decommission authority was granted in this tenure.
- The signed private Linux v0.1.0 artifact is cryptographically verified but is
  not a production deployment or release-readiness decision.
- `SEC-005` remains the critical known product boundary: submitted workloads
  still share the deployment service identity until containment closes.
- `scripts/verify-ticket-closure-receipts.py` currently reports
  `done=84`, `receipted=29`, `reviewed=28`, and `debt=37`. This is admitted,
  ratcheted historical debt, not a newly clean ledger. Do not use `--strict` as
  a routine green check until the zero-debt ceremony is intended.
- The board header date can lag individual merges; the ticket table, batch
  ledger, current queue, protected-main identity, and machine verifiers are the
  authoritative combination.

## Reproduction and verification

Start from a clean checkout of current protected main, not any path listed in
the cleanup section:

```text
git fetch origin main
git switch --detach origin/main
git status --short
python3 scripts/verify-execution-board.py
python3 scripts/test-execution-board.py
python3 scripts/verify-ticket-closure-receipts.py
python3 scripts/test-ticket-closure-receipts.py
./scripts/validate-foundation.sh
```

For a mutable ticket, create a fresh `codex/` branch from the re-fetched main.
Before merge, require exact-head review, zero unresolved review threads, every
required exact-head check, clean status, protected-main synchronization, and
post-merge verification. A bot clarification changes the head even when it
does not change receipt bytes; rerun reviews and gates against the actual final
head.

## Noncanonical leftovers

The canonical receipts are committed under `docs/evidence/`. The following
temporary copies were confirmed present on Mario at handoff time and may be
removed after no operator needs them for forensic convenience:

- `/tmp/mcloving-perf110-final-iaNWBi/repo/target/stage-latency-e57f7c9c6dcd8a1f45bc41393780d90fdbf7c13a.json`
- `/tmp/mcloving-split-idle-vuNa2H/split-idle-cpu.tsv`

Their hashes match the committed files. No disposable benchmark or split-idle
container was running. The local QA clone and source bundles live under
`/tmp/mcloving-qa-npAVOa/` and `/tmp/mcloving-pr110-v11.bundle`; they are
noncanonical scratch and can disappear without evidence loss.

No completed `codex/perf001*` branch remained on the remote at authoring time.
There were no open pull requests. Recheck both facts rather than assuming they
remain true.
