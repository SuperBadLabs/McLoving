# Custodian handoff — 2026-09-01 September freeze

## Executive state

McLoving enters a month-long code freeze with a verified, green protected
baseline. Engineering effort moves to Fogell; no McLoving implementation ticket
is authorized to start during September. The normative freeze contract is
[`SEPTEMBER_2026_CODE_FREEZE.md`](SEPTEMBER_2026_CODE_FREEZE.md).

| Item | Identity or result |
|---|---|
| Protected main | `c17bbafafe4f983b6e936cd2f57245edabfb1ffd` |
| Protected tree | `dddf3c31edd2aa6f41d1614e119367beaa8dca5b` |
| GitHub verification | `verified=true`, `reason=valid` |
| Open pull requests | none at authoring time |
| Board | 107 tickets; 21 remaining; one selected pending slot, `EXEC-005` |
| Closure accounting | 86 done; 31 receipted; 30 threat-model reviewed; 37 admitted historical debt items |
| Production authority | none |
| Release readiness | not ready |

Latest successful workflows on that exact main commit:

- Foundation run
  [`33556596622`](https://github.com/SuperBadLabs/McLoving/actions/runs/33556596622),
  aggregate job
  [`100025540191`](https://github.com/SuperBadLabs/McLoving/actions/runs/33556596622/job/100025540191).
- Windows Agent run
  [`33556596621`](https://github.com/SuperBadLabs/McLoving/actions/runs/33556596621),
  native Windows execution and aggregate job
  [`100020258050`](https://github.com/SuperBadLabs/McLoving/actions/runs/33556596621/job/100020258050).
- Release Builder run
  [`33558663955`](https://github.com/SuperBadLabs/McLoving/actions/runs/33558663955).

Live protection at authoring time has strict synchronization, admin
enforcement, linear history, conversation resolution, and disabled force pushes
and deletion. It requires exactly these eight contexts, each bound to GitHub
Actions app id `15368`:

- `Rust`
- `Dependencies and licenses`
- `Secret scan`
- `Architecture records`
- `Formal model`
- `Controller PostgreSQL`
- `Foundation`
- `Windows`

## Work closed by the outgoing custodian

The completed impact dimension is repository merge integrity, ticket `CI-003`.

Implementation PR
[#116](https://github.com/SuperBadLabs/McLoving/pull/116) added stable,
always-running Foundation and Windows aggregate contexts, app-bound all eight
required contexts, retained the six granular Foundation contexts, and hardened
candidate-controlled workflow authority with exhaustive and mutation-oriented
oracles. Exact reviewed head
`0ee95767a96d5664b41a7c035558e41c09f39270` squash-merged as
`463ad646fecccf993fa8a837eb7b9a9c19eb71c7` and passed both aggregates again on
protected main.

Closure PR
[#118](https://github.com/SuperBadLabs/McLoving/pull/118) recorded immutable
receipts, made `CI-003` consistently `DONE` across the board, topology, closed
ticket ratchet, and threat-model attribution, and merged as the handoff baseline
`c17bbafafe4f983b6e936cd2f57245edabfb1ffd`. Its protected-main Foundation and
native Windows aggregates passed at that exact commit. Canonical evidence is
`docs/evidence/CI-003_SECURITY_REVIEW.md`.

## Frozen queue and safe next work

The execution board selects `EXEC-005`, but the freeze overrides dispatch: it
must remain `PENDING` through September. Its future objective is to make a
submitted pipeline reach the already sealed source-acquirer, dependency
resolver, cache, input-adapter, and provisioner helpers through the real product
path, with an end-to-end invocation gate per helper. It then unblocks
`SECRET-002`; `SEC-005` follows both and remains the critical workload
containment boundary.

On thaw, read in order:

1. `docs/handoffs/SEPTEMBER_2026_CODE_FREEZE.md` and confirm it was not
   extended.
2. `docs/EXECUTION_BOARD.md`, especially the current dispatch section and the
   full `EXEC-005`, `SECRET-002`, and `SEC-005` rows.
3. `docs/evidence/CI-003_SECURITY_REVIEW.md` before changing any workflow,
   classifier, verifier, oracle, or branch-protection rule.
4. `docs/related-work/FOGELL.md` before using any work produced during the
   September Fogell focus.

Do not resume the remote `codex/ci-003-*` or `codex/deploy-*` branches. Their
work is merged and their heads are not a thaw baseline. Create a fresh branch
from a freshly fetched protected main.

## Standing risks and non-authority

- No production effect, credential, connector, observer, trigger, discovery,
  cache, provisioning, source, dependency-repository, canary, cutover,
  rollback, recutover, or decommission authority is granted.
- The signed private Linux v0.1.0 artifact is evidence, not a production
  deployment or a release-readiness decision.
- `SEC-005` remains open: submitted workloads share the deployment service
  identity until per-platform containment closes.
- The closure verifier's 37 historical debt items are admitted and ratcheted,
  not a clean ledger. Routine verification succeeds while reporting them;
  `--strict` remains reserved for an intentional zero-debt ceremony.
- Dependabot alerts
  [#1](https://github.com/SuperBadLabs/McLoving/security/dependabot/1) and
  [#2](https://github.com/SuperBadLabs/McLoving/security/dependabot/2) are two
  manifest records for the same moderate `jsonwebtoken` advisory
  `GHSA-h395-gr6q-cpjc`. The freeze defers a routine upgrade; it does not accept
  or dismiss the risk. Reassess on thaw or under an explicit emergency decision.
- Fogell receipts remain Fogell receipts. They may guide McLoving work but
  grant no McLoving status, evidence, compatibility, release, or production
  authority.

## Reproduction and thaw verification

Use a clean checkout after confirming the freeze has expired or been lifted:

```text
git fetch origin main
git switch --detach origin/main
git status --short
python3 scripts/verify-execution-board.py
python3 scripts/test-execution-board.py
python3 scripts/verify-ticket-closure-receipts.py
python3 scripts/test-ticket-closure-receipts.py
python3 scripts/test-workflow-aggregate.py
python3 scripts/test-windows-agent-impact.py
./scripts/validate-foundation.sh
```

Then re-read GitHub protection, alerts, open pull requests, releases, and every
default-branch workflow since the authoring baseline. The local checkout used
to author this handoff contains an unrelated untracked `.claude/` directory;
it is user-owned, noncanonical, and was neither modified nor committed.

## Publication note

This handoff publication is accounting only. Its squash commit will advance
protected main beyond the authoring baseline. Require its exact-head checks and
review, merge through protection, and verify Foundation and Windows afterward.
The resulting publication commit, not the authoring baseline, is the commit the
next custodian should fetch; the identities above remain the measured state the
handoff records.
