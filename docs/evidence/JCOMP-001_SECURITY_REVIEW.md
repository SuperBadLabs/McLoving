# JCOMP-001 contract and fixture review

## Status and scope

Implementation under review. JCOMP-001 is ACTIVE;
protected-head checks, protected merge and exact post-merge Foundation/native
Windows verification must complete before a subsequent closure update.
This receipt does not claim new compiler admission or execution compatibility.

The versioned sequential Declarative contract preregisters ten authored
supported-input expectations, twelve authored negative expectations, and one
unchanged historical regression. The 228-source corpus remains a separate
future reclassification denominator. Source hashes and the existing Jenkins
profile remain pinned; original authored fixtures make no new license grant.
Historical migration and differential receipts are unchanged.

## Reviewed content

These hashes bind the local authoring checks below. Any change to a covered
file requires the relevant checks and independent review again.

| File | SHA-256 |
|---|---|
| `docs/architecture/JENKINS_SEQUENTIAL_DECLARATIVE_V1.md` | `ae47b3f3cc58d6a66cec6d73832a189417864df74110c83bf1f656840c5d5dfe` |
| `compat/jenkins-worker/fixtures/sequential-v1/manifest.json` | `654898829f31872d471db88830414b23a9453e021bec281f05ac1aa4175de727` |
| `compat/jenkins-worker/fixtures/sequential-v1/validate.py` | `6e0da9ca79c8d20d804e207559948cdc48682b348578f0d8ed28552db409ca39` |
| `compat/jenkins-worker/fixtures/sequential-v1/test_manifest.py` | `c1f900bebf8e3333bb2b6ee67abfe1ace147f88ef298eaac67b4db42606f112f` |
| `compat/jenkins-worker/fixtures/sequential-v1/check_literals.clj` | `b50b7afd1522cc6748e8a12c9652df67ecd0c27d468a5c408af52b37e251a589` |
| `scripts/test-jenkins-sequential-contract.sh` | `5a4b23c59dbd56e7dd28776120218976aea171aa927eb945b967bfe2daded2c5` |
| `.github/workflows/foundation.yml` | `f0f9fdcebc2237fbae73cc8d04290ba65c1bf72effa447408365f1a80078e279` |
| `scripts/validate-foundation.sh` | `c98ebafb48aab3d1eb9789b9f3efaa22bfc3ff12a79d8af1ebcbe06b732a767b` |
| `compat/jenkins-worker/README.md` | `ddc4be667521ba4621d3785df1ad3f6538681f51bbe182b051e75ba73303365e` |

## Verification and review

The shared read-only authoring gate passed: 23 fixture records, all 16 mutation
tests, 11 exact source-stage/script comparisons using the digest-pinned Groovy
2.4.21 CONVERSION AST, and malformed-quoting rejection. No Jenkinsfile or shell
was evaluated by this gate. Independently reviewed local shell-snippet drafts
were authoring checks only, not Jenkins or McLoving execution evidence.

Initial independent wrapper review of the 15-test version used temporary minimal repository copies and a
marker in place of Clojure. Removing one test (14 instead of 15), emptying the
test module (zero tests), and skipping an existing test each failed before the
marker could run. The complete population is required; absent, skipped or
partial suites cannot turn the gate green. Shell syntax validation and repository-pinned actionlint passed. Both local
and hosted Foundation invoke the shared gate alongside the unchanged six-test,
20-assertion Clojure compiler/protocol suite and plugin-directory contract;
those existing checks also passed. All 49 board and 78 closure tests passed,
with 115 tickets, 87 done, 28 remaining, and unchanged 37-item historical debt.

Independent contract/fixture review corrected Groovy escape mismatches in
multiline fixtures before these checks. Validator review then corrected a
substitutable contract path and missing normalized stage-ID collision checks;
regression mutations cover both. Stage normalization now specifies ASCII-only case folding and preserved
periods, underscores and hyphens; a Kelvin-sign regression rejects Unicode
case folding that could produce inconsistent identifiers across runtimes. Final targeted reviews found no remaining
action items in the contract, fixtures, validator or shared wrapper.

## Threat and claim boundaries

The new manifest and checker are repository-owned expectation data and local
CI authoring tools. They do not replace the isolated compiler or independent
Rust admission boundary. Groovy constructs an AST only at CONVERSION; it does
not evaluate source, invoke Jenkins plugins, schedule work or contact an agent.
No fixture or model-generated draft is accepted as execution evidence.

Independent semantic source-to-output checking remains JCOMP-002 work. Real
step execution remains JCOMP-002A work. JCOMP-002B owns workspace lifecycle,
namespace allocation, fenced controller/agent operations and cleanup; hostile
same-UID workload filesystem isolation remains SEC-005. The M1 campaign must
use dedicated disposable environments with no production endpoints or
credentials, not a production agent claiming containment from path naming.

Existing compiler/profile/provenance and workflow protection requirements
remain in force. This ticket adds no production API, operational authority,
expanded history migration, corpus admission count or certified parity claim.
The exact implementation PR review and hosted receipts will be recorded after
they exist; the current content pins do not discharge future protected checks.

## Implementation review corrections

Copilot review of `34a2636` identified that the authoring validator pinned the
contract path but did not enforce the reviewed contract bytes. The validator
now checks the contract SHA-256 and a dedicated drift mutation fails on an
unreviewed content edit; the wrapper requires all 16 tests. Both Python
invocations explicitly suppress bytecode generation. Direct script execution
did not import repository-local modules previously; the explicit setting
keeps the two invocations consistent as imports evolve.

Independent correction review repeated the wrapper controls on temporary
minimal repository copies with no inherited `PYTHONDONTWRITEBYTECODE`: the
complete 16-test suite reached the Clojure marker, while removing one test
(15 remaining), emptying the module, or skipping one test each failed before
the marker. All four runs created zero `__pycache__` directories or `.pyc`
files. The full shared gate also passed all 16 tests and 11 pinned AST
comparisons. Independent review found no remaining action items.
