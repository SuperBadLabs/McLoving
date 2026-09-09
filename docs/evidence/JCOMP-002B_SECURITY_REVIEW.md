# JCOMP-002B contained workspace transfer review

## Status and boundary

JCOMP-002B is ACTIVE. This is a review plan and implementation record, not a
closure receipt. The historical shipped runtime campaign passed on `941d473`,
but a continuation review identified an uncovered operator-reconciliation path.
The reconciliation correction passed independent review and a fresh campaign
at `e4b6fcd`. Subsequent PR review found terminal-reason precedence and schema
receipt/generation issues; their dispositions and refreshed validation are
recorded below. Earlier campaigns do not verify later source changes.
Protected final-head checks, merge and exact-main verification remain outstanding. The design is
`docs/architecture/BUILD_WORKSPACE_TRANSFER_V1.md`.

The selected internal mode transfers a bounded controller-owned checkpoint
between fresh attempt workspaces. It preserves the existing sequential shell,
process supervision and fenced terminal paths. A unique build namespace and
monotonic checkpoint generation prevent controller-assigned state collision;
this does not establish hostile same-UID filesystem isolation. Imported jobs
remain disabled and public admission guards retain their existing boundary.

## Threat review and obligations

- TM-001/TM-038: bind every checkpoint grant and completion to organization,
  build, namespace, saved enabled pipeline and existing operational fences.
  Legacy builds must reject unsolicited transfer results. A successful transfer
  completion cannot omit its snapshot or return a capture error.
- TM-003/TM-005/TM-006/TM-007/TM-011/TM-017: retain attempt/session/restore/fence
  checks, safe pre-start reoffer and reconciliation after uncertain StartWork.
  Checkpoint publication and successor readiness must commit atomically.
  Exact completion replay must not advance generation twice, including after
  final workspace closure. This mode refuses manual retries; restart as a new
  build after failure.
- TM-008/TM-009/TM-016/TM-023: enforce independent content, entry, path, depth
  and encoded-size limits; refuse links and special files; verify materialized
  input before process execution and capture only after process containment.
  Transfer bounds do not replace the disposable runner's hard tmpfs limit.
- TM-018/TM-022/TM-024: retain complete ordered content and metadata identity in
  receipts without copying raw file contents into terminal summaries/events.
  Observe outputs before whole-build cleanup, remove live checkpoint bytes on
  terminal closure, and retain truthful cleanup and uncertainty observations.
- TM-052: require exact non-skipped test populations, executed-source/binary/
  image bindings and a private disposable database/runner campaign. Mock gate
  controls and store-accounting tests must remain distinct from real runtime
  evidence. Final source changes require appropriate fresh evidence.

## Initial independent schema inspection

A read-only subagent inspected `domain::workspace`, the added WorkAssignment
field, and its current store/agent consumers during implementation. No actionable
schema blocker was identified in that bounded snapshot. The inspector did not
run domain, store or runtime tests and did not certify the unfinished consumers.

Canonical sorted paths plus explicit directory parents reject aliases,
duplicates and file-as-parent layouts. The typed snapshot digest binds bytes,
paths, empty directories and executable bits. Grants require canonical nonnil
UUIDs and matching snapshot digest. Results require exactly one snapshot or
bounded nonempty error; namespace/generation/input-digest authority remains a
contextual store check, not something schema validation alone can establish.
The agent's candidate assignment validation refuses declared environment and
credentials in transfer mode. Protocol compatibility requires negotiated
feature/capability gating in addition to the empty-default bytes field.

Recommended focused checks include worst-case encoded-size expansion,
metadata-only digest and replay mutations, exact error/identity/generation
bounds, absent or unknown fields, and mismatch between a valid standalone
grant and the receiving assignment. These recommendations are not evidence
that the checks have run or passed.

## Focused candidate verification

The integrating custodian and store/runtime agents report passing focused
candidate checks: three real-PostgreSQL workspace-store tests, four existing
sequential-store tests and five planner tests; 55 agent library tests and 35
agent-runtime library tests; and strict Clippy for affected packages. These are
working-tree observations, not a final committed-source campaign or protected
head receipt. They do not establish actual workspace transfer through the
shipped controller and agent.

The schema reviewer independently ran all 15 domain tests and strict
all-target domain Clippy successfully. Added tests cover the exact 48 KiB
encoded snapshot limit and one-byte overflow with JSON-expanding paths/content,
metadata-only digest and receipt changes, 1024/1025-byte errors, canonical UUID
and generation 64/65 boundaries, and receipt metadata integrity. The new
`WorkspaceSnapshotReceipt::validate` helper validates structure and aggregate
sizes only; content digest verification still requires a matching snapshot or
independently bound terminal receipt.

All four mocked gate-control tests pass after adding the separate three-test
workspace-store population and expanding the remote population to eleven.
Each of the three suites independently refuses failed, empty, wrong-sized,
skipped and ignored outcomes, and every required source target is checked.
These mocks are control-flow verification only. The historical contained driver
required four sequential-store, three workspace-store and eleven remote tests,
with eight sequential and five workspace evidence markers; that passing campaign
is recorded below. The reconciliation correction adds a fourth workspace-store
test to both runtime gates and their mocked population control.

A read-only inspection of the five new actual-runtime test definitions found
useful generation/output/owner bindings and identified improvements needed
before relying on their cleanup and filesystem-metadata claims: named-marker
absence alone does not prove whole workspace deletion, a cancellation marker
checked only after cleanup can be vacuous, and empty-directory/executable-bit
continuity needs direct later-step observations. The corrected definitions now check exact attempt/fence paths and result
spools, observe a private cancellation marker outside deleted workspaces,
execute a transferred tool and inspect its executable bit, and observe an
empty directory in a later stage. They wait for both agent sessions before
admission and include actual exit-7 failure with captured file receipts.
Focused strict Clippy passes; the corrected candidate passed actual execution
as recorded below.

## Development campaign correction

The first contained campaign on `5152089` passed all four sequential-store
and three workspace-store tests, then passed the six predecessor remote tests
and failed all five new workspace tests. The actual agent wrote transfer data
into its durable result but reconstructed a smaller wire summary that omitted
it. Successful steps were therefore refused by the controller; a capture
failure also lost its named reason. Source review and serialization-only tests
had missed that publication boundary.

The correction makes live completion and recovery use the same builder from
the verified durable result. Workspace publications preserve full transfer,
actual exit/termination, reason and original result digest; legacy summary
shapes remain unchanged. New regression coverage checks the actual builder
for success, capture failure and identical replay. All 56 agent library tests
and strict all-target Clippy pass, and the store reviewer independently
inspected both publication paths. The fresh campaign below verifies the fix.

The initial full Foundation gate also refused an unversioned new local domain
dependency. Adding its exact `=0.0.0` version passes the pinned dependency-ban
check without changing policy. The separate source-acquirer package passed
under its required AppArmor profile; those source files are unchanged by these
corrections.

## Historical corrected committed-source campaign and review

The fresh contained campaign on exact source
`941d473144d942824b767eb78744ad27bdf6ac20` passed all four sequential-store,
three workspace-store and eleven actual remote-agent tests, with zero failed,
ignored or skipped tests. All eight predecessor and five workspace evidence
markers were present. The retained
[`jcomp-002b-workspace-v1`](jcomp-002b-workspace-v1/README.md) inventory binds
source/tree/archive, pinned images, all five executable hashes, complete build
and runtime logs, database identity and successful disposable cleanup.

The controller hash is
`f78ce4a2ea046f0a08ff91a8fcd8049e345fa2ee2c9afa4592ff5958a358e73a`;
the corrected agent hash is
`fa7abc7c60b98572916999639885034adf73ef40e1de0410ad83851786b5e5aa`.
The actual tests verify different-agent placement and controller restart,
terminal-commit crash/replay after namespace closure, four fresh shells,
file-content/binary/executable/empty-directory continuity, concurrently admitted
builds with distinct state, exact workspace and result-spool path removal,
pre-start and active cancellation, oversized/symlink capture refusal, retained
exit-7 evidence and no transfer of uncertain writes after started lease loss.
The lease-loss case retains the last verified generation pending reconciliation;
it does not claim whole-build terminal cleanup.

Full local Foundation validation passed on this corrected source using the
September handoff's documented source-acquirer split: the workspace test command
excluded only that package, which separately passed under its required
`mcloving-source-acquirer` AppArmor profile. Repository validation policy and
workflow commands were not weakened. Four mocked gate-control tests and eleven
workflow contract tests pass; these remain distinct from actual execution.

The runtime author independently reviewed the domain/store/controller changes;
the store author independently reviewed agent/runtime/controller and the gate
changes at `5152089`, then independently reviewed the final publication fix at
exact `941d473144d942824b767eb78744ad27bdf6ac20`. The latter review explicitly
checked live/replay equivalence, verified durable digest, malformed-transfer
refusal, bytes-free store normalization, cancellation-substituted summaries and
replay before checkpoint mutation. No actionable blocker remained. The separate
schema/gate reviewer ran domain tests and inspected actual-test assertions;
strengthened cleanup and metadata checks were included in the passing campaign.
The independent retained-evidence audit reconstructed the committed source
archive and verified all eleven inventory hashes, all eighteen source hashes,
nineteen source-bound result records, thirty stdout records, eight closed
cleanup receipts, and eleven controller plus eleven agent executable identity
records. It independently reran four gate controls and eleven workflow tests;
all passed. The retained manifest counts and cleanup/nonclaim language matched
the actual log. No edits or actionable findings were required by that audit.
These independent reviews do not substitute for protected PR checks.

## Continuation finding: operator reconciliation bypassed workspace publication

The continuation store review found that `finalize_reconciled_attempt` bypassed
the workspace publication boundary. Operator reconciliation could report a
workspace-enabled attempt successful without a verified checkpoint, allowing
downstream work to consume the previous generation. Operator-supplied workspace
transfer data also lacked the normal publication and summary-normalization path.
The historical campaign did not exercise this boundary; its passing receipt
remains evidence only for its recorded scenarios and exact source.

The correction refuses success and operator-supplied workspace transfer data
for workspace-enabled attempts before replay or mutation. Operators may resolve
uncertain work as failed or aborted without manufacturing a checkpoint; terminal
closure retains the last verified generation and receipt and removes live bytes.
The added workspace-store regression covers refusal, terminal closure and exact
replay. Both actual runtime gates now require four workspace-store tests.

The runtime reviewer independently inspected the store correction and regression
and found no blocker. The same reviewer checked the complete gate-count delta:
both drivers and the mocked control consistently require four workspace-store
tests, with the strict population/skip refusal unchanged. The four mocked gate
tests and shell syntax checks passed before the reviewed source was committed.

## Historical reconciliation campaign and validation

The fresh contained campaign executed exact reviewed source
`e4b6fcd9f21bd7bdf54986bff5dab3628942e426`, tree
`a67078a4269ce017ed50b3f41a9fb1e4c9265af1`. All four sequential-store, four
workspace-store and eleven actual remote-agent tests passed with zero failed,
ignored or filtered tests. The named reconciliation regression executed against
real private PostgreSQL. All eight sequential and five workspace markers were
present. The separate [`jcomp-002b-workspace-v2`](jcomp-002b-workspace-v2/README.md)
inventory supersedes v1 for this corrected candidate and preserves v1 unchanged.

The executed controller hash is
`f31457b73676f300519bfcf4935231cfaed253614f902d35a6492f3ec10baba3`;
the agent hash remains
`fa7abc7c60b98572916999639885034adf73ef40e1de0410ad83851786b5e5aa`.
The source archive hash is
`bda74702ab63c0c30f397b0e46ce1d861a7d216e35626dc0c4d892fa47c06e22`.
The independent implementation reviewer reconstructed the archive and verified
all raw inventory hashes, 4+4+11 exact test populations including the new
regression, eleven controller/agent identity pairs, eighteen source hashes,
nineteen source-bound results, thirty stdout attempt bindings and eight closed
cleanup receipts. A separate Podman readback confirmed the private database
container was absent. The reviewer also verified all eleven retained inventory
hashes, all nine byte-identical copied execution artifacts, manifest/README
claims and the unchanged v1 inventory, with no findings. These are independently
checked execution receipts, not new protected GitHub evidence.

The runtime reviewer also ran full local Foundation successfully on exact
`e4b6fcd`, using the previously documented source-acquirer split. The split
changes only the script location and exclusion of that one package from the
workspace test command; the excluded package independently passed all 31 tests
under its required AppArmor profile. Its retained local receipt explicitly
distinguishes this Linux validation from native Windows and protected checks.
The contained campaign above supplies the separate actual PostgreSQL execution
evidence. Initial sandbox startup errors were diagnostic only; ordinary local
Podman approvals allowed the unchanged validation commands to run successfully.

## PR review corrections and refreshed validation

Automated PR review identified that workspace capture failure took precedence
over the lease-loss reason in durable terminal results. A cancelled execution
could retain its capture error while losing the reason that explains uncertain
execution and reconciliation. The correction prioritizes the lease-loss reason
and retains the capture error in the workspace transfer result. Existing unit
coverage now checks live/replayed terminal publication, and the actual remote
lease-loss scenario checks the exact fenced durable result before restarting
the controller. Its marker additionally reports retained lease reason and
`execution_not_completed` capture error. Test populations remain 4+4+11.

The second automated finding identified a missing database invariant between
workspace generation and receipt presence. The migration now requires no receipt
at generation zero and a receipt after generation advances, including closed
namespaces. The existing real-PostgreSQL lifecycle test attempts invalid initial,
open and closed states and requires SQLSTATE `23514` with the named
`builds_workspace_receipt_shape` constraint. Runtime receipt validation remains
responsible for the richer receipt structure and digest checks.

The implementation reviewer independently approved the runtime correction and
durable-result observation; the runtime reviewer independently approved the
schema correction and regression. No blocker remains from those bounded reviews.
A fresh contained campaign on the consolidated clean committed source remains
pending. Keep v1 and v2 unchanged as historical evidence; retain the next
campaign as v3.

## Evidence required before closure

Run the actual shipped controller/agent through cross-step/stage continuity,
fresh shells, distinct-build namespaces and placement transfer, supported file
metadata, explicit capture refusals, cancellation, lease loss, stale lifecycle
operations and terminal replay. Verify final output before agent cleanup and
controller raw-byte erasure after build closure. Exercise atomicity and replay
in real PostgreSQL, including current ownership mismatch and closed namespace
behavior. Retain reproducible source/tree/image/binary identities, exact test
populations, output records and cleanup evidence.

Review the final implementation and gate changes independently, resolve every
actionable finding, pass all protected final-head checks, merge under current
protection and observe Foundation and actual native Windows success on the
exact merged-main commit. Record those observations before marking this ticket
DONE or beginning JCOMP-003.

## Residuals and nonclaims

The checkpoint transfers ordinary authored file bytes. It cannot recognize a
credential deliberately written into a permitted file, so the contained
campaign must provide no production credentials. No credential grants or new
external effects are authorized. Arbitrary file permissions, symlinks, hard
links, special files, extended attributes and Windows workspace semantics are
unsupported. Byte/entry bounds do not promise a production runtime disk quota.

Hostile same-UID sibling access, external concurrent mutation and general
workload containment remain SEC-005. Paired Jenkins equivalence, S03/S06/S07
fixture acceptance and original-corpus coverage remain unearned until the
appropriate actual campaigns pass; JCOMP-003 owns the paired claim and separate
228-source report. No production, deployment, canary, cutover or release
authority is granted.
