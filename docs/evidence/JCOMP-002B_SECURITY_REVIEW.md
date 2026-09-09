# JCOMP-002B contained workspace transfer review

## Status and boundary

JCOMP-002B is ACTIVE. This is a review plan and implementation record, not a
closure receipt. The actual shipped runtime campaign, final independent review,
protected merge and exact-main verification remain outstanding. The design is
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
These mocks are control-flow verification only. The contained driver requires
four sequential-store, three workspace-store and eleven remote tests, with
eight sequential and five workspace evidence markers; its actual campaign
has not yet supplied passing evidence for this candidate.

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
Focused strict Clippy passes; actual execution of this corrected candidate
remains the next verification obligation.

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
inspected both publication paths. A fresh contained campaign remains required.

The initial full Foundation gate also refused an unversioned new local domain
dependency. Adding its exact `=0.0.0` version passes the pinned dependency-ban
check without changing policy. The separate source-acquirer package passed
under its required AppArmor profile; those source files are unchanged by these
corrections.

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
