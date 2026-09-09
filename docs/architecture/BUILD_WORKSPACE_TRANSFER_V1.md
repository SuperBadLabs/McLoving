# Contained build workspace transfer v1

Status: JCOMP-002B ACTIVE implementation candidate. The design and tests below
are obligations, not completed runtime or closure evidence. JCOMP-002A's earned
sequential execution remains a separate bounded receipt.

## Scope and authority

The internal `SequentialDagBuild::with_workspace_transfer` mode extends the
contained Linux sequential chain with controller-owned, bounded workspace
checkpoints. It uses verified state transfer between fresh attempt workspaces;
it does not assign a shared mutable directory to multiple attempts. There is no
public admission route, imported-job enablement, production pool or credential
opt-in. Placement stays in `migration-deny-authority`. Transfer-capable agents
must negotiate `build-workspace-transfer-v1` and advertise
`workspace-transfer-v1`; legacy agents retain attempt-only behavior.

Each literal step still runs a fresh shell. Shell environment and current
working directory do not persist. The agent rejects explicit environment and
credential declarations in this mode. Checkpoints contain only permitted
workspace directories and regular files; they carry no credential envelope,
agent journal, log spool, process identity, ownership or ambient environment.
This format cannot identify secrets that a workload deliberately writes into an
ordinary file. Disposable fixtures must have no production credentials.

## Ownership, transfer and replay

The admission transaction allocates a unique namespace UUID per build and an
empty generation-zero checkpoint. Organization/build/namespace identity and the
current generation travel with the snapshot and its SHA-256 digest in optional
`WorkAssignment.workspace_transfer_json`. Empty bytes preserve the existing
protocol meaning. Transfer metadata does not replace the existing attempt,
fence, agent session, restore and execution-payload checks.

An agent materializes the validated checkpoint in the fresh attempt/fence
workspace using create-new files and explicit parent directories. Readback
must reproduce the snapshot digest before the process starts. Agent placement
may change between steps because the controller supplies the checkpoint;
continuity does not depend on the preceding agent retaining its directory.

After process-tree containment, the executor captures eligible workspace
entries. Completion carries either a validated output snapshot or an explicit
bounded capture error. The controller compares organization, build, namespace,
generation and input digest to current ownership while holding the build row
lock in the existing fenced terminal transaction. A successful completion
cannot omit its snapshot or report capture failure. Publishing the checkpoint,
advancing its generation and making a successor runnable must be atomic.

Replay compares normalized content receipts before repeating state mutation.
Receipts retain snapshot digest, ordered paths, directory identity, regular-file
length/content digest and executable bit, so a metadata-only substitution is
still a different result. Raw contents do not belong in terminal summaries or
build events. Exact committed completion replay must remain valid after the
active checkpoint has advanced or been closed, without advancing it again.

Manual retries are refused for this mode. A failure requires a new build,
preventing a failed-step retry from silently selecting a different checkpoint.
Pre-start lease expiry may safely reoffer the unchanged input. StartWork followed
by lease loss retains JCOMP-002A's reconciliation boundary; it cannot rerun an
uncertain shell or advance a successor with uncertain files. Cancellation,
restore and stale session/fence refusal remain existing authority boundaries.

## Canonical representation and limits

A version-one snapshot contains at most 32 lexically ordered unique entries,
with at most 8 KiB total regular-file content. Paths contain at most 256 UTF-8
bytes and eight slash-separated components. Absolute paths, empty components,
`.`/`..`, control characters, backslashes and colons are refused. Every parent
must be an explicitly earlier directory. Root `spool` and `.agent-results`
are reserved. The runtime excludes its own root spool from captured files.

Directories, including empty directories, and regular files with an executable
boolean are supported. Symlinks, hard-linked files, special files and non-UTF-8
paths are refused. Ownership, arbitrary permission bits, timestamps, extended
attributes and platform-specific filesystem behavior are not transferred.
Regular files materialize privately as 0600 or 0700. Snapshot digest is SHA-256
of the validated typed JSON encoding, covering all ordered metadata and bytes.

The snapshot's encoded JSON is limited to 48 KiB; its enclosing transfer result
is limited to 60 KiB, within the existing 64 KiB terminal-result boundary. These
are separate bounds because byte arrays and escaped paths expand in JSON.
Error text is nonempty and at most 1024 bytes. UUID strings must be canonical
and nonnil, and generation is bounded by the 64-step chain.

The checkpoint limits bound transfer and controller state. They do not impose a
live filesystem quota on an arbitrary workload. The disposable runner must use
a 512 MiB tmpfs and explicit container resource limits for the campaign's hard
storage bound. No production storage-containment claim follows from this test.

## Cleanup and required verification

Final outputs must be observed and bound to content receipts before cleanup.
Terminal build cleanup removes the controller's raw checkpoint bytes and closes
the namespace while retaining output identity. Agent attempt cleanup retains
its existing journal/result replay ordering and removes the whole attempt
workspace. A fresh build receives a fresh namespace even for identical source.

Required tests include cross-step and cross-stage file continuity with fresh
shell state, separate-build non-collision and actual placement transfer; binary
content, executable files and empty directories; stale namespace/generation/
digest/session/fence refusals; exact terminal replay after crash; failure,
cancellation, lease loss and whole-build cleanup; and oversized, malformed or
unsupported entries. Tests must observe actual outputs before deletion and
verify that no raw checkpoint remains after terminal closure. Store-only
accounting and mock gate checks are not substitutes for actual agent execution.

SEC-005 owns hostile same-UID sibling filesystem/process isolation. This design
assumes the executor has contained its process tree before capture and does not
claim immunity to another hostile process with the agent's OS identity.
JCOMP-003 owns paired Jenkins execution and separate 228-source classification.
Neither those claims nor release, canary, cutover or production authority is
established by this candidate.
