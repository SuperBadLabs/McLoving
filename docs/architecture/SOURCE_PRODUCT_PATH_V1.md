# Source checkout product path v1

PAR-012 delivers the source slice `EXEC-005` owed: a submitted pipeline can
check a repository out at an exact commit through the API, controller, remote
mTLS agent and the sealed source acquirer, and the steps that follow in the
same stage build in that checkout. Nothing the acquirer already did changes;
this document is about the seam that puts it on the product path.

## Submission and scheduling

A stage may contain at most one literal `checkout` step, alongside process
steps, in any position. It carries `mapping_id`, `mapping_digest` (`sha256:`
followed by 64 lowercase hex digits), `ref` (a fully qualified `refs/...`
name), `commit` (an exact 40 or 64 lowercase hex object id, either a literal
or an expression over typed parameters), an optional `destination` (one plain
workspace path component, default `source`; `spool` is reserved) and an
optional `timeout_seconds` in 1..=3600 (default 600). No repository URL,
credential, executable, depth, sparse root or submodule is accepted from the
job: all of those are deployment bindings. A checkout stage selects canonical
IR 1.7, opcode 5 and the version-5 execution envelope even with a single step,
and may also name an `image`: the checkout step runs the sealed acquirer on
the host under its own containment, never in the image, and the tree lands in
the workspace the image steps see at `/workspace`. The literal-shell migration
planner remains process-only and refuses checkout stages.

The acquirer resolves `ref` and requires it to resolve to exactly `commit`;
a ref that has moved on is refused as `revision_mismatch` rather than checked
out at whatever it now points to. Webhook and parameter plumbing that supplies
the commit is `PAR-001`'s.

The default controller grants no source authority. Startup configuration pairs
`MCLOVING_SOURCE_MAPPING_CATALOG` with the exact raw-byte
`MCLOVING_SOURCE_MAPPING_CATALOG_SHA256`. The strict
`mcloving.source-mapping-catalog/v1` catalog contains profile, generation and
mapping records binding mapping id/digest, organization/project/pipeline and
trust pool. Every validate, plan, save, submission and saved replay admission
checks the relevant authoritative scope; validation and planning need an
explicit pipeline ID; Windows and scope/digest mismatches are refused before
queueing. A pipeline plan reports `checkout_steps` per stage beside the
other step-kind counts. Catalog updates require restart.

Scheduling requires `multi-step-v1`, `sealed-source-v1` and a
domain-separated capability for the exact mapping id and full mapping digest.
Agents advertise matching bindings only in their configured pool; an agent
whose binding names another mapping cannot claim the node, and the generic
capability alone is never sufficient. Agent-side binding checks remain
mandatory after assignment.

## Operator binding

The agent loads `MCLOVING_AGENT_SOURCE_BINDINGS_PATH` with exact raw-byte
`MCLOVING_AGENT_SOURCE_BINDINGS_SHA256`. The file is owner-private,
single-link, mode 0400, bounded at 256 KiB and strictly duplicate/unknown-field
rejecting. Its `mcloving.agent-source-bindings/v1` mappings are `SourceBinding`
records in `bins/agent/src/source.rs`: pinned acquirer executable and digest,
acquirer configuration path and canonical digest, credential, receipt signing
key and secret marker paths, and an optional `launcher`. The launcher is how a
host that restricts unprivileged user namespaces enters the acquirer:
`aa-exec -p <profile> -- /proc/self/fd/N`, the profile granting only
`userns create` and the image still being the sealed memory file. A
`test_mode` binding is a fixture-only operator opt-in that lets the acquirer
configuration name file or loopback repositories; a configuration that names
them without it is refused.

Before the spawn the agent re-reads the acquirer configuration and checks its
canonical digest, the signing key digest, the secret marker set digest and
that the requested ref is inside the configuration's allowed prefixes, so a
job cannot learn about a binding by probing it. The request it writes is the
acquirer's own `AcquisitionRequest`: identities from the controller-authorized
work context, a deterministic acquisition id per attempt and step, the
repository from the configuration, depth 1, no sparse roots or submodules, and
a time window opened immediately before the step's own spawn, for exactly
the step timeout, so waiting for credentials or earlier steps never spends
the checkout's time. The acquirer is entered with the sealed
image, the four private paths in its environment, and no argument the job
wrote.

## Answer authentication and publication

The acquirer answers one NDJSON line. The agent authenticates a success
against the same material it configured the helper with: the receipt's
HMAC signature under the signing key, its configuration, implementation and
runtime-closure digests, its `request_sha256` against the request the agent
wrote, its acquisition, attempt and build identities, its checkout name, and
that the primary tree resolved to exactly the requested commit. Only a typed
public summary (`mcloving.source-invocation/v1`: invocation id, mapping id,
acquisition id, destination, outcome, resolved commit and tree, file, byte and
transport counts) reaches the step's public stream; the acquirer's message is
never carried, and a failure code outside its closed list is reported as
`acquisition_failed`.

The verified tree is then published into `<workspace>/<destination>` by a
descriptor-relative move: the acquisition directory and the workspace are
opened `O_DIRECTORY|O_NOFOLLOW` and checked owned by the agent; the tree's
identity is taken from its own descriptor; the destination is checked absent
by a no-follow stat; the move is `renameat2(RENAME_NOREPLACE)` between the two
descriptors; and the moved entry is checked afterwards to be that very inode
and a directory. A destination an earlier step pre-created is refused as
`checkout_destination_preexists:<name>` with nothing written through it; one
that appears between the check and the move makes the move fail rather than
replace and is reported as `checkout_destination_substituted:<name>`; an
output root on a different filesystem from the workspace root is
`checkout_publication_cross_device`, so the deployment must colocate them.
The acquirer leaves its tree read-only; publication then gives every
directory and regular file below the destination its owner's write bit,
walking by descriptor and skipping links, so build steps can work in the
checkout. A checkout step whose exit was clean but whose answer was not
accepted, or whose publication was refused, is the failed step that stops the
stage, with the reason in its step record and the terminal summary.

## Gate

`bins/agent/tests/source_work.rs`, run by `scripts/test-source-product.sh`
inside the source-acquirer Foundation job: a real controller, a real agent, the
shipped acquirer and a file repository. It proves that an ineligible agent
serves other work while the checkout stays queued, that the eligible agent
lands the branch head whose README names its parent and a following step runs
the repository's own script and writes into the checkout, that the acquirer's
output root keeps its receipt but no tree, that a planted symlink destination
is refused by name with nothing written through it, and that an unknown
mapping, a wrong digest, a malformed commit, a path-escaping destination and
the Windows platform are refused before any build exists.
