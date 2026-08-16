# Migration package v1

Status: `MIG-007` implementation complete pending exact-head review, CI, and protected-main merge

## Purpose and boundary

`mcloving.jenkins.migration-package/v1` is a deterministic, reviewable,
deny-authority envelope over the exact artifacts and blockers for the sole
currently code-equivalent migration candidate. It does not compile new Jenkins source,
rerun a state transform, expand the certified denominator, enable the source
job, deploy McLoving, or transfer any production authority.

The package is one canonical JSON file rather than a mutable tree of semantic
inputs. This keeps parsing bounded and lets every embedded document flow
directly into the existing in-memory canonical validator that already owns its
semantics.

## Exact contents

The envelope binds and embeds:

- the immutable source export for `corpus-052-cinqict_jenkinsdev`;
- the canonical compiler EDN response, strict pipeline YAML, separate disabled
  `JOBSTATE-001` YAML, and reviewed compiler trace;
- the exact compiler/profile/worker-image, inventory, source/configuration,
  pipeline, job-state, canonical-IR, oracle, and corpus identities;
- the mapping catalog and detached semantic lock;
- the complete 228-row corpus index plus a normalized 228-row package
  disposition ledger;
- the canonical MIG-006 aggregate and DIFF-002 state-policy evidence;
- the reviewed v0.1.0 release identity, envelope, evidence-manifest, and
  verification-receipt digests; and
- the exact eligibility-ledger and persistent-state inventory digests; and
- a normalized record for the candidate's one retained `build-history`
  dependency, including its count, source/subject identities, retention and
  conflict policy, and unsupported forward/rollback transform dispositions.

The public `mcloving.jenkins.migration-package/v1` baseline has zero packaged cases. The admitted compiler case is
`deterministically_rejected_state_transfer_incomplete` with
`E_STATE_TRANSFER_EVIDENCE_UNAVAILABLE`; the other 227 are
`deterministically_rejected` with `E_SOURCE_NOT_ADMITTED`. The package does
not reinterpret the historical parser/model reach denominator. Each row keeps
the source index's `source_certified_equivalence=false` truth separate from
the later `mig006_certified_equivalence` result; only the admitted case has the
latter set to true.

## Canonical verification

Generation is deterministic: serializing the same protected repository inputs
produces byte-identical pretty JSON with one trailing newline. Verification
first requires those exact canonical bytes and the compiled package SHA-256.
It then:

1. compares every identity, state-transfer disposition, and all-false authority
   field with its compiled reviewed value;
2. hashes every embedded artifact;
3. passes the embedded source and worker response to
   `mcloving-jenkins-compiler-admission`, which reparses strict YAML and
   canonical IR and returns the exact disabled admission receipt;
4. passes the embedded mapping catalog to the canonical mapping validator;
5. passes the embedded DIFF-002 JSON to the canonical state-policy verifier;
6. invokes the canonical MIG-006 verifier over the sealed repository evidence;
   and
7. authenticates and parses the sealed eligibility and persistent-state
   inventories, requiring the exact one-record `build-history` dependency and
   its unsupported forward/rollback classifications; and
8. independently rebuilds the ordered disposition ledger from the embedded
   corpus index and requires zero packaged plus 228 rejected cases.

There is no alternative compiler, mapping, differential, or state-transform
logic in the package verifier.

## State and credential truth

The source text is simple, but the job is stateful. The sealed inventory records
one retained build under `build-history`, an indefinite retention deadline,
and unsupported forward and rollback transforms. The package therefore requires
`status=incomplete_state_transfer_unsupported`,
`blocking_error=E_STATE_TRANSFER_EVIDENCE_UNAVAILABLE`, one authenticated state
dependency, `case_specific_rehearsal_receipts=[]`, `packaged_artifacts=[]`,
`cutover_eligible=false`, and `rollback_eligible=false`. It does not retain
digest-only pointers to unavailable synthetic MIG-005A objects. The exact raw
build tree is retained privately on HeMan and its exporter-compatible digest
reproduces the inventory value
`b47cc3e1c19e1d486a2df2fc76343e3031ee370a79564fe88a471adbf6e53107`.
The private tree passed the pinned networkless Gitleaks scan with zero findings
and is retained owner-read-only under an internal source-seal receipt kept only
on HeMan; no source bytes or private seal metadata enter the repository.
MIG-005A supplies bounded forward and reverse objects, independently retrieved
PostgreSQL destination truth, and pinned case-specific Jenkins
reverse-continuity evidence. Those private objects cannot enter GitHub. The
`mcloving.jenkins.migration-package/private-v1` extension therefore embeds the
canonical public baseline plus the complete owner-manifest-pinned forward and
reverse archives in one owner-only canonical JSON envelope retained on HeMan.
It reconstructs both transforms only after their implementation identities
match separately supplied owner-private pins, then cross-checks those identities and configuration against the
independent rehearsal summary and Jenkins binding receipts, authenticates the
sealed five-file source tree, and verifies ordered logs, results, restart, and
next-build continuity. Its verified denominator is one packaged case and 227
deterministic rejections. It is package-complete and deny-authority
shadow-eligible, but not canary-, cutover-, rollback-, or production-authority
eligible.

The envelope has no field capable of carrying credential material. Its
free-form embedded artifacts are accepted only at their exact previously
secret-scanned digests and through their canonical validators. Every authority
bit is false and the source operational state is disabled.

## Seal and portability

The canonical public package SHA-256 is
`304f75f7c85f11b4fb15ce11f5cf65e5dc69168e3ef85b03a9b3eabdbb3d4ed9`.
The package and seal are marked non-translatable in `.gitattributes`.
Linux and hosted Windows compile, lint, and execute the verifier. The CLI opens
the supplied package once with platform no-follow semantics, validates a
bounded regular-file handle, reads at most 1 MiB, and then verifies only the
captured bytes.
On Unix, output publication opens the plain parent directory once without
following a final symlink and holds that directory handle through the entire
transaction. It creates and syncs an owner-private temporary sibling, creates
the destination through an atomic no-clobber hard link, syncs the held parent,
and cleans up or rolls back only through descriptor-relative operations on that
same directory. Renaming or replacing the original parent path cannot redirect
publication, durability, rollback, or temporary-file cleanup. If the
publication sync fails, rollback must both remove the destination and make that
removal durable. A failed removal or rollback sync returns
`E_PUBLICATION_ROLLBACK_AMBIGUOUS`; the destination is treated as poisoned and
requires explicit verification and reconciliation. An already-present
destination is never replaced and likewise requires verification before retry.
File publication is explicitly unsupported on Windows because the current CLI
cannot provide the same descriptor-relative durability boundary there; Windows
operators must generate to standard output and use an independently reviewed
atomic publisher. Verification remains supported on both platforms.

The public baseline alone is not an admissible input to `SHADOW-001`. The
owner-private extension is the admissible package only when its separately
retained owner package pin, both evidence-manifest pins, both transform-implementation
pins, sealed source tree, exact
reviewed repository heads, and complete verifier all agree. The CLI never
prints its digest and publishes it as a new owner-only file with mode `0600`.
Every owner-private input and immediate parent must belong to the invoking
effective user and deny group/other access; every ancestor is a plain,
non-symlink directory that either denies group/other writes or is the standard
root-owned sticky temporary boundary. Private publication additionally requires confirmed staging-link removal and a
second held-parent directory sync; either cleanup failure is reported for
explicit verification and reconciliation. The private verifier rejects
group/other access on every traversed sealed-source directory and member, and
joins the retained Jenkins build, import receipt, and native-provenance
sidecars exactly to the authenticated reverse bundle and all-false authority
ledger. The completed build's ordered normalized log entries are joined by
digest, byte length, retrieval digest, and media type to both captured stream
chunks and their exact aggregate. Restart continuity includes the original build-1 result and log, the
retained build-2/build-3 XML identities/results/timings joined to their API
receipts, the retained build cursor and complete permalink set after continued build 3, and
both ceremonies' exclusive container attachment to their captured internal
Podman networks.
The verified private package is 704,617 bytes and remains solely under
`/sn8100/runs/mcloving/mig005a-corpus052-corrective-20260816T034309Z/`.
Neither package grants production, credential, trigger, scheduler, effect,
canary, cutover, rollback, or decommission authority.
