# Migration package v1

Status: `MIG-007` incomplete implementation; `MIG-005A` corrective work required

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

There are zero packaged cases. The admitted compiler case is
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
on HeMan; no source bytes or private seal metadata enter the repository. It is
not yet transformed, rehearsed, or admitted as a complete package input.
Completion requires bounded certified forward and reverse objects, destination
state, and a case-specific rehearsal whose bytes are embedded or immutably
retrieved and verified.

The envelope has no field capable of carrying credential material. Its
free-form embedded artifacts are accepted only at their exact previously
secret-scanned digests and through their canonical validators. Every authority
bit is false and the source operational state is disabled.

## Seal and portability

The canonical package SHA-256 is
`304f75f7c85f11b4fb15ce11f5cf65e5dc69168e3ef85b03a9b3eabdbb3d4ed9`.
The package and seal are marked non-translatable in `.gitattributes`.
Linux and hosted Windows compile, lint, and execute the verifier. The CLI opens
the supplied package once with platform no-follow semantics, validates a
bounded regular-file handle, reads at most 1 MiB, and then verifies only the
captured bytes.

This incomplete package is not an admissible input to `SHADOW-001`. It does
not make the job shadow- or canary-eligible and grants no production, credential,
trigger, scheduler, effect, cutover, rollback, or decommission authority.
