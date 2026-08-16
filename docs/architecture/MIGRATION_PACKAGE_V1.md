# Migration package v1

Status: `MIG-007` implementation

## Purpose and boundary

`mcloving.jenkins.migration-package/v1` is a deterministic, reviewable,
deny-authority envelope over the exact artifacts needed to reproduce the sole
currently certified migration case. It does not compile new Jenkins source,
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
- the MIG-005A transform binary, source/evidence/reverse manifests, forward
  and reverse bundles, and four accepted repair/import/protection/retry receipt
  digests.

Exactly one disposition is `packaged_disabled_certified`. The other 227 are
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

1. compares every identity, state-transfer binding, and all-false authority
   field with its compiled reviewed value;
2. hashes every embedded artifact;
3. passes the embedded source and worker response to
   `mcloving-jenkins-compiler-admission`, which reparses strict YAML and
   canonical IR and returns the exact disabled admission receipt;
4. passes the embedded mapping catalog to the canonical mapping validator;
5. passes the embedded DIFF-002 JSON to the canonical state-policy verifier;
6. invokes the canonical MIG-006 verifier over the sealed repository evidence;
   and
7. independently rebuilds the ordered disposition ledger from the embedded
   corpus index and requires 1 admitted plus 227 rejected cases.

There is no alternative compiler, mapping, differential, or state-transform
logic in the package verifier.

## State and credential truth

The admitted source is a single literal shell step with no persistent
cross-build state dependency. Therefore
`admitted_state_dependencies=[]` and
`case_specific_rehearsal_receipts=[]` are exact, non-vacuous denominator
statements tied to that reviewed source. MIG-005A's synthetic seeded-history
receipt proves transform capability but is not presented as a case-specific
production rehearsal.

The envelope has no field capable of carrying credential material. Its
free-form embedded artifacts are accepted only at their exact previously
secret-scanned digests and through their canonical validators. Every authority
bit is false and the source operational state is disabled.

## Seal and portability

The canonical package SHA-256 is
`9f68159216d385bf9b14deb3bb3957bdb7e79e1ed77ca374786da5676c07b13c`.
The package and seal are marked non-translatable in `.gitattributes`.
Linux and hosted Windows compile, lint, and execute the verifier. The CLI opens
the supplied package once with platform no-follow semantics, validates a
bounded regular-file handle, reads at most 1 MiB, and then verifies only the
captured bytes.

This package is an input to later effect-free `SHADOW-001` qualification. It
does not make the job canary-eligible and grants no production, credential,
trigger, scheduler, effect, cutover, rollback, or decommission authority.
