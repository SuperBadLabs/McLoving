# CI-004 security review working record

## Status and exact scope

CI-004 remains ACTIVE. This record is not closure evidence: corrected-head
hosted validation and independent final review are still pending. There is no
closure-attribution entry or CLOSED_TICKETS entry for CI-004.

The retained implementation strips only debug sections from disposable smoke
fixture copies before their checksum manifest is sealed. The smoke script is
byte-identical to the precursor implementation reviewed at
`4e93d5d35caa5d827d18cd49803bc73ecdbcdb7d`; its SHA-256 is
`5ef0303d1f167ad1da38aca543cfd6946c97c4dd58160cdb9a4e469663fde8a1`.
The precursor's systemd workflow stripping is removed. The corrected Foundation
workflow is identical to protected main `f3aeb03` and has SHA-256
`c17ae6a6bbc9244bc6bcf6309ef6828ca0710d6751e9f9b973b8267818f94a32`.
These content pins bind the implementation without pretending a later metadata
commit has already passed its own protected checks.

## Evidence and rejected precursor

The local and hosted measurements, references, and limitations are recorded in
`docs/verification/DEPLOYMENT_FIXTURE_TIMING.md`. Local review compared all 31
allocated ELF sections per binary and defined symbols; contents matched after
stripping, and original build outputs remained byte-identical. Actual isolated
installation, digest verification, stripped CLI execution, stale-checksum
refusal, verified upgrade, and rollback checks passed. All assertions and
full-byte checksum reads remain present.

Precursor Foundation run 34287782278 passed the full smoke matrix in 13m58s,
but FAILED the controlled-systemd final runtime gate: its installed stripped
controller differed from the unstripped controller the test would spawn. The
identity gate correctly refused; the correction preserves the original systemd
fixture and equality gate without weakening either. The passed precursor smoke
matrix covers the unchanged smoke-script content only. Full corrected-head
Foundation and Windows checks remain mandatory; no full-gate improvement,
merged closure, or production capability is claimed.

## Threat review scope and residuals

- TM-050: fixture preparation still seals checksums after the final byte
  transformation. Every install, substitution, upgrade, rollback, containment,
  and manager check retains its existing acceptance conditions. The systemd
  exact deployed/controller identity check is unchanged. SEC-005 depends on
  CI-004 because both own the deployment smoke script.
- TM-052: all workflow jobs, tests, required context names, aggregate needs,
  literal-success behavior, and protected-main requirements remain unchanged.
  The final source and its bookkeeping still need independent review and all
  exact-head checks before merge.
- TM-016 and TM-023: the host-provided GNU `strip` utility becomes an explicit
  smoke-harness prerequisite. Its bytes/version are not newly pinned by this
  change. Trust in the CI runner's binutils installation is an explicit
  residual: a compromised tool could alter executable code before checksums
  are generated. This is a test-fixture trust assumption, not an assertion
  that checksums authenticate the transformer. Review owns this residual; no
  production release-builder toolchain change follows.
- TM-042: production release artifacts, signing, provenance, and deployment
  authority are unchanged. Nothing in this ticket signs or releases a fixture.

Disposable smoke binaries omit source-line debug sections; their original
build outputs retain those sections for diagnosis. Code, debug assertions,
symbol names, and unwind information remain present. The failed precursor is
retained as evidence that those semantic checks do not replace exact binary
identity where the deployment contract requires it.

## Remaining closure obligations

Independent review must approve the corrected scope and these residuals, the
CI-004/SEC-005 graph edge, the 113-row floor, and the absence of premature
closure attribution. Corrected source must pass all hosted gates. Only then
may CI-004 become DONE with an affirmative threat-model attribution and the
closed-ticket membership ratchet advanced. The selected JCOMP-001 milestone
and its dispatch are unchanged.
