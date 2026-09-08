# CI-004 security review

## Status and exact scope

CI-004 implementation acceptance is complete at exact corrected head
`3880043226f54b35984defc0d09957e5ff1d26ac`. Independent source/accounting review
found no actionable findings, and the full corrected-head Foundation and
classified Windows gates passed. CI-004 nevertheless remains ACTIVE: final-head
checks, protected merge, and post-merge verification remain pending. There is
no closure-attribution entry or closed-ticket membership for CI-004. Passing
implementation tests does not satisfy its downstream dependency before the
stated closure gates complete.

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
matrix covers the unchanged smoke-script content only. Corrected head
`3880043226f54b35984defc0d09957e5ff1d26ac` subsequently passed Foundation run
`34289733746` and Windows run `34289733750`. Deployment job `102273373588`
passed the entire smoke matrix, controlled-systemd install/upgrade/rollback,
exact controller-identity check, and both deployable-runtime tests (2 passed,
0 failed, 0 ignored). Windows classification and its aggregate passed; the
native Windows job was explicitly skipped by the unchanged classifier, so
this is no claim of a new native-Windows execution campaign. The timing
record distinguishes observed full-workflow duration from causal speed claims.
No merged closure or production capability is claimed.

## Threat review scope and residuals

- TM-050: fixture preparation still seals checksums after the final byte
  transformation. Every install, substitution, upgrade, rollback, containment,
  and manager check retains its existing acceptance conditions. The systemd
  exact deployed/controller identity check is unchanged. SEC-005 depends on
  CI-004 because both own the deployment smoke script.
- TM-052: all workflow jobs, tests, required context names, aggregate needs,
  literal-success behavior, and protected-main requirements remain unchanged.
  The corrected source and initial accounting passed independent review.
  The final source still needs its own independent review and all exact-head
  checks before merge, followed by protected-main verification before closure.
- TM-016 and TM-023: the host-provided GNU `strip` utility becomes an explicit
  smoke-harness prerequisite. Its bytes/version are not newly pinned by this
  change. Trust in the CI runner's binutils installation is an explicit
  residual: a compromised tool could alter executable code before checksums
  are generated. This is a test-fixture trust assumption, not an assertion
  that checksums authenticate the transformer. CI maintainers own this
  residual, reviewed on 2026-09-08; no production release-builder toolchain
  change follows.
- TM-042: production release artifacts, signing, provenance, and deployment
  authority are unchanged. Nothing in this ticket signs or releases a fixture.

Disposable smoke binaries omit source-line debug sections; their original
build outputs retain those sections for diagnosis. Code, debug assertions,
symbol names, and unwind information remain present. The failed precursor is
retained as evidence that those semantic checks do not replace exact binary
identity where the deployment contract requires it.

## Final metadata and merge obligations

Independent review of corrected head 3880043 covered the smoke-only scope,
unchanged exact systemd identity, source pins, the CI-004/SEC-005 graph edge,
and host-strip residual. All 49 board tests, 78 closure tests, and 11 aggregate
tests passed locally. The final metadata successor must independently pass its
own review and protected checks before merge, with protected-main verification
afterward. Implementation script and workflow content remain bound by the
hashes above; a metadata update cannot silently replace that tested source.

The row floor remains 113. CI-004 stays ACTIVE and enters neither CLOSED_TICKETS
nor the threat closure-attribution table until its protected merge and
post-merge verification complete. The review finding against precursor
`261858401e849f8f3b13892bf72b4c063701bdda` correctly identified that premature
DONE status would satisfy downstream dependencies despite missing those gates;
that candidate attribution and membership are removed. No previously merged
closed-ticket membership is removed. Historical debt remains 37, and the
selected JCOMP-001 milestone and dispatch remain unchanged.
