# CI-004 security review

## Status and exact scope

CI-004's implementation, protected-merge, and post-merge verification gates
are complete. [PR #125](https://github.com/SuperBadLabs/McLoving/pull/125)
squash-merged exact reviewed head
`7ff7d726632cb1f0ee128b78a5cb92ec5432839a` as protected-main commit
`1d81127c7913a92a43402e377eb62289897356e0` at 2026-09-09 00:02:38 UTC.
Exact merged-main Foundation run `34293282546` and native Windows run
`34293282632` both passed. This record now supports ticket closure; the earlier
implementation-only results did not satisfy these later gates.

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
Those corrected-head results preceded protected merge and therefore did not
alone establish closure. The subsequent merge evidence is recorded below; no
production capability is claimed.

## Threat review scope and residuals

- TM-050: fixture preparation still seals checksums after the final byte
  transformation. Every install, substitution, upgrade, rollback, containment,
  and manager check retains its existing acceptance conditions. The systemd
  exact deployed/controller identity check is unchanged. SEC-005 depends on
  CI-004 because both own the deployment smoke script.
- TM-052: all workflow jobs, tests, required context names, aggregate needs,
  literal-success behavior, and protected-main requirements remain unchanged.
  The corrected source and initial accounting passed independent review.
  Final head 7ff7d72 passed independent review and all eight exact-head,
  GitHub-Actions-bound required contexts before guarded merge. Exact merged-main
  Foundation and actual native Windows execution subsequently passed.
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

## Final review correction and protected merge

Independent review covered the smoke-only scope, unchanged exact systemd
identity, source pins, CI-004/SEC-005 graph edge, and host-strip residual.
All 49 board tests, 78 closure tests, and 11 aggregate tests passed locally.

The Codex P2 finding
[3963247779](https://github.com/SuperBadLabs/McLoving/pull/125#discussion_r3963247779)
against `261858401e849f8f3b13892bf72b4c063701bdda` correctly identified premature
DONE status: it would have satisfied downstream dependencies while protected
merge and post-merge verification were still pending. Correction
`7ff7d726632cb1f0ee128b78a5cb92ec5432839a` restored ACTIVE and removed candidate
closed-ticket membership and attribution. No previously merged closed-ticket
membership was removed. The addressed thread was resolved, and independent
review of exact 7ff7d72 found no actionable findings. The prior Copilot review
recommended approval with zero generated comments; its GitHub review state was
COMMENTED, not a formal approval.

Final-head Foundation run `34292013621` and classified Windows run
`34292013546` passed. Immediately before merge, a fresh readback verified:

- the exact eight required contexts, all successful at 7ff7d72 and bound to
  GitHub Actions application 15368;
- strict synchronization, admin enforcement, conversation resolution, linear
  history, and disabled force-push/deletion permissions;
- an OPEN, non-draft, CLEAN/MERGEABLE PR at that exact head and a clean matching
  worktree; and
- completed automated reviews and all paginated review threads resolved.

The eight contexts were Rust, Dependencies and licenses, Secret scan,
Architecture records, Formal model, Controller PostgreSQL, Foundation, and
Windows. Squash merge used `--match-head-commit` with exact 7ff7d72 and no admin
bypass. GitHub verified merged commit 1d81127 with reason `valid`; its tree
`6bf77499d5fe1667aba74b0e7e951ce400f87f21` exactly matches the tested head.

## Exact protected-main verification

[Foundation run 34293282546](https://github.com/SuperBadLabs/McLoving/actions/runs/34293282546)
passed exact merged commit
`1d81127c7913a92a43402e377eb62289897356e0`. Deployment job `102284301764` passed
the full smoke matrix and controlled-systemd gate. The Foundation aggregate
completed at 2026-09-09 00:22:19 UTC.

[Windows run 34293282632](https://github.com/SuperBadLabs/McLoving/actions/runs/34293282632)
passed the same exact merged commit. Unlike the PR's classified skip, native
Windows agent job `102284330767` actually executed and succeeded in 4m56s,
including Windows runtime, differential, migration/state-transfer, and both
debug and release native-service/crash-recovery gates. Its Windows aggregate
completed at 00:07:56 UTC.

The implementation content remains bound by the hashes above. The protected
merge and these post-merge successes now provide the previously missing
closure evidence; closing CI-004 no longer depends on unexecuted gates.
Historical debt remains 37, and this ticket grants no production authority.
Observed Foundation timing varied from 15m32s on corrected PR head 3880043 to
19m39s on merged main. The detailed timing record preserves that variation;
a guaranteed 32% speedup is not established.
