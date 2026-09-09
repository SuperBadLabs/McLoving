# Deployment fixture size and merge-gate timing

Measured on 2026-09-08. This is a CI-fixture optimization, not a release or
Jenkins compatibility claim.

## Hosted baseline

[Foundation run 34134300027](https://github.com/SuperBadLabs/McLoving/actions/runs/34134300027)
completed successfully at PR head `e5fc14c67d0f81baaa41d160ed0faba8fbee9d8c`.
The deployment job ran for 20m40s; every other substantive job finished within
4m39s. Its Rust cache restored approximately 501 MB in seven seconds.
The smoke step took 15m51s, including only 25.11s of compilation. Phase 9
(install/upgrade/rollback and refusal cases) occupied approximately 14m22s.
The subsequent controlled-systemd step took 3m01s. These timestamps identify
deployment verification, rather than Rust compilation, as the critical path.

## Change

After copying each built executable into the disposable smoke
release fixture, run `strip --strip-debug` before generating checksums.
Every installation, digest read, upgrade, rollback, and refusal assertion
still runs against the entire sealed fixture. There are no cached digest
verdicts, skipped suites, new conditionals, or changed aggregate dependencies.

The original `target/debug` outputs, compilation profile, debug assertions,
systemd fixture, release builder, and published release policy remain unchanged. The fixture
retains executable code, allocated data, symbol names, and unwind sections.
Source-line debug information is absent from the disposable copy; the build
outputs retain it for diagnosis.

## Local evidence

HeMan measurements used existing build outputs copied into a fresh temporary
fixture. GNU `strip --strip-debug` reduced the four-binary payload:

| Binary | Original bytes | Fixture bytes |
|---|---:|---:|
| Controller | 277,016,352 | 60,162,472 |
| Agent | 112,871,928 | 26,044,520 |
| CLI | 178,426,960 | 24,130,216 |
| Identity admin | 77,233,488 | 10,338,120 |
| Total | 645,548,728 | 120,675,328 |

A read-only ELF parser compared every `SHF_ALLOC` section: all 31 sections of
each binary retained identical type, flags, virtual address, size, and bytes
(including unwind information). `nm --defined-only` output also matched.
The original fixture copies remained SHA-256-identical to `target/debug`.

An interleaved original/stripped/stripped/original benchmark ran the real
`mcloving-install --no-systemd` and three `mcloving-deployed-digests` reads per
installation in distinct temporary homes, with normal host ownership checks.

| Operation | Original | Stripped |
|---|---|---|
| Install, seconds | 1.634, 1.623 | 1.121, 1.140 |
| Digest-read median per installation, seconds | 1.868, 1.869 | 1.649, 1.679 |

This is approximately 31% less installation time and 11% less digest-read
time on this host; the later hosted observations are recorded below.
Filesystem, CPU, runner, and fixed verification costs prevent extrapolating
an 81% payload-size reduction into an 81% end-to-end speedup.

Focused checks also passed: the stripped CLI executes, stale checksums reject
a modified binary without changing the current release, a newly sealed
upgrade changes the current release, and rollback restores its predecessor.
Workflow aggregate tests (11), actionlint, shell syntax, and whitespace checks
passed. These local checks did not substitute for either hosted lane; the
corrected-head full hosted validation is recorded below.

## Hosted precursor and correction

[PR #125 precursor run 34287782278](https://github.com/SuperBadLabs/McLoving/actions/runs/34287782278)
tested exact head `4e93d5d35caa5d827d18cd49803bc73ecdbcdb7d`. Its complete
smoke matrix passed in 13m58s (22:50:28–23:04:26 UTC on September 8).
The adjacent [PR #124 run 34286787846](https://github.com/SuperBadLabs/McLoving/actions/runs/34286787846),
head `3e7255d8b1150152bd9ecc331a01d6bdf3d4a321`, passed the unchanged smoke
matrix in 16m23s (22:39:32–22:55:55 UTC): the observed smoke reduction was
2m25s, or 14.8%. Against the older 15m51s baseline, it was 1m53s, or 11.9%.
These are individual hosted observations, not a statistically controlled claim.

The precursor workflow FAILED. Its controlled-systemd final runtime gate
correctly refused the stripped installed controller because it was not
byte-identical to the unstripped controller beside the prebuilt runtime test.
The service-managed install, upgrade, and rollback had run, but they did not
complete the required final runtime gate. No full-workflow speedup or successful
systemd qualification follows from this run.

The correction removes the precursor's workflow edit entirely. Only the smoke
fixture copies are stripped; systemd copies and its exact byte-identity oracle
remain unchanged. The smoke script content is identical to the precursor's
passed matrix. At this correction point, full corrected-head hosted validation was
still pending and CI-004 remained ACTIVE. The subsequent evidence follows.

## Corrected-head full hosted validation

[Foundation run 34289733746](https://github.com/SuperBadLabs/McLoving/actions/runs/34289733746)
and [Windows run 34289733750](https://github.com/SuperBadLabs/McLoving/actions/runs/34289733750)
both passed exact corrected head
`3880043226f54b35984defc0d09957e5ff1d26ac`. Windows classification and aggregate
passed with the native job explicitly skipped under the unchanged classifier.
Deployment job `102273373588` ran the complete smoke and controlled-systemd
lanes; its final exact-identity check and both runtime tests passed (2 passed,
0 failed, 0 ignored).

| Observed hosted duration | Adjacent PR #124 baseline | Corrected PR #125 |
|---|---|---|
| Smoke step | 16m23s | 10m59s |
| Controlled-systemd step (unchanged) | 3m06s | 2m30s |
| Complete deployment job | 22m02s | 15m17s |
| Foundation run start to aggregate completion | 22m48s | 15m32s |

Corrected smoke timestamps are 23:16:06–23:27:05 UTC; systemd is
23:27:22–23:29:52; the job is 23:14:37–23:29:54; and Foundation is
23:14:33–23:30:05, all on September 8. Baseline Foundation starts
22:36:46 and its aggregate completes 22:59:34. The observed full-workflow
reduction is 7m16s (31.9%); the smoke reduction is 5m24s (33.0%).

This is an observed before/after comparison, not a guaranteed or isolated
causal estimate. Even the unchanged systemd step became faster, and the two
identical stripped smoke runs varied from 13m58s to 10m59s. Runner load,
setup/queue time, and filesystem effects contribute. No systemd optimization
or production-performance improvement is claimed.

Those corrected-head implementation results did not by themselves earn
closed-ticket attribution or satisfy downstream dependencies. The final
review correction kept CI-004 ACTIVE until protected merge and exact
post-merge verification. That completed sequence is recorded next.

## Final head and verified protected-main closure

[PR #125](https://github.com/SuperBadLabs/McLoving/pull/125) merged exact final
head `7ff7d726632cb1f0ee128b78a5cb92ec5432839a` as protected-main commit
`1d81127c7913a92a43402e377eb62289897356e0` at 2026-09-09 00:02:38 UTC.
The final head corrected the premature DONE status identified in review;
CI-004 remained ACTIVE during merge and while post-merge gates ran.

Final-head [Foundation run 34292013621](https://github.com/SuperBadLabs/McLoving/actions/runs/34292013621)
and [classified Windows run 34292013546](https://github.com/SuperBadLabs/McLoving/actions/runs/34292013546)
passed before the guarded, exact-head squash merge. Fresh protection and
paginated review checks are described in `docs/evidence/CI-004_SECURITY_REVIEW.md`.
The smoke-script and Foundation-workflow bytes match the successful
corrected-head tests.

On exact merged commit 1d81127,
[Foundation run 34293282546](https://github.com/SuperBadLabs/McLoving/actions/runs/34293282546)
and [native Windows run 34293282632](https://github.com/SuperBadLabs/McLoving/actions/runs/34293282632)
both passed. Native Windows agent job `102284330767` actually executed for
4m56s, including debug and release service/crash-recovery gates; it was not a
classified skip. The deployment smoke and controlled-systemd gates both passed
in Foundation job `102284301764`.

| Observed hosted duration | Corrected candidate 3880043 | Final PR head 7ff7d72 | Merged main 1d81127 |
|---|---|---|---|
| Smoke step | 10m59s | 10m05s | 15m02s |
| Controlled-systemd step (unchanged) | 2m30s | 2m25s | 3m15s |
| Complete deployment job | 15m17s | 15m07s | 19m26s |
| Foundation run start to aggregate completion | 15m32s | 15m45s | 19m39s |

For final PR head 7ff7d72, smoke ran September 8 23:47:42–23:57:47 UTC,
systemd 23:58:03–September 9 00:00:28, and the deployment job
23:45:24–00:00:31. Foundation started 23:44:55 and its aggregate completed
00:00:40. For merged main on September 9, smoke ran 00:03:29–00:18:31,
systemd 00:18:52–00:22:07, deployment 00:02:44–00:22:10, and Foundation
00:02:40–00:22:19.

The protected-main observation is 19m39s, not the corrected candidate's
15m32s. Against the adjacent 22m48s baseline, that is an observed 3m09s
(13.8%) shorter workflow, while the final PR observation was faster again.
The unchanged systemd step also varied. These runs demonstrate successful
validation and substantial variability; they do not establish a guaranteed
32% improvement, a systemd optimization, or production performance gains.

Protected merge and exact-main Foundation/native-Windows success now provide
CI-004's previously outstanding closure evidence. Later bookkeeping commits
must still pass their own review and checks; these receipts identify the
already merged and verified implementation rather than asserting success for
an unknown future head.
