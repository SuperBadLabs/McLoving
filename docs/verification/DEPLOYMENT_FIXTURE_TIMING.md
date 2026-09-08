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

After copying each built executable into the disposable smoke or systemd
release fixture, run `strip --strip-debug` before generating checksums.
Every installation, digest read, upgrade, rollback, and refusal assertion
still runs against the entire sealed fixture. There are no cached digest
verdicts, skipped suites, new conditionals, or changed aggregate dependencies.

The original `target/debug` outputs, compilation profile, debug assertions,
release builder, and published release policy remain unchanged. The fixture
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
time on this host; the hosted full-gate reduction remains to be measured.
Filesystem, CPU, runner, and fixed verification costs prevent extrapolating
an 81% payload-size reduction into an 81% end-to-end speedup.

Focused checks also passed: the stripped CLI executes, stale checksums reject
a modified binary without changing the current release, a newly sealed
upgrade changes the current release, and rollback restores its predecessor.
Workflow aggregate tests (11), actionlint, shell syntax, and whitespace checks
passed. Full smoke and controlled-systemd coverage remains required on the
candidate PR; these local checks do not substitute for either hosted lane.
