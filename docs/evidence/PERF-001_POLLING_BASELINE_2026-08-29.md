# PERF-001 polling-observation baseline identity — filed 2026-08-29

The externally filed 2026-08-29 observation ("replace the fixed-interval
polling regime with event-driven waits") measured commit `83a6d6c`, which is
not an ancestor of protected main: it is two migration-packaging commits on
top of protected-main `6ac9be99bd3c3241de1e3d14a324b0eea02b3b73` (MIG-006's
closure commit) and was never merged. This carrier preserves the baseline's
full source identity so the observation's closure rationale on
`docs/EXECUTION_BOARD.md` stays auditable independent of the external filing.
Git commits are content-addressed, so the raw commit objects below fully
determine — and let anyone holding the objects verify — the recorded ids.

## Identity

| Item | Identity |
|---|---|
| Filed baseline commit | `83a6d6c6f843cf7acd3b05902ecb98b22688674f` |
| Filed baseline tree | `fa88a0530189fbf7d40d9a407e49e673c73322fa` |
| Intermediate commit | `52a879c73db31b711efff0dccf18701031ee4433` |
| Protected-main ancestor | `6ac9be99bd3c3241de1e3d14a324b0eea02b3b73` (reachable from `main`) |

## Raw commit objects

`git cat-file commit 52a879c73db31b711efff0dccf18701031ee4433`:

```
tree 40b7406fb26009db0a58027fde42efd77f498ca2
parent 6ac9be99bd3c3241de1e3d14a324b0eea02b3b73
author Srikanth Remani <srikanth.remani@gmail.com> 1786843988 -0500
committer Srikanth Remani <srikanth.remani@gmail.com> 1786843988 -0500

feat(migration): seal MIG-007 review package
```

`git cat-file commit 83a6d6c6f843cf7acd3b05902ecb98b22688674f`:

```
tree fa88a0530189fbf7d40d9a407e49e673c73322fa
parent 52a879c73db31b711efff0dccf18701031ee4433
author Srikanth Remani <srikanth.remani@gmail.com> 1786844561 -0500
committer Srikanth Remani <srikanth.remani@gmail.com> 1786844614 -0500

fix(mig-007): preserve evidence semantics
```

## Divergence from the protected-main ancestor

`git diff --stat 6ac9be9..83a6d6c` — migration-package sealing only; no
scheduler, agent, controller, or store source differs from `6ac9be9`:

```
 .gitattributes                                     |    1 +
 .github/workflows/windows-agent.yml                |    9 +
 Cargo.lock                                         |   14 +
 Cargo.toml                                         |    1 +
 crates/migration-package/Cargo.toml                |   19 +
 crates/migration-package/src/lib.rs                |  712 +++++++
 crates/migration-package/src/main.rs               |   88 +
 docs/architecture/MIGRATION_PACKAGE_V1.md          |   94 +
 docs/threat-model/README.md                        |    1 +
 migration/migration-package-v1/README.md           |   29 +
 migration/migration-package-v1/SHA256SUMS          |    1 +
 .../migration-package-v1/migration-package.json    | 2126 ++++++++++++++++++++
 scripts/test-windows-agent-impact.py               |   55 +-
 scripts/windows-agent-impact.py                    |   28 +-
 14 files changed, 3160 insertions(+), 18 deletions(-)
```

## Reconstruction and verification

`PERF-001_POLLING_BASELINE_2026-08-29.patch` (same directory) is the
binary-safe, full-index content delta `6ac9be9..83a6d6c`. From any clone of
this repository the baseline tree is reproducible and every recorded id
verifiable with no external source:

```
git worktree add --detach /tmp/baseline 6ac9be99bd3c3241de1e3d14a324b0eea02b3b73
cd /tmp/baseline
git apply --binary <repo>/docs/evidence/PERF-001_POLLING_BASELINE_2026-08-29.patch
git add -A && git write-tree
# prints fa88a0530189fbf7d40d9a407e49e673c73322fa — the filed baseline tree
```

Each raw commit object above, piped through
`git hash-object -t commit --stdin`, reproduces its recorded commit id
(`52a879c…` references the intermediate tree `40b7406…`, which the same
patch minus its final commit's hunks would produce; the closure's claims
rest only on the end-state tree verified above). This chain — reachable
ancestor, in-repo content delta, reconstructed tree hash, content-addressed
commit payloads — was executed and verified before this document was
committed.

## Which measurements attach to which identity

- Attached to this baseline (`83a6d6c`, equivalently `6ac9be9` for every
  runtime crate, per the divergence above): the filing's 217.4 ms/stage
  baseline, its 174.5 ms/stage poll-1ms cell, and the 41 ms/stage poll
  sensitivity those imply (Mario, delta method, both polls at the stated
  values).
- Attached to protected-main-reachable identities, not this baseline: the
  496.4 ms/stage shipped-default measurement is recorded in `b1301e9`'s
  commit message against its parent `bed6c0f`; the closing receipts are the
  `e57f7c9` evidence in `docs/evidence/PERF-001_EVENT_WAIT_QA_2026-08-31.md`.
