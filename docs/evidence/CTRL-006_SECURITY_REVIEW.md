# CTRL-006 sequential artifact refusal: candidate evidence

This is a candidate implementation and review record, not a closure receipt.
Independent review, protected merge, and exact-main Foundation and native
Windows verification remain required. `CTRL-006` remains unclosed.

## Acceptance and scope

The sequential planner lowers each literal shell step to a separate host
process node. It has no stage-level artifact collection and must refuse a
stage with artifact declarations, naming that stage, rather than return a
successful plan with those declarations omitted. This preserves the meaning
of the saved pipeline semantic digest.

The issue was filed during the PAR-014 review. Its receipt records that the
Jenkins compiler emits no artifact declarations, so this is a latent planner
gap rather than evidence of an affected submitted build. This change does not
add sequential artifact collection or broaden Jenkinsfile admission.

## Verification design

The regression cases in
`crates/controller-api/tests/sequential_planner.rs` call the exported
production planner with valid strict-YAML-compiled and independently
validated IR v1.8. They exercise declarations in the first and later stage,
including a later stage that declares both an image and artifacts,
check that the error is `InvalidDag`, and require an artifact diagnostic
naming the offending stage. The first-stage and later-stage cases first
verify their artifact-free counterpart still plans every step and retains the
semantic digest; a blanket planner refusal cannot satisfy those tests.

The native test-only baseline command
`cargo test --locked -p mcloving-controller-api --test sequential_planner artifact_stage -- --nocapture`
returned exit 101 in 10.17 seconds. Both new tests failed at `unwrap_err`
because the exported planner returned `Ok(SequentialDagBuild)` with the valid
declarations omitted; seven existing tests were filtered. This demonstrates
the intended defect rather than a compiler/IR validation refusal.

The initial corrected source passed the full nine-test sequential planner
target in 1.10 seconds (exit 0). Independent inspection then found that the
generic container refusal took precedence for a stage with both an image and
artifacts, omitting the artifact-stage name. The candidate moves the artifact
guard before the container refusal and adds a valid compiled-IR regression
for that combined shape; container-only refusal remains covered.

The corrected candidate refuses any nonempty declaration list before
lowering that stage's steps and names the stage ID in the diagnostic. Native
execution of
`cargo test --locked -p mcloving-controller-api --test sequential_planner -- --nocapture`
passed all ten tests in 1.26 seconds, including the combined-shape regression
and the existing container-only refusal.

Native execution of the exact guard-removal mutation returned exit 101 in
1.13 seconds: all three artifact-stage regressions failed. The first/later
cases again received successful plans with declarations dropped; the combined
case received the generic container error without an artifact-stage name.
The mutation runner restored the candidate source in `finally` and verified
byte-identical SHA-256 before and after:
`ac4aeb5a2c6ba3db0969f668d297dd73866e0cb1fa0e206822258a5ca378829a`.
These local checks do not substitute for protected merge or post-merge
verification.

After the mutation restored the source, the native full sequential planner
target passed all ten tests again in 1.50 seconds. Targeted warning-denied
Clippy also passed in 13.98 seconds. The coordinator retained those outcomes
in `root-green.json`. No source or
test changes followed those runs; this update records their evidence.

## Affected threat boundaries

- **TM-009:** the unsupported stage semantics must be refused rather than
  represented as successful execution. The candidate guard and three planner
  regressions address this lowering boundary.
- **TM-014:** artifact upload, digest verification, immutable metadata and
  restore controls remain unchanged. No artifact is collected, staged or
  published by this planner correction.
- **TM-020 and TM-026:** the compile-only worker, independent compiler
  validation and earned Jenkins step mappings remain unchanged. The new
  planner refusal narrows an unsupported runtime shape; it admits no new
  construct and grants no execution or external-effect authority.
- **TM-001, TM-003, TM-005, TM-006, TM-007, TM-008, TM-011, TM-016,
  TM-017, TM-018, TM-022, TM-023, TM-024, TM-038 and TM-052:** the
  existing sequential tenant, fencing, durability, recovery, cancellation,
  bounds, pool, supply-chain, restore, quota, audit, rendering, migration and
  protected-check controls are unchanged. The correction occurs before any
  plan is returned and does not change those controls.

These are the implementation author's proposed determinations. They require
independent review of the actual candidate before becoming a reviewed
no-change receipt. There is no production, canary, migration or release
authority claim. Hostile same-UID isolation remains SEC-005; stage-level
artifact collection in sequential nodes remains unsupported.
