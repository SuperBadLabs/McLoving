# HYG-001 retrospective security review

Date: 2026-08-30

`HYG-001` closed in protected-main commit `880fb2c` (PR #83). Its three scoped
changes remove ambiguity from security-relevant shared code, add executable
object-store boundary tests, and prove a test-only insecure OIDC option cannot
be enabled in the shipped controller.

The stale `crates/state-machine` copy of `AttemptPhase` was removed so recovery
and execution do not have two competing phase vocabularies. `crates/domain`
became the real shared vocabulary instead of a placeholder depended on by the
agent. The object-store integration suite covers staged publication, byte and
total quota enforcement, no-overwrite immutability, and typed missing/corrupt
gap classification. The OIDC permission-negative test demonstrates that
`allow_insecure_loopback_for_tests` is available only through the test feature
and cannot be selected through production environment or configuration.

The threat-model review covered phase-truth divergence, artifact substitution
or overwrite, quota exhaustion, ambiguous object gaps, and accidental insecure
OIDC transport. These are already owned by the agent recovery, artifact
storage, quota, and identity-provider boundaries. The ticket introduced no new
runtime endpoint, credential, scheduler, connector, or production authority,
so the threat register result is an explicit reviewed no-change receipt.

Residual risk remains in callers: a correct object store cannot prevent an
authorized caller from publishing the wrong digest, and production OIDC still
depends on correct provider and redirect configuration. Future shared-domain
types must not be duplicated into leaf crates, and test-only transport escape
hatches must retain compile-time separation from release builds. This document
records the retrospective security review missing at the original `DONE`
transition for `HYG-001`.
