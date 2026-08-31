# EXEC-002 retrospective security review

Date: 2026-08-30

`EXEC-002` closed in protected-main commit `75e618d` (PR #82). The reviewed
failure was configuration that looked valid but could never match the default
submission: an embedded worker declaring the informal token `linux` started
successfully while submissions required `platform:linux`, leaving work queued
forever.

The implementation centralizes the platform vocabulary in `crates/domain`.
The `platform:` namespace is closed to `platform:linux` and
`platform:windows`; startup classifies a declaration as schedulable, disabled,
or a named invalid configuration. Empty capability sets, unsupported platform
members, declarations with no supported platform, and the disable sentinel
mixed with other tokens fail closed. A Windows-only worker is allowed to start
because it is valid for explicitly Windows work; the control rejects lies and
impossible declarations, not legitimate non-default pools.

The threat-model review covered capability spoofing, platform substitution,
silent queue starvation, and disagreement between controller and executor
vocabularies. Those are already owned by the scheduling-capability and agent
pool boundaries. No identity, credential, persistence, connector, or release
authority changed, so the register result is reviewed no-change with this
receipt as attribution evidence.

Residual risk is operational: a valid pool may intentionally omit the default
platform and therefore cannot serve default submissions. Explainability and
pool planning must identify that condition; it is not a malformed declaration.
Any new platform must be added to the shared closed vocabulary and exercised
at controller startup, scheduling explanation, remote-agent negotiation, and
execution admission together. This receipt documents the retrospective review
missing when `EXEC-002` became `DONE`.
