# SECRET-001 security and closure review

Date: 2026-08-13

Verdict: PASS. The contained credential-mapping and short-lived grant broker is
bound to exact reviewed head
`87951abddf174829dc5fe70b22dd6a4a07724f5c` and closed against protected
`main` commit `f08756fd91810268a0ea18321d9e333895501ab7` after exact-head
and post-merge Foundation and Windows verification.

## Scope

SECRET-001 adds the provider-neutral `mcloving-secret-broker`, exact sealed
Jenkins runtime-credential reconciliation, typed consumer and taint
classification, startup-pinned owner approval keys, signed monotonic provider
mapping generations, and fenced short-lived one-time grants. Only exact
external-connector and source-acquirer consumers are grant eligible.
Controller-visible and workload-visible credentials remain permanently
ineligible; neither an owner signature nor redaction can waive that boundary.

Every mapping binds the inventory epoch, job, dependency and Jenkins reference;
owner and signing-key identity; tenant, project, environment and action;
consumer implementation and configuration; provider implementation,
configuration, reference, API and secret version; taint path and evidence; and
rotation generation. Grant issue and redemption bind the build, attempt, fence,
consumer, trusted time and expiry. Durable per-scope uniqueness prevents a
caller from minting a second grant by renaming its ID. Redemption is atomic and
one-time; rotation and emergency revocation fence every older unredeemed grant.

Secret bytes exist only in nonserializable, redacted, zeroizing
`SecretMaterial`. Consumer bindings omit the provider reference and expose only
the exact bounded grant protocol and consumer identity. Before successful
redemption, the broker denies raw, padded and unpadded Base64, Base64URL,
hexadecimal, and percent-encoded secret representations in public mapping,
grant, receipt or audit evidence. State is held in an owner-private,
single-link, non-symlink SQLite database with validated sidecars, permanent
grant-scope uniqueness and a domain-separated hash-chained audit trail.

Mario's sealed runtime inventory remains pinned to its exact digest and contains
230 jobs with zero credential references, redaction references or secret
consumers. The implementation therefore grants Mario no production credential,
provider, grant, canary or authority-transfer capability.

## Exact evidence

- Pull request: `#51` (`SECRET-001: add credential mapping and grant broker`).
- Exact reviewed implementation head:
  `87951abddf174829dc5fe70b22dd6a4a07724f5c`.
- Focused gate: fourteen tests passed, comprising thirteen broker contract tests
  and one sealed Mario inventory assertion. The contracts cover exact and
  missing inventory truth; permanently ineligible workload/controller paths;
  startup-pinned owner-key registry, signature, payload and expiry checks;
  connector and source bindings; cross-tenant/project/build/attempt/fence and
  consumer denial; trusted time, renamed-ID and replay denial; provider-version
  substitution; rotation and emergency revocation; raw/encoded non-disclosure;
  audit tampering; and private state-path enforcement.
- Local gates: formatting, focused strict all-target Clippy with warnings
  denied, locked offline metadata, diff hygiene, execution-board tests and
  verifier, and protected-boundary shell syntax passed. The local macOS full
  workspace compile reached pre-existing dependency-resolver platform-branch
  errors; the authoritative pinned Linux gate compiled and passed the complete
  workspace unchanged.
- Protected exact-head checks: Foundation run `31757171520` passed every Linux
  job, including pinned Rust 1.97.1 workspace Clippy, complete non-source
  workspace tests, dependency-resolver containment, connector/shadow network
  denial, and the serialized AppArmor source-acquirer suite. Windows Agent run
  `31757171555` passed exact impact classification and correctly skipped the
  unaffected Windows runtime job.
- Exact-head review found no major issue after the owner approval key source was
  moved from the installation call into a startup-pinned nonempty and
  unambiguous trusted-key registry. GitHub reported zero review threads at the
  merge head.
- Squash merge: `f08756fd91810268a0ea18321d9e333895501ab7`, with
  protected-main parent `0a957a178c42b2b54f5dc92d0905fa7633cc63e4`.
- Post-merge verification: Foundation run `31759242897` and Windows Agent run
  `31759242933` passed on that exact protected-main commit. The post-merge
  Windows classifier correctly selected and passed the complete persistent
  Windows runtime and native-service/crash-recovery gate because the workspace
  manifest and lockfile changed.

## Residual boundary

This closure proves the contained classification, mapping, grant, redemption,
rotation, revocation and non-disclosure implementation. It does not install a
production provider adapter, owner-key source, service identity, clock,
secret-manager authorization, connector/source launch path, credential mapping,
canary, cutover, rollback, recutover or decommission authority. Transformed
secret representations beyond the explicitly tested detectors and compromise
of the trusted host, deployment operator, owner decision/key or provider remain
inside the declared residual trust boundary. Workload-visible credentials stay
ineligible unless a future separately approved typed non-disclosing surrogate
protocol proves deterministic equivalence and permission-negative behavior.
