# DEPLOY-001 security and implementation closure

Date: 2026-08-25

Verdict: PASS for the implementation gate at protected-main commits
`52b2ecb7641c38c956a2612614b50ea6fb3d344d` (PR #84, the deployment lane) and
`586230bfb51c30eed268bc7ea31921928f68aaa4` (PR #93, the follow-up closing five
deferred findings). All fifteen protected checks pass on that second commit
— `Rust`, `Rust lint`, `Rust workspace tests`, `Rust boundary suites`,
`Rust source-acquirer suite`, `Dependencies and licenses`, `Secret scan`,
`Architecture records`, `Formal model`, `Controller PostgreSQL`,
`Backup and restore`, `Isolated Linux amd64`, `Classify Windows impact`,
`Windows agent`, and the lane's own new `Deployment lane` job — as they do on the first.

This receipt closes `DEPLOY-001`. It was withheld until now for a reason worth
recording: the implementation merged on 2026-08-24/25, but the board's Working
rule bars an implementation ticket from `DONE` until
`docs/threat-model/README.md` is reviewed and updated for every affected
boundary, "including … deployment". That never happened — the threat model's
last change before this one was `03a1f5d` (`EXT-002`), which predates this
ticket — and no evidence receipt existed while eighteen other closed boundary
tickets carried one. **The board was correct to hold `DEPLOY-001` at `ACTIVE`,
and the 2026-08-25 custodian handoff's claim that it was `DONE` was premature on
those two receipts.** Both are now supplied: `TM-050` records the boundary, and
this document records closure.

Nothing in this lane grants production, canary, cutover, or Jenkins authority.

## Review cost, stated plainly

Measured from the GitHub API rather than recollection:

| | measured |
|---|---|
| Top-level review findings | 162 |
| Reviewer submissions, one per reviewed head | 81 |
| Findings per round | 2.0, flat |
| Severity | 62 P1, 100 P2 |
| Commits on the branch | 105 |
| Findings per day | 37, 39, 43, 43 |

Every finding was valid; none was a false positive; every one was answered.
**The daily rate never declined.** 134 of the 162 findings (83%) landed in four
validation scripts rather than in the units, quadlets, or contracts they
validate.

That cost is the reason this ticket has a design successor. Under the owner's
standing correction-round cap, a finding population that does not converge is a
design property being paid for one patch at a time rather than a defect
population being exhausted. The analysis is in
`docs/architecture/DEPLOYMENT_TRUST_BOUNDARY_V1.md` and the remaining work is
`DEPLOY-003`. **This receipt does not defer any finding to that ticket** — the
five findings deferred from PR #84 were closed in PR #93, including the
local-escalation chain, and nothing security-relevant is outstanding from that
deferral.

## Implemented boundary

- one supported single-host production deployment lane: systemd user units for
  the controller and agent, a oneshot database bootstrap, and PostgreSQL as a
  rootless podman quadlet with a digest-pinned image and a `Notify=healthy`
  gate, ordered postgres → db-init → controller → agent;
- digest-pinned release artifacts with install-time identity recomputation, a
  staged-then-published release directory, retained releases, and an atomic
  `current` symlink transition under an exclusive transition lock;
- split migration and runtime database roles, with the runtime login constrained
  to `mcloving_tenant` and refused otherwise;
- explicit environment contracts rendered per deployment rather than copied, one
  0600 file per service, with a default-deny declared-variable allowlist that
  refuses a declared `PATH` outright;
- `PATH` pinned at the unit boundary in three independent layers — unit
  directive, absolute interpreter shebangs, and the contract allowlist — because
  `EnvironmentFile=` overrides `Environment=` regardless of declaration order on
  systemd 255;
- pre-`main()` execution hooks stripped at the unit boundary by
  `UnsetEnvironment=`, with a validation-time refusal of any contract that would
  reintroduce one;
- the §2.1 ancestor invariant of `TM-050` established before every transition and
  again at every service start, judged through symlinks with resolved target
  chains joined to the walk, with creation bounds for paths that do not yet exist;
- a deployed-digest re-read covering every installed executable, contracts and
  PKI committed by hash rather than by content, so `CUTOVER-001` can read
  deployed implementation digests without hand-assembled state;
- health verification per service, an upgrade path with health and stability
  gates, and a rollback path to a retained release;
- a documented install/upgrade/rollback runbook in
  `docs/operations/DEPLOYMENT_V1.md`;
- `deploy/test-deployment.sh`, which exercises install, health, upgrade,
  rollback and digest re-read end to end without root — 600 named refusals in
  230 blocks — and now runs as the `Deployment lane` job on every pull request.

## Bounded deliberately

The signed `REL-001` artifact packages `mcloving-controller`, `mcloving-agent`,
`mcloving-cli`, and — added by this ticket as a fourth component with role
`migration_tool` — `mcloving-identity-admin`. The sealed helper executables the
spine spawns, the secret broker, the ceremony driver, and the qualification
verifier are outside that release, so this lane cannot install them from signed
digest-pinned artifacts and does not claim to. That gap is `REL-003`, and
revalidating this lane against the release that actually ships is `DEPLOY-002`.

## Residual risk

- **The service account owns its deployed tree, and nothing here bounds it.**
  Release-identity verification detects corruption, partial writes, and in-place
  substitution; it is not a defence against a compromised service user, who owns
  those files. A submitted workload runs as that account. **Until `SEC-005`
  ships, the right to submit a pipeline equals the right to read that host's
  deployment credentials**, and an untrusted submission must not be run on a
  host whose credentials the operator is unwilling to disclose.
- The operator is trusted for the host's directory configuration. The lane
  refuses to install onto a host whose ancestor chains permit a third party to
  write, but it cannot repair one.
- No TOCTOU-freeness. The lane cannot hold the filesystem still; each check is
  converted into a containing-directory bound, and the guarantee is that bound.
- **Namespace-based systemd hardening is silently unavailable under a user
  manager on Ubuntu 24.04+ at default settings** — measured: thirteen directives
  enforced, eleven silently unenforced with the unit still reporting success,
  three fail closed. The shipped units declare none of the failing directives,
  but no filesystem hardening directive may be added to this lane without a
  runtime proof that it is in effect.
- Release signatures are not verified at install; the cryptographic chain is
  verified separately by `mcloving-release-provenance verify-chain`.
- The database bootstrap trusts the container boundary and runs `psql` via
  `podman exec` as the PostgreSQL superuser; the database listens on loopback only.
- Single host, no HA, no Kubernetes. Nothing here satisfies `CUTOVER-001`'s gates.
- Six audit observations from the `DEPLOY-003` analysis are carried into that
  ticket rather than fixed here, none of them a disclosure or escalation path:
  a discarded mask answer that is then re-derived, an unbounded PID-recycling
  window on `ExecMainPID` → `/proc/PID/environ`, a suite that exercises the
  manager-query path in only 3.3% of its gates, four unlabelled derived
  fallbacks, an install-time integrity check taken outside the transition lock,
  and `NoNewPrivileges=` absent from the db-init unit and both quadlets.

## Inventory denominator

The accepted `MIG-000` Mario inventory grants no deployment authority and no
production effect authority, and this lane changes neither. No production
deployment, canary, cutover, rollback, or Jenkins decommissioning event is
claimed or authorized by this receipt.
