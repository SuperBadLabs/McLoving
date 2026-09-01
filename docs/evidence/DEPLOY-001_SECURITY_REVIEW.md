# DEPLOY-001 security and implementation closure

Date: 2026-08-25

Status update (2026-08-30): the statements below that the ticket was `ACTIVE`
and that gate two was unmet describe this review's 2026-08-25 snapshot. The
later hand-run systemd evidence in `docs/evidence/DEPLOY-001_SYSTEMD_LANE.md`
gave the original ticket a bounded implementation closure on 2026-08-27. That
closure is not a claim of CI-reproducible systemd coverage or production
readiness: the manager-query, complete load-path, and trust-surface residuals
remain `DEPLOY-003`, and dependent production authority stays blocked behind
that ticket.

Verdict: PASS for the implementation gate at protected-main commits
`52b2ecb7641c38c956a2612614b50ea6fb3d344d` (PR #84, the deployment lane) and
`586230bfb51c30eed268bc7ea31921928f68aaa4` (PR #93, the follow-up closing five
deferred findings). All fifteen protected checks pass on that second commit
— `Rust`, `Rust lint`, `Rust workspace tests`, `Rust boundary suites`,
`Rust source-acquirer suite`, `Dependencies and licenses`, `Secret scan`,
`Architecture records`, `Formal model`, `Controller PostgreSQL`,
`Backup and restore`, `Isolated Linux amd64`, `Classify Windows impact`,
`Windows agent`, and the lane's own new `Deployment lane` job — as they do on the first.

**At this review point, this receipt did not close `DEPLOY-001`, and the ticket
was `ACTIVE`.** It
records what the lane implements and what it is verified to do — a prerequisite
for closure, not the whole of it. Two gates stood in the way; one is now met and
the other is not.

**Gate one, now met.** It was withheld until now for a reason worth recording: the implementation merged on 2026-08-24/25, but the board's Working
rule bars an implementation ticket from `DONE` until
`docs/threat-model/README.md` is reviewed and updated for every affected
boundary, "including … deployment". That never happened — the threat model's
last change before this one was `03a1f5d` (`EXT-002`), which predates this
ticket — and no evidence receipt existed while eighteen other closed boundary
tickets carried one. **The board was correct at this review point to hold
`DEPLOY-001` at `ACTIVE`,
and the 2026-08-25 custodian handoff's claim that it was `DONE` was premature on
those two receipts.** Both are now supplied: `TM-050` records the boundary, and
this document records closure.

**Gate two was NOT met in this snapshot — why the ticket stayed `ACTIVE`.** The row's acceptance is
"a scripted install on a clean host brings up the controller and agent and passes
the deployable-runtime gate", for a lane defined as "systemd units or podman
quadlets". `deploy/test-deployment.sh` passes `--no-systemd` to install, upgrade
and rollback, and starts postgres from a quadlet-*derived* command — so **systemd
never generates, enables, orders or starts anything, in any gate.** The install,
contract, digest and rollback mechanics are proven; the service-managed lane is
not. Closing on the first while the row names the second is precisely the
substitution this project's receipt rules exist to prevent.

It is measured closable, which is why this is a gap rather than a redesign: on a
stock `ubuntu-24.04` runner a linger-enabled dedicated account installs, enables
and starts a real unit under its own `~/.config/systemd/user` and reports
`active`, needing no change to `require_systemd_home`. Rootless podman under that
account is the one open item, and the postgres quadlet needs it.

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
  rootless podman quadlet with a digest-pinned image and version-stable conmon
  readiness; the db-init oneshot requires two bounded `pg_isready` successes
  before any mutation, ordered postgres → db-init → controller → agent;
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
- the §2.1 ancestor invariant of `TM-050` established before every transition,
  judged through symlinks with resolved target chains joined to the walk, with
  creation bounds for paths that do not yet exist. At service start the
  re-establishment is PARTIAL: systemd loads the unit before any `ExecStartPre`,
  and `mcloving-env-guard` walks only the environment file and configured secret
  and state paths, not the unit, the guard binary, or the release binary --
  a start-time verifier is PENDING under `DEPLOY-002`;
- a deployed-digest re-read covering every installed executable, contracts and
  PKI committed by hash rather than by content, so `CUTOVER-001` can read
  deployed implementation digests without hand-assembled state;
- health verification per service, an upgrade path with health and stability
  gates, and a rollback path to a retained release;
- a documented install/upgrade/rollback runbook in
  `docs/operations/DEPLOYMENT_V1.md`;
- `deploy/test-deployment.sh`, which exercises install, health, upgrade,
  rollback and digest re-read without root — 600 named refusal sites
  (`rg -c '^\s*exit 1' deploy/test-deployment.sh` at this head) — and now runs as
  the `Deployment lane` job on every pull request. **It drives install, upgrade
  and rollback with `--no-systemd`, and starts postgres by deriving the command
  from the quadlet rather than letting systemd generate and start it**, so unit
  generation, enablement, ordering and service-managed upgrade/rollback are not
  exercised by any gate. See the residual risks.

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
- **The systemd write path is exercised by no gate, so this lane's clean-host
  acceptance is demonstrated only for the derived-command path.**
  `deploy/test-deployment.sh` passes `--no-systemd` to install, upgrade and
  rollback, and starts postgres by deriving its invocation from the quadlet
  rather than letting systemd generate and start it. Unit generation,
  enablement, `Requires=`/`After=` ordering, Quadlet generation and
  service-managed upgrade/rollback are therefore unproven. The manager *read*
  path is partly covered — three gates query a live manager where one is
  reachable — but the *write* path is covered nowhere. The structural reason is
  `require_systemd_home`: units resolve `%h` at the passwd home and the suite
  installs into `mktemp -d` trees, so it must pass `--no-systemd`; CI runners
  have no user session either.
  **This was measured to be closable and was not closed in this snapshot.** On a stock
  `ubuntu-24.04` runner, `useradd` + `loginctl enable-linger` with both
  `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` set gives a manager that
  answers, runs transient units, reloads, and installs, enables and starts a
  real unit under the account's own `~/.config/systemd/user` reporting
  `active` — needing no change to `require_systemd_home`, because such an
  account's `--home` *is* its passwd home. Rootless podman under that account
  remains unresolved (`mkdir /run/user/<runner-uid>/libpod: permission denied`),
  and the postgres quadlet needs it. Until that arm exists, treat this ticket's
  clean-host claim as covering the install/contract/digest/rollback mechanics
  and **not** the service-managed lane.
- The operator is trusted for the host's directory configuration. The lane
  refuses to install onto a host whose ancestor chains permit a third party to
  write, but it cannot repair one.
- No TOCTOU-freeness. The lane cannot hold the filesystem still; each check is
  converted into a containing-directory bound, and the guarantee is that bound.
- **Namespace-based systemd hardening is silently unavailable under a user
  manager on Ubuntu 24.04+ at default settings** — measured: thirteen directives
  enforced, **thirteen** silently unenforced with the unit still reporting
  success, three fail closed. The silent thirteen are four classes with
  different causes: nine needing a mount namespace, one needing a network
  namespace (`PrivateNetwork=`, which fails for a different reason and must not
  be remediated as a mount case), one needing BPF this build
  lacks (`IPAddressDeny=`), and two needing an undelegated cgroup controller
  (`IOReadBandwidthMax=`, `AllowedCPUs=`) — a user-namespace fix would not help
  the last two. The shipped units declare none of the failing directives,
  but no filesystem hardening directive may be added to this lane without a
  runtime proof that it is in effect.
- Release signatures are not verified at install; the cryptographic chain is
  verified separately by `mcloving-release-provenance verify-chain`.
- The database bootstrap trusts the container boundary and runs `psql` via
  `podman exec` as the PostgreSQL superuser; the database listens on loopback only.
- Single host, no HA, no Kubernetes. Nothing here satisfies `CUTOVER-001`'s gates.
- Seven audit observations from the `DEPLOY-003` analysis are carried into that
  ticket rather than fixed here, and they are the same seven the `DEPLOY-003`
  row enumerates: a discarded mask answer that is then re-derived, an unbounded
  PID-recycling window on `ExecMainPID` → `/proc/PID/environ`, four unlabelled
  derived fallbacks, an install-time integrity check taken outside the
  transition lock, `mcloving-env-guard` re-walking ancestors under no lock,
  `NoNewPrivileges=` absent from the db-init unit and both quadlets, and no
  start-time verification of the unit, the guard executable, or the selected
  release binary.
- **One of those seven is an escalation path, and an earlier revision of this
  receipt said none was.** Where the deployment layout is exposed in the
  `DEPLOY-004` sense, the missing start-time verification lets a substituted
  unit execute as the service account, which reaches that account's own
  credentials. The other six are not disclosure or escalation paths. Read this
  line together with the `DEPLOY-004` severity: exposure is conditional, impact
  where exposed is credential compromise.
- Separately, and tracked as `DEPLOY-003`'s fourth acceptance item rather than
  as an audit observation: the suite exercises the manager-query path in only
  3.3% of its gates (20 of 600), so it currently specifies the derived path.

## Inventory denominator

The accepted `MIG-000` Mario inventory grants no deployment authority and no
production effect authority, and this lane changes neither. No production
deployment, canary, cutover, rollback, or Jenkins decommissioning event is
claimed or authorized by this receipt.
