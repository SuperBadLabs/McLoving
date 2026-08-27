# DEPLOY-001 service-managed lane: the clean-host evidence

`DEPLOY-001`'s acceptance is *"a scripted install on a clean host brings up the
controller and agent"*, for a lane its own row defines as *"systemd units or
podman quadlets"*. It was `DONE`, and was **reverted to `ACTIVE`** because that
sentence was not met: `deploy/test-deployment.sh` passes `--no-systemd` at all
184 of its install, upgrade and rollback sites, and re-derives what the units say
in bash. That proves the install, contract, digest and rollback *mechanics*. It
proves nothing about the lane the units describe, because systemd never
generated, enabled, ordered or started anything in any gate.

This records the missing half, and the two shipped defects it found.

## What the arm proves that nothing did before

`deploy/test-deployment-systemd.sh` installs to a real service account's passwd
home **without `--no-systemd`** and lets the manager do its job:

| step | previously asserted by |
|---|---|
| `systemctl --user daemon-reload` after install | nothing — the installer's non-`--no-systemd` path had never run |
| Quadlet generating `mcloving-postgres.service` from the `.container` | nothing — the generator had never been invoked |
| the library's `deployment_quadlet_generated_name` model | a hard-coded table whose comment says *"verified against `/usr/libexec/podman/quadlet`'s actual output"* — verified once, by hand, in a comment |
| `Requires=` / `After=` ordering | nothing — the suite achieves the order by writing steps consecutively in bash |
| `StateDirectory=` creating the agent workspace at `0700` | nothing — the suite `mkdir -p`s it, commented *"Mirror what StateDirectory= creates for the real units"* |
| `require_service_stable` against real units | nothing — skipped entirely under `--no-systemd` |
| `mcloving-health --unit` through the manager | ~3% of gates reach a real manager query; the write path, none |
| service-managed upgrade **and** rollback | nothing — both scripts `exit 0` before reaching it |

Measured result, on this host, as the dedicated `mcloving` account:

```
mcloving-postgres.service   active/running   (generated)
mcloving-controller.service active/running
mcloving-agent.service      active/running
mcloving-db-init.service    active/exited
StateDirectory= created /home/mcloving/.local/state/mcloving-agent/workspace at 700, unaided
controller and agent held steady across the sampling window
mcloving-health[controller]: public API answers on 127.0.0.1:8080
upgrade:  releases/ddd1f7bae2da -> releases/ee80521177e7   (both services active)
rollback: releases/ee80521177e7 -> releases/ddd1f7bae2da   (both services active)
```

## Two shipped defects, both only findable by running systemd

**1. The documented install procedure's final step fails.** `mcloving-install`
printed, and `docs/operations/DEPLOYMENT_V1.md` step 5 instructed:

```
systemctl --user enable --now mcloving-postgres mcloving-db-init mcloving-controller mcloving-agent
```

and that command errors:

```
Failed to enable unit: Unit /run/user/1001/systemd/generator/mcloving-postgres.service
is transient or generated.
```

`mcloving-postgres.service` is *generated* by Quadlet, and systemd refuses to
enable a generated unit; Quadlet honours the quadlet's own `[Install] WantedBy=`
itself, so it wants starting, not enabling. An operator following the runbook hit
this. Both the installer's text and the runbook are corrected, and **the corrected
command is now a gate** — the arm runs the documented sequence and additionally
pins that `enable mcloving-postgres` is refused, so an edit cannot quietly put the
old wording back.

**2. `mcloving-upgrade` could not upgrade the lane it is written for.** Quadlet
stamps `Environment=PODMAN_SYSTEMD_UNIT=%n` onto every unit it generates, and
`require_unit_environment_allowed`'s default-deny rule refused it:

```
mcloving-upgrade: unit Environment= directive(s) set variable(s) this deployment
does not recognise: PODMAN_SYSTEMD_UNIT
```

So the shipped upgrade path was blocked on any real service-managed deployment.
The `--no-systemd` suite never reads a generated unit and never saw it.

The fix follows the rule's own precedent — `PATH` is allowed **by value**, pinned
to the trusted spelling, never by name — and allows exactly
`PODMAN_SYSTEMD_UNIT=%n`. `%n` is systemd's *"this unit's own name"*, expanded at
load, so the value cannot designate another unit however the file is edited.

**A first attempt at that fix could never have fired**, and the reason is worth
keeping: it matched the *expanded* unit names this deployment knows. The unit
file contains the literal `%n`; only the manager ever sees the expansion. It was
caught by reading the generated file rather than by reasoning about it.

## The second clause: the deployable-runtime gate

The acceptance also says *"and passes the deployable-runtime gate"*. Wiring that
meant fixing the gate first, because **it returned success with no assertions**
when `MCLOVING_TEST_DATABASE_URL` was unset:

```rust
let Ok(migration_url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
    eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
    return;
};
```

An acceptance criterion satisfiable by not running is this repository's signature
failure, sitting inside `DEPLOY-001`'s own acceptance.

Three changes, and the shape of them matters:

- **`#[ignore]`, not a hard failure alone.** A bare `panic!` would have broken
  every `cargo test --workspace`, where the gate has no database and is not
  meant to run. Ignored, a plain run reports `2 ignored` — visible, and not a
  false pass. Both real invocations (`scripts/test-controller-postgres.sh` and
  CI's `Controller PostgreSQL` job) now pass `-- --ignored`, so the gate still
  runs where it always did.
- **A missing database is now a hard failure** when the gate is invoked
  explicitly. Verified: `2 failed` where it previously reported success.
- **An optional `MCLOVING_TEST_RUNTIME_DATABASE_URL`.** The gate derived the
  runtime URL by string-replacing `postgres://mcloving@`, which only works for
  the passwordless CI database. A real deployment gives the migration and
  runtime roles **different passwords** — that split being the very property
  this gate checks — so one URL cannot derive the other. When supplied it is
  used; otherwise the historical derivation applies, so CI is unchanged.

The arm then runs it against **this deployment's** database and roles, read from
the contract systemd starts the controller with — not a database the test
brought up for itself, which is what made the gate and the install two unrelated
CI jobs sharing no state.

**The gate spawns the build tree's controller**, because
`CARGO_BIN_EXE_mcloving-controller` is baked in at compile time. That is
checkable rather than hand-waved: the installed release was staged from that
build and digest-verified, so the arm asserts the two are byte-identical before
running the gate. **That assertion fired on its first run and was right** — a
later `cargo test --no-run` had rebuilt the controller, leaving the staged
release out of step with what the gate would spawn. Restaged from the same
build, both tests pass:

```
   the gate's controller is byte-identical to the installed one
test failed_runtime_preflight_does_not_rotate_the_active_api_credential ... ok
test shipped_controller_uses_split_credentials_and_executes_submissions ... ok
   deployable-runtime gate passed against the installed deployment's database and roles
```

## Review round 1 — seven findings, two of them P1

Every one was real. Two are worth stating in full because they were mine and
they were the dangerous kind.

**P1 — the arm could destroy a production deployment.** Every precondition it
checks passes just as well on a real McLoving service account as on a disposable
one, and its teardown force-removes the `mcloving-postgres-data` volume and the
deployment tree. It could not tell the two apart and did not ask. **An existing
deployment is now a refusal**, and destroying one has to be requested by name
with `--reset`. Verified in both directions: the libexec tree alone refuses, and
the volume alone refuses.

The probe for "is there a deployment here" was itself wrong at first, and the
correction is the interesting part: it looked only at the libexec root and the
volume, so a failed run that had left `StateDirectory=` trees behind was judged
"nothing to clean" — and the next run's assertion that *systemd* creates the
workspace then failed on a directory from the run before. **What makes a
deployment present is any of its parts, not the tidiest one.**

**P1 — a stray `rm -rf "${scratch}"` before `scratch` existed.** Under `set -u`
that exits immediately after deleting the volume and *before the teardown trap
is installed*. It came from a patch that matched the wrong one of two identical
lines — the third time that same mistake appeared in this shift, after the
mutation harness and the `statuses.get(ticket) != "DONE"` anchor. **A textual
patch against a non-unique anchor is not a patch; it is a coin flip.**

The five P2s, each fixed:

- **The gate ran `enable`, not the documented `enable --now`.** The runbook asks
  for both operations and starting is the half that can fail. Fixing it exposed
  an ordering error of my own: `--now` starts the units, so it has to come after
  the contracts and PKI — which is exactly where the runbook puts it. The arm
  now follows the documented order because the documented order is what it is
  testing.
- **Contracts read from the wrong root.** `mcloving-install` writes contracts and
  PKI to the literal `%h/.config/mcloving` and uses the manager's effective XDG
  base only for units and quadlets. On an account with an absolute
  `XDG_CONFIG_HOME` those differ, and the arm would have read contracts from a
  directory the installer never wrote to.
- **The workspace assertion inspected `~/.local/state` directly**, so on an
  account with a custom `XDG_STATE_HOME` it would have checked a path the
  services never used — and passed, having looked at nothing.
- **The board contradicted itself**: the row read `DONE` while its own closure
  text still said the ticket stays `ACTIVE`, and the prose under the dispatch
  table still had `DEPLOY-001` holding the slot and blocking `DEPLOY-003`.

## Review round 2 — three more, all the same family

- **`--reset` stopped three units and not the fourth.** The generated postgres
  unit cannot be *disabled*, so it was not in the list — and while it runs it
  holds the data volume open, making the volume removal underneath it a race at
  best. Stopped by name now.
- **An unverifiable gate identity printed a note and carried on.** If
  `--runtime-gate` named a relocated binary, the controller beside it could not
  be found, and the arm said *"identity unasserted"* and ran the gate anyway.
  That is this ticket's own defect in miniature: the gate would report success
  and nobody would know which controller it exercised. **It is a refusal now**,
  verified against a deliberately relocated binary.
- **The scratch tree was never removed.** It holds a second full copy of the
  release — measured at **596 MB per run** — and the teardown lost its cleanup
  when a stray `rm -rf "${scratch}"` was deleted from the preconditions, where
  it never belonged. Restored to the teardown, where it does. Six leaked trees
  from earlier runs were reclaimed.

Three rounds, ten findings, every one of them mine. The pattern across all ten
is worth more than the list: **a check that cannot establish its claim must
refuse, not narrate.** Two of the ten were narration — *"identity unasserted"*,
and a probe that judged a half-present deployment absent — and both would have
produced a green run that proved less than it appeared to.

## Review round 3 — two more, and one of them was a lie

- **`--keep` destroyed the database it said it was keeping.** The volume removal
  sat outside the `keep` branch, so every `--keep` run wiped
  `mcloving-postgres-data` and then printed *"the deployment under … was left in
  place"*. A deployment kept for inspection without its data is not the thing
  anyone asked to keep, and the message made it worse by saying otherwise. The
  removal is inside the branch now, and the message says exactly what survives
  and what the next run will do to it.
- **Cleanup roots came from the invoking shell's XDG, not the manager's.**
  `mcloving-install` writes units and quadlets under
  `deployment_effective_config_root`, which asks the running manager;
  `deployment_config_root` answers from the caller's environment. Where the two
  disagree, `--reset` would clean a directory the installer never wrote to,
  leave the real units in place, and report a reset that had not happened. This
  is the third instance of the same mistake on this branch, after the contract
  root and the state root: **when the installer asks the manager, the test must
  ask the manager too.**

Twelve findings across three rounds, all mine, none disputed. Two shapes account
for all of them: **narrating instead of refusing** when a claim could not be
established, and **asking the wrong oracle** — the caller's environment, a
remembered table, a path's spelling — instead of the one that decides.

## Review round 4 — one, and it closes a validity hole as well as a safety one

**A surviving unit drop-in did not count as an existing deployment.** A lone
`mcloving-agent.service.d/override.conf` left by a previous run or by an
operator, and the arm declared the account clean and proceeded.

Two things wrong with that, and the second is the sharper: proceeding over it
destroys work this script cannot see, **and systemd merges drop-ins** — so an
unnoticed one changes what the units under test actually do, and the arm would
have exercised something other than the shipped lane while reporting on the
shipped lane. Drop-ins now count in the probe, and `--reset` removes the drop-in
*directories* rather than only `*.service` files, since `rm -f '*.service'`
leaves `mcloving-agent.service.d/` standing and a drop-in that survives a reset
is merged into the next run.

Thirteen findings across four rounds, at a declining rate (7, 3, 2, 1), all
mine, none disputed.

## Bounded deliberately
- **The arm needs a dedicated account and refuses without one.** Every
  precondition — passwd home, `HOME` agreeing with it, lingering, a reachable
  manager, the Quadlet generator, rootless podman — is a refusal by name. None
  of them skips. That is deliberate: the gate this ticket also names fails by
  skipping, and repeating that inside its replacement would be indefensible.
- **CI cannot run this arm as written.** It needs a lingering service account
  with rootless podman, which the runner did not provide when this was last
  attempted. The arm is therefore evidence produced on a clean host and recorded,
  not a check that runs on every pull request. Saying so plainly is the point;
  claiming CI coverage it does not have would be the substitution the revert
  refused.
