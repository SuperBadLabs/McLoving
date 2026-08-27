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

## Bounded deliberately

- **The deployable-runtime gate is not run against the installed deployment.**
  `DEPLOY-001`'s acceptance names it, and it lives in
  `bins/controller/tests/deployable_runtime.rs`, run by CI's `Controller
  PostgreSQL` job against its own postgres. It is **not** wired to an installed
  lane here. Worse, it **returns success with no assertions** when
  `MCLOVING_TEST_DATABASE_URL` is unset — a silent skip inside an acceptance
  criterion, which is this repository's signature failure. Wiring it to the
  installed deployment, and making the absent variable a hard failure, is the
  one part of the acceptance this change does not close.
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
