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

Measured result, on this host, as the dedicated `mcloving` account. This is the
single ten-step run that also exercised the deployable-runtime gate — an earlier
revision's run (`ddd1f7bae2da -> ee80521177e7`) proved the lane before the gate
was wired, and citing it here would have quoted the weaker of the two:

```
mcloving-postgres.service   active/running   (generated)
mcloving-controller.service active/running
mcloving-agent.service      active/running
mcloving-db-init.service    active/exited
StateDirectory= created /home/mcloving/.local/state/mcloving-agent/workspace at 700, unaided
controller and agent held steady across the sampling window
mcloving-health[controller]: public API answers on 127.0.0.1:8080
upgrade:  releases/932de69ff63e -> releases/a1eeefbc0b19   (both services active)
rollback: releases/a1eeefbc0b19 -> releases/932de69ff63e   (both services active)
deployable-runtime gate passed against the installed deployment (2 tests executed)
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

## Review round 5 — a failed gate must not leave a weakened database

`failed_runtime_preflight_does_not_rotate_the_active_api_credential`
deliberately weakens `identity_sessions_tenant_policy` to `USING (true OR …)`,
asserts that startup is **rejected**, and restores the policy only *after* that
assertion. A failed assertion unwinds past the restore, leaving row-level
security effectively off for reads — and `--keep` would have preserved the
volume with it, ready for someone to restart.

Verified by reading the test: weaken at line 562, assert, restore at 583.

**Fixing the test to restore on unwind is the better repair and is not this
ticket's file.** What this script owes is not to *preserve the result*: a flag
set around the gate makes teardown destroy the database on a failed gate even
under `--keep`, and say so in as many words. The deployment tree is still kept,
so the failure stays inspectable — it is the database, specifically, that does
not survive a gate that may have switched its RLS off.

Fourteen findings across five rounds (7, 3, 2, 1, 1), all mine, none disputed.

## Review round 6 — the fix for narration was narrating

Round 5's fix removed the volume with `podman volume rm -f … || true` and then
printed that it had been **REMOVED**. If podman refuses — the volume still in
use — the message reports a deletion that did not happen. That is the same
narrating-instead-of-refusing this script has been corrected for five times,
occurring *inside the correction for it*.

The removal is now verified rather than announced: `podman volume exists` after
the fact, and if the volume survives, teardown says so on stderr, names the
command to run, and **raises a zero exit status to non-zero** — because a run
that leaves a possibly-RLS-disabled database behind has not succeeded, whatever
the gates said.

Fifteen findings across six rounds (7, 3, 2, 1, 1, 1). Every one mine, none
disputed, and the last three are all the same sentence: **a claim you have not
checked is not a claim, it is a caption.**

## Review round 7 — the same claim in three places, and I fixed one

The row read `DONE` while **two further board sections** still said
`DEPLOY-001` held the active slot with its systemd acceptance unproven. Round 1
had raised this and I fixed the one block I was shown; the intro at line 26 and
the dispatch narrative at 1021 survived.

**The board gate cannot catch it**, and that is the part worth keeping.
`verify-execution-board.py` reads the *status column*; the contradiction lived in
prose. A green board gate does not mean the board agrees with itself — the same
shape as `HYG-002`'s finding that a green closure gate does not mean a row points
at its evidence.

Both sections now say what happened. The habit that would have caught it the
first time is the one this repository's own packs list four times and I have now
demonstrated twice in one shift: **after fixing a claim, grep for the claim, not
for the line you edited.**

Sixteen findings across seven rounds (7, 3, 2, 1, 1, 1, 1).

## Round 8 — self-found: the arm accepted a gate that asserted nothing

No reviewer raised this one. Step 10 ran the deployable-runtime gate and judged
it by **exit status alone**, and a Rust test binary that runs no tests exits `0`.
Measured against the real binary rather than reasoned about:

    $ deployable_runtime-86802c3e4c9636b7 --ignored --test-threads=1 nonexistent_test_name_xyz
    running 0 tests
    test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out
    exit=0

So a rename out of `--ignored`, a deleted test, or a stray filter would have had
the arm print `deployable-runtime gate passed against the installed deployment`
having verified nothing about it. **That is the defect this ticket exists to
remove** — the gate itself used to return success when
`MCLOVING_TEST_DATABASE_URL` was unset — rebuilt one level up inside its own fix.
The lesson generalises past this line: when you replace a vacuous check, the
replacement's own success condition is the next thing to distrust.

Step 10 now counts what executed and refuses `< 2`. `>= 2` rather than matching
the two test names: a rename still proves two behaviours, while a deletion, an
un-ignored test or a bad filter drops the count and is refused.

Perturbed before being believed, and against the block as shipped rather than a
retyping of it — the lines from `database_possibly_weakened=1` to the success
`echo` were extracted verbatim into a harness and driven three ways:

| gate under test | result |
| --- | --- |
| the real binary, filtered to zero tests (exit `0`) | refused by name, exit 1 |
| a gate that exits `101` | refused as failed, exit 1 |
| a gate reporting `2 passed` | accepted, flag cleared, `(2 tests executed)` |

The second case also confirms the ordering that matters: the refusal fires while
`database_possibly_weakened` is still `1`, so teardown destroys a volume whose
row-level security may be off rather than preserving it.

**What was not re-run:** the full ten-step lane. The transcript in this document
was produced by the previous revision of step 10; this change only adds
assertions after the point that transcript reached, and the block was exercised
directly as above. Saying which evidence is fresh and which is inherited is the
same discipline the rest of this document is about.

## Round 9 — self-found: the widened default-deny rule was unratcheted

Also unraised by any reviewer, and the more serious of the two. Admitting
`PODMAN_SYSTEMD_UNIT=%n` **widens a default-deny allowlist** — the rule whose own
message explains that an unenumerated loader hook executes code as the service
account before the program's first instruction. The allowance is written
correctly, pinned to the specifier by VALUE so it cannot designate another unit.

**Nothing tested that narrowness.** Relaxing it to `${entry%%=*} != PODMAN_SYSTEMD_UNIT`
would have broken no test. The sibling `PATH` pin — the same rule, the same
by-value reasoning — carries about 130 lines of gating in
`deploy/test-deployment.sh`, so this was a gap against the repository's own
established practice, in my own diff.

Gate `(5)` now pins it, and is proved both ways rather than asserted:

| library under test | gate |
| --- | --- |
| as shipped | passes: `%n` accepted; `mcloving-postgres.service`, `attacker.service`, `/srv/writable` and the empty value each refused **by name** |
| pin relaxed to a name match | **red** — "ACCEPTED `PODMAN_SYSTEMD_UNIT=mcloving-postgres.service`, so the allowance is matching the variable name rather than the `%n` specifier" |
| allowance deleted | **red** — the accept case fails, which is the Quadlet lane becoming unupgradable again |

The third row is also built into the gate itself, so the accept case cannot
silently stop testing the allowance.

**One mutation proved nothing, and is recorded rather than quietly fixed.** The
first attempt at the name-match mutant used `sed 's|…||…|'` on a pattern
containing `||` — the delimiter appeared inside the expression, sed failed, the
"mutant" was an empty file, and the gate went red with
`require_unit_environment_allowed: command not found`. **Red for the wrong reason
is not a passing mutation test.** A `cmp` guard that only asked whether the file
had changed accepted it. The mutant is now built in Python with the pin matched
exactly once, the line count held constant, and the function's presence asserted
in the output. This is the second time in two tickets that a mutation harness
mutated something other than what it claimed.

Eighteen findings across nine rounds (7, 3, 2, 1, 1, 1, 1, 1, 1) — sixteen
received, and the last two found by looking rather than by being told.

**On the correction-round cap, honestly.** Nine rounds is past the point where
this repository's own rule says to merge what is sound and open a design ticket,
and the rate has been flat at one for five rounds rather than declining. Two
things argue for finishing here instead. The findings stopped being about the
lane after round 3 — rounds 4 through 9 are documentation, teardown hygiene and
test ratchets around a core that has not changed since the first review. And the
last two are of *different* classes from the first sixteen: round 8 is a vacuous
success, round 9 an unratcheted security widening. That is what a search
broadening looks like once the original class is exhausted, not a tar pit.

What would change the reading is a round 10 that finds the LANE wrong — the
units, the ordering, the upgrade path. That would say the core was never
understood, and it is the thing to watch for rather than the round count.

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
