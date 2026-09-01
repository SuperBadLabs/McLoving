# DEPLOY-003 deployment-manager truth closure

Date: 2026-08-31

`DEPLOY-003` closes the deployment lane's non-converging validation surface.
On a real service-managed deployment, systemd is now the authority for what it
loaded, merged, expanded, and will execute. The retained shell model is an
explicitly labelled fallback for `--no-systemd`, image construction, and a
fresh install before its first `daemon-reload`; it is no longer accepted as
service-managed evidence.

This ticket grants no production, Jenkins, connector, canary, cutover,
rollback, or decommissioning authority.

## Manager truth and union validation

`deployment_manager_unit_facts` reads typed D-Bus JSON rather than parsing the
human rendering of `systemctl show`. For every native service and every service
Quadlet generates, two atomic `GetAll` calls obtain:

- `FragmentPath` and the exact composed `DropInPaths`;
- every `ExecStart`, `ExecStartPre`, `ExecStartPost`, `ExecReload`, `ExecStop`,
  `ExecStopPost`, and `ExecCondition` path and argv array;
- `EnvironmentFiles`, `WorkingDirectory`, and the state/cache/log directory
  lists after systemd parsing and specifier expansion;
- the composed `Environment` and `UnsetEnvironment`; and
- the runtime `NoNewPrivileges` verdict.

The manager's `LoadState` and `UnitFileState` now refuse an effective mask
directly. A masked answer is not reclassified as “manager unavailable” and is
not re-derived from a symlink. Manager mode is mandatory after `daemon-reload`:
failure to obtain any typed fact refuses the transition rather than falling
back to the shell parser.

Selection and precedence no longer carry the adversary-A security verdict.
`UnitPath` itself is a typed D-Bus string array, preserving whitespace and path
boundaries. Every root, including an absent root whose nearest existing parent
is its creation bound, takes the ancestor rule. Every extant candidate fragment
across the manager's complete `UnitPath` takes the ancestor and integrity
rules. Quadlet input is a separate namespace: the manager's typed
`QUADLET_UNIT_DIRS` replacement is consumed when present, Podman's defaults
apply otherwise, and every source root is walked recursively. Every extant
candidate across that complete source-search union is judged too;
generated output is covered by `UnitPath`. Every extant drop-in across every
type-wide, dash-truncated, template, and exact directory in both namespaces is
part of the same union. The real-manager arm places same-name files at two
precedence levels and requires both candidates even though the manager's
active `DropInPaths` reports only the higher one. A lower-precedence candidate
cannot escape because it is inactive at the instant of review. The selected
`FragmentPath` and exact `DropInPaths` remain operational truth, while the
security property is additive.

O4 remains deliberately local: systemd reports an `EnvironmentFiles` wildcard
literally, so the lane still judges the pattern's containing-directory bound
and every current match. O6 also remains local: manager state cannot prove the
identity, ownership, mode, or bytes of a release, helper, command, contract, or
unit source. The existing artifact and ancestor gates are unchanged.

The controlled manager fixture proves line continuation, quoting, C-style
escape, command prefixes, `%h`, and a non-`%h` specifier are resolved rather
than guessed. It also records one correction to the architecture note's
measurement: on systemd 255 the typed `ExecStart` tuple leaves a bare
executable bare rather than resolving it to an absolute path. Manager mode
therefore retains the same named fail-closed refusal for that spelling; no
search path is guessed. Both fixtures are removed and the manager is reloaded
before service evidence begins.

## Transition and process-identity fixes

Install retains its pre-create ancestor check, then re-runs full deployment
integrity immediately after acquiring the same exclusive transition lock used
by upgrade and rollback. After publishing units it performs `daemon-reload`
and, while still holding that lock, performs the mandatory typed manager pass.
No sanctioned transition can change the tree between install's verdict and
lock acquisition, and no pre-reload manager cache is accepted as the new
configuration.

The transition health path no longer returns `/proc/$PID/environ` for another
process to open later. It samples the manager's invocation id, main PID, and
monotonic exec-start timestamp, opens the environment immediately, compares
the `/proc` start time, re-samples the exact manager tuple, and copies only
through the held descriptor. PID reuse can no longer redirect the later read
to an unrelated process.

Every fallback diagnostic now labels unit selection, hook stripping, cache
root, and data root as manager-derived or shell-derived. On a loaded manager,
hook stripping and all managed-directory roots come from composed properties;
the different-semantics hook fallback cannot be mistaken for manager truth.

## Runtime hardening

`NoNewPrivileges=yes` is required on the controller, agent, and database-init
services. It is deliberately absent from the two generated Podman services:
an implementation-time fresh-account probe measured rootless namespace
creation fail before startup because the bit prevents Podman's required
`newuidmap`/`newgidmap`
setuid transition (`newuidmap: write to uid_map failed: Operation not
permitted`). This is a measured compatibility boundary, not an inferred
exception. The disposable account performs no Podman operation before the
generated volume unit, so a persistent pause namespace cannot mask the result.
The real arm requires the manager's exact yes/no split, reads kernel
`NoNewPrivs: 1` from both live native MainPIDs, uses an in-unit probe for the
exited database-init oneshot, and runs the cold rootless volume/container,
database bootstrap, controller, and agent.

## Reproducible per-PR systemd evidence

The protected `Deployment lane` job now runs both halves in order:

1. the unchanged fallback smoke specification, including its 600 named
   refusal sites; and
2. the service-managed arm under a disposable account on the same fresh
   `ubuntu-24.04` runner.

The hosted 20260823 image exposes `/usr/share`, `/usr/share/containers`, and
`/usr/share/systemd` as root-owned mode 0777. The fallback union correctly
refuses those future source/drop-in creation points. Because the job owns the
disposable VM, its preparation removes group/world write from those exact
package ancestors before running the unchanged refusal specification; any new
unsafe ancestor still fails by name.

The first protected run (`33463706014`, job `99719163651`) on image
`20260823.283.1` also exposed a distinct packaging assumption: the image's
Podman 5.8.4 static bundle
puts `podman`, Quadlet, and its user-generator symlink under `/usr/local`, while
Ubuntu's distro package puts the version-matched trio under `/usr`. The arm had
hard-coded the distro generator path and refused before account creation after
the fallback matrix had passed. The shared host preflight now maps only those
two explicit command layouts to their exact generator and Quadlet target,
requires one layout (never a mixed or discovered-first layout), checks root
ownership and no group/world write on every fixed input, checks the symlink
target and Quadlet version, and prints both executable hashes without invoking
Podman. Podman 4.9 was measured initializing rootless state even for
`--version`, so the selected command's version is read and compared with
Quadlet only after the generated volume unit has performed the first Podman
operation.
It also refuses `/run` and `/etc` overrides and a second vendor generator. The
same resolver runs before the expensive matrix and again under the disposable
account. Those hashes are exact run evidence, not a repository-enforced bundle
pin; the image provider's authenticated manifest owns the download checksum.
After generation, typed manager facts retain the exact `Exec*` property name
and command tuple. Every generated `ExecStart`, plus every present `ExecStop`
and `ExecStopPost`, must execute the selected Podman path exactly. This binds
the recorded generator/runtime identity to the cold lifecycle without
mistaking an absolute argument, or a command belonging to another phase, for
the start command executable.
The per-PR closure claim remains conditional on a successful protected run at
the corrected exact head, and that result remains the merge authority.

The correction's first protected run (`33467033677`, job `99728923622`) then
proved why preflight belongs first: it refused in eight seconds because the
hosted image also exposes `/usr/local/bin` as root-owned mode 0777. This is the
same image-owned ancestor class as `/usr/share`, not a production exception.
The disposable job now removes group/world write before preflight from only the
fixed `/usr/share` union roots and the explicit `/usr/local` Podman/Quadlet
ancestor chain; the validator and fallback specification remain unchanged and
still refuse any new writable input by name. Fixed layout components other than
the one expected generator link must also be non-symlinks.

The next protected run (`33467671252`, job `99730797321`) passed that directory
normalization and refused in the same eight-second preflight because the
static `/usr/local/bin/podman` executable itself is also mode 0777. The known
hosted-bundle normalization therefore covers exactly its two expected regular
executables, `podman` and Quadlet, as well as their fixed directory chain. It
refuses to chmod a symlink or non-root-owned file and requires the exact reviewed
image-provider digests before changing either mode; an image revision therefore
fails closed until its pins are reviewed. The unchanged validator then repeats
the exact-target, root-owner, non-writable, version, and hash checks.

Protected run `33468046013` (job `99731881671`) then passed those digest pins,
the controlled-input preflight, the full fallback/adverse suite, and exact
release construction. Its wrapper refused before invoking the real-manager arm:
the image account's `/home/runner` is mode 0750, so disposable uid 1002 could
not traverse to the runtime gate and release beneath it. The two later
`/home/runner/.config/containers/storage.conf` messages came from failure-only
Podman diagnostics, not Quadlet, and exposed a separate environment-boundary
flaw. The workflow now requires the exact image-owned home mode and owner, then
adds only search permission (0750 to 0751) immediately before the disposable
account run and restores 0750 on every exit path before later workflow steps.
The wrapper names each traversal failure and never invokes Podman
from diagnostics, preserving the generated volume unit as the cold first
operation.

Independently, the wrapper starts the manager with explicit account-local HOME
and XDG bases, exact account identity/path/locale values, and controlled unit
and Quadlet paths. The disposable `user@UID` drop-in replaces `ExecStart`
directly with `/usr/bin/env -i`, the exact fourteen-entry block, systemd's
single expanded `NOTIFY_SOCKET`, and `/usr/lib/systemd/systemd --user`; no shell
or inherited executable lookup runs before the environment is cleared. Thus
neither the system service manager nor PAM can contribute to the manager
process environment. The wrapper also requires its controlled PATH to equal
the user manager's compiled `systemd-path search-binaries-default`, so systemd's
documented PATH normalization cannot give initial or reload generators a
different input. Every account command uses a direct UID/GID
transition from an empty client environment, avoiding later PAM sessions that
could re-import host variables into the live manager. All installed user
environment-generator basenames are masked at the highest-precedence runtime
directory before manager startup, preserving the exact block across every
later `daemon-reload`. Before D-Bus starts, the
wrapper uses the manager's private socket
to install the exact fourteen-entry environment and remove every inherited
extra, then proves exact count and value. D-Bus therefore inherits the same
block. A typed atomic manager transaction and typed exact-count/value readback
repeat that proof after D-Bus is live and before the first Podman operation, so
user-environment generators cannot override the verdict.

Protected run `33470333291` (job `99738626192`) passed traversal, then
refused because the hosted manager retained an unrelated image variable
mentioning `/home/runner`, even though every security-relevant
HOME/XDG/identity/path and container-selector assertion had passed. A broad
value-substring deny rule is not an environment boundary. The wrapper now
sanitizes the live manager before D-Bus inheritance, then reads only inherited
variable names through typed D-Bus and atomically replaces the manager's entire
environment block with exactly the fourteen required
HOME/XDG/identity/path/locale/unit/Quadlet/D-Bus entries, and requires an
exact-count plus exact-value typed readback before the arm starts.

Protected run `33473297249` (job `99747328219`) proved that manager API
unsets cannot remove the environment inherited into the manager process by
`user@.service`'s process environment: the hosted image variables remained
after every bounded unset. The disposable manager drop-in now replaces
`ExecStart` with the direct exact-environment invocation described above, moving the
boundary before manager process creation rather than claiming a runtime API
can erase the inherited base. The wrapper also masks the complete user
environment-generator namespace, because those generators otherwise re-read
host environment configuration at startup and reload independently of PAM.

Protected run `33475226048` (job `99752965064`) passed the complete manager
environment boundary and typed query fixture, then refused the first install
because the hosted `/home` default ACL produced group-writable 0775 XDG parent
directories despite the arm's 0022 umask. The wrapper now removes both inherited
access and default ACLs from a newly installed empty disposable home, restores
0755, and proves the exact owner/mode and three-entry ACL before creating any
account-owned child. `useradd --no-create-home` prevents `/etc/skel` descendants
from inheriting the host ACL before that proof. No existing account or shared
home ACL is modified.

Protected run `33476931957` (job `99758031256`) was the first to pass every
host-input, manager-environment, ACL, install, union, typed-query, command-path,
and runtime-policy gate and reach the cold service start. It exposed a real
version-dependent readiness contract. Quadlet 4.9 treated `Notify=healthy` as
conmon readiness, while the selected Quadlet 5.8.4 generated
`--sdnotify=healthy`. The first attempt reached `Writing manifest to image
destination` and then systemd enforced the shipped 300-second start bound. A
second attempt emitted no pull progress and reached the same exact timeout.
Because the original teardown erased the generated units and container before
diagnostics, that run alone cannot distinguish pull finalization, storage,
container creation, or health-wait state. Version-matched Podman source explains
the observed repeated shape: its healthy-notify path waits without a
retry-derived deadline; `HealthRetries=12` can mark the container unhealthy but
does not bound that wait.

The Quadlet now explicitly selects the stable conmon notification mode with
`Notify=false`; the real-manager gate reads the generated `ExecStart` argv from
typed manager properties, requires `--sdnotify=conmon`, and refuses both
`--sdnotify=healthy` and `--sdnotify=container`. PostgreSQL health remains
fail-closed at the existing db-init barrier: it requires two successive
`pg_isready` successes within a bounded loop before any migration or
provisioning, and the controller requires that successful oneshot. Container
health metadata remains available for observation without becoming an
unbounded unit-start dependency. A nonzero arm now captures secret-safe unit
state, status, journals, and—only after rootless state proves the cold-first
boundary was crossed—container state and logs before teardown removes them.
That evidence block is skipped while the runtime gate may have left database
row-level security weakened, so no diagnostic query can delay immediate
service teardown and removal of the proof database.

The wrapper makes clean state true by construction. Before starting the
account's manager it supplies an exact `SYSTEMD_UNIT_PATH` containing only
that account's home/runtime paths and one root-owned, read-only bind of the
packaged vendor units. `QUADLET_UNIT_DIRS` admits only two account-private
source directories; the selected fixture exists in a nested custom root, so
the proof exercises replacement and recursive-search semantics rather than
coinciding with Podman's default. Higher-precedence Podman generators, a
second vendor generator, and every unrelated user-generator basename are
refused or masked for this ephemeral job. The selected generator is the exact
root-owned member of the version-matched Podman layout rather than an assumed
`/usr` path. The arm
asserts the manager retained both exact boundaries, lets the generated volume
unit perform the first Podman operation and the generated container unit
cold-pull the pinned image,
then proves install, Quadlet generation, dependency ordering, runtime
hardening, ordered start, stability, health, upgrade, rollback, and both exact
deployable-runtime tests. Failure captures unit status, the user journal,
mount state, and tool versions before removing the account; it deliberately
does not invoke Podman because a pre-arm failure has not crossed the cold-first
operation boundary. The inner arm's guarded evidence block may invoke bounded,
secret-safe Podman observations only after both the start attempt and an
on-disk rootless store prove that boundary was crossed.

The arm snapshots configuration, state, runtime, manager `UnitPath`, and
Quadlet roots once and reuses that model for probe, optional reset, and
teardown. A mutable shared-host re-derivation is not part of protected evidence.

## Audit-observation disposition

The seven observations carried by `DEPLOY-001` are disposed as follows:

1. **Discarded mask answer — closed.** The manager states are consumed as the
   operational refusal.
2. **PID-recycling window — closed.** Environment capture is descriptor-held
   and tuple-bound as described above.
3. **Four unlabelled fallbacks — closed.** All four are labelled, and loaded
   manager transitions use typed composed properties plus both unions.
4. **Install integrity outside the lock — closed.** The complete verdict is
   repeated inside exclusion and after reload.
5. **Environment-guard ancestor walk without the transition lock — retained
   with reason.** Upgrade and rollback hold the exclusive lock while starting
   units and waiting for their guards. A guard that acquired the shared side
   would deadlock; a non-blocking acquisition would make every sanctioned
   transition fail. The lock coordinates sanctioned transitions and cannot
   stop root, the service identity, or an attacker who already has filesystem
   mutation authority. The ancestor invariant proves another local user lacks
   that authority at each walk; the documented residual remains lack of
   TOCTOU-freeness rather than a fictitious guard lock.
6. **Missing `NoNewPrivileges` — closed on the three compatible native
   services; explicitly deferred on both generated Podman services.** The real
   protected arm proves the native kernel bits and the NNP-disabled cold
   rootless lifecycle. It does not recreate the incompatible NNP-enabled
   namespace attempt in CI; the exact `newuidmap` failure above is the separate
   fresh-account implementation measurement supporting this explicit
   deferral. Manager validation requires the resulting yes/no split so a warm
   host cannot silently substitute a different policy.
7. **No mandatory start-time verification of the unit, guard, and selected
   release — explicitly deferred to an external trust anchor.** A check named
   by a replaceable user-owned unit cannot verify that unit: substitution can
   omit the check. A helper in the same writable ownership domain cannot make
   itself mandatory. The accepted next boundary is `DEPLOY-002`, where the
   complete release is installed and may require root/system-manager policy.
   Until that external anchor is implemented and revalidated, the lane proves
   transition-time integrity but does not claim that an ordinary or crash
   restart detects permission drift occurring after the last transition.

The last item is a real residual, not a credit. It remains a production
qualification blocker through `DEPLOY-002`; `DEPLOY-003` does not claim an
in-unit self-check can establish an out-of-unit trust root.

## Threat-model review

The changed boundary is TM-050. No authentication, authorization, tenant,
protocol, database schema, connector, migration, or production-effect contract
changes. The service account still owns its deployment tree; workload
containment against that account remains `SEC-005`. The operator, root, kernel,
and sound host directory configuration remain trusted. The lane refuses a bad
host but does not repair it, and the containing-directory guarantee remains a
point-in-time bound rather than TOCTOU freedom.

## Verification

- `bash deploy/run-systemd-ci.sh --check-host`
- `bash deploy/test-deployment.sh`
- `bash deploy/run-systemd-ci.sh ...` driving
  `deploy/test-deployment-systemd.sh` on a controlled disposable account
- typed manager-fact fixtures covering the resolved spellings and the measured
  bare-executable refusal
- held-descriptor environment capture against a live user-manager service
- `bash -n deploy/bin/* deploy/*.sh`
- `shellcheck -x -P deploy/bin deploy/bin/* deploy/*.sh`
- `actionlint .github/workflows/foundation.yml`
- `python3 scripts/test-execution-board.py`
- `python3 scripts/verify-execution-board.py`
- `python3 scripts/test-ticket-closure-receipts.py`
- `python3 scripts/verify-ticket-closure-receipts.py`

Protected qualification of implementation head
`fd32508b6ca81bd48dae736ccf56be6ae93138aa` completed successfully in
Foundation run `33481452092` (deployment job `99771776176`) and Windows run
`33481452116`. The deployment job ran on the `ubuntu-24.04` image
`20260823.283.1` and bound the cold lifecycle to Podman/Quadlet 5.8.4 at:

- `/usr/local/bin/podman`, SHA-256
  `3ae655eb71d62e2b44c25d83364da99175458a0a5f9a77a91c51e99f0cba4d79`;
- `/usr/local/lib/systemd/user-generators/podman-user-generator`, targeting
  `/usr/local/libexec/podman/quadlet`, SHA-256
  `5d974f1eac4d69afe29b6ef68bf83f1248fb6f22f023f2af690d447c705c1b00`.

The protected real-manager arm passed all ten stages: exact environment and
manager boundaries, install, complete unit/Quadlet union validation, generated
`--sdnotify=conmon`, ordered cold start, native-process `NoNewPrivs: 1`, stable
controller and agent identities, health through the manager, service-managed
upgrade and rollback, and both deployable-runtime tests. Teardown completed
with status zero. The immutable run is
<https://github.com/SuperBadLabs/McLoving/actions/runs/33481452092>.

Protected exact-head qualification of this evidence commit and post-merge
Foundation/Windows workflow results remain the merge authority.
