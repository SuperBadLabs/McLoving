# AGENT-009 candidate security evidence

This is a candidate receipt for the leaf `/root/milestone_m2/agent009`, based on
`4fa136de9515cf0ac6c423bfc9bd19d0ebc5c45a`. It records local observations made on
2026-10-07 UTC. It grants no ticket closure, merge, production, or decommission
authority. The execution board and protected Foundation/native Windows gates
remain authoritative. Full independent review must bind the final source hashes;
earlier reviews before the private-HOME correction are historical.

## Changed boundary

Rootless Podman storage is discovered with bounded `info` at session open and
confirmed under explicit graphroot/runroot/driver/options. Those exact flags are
used for confirmation, launch, teardown and recovered reap. Bootstrap discovery
must consult the deployment's storage configuration before its tuple can be
resolved. `STORAGE_DRIVER` also fixes Podman's internal ID-mapping reexec.
The v3 journal identity preserves byte-exact runtime, store/options, controlled
configuration/HOME/mounts paths and optional original HOME/runtime/user/temp
inputs, distinguishing unset, empty, non-UTF-8 and delimiter-bearing values.
Original HOME is a bootstrap input; actual workload HOME is the private installed
configuration root. Recovery compares a freshly resolved context before proving
absence, and legacy v2 identities park.

The private mode-0700 root, `.config`, and `.config/containers` hold service-owned
regular, no-follow, single-link mode-0400 containers.conf/storage.conf and an
empty mounts.conf. Actual Podman reads mounts from HOME independently of
CONTAINERS_CONF and XDG_CONFIG_HOME. Installer configuration creation occurs
under transition exclusion, with pre-mutation ancestor checks and locked
fresh/established integrity classification; partially created roots are refused.
Configuration-file inventories remain separate from `.env` contract parsers.
IR container admission and the independent executor reject leading-# names,
equals, multiline and NUL contracts before workspace mutation/serialization.
Plain host-process semantics retain their existing boundary.

## Actual proof and discriminating controls

Canonical raw logs and machine-readable receipts are retained in
`/tmp/mcloving-milestones/M2/AGENT-009/`; the final source/receipt manifest binds
all their hashes. These paths are local evidence, not durable publication.

| Requirement | Actual retained evidence |
| --- | --- |
| Real storage configuration drift | `green-private-storage-authority` and `green-byte-restored-remote11`: exact expected graph/run/vfs values in the matching durable row; real storage.conf edit; named production refusal `effective store changed; absence unproven`; matching controller attempt parked, zero terminal rows/events, original-store container alive. |
| Restoration and discharge order | The same test restores configuration, observes `effective store matches journal; proving original-store absence`, verifies original container absence while controller remains parked, then invokes existing `Store.finalize_reconciled_attempt` with actor `AGENT-009-owned-storage-fixture-operator`; real attributed operator receipt precedes local journal retirement. Independent PGID uncertainty is explicit and never silently discharged. |
| Genuine implicit mounts | `green-private-mount-diagnostic` and final remote11: uncontrolled Podman exposes `host-only-mount-secret`; controlled agent step excludes the sentinel while workspace is writable. |
| Specific private-HOME mutation | `mutant-private-home`: fetched controller stdout contains `workspace-writableunintended-sentinel-present:host-only-mount-secret`, distinguishing the mount defect from engine/workspace setup failure. Candidate source is byte-restored. Earlier generic failed-build RED is explicitly unearned for this specific claim. |
| Independent name refusal | Actual original IR implementation admits the leading-# name (RED); candidate admission and direct executor tests pass. Removing each independent guard separately causes its named semantic test to fail; both candidate files are byte-restored. |
| Store identity mutation | Removing the recovery equality check fails the required named storage refusal. Independent PGID parking alone cannot satisfy this assertion. Candidate source is byte-restored. |
| Installed lifecycle and custody | `scoped-deployment-receipt.json`: 41 commands comprise 16 strip/provenance operations and 25 actual shipped transitions, with five positive and twenty intended refusals; install/reinstall/upgrade/rollback, lock exclusion, partial-root refusal, writable/hardlink/symlink/nonempty/missing/private-directory adversaries. `installed-guard-receipt.json` records actual installed guard positive/refusals/restored positive. |

The pre-lint byte-restored integration receipt `green-byte-restored-remote11.json` records
11 passing tests in 42.283 seconds, log SHA-256
`0365edce6b01448ade463631113eef95919f1e0427d44c9fac845ca773527b72`.
The later rebuilt-agent receipt `green-final-lint-restored-remote11.json`
records all eleven tests passing in 37.527 seconds after the equivalent parser
cleanup, log SHA-256
`f77f59e20692dce56340a35cb50b30ebed7ca16be71457dbd6724f696f72b3e8`.
The changed-package all-target campaign `green-final-required-all-targets`
passed 272 tests with zero failures in 222.845 seconds. Two dedicated
JCOMP-003/Windows targets are ignored; they are not earned by this Linux run.
Its long-step floor is eight tests on the qualified baseline; later protected
AGENT-008 composition has a ninth test and must preserve that separate gate.
The final four-input identity regression separately passes its fully qualified
named unit. Final Clippy with warnings denied passes after two equivalent
let-chain cleanups; the earlier lint failures remain unearned semantic proof.

Existing pinned-image, isolation/workspace/environment, timeout/recovery,
artifact, multi-step and container gates remain present. Bounded discovery tests
retain missing/nonzero, malformed/oversize, deadline and exact-byte identity
regressions. Required remaining test/lint results are recorded individually in
the final canonical receipt, rather than inferred from source counts.

## Qualification limits and historical failures

The deployment campaign executes actual shipped entrypoints with `--no-systemd`,
private roots, real binaries and private PostgreSQL. Its release artifacts are
two differently stripped forms of the same built product: this is lifecycle
integrity proof, not predecessor-version compatibility. No live service-manager
execution is claimed. The full deployment driver retains the focused new custody
test and remains a separate Foundation obligation. Legacy deployments without
new assets require actual installation/reinstallation plus environment enrollment;
upgrade alone does not create the private configuration. Legacy v2 journals park.

Initial live fixtures omitted `rootless_storage_path`; bootstrap selected the
owner's ambient store. Those private-store qualifications are void and their raw
logs retained. Historical Drop source used explicit private store flags, but no
per-command effective-info/global inventory receipts were captured, so this
receipt cannot assert the owner's whole store remained unchanged. Only the
attributed accidental container `mcloving-3189c9af-ea1c-4175-9c20-922e100f2df5-0`
(build `20ca063f-67ac-4688-9c78-a576f21bd42b`) was narrowly removed after inspection;
`unearned-global-fixture-cleanup-bounded.json` records successful removal and
exact absence. No global reset, rm-all, image or volume cleanup is claimed.

Corrected fixtures require actual bootstrap and pinned info to match exact owned
private graph/run/driver/options before their first workload. Mismatch permits no
cleanup mutation; failed absence/custody verification preserves diagnostic paths.
Successful cleanup records explicit argv/environment, exact effective info,
rm/empty-list/reset/post-reset container/image absence and bounded owned store
custody. The private PostgreSQL 17.6 fixture has network=none, no published ports,
512 MiB private PG-data tmpfs and private-ancestor Unix sockets. Final exact
cleanup is independently verifiable through the canonical cleanup receipt.

Setup/compiler/fixture failures are retained as unearned semantic proof, including
incorrect private fixture directory modes, missing helper environment, accidental
ambient store selection, Podman ID-mapping reexec configuration, and a reinstall
parser defect corrected by preserving separate configuration inventories.

## Residual threat scope

TM-003 recovery authority, TM-023 agent/runtime input custody and TM-052 container
configuration are affected. Same-account/root operators can replace service-owned
configuration despite mode 0400; they remain trusted. Rootless runtime escape,
kernel/storage failure and SEC-005 host-process execution remain residual risks.
Store absence does not remove the independent process-group or authorized
controller-discharge boundary. No controller protocol/persistence/migration,
credential, connector, enrollment or decommission authority changes are intended.
Independent review must assess those boundaries and current-base composition;
local passing tests cannot substitute for protected or post-merge receipts.


## 2026-10-07 UTC: source continuation after hosted CI failures

The earlier qualification above is a historical observation on its recorded
baseline. For the candidate observed at
`66a0cd4763da140deb0f561d03adb4793a6ee44e`, based on
`dc5c58e85f0835d9761beffa330d46d960139e10`, the retained hosted Windows job
112594812386 failed the unconditional storage-options unit test: 80 passed,
one failed at `container.rs:272` because `/private/graph` and `/private/run`
are not absolute Windows paths. Its raw log SHA-256 is
`33f7d93f310e4a1ce15d731822929cd9c4256211dc12f9532149ff46192cfabe`.
The test fixture now joins graph/run paths below a canonical actual temporary
root and serializes them with `serde_json::json!`, preserving platform escaping.
Mount-program option shape/preservation, relative-path refusal and unknown-shape
refusal remain tested on Windows; production absolute-path checks are unchanged.

Hosted PostgreSQL job 112594706823 actually ran all eleven remote-work tests:
11 passed, zero failed/ignored in 47.97 seconds, then its exact-count gate refused
the obsolete expected count of nine. The direct raw log SHA-256 is
`16baebeb0b44448aecc92cc50e460f4597c90446af38afc23e5ae87478dfd563`.
Foundation and `scripts/test-controller-postgres.sh` now require exactly eleven
remote-work tests. Long-step's nine-test floor, existing CLI build/environment
wiring, mandatory HYG archival checks and every other count/oracle remain in
place. Neither a generic gate relaxation nor a test skip is introduced.

This continuation records source authoring and retained failure readback only.
Fresh scheduled native verification, the named Windows test and full hosted
Foundation/Windows reruns on the revised candidate are still owed. The original
three-clause acceptance remains ACTIVE; no revised green result or ticket closure
is claimed. Historical receipts and threat scope above are retained verbatim.
