# State-transfer v1 fixtures

This directory contains the exact-profile `MIG-005A` Jenkins fixture used by
the forward and reverse rehearsal harnesses.

- `fixtures/init.groovy` configures the disposable, unauthenticated internal-only oracle.
- `fixtures/job-config.xml` exercises build-number state plus SCM `changeset`
  and `changelog` baselines while clearing only prior intent markers.
- `fixtures/corpus052-job-config.xml` is the exact public pipeline definition
  used to reconcile the admitted job's one retained private build-history
  dependency.
- `fixtures/corpus052-template-job-config.xml` is a non-authoritative native
  `ShellStep` serialization fixture. Its controller replaces the global shell
  with a recorded non-executing stub, so the graph describes the admitted step
  without running its script; the controller is destroyed before destination
  continuity proof starts.
- `fixtures/repo/` supplies the initial, two matching, and final nonmatching revisions.

Run `scripts/test-state-transfer-rehearsal.sh` to create the two-build Jenkins
source epoch. Run the `state_transfer_rehearsal` controller-store example
against a fresh pinned PostgreSQL instance to import/replay/export the state.
Then run `scripts/test-state-transfer-reverse-reconcile.sh` against the stopped
runtime to import build 3 and prove Jenkins resumes at build 4 without stale
SCM decisions or duplicate effects.

For the exact admitted case, run
`scripts/test-corpus052-state-rehearsal.sh` with the owner-held sealed build
directory, expected public tree digest, opaque evidence identifier, and a new
private output directory. It verifies and normalizes the exact five-file
denominator, proves idempotent forward/reverse persistence against a fresh
PostgreSQL instance, and executes one externally effect-free McLoving build.
Then run `scripts/test-corpus052-jenkins-reverse.sh` with the sealed directory,
the independently pinned public tree digest, its opaque evidence identifier,
that transform output, an owner-private independently retained digest of the
enclosing rehearsal manifest, the pinned private plugin profile, and a new
output directory. Before any controller starts, it authenticates and verifies
the complete rehearsal manifest, copies every authenticated member into a
private snapshot, transfers it to root ownership with read access only for the
invoking unprivileged account's dedicated group (root invocation is rejected),
proves that UID cannot chmod or replace
the snapshot, reauthenticates it after lockdown, and reauthenticates
the exact five-file tree, proves build 1 equals the reverse bundle, and copies
exactly the committed 90-plugin manifest denominator with digest verification
before and after each copy. Both verified plugin trees are moved into
root-owned non-writable snapshots under the sticky temporary boundary,
reverified after lockdown, proven immutable to the invoking UID, and mounted
as 90 individual read-only `.jpi` files over separate writable plugin-expansion
directories in their controllers. A separate non-authoritative template controller
creates an exact native `ShellStep` graph through a non-executing shell stub.
The harness replaces its log and rebuilds the byte-offset `log-index` so the
complete transferred process log belongs to the exact ShellStep, remaps the
ShellStep start/end to the exact durable attempt while keeping every other
native workflow timestamp inside the canonical transferred interval, replaces
the nonrepresentable template queue ID with Jenkins unknown sentinel `-1`,
removes template cause/queue-timing actions, retains the exact canonical
trigger in a typed sidecar, proves no template marker or provenance remains,
byte-verifies the canonical trigger sidecar after install, restart, and
archival, and destroys the controller. The fresh destination controller then
loads the reverse-imported history without
executing build 2, verifies native workflow and log retrieval across restart,
executes build 3 once, proves contiguous numbering, and denies public network
egress. Both harnesses retain only owner-private evidence and grant no
production authority.

The complete contract, accepted hashes, security boundary, and limitations are
documented in `docs/architecture/STATE_TRANSFER_V1.md`. These fixtures grant no
production trigger, scheduler, credential, agent, connector, or effect authority.
