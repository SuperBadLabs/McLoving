# State-transfer v1 fixtures

This directory contains the exact-profile `MIG-005A` Jenkins fixture used by
the forward and reverse rehearsal harnesses.

- `fixtures/init.groovy` configures the disposable, unauthenticated internal-only oracle.
- `fixtures/job-config.xml` exercises build-number state plus SCM `changeset`
  and `changelog` baselines while clearing only prior intent markers.
- `fixtures/repo/` supplies the initial, two matching, and final nonmatching revisions.

Run `scripts/test-state-transfer-rehearsal.sh` to create the two-build Jenkins
source epoch. Run the `state_transfer_rehearsal` controller-store example
against a fresh pinned PostgreSQL instance to import/replay/export the state.
Then run `scripts/test-state-transfer-reverse-reconcile.sh` against the stopped
runtime to import build 3 and prove Jenkins resumes at build 4 without stale
SCM decisions or duplicate effects.

The complete contract, accepted hashes, security boundary, and limitations are
documented in `docs/architecture/STATE_TRANSFER_V1.md`. These fixtures grant no
production trigger, scheduler, credential, agent, connector, or effect authority.
