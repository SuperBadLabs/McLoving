# CI-002 security and verification-integrity closure

Date: 2026-08-31

`CI-002` closes one failure class: a green gate that did not execute the
security or recovery contract it appeared to represent. It changes no shipped
runtime code, API, credential, protocol, persistence schema, deployment unit,
or production authority.

## Findings closed

The default workspace run discovered the `destination-observer` integration
target but compiled every test out unless `loopback-test` was enabled. Hosted
Foundation never enabled that feature for this crate, while the canonical
local gate did. The focused all-feature target executes 58 contracts covering
read-only destination observation, request and receipt substitution, freshness,
credential separation, restart, timeout, and permission-negative behavior.
Foundation now runs that exact target, runs all-feature Clippy, and requires an
exact 58-test summary.

The 30-test `execution-spine` integration target returned early from its
PostgreSQL tests when `MCLOVING_TEST_DATABASE_URL` was absent. The default
workspace job consequently reported the target green in roughly 0.01 seconds.
The hosted PostgreSQL job did not invoke it at all. That job now runs the real
spine serially with its database URL, together with the previously local-only
unsupported-spec, controller differential/capability, and shipped remote-agent
identity, long-lease, and execution gates. This brings the hosted job back into
line with `scripts/test-controller-postgres.sh`. Every newly authoritative
focused target requires the database URL before Cargo starts and proves its
exact test denominator (1, 30, 2, 1, 2, 3, 1, and 2 respectively), so deleting
the job environment, compiling out tests, or shrinking a target fails closed.

The first complete local run then found a live race in the remote-agent gate:
it counted two tenant work-ready notifications and assumed the second meant the
build was terminal. The channel is deliberately a wakeup rather than a typed
lifecycle stream, so admission, claim, lease release, terminal publication, and
other tenant work can all notify it. The gate observed `running` and failed.
It now re-reads PostgreSQL after each matching wakeup and stops only when the
durable build status is terminal. This preserves event-driven waiting without
reintroducing fixed polling or counting transport details as state truth.

The second complete run exposed an independent harness race: the remote-agent
tests reserved a loopback port by binding and releasing it before launching a
child process, while sibling tests ran in parallel and could claim the same
port in that handoff window. The canonical local gate and hosted commands now
run each focused process-launching test binary with one test thread. The tests
remain event-driven and independent, but their necessarily non-atomic port
handoffs can no longer collide with a sibling in the same binary.

The harness retains PostgreSQL migration authority, but the shipped agent
processes now explicitly remove `MCLOVING_TEST_DATABASE_URL` from their child
environments. This keeps the hosted security evidence faithful to production:
agents exercise the mTLS controller protocol without inheriting the harness's
database connection configuration. The hosted trust-auth service remains
network-reachable on loopback, so this is credential/configuration separation,
not a network-isolation proof; a child that independently guessed the test
endpoint would remain a residual of the local test topology.

The backup/restore drill invoked six exact ignored Rust canaries and trusted
their exit status. Cargo exits zero when an exact name matches no test, so a
rename or deletion let the script print all three recovery receipts after six
zero-test runs. Each canary now captures its focused test-binary output and must
prove exactly one passed test through `scripts/verify-rust-test-execution.py`.
That verifier is mutation-oriented: its tests require zero, partial, missing,
multiple, and failed summaries to be refused.

Finally, hosted Foundation omitted both compatibility checks present in
`scripts/validate-foundation.sh`. The architecture job now installs Clojure CLI
1.12.4.1618 through setup-clojure commit
`4c7a6f613e5089821bb3bb2a33a3ee115578580d`, then runs the Clojure compiler and
protocol suite plus the plugin-directory contract. The Clojure runner itself
requires the complete six-test denominator, so removing a namespace or every
`deftest` cannot become a green zero-test run.

## Threat-model review

The affected verification evidence belongs to TM-003 through TM-007 (session,
lease, restart, cancellation, and reconciliation), TM-009 and TM-020
(fail-closed compatibility), TM-010 (independent observer and effect joins),
and TM-017 (restore fencing). Their production mitigations are unchanged;
`CI-002` makes their existing executable evidence run on every Foundation pull
request instead of relying on local coverage or a successful process status.

The action pin closes mutable-action substitution at the workflow boundary,
but that pinned action downloads a version-addressed Clojure installer script
without a repository-owned digest. That release asset, and normal Maven
resolution for the version-pinned but not content-locked dependencies, remain
upstream availability and repository/artifact-substitution trust residuals.
The PostgreSQL tests still contain explicit local no-database returns so a
plain developer workspace run remains convenient; the hosted job's declared
database environment and direct focused invocations are now the authoritative
evidence. Windows-specific contracts remain owned by the separate protected
Windows workflow.

## Verification

- `python3 scripts/test-verify-rust-test-execution.py`
- `bash -n scripts/run-verified-rust-test.sh` and its missing-database negative path
- `bash -n scripts/test-backup-restore.sh`
- `shellcheck -x -P scripts scripts/test-backup-restore.sh`
- `cargo test --locked -p mcloving-destination-observer --all-features --test observer_contract`
- `clojure -M:test` and `compat/jenkins-worker/test-plugin-directory.sh`
- the focused PostgreSQL and agent commands added to the hosted workflow
- `python3 scripts/test-execution-board.py` and `python3 scripts/verify-execution-board.py`
- `python3 scripts/test-ticket-closure-receipts.py` and `python3 scripts/verify-ticket-closure-receipts.py`

The full Foundation and Windows workflows remain the merge authority. This
receipt grants no migration, connector, effect, canary, cutover, rollback, or
decommissioning authority.
