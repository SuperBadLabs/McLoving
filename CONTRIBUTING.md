# Contributing

All changes land through a protected pull request.

Before requesting review:

```text
./scripts/validate-foundation.sh
```

Every material change must update tests, documentation, the execution board,
and threat-model or architecture records when its boundary changes. Unsupported
behavior must remain explicit and must never be represented as successful.

Use `codex/` for Codex implementation branches. Keep commits coherent and do
not mix unrelated repairs into a ticket.

## Closing a ticket

Two artifacts are checked mechanically by
`scripts/verify-ticket-closure-receipts.py`, which the Architecture records job
runs on every pull request. Before a board row may read `DONE`:

* write `docs/evidence/<TICKET>_SECURITY_REVIEW.md`. It must name the ticket
  it closes and be a real headed document -- an empty file at the right path
  is not a receipt, and the gate rejects one, and
* review `docs/threat-model/README.md` for every affected boundary and record
  the affected threats, mitigations, verification evidence, and residual risks
  there under the ticket's name, **in a table row or a section heading**. An
  unchanged section still needs an explicit reviewed no-change receipt that
  names the ticket, because a boundary nothing mentions is indistinguishable
  from a boundary nobody looked at.

Attribution has to be structural because a substring is not a review: a line
reading `TODO: <TICKET> has not been reviewed yet` mentions the ticket exactly
as well as a real review section does, and the gate used to accept it.

A ticket that genuinely owes neither -- a docs-only or board-replan ticket --
needs an exemption in that script naming the ticket and stating why. The
script also carries a debt ledger of tickets that closed before the gate
existed without either artifact; it is reported on every run and may only
shrink. Do not add to it to make a build pass, and do not turn a real gap into
an exemption: both hide exactly what this gate exists to surface. Run
`scripts/verify-ticket-closure-receipts.py --strict` to see the debt as
failures.

Both ledgers are capped at their current size, so "may only shrink" is now the
gate's behaviour rather than this paragraph's request. Pay an obligation down
and lower the cap in the same commit. Raising one is possible and is meant to
be conspicuous: it is a recorded admission that closure discipline moved
backwards, and it belongs in its own commit that says why.

## Source-acquirer tests on hosts that restrict unprivileged user namespaces

The `mcloving-source-acquirer` suite drives a sealed launcher inside a kernel
user namespace. On a host with `kernel.apparmor_restrict_unprivileged_userns=1`
(the Ubuntu 24.04+ default), an unconfined run cannot execute the sealed
launcher there, and credential-bearing acquisition is refused by name as
`transport_namespace_unavailable`. The standalone test asserts that named
refusal in that environment -- nothing is skipped -- but the full acquisition
path only runs under the deployment AppArmor profile, which grants exactly
`userns create`.

To exercise the full path locally, do what
`.github/workflows/foundation.yml` does:

```text
bash scripts/prepare-source-transport-test-filesystems.sh
sudo apparmor_parser --replace --skip-cache \
  deploy/apparmor/mcloving-source-acquirer
aa-exec -p mcloving-source-acquirer -- \
  cargo test --locked -p mcloving-source-acquirer -- --test-threads=1
```

The transport roots under `/tmp/mcloving-source-transport-*` are host-global:
do not run two suites against them concurrently, and do not rebuild the crate
while a suite is running.
