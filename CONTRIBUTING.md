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
  there under the ticket's name, in one of the three shapes that exist to
  record a review: a **verification-ownership row**, a **threat-register row**,
  or a **closure-review heading the ticket leads**. An
  unchanged section still needs an explicit reviewed no-change receipt that
  names the ticket, because a boundary nothing mentions is indistinguishable
  from a boundary nobody looked at.

Attribution has to be affirmative because neither a substring nor a shape is a
review. A bare mention let `TODO: <TICKET> has not been reviewed yet` close a
ticket; requiring a heading or a table row let
`## TODO: <TICKET> has not been reviewed yet` do the same; requiring the ticket
to lead the heading let `## <TICKET> review has not happened` do the same. Only
a structure whose sole purpose is recording a review counts, and a negation
veto then removes credit from a structure that reads as a denial.

Know what that is: a heuristic over English, not a decision procedure. Four
tightenings were each got past by one sentence in a new wrapper, and a denial
phrased without a vetoed word would still pass. The durable fix is a
machine-readable attribution field in the threat model -- a column holding a
ticket id and nothing else -- so the gate reads data rather than parsing
sentences. Until that exists, treat a green gate as evidence that the record
has the right shape, not that the review happened.

A ticket that genuinely owes neither -- a docs-only or board-replan ticket --
needs an exemption in that script naming the ticket and stating why. The
script also carries a debt ledger of tickets that closed before the gate
existed without either artifact; it is reported on every run and may only
shrink. Do not add to it to make a build pass, and do not turn a real gap into
an exemption: both hide exactly what this gate exists to surface. Run
`scripts/verify-ticket-closure-receipts.py --strict` to see the debt as
failures.

Both ledgers pin their **membership**, so "may only shrink" is the gate's
behaviour rather than this paragraph's request. A ticket may leave a ledger by
earning its artifact; none may enter. Pinning the size instead would not be
enough -- paying one historical debt while admitting one newly closed ticket
leaves the count unchanged, so a fresh gap gets laundered into a set that
exists to record old ones. Widening a baseline is possible and is meant to be
conspicuous: it is a recorded admission that closure discipline moved
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

## Declaring dependency edges

`scripts/verify-execution-board.py` checks that every edge you declare is well
formed. It now also asks whether an edge you did *not* declare is required: if
two tickets name the same file, helper or `TM-nnn` boundary in their acceptance
criteria, at least one of them is still open, and neither reaches the other
through the graph, the board fails.

The rule exists because four separate reviews found the same mistake -- long
fail-closed acceptance criteria with the edges underspecified -- and this
verifier passed cleanly on all four. A missing edge is not an invalid one, so
a well-formedness check could never have caught them. Tested retroactively
against those four boards, this rule catches all four.

Whole components are not boundaries: `bins/agent` is shared by everything that
touches the agent, so a path token counts only when it names a file. The
repository decides when it knows the path; for one a ticket is about to create,
a dotted basename or a nested path names a file while a two-segment path
without a dot is a component root. Paths are normalised, so `scripts/x.py` and
`./scripts/x.py` are one boundary. If a pair
genuinely needs no edge, record the argument in the board rather than deleting
the finding:

```text
<!-- board-graph: allow AAA-001 ~ BBB-001 -- reason -->
```

An allowance fails as stale once the edge is declared, and also once the pair
stops sharing a boundary, so an exception cannot outlive the gap it excused or
quietly excuse the next one.

**Backtick every path you name in acceptance criteria.** The rule reads
backticked tokens only, so an unquoted path is invisible to it. Detecting bare
path-shaped text is not viable here -- the board's prose carries 337 such
tokens (`I/O`, `API/CLI`, `134/162`, `Linux/Windows`) and not one of them is a
file -- so the convention is enforced from the other side: an unbackticked
token that resolves to a real file in the repository fails the board.
