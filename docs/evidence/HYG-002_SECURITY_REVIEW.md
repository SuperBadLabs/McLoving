# HYG-002 security and implementation closure

`HYG-002` replaces the closure gate's inference of a threat-model review from
English prose with a field that holds data. The gate now reads a two-column
table — a ticket id and the path to the document recording its review — and both
cells are matched whole, so neither can contain a sentence.

## What the old predicate was actually reading

The ticket was filed because four successive tightenings of a prose predicate
were each defeated by the same denial in a new wrapper, and because the function
itself conceded that a denial phrased without a vetoed word would still pass.
That is true, and it is not the worst of it.

**Seventeen of the thirty-eight credited reviews came from the table headed
`| Area | First implementation ticket |`.** That table records which ticket first
implemented an area. It asserts nothing about a review, and it never claimed to.
The gate was reading an ownership map as an attestation, and the table was not
lying — it was being misread.

Two more came from a threat-register verification cell whose only cited document
is **another ticket's closure evidence**: `DIFF-001`'s names the aggregate
contract whose own header reads `Status: MIG-006 complete`, and `MIG-005A`'s
names the migration package belonging to `MIG-007`.

So the defect was never only "the predicate can be fooled by a denial". It was
that the predicate could be satisfied by structures that assert something else
entirely, and no denial had to be written for that to happen.

## The design, and why it needs no negation veto

A ticket is attributed a review if and only if it has a row in
`## Closure attribution` in `docs/threat-model/README.md`:

```
| Ticket | Evidence |
|---|---|
| ADMIN-001 | `docs/evidence/ADMIN-001_SECURITY_REVIEW.md` |
```

The ticket column is `fullmatch`ed against a ticket id and the evidence column
against a backticked path under `docs/`. `AAA-001 review has not happened` is no
longer a denial the gate must detect — it is a cell that is not a ticket id. The
negation veto, its 70-character window, and all three structural shapes are
deleted rather than kept alongside the new field, because a second way to be
credited is a second way to be wrong.

The prose did not go away and should not. The register still explains what was
examined and what risk remains; it is simply no longer load-bearing, which is the
only claim this change makes about it.

**Checked both ways, which nothing did before.** An attribution whose evidence
path does not exist is an error, and so is one naming a ticket that never closed.
Neither is hypothetical: `docs/evidence/` holds twenty receipts while nineteen
DONE tickets are credited, and the extra is `DEPLOY-001_SECURITY_REVIEW.md` for a
ticket that reads `ACTIVE`. Nothing in this file saw that.

## The migration, stated as a disclosure

| | before | after |
|---|---:|---:|
| credited with a review | 38 | 19 |
| closure debt | 31 | 50 |

**Nineteen tickets stopped being credited, and every one lost a credit it should
never have had.** They move to `THREAT_MODEL_DEBT` with that reason recorded per
ticket, and `THREAT_MODEL_DEBT_BASELINE` is widened once, deliberately, with the
argument written beside it. That baseline exists to make entry conspicuous, and
this is the second time it has widened for this reason — the `MIG-002/006/007`
block did the same when register attribution was narrowed to the verification
column, and recorded the same argument: *the ledger widened because the predicate
got stricter, not because closure discipline slipped.*

The debt bound in `test_the_repository_never_slips_backwards` moves from 31 to
50 with its argument in the test, as that comment requires. **A ratchet that
could never widen would have forced the opposite choice** — keep reading the
ownership table as an attestation, and keep the number at 31.

No ticket's status changed, no receipt was deleted, and no review was undone.

## One correction to the ticket's own text

The row says "the 37 tickets credited today". The gate reports **38**. The
thirty-eighth is `DEPLOY-004`, and it is thirty-eighth because of `cced27e` —
this custodian's own previous change, which named `DEPLOY-004` in `TM-050`'s
Required-verification cell. Verified against `cced27e^`, where
`threat_model_attribution` returns `None` for it. The spec was accurate when
written; the work that preceded this ticket moved the number.

## Evidence

**Every check is mutation-proved.** Each one, removed or weakened, turns a named
test red:

| mutation | test that goes red |
|---|---|
| ticket column `fullmatch` → `match` | `test_a_denial_in_the_ticket_column_is_not_a_ticket_id`, `test_a_denial_with_no_vetoed_word_still_fails` |
| evidence column `fullmatch` → `search` | `test_an_evidence_cell_containing_a_path_is_still_refused` |
| drop the path-exists check | `test_an_evidence_path_that_does_not_exist_is_refused` |
| drop the ticket-is-DONE check | `test_an_attribution_for_an_open_ticket_is_refused` |
| drop the duplicate-row check | `test_a_ticket_attributed_twice_is_refused` |
| short row skips instead of erroring | `test_a_short_row_is_an_error_not_a_skip` |
| drop the two-tables check | `test_two_tables_are_refused` |

**One of those mutations initially proved nothing, and that is worth recording.**
`if statuses.get(ticket) != "DONE":` appears twice in the file, and a
`replace(old, new, 1)` mutated the wrong one — so the check under test was still
intact and its test "passed". The mutation harness was wrong, not the gate, but a
harness that silently tests the wrong line is the same defect class this ticket
exists to remove. Re-run against a unique anchor, the check is proved.

**The nine recorded bypasses are kept as tests**, no longer as veto cases but as
the stronger assertion the old design could never make: this English, *wherever*
it appears, does not attribute a review. One test places a denial immediately
above and below a valid attribution row and requires the gate to stay green —
the field is data, and its surroundings are not read at all.

The first cut of that test class fell into the trap it was written to catch:
every negative passed, because their fixtures had no attribution table and
`attributes no review` therefore appeared regardless of the denial under test.
Each negative now supplies a well-formed table crediting a different ticket, so
the assertion isolates the predicate.

## The parser debt, and three corrections to how the ticket words it

Each of the five was independently reproduced before being fixed, and each fix
turns a named test red when reverted.

| item | verdict | correction |
|---|---|---|
| (a) two inline pipe splits | closed | padding and code-span pipes do **not** diverge from `row_cells`; only the escaped pipe does. The dispatch half was a false alarm — an escaped pipe there made a legal row be *refused*, not silently passed. Routed through `row_cells` anyway: one grammar per board. |
| (b) topology skips an unknown class | closed | in isolation it is backstopped by the missing-classification check. The reachable case is a class cell holding **a ticket status matching the row's ticket**, which bought two contradictory execution classes for one ticket in silence. |
| (c) ownership table's last cell | already closed | the whole prose predicate went with the first commit; nothing reintroduced. |
| (d) execution class in any view | closed | the ticket says "Batch and Dispatch rows must carry a ticket status" as though both were open. Dispatch was already guarded by `verify-execution-board.py`; only the Batch half was live. Both are guarded here so neither cross-check depends on the other file keeping it. |
| (e) unbackticked citations | closed, **broader than written** | four spellings bypassed it, three of them *properly backticked*: `./docs/…`, `<docs/…>`, and a trailing space inside the backticks. Confirmed too that the bare-path rule in the board verifier fires only when the path **resolves**, so it catches real files and stays silent on fabricated ones — backwards for this purpose, and unable to backstop (e). |

**The exploit for (a) and (d) was re-run end to end against the fixed
verifiers**, not just unit-tested. The Batch ledger's `W0-A` reading `SERIAL`
is now named by line. A reversed production-qualification chain hidden behind an
escaped pipe is now read and refused; stated precisely, the simplified variant
re-run here does not reproduce the *fully green* state on `main` — the original
exploit needed three restated `PARALLEL` rows to satisfy the backstop — but it
does show the fixed verifier reading a row `main`'s parser cannot see.

**One judgement was reversed after measuring.** Broadening the citation scan
past delimiters truncates a template `docs/evidence/<TICKET>_SECURITY_REVIEW.md`
to the real directory `docs/evidence`, and the first cut relaxed the predicate
from `is_file` to `exists` to admit it. Measured: no `DONE` row on the board
spells a template, and all 25 of their cited paths resolve to files. The
relaxation defended a case that does not exist, at the cost of one that does —
every citation of a directory where a document was meant. `is_file` stands, and
a `DONE` row citing a template is refused, which is the right answer: a closed
ticket has a document, not a pattern.

Test suites go 44 → 49 and 63 → 73.

## Bounded deliberately

Three defects were found while reproducing this ticket's items that are **larger
than any of them**, and are recorded here rather than fixed, because absorbing
them would have doubled the change:

- **A receipt can be replaced with a kilobyte of nonsense.** `receipt_defects`
  tests size ≥ 1000 bytes, that the ticket is named, and that some line starts
  with `#`. Overwriting the real 52,326-byte `DEP-001` receipt with `# DEP-001`
  plus 1,080 bytes of filler leaves both gates green. This affects all nineteen
  receipted tickets.
- **`DEFERRED` is an unratcheted exit from the board.** It is a valid status, it
  is not in `REMAINING_STATUSES`, and `CLOSED_TICKETS` pins only `DONE`. Flipping
  a ticket from `PENDING` to `DEFERRED` and deleting its topology row silently
  retires it — no receipt owed, no attribution owed, no execution class owed.
  The whole ratchet architecture protects `DONE` and leaves the open set
  unguarded. **`HYG-002` could have deleted itself this way.**
- **Batch-ledger membership is validated by nothing.** A fabricated row naming
  real tickets with matching statuses passes both verifiers.

Each is reproduced; none is speculative.
