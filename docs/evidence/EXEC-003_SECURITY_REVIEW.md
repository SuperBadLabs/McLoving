# EXEC-003 retrospective security review

Date: 2026-08-30

`EXEC-003` closed in protected-main commit `2c3c266` (PR #80). It addresses a
shared agent identity and journal: two executors advanced one session epoch,
the running attempt correctly parked for reconciliation, but the operator saw
no diagnostic naming the collision and had no supported way to discharge the
orphaned recovered attempt.

The control preserves fail-closed recovery while adding an explicit collision
diagnostic on agent and controller, a reasoned cancellation refusal, and a
documented resolution verb that discharges an orphan without replacing or
editing the journal. The regression gate reproduces the shared identity so a
generic network or lease message cannot satisfy the contract. Follow-up PR
#104 made generated harness identities unique per run, preventing the test
itself from reintroducing the configuration it is intended to diagnose.

The threat-model review covered agent identity substitution, session-epoch
rollback, unsafe journal replacement, premature cancellation, and operator
ambiguity. These are instances of the existing durable session authority,
agent recovery, and reconciliation boundaries; the implementation adds no new
credential or execution authority. The operator verb remains an explicit
reconciliation action rather than automatic evidence erasure.

Residual risk is deliberately fail-closed: an unresolved recovered attempt
still prevents new polling until an operator supplies the required resolution.
The unrelated Linux `/proc` ESRCH parking defect found later is not evidence
against the collision control and is remediated separately; it must not be
folded into this receipt. This document supplies the missing retrospective
security review for `EXEC-003` without claiming all parking causes are closed.
