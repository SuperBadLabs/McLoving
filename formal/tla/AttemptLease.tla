----------------------------- MODULE AttemptLease -----------------------------
EXTENDS Naturals

CONSTANT Agents

VARIABLES phase, leaseAgent, leaseEpoch, terminal

vars == <<phase, leaseAgent, leaseEpoch, terminal>>

Init ==
    /\ phase = "ready"
    /\ leaseAgent = "none"
    /\ leaseEpoch = 0
    /\ terminal = FALSE

Offer(agent) ==
    /\ phase = "ready"
    /\ agent \in Agents
    /\ phase' = "offered"
    /\ leaseAgent' = agent
    /\ leaseEpoch' = leaseEpoch + 1
    /\ UNCHANGED terminal

Accept(agent, epoch) ==
    /\ phase = "offered"
    /\ agent = leaseAgent
    /\ epoch = leaseEpoch
    /\ phase' = "running"
    /\ UNCHANGED <<leaseAgent, leaseEpoch, terminal>>

Finish(agent, epoch) ==
    /\ phase = "running"
    /\ agent = leaseAgent
    /\ epoch = leaseEpoch
    /\ phase' = "terminal"
    /\ terminal' = TRUE
    /\ UNCHANGED <<leaseAgent, leaseEpoch>>

Fence ==
    /\ ~terminal
    /\ phase' = "reconciliation"
    /\ leaseAgent' = "none"
    /\ leaseEpoch' = leaseEpoch + 1
    /\ UNCHANGED terminal

Next ==
    \/ \E agent \in Agents : Offer(agent)
    \/ \E agent \in Agents, epoch \in Nat : Accept(agent, epoch)
    \/ \E agent \in Agents, epoch \in Nat : Finish(agent, epoch)
    \/ Fence

TypeInvariant ==
    /\ phase \in {"ready", "offered", "running", "reconciliation", "terminal"}
    /\ leaseEpoch \in Nat
    /\ terminal \in BOOLEAN

TerminalIsMonotonic == terminal => phase = "terminal"

Spec == Init /\ [][Next]_vars

=============================================================================
