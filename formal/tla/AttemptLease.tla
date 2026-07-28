----------------------------- MODULE AttemptLease -----------------------------
EXTENDS Naturals

CONSTANTS Agents, MaxEpoch

ASSUME /\ Agents # {}
       /\ MaxEpoch \in Nat \ {0}

NoAgent == "none"
NoLease == <<NoAgent, 0>>
Epochs == 0..MaxEpoch

VARIABLES
    phase,
    leaseAgent,
    leaseEpoch,
    acceptedLease,
    completion,
    lastRejected,
    terminalSeen

vars ==
    <<phase, leaseAgent, leaseEpoch, acceptedLease, completion, lastRejected,
      terminalSeen>>

Init ==
    /\ phase = "ready"
    /\ leaseAgent = NoAgent
    /\ leaseEpoch = 0
    /\ acceptedLease = NoLease
    /\ completion = NoLease
    /\ lastRejected = NoLease
    /\ terminalSeen = FALSE

Offer(agent) ==
    /\ phase \in {"ready", "reconciliation"}
    /\ agent \in Agents
    /\ leaseEpoch < MaxEpoch
    /\ phase' = "offered"
    /\ leaseAgent' = agent
    /\ leaseEpoch' = leaseEpoch + 1
    /\ acceptedLease' = NoLease
    /\ UNCHANGED <<completion, lastRejected, terminalSeen>>

Accept(agent, epoch) ==
    /\ phase = "offered"
    /\ agent = leaseAgent
    /\ epoch = leaseEpoch
    /\ phase' = "running"
    /\ acceptedLease' = <<agent, epoch>>
    /\ UNCHANGED
        <<leaseAgent, leaseEpoch, completion, lastRejected, terminalSeen>>

Publish(agent, epoch) ==
    \/ /\ phase = "running"
       /\ <<agent, epoch>> = acceptedLease
       /\ acceptedLease = <<leaseAgent, leaseEpoch>>
       /\ phase' = "terminal"
       /\ completion' = <<agent, epoch>>
       /\ terminalSeen' = TRUE
       /\ UNCHANGED <<leaseAgent, leaseEpoch, acceptedLease, lastRejected>>
    \/ /\ ~(phase = "running" /\ <<agent, epoch>> = acceptedLease)
       /\ lastRejected' = <<agent, epoch>>
       /\ UNCHANGED
           <<phase, leaseAgent, leaseEpoch, acceptedLease, completion,
             terminalSeen>>

Fence ==
    /\ phase \in {"offered", "running"}
    /\ leaseEpoch < MaxEpoch
    /\ phase' = "reconciliation"
    /\ leaseAgent' = NoAgent
    /\ leaseEpoch' = leaseEpoch + 1
    /\ acceptedLease' = NoLease
    /\ UNCHANGED <<completion, lastRejected, terminalSeen>>

Requeue ==
    /\ phase = "reconciliation"
    /\ phase' = "ready"
    /\ UNCHANGED
        <<leaseAgent, leaseEpoch, acceptedLease, completion, lastRejected,
          terminalSeen>>

Next ==
    \/ \E agent \in Agents : Offer(agent)
    \/ \E agent \in Agents, epoch \in Epochs : Accept(agent, epoch)
    \/ \E agent \in Agents, epoch \in Epochs : Publish(agent, epoch)
    \/ Fence
    \/ Requeue

TypeInvariant ==
    /\ phase \in {"ready", "offered", "running", "reconciliation", "terminal"}
    /\ leaseAgent \in Agents \cup {NoAgent}
    /\ leaseEpoch \in Epochs
    /\ acceptedLease \in (Agents \cup {NoAgent}) \X Epochs
    /\ completion \in (Agents \cup {NoAgent}) \X Epochs
    /\ lastRejected \in (Agents \cup {NoAgent}) \X Epochs
    /\ terminalSeen \in BOOLEAN

LeaseShape ==
    /\ phase \in {"ready", "reconciliation"} => leaseAgent = NoAgent
    /\ phase \in {"offered", "running", "terminal"} => leaseAgent \in Agents

RunningLeaseIsCurrent ==
    phase = "running" => acceptedLease = <<leaseAgent, leaseEpoch>>

CompletionHasAuthority ==
    completion # NoLease =>
        /\ phase = "terminal"
        /\ terminalSeen
        /\ completion = acceptedLease
        /\ completion = <<leaseAgent, leaseEpoch>>

TerminalIsConsistent == terminalSeen = (phase = "terminal")

TerminalIsMonotonic == [] [terminalSeen => terminalSeen']_vars

CompletionIsStable == [] [completion # NoLease => completion' = completion]_vars

Spec == Init /\ [][Next]_vars

=============================================================================
