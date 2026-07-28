# ADR 0008: Extensions

Status: Accepted

Extensions are capability-specific and out of process. Mapping packs,
connectors, secret brokers, provisioners, and agent actions receive distinct
authority. No extension loads code into the controller, accesses its database,
contacts agents directly, or publishes success outside a valid contract.
