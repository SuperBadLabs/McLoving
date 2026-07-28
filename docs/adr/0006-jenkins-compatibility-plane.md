# ADR 0006: Jenkins compatibility plane

Status: Accepted

Isolated JVM/Clojure workers compile pinned Jenkins inputs into IR plus
diagnostics and provenance. Workers have no agent, database, scheduler, or
execution-secret authority. Compatibility is certified against exact Jenkins
profiles through semantic differential evidence.
