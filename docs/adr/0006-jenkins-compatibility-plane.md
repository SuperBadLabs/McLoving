# ADR 0006: Jenkins compatibility plane

Status: Accepted

Isolated JVM/Clojure workers compile pinned Jenkins inputs into IR plus
diagnostics and provenance. Workers have no agent, database, scheduler, or
execution-secret authority. Compatibility is certified against exact Jenkins
profiles through semantic differential evidence.

## Amendment 2026-09-10: GROOVY-001 decided NO

`GROOVY-001` asked whether McLoving should evaluate Groovy under some trust
boundary. The answer is no. The worker keeps constructing a conversion-phase
AST and never runs a script, closure, method, Jenkins extension or user
source; `TM-020`'s "never evaluated" mitigation stands unchanged.

Declarative coverage widens only by compilation onto native constructs, in
corpus-frequency order and only after the native construct exists. The
following stay permanently unsupported and are reported as such rather than
approximated: `script` blocks and any Scripted Pipeline, dynamic `load`,
shared-library code with behaviour beyond pinned declarative content, and
arbitrary Groovy expressions in `when`, `environment` or step arguments.
A future proposal to evaluate Groovy is a new ADR that re-derives `TM-020`,
not an amendment here. See ADR 0016.
