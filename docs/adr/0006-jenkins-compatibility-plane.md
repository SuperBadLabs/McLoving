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
The over-acceptance defect the 2026-09-05/06 campaign measured -- a
Jenkinsfile with malformed quoting that the pinned Jenkins oracle refuses at
compilation while Fogell's parser admits and executes -- is dispositioned as
follows. No parser or interpreter is absorbed, so McLoving inherits nothing.
McLoving's own compiler refuses the same input before any plan exists,
naming its offender (`E_SOURCE_LEXICAL`), which is the fail-closed property
`ARCH-002` proves at every schema level. Because no differential case covers
that input in either project, the ticket that exposes the compiler from the
CLI must add a malformed-quoting negative case to the compiler fixtures and
show it refused with its offender named; a refusal that does not name its
offender does not count.

A future proposal to evaluate Groovy is a new ADR that re-derives `TM-020`,
not an amendment here. See ADR 0016.
