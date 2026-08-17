# McLoving

McLoving is a greenfield CI/CD system pursuing a deliberately hard goal:
provide a better and faster operational experience than Jenkins while making
compatibility claims only where differential evidence proves them.

The approved architecture uses a durable Rust controller and native Rust
Linux/Windows agents. An isolated JVM/Clojure compatibility plane compiles
supported Jenkins behavior into a versioned Pipeline IR. PostgreSQL remains the
controller source of truth.

## Current implementation

McLoving has moved beyond its architecture-foundation milestone. Protected
`main` contains a working PostgreSQL-backed controller and scheduler, outbound
fenced agents, durable Linux and Windows execution, a public API, CLI and
static UI, artifact and test-result storage, audit records, backup/restore
drills, identity lifecycle and versioned action-scoped authorization mapping,
and the isolated Jenkins compiler and migration evidence planes.
The contained parity substrate also includes a standalone, signed, fenced
dynamic-agent provisioner protocol; the sealed Mario inventory currently
contains zero admitted live dynamic provisioners, so no production dynamic
compute claim follows from that implementation. A standalone transactional
cache boundary likewise isolates tenant, project, pipeline, and trust-class
state behind immutable keys and signed receipts; the sealed inventory contains
zero admitted production cache mappings.

The project is not release-ready. The execution board remains authoritative
for source and trigger boundaries, external effects, external client migration,
production qualification, performance, security,
disaster recovery, and release provenance. Jenkins compatibility claims remain
bounded by differential receipts; general Scripted Pipeline and binary Jenkins
plugin compatibility are not promised.

See:

- [Mario end-to-end alpha demo](docs/ALPHA_DEMO.md)
- [Architecture charter](docs/architecture/CHARTER.md)
- [Architecture decisions](docs/adr/README.md)
- [Execution board](docs/EXECUTION_BOARD.md)
- [Threat model](docs/threat-model/README.md)
- [Contributing](CONTRIBUTING.md)

On HeMan, run the complete pinned repository validation gate with:

```text
./scripts/validate-foundation.sh
```
