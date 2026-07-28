# McLoving

McLoving is a greenfield CI/CD system pursuing a deliberately hard goal:
provide a better and faster operational experience than Jenkins while making
compatibility claims only where differential evidence proves them.

The approved architecture uses a durable Rust controller and native Rust
Linux/Windows agents. An isolated JVM/Clojure compatibility plane compiles
supported Jenkins behavior into a versioned Pipeline IR. PostgreSQL remains the
controller source of truth.

This repository is currently at its architecture-foundation milestone. The
binary crates are compilable placeholders; no controller, scheduler, or agent
runtime is represented as implemented.

See:

- [Architecture charter](docs/architecture/CHARTER.md)
- [Architecture decisions](docs/adr/README.md)
- [Execution board](docs/EXECUTION_BOARD.md)
- [Threat model](docs/threat-model/README.md)
- [Contributing](CONTRIBUTING.md)
