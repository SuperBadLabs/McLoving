# Architecture charter

McLoving is a faster, deterministic CI/CD controller that accepts Jenkins
pipelines where compatibility is proven, reports unsupported behavior
precisely, and executes through native Rust agents on Linux and Windows.

## Non-negotiable boundaries

- Rust owns scheduling, durable state, execution, cancellation, and recovery.
- PostgreSQL is the controller source of truth.
- Agents connect outbound using authenticated, fenced leases.
- Agent-local SQLite is a crash-recovery journal, not global truth.
- JVM/Clojure workers compile compatibility inputs but hold no runtime authority.
- Pipeline execution uses versioned, validated IR rather than Jenkins CPS.
- Unsupported behavior fails closed.
- Compatibility claims require pinned Jenkins differential evidence.
- Linux and Windows are first-class execution platforms.
- Extensions remain capability-specific and out of process.
- Dynamic compute is created only through a typed, fenced, out-of-process
  provisioner with exact immutable agent policy and confirmed cleanup evidence.
- Live external runtime inputs are captured once through a typed, bounded,
  read-only adapter and replayed identically to compared runners.
- Production changes are reviewable, auditable, and recoverable.

## Compatibility contract

Behavior is classified as proven compatible, migratable through bounded
changes, or unsupported. General Scripted Pipeline and binary Jenkins plugin
compatibility are not promised.

## Performance contract

McLoving may claim a speed or capacity advantage only after equivalent
semantics, resources, inputs, and raw benchmark evidence have been established.
