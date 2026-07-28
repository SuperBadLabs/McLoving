# ADR 0002: Canonical Pipeline IR

Status: Accepted

All frontends compile to immutable, versioned Pipeline IR. Rust independently
validates the IR before admission. Nodes have stable identity, provenance,
capabilities, timeout, retry, and idempotency classification. Arbitrary Groovy
and controller-object access cannot enter the IR.
