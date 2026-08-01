# ADR 0012: Packaging, upgrades, and rollback

Status: Accepted

Signed Rust controller, agent, and CLI artifacts accompany an isolated
compatibility worker. Compact and HA profiles use identical state semantics.
Migrations are controlled operations; rolling upgrades retain a declared
compatibility window. Database restoration is not normal rollback.

Schema additions consumed as durable execution truth must remain safe while an
older replica is still admitted. A compatibility default or trigger must cover
legacy writes, including state-dependent exceptions such as blocked DAG
attempts, and the migration must test both runnable/blocked legacy inserts and
legacy multi-statement retry reopening before the new field becomes a
validation requirement. Compatibility triggers that translate a retry must
share the new writer's build-scoped serialization lock and reevaluate the exact
dependency conditions before admitting readiness.
