# ADR 0012: Packaging, upgrades, and rollback

Status: Accepted

Signed Rust controller, agent, and CLI artifacts accompany an isolated
compatibility worker. Compact and HA profiles use identical state semantics.
Migrations are controlled operations; rolling upgrades retain a declared
compatibility window. Database restoration is not normal rollback.
