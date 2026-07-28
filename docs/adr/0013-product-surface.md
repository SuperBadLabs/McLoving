# ADR 0013: Product surface and migration

Status: Accepted

The web UI and Rust CLI use the documented public API. Waiting and uncertain
states are explainable. Jenkins migration proceeds through inventory, analysis,
strict-YAML generation, differential shadowing, canary, cutover, and explicit
decommissioning.
