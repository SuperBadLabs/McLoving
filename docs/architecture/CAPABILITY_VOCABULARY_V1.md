# Capability vocabulary v1

Status: EXEC-002 sealed vocabulary; the embedded worker fails startup on any
declaration outside it

## Purpose

A submission queues until an agent session declares every capability the
stored node requires. The vocabulary below is the complete, closed spelling of
those tokens for Wave 1. Its single code definition is the
`mcloving_domain::capability` module (`crates/domain/src/lib.rs`); the public
API, controller store, embedded worker, CLI, and remote agent all reference
that module rather than restating the strings.

The vocabulary exists because a capability set is silently inert when it is
spelled outside it: a worker declaring `linux` (measured 2026-08) polls
forever while every default submission requires `platform:linux`, and only the
`explain` diagnostic reveals the mismatch. Startup now rejects that
configuration by name instead of running it.

## The vocabulary

- `platform:linux` and `platform:windows` are the only platform capabilities.
  The public API accepts exactly `linux` and `windows` as submission
  platforms (`SUPPORTED_PLATFORMS`), defaults an unnamed platform to `linux`
  (`DEFAULT_PLATFORM`), and the store appends
  `platform:<required_platform>` to every stored node's required capability
  set. A DAG node may not declare a `platform:`-prefixed capability that
  conflicts with its `required_platform`.
- Any other required capability is an exact opaque token chosen by the
  pipeline (for example `gpu:cuda`). Matching is exact string equality; there
  is no wildcard or prefix matching.
- Trust pools are not capabilities. Scheduling takes the trust pool from the
  authenticated agent enrollment (`AGENT_RUNTIME.md`), never from a declared
  capability, and claims only an exact pool match.
- Remote agent sessions declare their capabilities from the binary itself:
  `<os>`, `platform:<os>`, and `<arch>` (`bins/agent`). The bare `<os>` and
  `<arch>` tokens are informational legacy tokens; scheduling against them is
  not part of this contract.

## Embedded worker startup contract

`MCLOVING_AGENT_CAPABILITIES` is a comma-separated declaration for the
controller-embedded worker. Startup classifies it against the vocabulary and
fails closed with a named `EmbeddedWorkerCapabilityError` unless the
declaration is one of:

- a set containing at least one of `platform:linux` or `platform:windows`
  (additional exact opaque tokens are allowed); or
- exactly the disable sentinel `disabled`, alone. A disabled embedded worker
  still performs expired-lease reconciliation but never claims work; this is
  the supported way to run a controller whose execution comes only from
  remote agents.

The named rejections are:

- `EmbeddedWorkerCapabilityError::EmptyDeclaration` — no capability declared;
- `EmbeddedWorkerCapabilityError::DisableSentinelNotAlone` — `disabled` mixed
  with other capabilities;
- `EmbeddedWorkerCapabilityError::NoSchedulablePlatform` — no declared
  capability spells `platform:linux` or `platform:windows`, so no submission
  (including the default) could ever be claimed. `MCLOVING_AGENT_CAPABILITIES=linux`
  is the measured instance of this error.

The gates live in `bins/controller/tests/capability_vocabulary.rs`: a
controller whose embedded worker declares `platform:linux` executes a
default-platform public-API submission to terminal success with no remote
agent, and the measured misconfiguration exits at startup with the named
error.
