# Jenkins inventory contract v1

Wave 4 begins with four independently collected, immutable source-truth
manifests. McLoving does not compile or execute a Jenkins definition merely
because it appears in an inventory.

## Files

Before reconciliation, an inventory root contains exactly these source-evidence
files:

```text
job-graph.yaml
identity-clients.yaml
runtime-dependencies.yaml
persistent-state.yaml
SHA256SUMS
```

`mcloving-inventory seal --root ROOT` creates `SHA256SUMS` with
create-new semantics. It refuses an already sealed root and any root containing
an entry outside the four source manifests, so stale or secret-bearing exports
cannot sit outside the seal. Every manifest is strict YAML: aliases, anchors,
tags, directives, duplicate keys, multiple documents, and resource-limit
violations fail before typed deserialization. Unknown typed fields also fail.

The manifests share one byte-identical `binding`. It identifies the controller,
Jenkins core and plugin profile, effective global configuration, exporter,
provenance, source generation, and collection epoch. A mixed epoch is rejected.
The collection time is an exact, calendar-valid UTC
`YYYY-MM-DDTHH:MM:SSZ` timestamp.
If Jenkins cannot provide a coherent snapshot, collection must quiesce all
configuration, identity, client, runtime-dependency, job-state, retention, hold,
and persistent-state mutation for one bounded export epoch.

## Families

- `job-graph.yaml` owns controller and job structure, canonical definition
  sources and digests, operational state, triggers, platform/agent/toolchain
  requirements, publication behavior, ownership, and reviewed scope. An
  independently sourced controller total and independently sourced direct-child
  count for every job must exactly match the manifest population and hierarchy;
  each count binds a collector distinct from the manifest exporter, provenance,
  and a source-evidence digest.
- `identity-clients.yaml` owns the security realm, immutable principals and
  lifecycle evidence, effective ACLs, and every read-side or write-side client.
  Principal kind is one of `user`, `service`, or `group`; lifecycle is one of
  `active`, `disabled`, `retired`, or `deleted`. Current aliases participate in
  the unique principal namespace. Historical-name claims carry their own
  generation and provenance, preserving deleted-name reuse without creating a
  current mapping ambiguity. A client caller is either a canonical principal
  reference or an explicit observed source; anonymous and legacy callers never
  require a fabricated principal.
- `runtime-dependencies.yaml` owns per-job parameters, credentials by typed
  reference, source and package resolution, approvals, triggers, live reads,
  mutable inputs, agents, caches, effects, provisioners, locks, global values,
  and built-in environment dependencies. The generic typed record uses `kind`
  for the dependency family, requires an explicit compatibility disposition,
  and carries typed coverage for declared shared libraries, triggers,
  platforms, agent labels, and toolchains. Every declared requirement must
  have exactly one matching compatibility classification; undeclared or
  duplicate coverage and duplicate declarations fail.
  Mutability is one of `immutable`, `pinned-revision`, `mutable`, or `floating`;
  mutable and floating dependencies cannot be classified `native`. Every secret
  dependency additionally binds its exact tagged consumer, typed taint class,
  non-empty taint path, provenance, and evidence digest. Consumer type and
  taint class must agree. Workload-visible secret taint is always
  `unsupported`; an owner-supplied weaker disposition is rejected.
- `persistent-state.yaml` owns each per-job record class, counts and source
  digest, retention-policy identity and digest, retention deadline, legal holds
  and release authority, restore target, conflict policy, external consumers,
  ownership, confidentiality, and provenance. Every external consumer must
  reference a client whose direction includes reads; write-only clients cannot
  consume state. Reusing a legal-hold identity with a conflicting scope, reason,
  generation, or release authority fails reconciliation. Retention deadlines
  use the exact UTC form `YYYY-MM-DDTHH:MM:SSZ` and must be valid calendar
  timestamps. Every state record carries independently classified forward and
  rollback transforms with mapping identity, evidence digest, and provenance.

Secret values are never inventory fields. A dependency classified `secret`
must carry a typed `credential_reference` or `redaction_reference`; the
reconciler rejects an unbound secret dependency or one without typed consumer
and taint evidence. Conversely, the presence of either reference or consumer
evidence forces the `secret` confidentiality label, so an exporter cannot
downgrade a credential-bearing dependency to bypass those checks.
Runtime dependencies and persistent-state records accept only the exact
confidentiality labels `public`, `internal`, `confidential`, and `secret`.
Unknown or case-variant labels fail closed.

## Reconciliation

`mcloving-inventory reconcile --root ROOT` verifies the detached hashes,
strictly parses all four manifests, checks epoch identity and referential
integrity, requires exactly one runtime and state record group for every
in-scope job, permits retained obligation groups for approved retired or
out-of-scope jobs, validates every supplied group regardless of scope, and
rejects:

- duplicate or ambiguous identities;
- unknown job, parent, ACL principal, or client principal references;
- exclusions without owner approval;
- source controller or direct-child counts that differ from the manifest;
- unclassified runtime or state-transform behavior;
- missing, duplicate, or undeclared compatibility evidence for a job's shared
  libraries, triggers, platforms, agent labels, or toolchains;
- secret dependencies without typed references and consumer/taint evidence;
- workload-visible secret dependencies with any disposition other than
  `unsupported`;
- malformed digests, missing ownership, duplicate state/hold identities, or
  incomplete per-job coverage.

The resulting derived `eligibility-ledger.yaml` is published with create-new
semantics. When the default output path is used, it is added to the sealed
inventory root after the five source-evidence files above; it is not an input
to `SHA256SUMS`. Verification rejects every other post-seal entry and requires
an existing published ledger to exactly match a fresh reconciliation of the
sealed source evidence. A custom output may be written outside the inventory
root; inside the root, the only permitted output is `eligibility-ledger.yaml`.
Eligibility is conservative: the least-compatible runtime dependency, forward
state transform, or rollback state transform determines a job's `native`,
`mappable`, `scripted`, or `unsupported` class. The ledger
reports whole-inventory population denominators, while eligibility rows,
parity-substrate demand by dependency kind, and state-transform record demand
cover only the approved in-scope population. Excluded-job retention and
legal-hold evidence remains sealed in the source manifests without inflating
migration eligibility or demand. The ledger grants no compiler, scheduler,
credential, agent, trigger, connector, effect, canary, or cutover authority.

`mcloving-inventory verify --root ROOT` performs the same reconciliation,
derived-ledger rendering, and strict output validation without writing an
output.

## Closure boundary

This contract and its contained fixtures implement the W4-A evidence machinery.
The four `INV-*` tickets and `MIG-000` close only after the owner-selected
controller population is exported under one coherent epoch, secret-scanned,
reviewed, sealed, and reconciled. Contained fixtures are verification evidence,
not production inventory.
