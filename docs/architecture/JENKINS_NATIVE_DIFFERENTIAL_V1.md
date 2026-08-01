# Jenkins native differential v1

Status: `DIFF-001` verified implementation

## Certified boundary

The v1 compiler admission surface contains exactly one job from the immutable
228-file Mario corpus: `corpus-052-cinqict_jenkinsdev`, source SHA-256
`666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100`.
Its canonical strict-YAML compilation has SHA-256
`551d489ca13bf5d130bdc5c10ce35e5d3d988bdaa1c5488dd9bc79b30674acdc`.
DIFF-001 certifies this whole currently admitted surface; it does not convert
Jenkins' much broader parse reach into a McLoving compatibility claim.

The certified trace is deliberately small and exact:

- one ordered `Build` stage;
- one literal process, `/bin/sh -xe -c 'echo "Hello World"'`;
- successful stage and terminal build outcome;
- attempt/build ordinal one;
- semantic stdout bytes `Hello World\n`;
- zero user-created workspace entries, artifacts, normalized tests,
  approvals, credential grants, or external effects.

The abstract Jenkins `agent any` source token does not become an abstract
McLoving scheduler platform. The compiler result is explicitly bound to a
Linux execution and `migration-deny-authority` trust pool. Windows and
alternate-agent selection remain non-admitted.

## Independent executions

Jenkins ran on Mario in a new disposable home using Jenkins 2.568.1 and exact
image digest
`f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02`.
The pinned 90-plugin oracle directory, source, and initialization fixture were
read-only mounts. The container had no network, a read-only root filesystem,
dropped capabilities, no privilege escalation, and explicit CPU, memory, PID,
file-descriptor, time, and output bounds. A negative external-network probe
failed. The live Mario oracle remained healthy and unchanged after teardown.

McLoving ran the exact compiled bytes through the shipped controller and
embedded Linux worker against fresh PostgreSQL. Controller and database shared
only an internal Podman network and published no ports. The non-root runner had
a read-only root filesystem, no effective or bounding capabilities, no-new-
privileges, a read-only source mount, and explicit CPU, memory, PID, time, and
output bounds. PostgreSQL had a read-only root filesystem and only the five
startup capabilities required by its image entrypoint. The build used
synthetic API identities, no production credential, and no external-effect
authority. The disposable database, network, and runner were removed after
evidence collection; the database receipt proves the one authoritative build.

Failed predecessors are excluded from semantic evidence. Jenkins' first
container was stopped before execution after the disk monitor rejected a
256 MiB `/tmp`. McLoving's first isolated runner correctly failed when a Rust
shim attempted a denied network update; its next run correctly rejected an
invalid abstract `any` platform. The final receipt uses the already pinned,
prebuilt test binary and concrete Linux platform. Later attempts that failed
before execution while tightening PostgreSQL startup, user mapping, and the
integrity query are preserved as non-semantic predecessors. The successful raw
capture and final evidence envelope are immutable.

## Fail-closed verifier

`mcloving-jenkins-differential` accepts only the exact 28-file self-excluding
manifest and exact filesystem tree. It rejects traversal, symlinks, special or
oversized files, unmanifested/missing/additional entries, and digest
substitution. It independently checks:

- source, compiled-pipeline, Jenkins image, runtime, locale, and containment;
- Jenkins build, stage, literal shell step, console, workspace, and artifact
  observations;
- McLoving image/runtime identities, internal network, runner/database
  containment, database integrity, graph, platform, trust pool, attempt,
  result, stdout/stderr, workspace, artifact, test, approval, and grant
  observations;
- the strict-YAML coverage and zero-authority contract; and
- equality of the independently derived canonical traces.

Mutation tests alter and reseal the Jenkins result, Jenkins network mode,
McLoving output, McLoving read-only root filesystem, and admission denominator;
unsafe paths, extra files, and symlinked evidence are also rejected.

## Coverage truth

Certified equivalence is 1/1 admitted cases and 1/228 corpus cases. The other
227 corpus cases remain non-admitted. Parameters, conditions, matrices,
timeouts, retries, caught errors, unstable results, cancellation, post,
parallel/join/fail-fast, multi-build behavior, shared resources, alternate
agents, approvals, dependencies, caches, artifacts, tests, failure outcomes,
Scripted Pipeline, shared-library runtime, and external effects receive zero
execution, credential, approval, or effect authority from this ticket.

Any compiler-admission expansion changes the denominator and requires a new
versioned two-sided differential. `DIFF-002` and `DIFF-003` remain responsible
for state/policy and external-boundary parity; DIFF-001 cannot satisfy them by
implication.

The repository receipt is
`migration/mario-jenkins-oracle-228/corpus-v1/differential-v1`. The sealed
external evidence is
`/sn8100/runs/mcloving/diff001-native-20260801T131600Z-v17`; its
self-excluding 32-file manifest SHA-256 is
`7c4d05df6d5902b3d769a86b298edc9613297ca573d5f657dae11c41dc5760f7`.
The immutable v5 envelope is superseded because it lacked McLoving containment
receipts. The immutable v10 envelope is rejected because its outer manifest
omitted the nested repository `SHA256SUMS`; v11 predates the final repository
README lock; v12 used temporary receipt filenames; and v13 had an incomplete
predecessor ledger. V14 was superseded by exact directory accounting, and v15
failed before execution on a glibc mismatch. None contributes authority.
