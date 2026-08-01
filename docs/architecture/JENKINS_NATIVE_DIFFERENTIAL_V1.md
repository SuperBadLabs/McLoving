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
The exact 90-plugin SHA-256 manifest and plugin files predated execution and
were later independently reverified against the pinned oracle directory
without mismatch; that directory, source, and initialization fixture were
mounted from their exact captured source paths as one complete four-mount set,
with only the isolated Jenkins home writable. The exact initializer digest and
body prove that `/fixture/Jenkinsfile` supplied the `CpsFlowDefinition` for
`diff-001-admitted`; the controller log proves initializer, readiness, and
build chronology, and the build receipt binds job name, number, and URL. The container
had no network, a read-only root filesystem, the exact dropped-capability and
2 GiB no-exec tmpfs policies, no privilege escalation, and explicit CPU,
memory/swap, PID, file-descriptor, time, and output bounds. A negative
external-network probe failed. The live Mario oracle remained healthy and
unchanged after teardown.
Its immutable container ID/name/creation/start identity, exact tini/jenkins.sh
invocation, configured image/user, and complete canonical UID/kernel/locale/
Java/Jenkins runtime receipt are verifier-bound.

McLoving ran the exact compiled bytes through the shipped controller and
embedded Linux worker against fresh PostgreSQL. Controller and database shared
only an internal Podman network and published no ports. The non-root runner had
a read-only root filesystem, no effective or bounding capabilities, no-new-
privileges, a read-only source mount, and explicit CPU, memory, PID, time, and
output bounds. The embedded worker enforces an exact 67,108,864-byte aggregate
stdout/stderr ceiling. PostgreSQL had a read-only root filesystem and only the five
startup capabilities required by its image entrypoint. The build used
synthetic API identities, no production credential, and no external-effect
authority. The disposable database, network, and runner were removed after
evidence collection; the database receipt proves the one authoritative build.
The runner's immutable container ID, name, creation timestamp, exact test
command, entrypoint, complete two-mount set, and configured empty-added/exactly-
dropped capability policy are identical across its created and exited receipts.

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

`mcloving-jenkins-differential` accepts only the exact 30-file self-excluding
manifest and exact filesystem tree. Security-relevant Jenkins and McLoving
image, container, network, runtime, negative-network, and test transcripts also
carry compiled detached SHA-256 anchors, so resealing the bundle cannot make an
unchecked receipt field authoritative. The original 14-entry Jenkins capture
manifest is independently parsed, required to use the exact capture root and
file set, and reconciled byte-for-byte with the repository bundle. It rejects
traversal, symlinks, special or
oversized files, unmanifested/missing/additional entries, and digest
substitution. It independently checks:

- source, compiled-pipeline, Jenkins image, exact 90-plugin manifest and
  verification receipt, initializer/source installation, controller chronology,
  exact container identity/invocation and canonical runtime, locale, Java,
  kernel, and complete containment/mount set;
- Jenkins exact job/build identity, stage, literal shell step, exact console transcript,
  workspace, and artifact observations;
- McLoving image/runtime identities, internal network, runner/database
  containment, database integrity, admitted canonical-IR digest, graph/build/
  node/attempt identity, platform, trust pool, fence, graph/status/attempt
  terminal-result agreement, ordered log
  sequence and stdout/stderr digests, workspace, artifact, test, approval, and
  grant observations, plus the runner's exact execution identity, invocation,
  capability policy, and complete mount set;
- the strict-YAML coverage and zero-authority contract; and
- equality of the independently derived canonical traces.

Mutation tests alter and reseal the Jenkins result, network mode, memory/swap,
container invocation, canonical runtime, ulimits, tmpfs, dropped capabilities,
plugin mount source, undeclared mount,
plugin manifest, initializer source, console output, McLoving output, admitted
IR digest, attempt identity, graph/status/attempt result agreement, log sequence,
runner command, runner configured image, added/dropped
capabilities, McLoving read-only root filesystem, and admission denominator; unsafe
paths, extra files, and symlinked evidence are also rejected.

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
`/sn8100/runs/mcloving/diff001-native-20260801T162027Z-v34`; its
self-excluding 35-file manifest SHA-256 is
`9f5f28dd10f0b07bb56918a9ee74306d35e7a312566ff1a85ed6924329783cd1`.
The immutable v5 envelope is superseded because it lacked McLoving containment
receipts. The immutable v10 envelope is rejected because its outer manifest
omitted the nested repository `SHA256SUMS`; v11 predates the final repository
README lock; v12 used temporary receipt filenames; and v13 had an incomplete
predecessor ledger. V14 was superseded by exact directory accounting, v15
failed before execution on a glibc mismatch, and v17 was superseded by the
review-driven exact plugin, console, and containment binding in v18; v18 was
then superseded by v19's chronology-accurate plugin-verification wording; v19
was superseded by v20's raw IR, attempt, fence, and log identity binding; v20
was superseded by v21's exact Jenkins source/job/mount and McLoving runner
invocation/capability binding; and v21 was superseded by v22's exact Jenkins
container invocation/identity and complete runtime binding. V22 was superseded
because its embedded worker binary had no aggregate output ceiling. V23-v25
failed before execution on evidence-directory permissions, host ABI mismatch,
and a login-shell PATH reset respectively. V26 was superseded because its
reconstructed command omitted explicit memory/swap equality; v28 was
superseded because an extra database network alias broadened the exact topology.
V29 is the successful 1 MiB-bounded capture incorporated into v30, which was
then superseded because that ceiling contradicted the shared 64 MiB execution
contract. V31 failed before execution on evidence-mount permissions and v32
failed before execution on a host-built glibc mismatch. V33 is the successful
shared-64-MiB capture incorporated byte-for-byte into v34.
None of the predecessors contributes authority.
