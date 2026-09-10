# Jenkins sequential differential v2

Status: **preregistered JCOMP-003 observation and comparison contract; no paired
execution result is asserted by this document.** The chief must approve this
contract and the exact runtime prerequisite before a campaign starts. A complete
report, protected review and merge, and exact-main gates remain separate duties.

## Population and frozen expectations

The authority for source, decoded scripts, ordered stages and steps, dispositions,
exit codes, semantic stdout and workspace files is the unchanged
`compat/jenkins-worker/fixtures/sequential-v1/manifest.json`, SHA-256
`654898829f31872d471db88830414b23a9453e021bec281f05ac1aa4175de727`.
Its source grammar and behavioral scope remain
`docs/architecture/JENKINS_SEQUENTIAL_DECLARATIVE_V1.md`, SHA-256
`ae47b3f3cc58d6a66cec6d73832a189417864df74110c83bf1f656840c5d5dfe`.
The profile remains `compat/jenkins-worker/profile-v1.properties`, SHA-256
`feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271`.

There are exactly ten authored positive inputs, twelve authored negative inputs,
and one unchanged historical C052 regression. The eleven positive inputs require
nineteen observed workload shell invocations on each runtime. Observer wrappers
and monitor/control helpers remain separate recorded control processes; this is
not a total process-count claim. Failed positive cases S08–S10
are compatibility requirements; downstream skipped steps must have no observed
shell invocation, exit code or logs. Negatives are compiler inputs only: named
independent admission denial, absence of an executable, and unchanged observed
scheduler population establish zero scheduled work. They do not establish an
unimplemented public runtime submission endpoint's rejection behavior.

The separate original-corpus classification covers exactly 228 preserved source
identities: 226 original-byte inputs and two preexisting redacted representations,
as specified by `docs/architecture/JENKINS_SEQUENTIAL_CORPUS_V1.md`. Authored fixtures, successful compilation, actual execution, certified
case equivalence, and production eligibility have separate denominators. Neither
ten authored positives nor nineteen observed shell processes increase the count
of original corpus sources. NOASSERTION sources remain evidence-only. No source
or historical receipt is rewritten to improve coverage.

## Frozen runtime and execution authority

Both JCOMP-002A and JCOMP-002B must have completed protected merge and exact-main
verification. Every intervening runtime prerequisite on the execution board must
also complete that boundary. The chief freezes a clean source commit and tree
containing the reviewed observation tooling. A build-only container consumes its
Git archive under the lockfile and pinned Rust toolchain; build network access
ends before any fixture submission. Both shipped binaries embed the frozen source
commit/tree through `MCLOVING_BUILD_SOURCE_HEAD` and
`MCLOVING_BUILD_SOURCE_TREE`. Their `build-provenance` output and executed-byte
SHA-256 are compared with the archive, binary inventory and external freeze pins.

The compiler uses an independently pinned immutable worker image. Each fixed
input compiles twice through `compat/jenkins-worker/run-worker.sh`, preserving
identical raw EDN and trusted Rust admission receipts. The preparation tool
replays Rust admission for every response with regenerated exact source context
and request identity. Full receipt equality, source/profile/contract bindings,
external campaign/worker/admission pins and exact admitted YAML hashes precede
release of executable input. The preparation tool does not manufacture YAML
from manifest expectations.

Compiler-produced disabled definitions remain exact retained bytes with their
independently admitted hashes and disabled state. They are not changed into
operational jobs. The product observer separately saves explicitly authorized
contained pipeline revisions using the admitted YAML and observes their enabled
operational state. It calls the existing internal sequential planner and store
admission in the dedicated disposable database; the shipped controller schedules
and serves actual work to the shipped remote agent. This test helper adds no
HTTP/gRPC route, production pool, imported-job enablement or scheduler bypass.
The disabled compiler definition is a retained import record, not a claim that
a nonexistent operational import API was invoked.

Jenkins executes unchanged positive Jenkinsfiles on the profile's pinned
2.568.1 image and all ninety exact plugin files. Startup verifies the WAR,
core/Groovy JARs, Java/Groovy versions, plugin contents and active versions. It
runs one executor with an explicit synthetic anonymous user cause and waits for
the host's inspected containment approval marker
before scheduling any fixture. The shell observer path is an explicit
instrumentation difference: Jenkins invokes the pinned observation wrapper,
which records arguments and script bytes and calls the image's `/bin/sh` with
unchanged `-xe` and script-path arguments, preserves output and returns its exact
exit code. It does not replace or edit the shell script. The product runs in a
separate container using the same pinned base image with a timeout/bash entrypoint
and no Jenkins service, so both sides' actual `/bin/sh` bytes are identical.
The observer wrapper and independent tracer are pinned and retained separately
from the historical compiler/profile identity.

## Containment and observation

The Jenkins environment has network `none`. Product PostgreSQL owns a separate
network-`none` namespace, and the product runner joins only that namespace's
loopback. Neither stack publishes ports. The inspected namespace, user, mounts,
capabilities, resource limits, tmpfs sizes, log bounds and internal watchdog
commands must equal the preregistered runner policy before the fixture release
marker is created. No production endpoint, proxy, credential, service home,
agent identity or shared workspace is mounted or inherited. Synthetic tokens and
fresh test certificates exist only within the disposable product tmpfs.

The product workload tmpfs is 512 MiB, with a 2 GiB memory/swap limit and 512-PID
limit. Jenkins has bounded home and temporary tmpfs suitable for its plugin and
disk-monitor requirements, a 4 GiB memory/swap limit and 1024-PID limit. Both
Jenkins tmpfs mounts use mode 1777 without uid/gid options, which the execution
host's Podman rejects. The sticky, root-owned home is private to this
disposable container and permits the fixed UID 1000 Jenkins process to initialize
its files without a root bootstrap. It is not a shared host home or a claim of
isolation between hostile users inside the container. All inspected namespace,
read-only root, nonroot user, mount and capability restrictions remain required.
Both runners have a 1024-file descriptor limit, four CPU limit, bounded container logs,
private PID/IPC namespaces, dropped capabilities, read-only roots and
no-new-privileges. PostgreSQL has no host data volume, a 512 MiB data tmpfs,
1 GiB memory/swap limit, two CPU limit and 256-PID limit; its image's bounded
default initialization capabilities are recorded separately. Internal deadlines
and forced termination bound container lifetime independently of host cleanup.
A boundary failure produces no equivalence evidence.

The product observer records each actual `SequentialBuildResult`, attempt UUID,
fence-bound log references, ordered log chunks, terminal summaries, stage/step
layout and namespace receipt. It does not substitute manifest outcomes for
observations. Independent strace records physical `execve` arguments and process
exit status. The tracer's copied libraries are used only by the tracer;
`LD_LIBRARY_PATH` is removed from the traced agent. Process argument evidence
contains only fixed fixture scripts and synthetic fixture paths, never production
secrets. Tracer output is bounded by the private tmpfs and internal deadline.

Jenkins retains raw console bytes, FlowNode parent relationships, stage tags,
block-start/end identities, per-shell logs and arguments, errors and timing, plus
wrapper-observed physical argv, script bytes, exit code and invocation chronology.
Stage/step order is established by graph ancestry and observed execution order;
source expectations cannot invent executed nodes. Expected skipped steps need no
synthetic Jenkins shell node. Skipped stage tags and failed stage end errors
provide separate stage truth.

## Comparison and cleanup

The report schema is `mcloving.jenkins.sequential-differential/2`. It is separate
from the historical one-process differential-v1 receipts. It carries exact source,
compiler, profile, image, binary, observer and evidence-inventory identities.
External freeze pins are inputs to verification; a self-indexed artifact hash is
not an independent runtime identity. JSON duplicate keys and optimization that
would disable Python assertion gates are rejected. File populations are closed,
all retained hashes verified, and raw evidence remains available for review.

For each actual shell, compare exact decoded script bytes, actual interpreter and
flags, exit code, stage/step identity, semantic stdout and terminal outcomes.
Jenkins script-path argv and product `-c` argv are separately retained rather than
required to be literally equal. Actual shell execution counts and order must
match the nineteen required executions; skipped work cannot be inferred merely
from precreated controller accounting attempts.

The fixed scripts intentionally emit no stderr. Product stderr is independently
attributed to the exact executed attempt and script. The separately frozen
`scripts/jcomp003/xtrace-expectations-v1.json` preregisters exact xtrace bytes for
each script, including empty traces for skipped steps. These manually authored
expectations are bound to the manifest and exact shell SHA-256; they are not
measured output. Product stderr must equal those bytes. Jenkins per-shell combined
log bytes must be an exact sequence-preserving merge of product stdout and that
same frozen xtrace; stdout must equal the manifest's exact bytes. No arbitrary line is
dropped because it starts with `+`, no whitespace is trimmed, and no unexpected
line is classified as protocol output after the fact. Raw top-level Jenkins
banners remain retained; per-shell log attribution avoids deleting banners from
workload data. This certifies combined semantic output for the fixed cases, not
universal stdout/stderr interleaving. An unexplained wrapper record or stream
mismatch fails verification and requires a reviewed, versioned correction.

Jenkins's complete workload workspace is inventoried before cleanup, including
regular file contents/digests, directories and any unexpected links or special
entries. Product's final validated workspace receipt carries its observed paths,
sizes and content digests captured before the runtime removes raw checkpoint
bytes. Both must match the manifest's exact files and derived ancestor directories;
extra files, directories, links or special entries fail. Jenkins control material
is separately and recursively inventoried, never removed by a broad filename
pattern. Controller checkpoint closure, eleven distinct build namespaces, exact
attempt workspace/result cleanup, Jenkins workspace/control cleanup and eventual
container/tmpfs removal are all required receipts.

## Published retention and offline verification

The retention receipt schema is `mcloving.jcomp003.retention/1`. Its exact
fields are `schema`, `source`, `pins`, `omissions`, and `files`. `source` binds
`base_commit`, `commit`, `tree`, `archive_sha256`, and `bundle_sha256`; `pins`
binds `report_sha256`, `jenkins_inventory_sha256`, `product_inventory_sha256`,
`compiler_campaign_sha256`, `prepared_input_sha256`, `worker_sha256`, and
`admission_sha256`. `omissions` is the exact fixed five product observer-body
path/digest map. `files` exhausts retained files except the receipt itself. The
read-only `verify-retained.py` requires external `--retention-sha256` and
`--base-commit` pins. It recomputes the original full report and requires exact
report equality except for the two explicit artifact-verification-mode fields.

A publication may replace the product `source.tar` body with a small incremental
Git bundle containing the executed source commit against the verified protected
runtime base. An externally pinned retention manifest binds that base, executed
commit/tree, bundle SHA-256, exact regenerated archive SHA-256, every retained
file and the original report/inventory/compiler/input pins. Hydration uses an
isolated temporary Git object database; it verifies the bundle's exact advertised
commit, prerequisite ancestry and tree, then reconstructs and authenticates the
archive. It never rewrites the user's checkout or treats an unversioned `/tmp`
file as authority. The hydrated archive must reproduce the externally pinned Git
tree and every retained observer/current-policy source byte used by verification.

Full artifact verification remains the default. A separate retained mode may
omit exactly five copied observer binary bodies: `tracer/strace` and
`tracer/lib/libunwind-ptrace.so.0`, `tracer/lib/libunwind-x86_64.so.8`,
`tracer/lib/libunwind.so.8`, and `tracer/lib/liblzma.so.5`. Their original hashes
remain in the unchanged externally pinned artifact inventory, and the report
explicitly labels them captured identities only. The observer script, all raw
semantic observations, source archive, profile, boundary inspections and cleanup
receipts remain mandatory. There is no generic allow-missing option. Retained
verification recomputes the same semantic comparison and identifies the precise
binary-body limitation; it does not claim a new runtime execution or compiler
admission replay. Controller/agent execution identities already use captured
binary digests and independently bound build provenance, not published executable
payloads.

## Findings and recertification

Any mismatch prevents a successful report. A runtime defect returns to a separate
bounded implementation ticket, protected review and merge, and exact-main gates;
affected evidence is regenerated on the corrected exact runtime. JCOMP-003 is not
a bucket for runtime repairs. Tooling defects also retain failed observations and
require a new versioned run after reviewed correction. Later runtime changes
invalidate this exact-runtime certification under existing recertification and
late-correction rules.

This campaign does not establish hostile same-UID isolation, production storage
quotas, artifacts/test reports, live SCM, credentials, plugin steps, performance,
migration/cutover/canary eligibility, deployment authority or arbitrary accepted
shell-program equivalence. SEC-005 retains hostile workload containment ownership.
