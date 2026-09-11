# Closed source containment prerequisite

This is a standalone Linux source launch protocol. Submitted jobs do not select
it, and it does not advertise source acquisition capability. Receipt/tree
custody, retained aggregate storage ownership, agent durable integration, and
workload containment remain separate gates. Passing source bytes on stdout is
not an accepted terminal result until the caller proves containment complete.

## Authority and supported caller

A trusted operator launcher selects and hashes the source executable, seals its
same-opened image in a memfd with WRITE/GROW/SHRINK/SEAL seals, clears the initial
loader environment, and passes only the documented authority channels. A sealed
image and a checked parent environment do not defeat an injected dynamic loader
that ran before `main`. A compromised same-UID actor with ptrace or active mount
interference, or a privileged host administrator, is outside this boundary.
The typed library API also trusts its calling implementation: same-image
lineage is meaningful because the operator pinned the intended source binary;
it is not an attestor for arbitrary programs linking the library.
The fixed source child command clears its environment, forwards only source
configuration/key/credential/marker paths and the explicit test controls, and
closes unrelated inherited file descriptors.

The outer process requires full identity UID and GID maps (`0 0 4294967295`) and
the operator's approved host launch context. It directly selects only
`mcloving-source-acquirer`, then checks the running label exactly as
`mcloving-source-acquirer (unconfined)`. This profile is an unconfined domain with
user-namespace creation authority, not a restrictive filesystem or network
sandbox. No profile name, arbitrary launcher path, or command argv comes from a
submitted intent. Missing transition permission, wrong label, restricted
namespace authority, unavailable `openat2`/pidfds, or remapped initial identity
refuses the closed path. No whole-agent profile transition is required.

The new user namespace maps namespace UID/GID 0 only to the caller's effective
host UID/GID. Namespace root is needed across exec for the source init's private
mount setup; it delegates no host identities or privileges beyond that caller.
Deployment should use a dedicated non-root service identity.
The init creates its own mount namespace, makes propagation recursively private,
and mounts fresh proc with `nosuid,nodev,noexec`. No shared host profile or mount
is replaced. Fresh proc is necessary for native nested transport admission to
address the correct namespace-local child UID/GID maps.

## Runtime ownership across UID translation

Existing native runtime loading requires root-owned, non-group/world-writable
libraries. A caller-only user namespace represents host-root libraries as an
unmapped UID, while caller-owned files may appear to be UID 0. Accepting the
unmapped UID or relaxing the ordinary root check would therefore be incorrect.

Before namespace creation, the fixed outer image reads a bounded configuration,
checks its canonical expected digest, and opens the configured runtime closure.
Each held original file must be regular, root-owned in the approved full identity
context, non-group/world-writable, at its canonical path, and match the pinned
SHA-256. Duplicate underlying objects are refused. The closed path allows at
most 256 runtime files, 512 MiB aggregate runtime bytes, and a 256 KiB sealed
custody manifest. These additional limits are fail-closed admission bounds.
Neither supervisor opens credentials, signing keys, or secret-marker files.

A bounded sealed manifest binds the exact configuration digest, runtime binding,
held FD, and device/inode/length/mode/mtime/ctime identity. The manifest is sealed;
the original root-owned runtime files remain held original files until native
loading creates its existing sealed runtime snapshots. An immutable manifest
alone does not prove who checked ownership. The typed receiver proves its live
parent pidfd, same sealed source-image inode, exact initial `outer` or `init`
mode, unambiguous parent environment, and parent's custody of that same manifest
FD. Each hop re-encodes a sealed manifest over its newly retained FD numbers.
Only a validated typed custody value permits the native constructor to consume
held runtime files; ordinary construction retains its existing UID-0 check and
never accepts an environment flag claiming that root ownership was checked.
Native runtime path-drift checks retain metadata captured after UID translation.

Proc authority reads use a held proc root, procfs/root-inode checks, a pinned
kernel `self` link, numeric task directories, and `openat2` with `NO_XDEV`,
`NO_SYMLINKS`, and `BENEATH`. Static bind overlays cannot impersonate UID/GID maps,
status, environment, or fdinfo. Final executable and FD magic links necessarily
leave proc when followed, so their genuine proc symlinks are pinned and checked
on both sides of the follow. This rejects static overlays; it does not claim
protection against active same-UID mount substitution between checks.

## Private launch protocol

The caller invokes only the sealed source image with no arguments. Environment
`MCLOVING_SOURCE_CONTAINMENT=outer` selects the closed path. The following
`MCLOVING_SOURCE_CONTAINMENT_` variables contain canonical decimal FD numbers:

- `IMAGE_FD`: the inherited fully sealed same-running-image memfd.
- `PARENT_PIDFD`: a pidfd opened by the caller to itself; unrelated/dead identities
  and ordinary files are refused.
- `READY_FD`: the outer's write end of a private control pipe.
- `GATE_FD`: the outer's read end of a separate private control pipe.

`DEADLINE_MONOTONIC_NS` is an absolute monotonic deadline no more than fifteen
minutes away. The source configuration's canonical expected digest is mandatory.
The image, parent, ready, and gate descriptors must be distinct. Both supervisors
also require the held ready and gate pipes to have different device/inode identities
before profile or runtime-custody work: different descriptor numbers for the
same pipe cannot acknowledge the supervisor's own readiness bytes. Stdout/stderr
remain native private response channels; the control stream is separate.

The outer emits `P` after exact profile selection and waits for byte `P`. It
captures runtime custody, creates/maps the user and child PID namespaces, emits
`N`, and waits for byte `N`. After the init has armed its death link, verified
custody, and mounted private proc, the outer emits `R` followed by the init's
positive host PID as four little-endian bytes. It then waits for byte `R` before
allowing the ordinary source worker to start. EOF, wrong acknowledgements, and
invalid setup refuse the launch. The caller keeps credential-bearing request
stdin withheld until its own durable spawn authority is committed.

Before acknowledging `R`, the caller must open and retain a pidfd for that exact
live namespace init while the outer is gated. It verifies the parent, namespace,
profile, and image identities against the exact outer invocation. A future
product wrapper must retain both outer and init identities; a raw stored PID is
not a substitute. Internal `init`, `worker`, and runtime custody controls are
implementation channels, not general command or profile APIs.

## Lifetime and recovery contract

The outer arms `PDEATHSIG(SIGKILL)` and checks its inherited caller pidfd before
and after setup transitions, including user namespace mapping. A dead pidfd's
kernel `Pid` identity is negative, so PID reuse does not revive parent authority.
Linux parent-death signals track the spawning thread: that thread must remain
alive for the invocation; its exit also terminates the source boundary.
The init arms `PDEATHSIG(SIGKILL)` before acknowledging readiness. Its parent
lives outside the new PID namespace, so `getppid()==0` is not used as a parent
identity check there; the private ready/gate handshake closes the early-parent
exit race. A finite outer monotonic SIGKILL timer also bounds blocked setup and
source lifetime. Native source deadlines and separate-process-group cancellation
remain in place.

The init waits for the ordinary source worker and then exits. Linux namespace
PID1 teardown kills and reaps every remaining descendant, including new process
groups and nested PID namespaces. On normal completion, the outer waits for that
exact child before returning success. On outer cancellation or death, outer
process exit alone does not prove that asynchronous namespace teardown has
finished: the caller must additionally join the retained init pidfd and enforce
its cleanup deadline. If that proof is unavailable, raw source output remains
unaccepted and the invocation is unresolved.

Agent death cannot persist a kernel descriptor for a restarted agent. Recovery
must park unresolved work and retain claims/receipts; it must not signal a reused
PID, delete a claim, refetch under another ID, or publish unproved success. This
standalone prerequisite is not a durable agent recovery implementation.
