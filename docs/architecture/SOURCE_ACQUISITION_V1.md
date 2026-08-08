# Source acquisition v1

Status: implementation contract for the SCM-001 contained boundary. No Mario
production repository, credential, checkout, canary, or cutover is claimed.

## Inventory boundary

The accepted Mario MIG-000 job graph and runtime-dependency manifest are the
files under
`migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/` pinned by
that directory's `SHA256SUMS`. All 230 jobs use frozen inline Jenkins sources;
the runtime manifest contains no admitted live SCM dependency, repository
configuration, source credential, submodule graph, or checkout grant. The
separate 228-file corpus index records historical public-source provenance and
commit identifiers, but it is not a live repository or credential inventory.
SCM-001 therefore implements a reusable contained boundary without converting
those provenance rows into production authority.

## Process and authority boundary

`mcloving-source-acquirer` is a standalone NDJSON process. It is not loaded into
the controller or either pipeline runner. Its admitted authorities are limited
to:

- read one immutable JSON configuration, one short-lived source credential,
  one receipt-signing key, and one secret-marker set;
- execute exact content-hashed Git and HTTPS-transport-helper binaries named by
  configuration with a cleared and allowlisted environment;
- contact only the configured repository endpoint, fetch one authenticated ref,
  and resolve it to the request's exact commit;
- materialize a bounded immutable source snapshot below its private output root
  without executing repository content; and
- durably publish one signed receipt or emit one bounded typed error per NDJSON
  command.

It has no scheduler, controller database/filesystem, agent RPC, workload
credential, unrelated secret, dependency resolver, cache, trigger, connector,
observer, or effect authority. Pipeline runners never receive the source
credential and cannot ask the acquirer to run an arbitrary Git command.

V1 is admitted only on Linux hosts with sealed-memory-file support. The output
root must be absolute, canonical, owned by the effective UID, non-symlink, and
mode `0700`. Configuration,
credential, signing-key, marker, executable, claim, receipt, and retained
manifest reads are bounded and reject non-regular or final-component symlink
files. Credential and signing-key files must be owned by the effective UID and
have no group or other permission bits. Runtime deployment must additionally
mount configuration and authority files read-only, expose only the exact
repository endpoint through egress policy, bound the private output volume, and
use a dedicated service identity.

## Certified configuration

The canonical configuration digest binds:

- protocol and schema versions;
- acquirer, deployment, operator, and monotonic generation identities;
- provider identity, exact normalized repository URL/identity, and fork policy;
- exact Git executable path/SHA-256/version and exact HTTPS remote-helper
  executable path/SHA-256;
- the strictly ordered canonical absolute path and SHA-256 of every resolved
  dynamic-runtime file plus the digest of that complete closure;
- grant identity/version/scope/expiry and credential SHA-256;
- receipt-key identity/content digest and secret-marker-set digest;
- allowed ref prefixes, submodule repositories, sparse roots, and maximum depth;
- fetch/process timeout, transport-staging, file/count/byte/path/submodule bounds;
- private output root, optional private-CA path/content digest; and
- the loopback/file-fixture flag, which also requires explicit test mode.

Production repositories use HTTPS, contain no user information, query, or
fragment, and require a content-pinned private CA. Redirects, ambient proxies,
host credential helpers, interactive prompts, automatic maintenance, hooks,
filters, alternate object stores, replacement objects, filesystem monitors,
and recursive submodule commands are disabled. Cleartext loopback or local
`file` fixtures require both the configuration flag and
`MCLOVING_SOURCE_ACQUIRER_TEST_MODE=1`.

Before every credential-bearing network command, including a lazy promisor
object read, the acquirer passes the configured normalized repository URL as a
separate trusted parameter rather than trying to infer it from Git's command
arguments, then starts its sealed, runtime-bound implementation snapshot in a
dedicated resolver mode. That child receives only the URL's endpoint hostname
and port in a cleared environment and
refuses to run if any credential-file, credential-digest, signing-key, or
secret-marker authority is present. Its numeric results and diagnostics are
bounded, its process group and the following Git child share one monotonic
command/request deadline, and any malformed, empty, excessive, failed, or
timed-out result fails source acquisition. The resolver receives that absolute
deadline rather than a relative duration: its own ten-second cap is intersected
with the shared deadline before URL parsing and command construction, the bound
is checked before spawn, and the remaining interval is recomputed after spawn
and pipe setup before the parent waits. The deadline is checked again before a
successful child status is accepted. Expiry at any check fails closed and
terminates the resolver process group. The parent captures the monotonic
anchor before sampling wall-clock expiry at full realtime resolution; it
subtracts that sample from the signed millisecond deadline without rounding the
remaining interval up. It rechecks the resulting absolute deadline before and
immediately after Git startup, checks it again before
accepting either exit path, and never restarts a relative duration. On Unix the
parent also passes that original absolute `CLOCK_MONOTONIC` deadline to the
transport launcher and askpass as nanoseconds; those child modes arm and check
the same bound directly and never reconstruct it through wall time. The parent
passes the complete bounded address set to Git through one
`http.curloptResolve` rule for the endpoint, encoding every numeric IPv4 and
IPv6 address in that single host/port entry while preserving the original HTTPS
hostname for TLS verification. Because redirects and proxies are disabled, the
credential-bearing Git/HTTPS-helper chain does not invoke ambient NSS service
modules for the admitted repository endpoint. Literal IP endpoints require no
resolver child.

The process opens itself, Git, the HTTPS remote helper, and any private CA
without following a final symlink, hashes the exact bytes, copies them into
anonymous memory-backed files, and applies write/grow/shrink/further-seal
kernel seals before use. Git and askpass execute only those immutable snapshots;
the CA is read only from its sealed snapshot. The sealed executable, runtime,
preload, and CA descriptors plus the read-only private-directory descriptors
are intentionally inherited with close-on-exec disabled and are addressed only
through `/proc/self/fd`. Namespace descendants therefore never reopen an
ancestor process's descriptor links, while every inherited file remains
kernel-sealed and every inherited directory topology is reverified. A private
descriptor-bound command directory is both `GIT_EXEC_PATH` and the sole `PATH`.
It exposes the sealed Git
snapshot as `git` and `git-upload-pack` and the sealed transport helper as
`git-remote-http` and `git-remote-https`, preventing ambient lookup by Git's
internal children as well as its transport. Original-path replacement or
in-place mutation therefore cannot substitute bytes between verification and
use. At initialization the process resolves the dynamic loader and shared
libraries for the sealed Git, helper, and askpass images, requires that exact
set to equal the configured runtime closure, and opens every closure file by
descriptor. Runtime files must be root-owned regular files with no group/world
write permission. Construction verifies their complete content digests, copies
each library and loader into a sealed memory file, and retains the original
path's device, inode, size, mode, owner, modification time, and unforgeable
change time. Git runs with immediate symbol binding and a private
descriptor-backed library directory whose exact links target only inherited
sealed descriptors. The sealed Git, helper, and askpass ELF images are
deterministically rewritten to name the retained loader descriptor as their
interpreter. Before sealing each retained loader, construction rewrites its sole
system-wide preload-file pathname to an inherited, kernel-sealed empty file
descriptor; the loader can therefore neither reopen `/etc/ld.so.preload` nor
inject an ambient library named there. Neither initial process startup nor
internal children reopen an ambient loader, library, or preload input.
Original-path metadata fingerprints, memory-file seals, inherited-descriptor
flags, and directory topology are reverified before every invocation. An atomic
package replacement or in-place change therefore fails closed, while a change
after verification cannot alter the sealed bytes used by the child. Missing,
extra, reordered, substituted, mutable, or same-name closure entries fail
closed. Credential material is also revalidated before every Git invocation. A
caller must present the acquirer, Git, helper, and canonical-configuration
hashes. Any implementation, runtime closure, Git, helper, repository, grant,
policy, or generation substitution fails before Git or network access.

## Acquisition request

Every request binds:

- acquisition ID plus tenant, project, pipeline, build, and attempt IDs;
- logical checkout name and audit lineage;
- expected acquirer/Git/configuration hashes, protocol/schema, and generation;
- provider and repository identities, authenticated full ref, and exact commit;
- trusted-source identity and explicit trusted/untrusted-fork disposition;
- positive requested shallow depth and canonical sparse roots;
- the complete expected recursive submodule path/repository/commit graph;
- request/expiry times and optional rollback-from generation.

Unknown fields, recursively duplicated JSON members, control-bearing identities,
noncanonical repository URLs, symbolic or abbreviated commits, refspecs,
negative refs, option-like refs, path traversal, duplicate sparse roots,
duplicate submodule paths, graph cycles, and unconfigured repositories are
denied. A rollback generation must be older than the active generation. The
NDJSON frame is capped at 64 KiB.

## Exact-ref and repository policy

The acquirer initializes a private bare partial-clone repository on a dedicated
configuration-bound transport filesystem, installs no
working-tree hooks, and fetches exactly the configured URL and requested full
ref with `blob:none`, no tag-following, and the configured depth. Git object
storage is still monitored while every credential-bearing Git command runs and
is measured after every command, but polling is not the enforcing quota. The
configured transport root must be a canonical, private `0700`, acquirer-owned
Linux mount point on a different device from both its parent and the publication
root; its total block capacity must equal `max_transport_bytes`. An exclusive
filesystem-root lock serializes every cooperating acquirer, and any residual
entry other than that lock fails closed before a claim is created. The kernel
therefore refuses even a temporary pack allocation beyond the bound, including
files created and removed between scans. A C-locale `ENOSPC` Git failure maps to
the typed limit outcome. The live traversal remains an early-kill mechanism:
the complete Git process group is killed when it observes a breach, child exit
and the exact command/request deadline remain concurrent with every traversal,
and a disappearing entry restarts measurement from the repository root before
three failed restarts fail closed. Only selected blobs and required
`.gitmodules` content are fetched lazily, and a quota breach fails before
publication. An
admitted repository endpoint must support filtered fetch and exact reachable
promisor-object wants. A successful server response that warns it ignored
`blob:none` is treated as refusal and is a typed source-unavailable failure;
the acquirer never accepts an unfiltered fallback. The private volume must
reserve the materialization ceiling separately from the dedicated transport
mount.
`FETCH_HEAD^{commit}` must equal the
request's full commit before any source is published. A later movement of the
same ref is delivered only by a new request naming the later exact commit; a
stale request cannot silently receive it.

The credential reaches Git byte-for-byte only through the acquirer's bounded,
implementation-hash-revalidated askpass mode; non-UTF-8 or newline-bearing
grants are ineligible. It never appears in argv, configuration, receipt,
diagnostics, or the output tree. Configuration is invalid unless the certified
secret-marker set contains the exact credential bytes, so the credential is
always denied if repository content attempts to reproduce it.
Askpass re-hashes the exact bytes it reads against the configured credential
digest before writing those same bytes, so a path replacement between parent
verification and the remote prompt fails closed. It also receives the earlier
of the signed request/publication deadline and configured command deadline, and
rechecks that bound before opening credential authority and immediately before
writing any username or credential bytes. On Unix it first arms a POSIX
`CLOCK_MONOTONIC` absolute timer whose kernel-delivered `SIGKILL` remains active
through the complete output operation, making credential emission impossible
after the deadline even if askpass is descheduled while its stdout pipe is
blocked. Before credential-bearing Git starts, the sealed acquirer launcher
creates a user and PID namespace under a named AppArmor profile that grants only
`userns create`. Its parent owns the UID/GID mapping. After the mapping gate,
the launcher arms a POSIX `CLOCK_MONOTONIC` timer that delivers `SIGKILL`
directly to the launcher, then starts PID-namespace process 1. That init installs
kernel `PDEATHSIG=SIGKILL` and reports readiness before Git can start. Only a
second parent gate releases init to execute the sealed Git snapshot. At expiry,
the kernel kills the launcher, the parent-death signal kills namespace init,
and Linux destroys every remaining Git, HTTPS-helper, askpass, and descendant
process in that PID namespace. No userspace signal handler or scheduled reaper
is required after the timer is armed. Normal completion also destroys the
namespace before output is accepted. A missing or unselected deployment profile
fails closed before Git starts. A parent runtime descheduled after successful
askpass emission therefore cannot let buffered credential authority continue
past the admitted transport deadline.
The Git child receives a cleared environment containing only fixed locale/path,
askpass, CA, and protocol-control values. All stderr is bounded and reduced to
typed errors after secret-marker scanning. Each credential-bearing fetch is
terminated at the earlier of the configured command timeout or the request,
grant, and publication deadline.

Fork admission is fail closed. A trusted request must name the configured
repository identity. An untrusted-fork request is rejected unless the immutable
configuration explicitly admits that exact fork repository and read-only trust
class; admitting source bytes never grants secrets, cache trust, deployment,
connector, or effect authority.

## Non-executing materialization

Repository-controlled code is never checked out by Git. After exact resolution,
the acquirer obtains the recursive tree and blob objects through fixed Git
plumbing commands and writes them itself. This prevents checkout hooks, smudge
filters, submodule update commands, or repository configuration from executing.

Only regular files (`100644`), executable files (`100755`), bounded relative
symlinks (`120000`), and expected submodule gitlinks (`160000`) are admitted.
Paths must be canonical UTF-8 relative paths, remain below the snapshot root,
contain no `.git` component, and satisfy configured path/count/byte limits.
Symlink targets must be relative and resolve within the same snapshot. Special
files, unsafe symlinks, duplicate/colliding paths, Unicode compatibility-
normalized full-case-fold collisions at any ancestor or leaf, and unexpected
gitlinks fail closed before publication. The
global materialized-file count includes every selected gitlink even when sparse
selection omits all of that submodule's child files. A gitlink selected directly
or as the component-boundary ancestor of a selected submodule path always
materializes its read-only directory boundary, including gitlink-only sparse
results, so first publication and replay verify the same tree shape. Ordinary
file and symlink leaves are selected only when equal to or below a sparse root;
they are never materialized merely because a requested root names an impossible
descendant below that leaf.

Sparse roots select complete path components, not string prefixes. The receipt
records both the full repository tree identity and the exact materialized
manifest so omitted paths cannot be mistaken for missing source. Empty sparse
results are denied without publishing an out-of-scope leaf ancestor.

The root tree's `.gitmodules` declarations and every gitlink are parsed without
executing repository code. They must match the request's complete recursive
submodule graph and immutable configuration allowlist exactly. Each submodule is
fetched and materialized through the same exact-ref/commit, credential, limit,
and non-execution rules. Missing, extra, moved, substituted, cyclic, or excessive
submodules are denied.

## Durable publication and replay

Before network access the acquirer durably records a first-writer claim binding
the canonical request digest and publication deadline. Concurrent or restarted
reuse with different content is denied. Matching completed requests replay the
same verified receipt and snapshot without another fetch. A crash after claim
creation but before publication is ambiguous and requires explicit cleanup; it
never silently re-fetches a mutable ref.

Objects and materialized files are built below an unpredictable private staging
directory. Every file and directory is synchronized, the canonical manifest and
signed receipt are written and synchronized, and the complete directory is
atomically renamed to its final acquisition-ID path. Each final file mode and
nested-directory mode is fsynced after chmod and before rename. Every retained file and
directory, including the acquisition root, is made read-only before publication,
and replay revalidates every directory's owner and exact mode as well as every
leaf. Publication and timeout decisions share the same exclusive output-root
lock. A claim is checked before any completed receipt can replay. After final
rename and root synchronization, the deadline is checked before and after claim
removal. If either check is late or any post-rename synchronization/finalization
step fails, the public acquisition directory is first atomically renamed to an
unpredictable hidden quarantine and that removal is synchronized. Only then is
an absent ambiguity claim recreated and synchronized; cleanup follows while the
root lock remains held. A late snapshot
therefore cannot replay or remain at its public path after a caller has accepted
timeout. Failed and expired staging trees recursively restore owner-write
directory modes before removal without following symlinks.

The canonical manifest binds path, Git mode, Git object ID, byte length, and
SHA-256 for every materialized entry plus each submodule boundary. The receipt
repeats every relevant request/configuration identity, including the certified
runtime-closure digest, and adds the resolved
commit/tree, complete submodule graph, sparse/depth options, manifest/content
digests, output-relative identity, counts/bytes, acquisition time, publication
deadline, and signing-key identity. HMAC-SHA-256 covers the complete receipt;
verification also re-hashes the retained manifest. The HMAC key is never
exposed to a runner. Acquirer/verifier collusion remains residual risk for
DIFF-003 and later production gates.

No receipt grants trigger, scheduler, secret, dependency, cache, connector,
effect, canary, cutover, rollback, or decommission authority. Later gates must
re-read the exact acquirer, Git binary, configuration, repository, grant,
snapshot, verifier, and generation and reject drift.

## Executable proof

Contained proof must exercise a real Git repository and the standalone binary.
It covers exact and later commits, ref movement/substitution, untrusted forks,
credential success/denial/non-disclosure, replay mismatch, concurrent
deduplication, restart replay, sparse/depth behavior, recursive submodules,
submodule substitution/cycles, unsafe paths/symlinks, file/count/byte/time
bounds, cleanup, configuration/Git/executable drift and path replacement,
credential-marker completeness, runtime-closure omission, filtered-fetch
refusal, retained-directory mode drift, late final-publication withdrawal,
generation cutover, rollback binding, and differential snapshot truth.

An inventory test separately pins the accepted Mario manifests and proves that
their current denominator contains zero admitted live SCM configurations or
credential grants. Historical corpus provenance is reported separately and
cannot satisfy that production denominator.
