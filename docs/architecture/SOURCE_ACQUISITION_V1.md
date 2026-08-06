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
- execute the exact content-hashed Git binary named by configuration with a
  cleared and allowlisted environment;
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

V1 is admitted only on Unix hosts. The output root must be absolute, canonical,
owned by the effective UID, non-symlink, and mode `0700`. Configuration,
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
- exact Git executable path, executable SHA-256, and admitted Git version;
- grant identity/version/scope/expiry and credential SHA-256;
- receipt-key identity/content digest and secret-marker-set digest;
- allowed ref prefixes, submodule repositories, sparse roots, and maximum depth;
- fetch/process timeout, file/count/byte/path/submodule bounds;
- private output root, optional private-CA path/content digest; and
- the loopback/file-fixture flag, which also requires explicit test mode.

Production repositories use HTTPS, contain no user information, query, or
fragment, and require a content-pinned private CA. Redirects, ambient proxies,
host credential helpers, interactive prompts, automatic maintenance, hooks,
filters, alternate object stores, replacement objects, filesystem monitors,
and recursive submodule commands are disabled. Cleartext loopback or local
`file` fixtures require both the configuration flag and
`MCLOVING_SOURCE_ACQUIRER_TEST_MODE=1`.

The process hashes itself and the configured Git executable before accepting a
request. A caller must present both hashes and the exact canonical configuration
digest. Any implementation, Git, repository, grant, policy, or generation
substitution fails before Git or network access.

## Acquisition request

Every request binds:

- acquisition ID plus tenant, project, pipeline, build, and attempt IDs;
- logical checkout name and audit lineage;
- expected acquirer/Git/configuration hashes, protocol/schema, and generation;
- provider and repository identities, authenticated full ref, and exact commit;
- trusted-source identity and explicit trusted/untrusted-fork disposition;
- requested shallow depth and canonical sparse roots;
- the complete expected recursive submodule path/repository/commit graph;
- request/expiry times and optional rollback-from generation.

Unknown fields, recursively duplicated JSON members, control-bearing identities,
noncanonical repository URLs, symbolic or abbreviated commits, refspecs,
negative refs, option-like refs, path traversal, duplicate sparse roots,
duplicate submodule paths, graph cycles, and unconfigured repositories are
denied. A rollback generation must be older than the active generation. The
NDJSON frame is capped at 64 KiB.

## Exact-ref and repository policy

The acquirer initializes a private bare repository, installs no working-tree
hooks, and fetches exactly the configured URL and requested full ref. It applies
the configured depth and no tag-following. `FETCH_HEAD^{commit}` must equal the
request's full commit before any source is published. A later movement of the
same ref is delivered only by a new request naming the later exact commit; a
stale request cannot silently receive it.

The credential reaches Git byte-for-byte only through the acquirer's bounded
askpass mode; non-UTF-8 or newline-bearing grants are ineligible. It never
appears in argv, configuration, receipt, diagnostics, or the output tree.
The Git child receives a cleared environment containing only fixed locale/path,
askpass, CA, and protocol-control values. All stderr is bounded and reduced to
typed errors after secret-marker scanning.

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
files, unsafe symlinks, duplicate/colliding paths, case-fold collisions, and
unexpected gitlinks fail closed before publication.

Sparse roots select complete path components, not string prefixes. The receipt
records both the full repository tree identity and the exact materialized
manifest so omitted paths cannot be mistaken for missing source. Empty sparse
results are denied.

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
atomically renamed to its final acquisition-ID path. The output tree is made
read-only before publication. Publication and timeout decisions share the same
exclusive output-root lock so a late snapshot cannot appear after a caller has
accepted timeout. Failed and expired staging directories are removed without
following symlinks.

The canonical manifest binds path, Git mode, Git object ID, byte length, and
SHA-256 for every materialized entry plus each submodule boundary. The receipt
repeats every relevant request/configuration identity and adds the resolved
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
bounds, cleanup, configuration/Git/executable drift, generation cutover,
rollback binding, and differential snapshot truth.

An inventory test separately pins the accepted Mario manifests and proves that
their current denominator contains zero admitted live SCM configurations or
credential grants. Historical corpus provenance is reported separately and
cannot satisfy that production denominator.
