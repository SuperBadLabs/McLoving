# Dependency resolution v1

Status: implementation contract for the DEP-001 contained boundary. No Mario
production dependency repository, credential, resolution, cache, canary, or
cutover is claimed.

## Inventory boundary

The accepted Mario MIG-000 runtime-dependency manifest is
`migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/runtime-dependencies.yaml`,
pinned by that directory's `SHA256SUMS`. It contains 230 jobs and exactly 230
`opaque-cps-runtime`, `controller-global`, `scripted` records. It contains zero
`workload-dependency` records and grants no Maven, npm, PyPI, repository,
package, resolver, signing-key, attestation, or credential authority.

DEP-001 therefore implements and adversarially proves a reusable contained
resolver. A later inventory generation and the board-defined differential,
package, canary, cutover, rollback, and decommission gates must explicitly
admit and reverify any production dependency authority.

## Component boundary

`mcloving-dependency-resolver` is a standalone strict-NDJSON process. It is not
loaded into the controller, pipeline runners, source acquirer, cache, or agent.
The crate keeps five internal components behind versioned Rust interfaces:

1. ecosystem adapters parse bounded lock bytes into one canonical graph;
2. policy admission binds source trust, repositories, coordinates, grants,
   resolver/toolchain identity, limits, and deadlines;
3. transport fetches exact allowlisted artifact paths without redirects,
   ambient proxies, or implicit retries;
4. verification checks size, content digest, and configured repository
   attestation before publication; and
5. publication writes an immutable content-addressed bundle plus a signed,
   replayable resolution receipt.

Adapters never perform network access. Transport never interprets lock syntax.
Verification never executes artifact bytes. Publication cannot contact a
repository. These interfaces allow an ecosystem adapter or transport to be
replaced only through a new configuration/implementation digest and later
recertification, without changing the canonical receipt contract.

The process may:

- read one immutable configuration, one optional repository credential per
  configured repository, one source-provenance attestation public key,
  repository attestation public keys, one receipt key, and one secret-marker
  set;
- read one bounded lock file supplied with the request;
- issue `GET` only to exact artifact paths derived from the admitted canonical
  graph and configured repository base URL;
- write transient downloads only on its dedicated bounded transport filesystem;
- atomically publish verified artifacts below its private output root; and
- emit one signed receipt or bounded typed error for each NDJSON request.

The `mcloving-dependency-resolver` executable accepts only `--config <path>`.
The configuration is a resolver-owned regular file with no group/other mode
bits, the running executable is re-hashed against `executable_sha256`, and each
input line is capped before JSON allocation. A frame is one closed
`ResolutionFrame` object containing `request` and standard-base64 `lock_base64`.
Output is exactly one LF-terminated closed object per input: either
`{"status":"ok","receipt":...}` or a static, source-independent
`{"status":"error","code":...,"message":...}`. Oversized receipts are
replaced by `DEP_RESPONSE_FRAME_OVERSIZED`; they are never emitted partially.

It has no scheduler, controller database/filesystem, source credential, source
network authority, package-execution authority, build tool, shell, agent RPC,
shared cache, connector, observer, or production-effect authority. A pipeline
runner receives neither repository credentials nor an API for arbitrary URLs.

## Canonical resolution plan

Every admitted adapter produces `mcloving.dependency-plan/v1`. Canonical plan
bytes bind:

- ecosystem and adapter protocol/implementation digest;
- original lock-file SHA-256 and source-tree SHA-256 from SCM-001 provenance;
- exact resolver and toolchain identity/digest;
- a sorted, duplicate-free repository identity set;
- sorted package nodes containing canonical coordinate, exact version,
  repository identity, relative artifact path, declared size, SHA-256, and
  optional required attestation identity;
- sorted dependency edges and sorted roots; and
- the complete graph SHA-256.

Node identity is the domain-separated SHA-256 of ecosystem, coordinate, exact
version, repository identity, artifact path, content digest, and attestation
identity. Edges reference only node identities. Missing nodes, duplicate nodes
or edges, self edges, cycles, unreachable nodes, conflicting coordinates,
noncanonical order, graph limits, traversal, absolute paths, URL syntax in an
artifact path, and mutable versions are denied before credential or network
access.

Reachability and cycle validation use an iterative enter/exit color worklist,
not process-stack recursion, and are proven at the signed 100,000-node maximum.
The distinct repository identities named by graph nodes must exactly equal the
request repository bindings; an unused repository or grant is denied before
claim creation or network access.

The canonical graph is the stable compatibility seam. Ecosystem-specific
source syntax does not leak into transport or receipt verification.

## V1 ecosystem adapters

V1 admits only closed, fail-closed subsets:

- **npm:** package-lock JSON v3 with an exact package version, one configured
  registry origin, integrity metadata that includes the configured SHA-256
  extension, and no link, workspace, file, Git, alias, bundled, optional,
  platform-conditional, or install-script authority. Unknown or duplicate JSON
  members are denied recursively. The contained v1 adapter admits only a flat
  `node_modules/<canonical-name>` layout. Each non-root package carries one
  closed `mcloving` object with `repository_id`, relative `artifact_path`,
  positive `declared_size`, lowercase `sha256`, and optional
  `attestation_key_id`; `integrity` is exactly `sha256-<same-lowercase-hex>`.
- **PyPI:** UTF-8 requirements lines containing exactly one normalized package
  name, `==` exact version, configured index identity, artifact relative path,
  declared size, and `--hash=sha256:<64 lowercase hex>`. Environment markers,
  extras, editable/local/VCS/direct URL requirements, includes, constraints,
  alternate indexes, and unhashed entries are typed unsupported.
  The closed line grammar is `name==version --repository=<id>
  --artifact=<relative-path> --size=<positive-u64>
  --hash=sha256:<lowercase-hex>`, plus optional `--attestation=<id>`, optional
  comma-separated exact `--depends=name==version,...`, and `--root`; files use
  LF, end in LF, and do not use continuation or inline-comment syntax.
- **Maven:** `mcloving.maven-lock/v1` strict JSON generated by a separately
  versioned exporter. Every node names exact group/artifact/classifier/type and
  version, configured repository, artifact path, size, SHA-256, attestation,
  and complete transitive edges. Maven ranges, snapshots, metadata lookup,
  relocation, parent/plugin discovery, mutable mirrors, and omitted transitive
  nodes are typed unsupported. Node `key` values are exporter-local stable
  graph handles only; sorted `dependencies` and `roots` contain those handles,
  and the adapter replaces every handle with its canonical content-derived
  node identity before policy or transport can observe the graph.

An additional ecosystem requires its own adapter version, canonicalization
rules, negative syntax corpus, and exact-plan fixtures. V1 never falls back from
an unsupported native lock to online version solving.

## Certified configuration

The canonical configuration digest binds:

- protocol, schema, resolver, deployment, operator, and generation identities;
- exact running executable and every adapter implementation digest;
- exact resolver/toolchain identity and digest;
- the dedicated source-provenance Ed25519 public-key identity and content
  digest;
- each repository identity, normalized base URL, allowed ecosystem and
  coordinate prefixes, trust classes, private/public disposition, content
  policy, and attestation public-key identity/content digest;
- each optional grant identity/version/scope/expiry and credential digest;
- receipt-key identity/content digest and secret-marker-set digest;
- request, repository, node, edge, lock-byte, artifact-count, artifact-byte,
  per-artifact, path, header, timeout, and publication bounds;
- private output root and dedicated transport root;
- optional private-CA path/content digest for each HTTPS repository; and
- the loopback-fixture flag, which also requires explicit test mode.

Production repositories require HTTPS, no URL user information, query, or
fragment, and a content-pinned private CA. Redirects, ambient proxies, host
credential helpers, `.netrc`, alternate registries, content decompression,
and client-library retries are disabled. Credential-bearing repository clients
explicitly install `reqwest::retry::never()`, including for implicit HTTP/2
protocol-NACK handling. Cleartext loopback fixtures require
both configuration admission and `MCLOVING_DEPENDENCY_RESOLVER_TEST_MODE=1`.

Configuration, credential, signing-key, marker, public-key, CA, lock, claim,
receipt, and retained-manifest reads are bounded regular-file reads. Certified
configuration and executable paths are first pinned with
`O_PATH|O_NOFOLLOW`, rejected unless regular, and reopened only through the
pinned `/proc/self/fd` identity with `O_NONBLOCK`; device/inode equality is
rechecked before reading. Authority paths are resolved against the actual output
and transport roots, and authority files are opened component by component
relative to already opened directory descriptors so neither an ancestor nor
final symlink is followed. The final authority component is likewise pinned
with `O_PATH|O_NOFOLLOW`, type-checked without invoking FIFO or device open
behavior, reopened nonblocking through its pinned identity, and device/inode
rechecked before content validation. Authority
files must be owned by the effective resolver UID, have exactly one filesystem
link, and have no group or other permission bits. Every authority role must have
a unique device/inode and verified content digest. In addition to the resolved
path separation, every filesystem identity opened along an authority path is
compared with a non-symlink-following walk of the canonical output and transport
trees. Every encountered directory mount path is enumerated independently
through a FIFO worklist, without device/inode path collapsing, and each entry is
counted before worklist insertion. That combined walk is bounded at one million
entries, uses no recursive process-stack traversal, and fails closed on an
unreadable entry or exceeded bound. This prevents an authority file, ancestor,
or path-distinct child mount from reappearing through a hard link or bind mount
beneath either mutable root. The receipt key and every
repository credential are also separated by first trimming HTTP optional
whitespace and expanding a case-insensitive `Basic` authorization value through
padded or unpadded standard-Base64 decoding. Bidirectional containment then
checks the raw and decoded views, hexadecimal ASCII-case-insensitively for every
per-digit case mixture, and standard or URL-safe Base64 in padded and unpadded
forms. Construction validates every authority and limit before creating a claim
or contacting a repository.

`mcloving.secret-markers/v1` is closed JSON with one strictly sorted,
duplicate-free `markers_hex` array. Entries are lowercase even-length hex for
at least eight bytes. Every configured credential and the receipt HMAC key must
occur as exact decoded entries; the receipt key must contain at least 256 bits
of key material. Repository headers, streamed bodies, stdout, stderr, and
durable receipts are checked against all decoded markers, including matches
spanning response chunks. Immediately before each external frame is written,
the complete serialized success or error object plus its line terminator is
scanned again so fixed protocol keys, status values, error codes, messages, and
JSON punctuation cannot collide with a configured marker. A collision emits
neither that frame nor a stderr diagnostic and terminates the process
fail-closed. Startup and fatal process errors are silent because no successfully
loaded marker boundary is necessarily available to certify a diagnostic.

## Resolution request

Every request binds:

- resolution ID plus tenant, project, pipeline, build, and attempt IDs;
- audit lineage and source trust class;
- expected protocol/schema, resolver executable, configuration, adapter,
  resolver/toolchain, and generation identities/digests;
- SCM-001 acquisition-receipt digest, source-tree digest, logical lock path,
  lock bytes, and expected lock SHA-256;
- ecosystem and complete expected canonical graph SHA-256;
- repository and grant identities/versions/scopes used by the graph;
- request and expiry times; and
- optional rollback-from generation.

The caller-supplied source trust class is not authority by itself. Every request
also carries a closed `mcloving.source-provenance/v1` envelope. Its canonical
unpadded standard-Base64 Ed25519 signature covers a domain-separated canonical
serialization of the complete request with only `signature_base64` cleared, so
it binds source trust,
acquisition-receipt and source-tree digests, logical lock path and digest,
scope identities, graph and repository policy, exact certified configuration,
generation, and lifetime in one statement. The envelope key identity is pinned
by certified configuration, and its issued/expiry fields must equal the request
times exactly. The dedicated public key is loaded through the same bounded,
no-follow, owner/mode/link, device/inode, content-digest, and mutable-root
separation checks as every other authority. Signature verification precedes
claim creation and repository policy admission; a forged `Trusted` value can
therefore never unlock credentialed transport.

Frames are capped at 1 MiB before JSON allocation. Unknown fields, recursively
duplicate JSON members, control-bearing identities, invalid UUIDs/digests,
untrusted-source use of a private or credentialed repository, expired grants,
stale/future generations, and a rollback that is not strictly older fail before
claim creation or network access. The repository identities bound by the request
must exactly equal the distinct repository identities used by graph nodes; no
unused repository or associated grant may enter a claim or receipt.

## Repository and credential policy

Transport constructs each URL from the configured base plus the canonical
relative artifact path. It cannot accept a request-provided origin. Each
response must be successful, have a bounded `Content-Length` equal to the
declared size, use `application/octet-stream`, and carry the configured
repository identity plus an Ed25519 attestation envelope. The signed canonical
message binds repository/key identity, ecosystem, coordinate, version, path,
size, SHA-256, and an immutable publication generation.

The singleton response headers are `x-mcloving-repository-id`,
`x-mcloving-publication-generation`, and standard-base64
`x-mcloving-attestation`. The Ed25519 message uses the domain
`mcloving-dependency-attestation-v1` and unsigned-big-endian-length-prefixed
segments in the exact binding order above. Header size and secret scanning
precede parsing. The configured authorization value is the only request header
derived from repository credentials and is marked sensitive in the client.

The response body is streamed to a unique private file while simultaneously
enforcing the declared size, per-artifact and aggregate limits, SHA-256, and
secret-marker absence. Source-derived headers are scanned before parsing and
are never copied into diagnostics. A wrong/missing/stale attestation, digest,
size, repository, package, coordinate, path, or generation is denied and the
complete transient resolution is removed.

Credentials are delivered only as the configured authorization value for that
repository, never in argv, URL, lock bytes, plan, error, receipt, output tree,
or logs. An untrusted source can use only explicitly public credential-free
repositories. Configuration is invalid unless every credential byte sequence
is present in the independent marker set.

## Resource and deadline enforcement

The transport root is a canonical private `0700`, resolver-owned Linux mount
whose total block capacity equals the configured aggregate transport ceiling
and whose device differs from its parent and output root. An exclusive root
lock and residual-state denial occur before claim creation. Kernel `ENOSPC`
therefore prevents transient allocation beyond the signed ceiling even if a
temporary artifact appears and disappears between scans.

An existing root-lock path is first opened with Linux `O_PATH|O_NOFOLLOW`, so
its type and identity are inspected without invoking FIFO or device open
behavior. Only a regular, single-link, resolver-owned inode is reopened through
its pinned `/proc/self/fd` identity with `O_NONBLOCK`; device/inode equality is
rechecked before any seek or read. A newly created lock uses exclusive creation
and the same nonblocking/no-follow boundary. Its logical metadata length must
not exceed the exact versioned lock content before allocation; the subsequent
read is limited to that length plus one byte so concurrent growth also fails
closed. Initialization rechecks owner, link count, mode, exact final length,
and directory-entry device/inode identity. Sparse oversized files, FIFOs,
devices, path replacements, malformed content, and other substituted lock state
are denied without blocking or unbounded allocation.

One absolute monotonic deadline is established before lock parsing and shared
by admission, every transport future, body streaming, verification, and
publication. No component reconstructs a relative window after descheduling.
Expiry cancels the HTTP body, removes transient state, withholds publication,
and emits no credential- or source-derived diagnostic.

Complete transport fetches are serialized through one async slot acquired
under that same absolute deadline. Poison state is checked only after the slot
is held, so a fetch that overlaps an unknown post-create identity cannot remain
admitted and later return a publishable archive after the poison transition.
Publication- or service-driven transport poison transitions also acquire this
slot before changing state; an active fetch therefore finishes before the
transition, while every later fetch observes poison after slot acquisition.

## Claim, publication, and replay

Before network access, the resolver durably publishes an immutable claim that
binds the canonical request digest and absolute publication deadline. Reuse of
the same resolution ID with different content is denied. A crash after claim
but before receipt is fail-closed and requires reconciliation; it never starts
a second mutable resolution silently.

Transport creates one exclusive mode-`0600` regular file named
`.<resolution-id>.transport` directly beneath the pinned transport root. Every
verified artifact occupies one contiguous admitted slice of that file. The
descriptor-returning exclusive create, retained device/inode identity,
nonblocking no-follow reopen, exact aggregate length, per-slice digest, and
final link revalidation eliminate a create-then-open directory window. One
stateful marker scanner spans every response-body chunk and every adjacent
artifact slice in plan order, so a configured marker cannot evade disclosure
checks by crossing either boundary. Final archive synchronization failure is
not a direct return: before the absolute deadline it removes and synchronizes
the exact retained archive inode; at or beyond the deadline, or if exact cleanup
cannot be proven, it poisons transport state and requires reconciliation after
restart. Once exclusive creation links the archive, any failure to inspect the
archive or pinned-root metadata, or any non-file, cross-device, or zero-inode
relationship,
likewise poisons transport state before returning; an unknown identity is never
treated as safe to remove or safe for later requests to ignore. Every later
production fetch must first acquire the serialized slot and then fails before
creating a new archive.

Publication copies the verified slices into one unique regular staging archive,
synchronizes and seals that inode to mode `0400`, and publishes it by atomic
no-overwrite rename below the output root. The archive has an eight-byte
big-endian header length, a bounded strict-JSON
`mcloving.dependency-archive/v1` header containing the exact
`mcloving.dependency-manifest/v1` and a closed sorted entry table, then one
contiguous payload for each unique content digest. Verification requires exact
schema and manifest equality, unique closed logical paths, contiguous offsets,
exact total length, every payload digest, the full archive digest, unchanged
file fingerprint, and final pathname-to-inode equality. No mutable stage,
artifact, or bundle subdirectory is created. Late publication is withdrawn;
ambiguous cleanup or publication state is retained and reported rather than
guessed. Before any archive byte is written or sealed, one stateful output
guard scans the exact eight-byte prefix, strict serialized header, and every
payload buffer in output order. It therefore denies markers wholly within or
spanning the prefix/header, header/payload, or payload/payload boundaries.

A matching completed request verifies and returns the exact signed receipt
without repository access. The receipt binds all request/configuration,
source/lock/plan/graph, repository/grant, adapter/resolver/toolchain,
attestation, artifact path/size/content, retained-archive, marker-set, generation,
deadline, and rollback lineage fields. HMAC-SHA-256 covers canonical receipt
bytes. The verifier re-hashes the retained archive and refuses substituted,
missing, extra, mutable, or late content.

Authority files are canonical absolute paths outside both mutable resolver
roots both lexically and after filesystem resolution. The output and transport
roots are disjoint before and after resolution: neither may contain the other.

The private output layout contains `.mcloving-dependency-output.lock` plus
mutable `claims/`, `ambiguities/`, `receipts/`, `completions/`, and `bundles/`
directories.
Claims are durable mode-`0600` `mcloving.dependency-claim/v1` JSON. A unique
mode-`0600` `bundles/.<resolution-id>.<uuid>.stage` regular file is populated
with the bounded archive header and content-addressed payloads, synchronized,
sealed to `0400`, and atomically renamed to
`bundles/<resolution-id>.bundle`. The `bundles/` parent is synchronized after
the rename. The archive manifest and entry table bind the exact node-to-content
mapping, while the receipt's compatibility-named `retained_tree_sha256` field
holds the digest of every byte in the sealed archive. Only then is a mode-`0400`
`mcloving.dependency-receipt/v1` written and HMAC-SHA-256 signed. While the
durable claim still blocks replay, the worker revalidates that signed receipt
against the complete retained archive, durably removes the exact private
transport archive by its retained device/inode identity, and rechecks the
deadline. Only then is a mode-`0400`
`mcloving.dependency-completion/v1` record binding the request and receipt HMAC
synchronized. The claim is removed and synchronized only after all fallible
verification and transient cleanup are complete. Replay requires an exact
receipt/completion pair and the absence of both a claim and a durable ambiguity
record. A claim or ambiguity record always takes precedence as incomplete
state. Every worker publication creates that ambiguity record before claim
removal and retains it while the already verified bounded receipt is serialized,
transmitted to the parent, wrapped in the external response, scanned against
every marker, and successfully flushed to stdout. Only after that external
delivery does the parent acknowledge it by removing and synchronizing the
record. If acknowledgement fails, the already delivered success remains the
client truth, further parent-store use is poisoned, and replay remains either
safely completed or explicitly ambiguous. If serialization, final marker
scanning, or output fails, the record remains and blocks restart replay. The
post-flush acknowledgement runs in a bounded blocking supervisor; timeout or
failure poisons further parent-store use and retains explicit ambiguity. Replay
and concurrent responses carry no active delivery ownership and therefore do
not attempt to remove a blocker. The parent performs no second fallible receipt
read. A deadline crossing before completion withdraws
the receipt and bundle and retains or restores the durable claim for explicit
reconciliation. If the final claim-directory sync is uncertain, the already
synchronized ambiguity record remains while claim restoration and completion
removal are attempted; any successful path blocks replay pending explicit
reconciliation.

## Required executable evidence

Contained proof uses real standalone-process NDJSON and real local HTTP
repositories. It must cover:

- valid npm, PyPI, and Maven locks with identical canonical graph semantics;
- duplicate/unknown/mutable/unsupported lock syntax and graph cycles;
- exact later-version delivery only through a new exact lock;
- missing artifact and repository/package/path/graph substitution;
- wrong content, size, signature, key, attestation generation, or mirror;
- untrusted-source denial for private/credentialed repositories;
- source-provenance signature, authority, lifetime, source tree, acquisition
  receipt, lock, scope, and forged-trust substitution denial before network;
- credential and marker non-disclosure across headers, bodies, errors, output,
  receipts, and working tree;
- timeout, offline failure, exact completed replay without network, concurrent
  claim convergence, restart ambiguity, generation cutover, and rollback;
- file/count/graph/header/lock/transport/output limits, residual transport
  state, disk-full cleanup, and no late publication; and
- zero artifact execution and zero request to an unconfigured origin.

`mario_inventory` pins the accepted MIG-000 manifest and proves the current
Mario denominator contains zero admitted workload dependencies. No contained
fixture grants production, cache, canary, cutover, rollback, or decommission
authority.
