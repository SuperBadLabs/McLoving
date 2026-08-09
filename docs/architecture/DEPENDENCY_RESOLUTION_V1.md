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
  configured repository, repository attestation public keys, one receipt key,
  and one secret-marker set;
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
and client-library retries are disabled. Cleartext loopback fixtures require
both configuration admission and `MCLOVING_DEPENDENCY_RESOLVER_TEST_MODE=1`.

Configuration, credential, signing-key, marker, public-key, CA, lock, claim,
receipt, and retained-manifest reads are bounded regular-file reads that deny a
final symlink. Authority files must be owned by the effective resolver UID with
no group or other permission bits. Construction validates every authority and
limit before creating a claim or contacting a repository.

`mcloving.secret-markers/v1` is closed JSON with one strictly sorted,
duplicate-free `markers_hex` array. Entries are lowercase even-length hex for
at least eight bytes. Every configured credential and the receipt HMAC key must
occur as exact decoded entries; the receipt key must contain at least 256 bits
of key material. Repository headers, streamed bodies, stdout, stderr, and
durable receipts are checked against all decoded markers, including matches
spanning response chunks.

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

Frames are capped at 1 MiB before JSON allocation. Unknown fields, recursively
duplicate JSON members, control-bearing identities, invalid UUIDs/digests,
untrusted-source use of a private or credentialed repository, expired grants,
stale/future generations, and a rollback that is not strictly older fail before
claim creation or network access.

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

One absolute monotonic deadline is established before lock parsing and shared
by admission, every transport future, body streaming, verification, and
publication. No component reconstructs a relative window after descheduling.
Expiry cancels the HTTP body, removes transient state, withholds publication,
and emits no credential- or source-derived diagnostic.

## Claim, publication, and replay

Before network access, the resolver durably publishes an immutable claim that
binds the canonical request digest and absolute publication deadline. Reuse of
the same resolution ID with different content is denied. A crash after claim
but before receipt is fail-closed and requires reconciliation; it never starts
a second mutable resolution silently.

Verified artifacts are copied from transport into a unique private staging
directory using content-addressed filenames, synchronized, made immutable, and
published by atomic no-overwrite rename below the output root. The complete
retained tree and every ancestor mode/owner/inode are verified before success.
Late publication is withdrawn. Ambiguous cleanup or publication state is
retained and reported rather than guessed.

A matching completed request verifies and returns the exact signed receipt
without repository access. The receipt binds all request/configuration,
source/lock/plan/graph, repository/grant, adapter/resolver/toolchain,
attestation, artifact path/size/content, retained-tree, marker-set, generation,
deadline, and rollback lineage fields. HMAC-SHA-256 covers canonical receipt
bytes. The verifier re-hashes the retained tree and refuses substituted,
missing, extra, mutable, or late content.

The private output layout contains `.mcloving-dependency-output.lock` plus
mutable `claims/`, `receipts/`, and `bundles/` directories. Claims are durable
mode-`0600` `mcloving.dependency-claim/v1` JSON. A unique mode-`0700` stage is
populated with content-addressed artifacts, files are synchronized and sealed
to `0400`, the artifacts directory is sealed to `0500`, and the stage is
renamed beneath `bundles/<resolution-id>`. The bundle root is sealed to `0500`
before its parent entry is synchronized. `mcloving.dependency-manifest/v1`
binds the exact node-to-content mapping. The retained-tree digest covers every
relative path, mode, size, and content digest. Only then is a mode-`0400`
`mcloving.dependency-receipt/v1` written and HMAC-SHA-256 signed. A deadline
crossing withdraws the receipt and bundle and retains or restores the durable
claim for explicit reconciliation.

## Required executable evidence

Contained proof uses real standalone-process NDJSON and real local HTTP
repositories. It must cover:

- valid npm, PyPI, and Maven locks with identical canonical graph semantics;
- duplicate/unknown/mutable/unsupported lock syntax and graph cycles;
- exact later-version delivery only through a new exact lock;
- missing artifact and repository/package/path/graph substitution;
- wrong content, size, signature, key, attestation generation, or mirror;
- untrusted-source denial for private/credentialed repositories;
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
