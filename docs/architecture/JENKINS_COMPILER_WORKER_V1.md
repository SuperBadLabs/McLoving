# Jenkins compiler worker v1

Status: Wave 4B deny-authority boundary

## Purpose

The Jenkins compatibility worker converts reviewed Jenkins source into a
versioned response for independent Rust admission. It is not a controller,
runner, agent, scheduler, credential broker, or effect executor. A successful
worker response alone grants none of those authorities.

Protocol v1 is one bounded EDN request on standard input and one canonical EDN
response on standard output. Requests bind the protocol version, caller request
identity, target-profile SHA-256, exact source SHA-256, and fixed in-container
source path. Unknown fields, operations, protocol versions, target profiles,
source paths, digests, tagged values, trailing forms, and resource-limit
violations fail closed with stable diagnostic codes.

MIG-003 admits one exact Mario-oracle case:
`corpus-052-cinqict_jenkinsdev` at source SHA-256
`666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100`.
The admitted syntax is `pipeline`, `agent any`, ordered `stages`, literal stage
names, `steps`, and literal `sh` bodies. It produces one direct
`/bin/sh -xe -c` process per shell step. Any additional directive, dynamic
expression, alternate agent, or source/provenance identity is unsupported.
Groovy is used only to construct a CONVERSION-phase AST; no source is
evaluated.

The result includes deterministic strict YAML and a separate versioned
operational-state import record. The latter preserves Mario's disabled state,
configuration generation, reason, actor, effective time, inventory
fingerprint, source hash, compiler, and profile. It grants no mutable
JOBSTATE-001 transition or execution authority.

The supported launcher refuses to return a `compiled` response unless the
independent Rust admission binary accepts the exact response, source,
request identity, job identity, and operational generation. Raw worker output
is evidence, not an admission path.

## Mario target profile

The owner-designated source is Mario's `jenkins-oracle-228`, quiesced and
copied at offline epoch `2026-07-31T06:44:17Z`. Profile v1 binds:

| Component | Identity |
|---|---|
| Inventory fingerprint | `b1c2f81c74ec0ffc36971f358f920b2d0775c6009f474bea924448cd2a1915c1` |
| Jenkins image | `docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02` |
| Jenkins core | `2.568.1` |
| Jenkins WAR SHA-256 | `58f24f3965fbef7708629fbe158d51bf138ffd577cadbc86b46367e8ad0beb83` |
| Jenkins core JAR SHA-256 | `07511327f8f69b4abdab17705f99c5de16bcb751b79e1403f4ac80ac151b3e6c` |
| Groovy | `2.4.21` |
| Groovy JAR SHA-256 | `de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0` |
| Java | Eclipse Adoptium Temurin `21.0.11+10-LTS` |
| Plugin files | 90 |
| Plugin manifest SHA-256 | `e33fa87646e6e360e7614373cc0057ba2e92ff18b9a9ea9419dea796dcb950b0` |
| Profile SHA-256 | `feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271` |

The offline image build verifies every plugin against the sealed manifest and
extracts Groovy and Jenkins core from the pinned WAR. Every worker process
re-verifies the profile file, runtime versions, core/Groovy JARs, plugin
manifest, and all plugin content before accepting a request.

## Isolation contract

The only supported launcher uses rootless Podman with:

- no network namespace attachment;
- a read-only root filesystem and read-only single-file source mount;
- inherited image volumes ignored, preventing an implicit writable
  `/var/jenkins_home`;
- all Linux capabilities dropped and `no-new-privileges`;
- a non-root UID, one CPU, 512 MiB memory/swap, 64 PIDs, and 64 file
  descriptors;
- a 16 MiB `noexec,nosuid,nodev` temporary filesystem;
- an unset host environment plus only `LANG` and `TZ`;
- no controller, database, agent, scheduler, credential, secret, or socket
  mounts;
- a five-second process deadline; and
- a 262,144-byte request/source limit plus one 65,536-byte response limit.

Worker responses repeat an all-false authority ledger. The independent Rust
admission crate rejects noncanonical EDN, unexpected fields or types,
authority/profile/source substitution, malformed or noncanonical pipeline and
job-state YAML, semantic drift, hash substitution, or invalid canonical IR.
Only after this reparse and validation does it issue a disabled import receipt.

## Verification

The unit suite proves deterministic canonical responses, all-false authority,
malformed/oversized/trailing input rejection, unknown-field rejection, and
target-profile substitution denial.

The rootless-container boundary suite independently proves:

- identical source/profile/request inputs produce byte-identical responses;
- source symlinks and oversized files are rejected before launch;
- a unique injected database-secret marker triggers `E_ENV_AUTHORITY` and is
  absent from the response;
- the live container has network mode `none`, read-only root, one read-only
  source mount, no inherited volume, the exact tmpfs, 512 MiB/64-PID limits,
  and all default capabilities dropped; and
- compile remains unsupported with no execution or effect authority.

The successor-inventory-bound HeMan rebuild had image ID
`344402b7e1a2b1831aa43184ee30db93ff8beaf13efaa80819d562511fd5a303`.
The MIG-003 compiler rebuild has image ID
`8459b3b080d4239daffa2d5ba632c707dfbd18657b0176fb0e6340ff5dd45548`.
These local image IDs are supporting evidence, not published release
identities. Future source changes require a new image receipt and all gates
again.
