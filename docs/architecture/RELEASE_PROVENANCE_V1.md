# Release provenance v1

Status: REL-001 implementation contract. The contained build and verification
boundary is implemented. No production signing key, release, deployment,
canary, cutover, or rollback authority is stored in this repository.

## Security objective

A McLoving deployment may consume a release only after one verifier has
accepted the exact protected source commit and tree, source archive, Cargo
lockfile and lock-derived SBOM, isolated builder, toolchain, workflow, policy
gate results, component set, bundle, signer, transparency evidence, and exact
rollback ancestry. Successful compilation or possession of a bundle is not
deployment authority.

The versioned objects are:

- `mcloving.release-build/v1`, the unsigned receipt emitted inside the isolated
  builder;
- `mcloving.release-sbom/v1`, the canonical projection of every Cargo.lock
  package;
- `mcloving.release-bundle/v1`, the deterministic self-hashing component
  archive;
- `mcloving.release-provenance/v1`, the Ed25519-signed release manifest; and
- `mcloving.release-deployment/v1`, serialization-only audit evidence emitted
  from the private-field `VerifiedRelease` type.

Unknown JSON fields, unknown schema versions, noncanonical encodings, empty
identity sets, duplicate or unordered entries, malformed digests, and
unbounded inputs fail closed.

## Isolated build

`.github/workflows/release-builder.yml` runs only after a successful Foundation
workflow for an exact protected `main` head. It checks out that head directly,
downloads the locked registry archives outside the builder, pulls the exact
platform manifest, and invokes `scripts/release-builder-contained.sh`.

The production builder identity is:

```text
docker.io/library/rust:1.97.1-bookworm@sha256:408fe88047cef61a2087653b0c5255fa51c0f2d6d94ddedd7a2562a9b91a46f6
platform: linux/amd64
target: x86_64-unknown-linux-gnu
toolchain: 1.97.1
```

The outer builder accepts only a canonical clean Git worktree, a new canonical
output path beneath an owner-owned directory that denies group and other
access, and a canonical Cargo cache. It archives the exact commit rather than
bind-mounting a mutable worktree. The container runs with no network, a
read-only root, no capabilities, `no-new-privileges`, the Docker default
AppArmor profile, bounded CPU, memory and process count, and fixed-size private
tmpfs filesystems. Only the dedicated build-target and ephemeral Cargo-home
tmpfs filesystems are executable, because Cargo must run freshly compiled build
scripts, procedural macros, and checksum-pinned vendored tools such as
`protoc`; both remain `nosuid` and `nodev`. The only writable persistent mount
is the newly created output directory.

The workflow fails closed unless GitHub's runner-supplied
`github.workflow_sha` (the commit containing the executing workflow file)
equals the protected Foundation head being released. The build receipt's
workflow identity hashes that workflow file together with both builder
scripts, all from the same exact checkout.

Only the registry index and packaged crate archive directories enter the
container as separate read-only mounts. Before copying them, the inner builder
rejects symlinks, hardlinked files, and special filesystem nodes. Cargo
credentials, mutable unpacked registry sources, the host target directory, and
Git configuration do not enter. Cargo reconstructs dependencies in an
ephemeral home using `--locked --offline`; the SBOM requires each registry
source to have the exact Cargo.lock checksum and therefore rejects Git or
other unchecksummed sources in v1.

The inner builder fixes its source path, target triple, locale, timezone,
`SOURCE_DATE_EPOCH`, incremental setting, debug stripping and linker build-ID
setting. It emits exactly:

```text
Cargo.lock
build-receipt.json
components.json
components/bin/mcloving-agent
components/bin/mcloving-cli
components/bin/mcloving-controller
release.bundle
sbom.json
source.tar
toolchain.txt
```

Any missing, additional, symlinked, hardlinked, unexpectedly owned,
group/other-accessible, or otherwise unexpected output denies the build. The
workflow packages those outputs into a deterministic tar and uploads it as one
immutable unsigned workflow artifact. CI has no production signing key.
Before upload, the protected workflow log records the exact source/tree,
canonical component-list SHA-256, SBOM SHA-256, bundle SHA-256 and bundle size.
The signer-policy authority retrieves that tuple from the authenticated exact
protected-main workflow run, not from the downloadable artifact, and provisions
it through the separate owner-private verification-policy channel.

## Bundle and SBOM

The bundle supports at most 128 components, 256 MiB per component and 1 GiB in
total. Component paths are relative UTF-8 normal components: absolute paths,
dot components, dot-prefixed components, backslashes, traversal, symlinks,
hardlinks, size changes and digest changes are denied. Entries are sorted and
bind path, role, executable bit, size, SHA-256 and bytes. Trailing data is
denied.

The canonical SBOM is derived directly from Cargo.lock and binds its SHA-256,
the release-tool SHA-256, and every sorted package name, version, source and
registry checksum. The Dependencies and licenses protected gate remains the
license-policy authority; the SBOM does not infer licenses from mutable
registry metadata.

## Signing boundary

`mcloving-release-provenance sign-build` is the production signing entrypoint.
It does not accept a preassembled manifest. It requires the independently
provisioned verification policy at signing time and, before producing a
signature, requires the unsigned build receipt's complete source, builder,
canonical component-list, SBOM, bundle and bundle-size tuple to equal that
policy exactly. The policy's artifact tuple comes from the authenticated
protected-builder run rather than from the unsigned artifact presented to the
signer. Replacing component bytes, regenerating a self-consistent component
list/bundle and editing the receipt therefore cannot obtain a signature.

The command also recomputes and compares the build receipt against the exact
component JSON, SBOM, bundle, source archive, Cargo.lock and toolchain record.
It reparses the bundle, requires exact component equivalence and canonical
JSON, and reconstructs the complete canonical SBOM from the supplied
Cargo.lock and the release executable digest named by the receipt before
signing. That digest is carried in the signed builder identity and must exactly
match the same independently supplied policy. The requested protected gates,
transparency tuple and release profile must match policy, and the signing key's
public half must already be present in the policy's trusted signer registry.

The release request supplies only the release ID/version/profile, signer key
identity, sorted exact protected policy gates, externally validated
transparency evidence, and optional rollback target. The command derives the
source, builder, artifact and signer-public-key identities itself, while the
separately provisioned policy authorizes their exact expected values. The
release request, trusted policy and private PKCS#8 key must all be absolute
owner-private, owner-owned, single-link regular files. Symlinks, hardlinks,
group/other access, relative paths and oversized keys are denied. Inputs are
opened once with `O_NOFOLLOW` and verified through that same file descriptor.
Key bytes are zeroized after the signing attempt.
Every output requires an owner-private directory, uses create-new mode, is
synchronized, and is never overwritten.

Verification pins the complete transparency tuple to policy: log and entry
identity, log index, signed-entry timestamp, inclusion proof, checkpoint and
independent audit event. The deployment receipt carries the same tuple so a
downstream operator can audit the exact evidence that authorized placement.
Its fields are private and it does not implement deserialization, so stored JSON
cannot be converted back into deployment authority or forged as a typed
receipt. Any authority-bearing deployment function must consume the live
`VerifiedRelease` value in the verifier process; the serialized receipt is
post-verification audit evidence only.

The signer host must separately establish:

1. the implementation head was reviewed with zero unresolved threads;
2. Foundation and Windows Agent policy evidence both succeeded for that exact
   head;
3. the source commit is the reviewed protected-main commit;
4. the builder workflow and platform image match the independently retained
   policy;
5. the component-list, SBOM and bundle digest/size tuple in that policy was
   retrieved from the authenticated exact-head protected builder run rather
   than derived from the downloaded unsigned artifact;
6. transparency inclusion, checkpoint and audit evidence were validated by an
   independent transparency client; and
7. the release request contains the exact previously verified rollback target,
   or the independently approved genesis policy.

The repository deliberately does not treat a private GitHub workflow artifact
as transparency evidence. Its retention follows workflow retention and it can
be deleted with the run. A production ceremony must retain the signed envelope,
SBOM, bundle, source archive, lockfile, toolchain record, policy, transparency
proof/checkpoint, audit anchor and exact protected-check receipts outside that
single system.

## Verification before deployment

`mcloving-release-provenance verify-chain` accepts one or more groups of exact
signed envelope, independently provisioned policy, canonical SBOM, bundle and
Cargo.lock. For every group it verifies:

- the Ed25519 signature against a nonempty, unambiguous startup-pinned signer
  registry and the manifest's public-key digest;
- exact source commit/tree/archive/lock and release profile pins;
- exact builder image reference/digest, Rust version, toolchain record,
  workflow, target and source epoch pins;
- exact independently pinned canonical component-list, SBOM and bundle
  digest/size tuple;
- the complete sorted protected-gate set, successful conclusion, run IDs,
  evidence digests and exact source head;
- a complete canonical SBOM reconstructed from the supplied exact Cargo.lock
  and policy-pinned release-tool identity;
- bundle size/digest and exact self-verified component equality;
- transparency log identity, independently pinned checkpoint and audit anchor;
  and
- exact rollback identity against the immediately supplied prior
  `VerifiedRelease`.

A genesis release is allowed only by an explicit policy bit. A non-genesis
release without its exact verified predecessor is denied. An unrelated valid
release cannot satisfy rollback. Only the final verified value can emit a
deployment receipt binding environment, deployment configuration digest,
release, source, builder, signer, transparency entry and rollback manifest.
That receipt is serialization-only audit output and cannot recreate the
verified value.

The verifier never extracts or executes the bundle. Installation remains a
separate least-authority deployment operation that must consume the live
`VerifiedRelease` and recheck the same bundle digest immediately before
placement; serialized receipt JSON must never be accepted as authority.

## Substitution and permission-negative proof

The focused contract suite proves:

- source commit, source archive and Cargo.lock substitution denial, including
  re-signing by the otherwise trusted test key;
- builder image and source-epoch substitution denial;
- release-tool/SBOM-generator substitution denial even when re-signed;
- re-signed SBOM generator mismatch against the signed builder identity;
- re-signed incomplete SBOM denial during independent verification from the
  exact supplied Cargo.lock;
- replacement component bytes plus attacker-regenerated canonical component
  JSON, bundle and edited unsigned receipt denial at the signing boundary;
- non-deserializable, private-field deployment audit evidence so only the live
  private-field `VerifiedRelease` can cross an authority-bearing API;
- protected-gate run substitution denial;
- SBOM, bundle bytes and component-role substitution denial;
- attacker key, malformed signature, malformed transparency and valid but
  independently untrusted entry identity, log index, signed-entry timestamp,
  inclusion proof, checkpoint and audit substitution denial;
- missing, unrelated and field-substituted rollback target denial;
- deterministic bundle reconstruction plus traversal and trailing-byte denial;
- complete canonical projection of the repository Cargo.lock; and
- end-to-end CLI signing/verification, incomplete-SBOM denial even with a
  matching attacker-edited receipt, owner-private key enforcement, symlink
  denial and create-new output enforcement.

The protected Foundation workflow runs the same crate in workspace Clippy and
tests, syntax-checks both builder scripts, and keeps dependency/license and
secret-scan gates separate. The release-builder workflow is not a pull-request
trust oracle: it runs only for the successful protected-main Foundation head.

## Residual trust and non-claims

The Linux kernel, Docker daemon, builder and signer hosts, protected-branch and
workflow administrators, Rust image/digest reviewer, crates.io index and crate
owners, policy/evidence collectors, production signing-key operator,
transparency validator, independent audit-anchor store and deployment operator
remain trusted within their declared roles. A jointly compromised builder host
and signer-policy authority can fabricate a release. An upstream crate that is
malicious at its correctly locked checksum remains malicious.

REL-001 implementation does not itself grant any controller, agent, scheduler,
secret, connector, observer, canary, cutover or deployment authority. A
production release is not claimed until the protected-main build, external
signing/transparency ceremony, independent verification and exact deployment
receipt are all retained in the REL-001 closure evidence.
