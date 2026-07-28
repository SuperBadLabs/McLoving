# Reproducible foundation toolchain

`scripts/validate-foundation.sh` is the canonical one-command validation path on
HeMan. It uses immutable container digests and downloads versioned tools only
after their SHA-256 values match `tools/versions.env`.

## Required host facilities

- Rootless Podman.
- Java for TLA+.
- Clojure CLI for the compatibility-worker skeleton.
- `curl`, `sha256sum`, and `tar`.

The Rust compiler and gitleaks scanner execute from digest-pinned containers.
Actionlint, cargo-deny, and TLA+ artifacts are cached only after checksum
verification.

## Cache policy

Caches are optimization only and cannot establish correctness.

- Tool downloads are keyed by version and verified digest.
- Rust dependency caches include `Cargo.lock`, toolchain, architecture, and
  target triple.
- Compatibility-worker caches include `deps.edn` and JVM identity.
- Protected-branch caches are not writable by untrusted pull requests.
- A missing or corrupt cache causes a verified refetch or ordinary rebuild.
- No cache contains credentials, repository tokens, or unredacted logs.
- Mutable container tags are not accepted by the validation script.
- Release evidence records the resolved image and tool digests.

## Updating a tool

1. Select the exact upstream release.
2. Retrieve its checksum from an authoritative release artifact where provided.
3. Independently calculate and record the digest.
4. Update version and digest in one reviewable change.
5. Run the complete validation script from an empty tool cache.
6. Preserve the validation receipt in the pull request.

The host-installed Rust 1.75 toolchain on HeMan is intentionally not used for
the edition-2024 workspace.

