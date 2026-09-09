# Local contained test preflight

Observed 2026-09-09 during JCOMP-002 PR review. This is tool availability
preparation only, not sequential execution evidence or successor implementation.

Cached Rust image immutable ID:
a0635962c16d5f26400703edd4317175cf9531f3285d632613f9da227f9c71d1

A disposable stock-tool probe ran with network none, read-only root, dropped
capabilities, no-new-privileges, user `1000:1000`, no host mounts and pull never.
Observed `/usr/bin/openssl` version 3.0.20, `/usr/bin/python3` version 3.11.2 and glibc 2.36. No source
fixture, controller, agent, database or Jenkins workload ran in that probe.

Readelf of existing host-built controller/agent binaries shows only libgcc_s,
libm, libc, loader dependencies and controller maximum GLIBC symbol version 2.34.
This supports using private copied binaries in the cached Debian image; inspect
new test/controller/agent binaries again after compilation before claiming ABI
compatibility. Host glibc 2.39 alone does not determine actual binary requirements.

Proposed later local gate: own disposable PostgreSQL `17.6-alpine` container on
network none with no published port; runner joins that container's network
namespace for loopback-only DB access. No external route, host DB, production
credentials, host workspace or agent identity. Mount only candidate git archive
read-only and private exact binaries; writable tmpfs scratch/tmp. Match the
compile-time CARGO_BIN_EXE path with the private binary mount. Set the controller
binary path explicitly. The existing verified Rust-test wrapper can invoke a
compiled test executable directly and still reject missing/empty/skipped tests.
Use the same pinned PostgreSQL digest as Foundation. Await cleanup of both
containers and retain exact image/binary/source/result identities. No rootless
pod infrastructure/pause-image pull is necessary when joining the PG namespace.


Source references in this planning note describe repository commit `904fd1fed083cd17a6fc371e0a300c3696d93483` (tree `26240208f51f6028bf6bb6e619a2dcd5d19555f0`). Re-resolve paths and line numbers on the successor head. Planning and historical tool observations are not new runtime evidence.
