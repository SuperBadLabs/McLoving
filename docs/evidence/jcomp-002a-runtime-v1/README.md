# Contained sequential runtime evidence v1

The campaign built committed source `68a7487` in the pinned Rust image and
executed copied controller, agent and test binaries in a private disposable
PostgreSQL/runner network namespace. The runtime had no external network,
published ports, production credentials, or host workspace. Its only mounts
were a read-only source archive and read-only copied binaries; writable scratch
was private tmpfs. Database cleanup completed after all checks passed.

Four PostgreSQL and six shipped remote-agent tests passed, with eight bounded
runtime evidence markers. `runtime.log` includes the actual saved authored
sources, ordered result projections and observed stdout, plus binary hashes.
`campaign.json` binds the retained file hashes and exact source tree. The two
API test refinements after `7630600` changed the test executables only: the
executed controller and agent hashes remained unchanged.

Reproduce locally from a clean checkout using:

```sh
bash scripts/test-sequential-runtime-contained.sh /tmp/new-sequential-evidence
```

The archive and executed binaries are identified but not stored in this
repository; sources remain in the named git commit, and the committed driver
rebuilds them. This is an intentional bounded retention set, not a promise
that any earlier temporary diagnostic campaign remains available. No TLS
private keys or private database state are retained.

These are fresh authored fixtures, not Jenkins oracle cases. This campaign
establishes no workspace continuity, hostile same-UID isolation, imported-job
enablement, production authority, paired Jenkins compatibility or original
228-source coverage. JCOMP-002A closure still requires final review, protected
merge and exact-main verification.

Verify retained inventory from this directory with `sha256sum -c ARTIFACTS.sha256`.
