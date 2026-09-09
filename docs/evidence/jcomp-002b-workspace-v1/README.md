# Contained workspace transfer evidence v1

The campaign built committed source `941d473144d942824b767eb78744ad27bdf6ac20`
in the pinned Rust image and executed copied controller, agent and three test
binaries with a private disposable PostgreSQL database. Runtime containers had
no external network or published ports, no production credentials, read-only
source and binaries, and bounded private tmpfs scratch. Database cleanup
completed after all checks passed.

All four sequential-store, three workspace-store and eleven real remote-agent
tests passed without skips or ignored cases. Eight sequential and five workspace
markers bind the expected scenario populations. The runtime log retains saved
authored sources, scoped result projections, stdout and cleanup receipts.
It covers fresh-shell file continuity across agents and controller restart,
terminal recovery, distinct concurrent build namespaces, executable/empty-dir/
binary metadata, cancellation, bounded capture refusals, nonzero exit and lease
loss. Uncertain started work requires reconciliation and preserves only the last
verified checkpoint; that case does not claim terminal cleanup.

Reproduce from a clean checkout with:

```sh
bash scripts/test-sequential-runtime-contained.sh /tmp/new-workspace-evidence
```

`campaign.json` binds exact source/tree/archive and retained artifact hashes.
The source archive and executed binaries are identified but not retained here;
`git archive <source_commit>` reconstructs the source archive and the committed
driver rebuilds the binaries. No private keys or database state are retained.
Verify this inventory with `sha256sum -c ARTIFACTS.sha256` in this directory.

These are fresh authored fixtures, not paired Jenkins oracle cases or original
228-source coverage. The mode is Linux-only and internally selected, bounded to
8 KiB content and 32 entries, with manual retries refused. It establishes no
hostile same-UID isolation, production disk quota, imported-job enablement or
production authority. Protected merge and exact-main verification remain
separate JCOMP-002B closure requirements.
