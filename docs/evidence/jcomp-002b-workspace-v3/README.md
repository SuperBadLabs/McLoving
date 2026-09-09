# Contained workspace transfer evidence v3

This campaign verifies reviewed committed source
`cfe6e4a2c85bd4d71912bdbdf5c3cf42a197623f`, including the operator-reconciliation,
lease-loss reason precedence and database receipt/generation corrections. It
supersedes v1/v2 for the corrected candidate; both earlier inventories remain
unchanged as historical evidence for their exact sources and recorded scenarios.

All four sequential-store, four workspace-store and eleven real remote-agent
tests passed with zero failed, ignored or filtered tests. The existing PostgreSQL
workspace lifecycle test now requires the named receipt/generation constraint
to refuse invalid initial, open and closed states with SQLSTATE `23514`.
The actual lease-loss scenario now observes the exact fenced durable agent
result before controller restart, verifies its lease-loss reason remains intact,
and separately checks `execution_not_completed` in its transfer error. The
workspace marker records both observations. The prior operator-reconciliation
regression remains in the passing four-test workspace-store population.

Eight sequential and five workspace markers bind the actual remote scenarios.
The log retains 18 source records, 19 source-bound result records, 30 stdout
records, eight closed cleanup receipts, and controller/agent executable identities
for every remote test. Coverage includes cross-agent and controller-restart
continuity, terminal replay, simultaneous builds, executable bits/empty directories/
binary data, cancellation, capture refusal, nonzero exit and started lease loss.
The lease-loss scenario retains its last verified generation pending reconciliation;
it does not claim whole-build terminal cleanup.

The driver built the clean source archive in the pinned Rust image, then ran
copied binaries with pinned private PostgreSQL, no external runtime network,
read-only source/binaries and bounded disposable scratch. Database removal
succeeded. No production credentials or endpoints were supplied. Ordinary local
Podman approval allowed the committed driver to use the required container runtime.

`campaign.json` binds source/tree/archive and every retained execution artifact.
The source archive and executable bytes are identified but not retained here;
`git archive <source_commit>` reconstructs the source archive. Verify the retained
inventory with `sha256sum -c ARTIFACTS.sha256` in this directory. Reproduce from a
clean committed checkout using:

```sh
bash scripts/test-sequential-runtime-contained.sh /tmp/new-workspace-evidence
```

This is internal Linux-only authored-fixture evidence, bounded to 8 KiB content
and 32 entries, with manual retries refused. It does not establish Jenkins
parity, original 228-source coverage, hostile same-UID isolation, production
quota or operational authority. Protected PR checks, protected merge and exact
merged-main Foundation/native Windows evidence remain separate obligations.
