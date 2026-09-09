# Contained workspace transfer evidence v2

This campaign verifies reviewed committed source
`e4b6fcd9f21bd7bdf54986bff5dab3628942e426`, including the operator-reconciliation
correction. It supersedes v1 for the corrected candidate; v1 remains unchanged
as historical evidence for its exact source and recorded scenarios.

All four sequential-store, four workspace-store and eleven real remote-agent
tests passed with zero failed, ignored or filtered tests. The new store test
executes refusal of operator-supplied success and workspace transfer data,
including cancellation-wrapped payloads, with unchanged state after refusal.
Failed/aborted reconciliation retains the verified generation and receipt,
closes the build and removes checkpoint bytes; exact replay remains idempotent.

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
succeeded. No production credentials or endpoints were supplied. An initial
sandbox startup failure occurred before building or running containers; it is
not included as passing evidence. The successful run used ordinary local Podman
approval with the same committed driver and containment settings.

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
