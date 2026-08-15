# Differential aggregate v1

Status: `MIG-006` complete. Exact PR head
`ab7c0061c9004c2e5cd33c50b55ddc35fb306d38` passed Foundation run
`31912421075`, Windows run `31912421043`, strict local and HeMan verification,
and clean exact-head review after all twenty-two review threads were fixed and
resolved. PR #61 squash-merged as protected-main commit
`2a8f983838b4bd063bd029b3e164f7ac36c20439`; protected-main Foundation run
`31914011695` and Windows run `31914011627` passed as the post-merge
verification receipts.

MIG-006 closes one immutable, non-authoritative compatibility claim over the
exact Mario inventory, corpus, and DIFF-001/002/003 receipts. It does not rerun
Jenkins, McLoving, a state transform, or any external-boundary implementation.
The aggregate invokes the three canonical repository verifiers and rejects the
closure if any verifier, immutable input, identity join, denominator, taxonomy,
or authority field changes.

## Inputs and verifier composition

The two-file bundle at `migration/differential-aggregate-v1` is sealed by a
detached SHA-256 manifest and a digest compiled into
`mcloving-differential-aggregate`. Bundle enumeration and both entry opens are
relative to the retained validated root handle, and the first unexpected,
duplicate, or third entry fails closed. Its twelve exact inputs bind:

- the 230-job inventory and source/job map;
- the 228-file source manifest, corpus manifest, and per-file corpus index;
- the historical oracle summary;
- the sole compiler-admission receipt and mapping catalog plus lock; and
- the immutable DIFF-001, DIFF-002, and DIFF-003 evidence sets.

Every relative path is fixed, repository-root/traversal/symlink aliases are
denied, and every input is a bounded, singly linked regular file with an exact
compiled digest on Linux and Windows. Semantic TSV checks parse the same bytes
that passed digest verification; each root is required to be its direct
lexically normalized canonical path, and each boundary file is opened once
with no-follow semantics. Before canonicalization, every original root
component—including a component later canceled by `..`—is traversed through
no-follow directory opens, so a symlink or reparse point cannot disappear by
lexical normalization. Unix opens are nonblocking so a FIFO cannot stall
validation. Unix traversal starts from an open root descriptor and uses
no-follow directory-relative opens for every component. Windows retains
no-reparse directory handles without delete sharing until the descendant file
is open. The validated final root handle remains live and is the anchor for
every descendant open, so a writable ancestor cannot redirect traversal after
root validation. Windows spelling comparison uses the OS ordinal Unicode
case-insensitive operation and then requires matching kernel directory
identity. Regular-file/reparse/link identity is validated from that file handle,
and bounded bytes are read from the same handle. Semantic checks never reopen
those paths. DIFF-001's authenticated 30-file manifest selects and authenticates
an exact in-memory map containing every bundle file and the manifest itself.
DIFF-002 and DIFF-003 use the exact evidence bytes already authenticated against
their compiled input digests. The canonical verifiers consume those maps and
byte slices directly; no temporary filesystem object is created and no path is
reopened after authentication. A mutable repository or concurrent local
process therefore cannot replace a file between aggregate authentication and
canonical semantic verification. The aggregate calls these existing verifiers
exactly once over the authenticated bytes:

1. `mcloving-jenkins-differential` for native execution parity;
2. `mcloving-state-policy-differential` for identity, authorization,
   operational state, and persistent-history parity; and
3. `mcloving-boundary-differential` for contained external-boundary parity.

The receipt field named `evidence_sha256` is the canonical result digest for
each verifier: DIFF-001 supplies its derived trace digest, while DIFF-002 and
DIFF-003 supply their evidence JSON digests. The distinction is explicit so a
future change cannot silently substitute a different DIFF-001 digest source.

No alternative parser, compiler, transform, runtime, connector, or observer is
an aggregate acceptance path. The future MIG-007 migration package is not an
input and cannot satisfy MIG-006 by implication.

## Exact joins

The ledger joins the Jenkins image across all three evidence sets, the Rust
runner image between DIFF-001 and DIFF-003, and the PostgreSQL image across all
applicable evidence. It also binds the admitted source, canonical pipeline,
90-plugin manifest, compiler profile, mapping catalog, successor corpus,
MIG-005A forward/reverse/evidence digests, runtime-dependency and identity-client
manifests, and the exact v0.1.0 `private-linux-x86_64` release identity,
envelope, evidence manifest, and verification receipt.

The corpus index must contain exactly 228 unique sources: one exact admitted
source and 227 cases carrying the stable `E_SOURCE_NOT_ADMITTED` disposition.
The source/job map must contain 230 unique disabled, parse-only jobs over those
same 228 sources. Any missing, duplicate, enabled, authoritative, or
unclassified row fails closed.

## Coverage truth

Each number retains its own named population and unit:

| Metric | Exact result | Meaning |
|---|---:|---|
| Production-population coverage | 230 / 230 disabled jobs | Inventory and source mapping only |
| Parse reach | 140 / 228 corpus files | Historical parser result |
| Native runnable coverage | 1 / 228 corpus files | The sole DIFF-001 execution-certified case |
| Actionable migration | 1 / 228 corpus files | Exact compiler plus mapping admission |
| Deterministic rejection coverage | 227 / 227 non-admitted cases | Stable `E_SOURCE_NOT_ADMITTED` result |
| Certified equivalence, admitted | 1 / 1 admitted case | Exact admitted denominator |
| Certified equivalence, corpus | 1 / 228 corpus files | Corpus-wide disclosure of the same result |

The historical oracle field `ranvil_native=18/228` means legacy parser/model
reach only. It is not native runnable coverage, actionable migration, or
certified equivalence and grants none of those claims.

The sealed corpus README also preserves the MIG-003 checkpoint statement that
native runnable and certified equivalence were then zero. That statement is
chronological evidence, not the current aggregate result, and cannot be edited
without invalidating the predecessor corpus seal. This contract is the current
cross-evidence interpretation after DIFF-001.

## Stable failure taxonomy

The public aggregate categories are:

- deterministic rejection: `E_SOURCE_NOT_ADMITTED`;
- aggregate mismatch: every public local-verifier failure (`E_AUTHORITY`,
  `E_CASE_COVERAGE`, `E_DENOMINATOR_BORROWING`, `E_EVIDENCE_DIGEST`,
  `E_IDENTITY_MISMATCH`, `E_INPUT_DENOMINATOR`, `E_INPUT_SUBSTITUTION`,
  `E_IO`, `E_MANIFEST`, `E_POPULATION_COVERAGE`, `E_RECEIPT_MISMATCH`,
  `E_SCHEMA`, `E_SIZE`, `E_TAXONOMY`, `E_TREE`, and
  `E_UNCLASSIFIED_CASE`); and
- upstream regression: `E_DIFF001_REGRESSION`, `E_DIFF002_REGRESSION`, and
  `E_DIFF003_REGRESSION`.

The upstream verifier's original diagnostic remains in the aggregate error
message. A caller therefore gets a stable aggregate classification without
losing the more specific source receipt failure.

## Authority boundary

This closure has no production credential, scheduler, execution, connector,
effect, deployment, canary, cutover, rollback, client-transfer, or Jenkins
decommission authority. It only verifies immutable contained evidence. MIG-007
must produce a separately reviewable package bound to this exact aggregate;
shadow, canary, cutover, rollback, and decommission remain later gates.
