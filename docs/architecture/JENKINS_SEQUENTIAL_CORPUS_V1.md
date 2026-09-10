# Sequential compiler corpus classification v1

This JCOMP-003 evidence contract records a new compile-only observation over
the 228 historical corpus identities. It does not change the historical corpus
or its receipts. The paired authored-fixture runtime campaign has its own
population and report; its successes cannot enter this report's counts.

## Population and representations

`scripts/classify-jenkins-sequential-corpus.py` pins the original corpus index,
source manifest, typed-redaction ledger, and Jenkins normalization ledger. It
requires exactly the 228 existing source files and retains every complete index
row in original order, including original source digest, repository digest,
Jenkins-representation digest, normalization, license, source commit, historical
compiler diagnosis, and prior execution disposition.

The repository contains 226 exact original byte representations and two already
redacted representations. The latter are the two `maxyermayank` sources named
in the original typed-redaction ledger. Their `source_sha256` and `bytes` index
fields describe protected original bytes, while `repository_source_sha256`
describes the retained input. The new worker request binds the repository
digest. No protected secret value is fetched or reconstructed, and no
classification of those two protected original byte representations is earned.
All 228 historical identities remain present; neither redacted identity is
dropped to improve a denominator. Existing `NOASSERTION` policy remains in force.

The tool never normalizes line endings or rewrites a source into the admitted
subset. Existing CRLF and all other original syntax are supplied unchanged.
Each input receives a canonical v2 `corpus-reference` document context with a
stable ordinal ID and repository origin. It creates no Jenkins inventory epoch,
operational state observation, execution authorization, or migration eligibility.

## Capture and outcomes

The capture uses the existing sealed `compile-sequential` launcher. That launcher
snapshots source and context, checks the immutable worker image/profile, performs
isolated compilation, and independently validates the complete response with
Rust before releasing successful observations. The campaign runs no Jenkinsfile
or shell workload and supplies no controller or agent endpoint.

Each row records the launcher exit, raw stdout/stderr digests, context digest,
and outcome. A successful independent admission is `admitted`, `unsupported`,
or `rejected` with the exact named diagnostic where applicable. A nonzero
launcher exit is always `unverified`. Its retained diagnostic describes the
trusted-side failure; it must never be presented as a verified source rejection.
Timeouts receive `E_CAMPAIGN_TIMEOUT` and remain unverified. No record can borrow
an unsupported/rejected count from an unknown outside-subset grammar or a
worker/Rust disagreement.

The outer launcher deadline is 30 seconds, followed by process-group TERM,
10 seconds for cleanup, and KILL if necessary. A timeout does not prove normal
container cleanup; any affected run requires explicit cleanup inspection before
further capture. No evidence-only timeout is silently retried or replaced.

`campaign.json` uses schema `mcloving.jenkins.sequential-corpus/1`. It contains
228 ordered records, a disjoint four-way summary, and explicit zero workload
executions, false execution-equivalence claim, and false production-eligibility
claim. `classification_complete` is true only when there are no unverified
records. Exactly 456 raw files (`001.stdout`/`001.stderr` through
`228.stdout`/`228.stderr`) accompany it. This inventory contains no paired-runtime
or authored-fixture observations.

## Provenance and verification

Capture requires clean compiler input paths and records the committed baseline,
the SHA-256 of `git archive BASELINE -- compat/jenkins-worker
crates/jenkins-compiler-admission crates/pipeline-ir Cargo.toml Cargo.lock`, the
capture tool digest, the selected immutable worker image digest, and the
executed admission binary digest. These identity observations do not themselves
prove that an image or binary was built from the archived source. The final
reviewed report must join the campaign to independent image/build provenance
and pin the complete campaign externally before it can be sealed.

The retained verifier requires a separately supplied reviewed campaign digest,
checks the closed raw-file inventory and all historical/context/receipt/summary
bindings, and rejects coordinated changes to the indexed artifacts. With
`--admission-bin`, it additionally requires the recorded executable digest and
replays independent Rust validation of each successfully classified raw response
against the unchanged source and regenerated context. Without that option its
result is explicitly retained-binding verification, not fresh admission or
execution. Failed admissions remain failed observations during either mode.

Mutation tests in `scripts/test-jenkins-sequential-corpus.py` cover missing and
duplicate identities, historical reason/redaction changes, context and raw-byte
substitution, reclassifying failed admission, hiding unverified rows, borrowed
runtime claims, aliases, and coordinated campaign replacement. Their synthetic
failure records are test data and earn no compiler or runtime result.
