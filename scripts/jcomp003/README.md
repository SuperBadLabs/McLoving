# JCOMP-003 contained evidence tools

These tools implement the preregistered
[sequential differential v2](../../docs/architecture/JENKINS_SEQUENTIAL_DIFFERENTIAL_V2.md).
They grant no production authority. A campaign begins only after the chief verifies
all runtime prerequisites, approves the observers, and freezes their clean source
commit/tree and immutable image identities.

The executable source is the exact compiler output, independently readmitted by
Rust. The fixed manifest supplies expectations; its commands are never rewritten
into replacement test pipelines. New output directories are mandatory. Failed
runs remain separate from later versions and cannot be sealed as success.

From the clean, approved source, use these operations in order:

1. `build-compiler.sh PUBLIC_PLUGIN_SNAPSHOT NEW_COMPILER_BUILD` builds a fresh
   compiler worker and admission binary from one Git archive. The snapshot must
   contain the ninety exact public `.jpi` files and original `PLUGIN_SHA256SUMS`.
   Record the source/tree, image ID, admission SHA-256, archive and build inventory
   as independent freeze inputs.
2. Run `../test-jenkins-sequential-contained.py` with the exact worker image ID,
   `--image-sha256`, `--admission-bin` and a new `--output` directory. This invokes
   the fixed 23-input compiler campaign twice per input. It does not execute shell
   workloads. Record the resulting `campaign.json` SHA-256 independently.
3. Run `prepare-input.py COMPILER_EVIDENCE NEW_INPUT_JSON` with the external
   `--campaign-sha256`, `--worker-sha256`, `--admission-bin` and
   `--admission-sha256`. It regenerates source contexts and reruns Rust admission
   for all retained responses. Record the exact prepared-input SHA-256 before any
   product submission; this is a separate external pin, not an echoed string
   inside product observations.
4. Run `run-jenkins.py PUBLIC_PLUGIN_DIRECTORY NEW_JENKINS_EVIDENCE` and
   `run-product.sh FROZEN_INPUT_JSON NEW_PRODUCT_EVIDENCE`. Their independent
   namespaces allow concurrent execution. Each checks its actual container
   boundary before releasing fixtures. The product runner rebuilds the shipped
   binaries and observer from the same clean source archive. Capture each new
   evidence directory's `artifacts.json` SHA-256 independently after teardown.
5. Run `verify-paired.py JENKINS_EVIDENCE PRODUCT_EVIDENCE NEW_REPORT_JSON`, supplying
   `--jenkins-inventory-sha256`, `--product-inventory-sha256`, `--source-commit`,
   `--source-tree`, `--compiler-campaign-sha256`, `--prepared-input-sha256`,
   `--worker-sha256` and `--admission-sha256` from the earlier independent freeze
   receipts. The verifier checks complete artifacts, reconstructs the archived
   Git tree, joins producer/policy bytes to that tree, replays both container
   boundary validators and profile checks, and compares all measured cases.

Full verification requires the source archive and captured tracer binaries.
A retained publication instead uses `verify-retained.py RETAINED_ROOT
--retention-sha256 EXTERNAL_SHA --base-commit PROTECTED_BASE --repository REPO`.
Its externally pinned `RETENTION.json` authenticates an incremental source bundle,
the original report and inventories, and exactly five omitted tracer payloads.
The verifier hydrates the exact archive against the protected ancestor and checks
all semantic observations again, treating only those five payloads as recorded
identities. It does not rerun compiler admission or either workload runtime.
Historical receipts are never overwritten or silently repinned.

The original 228-source classification uses the separate
`../classify-jenkins-sequential-corpus.py` workflow and contract. Its supported
count is not the authored-runtime denominator.

Preparation checks execute no Jenkinsfile or shell fixture:

```sh
python3 scripts/jcomp003/test-jenkins-boundary.py
python3 scripts/jcomp003/test-product-boundary.py
python3 scripts/jcomp003/test-paired-verifier.py
python3 scripts/jcomp003/test-retained.py
python3 scripts/jcomp003/test-compiler-timeout.py
cargo test --locked -p mcloving-agent --test jcomp003_paired --no-run
```

The integration test is deliberately ignored by ordinary test discovery; the
contained runner invokes its exact name with `--ignored` and requires one passed,
zero failed and zero ignored test. Running that observer directly on an ordinary
host is outside this contract.
