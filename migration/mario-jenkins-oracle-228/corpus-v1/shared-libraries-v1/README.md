# Mario Jenkins oracle shared-library ledger v1

This strict-YAML ledger reconciles every shared-library observation in the
sealed 228-file Mario oracle. It corrects two comment-only scanner matches and
adds four live runtime loads missed by the frozen inventory scanner.

Seven distinct public references (eight live occurrences) are pinned to exact
SCM commits and normalized `vars`, `src`, and `resources` digests. The worker
may ingest only those prefetched, read-only trees. It receives no network or
credential authority and performs no Groovy, CPS, sandbox, plugin, or
controller execution.

Source verification is not execution certification. All 20 live observations
remain explicitly unsupported and `executable_cases` is exactly zero.

The immutable external source/evidence root is
`/sn8100/runs/mcloving/mig005-shared-libraries-20260801T103457Z`; its
self-excluding 522-file manifest SHA-256 is
`a6671f966e3738e25135b33fc397b5fb21666ac60edb931b49e3b35672f5123b`.

Verification:

```text
cargo run --locked -p mcloving-jenkins-shared-library -- verify migration/mario-jenkins-oracle-228/corpus-v1/shared-libraries-v1
cargo run --locked -p mcloving-jenkins-shared-library -- verify-corpus migration/mario-jenkins-oracle-228/corpus-v1/shared-libraries-v1 migration/mario-jenkins-oracle-228/corpus-v1/sources
cargo run --locked -p mcloving-jenkins-shared-library -- verify-sources migration/mario-jenkins-oracle-228/corpus-v1/shared-libraries-v1 /sn8100/runs/mcloving/mig005-shared-libraries-20260801T103457Z/sources
```
