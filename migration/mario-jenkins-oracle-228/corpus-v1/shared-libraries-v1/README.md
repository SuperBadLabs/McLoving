# Mario Jenkins oracle shared-library ledger v1

This strict-YAML ledger reconciles every shared-library observation in the
sealed 228-file Mario oracle. It corrects two comment-only scanner matches and
adds seven live runtime loads missed by the frozen inventory scanner.

Seven distinct public references (eight live occurrences) are pinned to exact
SCM commits and normalized `vars`, `src`, and `resources` digests. The worker
may ingest only those prefetched, read-only trees. It receives no network or
credential authority and performs no Groovy, CPS, sandbox, plugin, or
controller execution.

Source verification is not execution certification. All 23 live observations
remain explicitly unsupported and `executable_cases` is exactly zero.

The immutable prefetched source tree originated at
`/sn8100/runs/mcloving/mig005-shared-libraries-20260801T103457Z/sources`.
The authoritative verification receipt and its immutable predecessor ledger
are recorded in `docs/architecture/JENKINS_SHARED_LIBRARY_ADMISSION_V1.md`.
The verifier embeds the owner-reviewed raw and semantic ledger digests; changing
the ledger and its adjacent lock together is rejected.

Verification:

```text
cargo run --locked -p mcloving-jenkins-shared-library -- verify migration/mario-jenkins-oracle-228/corpus-v1/shared-libraries-v1
cargo run --locked -p mcloving-jenkins-shared-library -- verify-corpus migration/mario-jenkins-oracle-228/corpus-v1/shared-libraries-v1 migration/mario-jenkins-oracle-228/corpus-v1/sources
cargo run --locked -p mcloving-jenkins-shared-library -- verify-sources migration/mario-jenkins-oracle-228/corpus-v1/shared-libraries-v1 /sn8100/runs/mcloving/mig005-shared-libraries-20260801T103457Z/sources
```
