# Jenkins 2.568.1 oracle

These are immutable observations from the isolated, authenticated Mario
Jenkins oracle over the exact 228-file corpus in
`../jenkins-crucible/jenkinsfiles/`.

The compatibility truth is a vector:

| Gate | Count |
|---|---:|
| Jenkins Declarative model valid | 80 |
| Jenkins compile/CPS entry | 199 |
| Jenkins agent scheduling reached | 119 |
| Chengis non-empty structured IR at the sealed baseline | 140 |

None of the first three gates implies successful build execution. In
particular, the oracle had zero executors and all imported jobs were disabled.
The 119 count means Jenkins reached agent scheduling rather than failing
earlier during model validation, compilation, binding, or plugin resolution.

`Jenkins-RAnvil-Chengis-228-projects.tsv` and
`Jenkins-RAnvil-Chengis-summary.json` are the joined, human-oriented views.
The JSONL files preserve the raw per-file Jenkins model and job results.

The RAnvil columns are historical observations from the pre-remediation
binary. They are retained to keep the receipt immutable and must not be used
as the current RAnvil baseline: the label-expression fidelity fix changed
RAnvil native acceptance from 18 to 17.

Source evidence was sealed at:

`/sn8100/runs/expeditions/anvil-rust/20260724T131902Z/closer/jenkins-label-e8a8d14`

The source evidence root `SHA256SUMS` file hash is:

`416f2fca917d8658bbb46f49519a7a4f574e3eaba481491eac3326d65d679668`

## Scheduled replay

`.github/workflows/jenkins-oracle.yml` replays this oracle weekly and on
manual dispatch. `scripts/jenkins-oracle-podman.sh` starts an ephemeral
rootless Podman controller from the exact Jenkins image digest recorded above
and the 90-plugin version/SHA-256 lock in `plugins.lock.tsv`.

The replay preserves the original safety boundary:

- Jenkins publishes only on an ephemeral `127.0.0.1` port on an internal
  Podman network;
- anonymous API access is denied and the random administrator password is
  destroyed before receipts are sealed;
- the controller has zero executors, no host runtime socket, a read-only
  root, no added capabilities, `no-new-privileges`, and explicit CPU, memory,
  PID, and per-probe time bounds;
- the corpus is mounted read-only;
- the container, network, and volume must be gone before the run can pass.

The replay emits fresh JSONL observations and a machine-readable delta against
the committed baseline. It never writes to the committed oracle files. Any
stable per-file classification drift makes the scheduled job fail while the
new observations, image/container/network inspections, cleanup receipt, and
self-excluding `SHA256SUMS` remain available as a review artifact. Baseline
changes therefore require a separate reviewed commit.

The comparator derives one stable semantic verdict from terminal diagnostics:
Jenkins wraps a missing configured Declarative tool in
`MultipleCompilationErrorsException`, so every diagnostic containing both
`Tool type` and `does not have an install of` is compared as
`tool_configuration_failure`. This normalizes seven otherwise identical
Maven-tool failures that the original capture split across two raw labels
because Jenkins published its terminal result just before the final console
bytes. Both the original baseline JSONL and its hash remain unchanged, and the
delta records every raw-to-semantic normalization explicitly.
