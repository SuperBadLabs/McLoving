# Mario end-to-end alpha demo

For the working day beginning 2026-08-16, this demo is the only accepted
measure of McLoving product progress. Migration-ticket throughput, additional
contained proofs, and unmerged implementation do not substitute for a passing
run on Mario.

## Acceptance

One invocation of `scripts/mario-alpha-demo.sh` on the Tailscale host `mario`
must:

1. build the controller, CLI, and bootstrap administrator from one clean exact
   Git head with the repository's digest-pinned Rust image and locked graph;
2. start a uniquely named, loopback-only PostgreSQL instance without touching
   the existing `jenkins-oracle-228` or `chengis-canary` containers;
3. migrate the database, create a new organization/project, and start the
   shipped controller with its embedded trusted-Linux worker;
4. retrieve the shipped UI and OpenAPI document, then use only the public CLI/API
   to validate, plan, apply, submit, watch, and inspect the three-stage alpha
   pipeline;
5. finish one build successfully with the ordered Prepare, Test, and Package
   log markers visible through the public log surface;
6. retrieve status, graph, logs, audit, pipelines, builds, artifacts, and tests;
7. restart the controller against the same PostgreSQL and agent journal, prove
   the completed build remains queryable, and resubmit the same idempotency key
   without creating another build or completion marker; and
8. retain an owner-only evidence directory containing all public responses,
   controller/PostgreSQL logs, binary digests, a self-excluding SHA-256
   manifest, and `result.json` with `alpha_demo_complete=true`.

This demo deliberately has no production connector, credential, source,
trigger, scheduler-transfer, Jenkins-write, or external-effect authority. Its
workload executes only fixed `printf` commands inside McLoving's isolated
workspace. A passing alpha demonstrates a usable native product journey; it
does not claim Jenkins migration parity or authorize canary/cutover.

## Run

From a clean checkout on Mario:

```text
./scripts/mario-alpha-demo.sh
```

The command prints the successful build UUID and retained evidence directory.
The default evidence root is
`~/.local/share/mcloving/alpha-runs`; override it with
`MCLOVING_ALPHA_RUN_ROOT` when an owner-approved retention location is needed.

`MCLOVING_ALPHA_SKIP_BUILD=1` may be used only for local iteration after the
exact binaries already exist under `target/alpha-demo/release`. The acceptance
run must use the default build path.
