# ADR 0011: Performance contract

Status: Accepted

Performance claims require equivalent behavior, resources, inputs, and raw
receipts. Component, synthetic, real-workload, recovery, capacity, and soak
lanes report latency, throughput, errors, CPU, memory, I/O, and safety margin.
A faster incorrect result is a defect.

The repository-owned stage-latency receipt is produced by:

```bash
./scripts/benchmark-stage-latency.sh
```

It runs the shipped release controller's embedded-worker profile at the
shipped 500 ms compatibility work setting and 50 ms cancellation setting, samples idle
CPU from `/proc` for the process containing both the controller and embedded
worker, and reports raw timings, PostgreSQL transaction deltas, and
median/minimum per-stage delta estimators for 50- and 100-stage `sh -c true`
pipelines. Both workload shapes are warmed before measurement and their order
alternates between heats. The receipt binds the clean source commit and tree,
controller binary digest, pinned Rust and PostgreSQL images, and host. The gate
requires median latency at or below 183 ms/stage, combined idle CPU below 5%,
and rejects a receipt whose median and minimum latency estimators differ by
more than 15%. The sample sizes can be overridden with
`MCLOVING_BENCH_SMALL_STAGES`, `MCLOVING_BENCH_LARGE_STAGES`,
`MCLOVING_BENCH_HEATS`, and `MCLOVING_BENCH_IDLE_SECONDS`.

For an already-running split controller/agent deployment, complete-stack idle
CPU is measured without process-name ambiguity by passing the exact controller,
agent, PostgreSQL, and rootless port-forwarder PIDs. The profiler rejects
duplicate PIDs, validates each positional role from its Linux process identity,
recursively includes every descendant under all four process roots, rejects a
process tree that changes during sampling, includes cumulative waited-child CPU
so a descendant born and reaped inside the window cannot escape accounting,
requires the sampled controller and agent executable hashes to match the clean
checkout's release binaries, records the forwarder executable hash and a
digest-pinned PostgreSQL image, and applies the non-overridable contract
threshold of 5%. Omitting the database or forwarder is not a whole-stack
receipt:

```bash
MCLOVING_IDLE_POSTGRES_IMAGE=postgres@sha256:... \
  ./scripts/profile-idle-cpu.sh 10 CONTROLLER_PID AGENT_PID POSTGRES_PID PORT_FORWARDER_PID
```
