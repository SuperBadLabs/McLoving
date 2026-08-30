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
documented default 10 ms work and 50 ms cancellation settings, samples idle
CPU from `/proc` for the process containing both the controller and embedded
worker, and reports raw timings, PostgreSQL transaction deltas, and
median/minimum per-stage delta estimators for 50- and 100-stage `sh -c true`
pipelines. Both workload shapes are warmed before measurement. The gate
requires median latency at or below 183 ms/stage, combined idle CPU below 5%,
and rejects a receipt whose median and minimum latency estimators differ by
more than 15%. The sample sizes can be overridden with
`MCLOVING_BENCH_SMALL_STAGES`, `MCLOVING_BENCH_LARGE_STAGES`,
`MCLOVING_BENCH_HEATS`, and `MCLOVING_BENCH_IDLE_SECONDS`.

For an already-running split controller/agent deployment, combined idle CPU
is measured without process-name ambiguity by passing exact PIDs:

```bash
./scripts/profile-idle-cpu.sh 10 CONTROLLER_PID AGENT_PID
```
