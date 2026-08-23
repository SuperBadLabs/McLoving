# Contributing

All changes land through a protected pull request.

Before requesting review:

```text
./scripts/validate-foundation.sh
```

Every material change must update tests, documentation, the execution board,
and threat-model or architecture records when its boundary changes. Unsupported
behavior must remain explicit and must never be represented as successful.

Use `codex/` for Codex implementation branches. Keep commits coherent and do
not mix unrelated repairs into a ticket.

## Source-acquirer tests on hosts that restrict unprivileged user namespaces

The `mcloving-source-acquirer` suite drives a sealed launcher inside a kernel
user namespace. On a host with `kernel.apparmor_restrict_unprivileged_userns=1`
(the Ubuntu 24.04+ default), an unconfined run cannot execute the sealed
launcher there, and credential-bearing acquisition is refused by name as
`transport_namespace_unavailable`. The standalone test asserts that named
refusal in that environment -- nothing is skipped -- but the full acquisition
path only runs under the deployment AppArmor profile, which grants exactly
`userns create`.

To exercise the full path locally, do what
`.github/workflows/foundation.yml` does:

```text
bash scripts/prepare-source-transport-test-filesystems.sh
sudo apparmor_parser --replace --skip-cache \
  deploy/apparmor/mcloving-source-acquirer
aa-exec -p mcloving-source-acquirer -- \
  cargo test --locked -p mcloving-source-acquirer -- --test-threads=1
```

The transport roots under `/tmp/mcloving-source-transport-*` are host-global:
do not run two suites against them concurrently, and do not rebuild the crate
while a suite is running.
