# systemd deployment

Systemd half of the single-host deployment lane (DEPLOY-001): user-manager
service units for a dedicated, lingering service user
(`loginctl enable-linger`). PostgreSQL runs rootless in podman via the
quadlet units in `deploy/podman/`.

Units (installed into `~/.config/systemd/user/` by
`deploy/bin/mcloving-install`):

- `mcloving-db-init.service` — oneshot bootstrap: waits for PostgreSQL,
  applies migrations with the migration role
  (`mcloving-identity-admin migrate`), enables constrained LOGIN on the
  `mcloving_tenant` runtime role, and provisions the configured
  organization/project pair. Idempotent.
- `mcloving-controller.service` — public API, agent-control mTLS plane, and
  the (deliberately disabled) embedded worker. Startup succeeds only when
  the public API answers.
- `mcloving-agent.service` — outbound-only mTLS agent. `mcloving-agent
  probe` runs as `ExecStartPre` to prove identity, controller reachability,
  and journal health before the long-running service starts.

Startup order: `mcloving-postgres.service` (healthy, via quadlet
`Notify=healthy`) → `mcloving-db-init.service` → `mcloving-controller.service`
→ `mcloving-agent.service`.

Every unit sources its environment contract from `~/.config/mcloving/*.env`
(templates in `deploy/env/`) and refuses to start while any variable is
missing, empty, or still a `__SET_ME…__` placeholder
(`deploy/bin/mcloving-env-guard`).

Operations — install, upgrade, rollback, health verification, and the
deployed-digest re-read consumed by a future cutover freeze — are documented
in `docs/operations/DEPLOYMENT_V1.md` and proven by
`deploy/test-deployment.sh`.

## Source-acquirer kernel deadline profile

SCM-001 credentialed HTTP transport requires a Linux user and PID namespace so
the kernel can revoke the complete transport at its absolute deadline. On an
AppArmor host that restricts unprivileged user namespaces, install and activate
the repository-owned named profile before starting the source acquirer:

```sh
sudo install -D -m 0644 \
  deploy/apparmor/mcloving-source-acquirer \
  /etc/apparmor.d/mcloving-source-acquirer
sudo apparmor_parser --replace --skip-cache \
  /etc/apparmor.d/mcloving-source-acquirer
```

The profile has no executable attachment and therefore grants nothing merely by
being loaded. The service must opt in explicitly:

```ini
ExecStart=/usr/bin/aa-exec -p mcloving-source-acquirer -- /usr/libexec/mcloving/mcloving-source-acquirer
```

The profile preserves the process's existing unconfined host boundary and adds
only `userns create`. It does not disable the host-wide restriction, add a
capability, or grant another process the right to enter the profile. A missing,
unloaded, or unselected profile makes credentialed HTTP acquisition fail closed
before Git starts.

Validate profile syntax without loading it with
`scripts/validate-source-acquirer-apparmor.sh`.
