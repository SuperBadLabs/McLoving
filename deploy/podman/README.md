# Podman deployment

Rootless-podman half of the single-host deployment lane (DEPLOY-001). The
only containerized service is PostgreSQL; the controller and agent run as
native systemd user services on verified release binaries (see
`deploy/systemd/`), because McLoving ships signed binaries, not container
images — wrapping them in an unpinned base image would weaken the digest
story the lane exists to protect.

Files:

- `mcloving-postgres.container` — quadlet unit for the digest-pinned
  PostgreSQL image from `tools/versions.env`. The generated service uses
  Quadlet's version-stable conmon readiness mode. The dependent db-init
  oneshot owns the database-health barrier: it requires two bounded
  `pg_isready` successes before migrations or provisioning.
- `mcloving-postgres-data.volume` — quadlet definition of the named
  `mcloving-postgres-data` volume holding the database.

Both files are installed into `~/.config/containers/systemd/` for the
service user by `deploy/bin/mcloving-install`. Requires podman >= 4.9.

The full lane — install, upgrade, rollback, health verification, digest
re-read, and honest limitations — is documented in
`docs/operations/DEPLOYMENT_V1.md`. `deploy/test-deployment.sh` proves the
lane end to end without root by deriving every invocation from these unit
files.
