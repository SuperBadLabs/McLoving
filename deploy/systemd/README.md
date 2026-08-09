# systemd deployment

Controller and Linux-agent service definitions will be added with packaging and
restart evidence.

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
