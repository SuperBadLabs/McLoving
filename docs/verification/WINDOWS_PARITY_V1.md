# Linux/Windows execution parity matrix v1

Status: WIN-001, WIN-002, and WIN-003 verified on persistent NucBoxG3

This matrix is a release contract, not a portability claim inferred from
cross-compilation. Every row needs exact-package evidence on both platforms.

| Behavior | Linux mechanism | Windows mechanism | Required result |
|---|---|---|---|
| Direct process | argv, no shell | argv, no shell | Same exit classification and byte-exact streams |
| Native shell | Explicitly unsupported | `cmd.exe /D /S /C` script | Fail closed off Windows; durable streams on Windows |
| PowerShell | Explicitly unsupported | Noninteractive `powershell.exe -File` | Fail closed off Windows; durable streams on Windows |
| Workspace | Canonical root; no symlink component | ACL-owned inherited root; no reparse component | Existing/traversal/link target rejected |
| Containment | New process group | Suspended child assigned to kill-on-close Job Object | Timeout/cancel kills descendants |
| Agent crash | Process-group recovery metadata | Kernel closes Job Object and kills descendants | Journal exposes one interrupted attempt |
| Service lifecycle | Deployment-specific | SCM install/start/stop/uninstall | Two clean starts with monotonic journal epoch |
| Machine reboot | Persistent Linux war host | Persistent Windows war host | Journal reconciliation without duplicate execution |
| Stale authority | Fence and restore epoch | Same durable protocol | Stale session/fence rejected |
| Output/result | File and parent-directory fsync, then SHA-256 | File flush and SQLite FULL commit, then SHA-256; no inferred directory-fsync guarantee | Matching content digest now; directory-entry survival in persistent reboot gate |

Strict YAML declares the process creation contract as `mode: direct`,
`mode: windows_cmd`, or `mode: powershell`. The compiler emits Pipeline IR
v1.2 whenever a non-direct mode is present, canonical bytes bind the mode, and
the controller includes it in the execution specification. No extension,
program name, or command text is used to infer a shell.

## Gates

The `Windows agent` CI job is real Windows execution. It compiles the complete
workspace, runs the native Job Object tests, installs the release binary as a
Windows service, proves restart and forced-service-crash cleanup, checks the
SQLite journal, and uninstalls the service.

The persistent `WIN-002` gate additionally runs the shipped HeMan controller
against the native NucBoxG3 SCM service over outbound mTLS. It proves direct,
cmd, and PowerShell success with durable result and log digests, explicit
controller cancellation, descendant Job Object cleanup observed by a separate
follow-up job, an ACL root limited to `SYSTEM` and Administrators, journal
integrity after stop, and clean service uninstall. These are execution and
lifecycle boundaries, not a hostile-tenant sandbox.

The persistent-host reboot row is intentionally separate because a hosted CI
VM cannot supply honest across-reboot evidence. NucBoxG3 ran the exact signed
qualification package over pinned LAN SSH. A physical reboot advanced the
journal epoch `3 -> 11`, returned the automatic SCM service, rejected stale
session authority, reported zero active attempts, and left no pre-reboot child.
The accepted attempt finalized `failed` with exit code 1 during SCM shutdown,
before the reboot removed connectivity, so it correctly had one offer and no
lease-expiration retry. The Rust gate additionally accepts only the alternate
honest reboot race observed under stress: one lease expiration, exactly two
offers, a `retry-after-reboot` log marker, and one terminal success. Controller
loss is a different transition: it produced one lease expiration, a higher-
fence second offer, eventual success, and no escaped first child. A new post-
reboot build also succeeded.

The evidence binds final reviewed implementation commit
`38dd5c81a3098a53f83c1bcb758f76499409f0de`, tree
`ea71b1e71c0269bd670f9a9ca0940d2897e27aab`, and signed binary SHA-256
`5da01172be9332b515c7a4a0952b6a5a611241e393c7c1424444e0e5224399ed`.
The signer was a short-lived self-signed qualification identity, not
production `REL-001` provenance. Its exact CNG key identity is bound before
cleanup, exactly one `My`-store private-key deletion is required, and PASS is
withheld unless that bound key file is absent. The external exact-package
qualification harness observed 13 CNG key files before and after with zero
delta. NucBoxG3's complete 23-file manifest SHA-256 is
`478a6d3d19a7acfa8db6ce05f11cfece825a968cc6e21fe3713ac86f3ebc8860`;
the nested package manifest SHA-256 is
`9f9428873fd4db02df9f8523deb088e4d604f76e5715acb74b8ea5806f41f9da`;
and the 39-file HeMan outer evidence manifest is
`b9c1d9e79fdc038525a4f6823aa3a8497ac67c63c3c386ed3f46b49c20d844c7`.
The exact archive SHA-256 is
`c33931c7dff914ea3fb9a95033c49da197e0cf84697fc0617e4479b731cfb0d8`.
The earlier `pr25-cfd7aa2-final` and `pr25-9859c7a-final` bundles remain
immutable predecessor evidence, as does the later `pr25-a250c86-final`
installer predecessor.
Three historical qualification keys were removed by exact CNG container name
under a manifest-covered remediation receipt.
The Nuc seal removed its private gate key, service state, installed identity,
certificate trust, and test-only recovery-probe shim; manifest-covered cleanup
receipts record that state. HeMan's remaining mTLS private keys and isolated
database fixture were removed after evidence capture and independently
rechecked before publication.

The installer is fail-closed: digest and signer thumbprint are mandatory, a
wrong-digest native probe leaves both service state and certificate stores
unchanged, the copied binary is reverified, and temporary self-signed trust is
removed before the SCM service starts. Package and TLS inputs are copied into
canonical roots created with the restricted security descriptor in the atomic
Win32 directory-creation call before validation. Existing ancestors must be
real directories with trusted owners, non-NULL DACLs, and no untrusted direct
replacement or raw generic-access rights. The service points only to a GUID-
named immutable TLS snapshot whose three installed PEM digests match hashes
captured before protected staging. The exact staged binary observes an existing
journal read-only before mutation; after service start, schema v2 and a strictly
higher session epoch must be observed while SCM remains running. A corrupt-
journal native preflight proved rollback with no service, binary, or signer
trust residue. Native probes also proved that replaceable ancestors below both
`GateRoot` and `PackageRoot` are rejected before service/package mutation. The
physical reboot completion echoed the current request UUID and build ID, and
the Rust gate removed any prior marker before publishing that request. The
entire post-snapshot seam is transactional, and old
generations are pruned only after successful binding. Production trust remains
`REL-001` work.

The production mTLS loader parses the presented client leaf certificate and
rejects expired and not-yet-valid identities before agent runtime startup.
Generated validity-window tests cover valid, expired, and future leaves; an
exact Windows-binary preflight also rejected an expired certificate without
creating a journal or workspace.
