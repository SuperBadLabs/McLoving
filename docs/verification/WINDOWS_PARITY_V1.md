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
journal epoch `3 -> 10`, returned the automatic SCM service, rejected stale
session authority, reported zero active attempts, and left no pre-reboot child.
The accepted attempt finalized `failed` with exit code 1 during SCM shutdown,
before the reboot removed connectivity, so it correctly had one offer and no
lease-expiration retry. Controller loss is a different transition: it produced
one lease expiration, a higher-fence second offer, eventual success, and no
escaped first child. A new post-reboot build also succeeded.

The evidence binds reviewed implementation commit
`cfd7aa240d4d402b2191acc887a9bec3535df215`, tree
`b2629e9d3f142429992ae86ee8917b1c5b6d670c`, and signed binary SHA-256
`f57cd07a5acc82f7d8e1ad2c8b27cd067056855d3deddae1477398359c8bf73b`.
The signer was a short-lived self-signed qualification identity, not
production `REL-001` provenance. Its exact CNG key identity is bound before
cleanup, exactly one `My`-store private-key deletion is required, and PASS is
withheld unless that bound key file is absent. The external exact-package
qualification harness observed 13 CNG key files before and after with zero
delta. NucBoxG3's complete 20-file
manifest SHA-256 is
`750c00979008c3b5c7df2eb139a51e846aa4d3aa09a12299b305b0f3aad71e3d`;
the HeMan outer evidence manifest is
`52f505055ca559dbc5d8bc3b6c61b676f3afd042f287881a22b9cb5e7b9c31f5`.
The initial incomplete 17-file Nuc seal from the same `cfd7aa2` qualification
run is retained by hash in the successor receipt, and the successor adds the
exact signed binary and cargo metadata
required by the nested package manifest. Three historical qualification keys
were also removed by exact CNG container name under a manifest-covered
remediation receipt.
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
Win32 directory-creation call before validation; existing roots are fully
revalidated. The service points only to a GUID-named immutable TLS snapshot
whose three PEM digests are verified. The entire post-snapshot seam is
transactional, and old generations are pruned
only after successful binding. Production trust remains `REL-001` work.
