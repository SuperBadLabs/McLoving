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
lease-expiration retry. Controller loss is a different transition: it produced
one lease expiration, a higher-fence second offer, eventual success, and no
escaped first child. A new post-reboot build also succeeded.

The evidence binds reviewed implementation commit
`1373a251069bbef50dc5952adf6378323c2e2504`, tree
`9fbb5a8783ff5d3473132a95815832854355c9a0`, and signed binary SHA-256
`03f2ef0eeb65d54ac8098381a5b0d99e4966bec577cb9750ac19302555d20282`.
The signer was a short-lived self-signed qualification identity, not
production `REL-001` provenance. NucBoxG3 manifest SHA-256 is
`2afb36ec50f4134bcb4a9d4a452543b5af721e67d6e257b5fa1637098b913950`;
the HeMan outer evidence manifest is
`530f6e9c07e740c983ada9853da7e2d86ea4d7f4237d958558eec70863509741`.
Private test keys, service state and installed identity, certificate trust,
the test-only recovery-probe shim, and the isolated database fixture were
removed before sealing; manifest-covered cleanup receipts record that state,
and independent verification rechecked both hashes and absence afterward.

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
