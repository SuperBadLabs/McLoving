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
journal epoch `3 -> 14`, returned the automatic SCM service, rejected stale
session authority, reported zero active attempts, and left no pre-reboot child.
The accepted attempt finalized `failed` with exit code 1 during SCM shutdown,
before the reboot removed connectivity, so it correctly had one offer and no
lease-expiration retry. The Rust gate additionally accepts only the alternate
honest reboot race observed under stress: one lease expiration, exactly two
offers, a `retry-after-reboot` log marker, and one terminal success. Controller
loss is a different transition: it produced one lease expiration, a higher-
fence second offer, eventual success, and no escaped first child. A new post-
reboot build also succeeded.

The protected-runtime physical-campaign evidence binds predecessor commit
`ee4fffac0b6bcc1b5e901bf2e6dfe3e485fd2e65`, tree
`4c03ae6727af27b2184c3bd639b1af7d7af3f954`, and signed binary SHA-256
`b7f9899013f88cf4be36c6c801a09f863b012da1cdd0582c17467cb149cf5019`.
The signer was a short-lived self-signed qualification identity, not
production `REL-001` provenance. Its exact CNG key identity is bound before
cleanup, exactly one `My`-store private-key deletion is required, and PASS is
withheld unless that bound key file is absent. The external exact-package
qualification harness observed 13 CNG key files before and after with zero
delta. NucBoxG3's complete 24-file manifest SHA-256 is
`5b952cabe3569deeb9e136ecaf0aea7e21df2f2251ac74b7c1139eafed175c18`;
the nested package manifest SHA-256 is
`8e9916715c75d667db2ade01a029e4e523a47667eb1a5e4f24065e6976634172`;
and the 37-covered-file HeMan outer evidence manifest is
`1cbd6bb5dc24ad51cd749644cf27c2a0324c853854637bcaa816cb40d9d87ac4`.
The separate bounded read-only verifier supplement manifest is
`2e380825e8d5e6abaed4940bb1481510541c8aa26fa013ed1a10efec35413e6c`;
Claude timed out while tool-using and returned no verdict or finding.
The exact archive SHA-256 is
`0da1475c9482d7a51ff7198d85ac18692666275f70affa9ddc21ff761b249f08`.
The earlier `pr25-f7ae170-final`, `pr25-cfd7aa2-final`, and
`pr25-9859c7a-final` bundles remain immutable predecessor evidence, as does the
`pr25-a250c86-final` installer predecessor.
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
captured before protected staging. After service start, schema v2 and a
strictly positive session epoch must be observed while SCM remains running.
Native probes also proved that replaceable ancestors below both
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

The installer never reuses an existing `PackageRoot`, because a tightened DACL
cannot revoke handles granted before installation. A writable-root preflight
proved rejection without ACL, marker, gate, or service mutation. Each accepted
install uses a fresh atomically protected package namespace; failed
transactions remove only the namespace created by that transaction after
rollback succeeds. The caller-writable `GateRoot` is input-only: runtime
journal, workspace, and test scripts live under a fresh atomically protected
`PackageRoot\runtime`. The exact physical campaign granted Users modify access
to `GateRoot`, then proved its ACL and marker unchanged, proved no runtime
children appeared there, and verified SCM paths and journal health only under
the restricted runtime root.

## Final PR #25 review repair

The final review repair binds commit
`eded04319089f182f90278285f6125fc51a34171`, tree
`7c762a15e12e583d8fdced60c76be0e26f5c3d8d`, and signed Windows binary
SHA-256
`fb8a8318d2b2afc2064309362cb8ba7e5e5e424b4d938dea8b9931a16ecee901`.
Client-certificate preflight now fails closed when Extended Key Usage excludes
TLS client authentication or Key Usage excludes digital signatures. An exact
server-auth-only leaf was rejected before package or service mutation, with the
existing SCM PID, registration, and environment unchanged.

An upgrade no longer initializes empty authority. It validates the existing
protected runtime, stops the predecessor, copies its SQLite database and WAL
plus complete workspace tree into a fresh package generation, verifies the
migrated stopped observation, and starts only after the new registration and
environment are durable. NucBoxG3 preserved predecessor epoch `193`, advanced
the replacement to `229`, retained active attempts `0 -> 0`, and preserved two
independently created durable workspace markers byte-for-byte. The complete
physical precursor gate at commit `3df4ad0` also passed all explicit modes,
recovery, and reboot, advancing epoch `3 -> 8` in 79.26 seconds.

The final archive SHA-256 is
`e1d8fb6215309c16481f404ff4b753eb9846c14d65929cb4d1af24998339bc3f`.
NucBoxG3's read-only 27-file evidence manifest is
`80a30bac93ec0ee090b3c2d380305fb71e9609175d1ab477e076ffd0f85f9ab2`,
with nested package manifest
`9c96eb438f2408471ade25f7bd127e5d15571dec86d3fbed23fdf34c68a34ffa`.
HeMan's immutable 41-file cross-host bundle is
`/sn8100/runs/mcloving/windows/pr25-eded043-final`, manifest
`8ecd9e79097f30e2ba2ccbf7160e940f3607f4e288e9bb6e1fb8161fa621a487`.
Cleanup removed the service, both install roots, gate private key, temporary
signer trust, qualification database container, and all transient package and
source paths while preserving the sealed evidence.
