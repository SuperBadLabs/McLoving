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

## Exact-head authenticated startup closure

Commit `11a0e18f860cc6ea39a623e601ad5ff1defb11ee`, tree
`50ffb804978cd457eba92d3d702d7a1c70516fd7`, closes the remaining
controller-trust seam. The production service writes a protected atomic
session receipt only after the mTLS `OpenSession` RPC is accepted; installation
requires its epoch to match the journal. A locally valid client-authentication
certificate from an untrusted issuer therefore failed after controller contact
and triggered complete service/package rollback.

The complete final-package NucBoxG3 campaign passed all execution modes,
cancellation/crash recovery, controller interruption, and physical reboot in
126.32 seconds. Session authority advanced `3 -> 8`, stale authority was
rejected, zero attempts remained active, and LAN SSH returned. The reboot gate
was corrected after an honestly preserved false positive where Windows reused
a numeric PID for `svchost.exe`; the final proof compares PID and process
creation identity. Live replacement then preserved journal/workspace state,
advanced epoch `55 -> 56`, and matched authenticated receipt epoch `56`.

The signed binary SHA-256 is
`68aa3779c1c31e91c917c546cc4d5ae643d7cabe59690ff2b03bc64be066e609`;
the archive SHA-256 is
`85ab3eb8117727a8f381b460f1545fdac62c88ac24c0f210fcf1be7bf08d0ba6`.
The immutable NucBoxG3 28-file manifest is
`750dd34beddfb95349e631e72f4dfdb203d32e91768a0fbd71b16cd8973fadd5`,
and HeMan's immutable 21-file cross-host manifest is
`0fe814ce842b6bdd978932f065eed5e8f591c60ad0075706f9ab303e49423e5b`.
All transient services, containers, package/source copies, TLS private keys,
and install roots were removed after sealing.

The final verifier identified one retry edge: after the first accepted session,
a transient reconciliation failure could reserve a newer epoch while the
write-once receipt stayed pinned to the older one. The follow-up implementation
keeps the receipt protected and atomic but updates it monotonically after each
accepted session. Equal epochs are idempotent and older epochs cannot replace a
newer receipt.

The exact repaired package is source commit
`06df6e82dec68e534c559b6fc90ad15cea1488e1`, tree
`c50ddee29b0a3bda637e2f1abc154fee88c2a6df`, archive SHA-256
`3ae5c215581519ecdde0c96ceeec8243a4b6d0355cc6ed4e1927b2d655895ae2`,
and signed-binary SHA-256
`596c5646c5a9754e15c6f72e00bd688a013c3dede0f229d01c13e88b4d965ecd`.
The full 118.80-second campaign passed and reboot advanced epoch `3 -> 10`.
The same runtime then recovered from controller absence at epoch `23` with a
matching authenticated receipt, proving monotonic receipt convergence on the
native target. Live replacement preserved state and advanced `23 -> 24`.

NucBoxG3's immutable 29-file evidence manifest is
`112b96f4144e8d222e0d51195db08a1385d4dd26bf3de6cd83500dd1e8dbc604`.
The immutable 46-file HeMan cross-host closure is
`/sn8100/runs/mcloving/windows/pr25-06df6e8-final`, manifest
`4ec9e0706ddd90c85c96894915994ecfd718384a831f83e3ee112f6098bb3ec4`.
Final read-only Claude verification returned `NO_FINDINGS`. All transient
Windows and HeMan campaign state was removed after the evidence was sealed.

## Exact final transactional post-start closure

Commit `99dc9be1912df8b0920e7afc0ce5b496aa6f4ec6`, tree
`716b2e56b21e56e6b17408ea41dcd4ef68ef6f48`, moves superseded-identity
cleanup and the final runtime ACL assertion inside the service-install
transaction. A uniquely anchored copy of the exact production installer was
instrumented to fail after authenticated service start; rollback removed both
the new service and fresh package root. The unmodified installer then passed
the complete native campaign. Read-only Claude verifier session
`ffc82179-b954-40f7-9397-67c2ab1bb4c5` reported `NO_FINDINGS` and made no
repository mutation.

The exact bundle SHA-256 is
`3ed49c45b444852475b6740a698f01b29bafe358a77137192ecad03329070b08`;
the archive SHA-256 is
`88d88c7271bdc78a016c932b80367505646157c6ea73a3e3d64e3e29b99c0641`;
the signed binary SHA-256 is
`3a45ee380fe81ef6639f23ed3edee2d45f5cfbd63863823e8b9030317321ee4b`.
The 138.47-second physical run passed every explicit execution mode,
cancellation/crash recovery, controller interruption, stale-authority
rejection, and reboot, advancing `4 -> 15` with zero active attempts.
Authenticated reconnect converged the journal and receipt at epoch `30`, and
same-package replacement preserved workspace state while advancing `30 -> 31`.

NucBoxG3's immutable 30-file evidence manifest is
`8ddb3ee02e9a42cf8adfacaf57fca0f97b0b74940d7cd407e0f44734f1992997`,
with nested package manifest
`287ff9bf701761023fc094104f5b4274ddfb24362d8b67da7d90c331e1917b86`.
The immutable 46-covered-file HeMan closure is
`/sn8100/runs/mcloving/windows/pr25-99dc9be-final`, manifest SHA-256
`759ecb5016b55bc106874ed3f3bb73f6e9968af47f930242f1317f743d6da5f6`.
All transient Windows and HeMan campaign state was removed after sealing.

## Recovery-ready authenticated-health closure

Commit `f12759e2e4ae8ccc1977193864fb1f1ba58bdc4f`, tree
`e6793ea05a0284ec01c939f482532cb97dacdfe7`, publishes authenticated agent
health only after reconciliation and finalization recovery initialize
successfully. A regression test starts with an epoch-40 receipt, fails recovery
initialization for epoch 41, and proves no epoch-41 health receipt is published.
This prevents service replacement from treating transport authentication alone
as proof that the recovered agent is ready.

The exact bundle SHA-256 is
`5efbe13e6807e80cef4538d009ec8e622dff92296d6de87ff62d07bd893a997f`;
the archive SHA-256 is
`7814bd3717c51b2352bf45d6f9b1658a3916b33785540451f388021a7f26dff5`;
the signed binary SHA-256 is
`ae71f7bfd38b235677b1724c98930449f928a4db32e8758d3da452d334ffa2d2`.
The 129.68-second native campaign passed every explicit execution mode,
cancellation/crash recovery, controller interruption, stale-authority
rejection, and physical reboot, advancing `2 -> 9` with zero active attempts.
Authenticated reconnect completed recovery at epoch `44`; same-package
replacement preserved workspace state and advanced `44 -> 45` with zero
active attempts.

NucBoxG3's immutable 30-file evidence manifest is
`ccab9ec5181e958c356dc3b55faca1890cdf84fa759bf1b3a5a588e503d4f51f`,
with nested package manifest
`65398956aedfde0d6be979522cc42262aee7eccf5fd6b924bcf404cde23691b6`.
The immutable 48-covered-file HeMan closure is
`/sn8100/runs/mcloving/windows/pr25-f12759e-final`, manifest SHA-256
`b7afa4c61fc1aadca566b6cf17a575cae5ac75163fe34b7b15c56c86fb78b295`.
An initial seal attempt stopped before producing an accepted manifest because
the prepared evidence harness still pinned the predecessor binary and signer;
the exact package identities were restored, the unsealed partial directory was
removed, and the clean seal plus independent verification passed. Final
cleanup removed the service, both install generations, all 20 Windows campaign
targets, temporary signer trust, TLS private material, controller, database
container, and HeMan gate roots while preserving only read-only evidence.
