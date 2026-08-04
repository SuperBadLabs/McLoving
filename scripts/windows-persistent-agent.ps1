param(
    [string]$GateRoot = "C:\ProgramData\McLoving-Windows-War\win002",
    [string]$ServiceName = "McLovingWin002",
    [string]$BinarySource = "C:\McLoving-Windows-Work\target-win001-20260803\release\mcloving-agent.exe",
    [string]$PackageRoot = "C:\Program Files\McLoving\win002",
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{64}$")]
    [string]$ExpectedBinarySha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{40}$")]
    [string]$ExpectedSignerThumbprint,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{64}$")]
    [string]$ExpectedAgentConfigSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{64}$")]
    [string]$ExpectedControllerCaSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{64}$")]
    [string]$ExpectedAgentCertificateSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{64}$")]
    [string]$ExpectedAgentPrivateKeySha256,
    [string]$SignerCertificateSource = ""
)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "persistent Windows agent installation requires an elevated administrator session"
}

function New-RestrictedAcl([bool]$IsDirectory) {
    $acl = if ($IsDirectory) {
        [Security.AccessControl.DirectorySecurity]::new()
    } else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $acl.SetAccessRuleProtection($true, $false)
    $administrators = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $acl.SetOwner($administrators)
    $inheritance = if ($IsDirectory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($sidValue in @("S-1-5-18", "S-1-5-32-544")) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function Assert-RestrictedTreeAcl([string]$Root) {
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer) {
        throw "restricted root must be an existing directory: $Root"
    }
    $items = @(Get-ChildItem -LiteralPath $rootItem.FullName -Force -Recurse -ErrorAction Stop)
    foreach ($item in @($rootItem) + $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "restricted tree contains a reparse point: $($item.FullName)"
        }
    }
    foreach ($item in @($rootItem) + $items) {
        $applied = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $ownerSid = $applied.GetOwner(
            [Security.Principal.SecurityIdentifier]
        ).Value
        $rules = @($applied.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        ))
        $unexpected = @($rules | Where-Object {
            $_.IdentityReference.Value -notin @("S-1-5-18", "S-1-5-32-544") -or
            $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl
        })
        # The root itself must block inheritance from its caller-controlled
        # parent. Descendants created later by the service may safely inherit
        # the root's exact SYSTEM/Administrators rules; inspect their complete
        # effective rule set rather than requiring each file to break
        # inheritance independently.
        $isRoot = $item.FullName -ieq $rootItem.FullName
        if ($ownerSid -ne "S-1-5-32-544" -or
            ($isRoot -and -not $applied.AreAccessRulesProtected) -or
            $rules.Count -ne 2 -or
            $unexpected.Count -ne 0) {
            throw "restricted ACL replacement verification failed: $($item.FullName)"
        }
    }
}

function Set-RestrictedTreeAcl([string]$Root) {
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer) {
        throw "restricted root must be an existing directory: $Root"
    }
    $items = @(Get-ChildItem -LiteralPath $rootItem.FullName -Force -Recurse -ErrorAction Stop)
    foreach ($item in @($rootItem) + $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "restricted tree contains a reparse point: $($item.FullName)"
        }
        Set-Acl -LiteralPath $item.FullName -AclObject (New-RestrictedAcl $item.PSIsContainer)
    }
    Assert-RestrictedTreeAcl $rootItem.FullName
}

function New-RestrictedDirectoryAtomic([string]$Path) {
    if (-not ("McLoving.Win32Directory" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace McLoving {
    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityAttributes {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    public static class Win32Directory {
        [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW",
            CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateDirectory(
            string path,
            ref SecurityAttributes securityAttributes);
    }
}
'@
    }

    $directoryCreated = $false
    try {
        $acl = New-RestrictedAcl $true
        $descriptor = $acl.GetSecurityDescriptorBinaryForm()
        $pinnedDescriptor = [Runtime.InteropServices.GCHandle]::Alloc(
            $descriptor,
            [Runtime.InteropServices.GCHandleType]::Pinned
        )
        try {
            $attributes = [McLoving.SecurityAttributes]::new()
            $attributes.Length = [Runtime.InteropServices.Marshal]::SizeOf($attributes)
            $attributes.SecurityDescriptor = $pinnedDescriptor.AddrOfPinnedObject()
            $attributes.InheritHandle = $false
            if (-not [McLoving.Win32Directory]::CreateDirectory($Path, [ref]$attributes)) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw [ComponentModel.Win32Exception]::new(
                    $errorCode,
                    "atomic restricted-directory creation failed for ${Path}"
                )
            }
            $directoryCreated = $true
        } finally {
            if ($pinnedDescriptor.IsAllocated) { $pinnedDescriptor.Free() }
        }
        Assert-RestrictedTreeAcl $Path
    } catch {
        if ($directoryCreated -and (Test-Path -LiteralPath $Path)) {
            # The directory is still empty here. Do not recurse into content a
            # concurrent administrator may have placed in a failed generation.
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Assert-NonReplaceableDirectoryChain([string]$Path) {
    $trustedSids = @(
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )
    $dangerousRights =
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    [uint64]$genericRightsMask = 4026531840
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($true) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "restricted directory ancestor is not a real directory: $($item.FullName)"
        }
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $rawDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            $acl.GetSecurityDescriptorBinaryForm(),
            0
        )
        if ($null -eq $rawDescriptor.DiscretionaryAcl) {
            throw "restricted directory ancestor has a NULL DACL: $($item.FullName)"
        }
        $ownerSid = $acl.GetOwner(
            [Security.Principal.SecurityIdentifier]
        ).Value
        if ($ownerSid -notin $trustedSids) {
            throw "restricted directory ancestor has an untrusted owner: $($item.FullName)"
        }
        $replaceableRules = @($acl.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        ) | Where-Object {
            [uint64]$rightsMask = [int64]$_.FileSystemRights -band 4294967295
            $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
            $_.IdentityReference.Value -notin $trustedSids -and
            (($rightsMask -band $genericRightsMask) -ne 0 -or
                ($_.FileSystemRights -band $dangerousRights) -ne 0)
        })
        if ($replaceableRules.Count -ne 0) {
            throw "restricted directory ancestor grants untrusted replacement rights: $($item.FullName)"
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-NonReplaceableParentChain([string]$Path) {
    $cursor = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    if ([string]::IsNullOrWhiteSpace($cursor)) {
        throw "restricted path has no parent: $Path"
    }
    while (-not (Test-Path -LiteralPath $cursor)) {
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
            throw "restricted path has no existing ancestor: $Path"
        }
        $cursor = $parent
    }
    Assert-NonReplaceableDirectoryChain $cursor
}

function New-RestrictedDirectoryPathAtomic([string]$Path) {
    $missing = [Collections.Generic.Stack[string]]::new()
    $created = [Collections.Generic.Stack[string]]::new()
    $cursor = [IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $cursor)) {
        $missing.Push($cursor)
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
            throw "restricted directory has no existing ancestor: $Path"
        }
        $cursor = $parent
    }
    Assert-NonReplaceableDirectoryChain $cursor
    try {
        while ($missing.Count -ne 0) {
            $createdPath = $missing.Pop()
            New-RestrictedDirectoryAtomic $createdPath
            $created.Push($createdPath)
        }
    } catch {
        while ($created.Count -ne 0) {
            $createdPath = $created.Pop()
            if (Test-Path -LiteralPath $createdPath) {
                Remove-Item -LiteralPath $createdPath -Force -ErrorAction SilentlyContinue
            }
        }
        throw
    }
}

function Get-RequiredConfigString([object]$Config, [string]$Name) {
    $property = $Config.PSObject.Properties[$Name]
    if ($null -eq $property -or
        $property.Value -isnot [string] -or
        [string]::IsNullOrWhiteSpace($property.Value)) {
        throw "agent configuration property $Name must be a non-empty string"
    }
    return $property.Value
}

function Get-RegularFileSha256([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "installer input must be a regular non-reparse file: $Path"
    }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
}

function Invoke-AgentConfigValidation([string]$AgentBinary, [hashtable]$Environment) {
    $priorEnvironment = @{}
    try {
        foreach ($name in $Environment.Keys) {
            $priorEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
            [Environment]::SetEnvironmentVariable($name, $Environment[$name], "Process")
        }
        & $AgentBinary validate-config
        if ($LASTEXITCODE -ne 0) {
            throw "agent configuration validation failed: $LASTEXITCODE"
        }
    } finally {
        foreach ($name in $Environment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $priorEnvironment[$name], "Process")
        }
    }
}

function Get-JournalObservation([string]$AgentBinary, [string]$JournalPath) {
    $item = Get-Item -LiteralPath $JournalPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "agent journal must be an existing regular non-reparse file: $JournalPath"
    }
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = (& $AgentBinary journal-observe $JournalPath 2>&1 | Out-String).Trim()
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorPreference
    }
    if ($exitCode -ne 0) {
        throw "read-only journal observation failed: exit=$exitCode output=$output"
    }
    $match = [regex]::Match(
        $output,
        '^schema_version=(\d+) journal_mode=wal integrity=ok session_epoch=(\d+) active_attempts=(\d+)$'
    )
    if (-not $match.Success) {
        throw "invalid read-only journal observation: $output"
    }
    return [pscustomobject]@{
        SchemaVersion = [uint64]::Parse($match.Groups[1].Value)
        SessionEpoch = [uint64]::Parse($match.Groups[2].Value)
        ActiveAttempts = [uint64]::Parse($match.Groups[3].Value)
        Output = $output
    }
}

function ConvertTo-ServiceStartMode([string]$StartMode) {
    switch ($StartMode) {
        "Auto" { return "Automatic" }
        "Manual" { return "Manual" }
        "Disabled" { return "Disabled" }
        default { throw "unsupported existing service start mode: $StartMode" }
    }
}

function Restore-PreviousBinary(
    [string]$InstalledBinary,
    [string]$BackupBinary,
    [bool]$PreviouslyExisted
) {
    $lastFailure = $null
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            if ($PreviouslyExisted) {
                Copy-Item -LiteralPath $BackupBinary -Destination $InstalledBinary -Force
            } else {
                if (Test-Path -LiteralPath $InstalledBinary) {
                    Remove-Item -LiteralPath $InstalledBinary -Force -ErrorAction Stop
                }
            }
            return
        } catch {
            $lastFailure = $_
            Start-Sleep -Milliseconds 500
        }
    }
    throw "prior binary could not be restored within 30 seconds: $($lastFailure.Exception.Message)"
}

function Install-StagedBinary(
    [string]$StagedBinary,
    [string]$InstalledBinary
) {
    $lastFailure = $null
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            Copy-Item -LiteralPath $StagedBinary -Destination $InstalledBinary -Force
            return
        } catch {
            $lastFailure = $_
            Start-Sleep -Milliseconds 500
        }
    }
    throw "staged binary could not be installed within 30 seconds: $($lastFailure.Exception.Message)"
}

$GateRoot = [IO.Path]::GetFullPath($GateRoot)
$PackageRoot = [IO.Path]::GetFullPath($PackageRoot)
# Protecting only the final directory is insufficient if another principal can
# rename/delete that pathname from its parent. Reject replaceable existing
# ancestors before reading GateRoot inputs or creating PackageRoot children.
Assert-NonReplaceableParentChain $GateRoot
Assert-NonReplaceableParentChain $PackageRoot
# A DACL replacement cannot revoke handles granted while an existing root was
# writable. Never reuse that namespace: upgrades must supply a fresh
# PackageRoot so its boundary is established atomically at creation.
if (Test-Path -LiteralPath $PackageRoot) {
    throw "package root already exists; use a fresh protected package root: $PackageRoot"
}
$binary = Join-Path $packageRoot "mcloving-agent.exe"
$stagedBinary = Join-Path $packageRoot "mcloving-agent.installing.exe"
$backupBinary = Join-Path $packageRoot "mcloving-agent.rollback.exe"
$configPath = Join-Path $GateRoot "agent-config.json"
$controllerCaSource = Join-Path $GateRoot "ca.pem"
$agentCertificateSource = Join-Path $GateRoot "agent.pem"
$agentPrivateKeySource = Join-Path $GateRoot "agent-key.pem"
$gateInputHashes = @(
    [PSCustomObject]@{
        Path = $configPath
        ExpectedSha256 = $ExpectedAgentConfigSha256.ToLowerInvariant()
    },
    [PSCustomObject]@{
        Path = $controllerCaSource
        ExpectedSha256 = $ExpectedControllerCaSha256.ToLowerInvariant()
    },
    [PSCustomObject]@{
        Path = $agentCertificateSource
        ExpectedSha256 = $ExpectedAgentCertificateSha256.ToLowerInvariant()
    },
    [PSCustomObject]@{
        Path = $agentPrivateKeySource
        ExpectedSha256 = $ExpectedAgentPrivateKeySha256.ToLowerInvariant()
    }
)
foreach ($gateInput in $gateInputHashes) {
    $sourceInputHash = Get-RegularFileSha256 $gateInput.Path
    if ($sourceInputHash -cne $gateInput.ExpectedSha256) {
        throw "operator-pinned gate input hash mismatch: $($gateInput.Path)"
    }
}
$controllerCaExpectedSha256 = $ExpectedControllerCaSha256.ToLowerInvariant()
$agentCertificateExpectedSha256 = $ExpectedAgentCertificateSha256.ToLowerInvariant()
$agentPrivateKeyExpectedSha256 = $ExpectedAgentPrivateKeySha256.ToLowerInvariant()

$commonApplicationData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonApplicationData
)
$inputStageRoot = Join-Path $commonApplicationData `
    ("McLoving-Install-Inputs-" + [Guid]::NewGuid().ToString("N"))
$protectedBinarySource = Join-Path $inputStageRoot "mcloving-agent.exe"
$protectedSignerCertificateSource = Join-Path $inputStageRoot "signer.cer"
$protectedConfigPath = Join-Path $inputStageRoot "agent-config.json"
$protectedControllerCaPath = Join-Path $inputStageRoot "ca.pem"
$protectedAgentCertificatePath = Join-Path $inputStageRoot "agent.pem"
$protectedAgentPrivateKeyPath = Join-Path $inputStageRoot "agent-key.pem"
$identityGeneration = Join-Path $PackageRoot `
    ("identity-" + [Guid]::NewGuid().ToString("N"))
$runtimeGeneration = Join-Path $PackageRoot "runtime"
$controllerCaPath = Join-Path $identityGeneration "ca.pem"
$agentCertificatePath = Join-Path $identityGeneration "agent.pem"
$agentPrivateKeyPath = Join-Path $identityGeneration "agent-key.pem"
$scripts = Join-Path $runtimeGeneration "scripts"
$journal = Join-Path $runtimeGeneration "agent.db"
$workspace = Join-Path $runtimeGeneration "workspaces"
$sessionReceipt = Join-Path $runtimeGeneration "authenticated-session.receipt"
$temporaryTrustStores = @()
$installFailure = $null
$trustCleanupFailures = @()
$inputCleanupFailures = @()
$packageRootCreated = $false
$identityGenerationCreated = $false
$runtimeGenerationCreated = $false
try {
    # Package and GateRoot inputs may be supplied from locations writable by a
    # non-administrator.  Copy the binary, signer, and TLS identity into a fresh
    # protected tree, then authenticate only those immutable copies.
    # The directory is protected before any child is created, so copied files
    # inherit the SYSTEM/Administrators-only boundary immediately.
    New-RestrictedDirectoryPathAtomic $inputStageRoot
    Copy-Item -LiteralPath $BinarySource -Destination $protectedBinarySource -ErrorAction Stop
    if ($SignerCertificateSource) {
        Copy-Item -LiteralPath $SignerCertificateSource `
            -Destination $protectedSignerCertificateSource -ErrorAction Stop
    }
    Copy-Item -LiteralPath $configPath `
        -Destination $protectedConfigPath -ErrorAction Stop
    Copy-Item -LiteralPath $controllerCaSource `
        -Destination $protectedControllerCaPath -ErrorAction Stop
    Copy-Item -LiteralPath $agentCertificateSource `
        -Destination $protectedAgentCertificatePath -ErrorAction Stop
    Copy-Item -LiteralPath $agentPrivateKeySource `
        -Destination $protectedAgentPrivateKeyPath -ErrorAction Stop
    Set-RestrictedTreeAcl $inputStageRoot

    $stagedIdentityHashes = @(
        [PSCustomObject]@{
            Path = $protectedConfigPath
            ExpectedSha256 = $ExpectedAgentConfigSha256.ToLowerInvariant()
        },
        [PSCustomObject]@{
            Path = $protectedControllerCaPath
            ExpectedSha256 = $controllerCaExpectedSha256
        },
        [PSCustomObject]@{
            Path = $protectedAgentCertificatePath
            ExpectedSha256 = $agentCertificateExpectedSha256
        },
        [PSCustomObject]@{
            Path = $protectedAgentPrivateKeyPath
            ExpectedSha256 = $agentPrivateKeyExpectedSha256
        }
    )
    foreach ($stagedIdentity in $stagedIdentityHashes) {
        $stagedHash = Get-RegularFileSha256 $stagedIdentity.Path
        if ($stagedHash -cne $stagedIdentity.ExpectedSha256) {
            throw "TLS identity changed while entering protected staging: $($stagedIdentity.Path)"
        }
    }

    # Parse configuration only from the operator-pinned immutable copy. The
    # caller-writable GateRoot is never an authority for controller or identity
    # selection merely because its files agree with one another.
    $configSource = Get-Content -Raw -LiteralPath $protectedConfigPath
    $config = $configSource | ConvertFrom-Json
    $agentId = Get-RequiredConfigString $config "agent_id"
    $trustPool = Get-RequiredConfigString $config "trust_pool"
    $organizationId = Get-RequiredConfigString $config "organization_id"
    $controllerUri = Get-RequiredConfigString $config "controller_uri"
    $controllerDnsName = Get-RequiredConfigString $config "controller_dns_name"
    $validationEnvironment = @{
        MCLOVING_AGENT_ID = $agentId
        MCLOVING_AGENT_TRUST_POOL = $trustPool
        MCLOVING_AGENT_ORGANIZATION_ID = $organizationId
        MCLOVING_CONTROLLER_URI = $controllerUri
        MCLOVING_CONTROLLER_DNS_NAME = $controllerDnsName
        MCLOVING_CONTROLLER_CA_PATH = $protectedControllerCaPath
        MCLOVING_AGENT_CERTIFICATE_PATH = $protectedAgentCertificatePath
        MCLOVING_AGENT_PRIVATE_KEY_PATH = $protectedAgentPrivateKeyPath
        MCLOVING_AGENT_JOURNAL_PATH = $journal
        MCLOVING_AGENT_WORKSPACE_ROOT = $workspace
        MCLOVING_AGENT_SESSION_RECEIPT_PATH = $sessionReceipt
        MCLOVING_AGENT_LEASE_SECONDS = "5"
        MCLOVING_AGENT_POLL_MILLISECONDS = "50"
        MCLOVING_AGENT_RENEW_MILLISECONDS = "500"
        MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS = "250"
    }

    $sourceHash = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $protectedBinarySource).Hash.ToLowerInvariant()
    if ($sourceHash -ne $ExpectedBinarySha256.ToLowerInvariant()) {
        throw "package binary hash mismatch: $sourceHash"
    }
    if ($SignerCertificateSource) {
        $signerCertificates = New-Object `
            Security.Cryptography.X509Certificates.X509Certificate2Collection
        $signerCertificates.Import($protectedSignerCertificateSource)
        if ($signerCertificates.Count -ne 1) {
            throw "signer certificate file must contain exactly one certificate"
        }
        if ($signerCertificates[0].Thumbprint -ne $ExpectedSignerThumbprint) {
            throw "signer certificate thumbprint mismatch"
        }
        foreach ($storeName in @("Root", "TrustedPublisher")) {
            $alreadyTrusted = Get-ChildItem "Cert:\LocalMachine\$storeName" |
                Where-Object { $_.Thumbprint -eq $ExpectedSignerThumbprint }
            if (-not $alreadyTrusted) {
                # Record cleanup responsibility before import so even a partially
                # successful provider operation is removed by the finally block.
                $temporaryTrustStores += $storeName
                $importedCertificate = Import-Certificate `
                    -FilePath $protectedSignerCertificateSource `
                    -CertStoreLocation "Cert:\LocalMachine\$storeName"
                if ($importedCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
                    throw "imported signer certificate thumbprint mismatch in $storeName"
                }
            }
        }
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $protectedBinarySource
    if ($signature.Status -ne "Valid") {
        throw "package Authenticode status is $($signature.Status)"
    }
    if ($signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
        throw "package signer thumbprint mismatch"
    }
    # Only the hash- and signer-pinned binary may parse the actual PEM files.
    # This proves that the client certificate and private key match before the
    # installer mutates ACLs, package contents, the registry, or SCM.
    Invoke-AgentConfigValidation $protectedBinarySource $validationEnvironment

    New-RestrictedDirectoryPathAtomic $PackageRoot
    $packageRootCreated = $true
    Assert-NonReplaceableDirectoryChain $PackageRoot
    # Runtime state must never live beneath the caller-supplied GateRoot. A
    # DACL replacement cannot revoke a hostile handle opened before elevation,
    # so establish a fresh protected generation before creating any journal,
    # workspace, or executable test-script child.
    New-RestrictedDirectoryAtomic $runtimeGeneration
    $runtimeGenerationCreated = $true
    New-RestrictedDirectoryAtomic $scripts
    New-RestrictedDirectoryAtomic $workspace
    New-RestrictedDirectoryAtomic $identityGeneration
    $identityGenerationCreated = $true
    $identityCopies = @(
        [PSCustomObject]@{
            Source = $protectedControllerCaPath
            Destination = $controllerCaPath
            ExpectedSha256 = $controllerCaExpectedSha256
        },
        [PSCustomObject]@{
            Source = $protectedAgentCertificatePath
            Destination = $agentCertificatePath
            ExpectedSha256 = $agentCertificateExpectedSha256
        },
        [PSCustomObject]@{
            Source = $protectedAgentPrivateKeyPath
            Destination = $agentPrivateKeyPath
            ExpectedSha256 = $agentPrivateKeyExpectedSha256
        }
    )
    foreach ($identityCopy in $identityCopies) {
        Copy-Item -LiteralPath $identityCopy.Source `
            -Destination $identityCopy.Destination -ErrorAction Stop
        $installedIdentityHash = Get-RegularFileSha256 $identityCopy.Destination
        if ($installedIdentityHash -cne $identityCopy.ExpectedSha256) {
            throw "installed TLS identity copy hash mismatch: $($identityCopy.Destination)"
        }
    }
    Set-RestrictedTreeAcl $PackageRoot
    Assert-NonReplaceableDirectoryChain $PackageRoot
    Remove-Item -LiteralPath $stagedBinary, $backupBinary -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $protectedBinarySource -Destination $stagedBinary -Force
    $installedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $stagedBinary).Hash.ToLowerInvariant()
    if ($installedHash -ne $ExpectedBinarySha256.ToLowerInvariant()) {
        throw "installed binary hash mismatch: $installedHash"
    }
    $installedSignature = Get-AuthenticodeSignature -LiteralPath $stagedBinary
    if ($installedSignature.Status -ne "Valid" -or
        $installedSignature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
        throw "installed binary Authenticode validation failed"
    }
    Set-RestrictedTreeAcl $PackageRoot
} catch {
    $installFailure = $_
} finally {
    foreach ($storeName in $temporaryTrustStores) {
        try {
            Get-ChildItem "Cert:\LocalMachine\$storeName" -ErrorAction Stop |
                Where-Object { $_.Thumbprint -eq $ExpectedSignerThumbprint } |
                Remove-Item -Force -ErrorAction Stop
            $residualTrust = Get-ChildItem "Cert:\LocalMachine\$storeName" -ErrorAction Stop |
                Where-Object { $_.Thumbprint -eq $ExpectedSignerThumbprint }
            if ($residualTrust) {
                throw "temporary signer remains in $storeName after cleanup"
            }
        } catch {
            $trustCleanupFailures += "${storeName}: $($_.Exception.Message)"
        }
    }
    try {
        if (Test-Path -LiteralPath $inputStageRoot) {
            Remove-Item -LiteralPath $inputStageRoot -Recurse -Force -ErrorAction Stop
        }
    } catch {
        $inputCleanupFailures += $_.Exception.Message
    }
}
if ($installFailure -or $trustCleanupFailures.Count -ne 0 -or
    $inputCleanupFailures.Count -ne 0) {
    Remove-Item -LiteralPath $stagedBinary, $backupBinary -Force -ErrorAction SilentlyContinue
    $primaryFailures = @()
    if ($installFailure) {
        $primaryFailures += $installFailure.Exception.Message
    }
    if ($trustCleanupFailures.Count -ne 0) {
        $primaryFailures += "temporary trust cleanup: $($trustCleanupFailures -join '; ')"
    }
    if ($inputCleanupFailures.Count -ne 0) {
        $primaryFailures += "protected input cleanup: $($inputCleanupFailures -join '; ')"
    }
    $cleanupFailures = @()
    if ($runtimeGenerationCreated) {
        try {
            Remove-Item -LiteralPath $runtimeGeneration -Recurse -Force -ErrorAction Stop
            $runtimeGenerationCreated = $false
        } catch {
            $cleanupFailures += "runtime generation: $($_.Exception.Message)"
        }
    }
    if ($identityGenerationCreated) {
        try {
            Remove-Item -LiteralPath $identityGeneration -Recurse -Force -ErrorAction Stop
            $identityGenerationCreated = $false
        } catch {
            $cleanupFailures += "installed identity: $($_.Exception.Message)"
        }
    }
    if ($packageRootCreated) {
        try {
            Remove-Item -LiteralPath $PackageRoot -Force -ErrorAction Stop
            $packageRootCreated = $false
        } catch {
            $cleanupFailures += "new package root: $($_.Exception.Message)"
        }
    }
    if ($cleanupFailures.Count -ne 0) {
        throw "installer failed: $($primaryFailures -join '; '); cleanup failed: $($cleanupFailures -join '; ')"
    }
    throw "installer failed: $($primaryFailures -join '; ')"
}

$serviceCommand = '"{0}" service' -f $binary
$serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$existingServiceConfig = $null
$existingServiceWasRunning = $false
$previousServicePath = $null
$previousServiceStart = $null
$previousDelayedAutoStartExists = $false
$previousDelayedAutoStart = $null
$previousEnvironmentExists = $false
$previousEnvironment = $null
$binaryExisted = $false
$newServiceCreated = $false
$registrationChanged = $false
$binaryReplaced = $false
$priorStateCaptured = $false
$serviceMutationStarted = $false
$delayedAutoStartWritten = $false
$environmentWritten = $false
$journalEpochBefore = [uint64]0
$priorRuntime = $null
$priorJournal = $null
$priorWorkspace = $null
$priorPackageRoot = $null
$priorIdentityGeneration = $null
$priorAgentPrivateKey = $null
try {
@'
@echo off
echo cmd-%~1
echo cmd-stderr 1>&2
'@ | Set-Content -Encoding ascii (Join-Path $scripts "mode.cmd")
@'
param([string]$Value)
Write-Output "ps-$Value"
[Console]::Error.WriteLine("ps-stderr")
'@ | Set-Content -Encoding utf8 (Join-Path $scripts "mode.ps1")
@'
$child = Start-Process powershell.exe -PassThru -ArgumentList @(
  '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 120'
)
Write-Output "child_pid=$($child.Id)"
[Console]::Out.Flush()
Wait-Process -Id $child.Id
'@ | Set-Content -Encoding utf8 (Join-Path $scripts "cancel-tree.ps1")
@'
param([uint32]$ProcessId)
if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) {
  Write-Error "escaped process $ProcessId remains alive"
  exit 1
}
Write-Output "process-gone"
'@ | Set-Content -Encoding utf8 (Join-Path $scripts "verify-gone.ps1")
@'
param([string]$Name)
$pidPath = Join-Path $PSScriptRoot "$Name.pid"
if (Test-Path -LiteralPath $pidPath) {
  Write-Output "retry-after-$Name"
  exit 0
}
$child = Start-Process powershell.exe -PassThru -ArgumentList @(
  '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 300'
)
$child.Id | Set-Content -Encoding ascii $pidPath
Write-Output "first-child-$Name=$($child.Id)"
[Console]::Out.Flush()
Wait-Process -Id $child.Id
'@ | Set-Content -Encoding utf8 (Join-Path $scripts "recovery.ps1")
@'
param([string]$Name)
$pidPath = Join-Path $PSScriptRoot "$Name.pid"
if (-not (Test-Path -LiteralPath $pidPath)) {
  Write-Error "missing recovery PID for $Name"
  exit 1
}
$processId = [uint32](Get-Content -Raw -LiteralPath $pidPath)
if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
  Write-Error "escaped recovery process $processId remains alive"
  exit 1
}
Write-Output "process-gone-$Name"
'@ | Set-Content -Encoding utf8 (Join-Path $scripts "verify-recovery.ps1")

Set-RestrictedTreeAcl $runtimeGeneration
$existingServiceConfig = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($existingServiceConfig) {
    $existingServiceWasRunning = $existingServiceConfig.State -eq "Running"
    $previousServicePath = $existingServiceConfig.PathName
    $previousServiceStart = ConvertTo-ServiceStartMode $existingServiceConfig.StartMode
    $previousDelayedAutoStartProperty = Get-ItemProperty -Path $serviceRegistryPath `
        -Name DelayedAutostart -ErrorAction SilentlyContinue
    if ($previousDelayedAutoStartProperty -and
        $previousDelayedAutoStartProperty.PSObject.Properties["DelayedAutostart"]) {
        $previousDelayedAutoStartExists = $true
        $previousDelayedAutoStart = [uint32]$previousDelayedAutoStartProperty.DelayedAutostart
    }
    $previousEnvironmentProperty = Get-ItemProperty -Path $serviceRegistryPath `
        -Name Environment -ErrorAction SilentlyContinue
    if ($previousEnvironmentProperty -and
        $previousEnvironmentProperty.PSObject.Properties["Environment"]) {
        $previousEnvironmentExists = $true
        $previousEnvironment = @($previousEnvironmentProperty.Environment)
    }
    if (-not $previousEnvironmentExists) {
        throw "existing service has no runtime environment to migrate"
    }
    $previousEnvironmentMap = @{}
    foreach ($entry in $previousEnvironment) {
        $separator = $entry.IndexOf('=')
        if ($separator -le 0) {
            throw "existing service has an invalid environment entry"
        }
        $name = $entry.Substring(0, $separator)
        if ($previousEnvironmentMap.ContainsKey($name)) {
            throw "existing service has a duplicate environment entry: $name"
        }
        $previousEnvironmentMap[$name] = $entry.Substring($separator + 1)
    }
    foreach ($requiredName in @(
        'MCLOVING_AGENT_JOURNAL_PATH',
        'MCLOVING_AGENT_WORKSPACE_ROOT',
        'MCLOVING_CONTROLLER_CA_PATH',
        'MCLOVING_AGENT_CERTIFICATE_PATH',
        'MCLOVING_AGENT_PRIVATE_KEY_PATH'
    )) {
        if (-not $previousEnvironmentMap.ContainsKey($requiredName) -or
            [string]::IsNullOrWhiteSpace($previousEnvironmentMap[$requiredName])) {
            throw "existing service is missing protected runtime path $requiredName"
        }
    }
    $priorJournal = [IO.Path]::GetFullPath(
        $previousEnvironmentMap.MCLOVING_AGENT_JOURNAL_PATH
    )
    $priorWorkspace = [IO.Path]::GetFullPath(
        $previousEnvironmentMap.MCLOVING_AGENT_WORKSPACE_ROOT
    )
    $priorControllerCa = [IO.Path]::GetFullPath(
        $previousEnvironmentMap.MCLOVING_CONTROLLER_CA_PATH
    )
    $priorAgentCertificate = [IO.Path]::GetFullPath(
        $previousEnvironmentMap.MCLOVING_AGENT_CERTIFICATE_PATH
    )
    $priorAgentPrivateKey = [IO.Path]::GetFullPath(
        $previousEnvironmentMap.MCLOVING_AGENT_PRIVATE_KEY_PATH
    )
    $priorRuntime = Split-Path -Parent $priorJournal
    $priorPackageRoot = Split-Path -Parent $priorRuntime
    $priorIdentityGeneration = Split-Path -Parent $priorAgentPrivateKey
    if ((Split-Path -Leaf $priorJournal) -ine 'agent.db' -or
        (Split-Path -Parent $priorWorkspace) -ine $priorRuntime -or
        (Split-Path -Leaf $priorWorkspace) -ine 'workspaces' -or
        (Split-Path -Leaf $priorControllerCa) -ine 'ca.pem' -or
        (Split-Path -Leaf $priorAgentCertificate) -ine 'agent.pem' -or
        (Split-Path -Leaf $priorAgentPrivateKey) -ine 'agent-key.pem' -or
        (Split-Path -Parent $priorControllerCa) -ine $priorIdentityGeneration -or
        (Split-Path -Parent $priorAgentCertificate) -ine $priorIdentityGeneration -or
        (Split-Path -Parent $priorIdentityGeneration) -ine $priorPackageRoot -or
        (Split-Path -Leaf $priorIdentityGeneration) -inotlike 'identity-*' -or
        $priorRuntime -ieq $GateRoot -or
        $priorRuntime -ieq $runtimeGeneration -or
        $priorPackageRoot -ieq $PackageRoot -or
        $priorPackageRoot -ieq $GateRoot) {
        throw "existing service runtime layout cannot be safely migrated"
    }
    Assert-NonReplaceableDirectoryChain $priorPackageRoot
    Assert-RestrictedTreeAcl $priorPackageRoot
    foreach ($priorIdentityFile in @(
        $priorControllerCa,
        $priorAgentCertificate,
        $priorAgentPrivateKey
    )) {
        [void](Get-RegularFileSha256 $priorIdentityFile)
    }
    [void](Get-JournalObservation $stagedBinary $priorJournal)
    $priorStateCaptured = $true
}
$binaryExisted = Test-Path -LiteralPath $binary -PathType Leaf
    if ($existingServiceConfig) {
        $existingService = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($existingService.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            $serviceMutationStarted = $true
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $existingService.WaitForStatus(
                [ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(30)
            )
        }
        $existingService.Dispose()
    }
    if ($existingServiceConfig) {
        $priorObservation = Get-JournalObservation $stagedBinary $priorJournal
        Copy-Item -LiteralPath $priorJournal -Destination $journal -ErrorAction Stop
        $priorWal = "${priorJournal}-wal"
        if (Test-Path -LiteralPath $priorWal -PathType Leaf) {
            Copy-Item -LiteralPath $priorWal -Destination "${journal}-wal" -ErrorAction Stop
        }
        foreach ($priorWorkspaceChild in @(
            Get-ChildItem -LiteralPath $priorWorkspace -Force -ErrorAction Stop
        )) {
            Copy-Item -LiteralPath $priorWorkspaceChild.FullName `
                -Destination $workspace -Recurse -ErrorAction Stop
        }
        Set-RestrictedTreeAcl $runtimeGeneration
        $migratedObservation = Get-JournalObservation $stagedBinary $journal
        if ($migratedObservation.SchemaVersion -ne $priorObservation.SchemaVersion -or
            $migratedObservation.SessionEpoch -ne $priorObservation.SessionEpoch -or
            $migratedObservation.ActiveAttempts -ne $priorObservation.ActiveAttempts) {
            throw "migrated journal observation does not match stopped prior runtime"
        }
    }
    if (Test-Path -LiteralPath $journal) {
        $journalBefore = Get-JournalObservation $stagedBinary $journal
        $journalEpochBefore = $journalBefore.SessionEpoch
    } elseif ((Test-Path -LiteralPath "${journal}-wal") -or
        (Test-Path -LiteralPath "${journal}-shm")) {
        throw "agent journal sidecars exist without the primary journal"
    }
    $serviceMutationStarted = $true
    if ($binaryExisted) {
        Copy-Item -LiteralPath $binary -Destination $backupBinary -Force
    }
    $binaryReplaced = $true
    Install-StagedBinary $stagedBinary $binary
    $committedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()
    if ($committedHash -ne $ExpectedBinarySha256.ToLowerInvariant()) {
        throw "committed binary hash mismatch: $committedHash"
    }
    Set-RestrictedTreeAcl $PackageRoot

    if ($existingServiceConfig) {
        $registrationChanged = $true
        $change = Invoke-CimMethod -InputObject $existingServiceConfig -MethodName Change `
            -Arguments @{ PathName = $serviceCommand; StartMode = "Automatic" }
        if ($change.ReturnValue -ne 0) {
            throw "service reconfiguration failed: $($change.ReturnValue)"
        }
        $delayedAutoStartWritten = $true
        New-ItemProperty -Path $serviceRegistryPath -Name DelayedAutostart `
            -PropertyType DWord -Value 0 -Force | Out-Null
    } else {
        New-Service -Name $ServiceName -BinaryPathName $serviceCommand -StartupType Automatic |
            Out-Null
        # Rollback owns the service only after this invocation successfully
        # created it.  A racing third-party registration must never be deleted.
        $newServiceCreated = $true
    }
    $environment = @(
        "MCLOVING_AGENT_ID=$agentId",
        "MCLOVING_AGENT_TRUST_POOL=$trustPool",
        "MCLOVING_AGENT_ORGANIZATION_ID=$organizationId",
        "MCLOVING_CONTROLLER_URI=$controllerUri",
        "MCLOVING_CONTROLLER_DNS_NAME=$controllerDnsName",
        "MCLOVING_CONTROLLER_CA_PATH=$controllerCaPath",
        "MCLOVING_AGENT_CERTIFICATE_PATH=$agentCertificatePath",
        "MCLOVING_AGENT_PRIVATE_KEY_PATH=$agentPrivateKeyPath",
        "MCLOVING_AGENT_JOURNAL_PATH=$journal",
        "MCLOVING_AGENT_WORKSPACE_ROOT=$workspace",
        "MCLOVING_AGENT_SESSION_RECEIPT_PATH=$sessionReceipt",
        "MCLOVING_AGENT_LEASE_SECONDS=5",
        "MCLOVING_AGENT_POLL_MILLISECONDS=50",
        "MCLOVING_AGENT_RENEW_MILLISECONDS=500",
        "MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS=250"
    )
    $environmentWritten = $true
    New-ItemProperty -Path $serviceRegistryPath `
        -Name Environment -PropertyType MultiString -Value $environment -Force | Out-Null
    Start-Service -Name $ServiceName
    $service = Get-Service -Name $ServiceName
    $service.WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(30)
    )
    # SCM can transiently report Running before the production worker opens its
    # durable state. Observe until this exact start both advances fenced
    # authority and publishes the receipt that is written only after the
    # controller accepts the authenticated open-session RPC. Never initialize
    # or migrate the journal from the installer health path.
    $journalDeadline = (Get-Date).AddSeconds(30)
    $journalStarted = $false
    $journalFailure = "journal did not appear"
    try {
        do {
            $service.Refresh()
            if ($service.Status -ne "Running") {
                throw "persistent agent service stopped before journal startup completed"
            }
            if (Test-Path -LiteralPath $journal) {
                try {
                    $journalAfter = Get-JournalObservation $binary $journal
                    if ($journalAfter.SchemaVersion -eq 2 -and
                        $journalAfter.SessionEpoch -gt $journalEpochBefore) {
                        if (Test-Path -LiteralPath $sessionReceipt -PathType Leaf) {
                            $receipt = (Get-Content -Raw -LiteralPath $sessionReceipt).Trim()
                            if ($receipt -match '^session_epoch=(\d+)$' -and
                                [uint64]$Matches[1] -eq $journalAfter.SessionEpoch) {
                                $journalStarted = $true
                                break
                            }
                            $journalFailure = "authenticated session receipt does not match journal epoch: receipt=$receipt epoch=$($journalAfter.SessionEpoch)"
                        } else {
                            $journalFailure = "authenticated session receipt did not appear for epoch $($journalAfter.SessionEpoch)"
                        }
                    } else {
                        $journalFailure = "epoch did not advance: before=$journalEpochBefore after=$($journalAfter.SessionEpoch) schema=$($journalAfter.SchemaVersion)"
                    }
                } catch {
                    $journalFailure = $_.Exception.Message
                }
            }
            Start-Sleep -Milliseconds 250
        } while ((Get-Date) -lt $journalDeadline)
        if (-not $journalStarted) {
            throw "persistent agent journal startup check failed: $journalFailure"
        }
    } finally {
        $service.Dispose()
    }

    # This assertion remains part of the rollback-protected transaction. The
    # predecessor package must stay intact until the new service has committed
    # so rollback can still restore its binary, identity, and runtime.
    Assert-RestrictedTreeAcl $runtimeGeneration
} catch {
    $serviceInstallFailure = $_
    $serviceRollbackFailures = @()
    $binaryRestored = -not $binaryReplaced
    try {
        if ($serviceMutationStarted) {
            $rollbackService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($rollbackService -and
                $rollbackService.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                $rollbackService.WaitForStatus(
                    [ServiceProcess.ServiceControllerStatus]::Stopped,
                    [TimeSpan]::FromSeconds(30)
                )
            }
            if ($rollbackService) { $rollbackService.Dispose() }
        }
    } catch {
        $serviceRollbackFailures += "stop: $($_.Exception.Message)"
    }
    if ($newServiceCreated) {
        try {
            if (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'") {
                & sc.exe delete $ServiceName | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "service deletion failed: $LASTEXITCODE" }
            }
            $deleted = $false
            for ($attempt = 0; $attempt -lt 60; $attempt++) {
                if (-not (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'")) {
                    $deleted = $true
                    break
                }
                Start-Sleep -Milliseconds 500
            }
            if (-not $deleted) { throw "new service remained after rollback timeout" }
        } catch {
            $serviceRollbackFailures += "delete: $($_.Exception.Message)"
        }
    }
    if ($binaryReplaced) {
        try {
            Restore-PreviousBinary $binary $backupBinary $binaryExisted
            $binaryRestored = $true
        } catch {
            $serviceRollbackFailures += "binary: $($_.Exception.Message)"
        }
    }
    if ($existingServiceConfig -and $priorStateCaptured) {
        try {
            if ($registrationChanged) {
                $restore = Invoke-CimMethod -InputObject $existingServiceConfig -MethodName Change `
                    -Arguments @{
                        PathName = $previousServicePath
                        StartMode = $previousServiceStart
                    }
                if ($restore.ReturnValue -ne 0) {
                    throw "prior service reconfiguration failed: $($restore.ReturnValue)"
                }
            }
            if ($delayedAutoStartWritten) {
                if ($previousDelayedAutoStartExists) {
                    New-ItemProperty -Path $serviceRegistryPath -Name DelayedAutostart `
                        -PropertyType DWord -Value $previousDelayedAutoStart -Force | Out-Null
                } else {
                    Remove-ItemProperty -Path $serviceRegistryPath -Name DelayedAutostart `
                        -ErrorAction SilentlyContinue
                }
            }
            if ($environmentWritten) {
                if ($previousEnvironmentExists) {
                    New-ItemProperty -Path $serviceRegistryPath -Name Environment `
                        -PropertyType MultiString -Value $previousEnvironment -Force | Out-Null
                } else {
                    Remove-ItemProperty -Path $serviceRegistryPath -Name Environment `
                        -ErrorAction SilentlyContinue
                }
            }
            if ($existingServiceWasRunning -and $serviceMutationStarted) {
                if (-not $binaryRestored) {
                    throw "prior running service cannot be restarted without its restored binary"
                }
                Start-Service -Name $ServiceName -ErrorAction Stop
                $restoredService = Get-Service -Name $ServiceName -ErrorAction Stop
                $restoredService.WaitForStatus(
                    [ServiceProcess.ServiceControllerStatus]::Running,
                    [TimeSpan]::FromSeconds(30)
                )
                $restoredService.Dispose()
            }
        } catch {
            $serviceRollbackFailures += "restore: $($_.Exception.Message)"
        }
    }
    if ($identityGenerationCreated) {
        try {
            Remove-Item -LiteralPath $identityGeneration -Recurse -Force -ErrorAction Stop
            $identityGenerationCreated = $false
        } catch {
            $serviceRollbackFailures += "identity: $($_.Exception.Message)"
        }
    }
    if ($runtimeGenerationCreated) {
        try {
            Remove-Item -LiteralPath $runtimeGeneration -Recurse -Force -ErrorAction Stop
            $runtimeGenerationCreated = $false
        } catch {
            $serviceRollbackFailures += "runtime: $($_.Exception.Message)"
        }
    }
    Remove-Item -LiteralPath $stagedBinary -Force -ErrorAction SilentlyContinue
    $retainedBackup = $null
    if ($binaryRestored) {
        Remove-Item -LiteralPath $backupBinary -Force -ErrorAction SilentlyContinue
    } elseif (Test-Path -LiteralPath $backupBinary -PathType Leaf) {
        $retainedBackup = $backupBinary
    }
    if ($packageRootCreated -and $serviceRollbackFailures.Count -eq 0) {
        try {
            Remove-Item -LiteralPath $PackageRoot -Force -ErrorAction Stop
            $packageRootCreated = $false
        } catch {
            $serviceRollbackFailures += "new package root: $($_.Exception.Message)"
        }
    }
    if ($serviceRollbackFailures.Count -ne 0) {
        $retainedBackupDiagnostic = if ($retainedBackup) {
            "; prior binary retained at $retainedBackup"
        } else { "" }
        throw "service installation failed: $($serviceInstallFailure.Exception.Message); service rollback failed: $($serviceRollbackFailures -join '; ')$retainedBackupDiagnostic"
    }
    throw $serviceInstallFailure
}

# The replacement transaction has committed. Recheck that SCM points only at
# the fresh package, revoke the predecessor private key first, then remove its
# now-unreferenced package tree. Cleanup cannot run earlier because rollback
# requires the complete predecessor identity and runtime.
if ($priorPackageRoot) {
    $committedService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($null -eq $committedService -or $committedService.State -ne 'Running' -or
        $committedService.PathName -ine $serviceCommand) {
        throw "replacement committed without the expected running service binding"
    }
    $committedEnvironment = @(
        (Get-ItemProperty -Path $serviceRegistryPath -Name Environment `
            -ErrorAction Stop).Environment
    )
    foreach ($priorPath in @($priorPackageRoot, $priorIdentityGeneration, $priorRuntime)) {
        if (@($committedEnvironment | Where-Object {
            if ($_ -notlike "*=*") {
                return $false
            }
            $candidate = $_.Substring($_.IndexOf('=') + 1)
            if (-not [IO.Path]::IsPathRooted($candidate)) {
                return $false
            }
            $candidate = [IO.Path]::GetFullPath($candidate).TrimEnd('\', '/')
            $predecessor = [IO.Path]::GetFullPath($priorPath).TrimEnd('\', '/')
            $candidate.Equals($predecessor, [StringComparison]::OrdinalIgnoreCase) -or
                $candidate.StartsWith(
                    "$predecessor\",
                    [StringComparison]::OrdinalIgnoreCase
                )
        }).Count -ne 0) {
            throw "committed service still references predecessor path: $priorPath"
        }
    }
    Assert-NonReplaceableDirectoryChain $priorPackageRoot
    Assert-RestrictedTreeAcl $priorPackageRoot
    Remove-Item -LiteralPath $priorAgentPrivateKey -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $priorAgentPrivateKey) {
        throw "superseded agent private key remained after revocation"
    }
    Remove-Item -LiteralPath $priorPackageRoot -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $priorPackageRoot) {
        throw "superseded package root remained after committed replacement"
    }
}
Remove-Item -LiteralPath $stagedBinary, $backupBinary -Force -ErrorAction SilentlyContinue
$binaryHash = (Get-FileHash -Algorithm SHA256 $binary).Hash.ToLowerInvariant()
Write-Output "persistent-agent-started service=$ServiceName binary_sha256=$binaryHash"
