param(
    [string]$GateRoot = "C:\McLoving-Windows-War\win002",
    [string]$ServiceName = "McLovingWin002",
    [string]$BinarySource = "C:\McLoving-Windows-Work\target-win001-20260803\release\mcloving-agent.exe",
    [string]$PackageRoot = "C:\Program Files\McLoving\win002",
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{64}$")]
    [string]$ExpectedBinarySha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{40}$")]
    [string]$ExpectedSignerThumbprint,
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

function Set-RestrictedTreeAcl([string]$Root) {
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "gate root must be an existing non-reparse directory"
    }
    Set-Acl -LiteralPath $rootItem.FullName -AclObject (New-RestrictedAcl $true)
    $items = @(Get-ChildItem -LiteralPath $rootItem.FullName -Force -Recurse -ErrorAction Stop)
    foreach ($item in $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "gate tree contains a reparse point: $($item.FullName)"
        }
        Set-Acl -LiteralPath $item.FullName -AclObject (New-RestrictedAcl $item.PSIsContainer)
    }
    foreach ($item in @($rootItem) + $items) {
        $applied = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $rules = @($applied.GetAccessRules(
            $true,
            $false,
            [Security.Principal.SecurityIdentifier]
        ))
        $unexpected = @($rules | Where-Object {
            $_.IdentityReference.Value -notin @("S-1-5-18", "S-1-5-32-544") -or
            $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl
        })
        if (-not $applied.AreAccessRulesProtected -or $rules.Count -ne 2 -or $unexpected.Count -ne 0) {
            throw "gate ACL replacement verification failed: $($item.FullName)"
        }
    }
}

Set-RestrictedTreeAcl $GateRoot
$binary = Join-Path $packageRoot "mcloving-agent.exe"
$config = Get-Content -Raw (Join-Path $GateRoot "agent-config.json") | ConvertFrom-Json
$scripts = Join-Path $GateRoot "scripts"
$journal = Join-Path $GateRoot "agent.db"
$workspace = Join-Path $GateRoot "workspaces"

$temporaryTrustStores = @()
$installFailure = $null
$trustCleanupFailures = @()
try {
    if ($SignerCertificateSource) {
        $signerCertificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($SignerCertificateSource)
        if ($signerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
            throw "signer certificate thumbprint mismatch"
        }
        foreach ($storeName in @("Root", "TrustedPublisher")) {
            $alreadyTrusted = Get-ChildItem "Cert:\LocalMachine\$storeName" |
                Where-Object { $_.Thumbprint -eq $ExpectedSignerThumbprint }
            if (-not $alreadyTrusted) {
                # Record cleanup responsibility before import so even a partially
                # successful provider operation is removed by the finally block.
                $temporaryTrustStores += $storeName
                Import-Certificate -FilePath $SignerCertificateSource `
                    -CertStoreLocation "Cert:\LocalMachine\$storeName" | Out-Null
            }
        }
    }

    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $BinarySource).Hash.ToLowerInvariant()
    if ($sourceHash -ne $ExpectedBinarySha256.ToLowerInvariant()) {
        throw "package binary hash mismatch: $sourceHash"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $BinarySource
    if ($signature.Status -ne "Valid") {
        throw "package Authenticode status is $($signature.Status)"
    }
    if ($signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
        throw "package signer thumbprint mismatch"
    }

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        if ($existingService.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $existingService.WaitForStatus(
                [ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(30)
            )
        }
        & sc.exe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "service deletion failed: $LASTEXITCODE" }
        $existingService.Dispose()
        $deleted = $false
        for ($attempt = 0; $attempt -lt 60; $attempt++) {
            if (-not (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'")) {
                $deleted = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $deleted) { throw "prior service remained after deletion timeout" }
    }
    New-Item -ItemType Directory -Force -Path $packageRoot, $scripts, $workspace | Out-Null
    Copy-Item -LiteralPath $BinarySource -Destination $binary -Force
    $installedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()
    if ($installedHash -ne $ExpectedBinarySha256.ToLowerInvariant()) {
        throw "installed binary hash mismatch: $installedHash"
    }
    $installedSignature = Get-AuthenticodeSignature -LiteralPath $binary
    if ($installedSignature.Status -ne "Valid" -or
        $installedSignature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
        throw "installed binary Authenticode validation failed"
    }
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
}
if ($installFailure) {
    if ($trustCleanupFailures.Count -ne 0) {
        throw "installer failed: $($installFailure.Exception.Message); temporary trust cleanup failed: $($trustCleanupFailures -join '; ')"
    }
    throw $installFailure
}
if ($trustCleanupFailures.Count -ne 0) {
    throw "temporary trust cleanup failed: $($trustCleanupFailures -join '; ')"
}

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

$serviceCommand = '"{0}" service' -f $binary
$newServiceCreated = $false
try {
    New-Service -Name $ServiceName -BinaryPathName $serviceCommand -StartupType Automatic | Out-Null
    $newServiceCreated = $true
    $environment = @(
        "MCLOVING_AGENT_ID=$($config.agent_id)",
        "MCLOVING_AGENT_TRUST_POOL=$($config.trust_pool)",
        "MCLOVING_AGENT_ORGANIZATION_ID=$($config.organization_id)",
        "MCLOVING_CONTROLLER_URI=$($config.controller_uri)",
        "MCLOVING_CONTROLLER_DNS_NAME=$($config.controller_dns_name)",
        "MCLOVING_CONTROLLER_CA_PATH=$(Join-Path $GateRoot 'ca.pem')",
        "MCLOVING_AGENT_CERTIFICATE_PATH=$(Join-Path $GateRoot 'agent.pem')",
        "MCLOVING_AGENT_PRIVATE_KEY_PATH=$(Join-Path $GateRoot 'agent-key.pem')",
        "MCLOVING_AGENT_JOURNAL_PATH=$journal",
        "MCLOVING_AGENT_WORKSPACE_ROOT=$workspace",
        "MCLOVING_AGENT_LEASE_SECONDS=5",
        "MCLOVING_AGENT_POLL_MILLISECONDS=50",
        "MCLOVING_AGENT_RENEW_MILLISECONDS=500",
        "MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS=250"
    )
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" `
        -Name Environment -PropertyType MultiString -Value $environment -Force | Out-Null
    Start-Service -Name $ServiceName
    $service = Get-Service -Name $ServiceName
    if ($service.Status -ne "Running") { throw "persistent agent service did not start" }
} catch {
    $serviceInstallFailure = $_
    $serviceRollbackFailures = @()
    if ($newServiceCreated) {
        try {
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
        } catch {
            $serviceRollbackFailures += "stop: $($_.Exception.Message)"
        }
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
    if ($serviceRollbackFailures.Count -ne 0) {
        throw "service installation failed: $($serviceInstallFailure.Exception.Message); service rollback failed: $($serviceRollbackFailures -join '; ')"
    }
    throw $serviceInstallFailure
}
$binaryHash = (Get-FileHash -Algorithm SHA256 $binary).Hash.ToLowerInvariant()
Write-Output "persistent-agent-started service=$ServiceName binary_sha256=$binaryHash"
