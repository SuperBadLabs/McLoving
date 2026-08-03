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
            throw "restricted ACL replacement verification failed: $($item.FullName)"
        }
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

$binary = Join-Path $packageRoot "mcloving-agent.exe"
$stagedBinary = Join-Path $packageRoot "mcloving-agent.installing.exe"
$backupBinary = Join-Path $packageRoot "mcloving-agent.rollback.exe"
$configPath = Join-Path $GateRoot "agent-config.json"
$configSource = Get-Content -Raw -LiteralPath $configPath
$config = $configSource | ConvertFrom-Json
$agentId = Get-RequiredConfigString $config "agent_id"
$trustPool = Get-RequiredConfigString $config "trust_pool"
$organizationId = Get-RequiredConfigString $config "organization_id"
$controllerUri = Get-RequiredConfigString $config "controller_uri"
$controllerDnsName = Get-RequiredConfigString $config "controller_dns_name"
$scripts = Join-Path $GateRoot "scripts"
$journal = Join-Path $GateRoot "agent.db"
$workspace = Join-Path $GateRoot "workspaces"
$controllerCaPath = Join-Path $GateRoot "ca.pem"
$agentCertificatePath = Join-Path $GateRoot "agent.pem"
$agentPrivateKeyPath = Join-Path $GateRoot "agent-key.pem"

$validationEnvironment = @{
    MCLOVING_AGENT_ID = $agentId
    MCLOVING_AGENT_TRUST_POOL = $trustPool
    MCLOVING_AGENT_ORGANIZATION_ID = $organizationId
    MCLOVING_CONTROLLER_URI = $controllerUri
    MCLOVING_CONTROLLER_DNS_NAME = $controllerDnsName
    MCLOVING_CONTROLLER_CA_PATH = $controllerCaPath
    MCLOVING_AGENT_CERTIFICATE_PATH = $agentCertificatePath
    MCLOVING_AGENT_PRIVATE_KEY_PATH = $agentPrivateKeyPath
    MCLOVING_AGENT_JOURNAL_PATH = $journal
    MCLOVING_AGENT_WORKSPACE_ROOT = $workspace
    MCLOVING_AGENT_LEASE_SECONDS = "5"
    MCLOVING_AGENT_POLL_MILLISECONDS = "50"
    MCLOVING_AGENT_RENEW_MILLISECONDS = "500"
    MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS = "250"
}
$inputStageRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ("mcloving-install-inputs-" + [Guid]::NewGuid().ToString("N"))
$protectedBinarySource = Join-Path $inputStageRoot "mcloving-agent.exe"
$protectedSignerCertificateSource = Join-Path $inputStageRoot "signer.cer"
$temporaryTrustStores = @()
$installFailure = $null
$trustCleanupFailures = @()
$inputCleanupFailures = @()
try {
    # BinarySource and SignerCertificateSource may be supplied from a location
    # writable by a non-administrator.  Copy both into a fresh protected tree,
    # then authenticate only those immutable copies before executing/importing.
    # The directory is protected before any child is created, so copied files
    # inherit the SYSTEM/Administrators-only boundary immediately.
    New-Item -ItemType Directory -Path $inputStageRoot -ErrorAction Stop | Out-Null
    Set-RestrictedTreeAcl $inputStageRoot
    Copy-Item -LiteralPath $BinarySource -Destination $protectedBinarySource -ErrorAction Stop
    if ($SignerCertificateSource) {
        Copy-Item -LiteralPath $SignerCertificateSource `
            -Destination $protectedSignerCertificateSource -ErrorAction Stop
    }
    Set-RestrictedTreeAcl $inputStageRoot

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

    New-Item -ItemType Directory -Force -Path $PackageRoot | Out-Null
    Set-RestrictedTreeAcl $PackageRoot
    Set-RestrictedTreeAcl $GateRoot
    $restrictedConfigSource = Get-Content -Raw -LiteralPath $configPath
    if ($restrictedConfigSource -cne $configSource) {
        throw "agent configuration changed while the gate ACL was being restricted"
    }

    New-Item -ItemType Directory -Force -Path $scripts, $workspace | Out-Null
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
if ($installFailure) {
    Remove-Item -LiteralPath $stagedBinary, $backupBinary -Force -ErrorAction SilentlyContinue
    $cleanupFailures = @()
    if ($trustCleanupFailures.Count -ne 0) {
        $cleanupFailures += "temporary trust: $($trustCleanupFailures -join '; ')"
    }
    if ($inputCleanupFailures.Count -ne 0) {
        $cleanupFailures += "protected inputs: $($inputCleanupFailures -join '; ')"
    }
    if ($cleanupFailures.Count -ne 0) {
        throw "installer failed: $($installFailure.Exception.Message); cleanup failed: $($cleanupFailures -join '; ')"
    }
    throw $installFailure
}
if ($trustCleanupFailures.Count -ne 0) {
    throw "temporary trust cleanup failed: $($trustCleanupFailures -join '; ')"
}
if ($inputCleanupFailures.Count -ne 0) {
    throw "protected input cleanup failed: $($inputCleanupFailures -join '; ')"
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

Set-RestrictedTreeAcl $GateRoot
$serviceCommand = '"{0}" service' -f $binary
$serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$existingServiceConfig = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
$existingServiceWasRunning = $false
$previousServicePath = $null
$previousServiceStart = $null
$previousDelayedAutoStartExists = $false
$previousDelayedAutoStart = $null
$previousEnvironmentExists = $false
$previousEnvironment = $null
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
}
$binaryExisted = Test-Path -LiteralPath $binary -PathType Leaf
$newServiceCreated = $false
$registrationChanged = $false
$binaryReplaced = $false
try {
    if ($existingServiceConfig) {
        $existingService = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($existingService.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $existingService.WaitForStatus(
                [ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(30)
            )
        }
        $existingService.Dispose()
    }
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
        "MCLOVING_AGENT_LEASE_SECONDS=5",
        "MCLOVING_AGENT_POLL_MILLISECONDS=50",
        "MCLOVING_AGENT_RENEW_MILLISECONDS=500",
        "MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS=250"
    )
    New-ItemProperty -Path $serviceRegistryPath `
        -Name Environment -PropertyType MultiString -Value $environment -Force | Out-Null
    Start-Service -Name $ServiceName
    $service = Get-Service -Name $ServiceName
    $service.WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(30)
    )
    # SCM can transiently report Running before the async production worker
    # discovers a fatal local startup error and terminates the service process.
    Start-Sleep -Seconds 2
    $service.Refresh()
    if ($service.Status -ne "Running") { throw "persistent agent service did not start" }
    $service.Dispose()
} catch {
    $serviceInstallFailure = $_
    $serviceRollbackFailures = @()
    $binaryRestored = -not $binaryReplaced
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
    if ($existingServiceConfig) {
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
            if ($previousDelayedAutoStartExists) {
                New-ItemProperty -Path $serviceRegistryPath -Name DelayedAutostart `
                    -PropertyType DWord -Value $previousDelayedAutoStart -Force | Out-Null
            } else {
                Remove-ItemProperty -Path $serviceRegistryPath -Name DelayedAutostart `
                    -ErrorAction SilentlyContinue
            }
            if ($previousEnvironmentExists) {
                New-ItemProperty -Path $serviceRegistryPath -Name Environment `
                    -PropertyType MultiString -Value $previousEnvironment -Force | Out-Null
            } else {
                Remove-ItemProperty -Path $serviceRegistryPath -Name Environment `
                    -ErrorAction SilentlyContinue
            }
            if ($existingServiceWasRunning) {
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
    Remove-Item -LiteralPath $stagedBinary, $backupBinary -Force -ErrorAction SilentlyContinue
    if ($serviceRollbackFailures.Count -ne 0) {
        throw "service installation failed: $($serviceInstallFailure.Exception.Message); service rollback failed: $($serviceRollbackFailures -join '; ')"
    }
    throw $serviceInstallFailure
}
Remove-Item -LiteralPath $stagedBinary, $backupBinary -Force -ErrorAction SilentlyContinue
$binaryHash = (Get-FileHash -Algorithm SHA256 $binary).Hash.ToLowerInvariant()
Write-Output "persistent-agent-started service=$ServiceName binary_sha256=$binaryHash"
