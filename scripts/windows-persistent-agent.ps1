param(
    [string]$GateRoot = "C:\McLoving-Windows-War\win002",
    [string]$ServiceName = "McLovingWin002"
)
$ErrorActionPreference = "Stop"
$binarySource = "C:\McLoving-Windows-Work\target-win001-20260803\release\mcloving-agent.exe"
$packageRoot = "C:\Program Files\McLoving\win002"
$binary = Join-Path $packageRoot "mcloving-agent.exe"
$config = Get-Content -Raw (Join-Path $GateRoot "agent-config.json") | ConvertFrom-Json
$scripts = Join-Path $GateRoot "scripts"
$journal = Join-Path $GateRoot "agent.db"
$workspace = Join-Path $GateRoot "workspaces"

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Milliseconds 500
}
New-Item -ItemType Directory -Force -Path $packageRoot, $scripts, $workspace | Out-Null
Copy-Item -Force $binarySource $binary

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

& icacls.exe $GateRoot /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "workspace ACL setup failed: $LASTEXITCODE" }

$serviceCommand = '"{0}" service' -f $binary
New-Service -Name $ServiceName -BinaryPathName $serviceCommand -StartupType Automatic | Out-Null
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
$binaryHash = (Get-FileHash -Algorithm SHA256 $binary).Hash.ToLowerInvariant()
Write-Output "win002-agent-started service=$ServiceName binary_sha256=$binaryHash"
