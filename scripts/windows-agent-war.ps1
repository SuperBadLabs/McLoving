param(
  [Parameter(Mandatory = $true)]
  [string]$AgentBinary
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Wait-Until {
  param(
    [Parameter(Mandatory = $true)]
    [scriptblock]$Condition,
    [Parameter(Mandatory = $true)]
    [string]$Description,
    [int]$Attempts = 200
  )
  for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
    if (& $Condition) {
      return
    }
    Start-Sleep -Milliseconds 50
  }
  throw "Timed out waiting for $Description"
}

function Remove-TestService {
  param([string]$Name)
  $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($null -ne $service) {
    if ($service.Status -ne "Stopped") {
      Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }
    & sc.exe delete $Name | Out-Null
    Wait-Until { $null -eq (Get-Service -Name $Name -ErrorAction SilentlyContinue) } `
      "service $Name deletion"
  }
}

$AgentBinary = (Resolve-Path $AgentBinary).Path
$root = Join-Path $env:RUNNER_TEMP "mcloving-windows-war"
$journal = Join-Path $root "agent.db"
$workspace = Join-Path $root "workspaces"
$treeScript = Join-Path $root "tree.ps1"
$lifecycleService = "McLovingAgentLifecycleCi"
$crashService = "McLovingAgentCrashCi"

Remove-TestService $lifecycleService
Remove-TestService $crashService
Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $root, $workspace | Out-Null

# The service account owns its inherited workspace ACL. No attempt code may
# widen this boundary or traverse a reparse point.
& icacls.exe $root /inheritance:r /grant:r `
  "SYSTEM:(OI)(CI)F" "$env:USERNAME`:(OI)(CI)F" | Out-Null

try {
  $lifecyclePath = "`"$AgentBinary`" service-smoke `"$journal`""
  New-Service -Name $lifecycleService -BinaryPathName $lifecyclePath `
    -StartupType Manual | Out-Null
  Start-Service $lifecycleService
  Wait-Until { Test-Path $journal } "first durable journal creation"
  Stop-Service $lifecycleService
  Start-Service $lifecycleService
  Start-Sleep -Milliseconds 250
  Stop-Service $lifecycleService
  $health = & $AgentBinary journal-check $journal
  if ($LASTEXITCODE -ne 0 -or $health -notmatch "journal_mode=wal integrity=ok") {
    throw "journal health failed after service restart: $health"
  }
  Remove-TestService $lifecycleService

  @'
$child = Start-Process powershell.exe -PassThru -ArgumentList @(
  "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 300"
)
$child.Id | Set-Content -Encoding ascii child.pid
Wait-Process -Id $child.Id
'@ | Set-Content -Encoding utf8NoBOM $treeScript

  $crashPath = "`"$AgentBinary`" service-execution-smoke `"$journal`" `"$workspace`" `"$treeScript`""
  New-Service -Name $crashService -BinaryPathName $crashPath `
    -StartupType Manual | Out-Null
  Start-Service $crashService
  $childPidPath = Join-Path $workspace "service-smoke\crash-recovery\child.pid"
  Wait-Until { Test-Path $childPidPath } "descendant process creation"
  $childPid = [int](Get-Content $childPidPath)
  $servicePid = [int](Get-CimInstance Win32_Service -Filter "Name='$crashService'").ProcessId
  if ($servicePid -le 0 -or $childPid -le 0) {
    throw "service or descendant PID was invalid"
  }

  Stop-Process -Id $servicePid -Force
  Wait-Until {
    $null -eq (Get-Process -Id $childPid -ErrorAction SilentlyContinue)
  } "Job Object descendant cleanup after service crash"
  Wait-Until {
    (Get-Service -Name $crashService).Status -eq "Stopped"
  } "SCM crash observation"

  # A restart must report the durable running attempt instead of duplicating
  # execution into the existing workspace.
  Start-Service $crashService
  Start-Sleep -Milliseconds 250
  $recovered = & $AgentBinary journal-check $journal
  if ($LASTEXITCODE -ne 0 -or $recovered -notmatch "active_attempts=1") {
    throw "journal reconciliation did not expose the interrupted attempt: $recovered"
  }
  Stop-Service $crashService
  Remove-TestService $crashService

  Write-Output "windows-agent-war-ok lifecycle=2 crash_cleanup=1 reconciliation=1"
}
finally {
  Remove-TestService $lifecycleService
  Remove-TestService $crashService
}

