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

function Write-CrashDiagnostics {
  param(
    [string]$Name,
    [string]$Root,
    [string]$Journal,
    [string]$Agent
  )
  Write-Output "windows-agent-war-diagnostics service=$Name root=$Root"
  try {
    & sc.exe queryex $Name 2>&1 | ForEach-Object { Write-Output "sc: $_" }
  }
  catch {
    Write-Output "sc-query-error: $($_.Exception.Message)"
  }
  try {
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    $processes = @(Get-CimInstance Win32_Process)
    $processIds = [System.Collections.Generic.HashSet[uint32]]::new()
    [void]$processIds.Add([uint32]$service.ProcessId)
    for ($depth = 0; $depth -lt 16; $depth++) {
      $added = $false
      foreach ($process in $processes) {
        if ($processIds.Contains([uint32]$process.ParentProcessId) -and
            $processIds.Add([uint32]$process.ProcessId)) {
          $added = $true
        }
      }
      if (-not $added) {
        break
      }
    }
    foreach ($process in $processes) {
      if ($processIds.Contains([uint32]$process.ProcessId)) {
        Write-Output (
          "process: pid=$($process.ProcessId) ppid=$($process.ParentProcessId) " +
          "name=$($process.Name) command=$($process.CommandLine)"
        )
        Get-CimInstance Win32_Thread -Filter "ProcessHandle='$($process.ProcessId)'" `
          -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Output (
              "thread: pid=$($process.ProcessId) tid=$($_.Handle) " +
              "state=$($_.ThreadState) wait_reason=$($_.ThreadWaitReason)"
            )
          }
      }
    }
  }
  catch {
    Write-Output "process-tree-error: $($_.Exception.Message)"
  }
  if (Test-Path $Journal) {
    try {
      & $Agent journal-check $Journal 2>&1 |
        ForEach-Object { Write-Output "journal: $_" }
    }
    catch {
      Write-Output "journal-check-error: $($_.Exception.Message)"
    }
  }
  if (Test-Path $Root) {
    Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue |
      ForEach-Object { Write-Output "workspace: $($_.FullName)" }
    Get-ChildItem -LiteralPath $Root -Recurse -File -Filter "*.log" `
      -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "log-begin: $($_.FullName)"
        Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue |
          ForEach-Object { Write-Output "log: $_" }
        Write-Output "log-end: $($_.FullName)"
      }
  }
  try {
    Get-WinEvent -FilterHashtable @{
      LogName = "System"
      ProviderName = "Service Control Manager"
      StartTime = (Get-Date).AddMinutes(-5)
    } -MaxEvents 12 -ErrorAction Stop |
      Select-Object TimeCreated, Id, LevelDisplayName, Message |
      Format-List | Out-String |
      ForEach-Object { Write-Output "scm-event: $_" }
  }
  catch {
    Write-Output "scm-event-error: $($_.Exception.Message)"
  }
}

$AgentBinary = (Resolve-Path $AgentBinary).Path
$temporaryRoot = if (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
  $env:RUNNER_TEMP
}
elseif (-not [string]::IsNullOrWhiteSpace($env:TEMP)) {
  $env:TEMP
}
else {
  throw "Neither RUNNER_TEMP nor TEMP names a persistent-host temporary directory"
}
$root = Join-Path $temporaryRoot "mcloving-windows-war"
$journal = Join-Path $root "agent.db"
$workspace = Join-Path $root "workspaces"
$boundaryScript = Join-Path $root "must-not-run.ps1"
$lifecycleService = "McLovingAgentLifecycleCi"
$crashService = "McLovingAgentCrashCi"
$containedService = "McLovingAgentContainedBoundaryCi"
$recordedService = "McLovingAgentRecordedBoundaryCi"

Remove-TestService $lifecycleService
Remove-TestService $crashService
Remove-TestService $containedService
Remove-TestService $recordedService
Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $root, $workspace | Out-Null

# The LocalSystem service and the CI operator are the only principals granted
# access after inherited permissions are removed. No attempt code may widen
# this boundary or traverse a reparse point.
& icacls.exe $root /inheritance:r /grant:r `
  "SYSTEM:(OI)(CI)F" "$env:USERNAME`:(OI)(CI)F" | Out-Null

try {
  $lifecyclePath = "`"$AgentBinary`" service-smoke `"$journal`""
  New-Service -Name $lifecycleService -BinaryPathName $lifecyclePath `
    -StartupType Manual | Out-Null
  Start-Service $lifecycleService
  Wait-Until {
    if (-not (Test-Path $journal)) { return $false }
    $observed = & $AgentBinary journal-check $journal 2>$null
    $LASTEXITCODE -eq 0 -and $observed -match "session_epoch=1"
  } "first durable service session epoch"
  Stop-Service $lifecycleService
  $firstHealth = & $AgentBinary journal-check $journal
  if ($LASTEXITCODE -ne 0 -or $firstHealth -notmatch "session_epoch=1") {
    throw "first service session did not reserve epoch 1: $firstHealth"
  }
  Start-Service $lifecycleService
  Wait-Until {
    $observed = & $AgentBinary journal-check $journal 2>$null
    $LASTEXITCODE -eq 0 -and $observed -match "session_epoch=2"
  } "second durable service session epoch"
  Stop-Service $lifecycleService
  $health = & $AgentBinary journal-check $journal
  if ($LASTEXITCODE -ne 0 -or
      $health -notmatch "journal_mode=wal integrity=ok" -or
      $health -notmatch "session_epoch=2" -or
      $health -notmatch "active_attempts=0") {
    throw "journal health failed after service restart: $health"
  }
  Remove-TestService $lifecycleService
  if ($null -ne (Get-Service -Name $lifecycleService -ErrorAction SilentlyContinue)) {
    throw "service uninstall left $lifecycleService registered"
  }
  Write-Output (
    "windows-agent-lifecycle-ok installed=1 starts=2 stops=2 uninstalled=1 " +
    "first_session_epoch=1 second_session_epoch=2 journal_mode=wal integrity=ok"
  )

  @'
"unexpected-resume" | Set-Content -Encoding ascii ran.txt
Start-Sleep -Seconds 300
'@ | Set-Content -Encoding utf8NoBOM $boundaryScript

  $boundaries = @(
    @{
      Name = $containedService
      Boundary = "contained-before-record"
      Journal = (Join-Path $root "contained-boundary.db")
      Marker = (Join-Path $root "contained-boundary.pid")
      Workspace = (Join-Path $workspace "service-boundary\contained-before-record")
    },
    @{
      Name = $recordedService
      Boundary = "recorded-before-resume"
      Journal = (Join-Path $root "recorded-boundary.db")
      Marker = (Join-Path $root "recorded-boundary.pid")
      Workspace = (Join-Path $workspace "service-boundary\recorded-before-resume")
    }
  )
  foreach ($boundary in $boundaries) {
    $boundaryPath = "`"$AgentBinary`" service-creation-boundary-smoke " +
      "`"$($boundary.Journal)`" `"$workspace`" `"$boundaryScript`" " +
      "`"$($boundary.Marker)`" $($boundary.Boundary)"
    New-Service -Name $boundary.Name -BinaryPathName $boundaryPath `
      -StartupType Manual | Out-Null
    Start-Service $boundary.Name
    Wait-Until { Test-Path $boundary.Marker } "$($boundary.Boundary) marker"
    $workloadPid = [int](Get-Content $boundary.Marker)
    $boundaryServicePid = [int](
      Get-CimInstance Win32_Service -Filter "Name='$($boundary.Name)'"
    ).ProcessId
    if ($workloadPid -le 0 -or $boundaryServicePid -le 0) {
      throw "$($boundary.Boundary) returned an invalid process ID"
    }
    if ($null -eq (Get-Process -Id $workloadPid -ErrorAction SilentlyContinue)) {
      throw "$($boundary.Boundary) workload disappeared before crash injection"
    }
    Stop-Process -Id $boundaryServicePid -Force
    Wait-Until {
      $null -eq (Get-Process -Id $workloadPid -ErrorAction SilentlyContinue)
    } "$($boundary.Boundary) atomic Job cleanup"
    Wait-Until {
      (Get-Service -Name $boundary.Name).Status -eq "Stopped"
    } "$($boundary.Boundary) SCM crash observation"
    if (Test-Path (Join-Path $boundary.Workspace "ran.txt")) {
      throw "$($boundary.Boundary) suspended workload ran before durable resume"
    }
    Remove-TestService $boundary.Name
  }

  # WIN-004 tests native atomic containment and durable recovery. PowerShell
  # mode is exercised separately under WIN-002 so shell startup policy cannot
  # mask a Job Object or reconciliation defect here.
  $crashPath = "`"$AgentBinary`" service-execution-smoke `"$journal`" `"$workspace`" `"$root`""
  New-Service -Name $crashService -BinaryPathName $crashPath `
    -StartupType Manual | Out-Null
  Start-Service $crashService
  $childPidPath = Join-Path $root "child.pid"
  try {
    Wait-Until { Test-Path $childPidPath } "descendant process creation"
  }
  catch {
    Write-CrashDiagnostics $crashService $root $journal $AgentBinary
    throw
  }
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

  Write-Output "windows-agent-war-ok lifecycle=2 atomic_boundaries=2 crash_cleanup=1 reconciliation=1"
}
finally {
  Remove-TestService $lifecycleService
  Remove-TestService $crashService
  Remove-TestService $containedService
  Remove-TestService $recordedService
}
