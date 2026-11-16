param(
    [ValidateSet("Preview", "Install", "Status", "Disable", "Remove")]
    [string]$Action = "Status",
    [string]$ConfigPath = "",
    [ValidatePattern("^[A-Za-z0-9_-]+$")]
    [string]$TaskName = "NetAssistant-DailyDiscovery"
)
$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if (-not $ConfigPath) { $ConfigPath = Join-Path $root "configs\daily-scan.local.json" }
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$python = Join-Path $root ".venv\Scripts\python.exe"
$pythonw = Join-Path $root ".venv\Scripts\pythonw.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    $python = [IO.Path]::GetFullPath((Join-Path $root "..\..\.runtime\venv\Scripts\python.exe"))
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        if ($Action -eq "Install") {
            throw "Scheduled-task deployment requires a dedicated backend .venv; use start.cmd for portable foreground operation."
        }
        $python = [IO.Path]::GetFullPath((Join-Path $root "..\..\.runtime\python\python.exe"))
    }
    $pythonw = Join-Path (Split-Path -Parent $python) "pythonw.exe"
}
$marker = "NetAssistant project daily discovery. Managed by manage-daily-scan.ps1."

if ($Action -in @("Preview", "Install")) {
    Push-Location -LiteralPath $root
    try {
        $raw = & $python -m app.scheduling.cli validate --config $ConfigPath
        if ($LASTEXITCODE -ne 0) { throw "Project schedule validation failed." }
        $validation = ($raw -join "`n") | ConvertFrom-Json
    } finally { Pop-Location }
    $plan = $validation.plan
    if (-not $plan.enabled) { throw "Schedule is disabled in the JSON configuration." }
    if (-not (Test-Path -LiteralPath $pythonw -PathType Leaf)) { throw "Virtualenv pythonw.exe is missing." }
    $hostOffset = [TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
    if ($hostOffset -ne $plan.utc_offset_minutes) {
        throw "Host UTC offset differs from plan. Set the host timezone or explicitly adapt the plan; no task installed."
    }
    $arguments = '-m app.scheduling.cli run-due --config "' + $ConfigPath + '"'
    $preview = [ordered]@{
        taskName = $TaskName; executable = $pythonw; arguments = $arguments
        workingDirectory = $root; dailyAt = $plan.at; utcOffsetMinutes = $plan.utc_offset_minutes
        catchUp = "At user logon, today only after due time"
        logonType = "Interactive"; overlap = "IgnoreNew plus SQLite file lock"
        executionLimitSeconds = [Math]::Max(1800, [Math]::Ceiling($validation.budgetSeconds + 300))
        enabled = $true
    }
    if ($Action -eq "Preview") { $preview | ConvertTo-Json -Depth 5; return }
}

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing -and $Action -ne "Status" -and (
    $existing.Description -ne $marker -or $existing.Actions.WorkingDirectory -ne $root
)) {
    throw "Refusing to change a task not owned by this project."
}
switch ($Action) {
    "Install" {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $taskAction = New-ScheduledTaskAction -Execute $pythonw -Argument $arguments -WorkingDirectory $root
        $at = [datetime]::Today.Add([TimeSpan]::Parse($plan.at))
        $triggers = @(
            (New-ScheduledTaskTrigger -Daily -At $at),
            (New-ScheduledTaskTrigger -AtLogOn -User $identity)
        )
        $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 10) `
            -ExecutionTimeLimit (New-TimeSpan -Seconds $preview.executionLimitSeconds)
        Register-ScheduledTask -TaskName $TaskName -Description $marker -Action $taskAction `
            -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
    }
    "Disable" {
        if (-not $existing) { throw "Task is not installed." }
        Disable-ScheduledTask -TaskName $TaskName | Out-Null
    }
    "Remove" {
        if ($existing) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
        [ordered]@{ taskName = $TaskName; installed = $false } | ConvertTo-Json
        return
    }
}
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    [ordered]@{ taskName = $TaskName; installed = $false } | ConvertTo-Json
} else {
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    [ordered]@{
        taskName = $TaskName; installed = $true; state = [string]$task.State
        lastRunTime = $info.LastRunTime.ToString("o"); lastTaskResult = $info.LastTaskResult
        nextRunTime = $info.NextRunTime.ToString("o")
        executable = $task.Actions.Execute; arguments = $task.Actions.Arguments
        workingDirectory = $task.Actions.WorkingDirectory
        logonType = [string]$task.Principal.LogonType
        triggers = @($task.Triggers | ForEach-Object {
            [ordered]@{
                type = $_.CimClass.CimClassName
                startBoundary = $_.StartBoundary
                enabled = $_.Enabled
            }
        })
    } | ConvertTo-Json -Depth 5
}
