param(
    [ValidateSet("Preview", "Install", "Status", "Start", "Stop", "Remove")]
    [string]$Action = "Status",
    [string]$ConfigPath = "",
    [ValidatePattern("^[A-Za-z][A-Za-z0-9_-]{2,60}$")]
    [string]$ServiceName = "NetAssistant-Discovery"
)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$defaultConfig = Join-Path $root "configs\daily-scan.local.json"
if (-not $ConfigPath) { $ConfigPath = $defaultConfig }
if ($Action -in @("Preview", "Install")) {
    $ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
} else {
    # Broken/deleted application configuration must not block stopping/removing SCM registration.
    $ConfigPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigPath)
}
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    if ($Action -eq "Install") {
        throw "SCM deployment requires a dedicated backend .venv; the collaboration runtime is for preview/development only."
    }
    $python = [IO.Path]::GetFullPath((Join-Path $root "..\..\.runtime\venv\Scripts\python.exe"))
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        $python = [IO.Path]::GetFullPath((Join-Path $root "..\..\.runtime\python\python.exe"))
    }
}
$bootstrap = Join-Path $root "scripts\service-bootstrap.py"
$marker = "NetAssistant native discovery service; managed by manage-discovery-service.ps1."
$account = "NT SERVICE\$ServiceName"
$existing = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"

function Assert-InProject([string]$Path) {
    $absolute = [IO.Path]::GetFullPath($Path)
    if (-not $absolute.StartsWith($root + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Service configuration and writable data must stay inside this project: $absolute"
    }
}
function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installation/management command in an administrator PowerShell."
    }
}
function Invoke-SC([string[]]$Arguments) {
    $message = & "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($message -join "`n") }
}
function Grant-Path([string]$Path, [string]$Rights) {
    $message = & "$env:SystemRoot\System32\icacls.exe" $Path /grant "${account}:$Rights" 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($message -join "`n") }
}
function Invoke-ProjectPython([string[]]$Arguments) {
    Push-Location -LiteralPath $root
    try { & $python @Arguments } finally { Pop-Location }
}

if ($Action -in @("Preview", "Install")) {
    if ($Action -eq "Install") { Assert-InProject $ConfigPath }
    Push-Location -LiteralPath $root
    try {
        $raw = & $python -m app.scheduling.cli validate --config $ConfigPath
        if ($LASTEXITCODE -ne 0) { throw "Project schedule validation failed; no service installed." }
        $validation = ($raw -join "`n") | ConvertFrom-Json
        $basePython = (& $python -c "import sys; print(sys._base_executable)").Trim()
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $basePython -PathType Leaf)) {
            throw "Cannot locate the base Python interpreter."
        }
    } finally { Pop-Location }
    $plan = $validation.plan
    if ($Action -eq "Install") {
        Assert-InProject $plan.scan_config
        Assert-InProject $plan.database
        Assert-InProject $plan.report_directory
    }
    # -I -S avoids user-site/global site initialization; bootstrap adds only this venv.
    $command = '"' + $basePython + '" -I -S "' + $bootstrap + '" service --name "' +
               $ServiceName + '" --config "' + $ConfigPath + '"'
    $preview = [ordered]@{
        name = $ServiceName; command = $command; account = $account
        startup = "Automatic"; requiresUserLogin = $false; configValidated = $true
        registrationMethod = "Win32_Service.Create"
        database = $plan.database; reportDirectory = $plan.report_directory
        recovery = "restart after 10/30/60 seconds, then stop; reset after 1 day"
        configChanges = "Restart service after editing configuration"
        legacyTaskCutover = ($ServiceName -eq "NetAssistant-Discovery" -and $ConfigPath -eq $defaultConfig)
    }
    if ($Action -eq "Preview") { $preview | ConvertTo-Json -Depth 5; return }
}

# Never take over or delete another application's service.
if ($existing -and $Action -ne "Status") {
    if ($existing.Description -ne $marker -or
        $existing.PathName.IndexOf('"' + $bootstrap + '"', [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Refusing to change a service not owned by this project."
    }
}

switch ($Action) {
    "Install" {
        Assert-Admin
        if ($existing) { throw "Service already exists. Use Status/Start; Stop and Remove before reinstalling." }
        $oldTask = $null
        $oldWasEnabled = $false
        $cutover = $preview.legacyTaskCutover
        if ($cutover) {
            $oldTask = Get-ScheduledTask -TaskName "NetAssistant-DailyDiscovery" -ErrorAction SilentlyContinue
            if ($oldTask) {
                if ($oldTask.Description -ne "NetAssistant project daily discovery. Managed by manage-daily-scan.ps1." -or
                    $oldTask.Actions.WorkingDirectory -ne $root) {
                    throw "Legacy task is not owned by this project; resolve it before cutover."
                }
                if ($oldTask.State -eq "Running") { throw "Legacy scan is running. Wait for it to finish before cutover." }
                $oldWasEnabled = $oldTask.State -ne "Disabled"
            }
        }
        $created = $false
        $installStarted = [DateTimeOffset]::UtcNow
        try {
            # CIM passes PathName as a string, without PowerShell 5 native-argument
            # re-quoting (which otherwise breaks paths containing spaces).
            $creation = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
                Name = $ServiceName; DisplayName = $ServiceName; PathName = $command
                ServiceType = [byte]16; ErrorControl = [byte]1; StartMode = "Automatic"
                StartName = $account
            }
            if ($creation.ReturnValue -ne 0) { throw "CreateService failed: $($creation.ReturnValue)" }
            $created = $true
            Invoke-SC @("description", $ServiceName, $marker)
            Invoke-SC @("sidtype", $ServiceName, "unrestricted")
            # No administrator/System token. Read source/dependencies; modify only data/reports.
            Grant-Path $root "(OI)(CI)RX"
            foreach ($directory in @((Split-Path -Parent $plan.database), $plan.report_directory)) {
                Assert-InProject $directory
                New-Item -ItemType Directory -Force -Path $directory | Out-Null
                Grant-Path $directory "(OI)(CI)M"
            }
            Invoke-SC @("failure", $ServiceName, "reset=", "86400",
                        "actions=", "restart/10000/restart/30000/restart/60000/none/0")
            Invoke-SC @("failureflag", $ServiceName, "1")
            $service = Start-Service -Name $ServiceName -PassThru
            $service.WaitForStatus("Running", (New-TimeSpan -Seconds 20))
            # A SCM Running flag alone is insufficient: verify this config's heartbeat.
            $ready = $false
            for ($attempt = 0; $attempt -lt 20; $attempt++) {
                Start-Sleep -Milliseconds 500
                $rawState = Invoke-ProjectPython @("-c", "import json,sys; from pathlib import Path; from app.scheduling.config import load_plan; from app.scheduling.runtime import read_runtime; print(json.dumps(read_runtime(load_plan(Path(sys.argv[1])))))", $ConfigPath)
                if ($LASTEXITCODE -eq 0) {
                    $runtime = ($rawState -join "`n") | ConvertFrom-Json
                    if ($runtime.state -in @("running", "checking") -and
                        [DateTimeOffset]::Parse($runtime.startedAt) -ge $installStarted) {
                        $ready = $true; break
                    }
                }
            }
            if (-not $ready) { throw "Service did not produce a new valid heartbeat; legacy task unchanged." }
            if ($oldTask -and $oldWasEnabled) {
                Disable-ScheduledTask -TaskName $oldTask.TaskName | Out-Null
            }
        } catch {
            if ($created) {
                Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
                & "$env:SystemRoot\System32\sc.exe" delete $ServiceName | Out-Null
            }
            if ($oldTask -and $oldWasEnabled) {
                Enable-ScheduledTask -TaskName $oldTask.TaskName | Out-Null
            }
            throw
        }
    }
    "Start" { Assert-Admin; Start-Service -Name $ServiceName }
    "Stop" {
        Assert-Admin
        $service = Get-Service -Name $ServiceName
        Stop-Service -Name $ServiceName
        $service.WaitForStatus("Stopped", (New-TimeSpan -Seconds 25))
    }
    "Remove" {
        Assert-Admin
        if ($existing) {
            if ($existing.State -ne "Stopped") { throw "Stop the service before removing it." }
            Invoke-SC @("delete", $ServiceName)
        }
        # Keep databases, reports and ACL evidence. Never implicitly enable the legacy task.
    }
}
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if (-not $service) {
    [ordered]@{ name = $ServiceName; installed = $false } | ConvertTo-Json
} else {
    [ordered]@{
        name = $ServiceName; installed = $true; state = $service.State
        startup = $service.StartMode; account = $service.StartName
        processId = $service.ProcessId; exitCode = $service.ExitCode
        command = $service.PathName; requiresUserLogin = $false
    } | ConvertTo-Json -Depth 5
}
