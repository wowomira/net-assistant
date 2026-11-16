param(
    [ValidateSet("Preview", "Install", "Status", "Start", "Stop", "Remove")]
    [string]$Action = "Status",
    [string]$ConfigPath = "",
    [ValidatePattern("^[A-Za-z][A-Za-z0-9_-]{2,60}$")]
    [string]$ServiceName = "NetAssistant-Monitoring"
)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if (-not $ConfigPath) { $ConfigPath = Join-Path $root "configs\automation.local.json" }
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
$marker = "NetAssistant integrated monitoring; managed by manage-monitoring-service.ps1."
$account = "NT SERVICE\$ServiceName"
$existing = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator PowerShell is required for service changes."
    }
}
function Assert-InProject([string]$Path) {
    $absolute = [IO.Path]::GetFullPath($Path)
    if (-not $absolute.StartsWith($root + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Installed service paths must remain inside this project: $absolute"
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
function Read-Runtime {
    Push-Location -LiteralPath $root
    try {
        $raw = & $python -m app.monitoring.automation status --config $ConfigPath
        if ($LASTEXITCODE -ne 0) { throw "Cannot read automation runtime." }
        return (($raw -join "`n") | ConvertFrom-Json)
    } finally { Pop-Location }
}

if ($Action -in @("Preview", "Install")) {
    $ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
    Push-Location -LiteralPath $root
    try {
        $raw = & $python -m app.monitoring.automation validate --config $ConfigPath
        if ($LASTEXITCODE -ne 0) { throw "Automation validation failed; service unchanged." }
        $validation = ($raw -join "`n") | ConvertFrom-Json
        $basePython = (& $python -c "import sys; print(sys._base_executable)").Trim()
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $basePython)) {
            throw "Base Python interpreter is unavailable."
        }
    } finally { Pop-Location }
    $plan = $validation.plan
    $command = '"' + $basePython + '" -I -S "' + $bootstrap +
               '" monitoring-service --name "' + $ServiceName + '" --config "' + $ConfigPath + '"'
    $preview = [ordered]@{
        name=$ServiceName; command=$command; account=$account; startup="Automatic"
        requiresUserLogin=$false; endpoints=$validation.endpoints; deviceId=$plan.device_id
        database=$plan.database; storage=$plan.storage
        collectorIntervalSeconds=$plan.collector_interval_seconds
        switchPlan=$plan.switch_plan
    }
    if ($Action -eq "Preview") { $preview | ConvertTo-Json -Depth 6; return }
}
if ($existing -and $Action -ne "Status") {
    if ($existing.Description -ne $marker -or
        $existing.PathName.IndexOf('"' + $bootstrap + '"', [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
        $existing.PathName.IndexOf("monitoring-service", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Refusing to modify a service not owned by this project."
    }
}
switch ($Action) {
    "Install" {
        Assert-Admin
        if ($existing) { throw "Service already exists; use Start or explicitly Stop/Remove it." }
        foreach ($path in @($ConfigPath, $plan.database, $plan.monitoring_plan, $plan.storage)) {
            Assert-InProject $path
        }
        if ($plan.switch_plan) { Assert-InProject $plan.switch_plan }
        $created = $false
        $startedAt = [DateTimeOffset]::UtcNow
        try {
            $creation = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
                Name=$ServiceName; DisplayName=$ServiceName; PathName=$command
                ServiceType=[byte]16; ErrorControl=[byte]1; StartMode="Automatic"; StartName=$account
            }
            if ($creation.ReturnValue -ne 0) { throw "CreateService failed: $($creation.ReturnValue)" }
            $created = $true
            Invoke-SC @("description", $ServiceName, $marker)
            Invoke-SC @("sidtype", $ServiceName, "unrestricted")
            Grant-Path $root "(OI)(CI)RX"
            foreach ($directory in @((Split-Path -Parent $plan.database), (Split-Path -Parent $plan.storage))) {
                New-Item -ItemType Directory -Force -Path $directory | Out-Null
                Grant-Path $directory "(OI)(CI)M"
            }
            Invoke-SC @("failure", $ServiceName, "reset=", "86400",
                        "actions=", "restart/10000/restart/30000/restart/60000/none/0")
            Invoke-SC @("failureflag", $ServiceName, "1")
            $service = Start-Service -Name $ServiceName -PassThru
            $service.WaitForStatus("Running", (New-TimeSpan -Seconds 30))
            $ready = $false
            for ($attempt=0; $attempt -lt 45; $attempt++) {
                Start-Sleep -Seconds 1
                $runtime = Read-Runtime
                if ($runtime.state -eq "running" -and $runtime.gatusReady -eq $true -and
                    $runtime.lastCollection.state -eq "completed" -and
                    [DateTimeOffset]::Parse($runtime.startedAt) -ge $startedAt) {
                    $ready=$true; break
                }
            }
            if (-not $ready) { throw "No fresh automation heartbeat after installation." }
        } catch {
            if ($created) {
                Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
                & "$env:SystemRoot\System32\sc.exe" delete $ServiceName | Out-Null
            }
            throw
        }
    }
    "Start" { Assert-Admin; Start-Service -Name $ServiceName }
    "Stop" {
        Assert-Admin
        $service = Get-Service -Name $ServiceName
        Stop-Service -Name $ServiceName
        $service.WaitForStatus("Stopped", (New-TimeSpan -Seconds 45))
    }
    "Remove" {
        Assert-Admin
        if ($existing) {
            if ($existing.State -ne "Stopped") { throw "Stop the service before removing it." }
            Invoke-SC @("delete", $ServiceName)
        }
        # Never remove application files, SQLite history, logs or backups.
    }
}
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if (-not $service) {
    [ordered]@{ name=$ServiceName; installed=$false } | ConvertTo-Json
} else {
    [ordered]@{
        name=$ServiceName; installed=$true; state=$service.State; startup=$service.StartMode
        account=$service.StartName; processId=$service.ProcessId; exitCode=$service.ExitCode
        requiresUserLogin=$false; command=$service.PathName
    } | ConvertTo-Json -Depth 5
}
