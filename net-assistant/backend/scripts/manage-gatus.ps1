param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Build", "Validate", "Run", "Status")]
    [string]$Action,
    [string]$Plan
)
$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$python = Join-Path $root ".venv/Scripts/python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    $python = [IO.Path]::GetFullPath((Join-Path $root "../../.runtime/venv/Scripts/python.exe"))
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        $python = [IO.Path]::GetFullPath((Join-Path $root "../../.runtime/python/python.exe"))
    }
}
$binary = Join-Path $root "tools/gatus/bin/gatus.exe"
if ($Action -eq "Build") {
    if (Test-Path -LiteralPath $binary) {
        throw "Project Gatus already exists. Refusing to overwrite a potentially used binary."
    }
    # Process-local settings only; never go env -w, driver installation or service changes.
    $settings = @{
        GOPATH=(Join-Path $root "tools/gatus/cache/go")
        GOCACHE=(Join-Path $root "tools/gatus/cache/build")
        GOBIN=(Join-Path $root "tools/gatus/bin")
        GOTOOLCHAIN="go1.26.11"
        GOPROXY="https://goproxy.cn"
        GOSUMDB="sum.golang.org"
        GONOSUMDB=""
        HTTP_PROXY=""; HTTPS_PROXY=""; ALL_PROXY=""
    }
    $previous = @{}
    try {
        foreach ($name in $settings.Keys) {
            $previous[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
            [Environment]::SetEnvironmentVariable($name, $settings[$name], "Process")
        }
        & go install "github.com/TwiN/gatus/v5@v5.38.0"
        if ($LASTEXITCODE -ne 0) { throw "Pinned Gatus build failed." }
        $license = Join-Path $settings.GOPATH "pkg/mod/github.com/!twi!n/gatus/v5@v5.38.0/LICENSE"
        Copy-Item -LiteralPath $license -Destination (Join-Path $settings.GOBIN "Gatus-LICENSE")
        Get-FileHash -Algorithm SHA256 -LiteralPath $binary
    } finally {
        foreach ($name in $previous.Keys) {
            [Environment]::SetEnvironmentVariable($name, $previous[$name], "Process")
        }
    }
    exit 0
}
if (-not $Plan) { throw "Validate/Run/Status require an explicit -Plan JSON path." }
$planPath = (Resolve-Path -LiteralPath $Plan).Path
Push-Location -LiteralPath $root
try {
    & $python -m app.monitoring.cli $Action.ToLowerInvariant() --config $planPath
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $code
