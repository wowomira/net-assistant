param(
    [ValidateSet('setup','init','doctor','check','start','serve','test','create-user','seed-check','seed-import','import-nmap')]
    [string]$Command = 'setup',
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments
)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Runtime = Join-Path $Root '.runtime'
$Resources = Join-Path $Runtime 'resources'
$Lock = Get-Content -LiteralPath (Join-Path $Root 'runtime.lock.json') -Raw | ConvertFrom-Json
$Python = Join-Path $Runtime 'python/python.exe'
foreach ($LocalPath in @($Runtime, $Resources, (Join-Path $Runtime 'python'))) {
    if ((Test-Path -LiteralPath $LocalPath) -and
        ((Get-Item -LiteralPath $LocalPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Runtime junctions/symlinks are not supported; use a real project-local directory.'
    }
}

function Assert-Hash([string]$Path, [string]$Expected) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing resource: $Path" }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
        throw "Checksum mismatch: $Path"
    }
}

function Expand-SafeZip([string]$Archive, [string]$Destination) {
    if (Test-Path -LiteralPath $Destination) { throw "Destination already exists: $Destination" }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        foreach ($Entry in $Zip.Entries) {
            $Name = $Entry.FullName.Replace('\','/')
            if ($Name.StartsWith('/') -or $Name.Contains(':') -or ($Name.Split('/') -contains '..') -or
                (($Entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) {
                throw "Unsafe archive path"
            }
        }
    } finally { $Zip.Dispose() }
    [IO.Compression.ZipFile]::ExtractToDirectory($Archive, $Destination)
}

if (![Environment]::Is64BitOperatingSystem -or ![Environment]::Is64BitProcess) {
    throw 'Use Windows x64 and 64-bit PowerShell.'
}
if ($Command -eq 'setup') {
    New-Item -ItemType Directory -Path $Runtime -Force | Out-Null
    if (!(Test-Path -LiteralPath (Join-Path $Resources 'manifest.json'))) {
        throw 'Download the repository Release asset named in runtime.lock.json, verify its SHA256, and extract .runtime/resources into this checkout. See README.md.'
    }
    Assert-Hash (Join-Path $Resources 'manifest.json') $Lock.resource_manifest_sha256
    Assert-Hash (Join-Path $Resources 'python.zip') $Lock.artifacts.'python.zip'.sha256
    if (!(Test-Path -LiteralPath $Python)) {
        $Stage = Join-Path $Runtime ('python-staging-' + [guid]::NewGuid().ToString('N'))
        Expand-SafeZip (Join-Path $Resources 'python.zip') $Stage
        Move-Item -LiteralPath $Stage -Destination (Join-Path $Runtime 'python')
    }
    $Pth = Join-Path $Runtime 'python/python313._pth'
    @('python313.zip','.','Lib/site-packages','../../scripts','../../net-assistant/backend','import site') |
        Set-Content -LiteralPath $Pth -Encoding ASCII
    & $Python (Join-Path $Root 'scripts/runtime_support.py')
} else {
    if (!(Test-Path -LiteralPath (Join-Path $Runtime 'portable-ready.json'))) {
        throw 'Run bootstrap.ps1 setup first.'
    }
    & $Python (Join-Path $Root 'scripts/workspace.py') $Command @Arguments
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
