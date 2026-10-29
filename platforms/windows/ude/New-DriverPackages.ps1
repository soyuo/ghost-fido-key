$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$driverRoot = Join-Path $repositoryRoot 'target\windows-ude'
$packageRoot = Join-Path $driverRoot 'packages'
$sdkRoot = $env:WindowsSdkDir

if ([string]::IsNullOrWhiteSpace($sdkRoot)) {
    $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
}

$inf2catCandidates = Get-ChildItem -LiteralPath (Join-Path $sdkRoot 'bin') -Filter 'Inf2Cat.exe' -File -Recurse -ErrorAction SilentlyContinue
$inf2cat = $inf2catCandidates |
    Where-Object { $_.Directory.Name -eq 'x64' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if ($null -eq $inf2cat) {
    $inf2cat = $inf2catCandidates | Sort-Object FullName -Descending | Select-Object -First 1
}

if ($null -eq $inf2cat) {
    throw "Inf2Cat.exe was not found under the Windows SDK bin directory '$sdkRoot\bin'."
}

$architectures = @(
    @{ Name = 'x64'; Platform = 'x64'; Os = '10_GE_X64,10_25H2_X64' },
    @{ Name = 'ARM64'; Platform = 'ARM64'; Os = '10_GE_ARM64,10_25H2_ARM64' }
)

foreach ($architecture in $architectures) {
    $driver = Join-Path $driverRoot (Join-Path $architecture.Platform 'Release\GhostFidoUde.sys')
    if (-not (Test-Path -LiteralPath $driver -PathType Leaf)) {
        throw "The $($architecture.Name) driver build did not produce '$driver'."
    }

    $package = Join-Path $packageRoot $architecture.Name.ToLowerInvariant()
    New-Item -ItemType Directory -Path $package -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'GhostFidoUde.inf') -Destination $package -Force
    Copy-Item -LiteralPath $driver -Destination (Join-Path $package 'GhostFidoUde.sys') -Force

    & $inf2cat.FullName "/driver:$package" "/os:$($architecture.Os)" /verbose
    if ($LASTEXITCODE -ne 0) {
        throw "Inf2Cat failed for the $($architecture.Name) package with exit code $LASTEXITCODE."
    }

    $catalog = if ($architecture.Platform -eq 'x64') {
        Join-Path $package 'GhostFidoUde-x64.cat'
    } else {
        Join-Path $package 'GhostFidoUde-arm64.cat'
    }
    foreach ($artifact in @(
        (Join-Path $package 'GhostFidoUde.inf'),
        (Join-Path $package 'GhostFidoUde.sys'),
        $catalog
    )) {
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
            throw "The $($architecture.Name) package is missing expected artifact '$artifact'."
        }
    }

    Write-Host "Created unsigned $($architecture.Name) package at $package"
}
