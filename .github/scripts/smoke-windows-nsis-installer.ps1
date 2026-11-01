param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath
)

$ErrorActionPreference = 'Stop'
$productName = 'Ghost FIDO Key'
$applicationName = 'ghost-fido-desktop.exe'
$uninstallRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'

function Get-ProductUninstallEntries {
    Get-ChildItem -LiteralPath $uninstallRoot -ErrorAction SilentlyContinue |
        ForEach-Object {
            $entry = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if ($entry.DisplayName -eq $productName) {
                [pscustomobject]@{
                    KeyPath = $_.PSPath
                    UninstallString = [string]$entry.UninstallString
                }
            }
        }
}

function Invoke-Installer([string]$Path, [string[]]$Arguments, [string]$Action) {
    $process = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru
    if (-not $process.WaitForExit(120000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "$Action did not finish within 120 seconds: $Path"
    }
    $process.Refresh()
    if ($process.ExitCode -ne 0) {
        throw "$Action failed with exit code $($process.ExitCode): $Path"
    }
}

function Wait-ForState([scriptblock]$Condition, [bool]$Expected, [string]$Description) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $actual = [bool](& $Condition)
        if ($actual -eq $Expected) {
            return
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for $Description to become $Expected."
}

$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$entriesBefore = @(Get-ProductUninstallEntries)
if ($entriesBefore.Count -ne 0) {
    throw "Expected a clean runner, but found $($entriesBefore.Count) existing $productName uninstall entries."
}

$uninstallPath = $null
try {
    Write-Host "Installing per-user NSIS package: $installer"
    Invoke-Installer -Path $installer -Arguments @('/S') -Action 'Silent installation'

    Wait-ForState -Expected $true -Description 'the per-user uninstall registry entry' -Condition {
        @(Get-ProductUninstallEntries).Count -eq 1
    }

    $entry = @(Get-ProductUninstallEntries)
    if ($entry.Count -ne 1 -or [string]::IsNullOrWhiteSpace($entry[0].UninstallString)) {
        throw "Expected one $productName uninstall entry with an uninstall command."
    }
    if ($entry[0].UninstallString -notmatch '^\s*"(?<path>[^"]+\.exe)"') {
        throw "Could not parse the registered uninstall command: $($entry[0].UninstallString)"
    }

    $uninstallPath = $Matches.path
    $installDirectory = Split-Path -Parent $uninstallPath
    $applicationPath = Join-Path $installDirectory $applicationName
    if (-not (Test-Path -LiteralPath $uninstallPath -PathType Leaf)) {
        throw "Registered uninstaller does not exist: $uninstallPath"
    }
    if (-not (Test-Path -LiteralPath $applicationPath -PathType Leaf)) {
        throw "Installed desktop executable does not exist: $applicationPath"
    }
    Write-Host "Verified installed executable: $applicationPath"

    Write-Host "Removing per-user installation with its registered uninstaller."
    Invoke-Installer -Path $uninstallPath -Arguments @('/S') -Action 'Silent uninstallation'

    Wait-ForState -Expected $false -Description 'the per-user uninstall registry entry' -Condition {
        @(Get-ProductUninstallEntries).Count -gt 0
    }
    Wait-ForState -Expected $false -Description 'the installed desktop executable' -Condition {
        Test-Path -LiteralPath $applicationPath -PathType Leaf
    }
    Wait-ForState -Expected $false -Description 'the installed application directory' -Condition {
        Test-Path -LiteralPath $installDirectory -PathType Container
    }
    if (Test-Path -LiteralPath $uninstallPath -PathType Leaf) {
        throw "Uninstaller remained after removal: $uninstallPath"
    }

    Write-Host 'Windows NSIS install/remove smoke check passed.'
}
finally {
    $remaining = @(Get-ProductUninstallEntries)
    if ($remaining.Count -eq 1 -and $remaining[0].UninstallString -match '^\s*"(?<path>[^"]+\.exe)"') {
        $cleanupUninstaller = $Matches.path
        if (Test-Path -LiteralPath $cleanupUninstaller -PathType Leaf) {
            try {
                Invoke-Installer -Path $cleanupUninstaller -Arguments @('/S') -Action 'Cleanup uninstallation'
            }
            catch {
                Write-Error "Cleanup failed; per-user installation may remain: $_"
            }
        }
    }
}
