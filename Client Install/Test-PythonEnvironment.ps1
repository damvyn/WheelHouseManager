<#
.SYNOPSIS
    Checks a Python environment against the wheelhouse's advisories: is anything installed
    that has since been found vulnerable, yanked, quarantined or removed?

.DESCRIPTION
    Optional, for users and support staff on client computers. It works offline: it reads
    advisories.json from the wheelhouse share (written by Wheelhouse Manager whenever the
    package catalog changes) and the list of installed packages of one environment, and
    lists every installed version the advisories mention, with what to install instead.

    The wheelhouse is found from the machine-wide uv configuration
    (%PROGRAMDATA%\uv\uv.toml, written by Startup_UV.ps1), unless -AdvisoriesPath is given.
    Installed packages are read with "uv pip list" (or "python -m pip list" when uv is
    missing) for the environment of -Python; by default the .venv in -Project (the current
    folder), otherwise the python on PATH.

    Exit codes: 0 nothing affected; 1 affected packages found; 2 the check could not run.

.PARAMETER Project
    Folder whose .venv to check (default: the current folder).

.PARAMETER Python
    python.exe of the environment to check (overrides -Project).

.PARAMETER AdvisoriesPath
    advisories.json to use (default: next to the wheelhouse configured in uv.toml).

.PARAMETER InstalledJson
    A file with the installed packages as JSON ([{"name": ..., "version": ...}]) instead of
    asking uv or pip - for an environment on another computer.

.EXAMPLE
    .\Test-PythonEnvironment.ps1

.EXAMPLE
    .\Test-PythonEnvironment.ps1 -Project C:\Work\analysis
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$Project = (Get-Location).Path,

    [string]$Python,

    [string]$AdvisoriesPath,

    [string]$InstalledJson
)

function Get-NormalizedName {
    param([string]$Name)
    return ($Name.ToLowerInvariant() -replace '[-_.]+', '-')
}

function Get-WheelhouseFromUvConfig {
    # The flat index url Startup_UV.ps1 writes into the machine-wide uv.toml.
    $config = Join-Path $env:PROGRAMDATA 'uv\uv.toml'
    if (-not (Test-Path -LiteralPath $config)) { return $null }
    foreach ($line in (Get-Content -LiteralPath $config)) {
        if ($line -match '^\s*url\s*=\s*"(?<url>.*)"\s*$') {
            # TOML basic string: \\ is one backslash.
            return ($Matches['url'] -replace '\\\\', '\')
        }
    }
    return $null
}

try {
    # Advisories.
    if (-not $AdvisoriesPath) {
        $wheelhouse = Get-WheelhouseFromUvConfig
        if (-not $wheelhouse) { throw "The wheelhouse is not configured on this computer ($env:PROGRAMDATA\uv\uv.toml). Pass -AdvisoriesPath." }
        $AdvisoriesPath = Join-Path $wheelhouse 'advisories.json'
    }
    if (-not (Test-Path -LiteralPath $AdvisoriesPath)) { throw "advisories.json was not found: $AdvisoriesPath (the wheelhouse manager has not written one yet, or the share is not reachable)." }
    $advisories = Get-Content -LiteralPath $AdvisoriesPath -Raw | ConvertFrom-Json
    $byKey = @{}
    foreach ($item in @($advisories.packages)) {
        if ($item) { $byKey["$(Get-NormalizedName $item.name)==$($item.version)"] = $item }
    }

    # Installed packages.
    if ($InstalledJson) {
        $raw = Get-Content -LiteralPath $InstalledJson -Raw
        $source = $InstalledJson
    }
    else {
        if (-not $Python) {
            $venvPython = Join-Path $Project '.venv\Scripts\python.exe'
            $Python = if (Test-Path -LiteralPath $venvPython) { $venvPython } else { 'python' }
        }
        $uv = Get-Command uv -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($uv) {
            $raw = (& $uv.Source pip list --format json --python $Python 2>$null) -join "`n"
            $source = "uv pip list --python $Python"
        }
        else {
            $raw = (& $Python -m pip list --format json 2>$null) -join "`n"
            $source = "$Python -m pip list"
        }
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) { throw "The installed packages could not be listed ($source)." }
    }
    # foreach, not @(): Windows PowerShell 5.1 emits a JSON array as one object.
    $installed = @(foreach ($item in ($raw | ConvertFrom-Json)) { $item })

    $affected = @(foreach ($package in $installed) {
            $match = $byKey["$(Get-NormalizedName $package.name)==$($package.version)"]
            if (-not $match) { continue }
            $worst = @($match.advisories) | Sort-Object { switch ($_.severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 1 } } } | Select-Object -First 1
            [PSCustomObject]@{
                Package     = $package.name
                Version     = $package.version
                Status      = $match.status
                Severity    = $(if ($worst) { $worst.severity } else { '' })
                Advisories  = (@($match.advisories) | ForEach-Object { $_.id }) -join ', '
                InstallInstead = $(if ($match.recommended) { "$($package.name)==$($match.recommended)" } else { '' })
                Reason      = $match.reason
            }
        })

    Write-Host "Checked $($installed.Count) installed package(s) ($source) against $AdvisoriesPath (generated $($advisories.generated_utc))."
    if ($affected.Count -eq 0) {
        Write-Host 'Nothing installed is affected.' -ForegroundColor Green
        exit 0
    }
    Write-Host "$($affected.Count) installed package(s) need attention:" -ForegroundColor Yellow
    foreach ($item in $affected) {
        $color = if ($item.Status -in 'overdue', 'quarantined', 'removed') { 'Red' } else { 'Yellow' }
        Write-Host ("  {0}=={1}  {2}{3}" -f $item.Package, $item.Version, $item.Status.ToUpperInvariant(), $(if ($item.Severity) { " ($($item.Severity))" } else { '' })) -ForegroundColor $color
        if ($item.Advisories) { Write-Host "      advisories: $($item.Advisories)" }
        if ($item.InstallInstead) { Write-Host "      install instead: uv pip install $($item.InstallInstead)" }
        elseif ($item.Reason) { Write-Host "      $($item.Reason)" }
    }
    Write-Host 'A quarantined or removed version can no longer be installed from the wheelhouse; upgrade it as shown, or ask the wheelhouse administrators.'
    exit 1
}
catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 2
}
