<#
.SYNOPSIS
    Resolves requirements.in into a pinned requirements.txt using uv.

.DESCRIPTION
    Runs `uv pip compile` against -RequirementsInPath, applying the cooldown
    (-MinimumPackageAgeDays) and target Python version, and writes the result to
    -RequirementsTxtPath. Does not touch the central wheelhouse - this only
    prepares the local file for review before Update-Wheelhouse.ps1 merges it in.

    If called with no path parameters, both default to the Input\ folder next to
    this script's deployment (WheelHouseManager\Input\requirements.in / .txt) -
    the same files Setup.ps1 creates.

.PARAMETER RequirementsInPath
    Source file to resolve (default: <manager root>\Input\requirements.in).

.PARAMETER RequirementsTxtPath
    Where to write the resolved, pinned file (default: <manager root>\Input\requirements.txt).

.PARAMETER PythonVersion
    Target Python version (major.minor). Defaults to the value in config\settings.psd1,
    falling back to 3.14 if that's not set either.

.PARAMETER MinimumPackageAgeDays
    Cooldown window passed to `uv pip compile --exclude-newer`. Defaults to the value
    in config\settings.psd1, falling back to 10 if that's not set either.

.EXAMPLE
    .\Update-Requirement.ps1

.EXAMPLE
    .\Update-Requirement.ps1 -RequirementsInPath "C:\temp\requirements.in" -RequirementsTxtPath "C:\temp\requirements.txt"

.NOTES
    Requires the WheelhouseManager module folder next to this script, and config\settings.psd1
    one level up (<manager root>\config\settings.psd1).
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$RequirementsInPath,

    [ValidateNotNullOrEmpty()]
    [string]$RequirementsTxtPath,

    [ValidateNotNullOrEmpty()]
    [string]$PythonVersion,

    [ValidateRange(0, 3650)]
    [int]$MinimumPackageAgeDays
)

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$cfg = Resolve-WheelhouseParameter -BoundParameters $PSBoundParameters `
    -Name RequirementsInPath, RequirementsTxtPath, PythonVersion, MinimumPackageAgeDays `
    -SettingName @{ RequirementsTxtPath = 'LocalRequirementsPath' }

Write-Log "=== Update-Requirement started ==="
Write-Log "Source (requirements.in): $($cfg.RequirementsInPath)"
Write-Log "Target (requirements.txt): $($cfg.RequirementsTxtPath)"
Write-Log "Target Python: $($cfg.PythonVersion) | Cooldown: $($cfg.MinimumPackageAgeDays) day(s)"

if (-not (Test-Path -Path $cfg.RequirementsInPath)) {
    Write-Log "requirements.in not found: $($cfg.RequirementsInPath)" "ERROR"
    Write-Log "Run Setup.ps1 first, or pass -RequirementsInPath explicitly." "ERROR"
    exit 1
}

$compileArgs = @(
    "pip", "compile", $cfg.RequirementsInPath,
    "--exclude-newer", "$($cfg.MinimumPackageAgeDays) days",
    "--python", $cfg.PythonVersion,
    "-o", $cfg.RequirementsTxtPath
)

& uv @compileArgs

if ($LASTEXITCODE -ne 0) {
    Write-Log "uv pip compile FAILED (exit code $LASTEXITCODE). Review the output above." "ERROR"
    exit 1
}

Write-Log "requirements.txt written successfully: $($cfg.RequirementsTxtPath)" "OK"
Write-Log "Review it, get it approved, then run Update-Wheelhouse.ps1 to merge it into the central wheelhouse."
Write-Log "=== Update-Requirement finished ==="
exit 0
