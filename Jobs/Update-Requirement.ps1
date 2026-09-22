<#
.SYNOPSIS
    Resolves requirements.in into a pinned requirements.txt using uv.

.DESCRIPTION
    Runs `uv pip compile` against -RequirementsInPath, applying the cooldown
    (-MinimumPackageAgeDays) and target Python version, and writes the result to
    -RequirementsTxtPath. Does not touch the central wheelhouse - this only
    prepares the local file for review before Update-WheelHouse merges it in.

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
    Requires functions.ps1 in the same folder as this script, and config\settings.psd1
    one level up (<manager root>\config\settings.psd1).
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$RequirementsInPath,

    [string]$RequirementsTxtPath,

    [string]$PythonVersion,

    [int]$MinimumPackageAgeDays
)

$commonPath = Join-Path $PSScriptRoot "functions.ps1"
if (-not (Test-Path -Path $commonPath)) {
    Write-Host "Required file not found: $commonPath" -ForegroundColor Red
    exit 1
}
. $commonPath

$managerRoot = Split-Path -Path $PSScriptRoot -Parent
$settingsPath = Join-Path $managerRoot "config\settings.psd1"
$settings = Get-WheelhouseSettings -SettingsPath $settingsPath

$RequirementsInPath = Resolve-Setting -Name "RequirementsInPath" -ExplicitValue $RequirementsInPath `
    -WasBound $PSBoundParameters.ContainsKey('RequirementsInPath') -Settings $settings `
    -FallbackDefault (Join-Path $managerRoot "Input\requirements.in")
$RequirementsTxtPath = Resolve-Setting -Name "LocalRequirementsPath" -ExplicitValue $RequirementsTxtPath `
    -WasBound $PSBoundParameters.ContainsKey('RequirementsTxtPath') -Settings $settings `
    -FallbackDefault (Join-Path $managerRoot "Input\requirements.txt")
$PythonVersion = Resolve-Setting -Name "PythonVersion" -ExplicitValue $PythonVersion `
    -WasBound $PSBoundParameters.ContainsKey('PythonVersion') -Settings $settings -FallbackDefault "3.14"
$MinimumPackageAgeDays = Resolve-Setting -Name "MinimumPackageAgeDays" -ExplicitValue $MinimumPackageAgeDays `
    -WasBound $PSBoundParameters.ContainsKey('MinimumPackageAgeDays') -Settings $settings -FallbackDefault 10

Write-Log "=== Update-Requirement started ==="
Write-Log "Source (requirements.in): $RequirementsInPath"
Write-Log "Target (requirements.txt): $RequirementsTxtPath"
Write-Log "Target Python: $PythonVersion | Cooldown: $MinimumPackageAgeDays day(s)"

if (-not (Test-Path -Path $RequirementsInPath)) {
    Write-Log "requirements.in not found: $RequirementsInPath" "ERROR"
    Write-Log "Run Setup.ps1 first, or pass -RequirementsInPath explicitly." "ERROR"
    exit 1
}

$compileArgs = @(
    "pip", "compile", $RequirementsInPath,
    "--exclude-newer", "$MinimumPackageAgeDays days",
    "--python", $PythonVersion,
    "-o", $RequirementsTxtPath
)

& uv @compileArgs

if ($LASTEXITCODE -eq 0) {
    Write-Log "requirements.txt written successfully: $RequirementsTxtPath" "OK"
    Write-Log "Review it, get it approved, then run Update-WheelHouse to merge it into the central wheelhouse."
}
else {
    Write-Log "uv pip compile FAILED (exit code $LASTEXITCODE). Review the output above." "ERROR"
    exit 1
}

Write-Log "=== Update-Requirement finished ==="
