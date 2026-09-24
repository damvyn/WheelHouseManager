<#
.SYNOPSIS
    Resolves requirements.in into a pinned requirements.txt using uv.

.DESCRIPTION
    Runs `uv pip compile` against -RequirementsInPath, applying the cooldown
    (-MinimumPackageAgeDays), target Python version and target platform, and writes
    the result to -RequirementsTxtPath. Does not touch the central wheelhouse - this
    only prepares the local file for review before Update-Wheelhouse.ps1 merges it in.

    The resolved file must be downloadable the way Update-Wheelhouse.ps1 downloads
    it (binary wheels only, for PythonVersion / Platform):
      - uv resolves with --only-binary :all: and --python-platform, so versions that
        only exist as source archives (e.g. numpy 1.26.4 on Python 3.14) are never
        picked.
      - uv ignores upper bounds on Requires-Python (e.g. "<3.14"), so the result is
        then checked with pip (`pip install --dry-run`, metadata only) - pip applies
        exactly the same rules as the later download.
    Only a file that passes both is written to -RequirementsTxtPath. Otherwise the
    existing requirements.txt is left untouched, the rejected result is saved next to
    it as requirements.rejected.txt, and every unavailable package is listed.

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

.PARAMETER Platform
    Target wheel platform tag (default: settings.psd1's Platform, else win_amd64).

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

    [ValidateNotNullOrEmpty()]
    [string]$Platform,

    [ValidateRange(0, 3650)]
    [int]$MinimumPackageAgeDays
)

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$cfg = Resolve-WheelhouseParameter -BoundParameters $PSBoundParameters `
    -Name RequirementsInPath, RequirementsTxtPath, PythonVersion, Platform, MinimumPackageAgeDays `
    -SettingName @{ RequirementsTxtPath = 'LocalRequirementsPath' }

Write-Log "=== Update-Requirement started ==="
Write-Log "Source (requirements.in): $($cfg.RequirementsInPath)"
Write-Log "Target (requirements.txt): $($cfg.RequirementsTxtPath)"
Write-Log "Target Python: $($cfg.PythonVersion) / $($cfg.Platform) | Cooldown: $($cfg.MinimumPackageAgeDays) day(s)"

if (-not (Test-Path -Path $cfg.RequirementsInPath)) {
    Write-Log "requirements.in not found: $($cfg.RequirementsInPath)" "ERROR"
    Write-Log "Run Setup.ps1 first, or pass -RequirementsInPath explicitly." "ERROR"
    exit 1
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Log "Python was not found on this machine - it is needed to verify the resolved packages." "ERROR"
    exit 1
}

try {
    $uvPlatform = ConvertTo-UvPythonPlatform -Platform $cfg.Platform
}
catch {
    Write-Log $_.Exception.Message "ERROR"
    exit 1
}

# Resolve into a temporary file first - the real requirements.txt is only replaced
# once the result has passed the wheel check below.
$targetFolder = Split-Path -Path $cfg.RequirementsTxtPath -Parent
$candidatePath = Join-Path $targetFolder "requirements.candidate.txt"
$rejectedPath = Join-Path $targetFolder "requirements.rejected.txt"

$compileArgs = @(
    "pip", "compile", $cfg.RequirementsInPath,
    "--exclude-newer", "$($cfg.MinimumPackageAgeDays) days",
    "--python-version", $cfg.PythonVersion,
    "--python-platform", $uvPlatform,
    "--only-binary", ":all:",
    "--custom-compile-command", ".\Update-Requirement.ps1",
    "-o", $candidatePath
)

Write-Log "Resolving with uv (binary wheels only, $($cfg.PythonVersion) / $uvPlatform)..."
Invoke-NativeCommand -FilePath uv -ArgumentList $compileArgs

if ($LASTEXITCODE -ne 0) {
    Write-Log "uv pip compile FAILED (exit code $LASTEXITCODE). Review the output above." "ERROR"
    Write-Log "Typical cause: a package (or a version range in requirements.in) has no binary wheel for Python $($cfg.PythonVersion) / $($cfg.Platform)." "ERROR"
    Remove-Item -Path $candidatePath -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Log "Checking with pip that every resolved package has a usable wheel for Python $($cfg.PythonVersion) / $($cfg.Platform)..."
$check = Test-RequirementWheelAvailability -RequirementsFilePath $candidatePath -PythonVersion $cfg.PythonVersion -Platform $cfg.Platform

if (-not $check.Passed) {
    Move-Item -Path $candidatePath -Destination $rejectedPath -Force
    if ($check.Error) {
        Write-Log $check.Error "ERROR"
    }
    if ($check.Unavailable.Count -gt 0) {
        Write-Log "The following resolved package(s) cannot be downloaded for Python $($cfg.PythonVersion) / $($cfg.Platform) (no compatible wheel, or Requires-Python excludes $($cfg.PythonVersion)):" "ERROR"
        foreach ($pin in $check.Unavailable) {
            Write-Log "  - $pin" "ERROR"
        }
        Write-Log "Remove them from requirements.in, or constrain them there to a version that supports Python $($cfg.PythonVersion), then run this script again." "ERROR"
    }
    Write-Log "requirements.txt was NOT changed. The rejected result was saved for review: $rejectedPath" "ERROR"
    exit 1
}

Move-Item -Path $candidatePath -Destination $cfg.RequirementsTxtPath -Force
Remove-Item -Path $rejectedPath -Force -ErrorAction SilentlyContinue

Write-Log "requirements.txt written successfully: $($cfg.RequirementsTxtPath)" "OK"
Write-Log "Review it, get it approved, then run Update-Wheelhouse.ps1 to merge it into the central wheelhouse."
Write-Log "=== Update-Requirement finished ==="
exit 0
