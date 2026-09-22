<#
.SYNOPSIS
    Deploys the wheelhouse manager scripts to a local folder and initializes its
    configuration and input files. Safe to re-run.

.DESCRIPTION
    Copies Jobs\ (functions.ps1, Update-Wheelhouse.ps1, Update-Requirement.ps1,
    Send-VulnerabilityAlert.ps1) and Invoke-WheelhousePipeline.ps1 (deployed to the
    destination root, not Jobs\) from next to this script into -DestinationPath,
    creates config\settings.psd1 if it doesn't exist yet, and creates an empty
    Input\requirements.in / Input\requirements.txt if they don't exist yet.

    Idempotent: re-running this script always refreshes the Jobs\ scripts (so a
    newer script package gets redeployed), but NEVER overwrites settings.psd1 keys
    you didn't pass, and NEVER overwrites an existing requirements.in/.txt - both
    of those are user data, not code.

.PARAMETER DestinationPath
    Where to deploy to (default: C:\WheelHouseManager).

.PARAMETER WheelhousePath
    UNC or local path to the central wheelhouse. If supplied, written into
    config\settings.psd1 as the default for the other scripts. Optional on a
    re-run if it's already set - omit it to leave the existing value untouched.

.EXAMPLE
    .\Setup.ps1 -WheelhousePath "\\server\share\wheelhouse"

.EXAMPLE
    # Custom destination folder
    .\Setup.ps1 -DestinationPath "D:\WheelHouseManager" -WheelhousePath "\\server\share\wheelhouse"

.NOTES
    Requires functions.ps1 (in Jobs\ next to this script) for Write-Log, Save-Settings,
    Set-WheelhouseSetting, and Initialize-ManagerFile.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$DestinationPath = "C:\WheelHouseManager",

    [string]$WheelhousePath
)

$sourceJobsPath = Join-Path $PSScriptRoot "Jobs"
$commonPath = Join-Path $sourceJobsPath "functions.ps1"
if (-not (Test-Path -Path $commonPath)) {
    Write-Host "Required file not found: $commonPath" -ForegroundColor Red
    exit 1
}
. $commonPath

Write-Log "=== Wheelhouse manager setup started ==="
Write-Log "Destination: $DestinationPath"

# ---------------------------------------------------------------------------
# Step 1: deploy Jobs\ (always refreshed - these are code, not user data)
# ---------------------------------------------------------------------------

$destJobsPath = Join-Path $DestinationPath "Jobs"
New-Item -ItemType Directory -Path $destJobsPath -Force | Out-Null

Copy-Item -Path (Join-Path $sourceJobsPath "*.ps1") -Destination $destJobsPath -Force
Write-Log "Deployed Jobs\ scripts to: $destJobsPath" "OK"

$sourceOrchestratorPath = Join-Path $PSScriptRoot "Invoke-WheelhousePipeline.ps1"
if (Test-Path -Path $sourceOrchestratorPath) {
    Copy-Item -Path $sourceOrchestratorPath -Destination $DestinationPath -Force
    Write-Log "Deployed Invoke-WheelhousePipeline.ps1 to: $DestinationPath" "OK"
}
else {
    Write-Log "Invoke-WheelhousePipeline.ps1 not found next to Setup.ps1 - skipped." "WARN"
}

# ---------------------------------------------------------------------------
# Step 2: config\settings.psd1 (created once, merged thereafter - never clobbered)
# ---------------------------------------------------------------------------

$inputPath = Join-Path $DestinationPath "Input"
$configPath = Join-Path $DestinationPath "config"
New-Item -ItemType Directory -Path $configPath -Force | Out-Null
$settingsPath = Join-Path $configPath "settings.psd1"

if (-not (Test-Path -Path $settingsPath)) {
    $defaultSettings = @{
        WheelhousePath         = ""
        RequirementsInPath     = (Join-Path $inputPath "requirements.in")
        LocalRequirementsPath  = (Join-Path $inputPath "requirements.txt")
        PythonVersion           = "3.14"
        Platform                = "win_amd64"
        MinimumPackageAgeDays   = 10
        VulnerabilityServices   = @("osv", "pypi")
        SmtpServer              = ""
        MailTo                  = "servicedesk@company.com"
        MailFrom                = "NoReply@company.com"
    }
    Save-Settings -SettingsPath $settingsPath -Settings $defaultSettings
    Write-Log "Created default settings file: $settingsPath" "OK"
}
else {
    Write-Log "Settings file already exists, leaving other keys untouched: $settingsPath"
}

if (-not [string]::IsNullOrWhiteSpace($WheelhousePath)) {
    Set-WheelhouseSetting -SettingsPath $settingsPath -Updates @{ WheelhousePath = $WheelhousePath }
    Write-Log "WheelhousePath set to: $WheelhousePath" "OK"
}
else {
    $currentSettings = Get-WheelhouseSettings -SettingsPath $settingsPath
    if ([string]::IsNullOrWhiteSpace($currentSettings["WheelhousePath"])) {
        Write-Log "No -WheelhousePath supplied and none is set yet in settings.psd1 - the other scripts will require it explicitly until this is set." "WARN"
    }
}

# ---------------------------------------------------------------------------
# Step 3: Input\ (created once - requirements.in/.txt are user data, never overwritten)
# ---------------------------------------------------------------------------

New-Item -ItemType Directory -Path $inputPath -Force | Out-Null

$requirementsInDefault = @"
# Add the packages you need, one per line, unpinned or with a version range.
# Example:
#   numpy
#   pandas>=2.0
"@

Initialize-ManagerFile -Path (Join-Path $inputPath "requirements.in") -DefaultContent $requirementsInDefault
Initialize-ManagerFile -Path (Join-Path $inputPath "requirements.txt") -DefaultContent ""

Write-Log "=== Wheelhouse manager setup finished ==="
Write-Log "Next step: edit $(Join-Path $inputPath 'requirements.in'), then run Update-Requirement.ps1."
