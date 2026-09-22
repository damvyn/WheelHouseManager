<#
.SYNOPSIS
    Audit-only check of the wheelhouse: integrity + vulnerability scan across every
    group file, with an automatic alert on any finding. Intended for the Scheduled Task.

.DESCRIPTION
    Deliberately does NOTHING else: no merge from Input\requirements.txt, no download,
    no manifest rebuild, no Defender scan. This is the script that should run
    unattended on a schedule - Update-WheelHouse.ps1 (merge + download) stays a
    manual, deliberate action taken after a requirements.txt change is approved.

    Steps:
      1. Verifies wheelhouse integrity against manifest.json (every tracked file's
         hash must still match). Stops immediately on any mismatch.
      2. For every requirements-N.txt group file, runs pip-audit against each
         configured vulnerability service.
      3. If any audit found a vulnerability, calls Send-VulnerabilityAlert.ps1 with
         every report that had a finding, across all groups and services, in one call.

.PARAMETER WheelhousePath
    UNC or local path to the wheelhouse. Optional if set in config\settings.psd1.

.PARAMETER VulnerabilityServices
    pip-audit vulnerability service(s) to check (default: osv, pypi, or the value in
    config\settings.psd1).

.PARAMETER SmtpServer
.PARAMETER MailTo
.PARAMETER MailFrom
    Passed through to Send-VulnerabilityAlert.ps1 if a finding triggers an alert.
    Same settings.psd1 fallback as that script (SmtpServer, MailTo, MailFrom keys).

.EXAMPLE
    .\Test-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse"

.NOTES
    Requires functions.ps1 and Send-VulnerabilityAlert.ps1 in the same folder as this script.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$WheelhousePath,

    [ValidateSet("osv", "pypi")]
    [string[]]$VulnerabilityServices,

    [string]$SmtpServer,
    [string]$MailTo,
    [string]$MailFrom,

    [ValidateNotNullOrEmpty()]
    [string]$SendAlertScriptPath = (Join-Path $PSScriptRoot "Send-VulnerabilityAlert.ps1")
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

$WheelhousePath = Resolve-Setting -Name "WheelhousePath" -ExplicitValue $WheelhousePath `
    -WasBound $PSBoundParameters.ContainsKey('WheelhousePath') -Settings $settings -FallbackDefault $null
$VulnerabilityServices = Resolve-Setting -Name "VulnerabilityServices" -ExplicitValue $VulnerabilityServices `
    -WasBound $PSBoundParameters.ContainsKey('VulnerabilityServices') -Settings $settings -FallbackDefault @("osv", "pypi")
$SmtpServer = Resolve-Setting -Name "SmtpServer" -ExplicitValue $SmtpServer `
    -WasBound $PSBoundParameters.ContainsKey('SmtpServer') -Settings $settings -FallbackDefault $null
$MailTo = Resolve-Setting -Name "MailTo" -ExplicitValue $MailTo `
    -WasBound $PSBoundParameters.ContainsKey('MailTo') -Settings $settings -FallbackDefault "servicedesk@company.com"
$MailFrom = Resolve-Setting -Name "MailFrom" -ExplicitValue $MailFrom `
    -WasBound $PSBoundParameters.ContainsKey('MailFrom') -Settings $settings -FallbackDefault "NoReply@company.com"

if ([string]::IsNullOrWhiteSpace($WheelhousePath)) {
    Write-Log "WheelhousePath was not supplied and is not set in config\settings.psd1." "ERROR"
    exit 1
}

Write-Log "=== Wheelhouse audit-only check started ==="
Write-Log "Wheelhouse path: $WheelhousePath"

if (-not (Test-Path -Path $WheelhousePath)) {
    Write-Log "Wheelhouse path does not exist or is not reachable: $WheelhousePath" "ERROR"
    exit 1
}

$reportsFolder = Join-Path $WheelhousePath "reports"
if (-not (Test-Path -Path $reportsFolder)) {
    New-Item -ItemType Directory -Path $reportsFolder -Force | Out-Null
    Write-Log "Created reports folder: $reportsFolder"
}

$logFile = Join-Path $reportsFolder "Log_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
try {
    Start-Transcript -Path $logFile -Append | Out-Null
    Write-Log "Full console output for this run is also being saved to: $logFile"
}
catch {
    Write-Log "Could not start transcript logging to $logFile - continuing with console output only. ($($_.Exception.Message))" "WARN"
}

# ---------------------------------------------------------------------------
# Step 1: manifest integrity check
# ---------------------------------------------------------------------------

$manifestPath = Join-Path $WheelhousePath "manifest.json"
Write-Log "Loading manifest: $manifestPath"

$parseError = Get-ManifestParseError -ManifestPath $manifestPath
if ($null -ne $parseError) {
    Write-Log "manifest.json exists but could not be parsed: $parseError" "ERROR"
    Write-Log "Refusing to continue until this is resolved manually." "ERROR"
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    exit 1
}

$manifest = @()
if (Test-Path -Path $manifestPath) {
    $manifestContent = Get-Content -Path $manifestPath -Raw -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace($manifestContent)) {
        foreach ($entry in (ConvertFrom-Json -InputObject $manifestContent)) {
            $manifest += $entry
        }
    }
}
Write-Log "Manifest contains $($manifest.Count) tracked file(s)."

if ($manifest.Count -gt 0) {
    Write-Log "Verifying wheelhouse integrity against manifest..."
    $integrityProblems = Test-ManifestIntegrity -Manifest $manifest -WheelhousePath $WheelhousePath

    if ($integrityProblems.Count -gt 0) {
        $integrityReportFile = Join-Path $reportsFolder "Report_Integrity_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $integrityProblems | ConvertTo-Json -Depth 3 | Out-File -FilePath $integrityReportFile -Encoding utf8

        Write-Log "WHEELHOUSE INTEGRITY CHECK FAILED. The following problem(s) were found:" "ERROR"
        foreach ($item in $integrityProblems) {
            Write-Log "  - $item" "ERROR"
        }
        Write-Log "Integrity report saved to: $integrityReportFile" "ERROR"
        Write-Log "Refusing to run the vulnerability audit until this is investigated manually." "ERROR"
        Write-Log "=== Wheelhouse audit-only check finished (ABORTED - integrity check failed) ==="
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
        exit 1
    }
    Write-Log "Wheelhouse integrity check passed. All tracked files match their recorded hash." "OK"
}
else {
    Write-Log "Manifest is empty - nothing to audit yet." "OK"
    Write-Log "=== Wheelhouse audit-only check finished ==="
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    exit 0
}

# ---------------------------------------------------------------------------
# Step 2: audit every group file against every configured vulnerability service
# ---------------------------------------------------------------------------

$groupFiles = Get-WheelhouseRequirementGroups -WheelhousePath $WheelhousePath
if ($groupFiles.Count -eq 0) {
    Write-Log "No requirement group files found in the wheelhouse - nothing to audit." "WARN"
    Write-Log "=== Wheelhouse audit-only check finished ==="
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    exit 0
}
Write-Log "Auditing $($groupFiles.Count) requirement group file(s)."

$allAuditsPassed = $true
$failingReportPaths = @()

foreach ($groupFile in $groupFiles) {
    $groupName = [System.IO.Path]::GetFileNameWithoutExtension($groupFile)
    Write-Log "--- Group: $groupName ---"

    foreach ($service in $VulnerabilityServices) {
        $result = Invoke-PipAudit -RequirementsFilePath $groupFile -ReportsFolderPath $reportsFolder -AuditName "Scheduled-$groupName" -Service $service
        if (-not $result.Success) {
            $allAuditsPassed = $false
            $failingReportPaths += $result.ReportPath
            Show-PipAuditFixSuggestions -RequirementsFilePath $groupFile
        }
    }
}

# ---------------------------------------------------------------------------
# Step 3: alert on any finding, across all groups and services in one call
# ---------------------------------------------------------------------------

if ($failingReportPaths.Count -gt 0) {
    Write-Log "$($failingReportPaths.Count) audit report(s) contain vulnerability findings. Triggering alert..." "ERROR"

    if (-not (Test-Path -Path $SendAlertScriptPath)) {
        Write-Log "Send-VulnerabilityAlert.ps1 not found at: $SendAlertScriptPath - cannot send the alert." "ERROR"
    }
    else {
        $alertParams = @{
            ReportPaths    = $failingReportPaths
            WheelhousePath = $WheelhousePath
            To             = $MailTo
            From           = $MailFrom
        }
        if (-not [string]::IsNullOrWhiteSpace($SmtpServer)) { $alertParams["SmtpServer"] = $SmtpServer }

        & $SendAlertScriptPath @alertParams
        Write-Log "Send-VulnerabilityAlert.ps1 finished with exit code $LASTEXITCODE."
    }
}
else {
    Write-Log "All groups passed on all configured vulnerability services. No known vulnerabilities found." "OK"
}

Write-Log "=== Wheelhouse audit-only check finished ==="
Stop-Transcript -ErrorAction SilentlyContinue | Out-Null

if (-not $allAuditsPassed) { exit 1 }
exit 0
