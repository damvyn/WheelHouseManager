<#
.SYNOPSIS
    Runs the wheelhouse maintenance script and automatically feeds any new
    vulnerability audit reports it produced into the alert script.

.DESCRIPTION
    Calls Update-Wheelhouse.ps1, then scans <WheelhousePath>\reports for
    Report_*-OSV_*.json / Report_*-PYPI_*.json files created during that run
    (by timestamp, not by parsing Update-Wheelhouse.ps1's internals - so this
    script keeps working even if that script's logic changes later, as long as
    the report naming convention stays the same). Those paths are passed
    straight into Send-VulnerabilityAlert.ps1 - no manual -ReportPaths needed.

    If Update-Wheelhouse.ps1 aborts before producing any audit report (e.g. an
    integrity check failure), this script skips the alert step and says why.

.PARAMETER WheelhousePath
    Passed through to both underlying scripts.

.PARAMETER PythonVersion
.PARAMETER Platform
.PARAMETER MinimumPackageAgeDays
.PARAMETER VulnerabilityServices
    Passed through to Update-Wheelhouse.ps1.

.PARAMETER SmtpServer
.PARAMETER To
.PARAMETER From
.PARAMETER OutputHtmlPath
    Passed through to Send-VulnerabilityAlert.ps1. Omit -SmtpServer to save an
    HTML file instead of emailing (same behavior as calling that script directly).

.PARAMETER UpdateWheelhouseScriptPath
.PARAMETER SendAlertScriptPath
    Paths to the two underlying scripts. Default to the same folder as this script.

.EXAMPLE
    .\Invoke-WheelhousePipeline.ps1 -WheelhousePath "\\server\share\wheelhouse"

.EXAMPLE
    .\Invoke-WheelhousePipeline.ps1 -WheelhousePath "\\server\share\wheelhouse" -SmtpServer "10.0.0.25"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$WheelhousePath,

    [string]$PythonVersion = "3.14",
    [string]$Platform = "win_amd64",
    [int]$MinimumPackageAgeDays = 10,
    [string[]]$VulnerabilityServices = @("osv", "pypi"),

    [string]$SmtpServer,
    [string]$To = "servicedesk@company.com",
    [string]$From = "NoReply@company.com",
    [string]$OutputHtmlPath,

    [string]$UpdateWheelhouseScriptPath = (Join-Path $PSScriptRoot "Update-Wheelhouse.ps1"),
    [string]$SendAlertScriptPath = (Join-Path $PSScriptRoot "Send-VulnerabilityAlert.ps1")
)

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "OK", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "OK"    { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

Write-Log "=== Wheelhouse pipeline started ==="

if (-not (Test-Path -Path $UpdateWheelhouseScriptPath)) {
    Write-Log "Update-Wheelhouse.ps1 not found at: $UpdateWheelhouseScriptPath" "ERROR"
    exit 1
}
if (-not (Test-Path -Path $SendAlertScriptPath)) {
    Write-Log "Send-VulnerabilityAlert.ps1 not found at: $SendAlertScriptPath" "ERROR"
    exit 1
}

# ---------------------------------------------------------------------------
# Step 1: run Update-Wheelhouse.ps1
# ---------------------------------------------------------------------------

$runStartTime = Get-Date
Write-Log "Running Update-Wheelhouse.ps1..."

& $UpdateWheelhouseScriptPath `
    -WheelhousePath $WheelhousePath `
    -PythonVersion $PythonVersion `
    -Platform $Platform `
    -MinimumPackageAgeDays $MinimumPackageAgeDays `
    -VulnerabilityServices $VulnerabilityServices

$wheelhouseExitCode = $LASTEXITCODE
Write-Log "Update-Wheelhouse.ps1 finished with exit code $wheelhouseExitCode."

# ---------------------------------------------------------------------------
# Step 2: find audit reports it just wrote and feed them into the alert script
# ---------------------------------------------------------------------------

$reportsFolder = Join-Path $WheelhousePath "reports"
$newAuditReports = @()

if (Test-Path -Path $reportsFolder) {
    $newAuditReports = @(
        Get-ChildItem -Path $reportsFolder -File -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.Name -match '-OSV_' -or $_.Name -match '-PYPI_') -and
                $_.LastWriteTime -ge $runStartTime
            } |
            Select-Object -ExpandProperty FullName
    )
}

if ($newAuditReports.Count -eq 0) {
    Write-Log "No new audit reports were produced this run - skipping the alert step." "WARN"
    Write-Log "(This is expected if Update-Wheelhouse.ps1 aborted early, e.g. on an integrity check failure - check its output above.)"
    Write-Log "=== Wheelhouse pipeline finished ==="
    exit $wheelhouseExitCode
}

Write-Log "Found $($newAuditReports.Count) new audit report(s):"
foreach ($report in $newAuditReports) {
    Write-Log "  - $report"
}

# ---------------------------------------------------------------------------
# Step 3: run Send-VulnerabilityAlert.ps1
# ---------------------------------------------------------------------------

Write-Log "Running Send-VulnerabilityAlert.ps1..."

$alertParams = @{
    ReportPaths    = $newAuditReports
    WheelhousePath = $WheelhousePath
    To             = $To
    From           = $From
}
if (-not [string]::IsNullOrWhiteSpace($SmtpServer)) { $alertParams["SmtpServer"] = $SmtpServer }
if (-not [string]::IsNullOrWhiteSpace($OutputHtmlPath)) { $alertParams["OutputHtmlPath"] = $OutputHtmlPath }

& $SendAlertScriptPath @alertParams
$alertExitCode = $LASTEXITCODE
Write-Log "Send-VulnerabilityAlert.ps1 finished with exit code $alertExitCode."

Write-Log "=== Wheelhouse pipeline finished ==="

if ($wheelhouseExitCode -ne 0) { exit $wheelhouseExitCode }
exit $alertExitCode
