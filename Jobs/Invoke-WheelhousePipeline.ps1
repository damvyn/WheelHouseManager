<#
.SYNOPSIS
    Runs the wheelhouse maintenance script and automatically feeds the audit results
    of that run into the alert script.

.DESCRIPTION
    Calls Update-Wheelhouse.ps1, collects the Wheelhouse.AuditResult objects it
    returns (one per group/service audit of THIS run - no guessing by report file
    timestamps), and passes every vulnerable or failed audit straight into
    Send-VulnerabilityAlert.ps1 - no manual -ReportPaths needed.

    Wheelhouse.Notice objects of the same run (a wheel missing or changed on the share, a
    download that did not match PyPI or was detected at intake) go into the same alert.

    If Update-Wheelhouse.ps1 aborts before running any audit (e.g. an integrity
    check failure), this script skips the alert step and says why.

    Exit code: Update-Wheelhouse.ps1's code if it is not 0 (1 needs attention, 2 error,
    3 busy), otherwise the alert script's (2 if the alert could not be delivered).

    Every parameter is only passed down if you supply it; otherwise each child
    script resolves it from config\settings.psd1 itself.

.PARAMETER WheelhousePath
    Passed through to both underlying scripts.

.PARAMETER LocalRequirementsPath
    Passed through to Update-Wheelhouse.ps1. If omitted, that script uses
    config\settings.psd1's LocalRequirementsPath (Input\requirements.txt), i.e. it
    merges it if it has content. Pass "" to skip the merge.

.PARAMETER PythonVersion
.PARAMETER Platform
.PARAMETER MinimumPackageAgeDays
.PARAMETER VulnerabilityServices
.PARAMETER ExpeditePackage
.PARAMETER ExpediteReason
.PARAMETER AutoQuarantine
    Passed through to Update-Wheelhouse.ps1.

.PARAMETER SmtpServer
.PARAMETER To
.PARAMETER From
.PARAMETER OutputHtmlPath
    Passed through to Send-VulnerabilityAlert.ps1. Without an SMTP server (here or in
    settings.psd1) the alert is saved as an HTML file instead of emailed.

.EXAMPLE
    .\Invoke-WheelhousePipeline.ps1 -WheelhousePath "\\server\share\wheelhouse"

.EXAMPLE
    .\Invoke-WheelhousePipeline.ps1 -WheelhousePath "\\server\share\wheelhouse" -SmtpServer "10.0.0.25"
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$WheelhousePath,

    [string]$LocalRequirementsPath,

    [ValidateNotNullOrEmpty()]
    [string]$PythonVersion,
    [ValidateNotNullOrEmpty()]
    [string]$Platform,
    [ValidateRange(0, 3650)]
    [int]$MinimumPackageAgeDays,
    [ValidateSet('osv', 'pypi')]
    [string[]]$VulnerabilityServices,
    [string[]]$ExpeditePackage,
    [string]$ExpediteReason,
    [ValidateSet('On', 'Off')]
    [string]$AutoQuarantine,

    [string]$SmtpServer,
    [string]$To,
    [string]$From,
    [string]$OutputHtmlPath
)
$UpdateWheelhouseScriptPath = (Join-Path $PSScriptRoot 'Update-Wheelhouse.ps1')
$SendAlertScriptPath = (Join-Path $PSScriptRoot 'Send-VulnerabilityAlert.ps1')

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

Write-Log '=== Wheelhouse pipeline started ==='

foreach ($scriptPath in $UpdateWheelhouseScriptPath, $SendAlertScriptPath) {
    if (-not (Test-Path -Path $scriptPath)) {
        Write-Log "Required script not found: $scriptPath" 'ERROR'
        exit 2
    }
}

# Split the explicitly-passed parameters between the two child scripts.
$updateParams = @{}
$updateParamsIn = @(
    'WheelhousePath',
    'LocalRequirementsPath',
    'PythonVersion',
    'Platform',
    'MinimumPackageAgeDays',
    'VulnerabilityServices',
    'ExpeditePackage',
    'ExpediteReason',
    'AutoQuarantine'
)
foreach ($name in $updateParamsIn) {
    if ($PSBoundParameters.ContainsKey($name)) {
        $updateParams[$name] = $PSBoundParameters[$name]
    }
}

$alertParams = @{}
$alertParamsIn = @(
    'WheelhousePath',
    'SmtpServer',
    'To',
    'From',
    'OutputHtmlPath'
)
foreach ($name in $alertParamsIn) {
    if ($PSBoundParameters.ContainsKey($name)) {
        $alertParams[$name] = $PSBoundParameters[$name]
    }
}

# ---------------------------------------------------------------------------
# Step 1: run Update-Wheelhouse.ps1 and collect this run's audit results
# ---------------------------------------------------------------------------

Write-Log 'Running Update-Wheelhouse.ps1...'
$output = @(& $UpdateWheelhouseScriptPath @updateParams)
$wheelhouseExitCode = $LASTEXITCODE
$auditResults = @($output | Where-Object { $_.PSObject.TypeNames -contains 'Wheelhouse.AuditResult' })
$notices = @($output | Where-Object { $_.PSObject.TypeNames -contains 'Wheelhouse.Notice' })
Write-Log "Update-Wheelhouse.ps1 finished with exit code $wheelhouseExitCode."

# ---------------------------------------------------------------------------
# Step 2: alert on every vulnerable or failed audit and every notice of this run
# ---------------------------------------------------------------------------

if ($auditResults.Count -eq 0 -and $notices.Count -eq 0) {
    Write-Log 'No audits ran this run - skipping the alert step.' 'WARN'
    Write-Log '(This is expected if script aborted early.)'
    Write-Log '=== Wheelhouse pipeline finished ==='
    exit $wheelhouseExitCode
}

# Published packages are alerted like the weekly check does - only what is new, overdue,
# reminded, unwaived or resolved (the catalog remembers what was alerted). Candidates this
# run blocked are always reported. Without a readable catalog, every vulnerable audit is.
$cfg = Resolve-WheelhouseParameter -BoundParameters $PSBoundParameters -Name WheelhousePath, OverdueReminderDays
$findingAlerts = $null
try {
    $findingAlerts = @(Get-CatalogFindingAlert -Catalog (Read-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath) -ReminderDays ([int]$cfg.OverdueReminderDays))
}
catch {
    Write-Log "The package catalog could not be read ($($_.Exception.Message)) - alerting every vulnerable audit of this run." 'WARN'
}
$alertParamsIn = @{ AuditResult = $auditResults; Notice = $notices; AlertParameters = $alertParams }
if ($null -ne $findingAlerts) { $alertParamsIn['Finding'] = $findingAlerts }
$alertParams = Get-VulnerabilityAlertParameter @alertParamsIn
$alertExitCode = 0
if ($null -ne $alertParams) {
    Write-Log 'Running Send-VulnerabilityAlert.ps1...'
    & $SendAlertScriptPath @alertParams | Out-Host
    $alertExitCode = $LASTEXITCODE
    Write-Log "Send-VulnerabilityAlert.ps1 finished with exit code $alertExitCode."
}
if ($null -ne $findingAlerts -and $findingAlerts.Count -gt 0 -and $alertExitCode -eq 0) {
    $alerted = $findingAlerts
    try {
        Update-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath -Update ({
                param($catalog)
                Set-CatalogFindingNotified -Catalog $catalog -Finding $alerted
            }.GetNewClosure())
    }
    catch {
        Write-Log "Could not record which findings were alerted ($($_.Exception.Message)); they are alerted again next time." 'WARN'
    }
}

Write-Log '=== Wheelhouse pipeline finished ==='

if ($wheelhouseExitCode -ne 0) { exit $wheelhouseExitCode }
exit $alertExitCode
