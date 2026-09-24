<#
.SYNOPSIS
    Runs the wheelhouse maintenance script and automatically feeds the audit results
    of that run into the alert script.

.DESCRIPTION
    Calls Update-Wheelhouse.ps1, collects the Wheelhouse.AuditResult objects it
    returns (one per group/service audit of THIS run - no guessing by report file
    timestamps), and passes every vulnerable or failed audit straight into
    Send-VulnerabilityAlert.ps1 - no manual -ReportPaths needed.

    If Update-Wheelhouse.ps1 aborts before running any audit (e.g. an integrity
    check failure), this script skips the alert step and says why.

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
    Passed through to Update-Wheelhouse.ps1.

.PARAMETER SmtpServer
.PARAMETER To
.PARAMETER From
.PARAMETER OutputHtmlPath
    Passed through to Send-VulnerabilityAlert.ps1. Without an SMTP server (here or in
    settings.psd1) the alert is saved as an HTML file instead of emailed.

.PARAMETER UpdateWheelhouseScriptPath
.PARAMETER SendAlertScriptPath
    Paths to the two underlying scripts. Default to Jobs\ next to this script
    (this script itself lives at the manager root, alongside config\ and Input\).

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

    [string]$SmtpServer,
    [string]$To,
    [string]$From,
    [string]$OutputHtmlPath
)
$UpdateWheelhouseScriptPath = (Join-Path (Join-Path $PSScriptRoot 'Jobs') 'Update-Wheelhouse.ps1')
$SendAlertScriptPath = (Join-Path (Join-Path $PSScriptRoot 'Jobs') 'Send-VulnerabilityAlert.ps1')

Import-Module (Join-Path (Join-Path $PSScriptRoot 'Jobs') 'WheelhouseManager') -ErrorAction Stop

Write-Log '=== Wheelhouse pipeline started ==='

foreach ($scriptPath in $UpdateWheelhouseScriptPath, $SendAlertScriptPath) {
    if (-not (Test-Path -Path $scriptPath)) {
        Write-Log "Required script not found: $scriptPath" 'ERROR'
        exit 1
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
    'VulnerabilityServices'
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
$auditResults = @(& $UpdateWheelhouseScriptPath @updateParams |
        Where-Object { $_.PSObject.TypeNames -contains 'Wheelhouse.AuditResult' })
$wheelhouseExitCode = $LASTEXITCODE
Write-Log "Update-Wheelhouse.ps1 finished with exit code $wheelhouseExitCode."

# ---------------------------------------------------------------------------
# Step 2: alert on every vulnerable or failed audit of this run
# ---------------------------------------------------------------------------

if ($auditResults.Count -eq 0) {
    Write-Log 'No audits ran this run - skipping the alert step.' 'WARN'
    Write-Log '(This is expected if script aborted early.)'
    Write-Log '=== Wheelhouse pipeline finished ==='
    exit $wheelhouseExitCode
}

$alertParams = Get-VulnerabilityAlertParameter -AuditResult $auditResults -AlertParameters $alertParams
$alertExitCode = 0
if ($null -ne $alertParams) {
    Write-Log 'Running Send-VulnerabilityAlert.ps1...'
    & $SendAlertScriptPath @alertParams | Out-Host
    $alertExitCode = $LASTEXITCODE
    Write-Log "Send-VulnerabilityAlert.ps1 finished with exit code $alertExitCode."
}

Write-Log '=== Wheelhouse pipeline finished ==='

if ($wheelhouseExitCode -ne 0) { exit $wheelhouseExitCode }
exit $alertExitCode
