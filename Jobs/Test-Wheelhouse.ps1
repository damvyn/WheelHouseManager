<#
.SYNOPSIS
    Audit-only check of the wheelhouse: integrity + vulnerability scan across every
    group file, with an automatic alert on any finding. Intended for the Scheduled Task.

.DESCRIPTION
    Deliberately does NOTHING else: no merge from Input\requirements.txt, no download,
    no manifest changes, no Defender scan. This is the script that should run
    unattended on a schedule - Update-Wheelhouse.ps1 (merge + download) stays a
    manual, deliberate action taken after a requirements.txt change is approved.

    Steps:
      1. Checks python / pip-audit are usable (installs or upgrades them if needed).
      2. Verifies wheelhouse integrity against manifest.json (every tracked file's
         hash must still match). Stops immediately on any mismatch.
      3. For every requirements-N.txt group file, runs pip-audit against each
         configured vulnerability service.
      4. If any audit found a vulnerability OR could not be completed, calls
         Send-VulnerabilityAlert.ps1 once with every such result, across all groups
         and services. A failed audit is never reported as "no vulnerabilities".

.PARAMETER WheelhousePath
    UNC or local path to the wheelhouse. Optional if set in config\settings.psd1.

.PARAMETER VulnerabilityServices
    pip-audit vulnerability service(s) to check (default: osv, pypi, or the value in
    config\settings.psd1).

.PARAMETER SmtpServer
.PARAMETER MailTo
.PARAMETER MailFrom
    Passed through to Send-VulnerabilityAlert.ps1 if a finding triggers an alert.
    If omitted, that script falls back to config\settings.psd1 itself.

.EXAMPLE
    .\Test-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse"

.NOTES
    Requires the WheelhouseManager module folder and Send-VulnerabilityAlert.ps1 in the
    same folder as this script.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$WheelhousePath,

    [ValidateSet('osv', 'pypi')]
    [string[]]$VulnerabilityServices,

    [string]$SmtpServer,
    [string]$MailTo,
    [string]$MailFrom,

    [ValidateNotNullOrEmpty()]
    [string]$SendAlertScriptPath = (Join-Path $PSScriptRoot 'Send-VulnerabilityAlert.ps1')
)

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$cfg = Resolve-WheelhouseParameter -BoundParameters $PSBoundParameters `
    -Name WheelhousePath, VulnerabilityServices, ReportRetentionMonths

$title = 'Wheelhouse audit-only check'
$outcome = $null
$exitCode = 0

try {
    $reportsFolder = Start-WheelhouseRun -WheelhousePath $cfg.WheelhousePath -Title $title -LogPrefix 'Log_Audit' -RetentionMonths $cfg.ReportRetentionMonths

    Confirm-PythonAndTooling

    # -----------------------------------------------------------------------
    # Step 1: manifest integrity check
    # -----------------------------------------------------------------------

    Write-Log "Loading manifest: $(Get-WheelhouseManifestPath -WheelhousePath $cfg.WheelhousePath)"
    $manifest = Read-WheelhouseManifest -WheelhousePath $cfg.WheelhousePath
    Write-Log "Manifest contains $($manifest.Count) tracked file(s)."

    $groupFiles = @()
    if ($manifest.Count -eq 0) {
        Write-Log 'Manifest is empty - nothing to audit yet.' 'OK'
    }
    else {
        Assert-WheelhouseIntegrity -Manifest $manifest -WheelhousePath $cfg.WheelhousePath -ReportsFolder $reportsFolder

        $groupFiles = Get-WheelhouseGroupFile -WheelhousePath $cfg.WheelhousePath
        if ($groupFiles.Count -eq 0) {
            Write-Log 'No requirement group files found in the wheelhouse - nothing to audit.' 'WARN'
        }
    }

    # -----------------------------------------------------------------------
    # Step 2: audit every group file against every configured vulnerability service
    # -----------------------------------------------------------------------

    $auditResults = [System.Collections.Generic.List[object]]::new()
    if ($groupFiles.Count -gt 0) {
        Write-Log "Auditing $($groupFiles.Count) requirement group file(s)."
    }
    foreach ($groupFile in $groupFiles) {
        Write-Log "--- Group: $([System.IO.Path]::GetFileNameWithoutExtension($groupFile)) ---"
        $groupResults = Invoke-GroupAudit -GroupFile $groupFile -Services $cfg.VulnerabilityServices -Stage 'Scheduled' -ReportsFolder $reportsFolder
        foreach ($result in $groupResults) { $auditResults.Add($result) }
    }

    # -----------------------------------------------------------------------
    # Step 3: alert on any finding or failed audit, in one call
    # -----------------------------------------------------------------------

    $alertParams = @{ WheelhousePath = $cfg.WheelhousePath }
    foreach ($name in 'SmtpServer', 'MailTo', 'MailFrom') {
        if ($PSBoundParameters.ContainsKey($name)) {
            $alertParams[$name -replace '^Mail', ''] = $PSBoundParameters[$name]
        }
    }
    $alertParams = Get-VulnerabilityAlertParameter -AuditResult $auditResults.ToArray() -AlertParameters $alertParams
    $alertExitCode = 0
    if ($null -ne $alertParams) {
        if (Test-Path -Path $SendAlertScriptPath) {
            & $SendAlertScriptPath @alertParams | Out-Host
            $alertExitCode = $LASTEXITCODE
            Write-Log "Send-VulnerabilityAlert.ps1 finished with exit code $alertExitCode."
        }
        else {
            Write-Log "Send-VulnerabilityAlert.ps1 not found at: $SendAlertScriptPath - cannot send the alert." 'ERROR'
            $alertExitCode = 1
        }
    }

    if ($auditResults | Where-Object { $_.Status -ne 'Passed' }) {
        $exitCode = 1
        $outcome = 'findings or failed audits'
    }
    elseif ($alertExitCode -ne 0) {
        $exitCode = $alertExitCode
    }
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    $exitCode = 1
    $outcome = 'ABORTED'
}
finally {
    Stop-WheelhouseRun -Title $title -Outcome $outcome
}

exit $exitCode
