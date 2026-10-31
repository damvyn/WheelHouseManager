<#
.SYNOPSIS
    Scheduled check of everything already published: integrity, vulnerabilities,
    denylist, PyPI yanked flag and (optionally) Microsoft Defender, with one automatic
    alert on any finding. Intended for the Scheduled Task.

.DESCRIPTION
    A package that passed every check when it entered the wheelhouse can fail one later:
    a new vulnerability is published, the release is yanked, someone denylists it, or
    Defender's updated signatures detect it. This script re-checks all of that.

    Deliberately does NOTHING else: no merge from Input\requirements.txt, no download,
    no manifest or group file changes. This is the script that should run unattended on
    a schedule - Update-Wheelhouse.ps1 (merge + download) stays a manual, deliberate
    action taken after a requirements.txt change is approved.

    Steps:
      1. Checks python / pip-audit are usable (installs or upgrades them if needed).
      2. Verifies wheelhouse integrity against manifest.json (every tracked file's
         hash must still match). Stops immediately on any mismatch - except for a
         wheel that Microsoft Defender removed itself, which is reported as a notice
         (Update-Wheelhouse.ps1 cleans it up).
      3. Checks every published version against the denylist and PyPI's yanked flag.
      4. For every group file (also when the manifest is still empty), runs pip-audit
         against each configured vulnerability service.
      5. With -DefenderScan or the DefenderScanInScheduledCheck setting, re-scans the
         whole wheelhouse with Microsoft Defender (needs an elevated account).
      6. If anything was found OR a check could not be completed, calls
         Send-VulnerabilityAlert.ps1 once with every such result. A failed check is
         never reported as "no problems".

    Exit codes: 0 OK; 1 findings (needs attention); 2 aborted, a check could not be
    completed, or the alert could not be sent.

.PARAMETER WheelhousePath
    UNC or local path to the wheelhouse. Optional if set in config\settings.psd1.

.PARAMETER VulnerabilityServices
    pip-audit vulnerability service(s) to check (default: osv, pypi, or the value in
    config\settings.psd1).

.PARAMETER DefenderScan
    Also re-scan the wheelhouse with Microsoft Defender, even if the
    DefenderScanInScheduledCheck setting is off.

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

    [switch]$DefenderScan,

    [string]$SmtpServer,
    [string]$MailTo,
    [string]$MailFrom
)

$sendAlertScriptPath = (Join-Path $PSScriptRoot 'Send-VulnerabilityAlert.ps1')
Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$whlParams = @{
    'BoundParameters' = $PSBoundParameters
    'Name' = @('WheelhousePath', 'VulnerabilityServices', 'ReportRetentionMonths', 'PythonVersion', 'Platform', 'DefenderScanInScheduledCheck')
}
$cfg = Resolve-WheelhouseParameter @whlParams

$title = 'Wheelhouse scheduled check'
$outcome = $null
$exitCode = 0

try {
    $whlRunParams = @{
        'WheelhousePath' = $cfg.WheelhousePath
        'Title' = $title
        'LogPrefix' = 'Log_Audit'
        'RetentionMonths' = $cfg.ReportRetentionMonths
    }
    $reportsFolder = Start-WheelhouseRun @whlRunParams

    Confirm-PythonAndTooling

    $notices = [System.Collections.Generic.List[object]]::new()
    $checkErrors = [System.Collections.Generic.List[string]]::new()
    $denylist = @(Read-WheelhouseDenylist)

    # -----------------------------------------------------------------------
    # Step 1: manifest integrity check
    # -----------------------------------------------------------------------

    Write-Log "Loading manifest: $(Get-WheelhouseManifestPath -WheelhousePath $cfg.WheelhousePath)"
    $manifest = Read-WheelhouseManifest -WheelhousePath $cfg.WheelhousePath
    Write-Log "Manifest contains $($manifest.Count) tracked file(s)."

    $published = $manifest
    if ($manifest.Count -eq 0) {
        Write-Log 'Manifest is empty - no published wheels to verify. Group files are still audited.' 'OK'
    }
    else {
        $removedByDefender = @(Assert-WheelhouseIntegrity -Manifest $manifest -WheelhousePath $cfg.WheelhousePath -ReportsFolder $reportsFolder -AllowDefenderRemoved)
        foreach ($item in $removedByDefender) {
            $noticeParams = @{
                Kind    = 'DefenderRemoved'
                Package = [string]$item.Entry.name
                Version = [string]$item.Entry.version
                File    = @([string]$item.Entry.file)
                Message = "Microsoft Defender detected $($item.ThreatName) and removed the wheel. It is still listed in the manifest and the group files."
                Action  = 'Run Update-Wheelhouse.ps1: it takes the pin out of the group files and the manifest and denylists the version. Then review the detection.'
            }
            $notices.Add((New-WheelhouseNotice @noticeParams))
        }
        $gone = @($removedByDefender | ForEach-Object { [string]$_.Entry.file })
        $published = @($manifest | Where-Object { $gone -notcontains [string]$_.file })
    }

    $groupFiles = Get-WheelhouseGroupFile -WheelhousePath $cfg.WheelhousePath
    if ($groupFiles.Count -eq 0) {
        Write-Log 'No requirement group files found in the wheelhouse - nothing to audit.' 'WARN'
    }

    # Group entries without a wheel can't be installed by clients.
    $undownloadParams = @{
        'GroupFiles' = $groupFiles
        'Manifest' = $manifest
        'PythonVersion' = $cfg.PythonVersion
        'Platform' = $cfg.Platform
    }
    $undownloaded = @(Get-UndownloadedPin @undownloadParams)
    if ($undownloaded.Count -gt 0) {
        Write-Log "$($undownloaded.Count) package(s) are listed in group files but have no wheel in the wheelhouse:" 'WARN'
        foreach ($item in $undownloaded) {
            Write-Log "  - $($item.Group): $($item.Package)==$($item.Version)" 'WARN'
        }
        Write-Log 'Run Update-Wheelhouse.ps1 to download them (it reports why a package is rejected), or remove those lines from the group files.' 'WARN'
    }

    # -----------------------------------------------------------------------
    # Step 2: published versions vs. the denylist and PyPI's yanked flag
    # -----------------------------------------------------------------------

    $deployed = Get-DeployedPackageNotice -Manifest @($published) -Denylist $denylist
    foreach ($notice in $deployed.Notices) { $notices.Add($notice) }
    foreach ($text in $deployed.Errors) { $checkErrors.Add($text) }

    # -----------------------------------------------------------------------
    # Step 3: audit every group file against every configured vulnerability service
    # -----------------------------------------------------------------------

    $auditResults = [System.Collections.Generic.List[object]]::new()
    if ($groupFiles.Count -gt 0) {
        Write-Log "Auditing $($groupFiles.Count) requirement group file(s)."
    }
    foreach ($groupFile in $groupFiles) {
        Write-Log "--- Group: $([System.IO.Path]::GetFileNameWithoutExtension($groupFile)) ---"
        $groupAuditParams = @{
            'GroupFile' = $groupFile
            'Services' = $cfg.VulnerabilityServices
            'Stage' = 'Scheduled'
            'ReportsFolder' = $reportsFolder
        }
        $groupResults = Invoke-GroupAudit @groupAuditParams
        foreach ($result in $groupResults) { $auditResults.Add($result) }
    }

    # -----------------------------------------------------------------------
    # Step 4: optional Defender re-scan with the current signatures
    # -----------------------------------------------------------------------

    if ($DefenderScan -or $cfg.DefenderScanInScheduledCheck) {
        $scan = Invoke-WheelhouseDefenderScan -Path $cfg.WheelhousePath -ReportsFolder $reportsFolder
        if ($scan.Status -eq 'Threat') {
            foreach ($threat in @($scan.Threats)) {
                $hit = $published | Where-Object { ([string]$threat.Resource).IndexOf((Join-Path $cfg.WheelhousePath ([string]$_.file)), [System.StringComparison]::OrdinalIgnoreCase) -ge 0 } | Select-Object -First 1
                $noticeParams = @{
                    Kind    = 'DefenderThreat'
                    Package = $(if ($hit) { [string]$hit.name } else { '' })
                    Version = $(if ($hit) { [string]$hit.version } else { '' })
                    File    = @([string]$threat.Resource)
                    Message = "Microsoft Defender detected $($threat.ThreatName) with the current signatures."
                }
                $notices.Add((New-WheelhouseNotice @noticeParams))
            }
        }
        elseif ($scan.Status -eq 'Error') {
            $checkErrors.Add("Microsoft Defender scan: $($scan.Message)")
        }
    }

    # -----------------------------------------------------------------------
    # Step 5: alert on any finding or failed check, in one call
    # -----------------------------------------------------------------------

    $alertParams = @{ WheelhousePath = $cfg.WheelhousePath }
    foreach ($name in 'SmtpServer', 'MailTo', 'MailFrom') {
        if ($PSBoundParameters.ContainsKey($name)) {
            $alertParams[$name -replace '^Mail', ''] = $PSBoundParameters[$name]
        }
    }
    $alertParamsIn = @{
        AuditResult     = $auditResults.ToArray()
        Notice          = $notices.ToArray()
        CheckError      = $checkErrors.ToArray()
        AlertParameters = $alertParams
    }
    $alertParams = Get-VulnerabilityAlertParameter @alertParamsIn
    $alertExitCode = 0
    if ($null -ne $alertParams) {
        if (Test-Path -Path $sendAlertScriptPath) {
            & $sendAlertScriptPath @alertParams | Out-Host
            $alertExitCode = $LASTEXITCODE
            Write-Log "Send-VulnerabilityAlert.ps1 finished with exit code $alertExitCode."
        }
        else {
            Write-Log "Send-VulnerabilityAlert.ps1 not found at: $sendAlertScriptPath - cannot send the alert." 'ERROR'
            $alertExitCode = 2
        }
    }

    $incomplete = ($checkErrors.Count -gt 0) -or [bool]($auditResults | Where-Object { $_.Status -eq 'Error' })
    $findings = ($notices.Count -gt 0) -or [bool]($auditResults | Where-Object { $_.Status -eq 'Vulnerable' })
    if ($incomplete -or $alertExitCode -ne 0) {
        $exitCode = Get-WheelhouseExitCode -Outcome Error
        $outcome = $(if ($incomplete) { 'a check could not be completed' } else { 'the alert could not be delivered' })
    }
    elseif ($findings) {
        $exitCode = Get-WheelhouseExitCode -Outcome Attention
        $outcome = 'findings'
    }
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    $exitCode = Get-WheelhouseExitCode -ErrorRecord $_
    $outcome = 'ABORTED'
}
finally {
    Stop-WheelhouseRun -Title $title -Outcome $outcome
}

exit $exitCode
