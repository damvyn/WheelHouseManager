<#
.SYNOPSIS
    Scheduled check of everything already published: integrity, vulnerabilities, denylist
    and PyPI yanked flag, with one automatic alert on any finding. Intended for the
    Scheduled Task.

.DESCRIPTION
    A package that passed every check when it entered the wheelhouse can fail one later:
    a new vulnerability is published, the release is yanked, someone denylists it, or the
    file server's antivirus removes or changes the wheel on the share. This script
    re-checks all of that.

    It does not virus-scan the share - the file server's own antivirus does that. When that
    antivirus moves a wheel to its quarantine, the integrity check here notices the missing
    file. Then, with AutoQuarantine on (the default), the version is taken out of the group
    files and the manifest and denylisted; a wheel whose content changed is quarantined as
    evidence. With AutoQuarantine off, it is only reported.

    Otherwise it changes nothing: no merge from Input\requirements.txt and no download. It
    only records the results in the package catalog and history. Update-Wheelhouse.ps1
    (merge + download) stays a manual, deliberate action taken after a requirements.txt
    change is approved.

    Steps:
      1. Checks python / pip-audit are usable (installs or upgrades them if needed).
      2. Verifies wheelhouse integrity against manifest.json (every tracked file's hash
         must still match). Wheels missing or changed on the share are handled as above.
         Any other problem (a file that cannot be read, a broken manifest record) stops
         the run.
      3. Checks every published version against the denylist and PyPI's yanked flag.
      4. For every group file (also when the manifest is still empty), runs pip-audit
         against each configured vulnerability service.
      5. Records the results in the catalog (the UI's package table and history).
      6. If anything was found OR a check could not be completed, calls
         Send-VulnerabilityAlert.ps1 once with every such result. A failed check is never
         reported as "no problems".

    Exit codes: 0 OK; 1 findings (needs attention); 2 aborted, a check could not be
    completed, or the alert could not be sent.

.PARAMETER WheelhousePath
    UNC or local path to the wheelhouse. Optional if set in config\settings.psd1.

.PARAMETER VulnerabilityServices
    pip-audit vulnerability service(s) to check (default: osv, pypi, or the value in
    config\settings.psd1).

.PARAMETER AutoQuarantine
    On or Off for this run, overriding the AutoQuarantine setting (default On).

.PARAMETER SmtpServer
.PARAMETER MailTo
.PARAMETER MailFrom
    Passed through to Send-VulnerabilityAlert.ps1 if a finding triggers an alert.
    If omitted, that script falls back to config\settings.psd1 itself.

.EXAMPLE
    .\Test-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse"

.EXAMPLE
    # Report wheels that disappeared from the share, but do not take them out
    .\Test-Wheelhouse.ps1 -AutoQuarantine Off

.NOTES
    Requires the WheelhouseManager module folder and Send-VulnerabilityAlert.ps1 in the
    same folder as this script. Needs no administrator rights.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$WheelhousePath,

    [ValidateSet('osv', 'pypi')]
    [string[]]$VulnerabilityServices,

    [ValidateSet('On', 'Off')]
    [string]$AutoQuarantine,

    [string]$SmtpServer,
    [string]$MailTo,
    [string]$MailFrom
)

$sendAlertScriptPath = (Join-Path $PSScriptRoot 'Send-VulnerabilityAlert.ps1')
Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$whlParams = @{
    'BoundParameters' = $PSBoundParameters
    'Name' = @('WheelhousePath', 'VulnerabilityServices', 'ReportRetentionMonths', 'PythonVersion', 'Platform', 'AutoQuarantine')
}
$cfg = Resolve-WheelhouseParameter @whlParams
# Not $autoQuarantine: variable names are case-insensitive, and that one is the
# -AutoQuarantine parameter, whose ValidateSet would refuse a [bool].
$takeOutChangedWheels = ConvertTo-WheelhouseBoolean $cfg.AutoQuarantine

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
    # Step 1: integrity - and wheels removed or changed outside the manager
    # -----------------------------------------------------------------------

    Write-Log "Loading manifest: $(Get-WheelhouseManifestPath -WheelhousePath $cfg.WheelhousePath)"
    $manifest = Read-WheelhouseManifest -WheelhousePath $cfg.WheelhousePath
    Write-Log "Manifest contains $($manifest.Count) tracked file(s)."

    $published = $manifest
    if ($manifest.Count -eq 0) {
        Write-Log 'Manifest is empty - no published wheels to verify. Group files are still audited.' 'OK'
    }
    else {
        $changed = @(Assert-WheelhouseIntegrity -Manifest $manifest -WheelhousePath $cfg.WheelhousePath -ReportsFolder $reportsFolder -AllowChangedFiles)
        if ($changed.Count -gt 0) {
            if ($takeOutChangedWheels) {
                # Taking them out changes the manifest and group files: write lock, waiting
                # for an update's write step if one is in progress.
                $lock = Open-WheelhouseWrite -WheelhousePath $cfg.WheelhousePath -TimeoutSeconds 300
                try {
                    $resolved = @(Resolve-WheelhouseIntegrityProblem -WheelhousePath $cfg.WheelhousePath -Problem $changed -AutoQuarantine)
                }
                finally {
                    Exit-WheelhouseLock -Lock $lock
                }
                $manifest = Read-WheelhouseManifest -WheelhousePath $cfg.WheelhousePath
            }
            else {
                $resolved = @(Resolve-WheelhouseIntegrityProblem -WheelhousePath $cfg.WheelhousePath -Problem $changed)
            }
            foreach ($notice in $resolved) { $notices.Add($notice) }
            $gone = @($changed | ForEach-Object { [string]$_.Entry.file })
            $published = @($manifest | Where-Object { $gone -notcontains [string]$_.file })
        }
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
    # Step 4: record the results in the catalog (the UI shows them from there)
    # -----------------------------------------------------------------------

    $catalogAudits = $auditResults.ToArray()
    $catalogChecked = @($deployed.Checked)
    $catalogServices = $cfg.VulnerabilityServices
    try {
        Update-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath -Update ({
                param($catalog)
                Update-CatalogAuditResult -Catalog $catalog -AuditResult $catalogAudits -Services $catalogServices
                Update-CatalogPyPIResult -Catalog $catalog -Checked $catalogChecked
            }.GetNewClosure())
    }
    catch {
        # Otherwise the UI would keep showing the previous results as current.
        $checkErrors.Add("The results could not be recorded in the package catalog: $($_.Exception.Message)")
        Write-Log $checkErrors[$checkErrors.Count - 1] 'ERROR'
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
