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

    A published version that OSV lists as a malicious package (MAL-* advisory) is
    quarantined and denylisted under the same AutoQuarantine switch.

    Otherwise it changes nothing: no merge from Input\requirements.txt and no download. It
    only records the results in the package catalog and history. Update-Wheelhouse.ps1
    (merge + download) stays a manual, deliberate action taken after a requirements.txt
    change is approved.

    Every vulnerability becomes a tracked finding with a severity (looked up on OSV) and a
    fix-by date (DueDays* settings). Alerts are stateful: a finding is alerted when it is
    new, when it becomes overdue (then again every OverdueReminderDays), when its waiver
    ends and when it is resolved - not every week again. Waived findings (accepted risk,
    config\waivers.json) are not alerted until the waiver expires.

    Steps:
      1. Checks python / pip-audit are usable (installs or upgrades them if needed).
      2. Verifies wheelhouse integrity against manifest.json (every tracked file's hash
         must still match). Wheels missing or changed on the share are handled as above.
         Any other problem (a file that cannot be read, a broken manifest record) stops
         the run.
      3. Checks every published version against the denylist and PyPI's yanked flag.
      4. Audits every published version with pip-audit against each configured service,
         packed into as few runs as possible (Invoke-PublishedAudit).
      5. Looks up each advisory's severity on OSV (cached; offline = treated as High) and
         records the results in the catalog (the UI's package table and history),
         including when this check last ran.
      6. Quarantines published versions with a malicious-package advisory (AutoQuarantine)
         and lists versions without a completed audit for AuditFreshnessDays (Unverified).
      7. If there is anything new to say OR a check could not be completed, calls
         Send-VulnerabilityAlert.ps1 once with all of it. A failed check is never
         reported as "no problems".

    Exit codes: 0 OK (also when every open finding is waived); 1 open findings or notices
    (needs attention); 2 aborted, a check could not be completed, or the alert could not be
    sent.

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
    'Name' = @('WheelhousePath', 'VulnerabilityServices', 'ReportRetentionMonths', 'PythonVersion', 'Platform', 'AutoQuarantine',
        'DueDaysCritical', 'DueDaysHigh', 'DueDaysMedium', 'DueDaysLow', 'AuditFreshnessDays', 'OverdueReminderDays')
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
    $waivers = @(Read-WheelhouseWaiver)
    $dueDays = Get-WheelhouseDueDayTable -Settings $cfg

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
        # Full check (every file hashed); it refreshes what the updates' quick check relies on.
        $integrityParams = @{ Manifest = $manifest; WheelhousePath = $cfg.WheelhousePath; ReportsFolder = $reportsFolder; AllowChangedFiles = $true; CachePath = (Get-WheelhouseIntegrityCachePath -WheelhousePath $cfg.WheelhousePath) }
        $changed = @(Assert-WheelhouseIntegrity @integrityParams)
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

        # Wheels nobody published: moved out of the index with AutoQuarantine.
        if ($takeOutChangedWheels) {
            $lock = Open-WheelhouseWrite -WheelhousePath $cfg.WheelhousePath -TimeoutSeconds 300
            try {
                $untrackedNotices = @(Move-UntrackedWheelFile -WheelhousePath $cfg.WheelhousePath -AutoQuarantine)
            }
            finally {
                Exit-WheelhouseLock -Lock $lock
            }
        }
        else {
            $untrackedNotices = @(Move-UntrackedWheelFile -WheelhousePath $cfg.WheelhousePath)
        }
        foreach ($notice in $untrackedNotices) { $notices.Add($notice) }
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
    # Step 3: audit every published version against every configured service - in as
    # few pip-audit runs as possible, whatever the number of group files
    # -----------------------------------------------------------------------

    $auditResults = [System.Collections.Generic.List[object]]::new()
    $publishedAuditParams = @{
        'Manifest' = @($published)
        'Services' = $cfg.VulnerabilityServices
        'Stage' = 'Scheduled'
        'ReportsFolder' = $reportsFolder
    }
    $publishedResults = Invoke-PublishedAudit @publishedAuditParams
    foreach ($result in $publishedResults) { $auditResults.Add($result) }

    # -----------------------------------------------------------------------
    # Step 4: severities, then record the results in the catalog (the UI shows
    # them from there)
    # -----------------------------------------------------------------------

    # Outside the write lock: it may go to the network.
    $catalogSeverity = Get-AuditResultSeverity -AuditResult $auditResults.ToArray() -WheelhousePath $cfg.WheelhousePath
    $catalogAudits = $auditResults.ToArray()
    $catalogChecked = @($deployed.Checked)
    $catalogServices = $cfg.VulnerabilityServices
    $catalogRecorded = $false
    try {
        Update-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath -Update ({
                param($catalog)
                $recordParams = @{
                    Catalog     = $catalog
                    AuditResult = $catalogAudits
                    Services    = $catalogServices
                    Severity    = $catalogSeverity
                    DueDays     = $dueDays
                    Waiver      = $waivers
                }
                Update-CatalogAuditResult @recordParams
                Update-CatalogPyPIResult -Catalog $catalog -Checked $catalogChecked
                # The heartbeat the UI and Update-Wheelhouse.ps1 check.
                $catalog.ScheduledCheckUtc = (Get-Date).ToUniversalTime().ToString('o')
            })
        $catalogRecorded = $true
    }
    catch {
        # Otherwise the UI would keep showing the previous results as current.
        $checkErrors.Add("The results could not be recorded in the package catalog: $($_.Exception.Message)")
        Write-Log $checkErrors[$checkErrors.Count - 1] 'ERROR'
    }

    # -----------------------------------------------------------------------
    # Step 5: malicious packages, versions without a recent audit, findings
    # -----------------------------------------------------------------------

    $findingAlerts = $null
    if ($catalogRecorded) {
        $catalog = Read-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath
        if (@(Get-CatalogMaliciousRecord -Catalog $catalog).Count -gt 0) {
            if ($takeOutChangedWheels) {
                $lock = Open-WheelhouseWrite -WheelhousePath $cfg.WheelhousePath -TimeoutSeconds 300
                try {
                    $resolved = @(Resolve-MaliciousPackage -WheelhousePath $cfg.WheelhousePath -AutoQuarantine)
                }
                finally {
                    Exit-WheelhouseLock -Lock $lock
                }
                $catalog = Read-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath
            }
            else {
                $resolved = @(Resolve-MaliciousPackage -WheelhousePath $cfg.WheelhousePath)
            }
            foreach ($notice in $resolved) { $notices.Add($notice) }
        }

        $unverified = @(Get-CatalogUnverifiedRecord -Catalog $catalog -FreshnessDays $cfg.AuditFreshnessDays)
        foreach ($record in $unverified) {
            $last = if ($record.checks.audit -and $record.checks.audit.last_run) { "the last completed audit was on $(([string]$record.checks.audit.last_run).Substring(0, 10))" } else { 'it has never been audited' }
            $notices.Add((New-WheelhouseNotice -Kind 'Unverified' -Package $record.name -Version $record.version -File @($record.files) -Message "Unverified: $last (more than $($cfg.AuditFreshnessDays) day(s) ago). New vulnerabilities in this version would go unnoticed."))
        }
        if ($unverified.Count -gt 0) {
            Write-Log "$($unverified.Count) published version(s) have no completed audit in the last $($cfg.AuditFreshnessDays) day(s) (Unverified)." 'ERROR'
        }

        $findingAlerts = @(Get-CatalogFindingAlert -Catalog $catalog -ReminderDays $cfg.OverdueReminderDays)
        $openFindings = @($findingAlerts | Where-Object { $_.Status -in 'Open', 'Overdue' })
        $overdueFindings = @($openFindings | Where-Object { $_.Status -eq 'Overdue' })
        $waivedFindings = @($findingAlerts | Where-Object { $_.Status -eq 'Waived' })
        if ($findingAlerts.Count -gt 0) {
            Write-Log "Findings: $($openFindings.Count) open ($($overdueFindings.Count) overdue), $($waivedFindings.Count) waived, $(@($findingAlerts | Where-Object { $_.AlertReason }).Count) to alert."
            foreach ($item in $overdueFindings) {
                Write-Log "  OVERDUE: $($item.Package)==$($item.Version) $($item.VulnId) ($($item.Severity)), fix by $(([string]$item.Due).Substring(0, 10))" 'ERROR'
            }
        }
    }

    # -----------------------------------------------------------------------
    # Step 6: alert on anything new or any failed check, in one call
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
    # Without a recorded catalog, fall back to alerting every vulnerable audit report.
    if ($null -ne $findingAlerts) { $alertParamsIn['Finding'] = $findingAlerts }
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

    # Remember what was alerted - only once it was delivered, so a failed delivery is
    # retried next run.
    if ($null -ne $findingAlerts -and $alertExitCode -eq 0 -and $findingAlerts.Count -gt 0) {
        $alerted = $findingAlerts
        try {
            Update-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath -Update ({
                    param($catalog)
                    Set-CatalogFindingNotified -Catalog $catalog -Finding $alerted
                })
        }
        catch {
            Write-Log "Could not record which findings were alerted ($($_.Exception.Message)); they are alerted again next run." 'WARN'
        }
    }

    $incomplete = ($checkErrors.Count -gt 0) -or [bool]($auditResults | Where-Object { $_.Status -eq 'Error' })
    $findings = if ($null -ne $findingAlerts) {
        ($notices.Count -gt 0) -or [bool]($findingAlerts | Where-Object { $_.Status -in 'Open', 'Overdue' })
    }
    else {
        ($notices.Count -gt 0) -or [bool]($auditResults | Where-Object { $_.Status -eq 'Vulnerable' })
    }
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
    Stop-WheelhouseRun -Title $title -Outcome $outcome -ExitCode $exitCode
}

exit $exitCode
