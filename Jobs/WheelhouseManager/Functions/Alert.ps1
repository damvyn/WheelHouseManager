# ---------------------------------------------------------------------------
# Vulnerability alert: findings from pip-audit reports, HTML body, triggering
# ---------------------------------------------------------------------------

function New-WheelhouseNotice {
    # A finding that needs an administrator but is not a pip-audit result: a published
    # version that is denylisted or yanked, a wheel that was removed or changed outside the
    # manager (e.g. by the file server's antivirus), a download that failed verification or
    # was detected at intake. Scripts emit these next to their
    # Wheelhouse.AuditResult objects, and the alert lists them in a section of their own.
    # Only builds an object - nothing to confirm.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Denylisted', 'Yanked', 'FileMissing', 'FileModified', 'IntakeBlocked', 'Malicious', 'Unverified', 'Untracked')]
        [string]$Kind,

        [AllowEmptyString()]
        [string]$Package = '',

        [AllowEmptyString()]
        [string]$Version = '',

        [AllowEmptyCollection()]
        [string[]]$File = @(),

        [Parameter(Mandatory)]
        [string]$Message,

        # What the administrator should do; a sensible default exists for every kind.
        [string]$Action
    )

    if (-not $Action) {
        $Action = switch ($Kind) {
            'Denylisted' { 'Quarantine or delete it (UI: Packages tab). The denylist only stops new downloads; this version is still installable.' }
            'Yanked' { 'Read the yank reason on PyPI. Pin another version in requirements.in, re-run Update-Requirement.ps1 and Update-Wheelhouse.ps1, then quarantine this one.' }
            'FileMissing' { "Check the file server's antivirus log and quarantine for this file, then quarantine or delete the version (UI: Packages tab)." }
            'FileModified' { 'Quarantine the version now (UI: Packages tab) and find out who or what changed the file.' }
            'IntakeBlocked' { 'Nothing was published. Find out why the download differed or was detected before trying this version again.' }
            'Malicious' { 'Quarantine the version now (UI: Packages tab) and find out which clients installed it.' }
            'Untracked' { 'Remove the files from the wheelhouse folder and publish the packages you need through Update-Wheelhouse.ps1.' }
            'Unverified' { 'Find out why the audits fail (network, proxy, pip-audit) - see the run log in the reports folder. Until an audit completes, new vulnerabilities in this version go unnoticed.' }
        }
    }
    return [PSCustomObject]@{
        PSTypeName = 'Wheelhouse.Notice'
        Kind       = $Kind
        Package    = $Package
        Version    = $Version
        Files      = @($File)
        Message    = $Message
        Action     = $Action
    }
}

function Get-VulnerabilityFinding {
    # Reads pip-audit reports and returns one finding per package/version/vulnerability.
    # The same vulnerability reported by several services or groups is merged into a
    # single finding. Reports that can't be read are returned in Errors - they are
    # never silently treated as "no vulnerabilities".
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowEmptyCollection()]
        [string[]]$ReportPaths = @()
    )

    $findings = [ordered]@{}
    $errors = [System.Collections.Generic.List[string]]::new()

    foreach ($reportPath in $ReportPaths) {
        Write-Log "Reading report: $reportPath"
        $info = Get-AuditReportInfo -Path $reportPath
        $service = if ($info) { $info.Service } else { 'Unknown' }
        # Reports of candidate audits (Invoke-CandidateIntake) are named <group>-candidates:
        # those packages were blocked before download and are not in the wheelhouse.
        $isCandidate = [bool]($info -and $info.Group -and $info.Group.EndsWith('-candidates'))
        $group = if ($info -and $info.Group) { $info.Group -replace '-candidates$', '' } else { $null }
        $groupFile = if ($group) { "$group.txt" } else { $null }

        try {
            $dependencies = Get-PipAuditReport -Path $reportPath
        }
        catch {
            Write-Log $_.Exception.Message 'WARN'
            $errors.Add("Report could not be read: $($_.Exception.Message)")
            continue
        }

        foreach ($dependency in $dependencies) {
            foreach ($vuln in @($dependency.vulns)) {
                if ($null -eq $vuln) { continue }

                $key = "$(Get-NormalizedPackageName $dependency.name)|$($dependency.version)|$($vuln.id)"
                if (-not $findings.Contains($key)) {
                    $findings[$key] = [PSCustomObject]@{
                        Package        = $dependency.name
                        NormalizedName = Get-NormalizedPackageName $dependency.name
                        Version        = $dependency.version
                        VulnId         = $vuln.id
                        Aliases        = (@($vuln.aliases) | Where-Object { $_ }) -join ', '
                        Description    = $vuln.description
                        FixVersions    = (@($vuln.fix_versions) | Where-Object { $_ }) -join ', '
                        Services       = [System.Collections.Generic.List[string]]::new()
                        GroupFiles     = [System.Collections.Generic.List[string]]::new()
                        Deployed       = $false
                    }
                }
                $finding = $findings[$key]
                if (-not $isCandidate) { $finding.Deployed = $true }
                if (-not $finding.Services.Contains($service)) { $finding.Services.Add($service) }
                if ($groupFile -and -not $finding.GroupFiles.Contains($groupFile)) { $finding.GroupFiles.Add($groupFile) }
            }
        }
    }

    return @{ Findings = @($findings.Values); Errors = $errors.ToArray() }
}

function ConvertTo-VulnerabilityAlertHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()]
        [object[]]$Findings = @(),

        [AllowEmptyCollection()]
        [string[]]$AuditErrors = @(),

        # Wheelhouse.Notice objects (New-WheelhouseNotice).
        [AllowEmptyCollection()]
        [object[]]$Notices = @(),

        [AllowEmptyString()]
        [string]$WheelhousePath
    )

    # Loaded once for every finding's quarantine lookup, instead of once per finding.
    $manifest = $null
    if (-not [string]::IsNullOrWhiteSpace($WheelhousePath)) {
        try { $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath } catch { $manifest = $null }
    }

    $sections = [System.Text.StringBuilder]::new()

    if ($Notices.Count -gt 0) {
        $noticeRows = foreach ($notice in $Notices) {
            $pin = if ($notice.Package) { "$($notice.Package)==$($notice.Version)" } else { '' }
            $filesHtml = (@($notice.Files) | Where-Object { $_ } | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join '<br/>'
            @"
<tr>
  <td>$(ConvertTo-HtmlSafe $notice.Kind)</td>
  <td>$(ConvertTo-HtmlSafe $pin)</td>
  <td>$filesHtml</td>
  <td>$(ConvertTo-HtmlSafe $notice.Message)</td>
  <td>$(ConvertTo-HtmlSafe $notice.Action)</td>
</tr>
"@
        }
        [void]$sections.AppendLine(@"
<h3>Packages that need attention ($($Notices.Count))</h3>
<table>
  <tr>
    <th>Kind</th>
    <th>Package</th>
    <th>File(s)</th>
    <th>Details</th>
    <th>Recommended Action</th>
  </tr>
  $($noticeRows -join "`n")
</table>
"@)
    }

    # Findings from the catalog (Get-CatalogFindingAlert) carry a severity, a due date and
    # why they are alerted; resolved ones get a short section of their own.
    $resolved = @($Findings | Where-Object { $_.PSObject.Properties['AlertReason'] -and $_.AlertReason -eq 'Resolved' })
    $Findings = @($Findings | Where-Object { -not ($_.PSObject.Properties['AlertReason'] -and $_.AlertReason -eq 'Resolved') })
    $tracked = [bool]($Findings | Where-Object { $_.PSObject.Properties['Severity'] })
    if ($tracked) {
        $order = @{ Overdue = 0; Reminder = 0; WaiverExpired = 1; New = 2 }
        $Findings = @($Findings | Sort-Object @{ Expression = { if ($_.AlertReason -and $order.ContainsKey([string]$_.AlertReason)) { $order[[string]$_.AlertReason] } else { 3 } } }, @{ Expression = { Get-SeverityRank -Severity $_.Severity }; Descending = $true }, Package, VulnId)
    }

    if ($Findings.Count -gt 0) {
        $affectedPackages = ($Findings | Select-Object -ExpandProperty Package -Unique) -join ', '
        [void]$sections.AppendLine("<p><b>$($Findings.Count)</b> vulnerability finding(s) affecting package(s): <b>$(ConvertTo-HtmlSafe $affectedPackages)</b></p>")
        if ($tracked) {
            $overdue = @($Findings | Where-Object { $_.Status -eq 'Overdue' }).Count
            $fresh = @($Findings | Where-Object { $_.AlertReason -in 'New', 'WaiverExpired' }).Count
            [void]$sections.AppendLine("<p>New: <b>$fresh</b>, overdue: <b>$overdue</b>. Findings already alerted and not yet due are listed again for completeness. A finding you have decided to accept can be waived until a date (UI: package History).</p>")
        }

        $rows = [System.Text.StringBuilder]::new()
        foreach ($finding in $Findings) {
            $quarantineParams = @{
                WheelhousePath = $WheelhousePath
                NormalizedName = $finding.NormalizedName
                Version        = $finding.Version
            }
            if ($null -ne $manifest) { $quarantineParams['Manifest'] = $manifest }
            $quarantineFilesHtml = (Get-QuarantineFileName @quarantineParams | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join '<br/>'

            $requirementsLine = "$($finding.NormalizedName)==$($finding.Version)"
            $groupFiles = if ($finding.GroupFiles.Count -gt 0) { $finding.GroupFiles -join ', ' } else { 'the wheelhouse group file(s) (requirements-N.txt)' }

            $fixNote = if ($finding.FixVersions) {
                " (suggested fix version: <b>$(ConvertTo-HtmlSafe $finding.FixVersions)</b>, subject to the cooldown policy)."
            }
            else {
                ' (no fix version is currently published - consider removing the dependency or accepting the risk with sign-off).'
            }

            if ($finding.Deployed) {
                $recommendation = "1) Remove or update the line <code>$(ConvertTo-HtmlSafe $requirementsLine)</code> in $(ConvertTo-HtmlSafe $groupFiles)$fixNote"
                $recommendation += "<br/>2) Move the following wheel file(s) to the quarantine folder:<br/>$quarantineFilesHtml"
            }
            else {
                $recommendation = "<b>Blocked before download</b> - this version was NOT added to the wheelhouse ($(ConvertTo-HtmlSafe $groupFiles)). "
                $recommendation += "Change or remove it in requirements.in and re-run Update-Requirement.ps1$fixNote"
            }

            $trackedCells = ''
            if ($tracked) {
                $due = if ($finding.Due) { ([string]$finding.Due).Substring(0, 10) } else { '' }
                $state = switch ([string]$finding.AlertReason) {
                    'New' { 'NEW' }
                    'Overdue' { 'OVERDUE' }
                    'Reminder' { 'OVERDUE (reminder)' }
                    'WaiverExpired' { 'waiver ended' }
                    default { $(if ($finding.Status -eq 'Overdue') { 'overdue' } else { 'open' }) }
                }
                $score = if ($null -ne $finding.Score) { " ($($finding.Score))" } else { '' }
                $trackedCells = "`n  <td>$(ConvertTo-HtmlSafe "$($finding.Severity)$score")</td>`n  <td>$(ConvertTo-HtmlSafe $due)</td>`n  <td>$(ConvertTo-HtmlSafe $state)</td>"
            }
            [void]$rows.AppendLine(@"
<tr>$trackedCells
  <td>$(ConvertTo-HtmlSafe $finding.Package)</td>
  <td>$(ConvertTo-HtmlSafe $finding.Version)</td>
  <td>$(ConvertTo-HtmlSafe $finding.VulnId)</td>
  <td>$(ConvertTo-HtmlSafe $finding.Aliases)</td>
  <td>$(ConvertTo-HtmlSafe ($finding.Services -join ', '))</td>
  <td>$(ConvertTo-HtmlSafe $finding.Description)</td>
  <td>$recommendation</td>
</tr>
"@)
        }

        $trackedHeaders = if ($tracked) { "`n    <th>Severity</th>`n    <th>Fix by</th>`n    <th>Status</th>" } else { '' }
        [void]$sections.AppendLine(@"
<table>
  <tr>$trackedHeaders
    <th>Package</th>
    <th>Version</th>
    <th>Vulnerability ID</th>
    <th>Aliases (CVE/GHSA)</th>
    <th>Source</th>
    <th>Description</th>
    <th>Recommended Action</th>
  </tr>
  $($rows.ToString())
</table>
"@)
    }

    if ($resolved.Count -gt 0) {
        $items = ($resolved | ForEach-Object { "<li>$(ConvertTo-HtmlSafe "$($_.Package)==$($_.Version)"): $(ConvertTo-HtmlSafe $_.VulnId) is no longer reported</li>" }) -join "`n"
        [void]$sections.AppendLine(@"
<h3>Resolved since the last alert ($($resolved.Count))</h3>
<ul>
$items
</ul>
"@)
    }

    if ($AuditErrors.Count -gt 0) {
        $items = ($AuditErrors | ForEach-Object { "<li>$(ConvertTo-HtmlSafe $_)</li>" }) -join "`n"
        [void]$sections.AppendLine(@"
<h3>Audits that could not be completed ($($AuditErrors.Count))</h3>
<p>The following audit(s) failed without producing a usable result. The affected groups have <b>not</b> been checked
for vulnerabilities in this run - review the run log in the reports folder.</p>
<ul>
$items
</ul>
"@)
    }

    return @"
<html>
<head>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; font-size: 13px; color: #222; }
  h2 { color: #b00020; }
  table { border-collapse: collapse; width: 100%; margin-top: 12px; }
  th { background-color: #b00020; color: #fff; text-align: left; padding: 6px 8px; }
  td { border: 1px solid #ddd; padding: 6px 8px; vertical-align: top; }
  tr:nth-child(even) { background-color: #f7f7f7; }
  code { background-color: #eee; padding: 1px 4px; border-radius: 3px; }
</style>
</head>
<body>
  <h2>Wheelhouse Security Alert from ${env:Computername}</h2>
  $($sections.ToString())
  <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
  <p style="margin-top:16px; color:#666; font-size:11px;">
    This is an automated alert generated by the wheelhouse vulnerability audit pipeline.
    Recommended actions require manual review before being applied.
  </p>
</body>
</html>
"@
}

function Get-VulnerabilityAlertParameter {
    # Builds the parameters for ONE Send-VulnerabilityAlert.ps1 call covering every
    # non-passing audit result (Vulnerable results as -ReportPaths, Error results as
    # -AuditErrors), every notice (-Notices) and every check that could not be completed
    # (-CheckError, added to -AuditErrors). Returns $null if there is nothing to alert on.
    #
    # The caller invokes the alert script itself - a script run from inside a module
    # function would execute in the module's scope and break its $script: variables.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$AuditResult,

        [AllowEmptyCollection()]
        [object[]]$Notice = @(),

        [AllowEmptyCollection()]
        [string[]]$CheckError = @(),

        # Tracked findings (Get-CatalogFindingAlert). When given, they replace the
        # Vulnerable reports of published packages: an alert is due only for findings with
        # an AlertReason, and then lists every open finding. Vulnerable candidate audits
        # (Stage PreDownload - blocked before publishing) are still reported as reports.
        [AllowEmptyCollection()]
        [object[]]$Finding,

        # Extra parameters passed through to the alert script (SmtpServer, To, ...).
        [hashtable]$AlertParameters = @{}
    )

    $vulnerable = @($AuditResult | Where-Object { $_.Status -eq 'Vulnerable' })
    $failed = @($AuditResult | Where-Object { $_.Status -eq 'Error' })
    $notices = @($Notice | Where-Object { $_ })
    $checkErrors = @($CheckError | Where-Object { $_ })
    $useFindings = $PSBoundParameters.ContainsKey('Finding')
    $alertFindings = @()
    if ($useFindings) {
        $vulnerable = @($vulnerable | Where-Object { $_.Stage -eq 'PreDownload' })
        if (@($Finding | Where-Object { $_ -and $_.AlertReason }).Count -gt 0) {
            $alertFindings = @($Finding | Where-Object { $_ -and ($_.AlertReason -or $_.Status -in 'Open', 'Overdue') })
        }
    }

    if ($vulnerable.Count -eq 0 -and $alertFindings.Count -eq 0 -and $failed.Count -eq 0 -and $notices.Count -eq 0 -and $checkErrors.Count -eq 0) {
        Write-Log 'All audits and checks passed, or every finding was already alerted - no alert needed.' 'OK'
        return $null
    }

    Write-Log "$($vulnerable.Count + $alertFindings.Count) vulnerability result(s)/finding(s), $($failed.Count + $checkErrors.Count) audit(s)/check(s) could not be completed, $($notices.Count) package notice(s). Triggering alert..." 'ERROR'

    $alertParams = @{} + $AlertParameters
    if ($vulnerable.Count -gt 0) {
        $alertParams['ReportPaths'] = [string[]]@($vulnerable | ForEach-Object { $_.ReportPath })
    }
    if ($alertFindings.Count -gt 0) {
        $alertParams['Findings'] = $alertFindings
    }
    $errors = @($failed | ForEach-Object { "$($_.Group) / $($_.Service.ToUpperInvariant()): $($_.Message)" }) + $checkErrors
    if ($errors.Count -gt 0) {
        $alertParams['AuditErrors'] = [string[]]$errors
    }
    if ($notices.Count -gt 0) {
        $alertParams['Notices'] = $notices
    }
    return $alertParams
}
