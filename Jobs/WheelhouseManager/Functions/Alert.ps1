# ---------------------------------------------------------------------------
# Vulnerability alert: findings from pip-audit reports, HTML body, triggering
# ---------------------------------------------------------------------------

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

        [AllowEmptyString()]
        [string]$WheelhousePath
    )

    # Loaded once for every finding's quarantine lookup, instead of once per finding.
    $manifest = $null
    if (-not [string]::IsNullOrWhiteSpace($WheelhousePath)) {
        try { $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath } catch { $manifest = $null }
    }

    $sections = [System.Text.StringBuilder]::new()

    if ($Findings.Count -gt 0) {
        $affectedPackages = ($Findings | Select-Object -ExpandProperty Package -Unique) -join ', '
        [void]$sections.AppendLine("<p><b>$($Findings.Count)</b> vulnerability finding(s) affecting package(s): <b>$(ConvertTo-HtmlSafe $affectedPackages)</b></p>")

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

            [void]$rows.AppendLine(@"
<tr>
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

        [void]$sections.AppendLine(@"
<table>
  <tr>
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
  <h2>Wheelhouse Vulnerability Alert from ${env:Computername}</h2>
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
    # non-passing audit result: Vulnerable results as -ReportPaths, Error results as
    # -AuditErrors. Returns $null if every audit passed (nothing to alert on).
    #
    # The caller invokes the alert script itself - a script run from inside a module
    # function would execute in the module's scope and break its $script: variables.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$AuditResult,

        # Extra parameters passed through to the alert script (SmtpServer, To, ...).
        [hashtable]$AlertParameters = @{}
    )

    $vulnerable = @($AuditResult | Where-Object { $_.Status -eq 'Vulnerable' })
    $failed = @($AuditResult | Where-Object { $_.Status -eq 'Error' })

    if ($vulnerable.Count -eq 0 -and $failed.Count -eq 0) {
        Write-Log 'All audits passed. No known vulnerabilities found - no alert needed.' 'OK'
        return $null
    }

    Write-Log "$($vulnerable.Count) audit(s) found vulnerabilities, $($failed.Count) audit(s) could not be completed. Triggering alert..." 'ERROR'

    $alertParams = @{} + $AlertParameters
    if ($vulnerable.Count -gt 0) {
        $alertParams['ReportPaths'] = [string[]]@($vulnerable | ForEach-Object { $_.ReportPath })
    }
    if ($failed.Count -gt 0) {
        $alertParams['AuditErrors'] = [string[]]@($failed | ForEach-Object { "$($_.Group) / $($_.Service.ToUpperInvariant()): $($_.Message)" })
    }
    return $alertParams
}
