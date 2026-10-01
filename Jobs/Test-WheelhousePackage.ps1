<#
.SYNOPSIS
    Audits the whole wheelhouse index or chosen packages for known vulnerabilities.
    Does not send alerts.

.DESCRIPTION
    Without -Package, every requirement group file is audited against every configured
    vulnerability service (like Test-Wheelhouse.ps1, but with no alert mail - this is
    the script behind the UI's "Audit" buttons).

    With -Package, only those name==version pins are audited. They must be tracked
    in manifest.json.

    Writes one Wheelhouse.AuditResult per audit to the output stream and exits 1 if
    any audit found a vulnerability or could not be completed.

.PARAMETER WheelhousePath
    Wheelhouse folder. Optional if set in config\settings.psd1.

.PARAMETER Package
    Pins to audit, as name==version. A single comma-separated string is accepted too
    ("numpy==2.0.0,pandas==2.2.0").

.PARAMETER VulnerabilityServices
    pip-audit service(s) to use (default: osv, pypi).

.EXAMPLE
    .\Test-WheelhousePackage.ps1 -Package numpy==2.0.0,pandas==2.2.0
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$WheelhousePath,

    [string[]]$Package,

    [ValidateSet('osv', 'pypi')]
    [string[]]$VulnerabilityServices
)

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$cfg = Resolve-WheelhouseParameter -BoundParameters $PSBoundParameters `
    -Name WheelhousePath, VulnerabilityServices, ReportRetentionMonths

$title = 'Wheelhouse package audit'
$outcome = $null
$exitCode = 0
$auditResults = [System.Collections.Generic.List[object]]::new()

try {
    $reportsFolder = Start-WheelhouseRun -WheelhousePath $cfg.WheelhousePath -Title $title -LogPrefix 'Log_PackageAudit' -RetentionMonths $cfg.ReportRetentionMonths
    Confirm-PythonAndTooling

    $manifest = Read-WheelhouseManifest -WheelhousePath $cfg.WheelhousePath
    Write-Log "Manifest contains $($manifest.Count) tracked file(s)."

    # A comma-separated string (how the UI passes a list) is split here.
    $pins = @($Package | ForEach-Object { $_ -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    if ($pins.Count -gt 0) {
        $packages = @{}
        foreach ($pin in $pins) {
            if ($pin -notmatch '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)$') {
                throw "Not a name==version pin: '$pin'"
            }
            $name = Get-NormalizedPackageName $Matches['name']
            $version = $Matches['version']
            if (-not ($manifest | Where-Object { $_.name -eq $name -and $_.version -eq $version })) {
                throw "$name==$version is not tracked in the wheelhouse manifest."
            }
            $packages[$name] = $version
        }
        Write-Log "Auditing $($packages.Count) selected package(s)..."
        $auditParams = @{ Packages = $packages; Services = $cfg.VulnerabilityServices; ReportsFolder = $reportsFolder }
        $results = Invoke-PackageAudit @auditParams
        foreach ($result in $results) { $auditResults.Add($result) }
    }
    else {
        $groupFiles = Get-WheelhouseGroupFile -WheelhousePath $cfg.WheelhousePath
        if ($groupFiles.Count -eq 0) {
            Write-Log 'No requirement group files found in the wheelhouse - nothing to audit.' 'WARN'
        }
        foreach ($groupFile in $groupFiles) {
            Write-Log "--- Group: $([System.IO.Path]::GetFileNameWithoutExtension($groupFile)) ---"
            $groupAuditParams = @{
                'GroupFile' = $groupFile
                'Services' = $cfg.VulnerabilityServices
                'Stage' = 'Manual'
                'ReportsFolder' = $reportsFolder
            }
            $groupResults = Invoke-GroupAudit @groupAuditParams
            foreach ($result in $groupResults) { $auditResults.Add($result) }
        }
    }

    $bad = @($auditResults | Where-Object { $_.Status -ne 'Passed' })
    if ($bad.Count -gt 0) {
        $exitCode = 1
        $outcome = 'findings or failed audits'
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

$auditResults.ToArray()
exit $exitCode
