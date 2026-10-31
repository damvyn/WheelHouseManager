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

    Writes one Wheelhouse.AuditResult per audit to the output stream. Exits 1 if an
    audit found a vulnerability, 2 if an audit could not be completed (never reported as
    clean) or the run aborted.

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

    # A comma-separated string (how the UI passes a list) is accepted too.
    $pins = @(ConvertTo-WheelhousePin -Pin $Package)

    if ($pins.Count -gt 0) {
        $packages = @{}
        foreach ($pin in $pins) {
            if (-not ($manifest | Where-Object { $_.name -eq $pin.Name -and $_.version -eq $pin.Version })) {
                throw "$($pin.Name)==$($pin.Version) is not tracked in the wheelhouse manifest."
            }
            $packages[$pin.Name] = $pin.Version
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

    # The UI's package table shows the results from the catalog.
    $catalogAudits = $auditResults.ToArray()
    $catalogServices = $cfg.VulnerabilityServices
    $recorded = $true
    try {
        Update-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath -Update ({
                param($catalog)
                Update-CatalogAuditResult -Catalog $catalog -AuditResult $catalogAudits -Services $catalogServices
            }.GetNewClosure())
    }
    catch {
        Write-Log "The results could not be recorded in the package catalog: $($_.Exception.Message)" 'ERROR'
        $recorded = $false
    }

    if (-not $recorded -or ($auditResults | Where-Object { $_.Status -eq 'Error' })) {
        $exitCode = Get-WheelhouseExitCode -Outcome Error
        $outcome = $(if ($recorded) { 'an audit could not be completed' } else { 'results not recorded' })
    }
    elseif ($auditResults | Where-Object { $_.Status -eq 'Vulnerable' }) {
        $exitCode = Get-WheelhouseExitCode -Outcome Attention
        $outcome = 'vulnerabilities found'
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

$auditResults.ToArray()
exit $exitCode
