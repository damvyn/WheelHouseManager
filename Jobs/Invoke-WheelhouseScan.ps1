<#
.SYNOPSIS
    On-demand Microsoft Defender scan of chosen wheels, or of every published wheel.

.DESCRIPTION
    Routine virus scanning of the share is the job of the file server's own antivirus.
    This script is for a second opinion with this server's Defender - for example after an
    alert, or for a package someone doubts.

    It never scans the share directly: Defender reads network paths as the computer
    account, and a policy can skip network files, so such a scan could report Clean
    without reading anything. Instead each wheel is copied to a local folder, its SHA256 is
    checked against manifest.json, and the copy is scanned (Invoke-WheelhouseCopyScan). A
    wheel that cannot be copied or no longer matches its recorded hash is not scanned and
    is reported.

    The result is saved as reports\Report_Scan_<timestamp>.json, recorded in the package
    catalog (the UI's Defender column) and written to the output stream as a
    Wheelhouse.ScanResult. Exit codes: 1 Defender reported a threat; 2 the scan could not
    be completed, a wheel could not be scanned, or the result could not be recorded.

.PARAMETER WheelhousePath
    Wheelhouse folder. Optional if set in config\settings.psd1.

.PARAMETER File
    Wheel file names to scan. A single comma-separated string is accepted too. Without
    it, every wheel in the manifest is scanned.

.EXAMPLE
    .\Invoke-WheelhouseScan.ps1 -File numpy-2.0.0-cp314-cp314-win_amd64.whl

.NOTES
    Start-MpScan needs an elevated PowerShell.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$WheelhousePath,

    [string[]]$File
)

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$cfg = Resolve-WheelhouseParameter -BoundParameters $PSBoundParameters -Name WheelhousePath, ReportRetentionMonths

$title = 'Wheelhouse Defender scan'
$outcome = $null
$exitCode = 0
$scan = $null

try {
    $reportsFolder = Start-WheelhouseRun -WheelhousePath $cfg.WheelhousePath -Title $title -LogPrefix 'Log_Scan' -RetentionMonths $cfg.ReportRetentionMonths

    $names = @($File | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    foreach ($name in $names) {
        if (-not (Test-WheelhouseWheelFileName $name)) {
            throw "Not a wheel file name: '$name'"
        }
    }
    Write-Log $(if ($names.Count -gt 0) { "Scanning $($names.Count) selected wheel(s)." } else { 'Scanning every published wheel.' })

    $scan = Invoke-WheelhouseCopyScan -WheelhousePath $cfg.WheelhousePath -File $names -ReportsFolder $reportsFolder

    # The UI's package table shows the results from the catalog.
    $catalogScan = $scan
    try {
        Update-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath -Update ({
                param($catalog)
                Update-CatalogScanResult -Catalog $catalog -ScanResult $catalogScan
            }.GetNewClosure())
    }
    catch {
        Write-Log "The result could not be recorded in the package catalog: $($_.Exception.Message)" 'ERROR'
        $exitCode = Get-WheelhouseExitCode -Outcome Error
        $outcome = 'result not recorded'
    }

    if ($scan.Status -eq 'Threat') {
        $exitCode = Get-WheelhouseExitCode -Outcome Attention
        $outcome = $scan.Status
    }
    elseif ($scan.Status -ne 'Clean' -or @($scan.NotScanned).Count -gt 0) {
        $exitCode = Get-WheelhouseExitCode -Outcome Error
        $outcome = $(if ($scan.Status -ne 'Clean') { $scan.Status } else { 'some wheels were not scanned' })
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

$scan
exit $exitCode
