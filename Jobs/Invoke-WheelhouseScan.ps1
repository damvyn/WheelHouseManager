<#
.SYNOPSIS
    Scans the whole wheelhouse folder, or chosen wheel files, with Microsoft Defender.

.DESCRIPTION
    Without -File, the whole wheelhouse folder is scanned. With -File, only those
    wheel files are scanned (names only, no paths; each must exist in the wheelhouse).

    The result is saved as reports\Report_Scan_<timestamp>.json and written to the
    output stream as a Wheelhouse.ScanResult. The script exits 1 if Defender reported
    a threat, or the scan could not be completed (that is never reported as clean).

.PARAMETER WheelhousePath
    Wheelhouse folder. Optional if set in config\settings.psd1.

.PARAMETER File
    Wheel file names to scan. A single comma-separated string is accepted too.

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
    $paths = @($cfg.WheelhousePath)
    if ($names.Count -gt 0) {
        $paths = foreach ($name in $names) {
            if ([System.IO.Path]::GetFileName($name) -ne $name -or $name -notlike '*.whl') {
                throw "Not a wheel file name: '$name'"
            }
            $fullPath = Join-Path $cfg.WheelhousePath $name
            if (-not (Test-Path -Path $fullPath -PathType Leaf)) {
                throw "File not found in the wheelhouse: $name"
            }
            $fullPath
        }
        Write-Log "Scanning $(@($paths).Count) selected file(s)."
    }
    else {
        Write-Log 'Scanning the whole wheelhouse folder.'
    }

    $scan = Invoke-WheelhouseDefenderScan -Path @($paths) -ReportsFolder $reportsFolder
    if ($scan.Status -ne 'Clean') {
        $exitCode = 1
        $outcome = $scan.Status
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

$scan
exit $exitCode
