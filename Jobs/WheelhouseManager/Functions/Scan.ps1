# ---------------------------------------------------------------------------
# Microsoft Defender scan of the wheelhouse (whole folder or chosen files)
# ---------------------------------------------------------------------------

function Test-WheelhouseDefenderAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return [bool](Get-Command Start-MpScan -ErrorAction SilentlyContinue)
}

function Invoke-MpScan {
    # Thin wrapper so the scan itself can be replaced in tests.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Start-MpScan -ScanPath $Path -ScanType CustomScan -ErrorAction Stop
}

function Get-WheelhouseThreatDetection {
    # Defender threat detections raised since -Since, as { Resource; ThreatName; ThreatId; ActionSuccess }.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$Since
    )

    $detections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $Since })
    foreach ($detection in $detections) {
        $threatName = ''
        try { $threatName = [string](Get-MpThreat -ThreatID $detection.ThreatID -ErrorAction Stop | Select-Object -First 1).ThreatName }
        catch { Write-Verbose "Threat name for ID $($detection.ThreatID) could not be read." }
        foreach ($resource in @($detection.Resources)) {
            [PSCustomObject]@{
                Resource      = [string]$resource
                ThreatName    = $threatName
                ThreatId      = [string]$detection.ThreatID
                ActionSuccess = [bool]$detection.ActionSuccess
            }
        }
    }
}

function Invoke-WheelhouseDefenderScan {
    # Scans each path (a folder or a file) with Microsoft Defender and returns a
    # Wheelhouse.ScanResult. Status:
    #   Clean  - every scan finished and Defender raised no detection for the paths
    #   Threat - Defender raised at least one detection
    #   Error  - Defender is unavailable or a scan failed; this is NOT a clean result
    # With -ReportsFolder the result is also saved as Report_Scan_<timestamp>.json.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Path,

        [string]$ReportsFolder
    )

    $started = Get-Date
    $threats = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $scanned = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-WheelhouseDefenderAvailable)) {
        $errors.Add('Start-MpScan is not available on this machine (Microsoft Defender is not installed or not accessible).')
        Write-Log $errors[0] 'WARN'
    }
    else {
        foreach ($item in $Path) {
            Write-Log "Starting Microsoft Defender scan: $item"
            try {
                Invoke-MpScan -Path $item
                $scanned.Add($item)
                Write-Log "Microsoft Defender scan finished: $item" 'OK'
            }
            catch {
                $errors.Add("Defender scan of '$item' failed: $($_.Exception.Message)")
                Write-Log $errors[$errors.Count - 1] 'ERROR'
            }
        }

        if ($scanned.Count -gt 0) {
            try {
                # A small margin covers clock rounding between this script and Defender.
                $detections = @(Get-WheelhouseThreatDetection -Since $started.AddSeconds(-5))
                foreach ($detection in $detections) {
                    foreach ($item in $scanned) {
                        if ($detection.Resource.IndexOf($item, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $threats.Add($detection)
                            break
                        }
                    }
                }
            }
            catch {
                $errors.Add("Defender scan results could not be read: $($_.Exception.Message)")
                Write-Log $errors[$errors.Count - 1] 'ERROR'
            }
        }
    }

    # A detection outranks a failed scan; a failed scan is never Clean.
    $status = 'Clean'
    $message = 'Microsoft Defender found no threats.'
    if ($threats.Count -gt 0) {
        $status = 'Threat'
        $message = "Microsoft Defender detected $($threats.Count) threat(s). $($errors -join ' ')".Trim()
    }
    elseif ($errors.Count -gt 0) {
        $status = 'Error'
        $message = $errors -join ' '
    }

    $level = switch ($status) { 'Clean' { 'OK' } default { 'ERROR' } }
    Write-Log "Defender scan result: $status. $message" $level

    $result = [PSCustomObject]@{
        PSTypeName   = 'Wheelhouse.ScanResult'
        Status       = $status
        Message      = $message
        ScanTime     = $started.ToString('yyyy-MM-dd HH:mm:ss')
        ScannedPaths = $scanned.ToArray()
        Threats      = $threats.ToArray()
        ReportPath   = $null
    }

    if ($ReportsFolder -and (Test-Path -Path $ReportsFolder)) {
        $reportFile = Join-Path $ReportsFolder "Report_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        Write-JsonFile -Path $reportFile -InputObject $result -Depth 4
        $result.ReportPath = $reportFile
        Write-Log "Scan report saved to: $reportFile"
    }
    return $result
}
