# ---------------------------------------------------------------------------
# Microsoft Defender: intake scans of staged downloads, on-demand scans of local copies
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

function Invoke-WheelhouseCopyScan {
    # On-demand Defender scan of published wheels that does not depend on how Defender
    # treats the share. Defender reads network paths as the computer account, and a policy
    # can skip network files altogether, so a scan of the share could report Clean without
    # reading anything. Instead, the wheels (-File, or every tracked wheel) are copied to a
    # local staging folder, each copy's SHA256 is checked against the manifest, and the
    # copies are scanned. A detection in a copy applies to the share file: both have the
    # hash recorded at publish.
    # Returns a Wheelhouse.ScanResult naming the wheelhouse files (ScannedPaths,
    # Threats.Resource), so it is recorded like a scan of the share; Status describes the
    # scanned files. Wheels that could not be copied or whose hash differs are not scanned
    # and are listed in NotScanned (the integrity check deals with those).
    # Routine scanning of the share is the file server's antivirus' job, not this tool's.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        # Wheel file names to scan; none = every wheel in the manifest.
        [AllowEmptyCollection()]
        [string[]]$File = @(),

        [string]$ReportsFolder,

        [string]$StagingRoot = (Join-Path $script:ManagerRoot 'staging')
    )

    $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
    $entries = @(if ($File.Count -gt 0) {
            foreach ($name in $File) {
                $entry = $manifest | Where-Object { $_.file -eq $name } | Select-Object -First 1
                if (-not $entry) { throw [System.Collections.Generic.KeyNotFoundException]::new("$name is not tracked in the wheelhouse manifest.") }
                $entry
            }
        }
        else { $manifest })

    $staging = Join-Path $StagingRoot ('scan-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    $map = [ordered]@{}
    $notScanned = [System.Collections.Generic.List[string]]::new()
    try {
        Write-Log "Copying $($entries.Count) wheel(s) to a local folder for the scan..."
        foreach ($entry in $entries) {
            $source = Join-Path $WheelhousePath ([string]$entry.file)
            $copy = Join-Path $staging ([string]$entry.file)
            try {
                Copy-Item -LiteralPath $source -Destination $copy -ErrorAction Stop
            }
            catch {
                $notScanned.Add("$($entry.file): could not be copied ($($_.Exception.Message))")
                continue
            }
            if ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -ne [string]$entry.sha256) {
                $notScanned.Add("$($entry.file): does not match its recorded hash - not scanned; run Test-Wheelhouse.ps1")
                Remove-Item -LiteralPath $copy -Force
                continue
            }
            $map[[string](Get-Item -LiteralPath $copy).FullName] = [string](Join-Path $WheelhousePath ([string]$entry.file))
        }
        foreach ($text in $notScanned) { Write-Log "  Not scanned: $text" 'WARN' }

        $status = 'Error'
        $message = 'Nothing could be scanned.'
        $scanned = @()
        $threats = @()
        $started = Get-Date
        if ($map.Count -gt 0) {
            $scan = Invoke-WheelhouseDefenderScan -Path @($staging)
            $status = $scan.Status
            $message = $scan.Message
            if (@($scan.ScannedPaths).Count -gt 0) { $scanned = @($map.Values) }
            # Report the share files, not the temporary copies.
            $threats = @(foreach ($threat in @($scan.Threats)) {
                    $resource = [string]$threat.Resource
                    foreach ($copyPath in $map.Keys) {
                        if ($resource.IndexOf($copyPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $resource = [regex]::Replace($resource, [regex]::Escape($copyPath), $map[$copyPath].Replace('$', '$$'), 'IgnoreCase')
                            break
                        }
                    }
                    [PSCustomObject]@{ Resource = $resource; ThreatName = $threat.ThreatName; ThreatId = $threat.ThreatId; ActionSuccess = $threat.ActionSuccess }
                })
        }
        if ($notScanned.Count -gt 0) { $message = "$message $($notScanned.Count) wheel(s) not scanned: $($notScanned -join '; ')".Trim() }

        $result = [PSCustomObject]@{
            PSTypeName   = 'Wheelhouse.ScanResult'
            Status       = $status
            Message      = $message
            ScanTime     = $started.ToString('yyyy-MM-dd HH:mm:ss')
            ScannedPaths = $scanned
            Threats      = $threats
            NotScanned   = $notScanned.ToArray()
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
    finally {
        Remove-Item -Path $staging -Recurse -Force -ErrorAction SilentlyContinue
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
