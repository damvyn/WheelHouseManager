# ---------------------------------------------------------------------------
# Script run lifecycle: reports folder, transcript, retention
# ---------------------------------------------------------------------------

function Remove-ExpiredReport {
    # Removes Log_*.txt, Report_*.json and Alert_*.html older than the retention
    # window from the reports folder.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$ReportsFolder,

        [Parameter(Mandatory)]
        [ValidateRange(1, 1200)]
        [int]$RetentionMonths
    )

    $cutoff = (Get-Date).AddMonths(-$RetentionMonths)
    $expired = @(Get-ChildItem -Path $ReportsFolder -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^(Log_.*\.txt|Report_.*\.json|Alert_.*\.html)$' -and $_.LastWriteTime -lt $cutoff })
    if ($expired.Count -eq 0) { return }

    Write-Log "Removing $($expired.Count) log/report file(s) older than $RetentionMonths month(s)..."
    foreach ($file in $expired) {
        if (-not $PSCmdlet.ShouldProcess($file.FullName, 'Remove expired report')) { continue }
        try {
            Remove-Item -Path $file.FullName -Force -ErrorAction Stop
        }
        catch {
            Write-Log "Could not remove old file '$($file.Name)': $($_.Exception.Message)" 'WARN'
        }
    }
}

function Start-WheelhouseRun {
    # Common start of every wheelhouse script: checks the wheelhouse is reachable,
    # creates <wheelhouse>\reports, starts a transcript there, and applies report
    # retention. Returns the reports folder path. Throws if the wheelhouse is
    # unreachable.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$LogPrefix,

        [int]$RetentionMonths = 0
    )

    if ([string]::IsNullOrWhiteSpace($WheelhousePath)) {
        throw 'WheelhousePath was not supplied and is not set in config\settings.psd1. Pass -WheelhousePath, or run Setup.ps1 with -WheelhousePath first.'
    }

    Write-Log "=== $Title started ==="
    Write-Log "Wheelhouse path: $WheelhousePath"

    if (-not (Test-Path -Path $WheelhousePath)) {
        throw "Wheelhouse path does not exist or is not reachable: $WheelhousePath"
    }

    $reportsFolder = Join-Path $WheelhousePath 'reports'
    if (-not (Test-Path -Path $reportsFolder)) {
        if ($PSCmdlet.ShouldProcess($reportsFolder, 'Create reports folder')) {
            New-Item -ItemType Directory -Path $reportsFolder -Force -ErrorAction Stop | Out-Null
            Write-Log "Created reports folder: $reportsFolder"
        }
    }

    $logFile = Join-Path $reportsFolder "$($LogPrefix)_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $script:CurrentRunLog = $logFile
    try {
        Start-Transcript -Path $logFile -Append -ErrorAction Stop | Out-Null
        Write-Log "Full console output for this run is also being saved to: $logFile"
    }
    catch {
        Write-Log "Could not start transcript logging to $logFile - continuing with console output only. ($($_.Exception.Message))" 'WARN'
    }

    if ($RetentionMonths -gt 0) {
        Remove-ExpiredReport -ReportsFolder $reportsFolder -RetentionMonths $RetentionMonths
    }

    return $reportsFolder
}

function Stop-WheelhouseRun {
    # Common end of every wheelhouse script: final log line, transcript stop, and - with
    # -ExitCode and the EventLog setting on - one Event Log entry (1000 OK, 1001 needs
    # attention, 1002 failed or busy). Safe to call even if the transcript never started.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [string]$Outcome,

        [int]$ExitCode = -1
    )

    $suffix = if ($Outcome) { " ($Outcome)" } else { '' }
    Write-Log "=== $Title finished$suffix ==="
    if ($ExitCode -ge 0) {
        $id = switch ($ExitCode) { 0 { 1000 } 1 { 1001 } default { 1002 } }
        $state = switch ($ExitCode) { 0 { 'finished OK' } 1 { 'finished - needs attention' } 3 { 'did not run - another operation held the lock' } default { 'failed or a check could not be completed' } }
        $log = if ($script:CurrentRunLog) { "`r`nLog: $($script:CurrentRunLog)" } else { '' }
        Write-WheelhouseEventLog -Id $id -Message "$Title $state$suffix (exit code $ExitCode).$log"
    }
    if ($PSCmdlet.ShouldProcess('transcript', 'Stop')) {
        try { Stop-Transcript -ErrorAction Stop | Out-Null } catch { Write-Verbose 'No transcript was running.' }
    }
}
