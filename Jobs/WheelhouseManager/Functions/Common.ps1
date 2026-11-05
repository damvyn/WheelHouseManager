# ---------------------------------------------------------------------------
# Generic helpers: logging, package-name normalization and validation, HTML
# escaping, file I/O, locks, exit codes
# ---------------------------------------------------------------------------

# The one definition of what a package name, a version and a wheel file name may look
# like wherever one comes from outside (UI requests, -Package/-File/-ExpeditePackage,
# the denylist). Requirement files have their own, more lenient parser.
$script:PackageNamePattern = '^[A-Za-z0-9][A-Za-z0-9._-]*$'
$script:PackageVersionPattern = '^[A-Za-z0-9][A-Za-z0-9._+!-]*$'
$script:WheelFileNamePattern = '^[A-Za-z0-9][A-Za-z0-9._+!-]*\.whl$'

function Test-WheelhousePackageName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Name
    )

    return [bool]($Name -match $script:PackageNamePattern)
}

function Test-WheelhousePackageVersion {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Version
    )

    return [bool]($Version -match $script:PackageVersionPattern)
}

function Test-WheelhouseWheelFileName {
    # A bare wheel file name - no folder, no path traversal.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$FileName
    )

    return [bool]($FileName -match $script:WheelFileNamePattern -and [System.IO.Path]::GetFileName($FileName) -eq $FileName)
}

function ConvertTo-WheelhousePin {
    # Parses pins written as "name==version". -Pin takes an array and/or comma- or
    # semicolon-separated strings (how the UI and a command line pass lists). Returns
    # { Name (normalized); Version } per pin; throws ArgumentException for anything else.
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$Pin = @()
    )

    foreach ($text in @($Pin | ForEach-Object { $_ -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        $parts = $text -split '==', 2
        if ($parts.Count -ne 2 -or -not (Test-WheelhousePackageName $parts[0].Trim()) -or -not (Test-WheelhousePackageVersion $parts[1].Trim())) {
            throw [System.ArgumentException]::new("Not a name==version pin: '$text'")
        }
        [PSCustomObject]@{ Name = (Get-NormalizedPackageName $parts[0].Trim()); Version = $parts[1].Trim() }
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'ERROR' { 'Red' }
        'WARN' { 'Yellow' }
        'OK' { 'Green' }
        default { 'White' }
    }
    # Console + transcript only - deliberately not the output stream, so scripts
    # can return result objects without log lines mixed in.
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Enable-WheelhouseTls12 {
    # Windows PowerShell 5.1 on older .NET Framework defaults to TLS 1.0/1.1, which pypi.org
    # and OSV reject - every web check would then fail closed. Call before a web request.
    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSEdition -ne 'Core') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
}

function Get-WheelhouseUserName {
    # The user name recorded in history, journals and denylist entries ('unknown' without one).
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($env:USERNAME) { return $env:USERNAME }
    return 'unknown'
}

function Get-NormalizedPackageName {
    # PEP 503 style normalization: runs of -, _, . collapse to a single "-", lowercase.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name
    )

    return ([regex]::Replace($Name, '[-_.]+', '-')).ToLowerInvariant()
}

function ConvertTo-HtmlSafe {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Write-TextFileAtomic {
    # Writes to a temp file next to the target, then swaps it in, so a crash or a
    # full disk mid-write never leaves a half-written manifest/settings file behind.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write file')) { return }

    $tempPath = "$Path.tmp"
    # Empty content gives an empty file - not a lone line break that a later append
    # would turn into a blank first line.
    Set-Content -Path $tempPath -Value $Content -Encoding utf8 -NoNewline:($Content -eq '') -ErrorAction Stop
    Move-Item -Path $tempPath -Destination $Path -Force -ErrorAction Stop
}

function Write-JsonFile {
    # Always writes a JSON array for collections - piping a single-element array
    # into ConvertTo-Json would otherwise produce a bare object.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object]$InputObject,

        [int]$Depth = 5
    )

    $json = ConvertTo-Json -InputObject $InputObject -Depth $Depth
    if ($null -eq $json) { $json = '[]' }
    Write-TextFileAtomic -Path $Path -Content $json
}

function Invoke-NativeCommand {
    # Runs an external program (python, uv, ...) and shows both its stdout and stderr
    # on the host, line by line. Windows PowerShell 5.1's Start-Transcript does not
    # record stderr that a native program writes straight to the console (pip prints
    # its "ERROR: ..." lines there), so stderr is merged into the pipeline first -
    # that way every line reaches both the console and the log file.
    # The program's exit code is left in $LASTEXITCODE as usual. With -PassThru the
    # lines are also returned, for callers that need to parse them.
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [string[]]$ArgumentList = @(),

        [switch]$PassThru
    )

    # With 'Stop', Windows PowerShell 5.1 would turn the first stderr line into a
    # terminating error.
    $ErrorActionPreference = 'Continue'
    $lines = [System.Collections.Generic.List[string]]::new()
    & $FilePath @ArgumentList 2>&1 | ForEach-Object {
        $line = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" }
        $lines.Add($line)
        $line
    } | Out-Host

    if ($PassThru) { Write-Output -NoEnumerate $lines.ToArray() }
}

function Enter-WheelhouseLock {
    # Takes one of the wheelhouse locks. Each is an exclusively opened, delete-on-close
    # file, so the operating system releases it even if the holder crashes.
    #   write (<wheelhouse>\.wheelhouse.lock) - held while the manifest, group files,
    #         catalog or quarantine change; only for the seconds that takes. Writers
    #         normally take it through Open-WheelhouseWrite (lock + journal repair).
    #   sync  (<wheelhouse>\.wheelhouse-sync.lock) - held for a whole Update-Wheelhouse
    #         run, so two runs never plan merges from the same state. Other operations
    #         ignore it.
    # -TimeoutSeconds waits for a busy lock (0 = fail at once). Returns the handle for
    # Exit-WheelhouseLock; throws InvalidOperationException (Data['WheelhouseLockBusy'])
    # when the lock stays busy.
    [CmdletBinding()]
    [OutputType([System.IO.FileStream])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [ValidateSet('write', 'sync')]
        [string]$Kind = 'write',

        [ValidateRange(0, 3600)]
        [int]$TimeoutSeconds = 0
    )

    $lockPath = Join-Path $WheelhousePath $(if ($Kind -eq 'sync') { '.wheelhouse-sync.lock' } else { '.wheelhouse.lock' })
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $announced = $false
    while ($true) {
        try {
            $stream = [System.IO.FileStream]::new(
                $lockPath,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None,
                4096,
                [System.IO.FileOptions]::DeleteOnClose)
            break
        }
        catch [System.IO.DirectoryNotFoundException] {
            throw "The wheelhouse folder does not exist or is not reachable: $WheelhousePath"
        }
        catch [System.IO.IOException] {
            if ((Get-Date) -ge $deadline) {
                $text = if ($Kind -eq 'sync') {
                    "Another Update-Wheelhouse run is already in progress (lock file in use: $lockPath). Wait for it to finish and try again."
                }
                else {
                    "Another wheelhouse operation is already running (lock file in use: $lockPath). Wait for it to finish and try again."
                }
                $busy = [System.InvalidOperationException]::new($text)
                # Lets scripts exit with the "busy" code (Get-WheelhouseExitCode).
                $busy.Data['WheelhouseLockBusy'] = $true
                throw $busy
            }
            if (-not $announced) {
                Write-Log "Waiting up to $TimeoutSeconds s for another wheelhouse operation to finish ($lockPath)..."
                $announced = $true
            }
            Start-Sleep -Milliseconds 500
        }
    }

    $info = [System.Text.Encoding]::ASCII.GetBytes("pid=$PID user=$env:USERNAME started=$((Get-Date).ToString('s'))")
    $stream.Write($info, 0, $info.Length)
    $stream.Flush()
    # The comma stops PowerShell from trying to enumerate the stream.
    return , $stream
}

function Exit-WheelhouseLock {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [System.IO.FileStream]$Lock
    )

    if ($null -ne $Lock) { $Lock.Dispose() }
}

function Open-WheelhouseWrite {
    # The way every writer starts changing the wheelhouse: takes the write lock, then
    # finishes any change a crashed process left half-done (Repair-WheelhouseJournal),
    # so the writer always starts from a consistent state. Returns the lock handle;
    # release it with Exit-WheelhouseLock.
    [CmdletBinding()]
    [OutputType([System.IO.FileStream])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [ValidateRange(0, 3600)]
        [int]$TimeoutSeconds = 0,

        [string]$DenylistPath = (Get-WheelhouseDenylistPath)
    )

    $lock = Enter-WheelhouseLock -WheelhousePath $WheelhousePath -TimeoutSeconds $TimeoutSeconds
    try {
        Repair-WheelhouseJournal -WheelhousePath $WheelhousePath -DenylistPath $DenylistPath
    }
    catch {
        Exit-WheelhouseLock -Lock $lock
        throw
    }
    return , $lock
}

function Get-WheelhouseExitCode {
    # The exit codes every script uses, so a Scheduled Task, the pipeline or the UI can
    # tell the outcomes apart:
    #   0 - OK
    #   1 - finished, but needs attention (vulnerabilities, rejected packages, threats)
    #   2 - error: the run aborted, or a check could not be completed
    #   3 - busy: another wheelhouse operation holds the lock
    # With -ErrorRecord, returns 3 for a busy lock, 1 for a change still waiting for
    # approval (nothing was done; someone has to approve it) and 2 for anything else.
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [ValidateSet('Ok', 'Attention', 'Error', 'Busy')]
        [string]$Outcome = 'Ok',

        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    if ($ErrorRecord) {
        if ($ErrorRecord.Exception.Data['WheelhouseLockBusy']) { return 3 }
        if ($ErrorRecord.Exception.Data['WheelhouseAwaitingApproval']) { return 1 }
        return 2
    }
    switch ($Outcome) {
        'Attention' { return 1 }
        'Error' { return 2 }
        'Busy' { return 3 }
        default { return 0 }
    }
}

function ConvertTo-WheelhouseBoolean {
    # An on/off value from a setting ($true/$false) or a command line (On/Off, True/False,
    # 1/0, Yes/No) as [bool]. Scheduled Tasks pass -File arguments as text, so scripts take
    # On/Off strings rather than [bool] parameters.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        $Value
    )

    if ($Value -is [bool]) { return $Value }
    return ([string]$Value).Trim() -in 'On', 'True', '1', 'Yes'
}

function ConvertTo-UtcDateTime {
    # JSON dates arrive as text on Windows PowerShell 5.1 and as [datetime] on
    # PowerShell 7 (ConvertFrom-Json and Invoke-RestMethod parse ISO strings). Either way
    # this returns a UTC [datetime].
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory)]
        $Value
    )

    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [System.DateTimeOffset]) { return $Value.UtcDateTime }
    return [System.DateTimeOffset]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture).UtcDateTime
}

function ConvertTo-OptionalUtcDateTime {
    # ConvertTo-UtcDateTime for values that may be missing: $null for an empty or
    # unreadable value instead of an error.
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value))) { return $null }
    try { return ConvertTo-UtcDateTime -Value $Value } catch { return $null }
}

# --- Windows Event Log (optional, setting EventLog) ---------------------------------------
# Event IDs: 1000 a run finished OK; 1001 a run needs attention; 1002 a run failed or a check
# could not be completed; 1003 an automatic action was taken; 1004 a change was made by
# someone (publish, quarantine, restore, approval).
$script:EventLogSource = 'WheelhouseManager'
$script:EventLogState = $null
$script:CurrentRunLog = $null

function Test-WheelhouseEventLogEnabled {
    # $true when the EventLog setting is on and writing has not failed in this process. (No
    # up-front check: without administrator rights Windows cannot even search for a missing
    # source; Setup.ps1 -EnableEventLog creates it once.)
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($null -eq $script:EventLogState) {
        $settings = Get-WheelhouseSetting
        $script:EventLogState = [bool]($settings.ContainsKey('EventLog') -and (ConvertTo-WheelhouseBoolean $settings['EventLog']))
    }
    return [bool]$script:EventLogState
}

function Write-WheelhouseEventLogEntry {
    # Writes one entry to the Application log (mock seam).
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [int]$Id,

        [Parameter(Mandatory)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if ($PSCmdlet.ShouldProcess($script:EventLogSource, "Event $Id")) {
        [System.Diagnostics.EventLog]::WriteEntry($script:EventLogSource, $Message, [System.Diagnostics.EventLogEntryType]$Level, $Id)
    }
}

function Write-WheelhouseEventLog {
    # Writes an event when the Event Log is enabled; otherwise does nothing. A failure only
    # warns - the Event Log is an extra channel, never a reason for a run to fail.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(1000, 1001, 1002, 1003, 1004)]
        [int]$Id,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not (Test-WheelhouseEventLogEnabled)) { return }
    $level = switch ($Id) { 1000 { 'Information' } 1004 { 'Information' } 1002 { 'Error' } default { 'Warning' } }
    $user = if ($env:USERNAME) { "$env:USERDOMAIN\$env:USERNAME" } else { 'unknown' }
    try {
        Write-WheelhouseEventLogEntry -Id $Id -Level $level -Message "$Message`r`n`r`nUser: $user; computer: $env:COMPUTERNAME"
    }
    catch {
        # Once is enough: stop trying for the rest of this run.
        $script:EventLogState = $false
        Write-Log "Could not write to the Event Log ($($_.Exception.Message)). Its source is created by Setup.ps1 -EnableEventLog, run once as administrator; the Event Log is skipped for the rest of this run." 'WARN'
    }
}

function Register-WheelhouseEventSource {
    # Creates the event source in the Application log (needs administrator rights). Returns
    # $true if it exists afterwards.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    # Run as administrator: then the search below can read every log.
    if ([System.Diagnostics.EventLog]::SourceExists($script:EventLogSource)) { return $true }
    if (-not $PSCmdlet.ShouldProcess($script:EventLogSource, 'Create event source')) { return $false }
    [System.Diagnostics.EventLog]::CreateEventSource($script:EventLogSource, 'Application')
    $script:EventLogState = $null
    return $true
}
