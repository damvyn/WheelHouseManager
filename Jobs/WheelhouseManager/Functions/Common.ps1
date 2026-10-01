# ---------------------------------------------------------------------------
# Generic helpers: logging, package-name normalization, HTML escaping, file I/O
# ---------------------------------------------------------------------------

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
    Set-Content -Path $tempPath -Value $Content -Encoding utf8 -ErrorAction Stop
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
    # Takes the wheelhouse-wide lock (<wheelhouse>\.wheelhouse.lock) that every
    # operation changing the manifest or the group files holds while it runs, so a
    # UI action, Update-Wheelhouse.ps1 and a scheduled run never rewrite them at
    # the same time. The lock is an exclusively opened, delete-on-close file: the
    # operating system releases it even if the holding process crashes.
    # Returns the lock handle for Exit-WheelhouseLock; throws InvalidOperationException
    # if another operation holds the lock.
    [CmdletBinding()]
    [OutputType([System.IO.FileStream])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $lockPath = Join-Path $WheelhousePath '.wheelhouse.lock'
    try {
        $stream = [System.IO.FileStream]::new(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::DeleteOnClose)
    }
    catch [System.IO.IOException] {
        throw [System.InvalidOperationException]::new("Another wheelhouse operation is already running (lock file in use: $lockPath). Wait for it to finish and try again.")
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
