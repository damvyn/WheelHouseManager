# ---------------------------------------------------------------------------
# Tooling check, pip-audit runs and reports, package-age (cooldown) check
# ---------------------------------------------------------------------------

# Report file naming convention - defined here once, used by both the writer
# (Get-AuditReportPath) and every reader (Get-AuditReportInfo).
#   Report_<Stage>-<Group>-<SERVICE>_<yyyyMMdd_HHmmss>.json
#   e.g. Report_Scheduled-requirements-2-OSV_20260921_153000.json
$script:AuditReportPattern = '^Report_(?<stage>[A-Za-z]+)(?:-(?<group>.+?))?-(?<service>OSV|PYPI)_(?<timestamp>\d{8}_\d{6})\.json$'

function Confirm-PythonAndTooling {
    # Checks python is available, keeps pip and pip-audit up to date, and installs
    # pip-audit if missing. Throws if python or pip-audit is unusable.
    [CmdletBinding()]
    param()

    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        throw 'Python was not found on this machine. Install Python before running this script.'
    }
    $pythonVersionOutput = & python --version 2>&1
    Write-Log "Python found: $pythonVersionOutput" 'OK'

    Write-Log 'Checking pip / pip-audit versions...'
    $outdatedJson = & python -m pip list --outdated --format=json 2>$null
    $outdated = @()
    if ($LASTEXITCODE -eq 0 -and $outdatedJson) {
        # foreach (not @()) flattens the result on every version: Windows PowerShell 5.1's
        # ConvertFrom-Json emits a JSON array as ONE object instead of enumerating it.
        $outdated = @(foreach ($item in ($outdatedJson | ConvertFrom-Json)) { $item })
    }
    else {
        Write-Log 'Could not determine outdated packages (pip list --outdated failed). Continuing with the installed versions.' 'WARN'
    }

    foreach ($tool in @('pip', 'pip-audit')) {
        $toolOutdated = $outdated | Where-Object { $_.name -eq $tool }
        if (-not $toolOutdated) {
            continue
        }
        Write-Log "$tool is outdated (current: $($toolOutdated.version), latest: $($toolOutdated.latest_version)). Upgrading..." 'WARN'
        Invoke-NativeCommand -FilePath python -ArgumentList '-m', 'pip', 'install', '--upgrade', $tool
        if ($LASTEXITCODE -eq 0) {
            Write-Log "$tool upgraded successfully." 'OK'
        }
        else {
            Write-Log "$tool upgrade FAILED (exit code $LASTEXITCODE). Continuing with the installed version." 'WARN'
        }
    }

    & python -m pip show pip-audit *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Log 'pip-audit is not installed. Installing...' 'WARN'
        Invoke-NativeCommand -FilePath python -ArgumentList '-m', 'pip', 'install', 'pip-audit'
        if ($LASTEXITCODE -ne 0) {
            throw "pip-audit installation FAILED (exit code $LASTEXITCODE)."
        }
        Write-Log 'pip-audit installed successfully.' 'OK'
    }
    else {
        Write-Log 'pip-audit is installed.' 'OK'
    }
}

function Get-AuditReportPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$ReportsFolder,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z]+$')]
        [string]$Stage,

        [Parameter(Mandatory)]
        [string]$Group,

        [Parameter(Mandatory)]
        [ValidateSet('osv', 'pypi')]
        [string]$Service
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    return Join-Path $ReportsFolder "Report_$Stage-$Group-$($Service.ToUpperInvariant())_$timestamp.json"
}

function Get-AuditReportInfo {
    # Parses an audit report file name back into its parts. Returns $null for any
    # file that isn't a pip-audit report (integrity/age reports, logs, ...).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fileName = Split-Path -Path $Path -Leaf
    if ($fileName -notmatch $script:AuditReportPattern) { return $null }

    return [PSCustomObject]@{
        Stage     = $Matches['stage']
        Group     = $Matches['group']
        Service   = $(if ($Matches['service'] -eq 'OSV') { 'OSV' } else { 'PyPI' })
        Timestamp = $Matches['timestamp']
    }
}

function Get-PipAuditReport {
    # Returns an array of dependency objects ({name, version, vulns:[...]})
    # regardless of whether the JSON root is a flat array (older pip-audit)
    # or an object with a "dependencies" property (newer pip-audit).
    # Throws if the report is missing or not valid JSON.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        throw "Report file not found: $Path"
    }

    $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Report file is empty: $Path"
    }
    try {
        $parsed = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    }
    catch {
        throw "Report file is not valid JSON: $Path ($($_.Exception.Message))"
    }

    if ($parsed -is [array]) {
        # Flat array format. Checking -is [array] first avoids a trap: accessing
        # .dependencies on an array whose elements don't have that property returns
        # an array of $null (one per element), not a plain $null.
        Write-Output -NoEnumerate $parsed
        return
    }
    if ($null -ne $parsed.dependencies) {
        Write-Output -NoEnumerate @($parsed.dependencies)
        return
    }
    Write-Output -NoEnumerate @($parsed)
}

function Get-VulnerableDependencyCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Dependencies
    )

    return @($Dependencies | Where-Object { $null -ne $_.vulns -and @($_.vulns).Count -gt 0 }).Count
}

function Invoke-PipAudit {
    # Runs pip-audit for one requirements file against one vulnerability service.
    # Group files are fully pinned (uv pip compile output), so pip-audit runs with
    # --no-deps --disable-pip: no throwaway venv, no dependency resolution.
    #
    # Returns a Wheelhouse.AuditResult whose Status distinguishes:
    #   Passed     - no known vulnerabilities
    #   Vulnerable - the report lists at least one vulnerability
    #   Error      - pip-audit failed without producing a usable report (network,
    #                tooling, unresolvable package, ...) - NOT a clean result
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RequirementsFilePath,

        [Parameter(Mandatory)]
        [string]$ReportsFolder,

        [Parameter(Mandatory)]
        [string]$Stage,

        [Parameter(Mandatory)]
        [ValidateSet('osv', 'pypi')]
        [string]$Service
    )

    $group = [System.IO.Path]::GetFileNameWithoutExtension($RequirementsFilePath)
    $reportFile = Get-AuditReportPath -ReportsFolder $ReportsFolder -Stage $Stage -Group $group -Service $Service
    $label = "$Stage-$group-$($Service.ToUpperInvariant())"

    Write-Log "Running $label audit against '$RequirementsFilePath'..."
    $pipAuditArgs = @(
        '-m', 'pip_audit',
        '-r', $RequirementsFilePath,
        '--no-deps', '--disable-pip',
        '--vulnerability-service', $Service,
        '--progress-spinner', 'off',
        '--format', 'json',
        '--output', $reportFile
    )
    Invoke-NativeCommand -FilePath python -ArgumentList $pipAuditArgs
    $exitCode = $LASTEXITCODE

    $status = 'Passed'
    $message = 'No known vulnerabilities found.'
    if ($exitCode -ne 0) {
        try {
            $vulnerableCount = Get-VulnerableDependencyCount -Dependencies (Get-PipAuditReport -Path $reportFile)
            if ($vulnerableCount -gt 0) {
                $status = 'Vulnerable'
                $message = "$vulnerableCount vulnerable package(s) found."
            }
            else {
                $status = 'Error'
                $message = "pip-audit exited with code $exitCode, but its report lists no vulnerabilities - the audit did not complete."
            }
        }
        catch {
            $status = 'Error'
            $message = "pip-audit exited with code $exitCode and produced no usable report ($($_.Exception.Message))."
        }
    }

    switch ($status) {
        'Passed' {
            Write-Log "$label audit passed. $message" 'OK'
            Write-Log "Audit report saved to: $reportFile" 'OK'
        }
        'Vulnerable' {
            Write-Log "$label audit FAILED: $message" 'ERROR'
            Write-Log "Audit report saved to: $reportFile" 'ERROR'
        }
        'Error' {
            Write-Log "$label audit could NOT be completed: $message" 'ERROR'
        }
    }

    return [PSCustomObject]@{
        PSTypeName = 'Wheelhouse.AuditResult'
        Stage      = $Stage
        Group      = $group
        GroupFile  = $RequirementsFilePath
        Service    = $Service
        Status     = $status
        ExitCode   = $exitCode
        ReportPath = $reportFile
        Message    = $message
    }
}

function Show-PipAuditFixSuggestion {
    # Informational only - shows what pip-audit would change, does NOT modify any file.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RequirementsFilePath
    )

    Write-Log 'Checking whether pip-audit can suggest safe replacement versions (informational only, NOT applied automatically)...'
    Invoke-NativeCommand -FilePath python -ArgumentList '-m', 'pip_audit', '-r', $RequirementsFilePath, '--vulnerability-service', 'pypi', '--progress-spinner', 'off', '--fix', '--dry-run'
    Write-Log 'Review the suggestions above. Update the requirements manually if you choose to adopt any of them.' 'WARN'
}

function Invoke-GroupAudit {
    # Audits one group file against every configured vulnerability service and
    # returns one Wheelhouse.AuditResult per service. Shows pip-audit's fix
    # suggestions once per group if anything was found.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupFile,

        [Parameter(Mandatory)]
        [string[]]$Services,

        [Parameter(Mandatory)]
        [string]$Stage,

        [Parameter(Mandatory)]
        [string]$ReportsFolder
    )

    $results = foreach ($service in $Services) {
        Invoke-PipAudit -RequirementsFilePath $GroupFile -ReportsFolder $ReportsFolder -Stage $Stage -Service $service
    }
    $results = @($results)

    if ($results | Where-Object { $_.Status -eq 'Vulnerable' }) {
        Show-PipAuditFixSuggestion -RequirementsFilePath $GroupFile
    }
    Write-Output -NoEnumerate $results
}

function Get-PyPIReleaseInfo {
    # Reads one release from the PyPI JSON API (https://pypi.org/pypi/<name>/<version>/json):
    # every file with its sha256 digest, upload time and yanked flag, plus whether the
    # release itself is yanked. An exact pin still installs a yanked release (PEP 592), so
    # callers must check that themselves. Throws if PyPI cannot be read or lists no files.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version
    )

    Enable-WheelhouseTls12

    $response = Invoke-RestMethod -Uri "https://pypi.org/pypi/$Name/$Version/json" -ErrorAction Stop
    $files = @(foreach ($url in @($response.urls)) {
            if ($null -eq $url) { continue }
            [PSCustomObject]@{
                FileName      = [string]$url.filename
                Sha256        = [string]$url.digests.sha256
                UploadTimeUtc = ConvertTo-UtcDateTime -Value $url.upload_time_iso_8601
                Yanked        = [bool]$url.yanked
                YankedReason  = [string]$url.yanked_reason
            }
        })
    if ($files.Count -eq 0) {
        throw 'No release files found for this version.'
    }

    return [PSCustomObject]@{
        Name           = $Name
        Version        = $Version
        Files          = $files
        FirstUploadUtc = ($files | Sort-Object UploadTimeUtc | Select-Object -First 1).UploadTimeUtc
        Yanked         = [bool]$response.info.yanked
        YankedReason   = [string]$response.info.yanked_reason
    }
}

function Test-PackageAge {
    # Reads each package's PyPI release (Get-PyPIReleaseInfo) and checks its publish date
    # - the first upload of the release - against the minimum age. Packages named in
    # -Expedite skip the age requirement (urgent fixes); their result says so.
    # Unresolvable packages fail closed. Each result also carries the release (files,
    # digests, yanked), which the checks after the download need.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Packages,

        [Parameter(Mandatory)]
        [int]$MinimumAgeDays,

        [AllowEmptyCollection()]
        [string[]]$Expedite = @()
    )

    $tooNew = [System.Collections.Generic.List[string]]::new()
    $results = [System.Collections.Generic.List[object]]::new()
    $nowUtc = (Get-Date).ToUniversalTime()

    foreach ($name in ($Packages.Keys | Sort-Object)) {
        $version = $Packages[$name]
        try {
            $release = Get-PyPIReleaseInfo -Name $name -Version $version
            $uploadTimeUtc = $release.FirstUploadUtc
            $ageDays = [math]::Floor(($nowUtc - $uploadTimeUtc).TotalDays)
            $expedited = $Expedite -contains $name
            $passed = $expedited -or ($ageDays -ge $MinimumAgeDays)
            $eligibleUtc = $uploadTimeUtc.AddDays($MinimumAgeDays)

            $results.Add([PSCustomObject]@{
                    Package             = $name
                    Version             = $version
                    UploadDateUtc       = $uploadTimeUtc.ToString('o')
                    AgeDays             = $ageDays
                    MinimumRequiredDays = $MinimumAgeDays
                    EligibleUtc         = $eligibleUtc.ToString('o')
                    Expedited           = $expedited
                    Passed              = $passed
                    Yanked              = $release.Yanked
                    YankedReason        = $release.YankedReason
                    Release             = $release
                })

            if ($expedited -and $ageDays -lt $MinimumAgeDays) {
                Write-Log "Age check SKIPPED (expedited): $name==$version was published $ageDays day(s) ago (normally requires $MinimumAgeDays)." 'WARN'
            }
            elseif ($passed) {
                Write-Log "Age check OK: $name==$version was published $ageDays day(s) ago (>= $MinimumAgeDays)." 'OK'
            }
            else {
                Write-Log "Age check FAILED: $name==$version was published only $ageDays day(s) ago (requires $MinimumAgeDays, eligible $($eligibleUtc.ToString('yyyy-MM-dd')))." 'WARN'
                $tooNew.Add("$name==$version (published $ageDays day(s) ago, requires $MinimumAgeDays)")
            }
        }
        catch {
            Write-Log "Could not verify publish date for $name==$version : $($_.Exception.Message). Treating as failing the age check." 'WARN'
            $results.Add([PSCustomObject]@{
                    Package             = $name
                    Version             = $version
                    UploadDateUtc       = $null
                    AgeDays             = $null
                    MinimumRequiredDays = $MinimumAgeDays
                    EligibleUtc         = $null
                    Expedited           = $false
                    Passed              = $false
                    Yanked              = $null
                    YankedReason        = $null
                    Release             = $null
                    Error               = $_.Exception.Message
                })
            $tooNew.Add("$name==$version (could not verify publish date)")
        }
    }

    return @{ TooNew = $tooNew.ToArray(); Results = $results.ToArray() }
}

function Get-DeployedPackageNotice {
    # Re-checks what is already published against conditions that can change after
    # intake: the denylist (an entry added later) and PyPI's yanked flag (the release or
    # one of the deployed files). Returns @{ Notices = Wheelhouse.Notice, ...; Errors =
    # string, ...; Checked = { Package; Version; Yanked; Reason }, ... (every version whose
    # PyPI data was read) }. A release whose PyPI data cannot be read is an error, never
    # "not yanked".
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [AllowEmptyCollection()]
        [object[]]$Denylist = @(),

        [switch]$SkipYanked
    )

    $notices = [System.Collections.Generic.List[object]]::new()
    $unreadable = [System.Collections.Generic.List[string]]::new()
    $checked = [System.Collections.Generic.List[object]]::new()

    $pins = [ordered]@{}
    foreach ($entry in ($Manifest | Sort-Object name, version)) {
        $key = "$($entry.name)==$($entry.version)"
        if (-not $pins.Contains($key)) { $pins[$key] = [System.Collections.Generic.List[string]]::new() }
        $pins[$key].Add([string]$entry.file)
    }
    if ($pins.Count -gt 0 -and -not $SkipYanked) {
        Write-Log "Checking $($pins.Count) published package version(s) against the denylist and PyPI's yanked flag..."
    }

    foreach ($key in $pins.Keys) {
        $name, $version = $key -split '==', 2
        $files = $pins[$key].ToArray()

        $blocked = Get-DenylistMatch -Name $name -Version $version -Denylist $Denylist
        if ($blocked) {
            $why = if ($blocked.reason) { ": $($blocked.reason)" } else { '' }
            $notices.Add((New-WheelhouseNotice -Kind 'Denylisted' -Package $name -Version $version -File $files -Message "Blocked by the denylist ($($blocked.version), $($blocked.source))$why, but still published."))
        }

        if ($SkipYanked) { continue }
        try {
            $release = Get-PyPIReleaseInfo -Name $name -Version $version
        }
        catch {
            $unreadable.Add("$key ($($_.Exception.Message))")
            continue
        }
        $yankedFiles = @($release.Files | Where-Object { $_.Yanked -and $files -contains $_.FileName })
        $isYanked = $release.Yanked -or $yankedFiles.Count -gt 0
        $reason = ''
        if ($isYanked) {
            $reason = [string](@($release.YankedReason) + @($yankedFiles | ForEach-Object { $_.YankedReason }) | Where-Object { $_ } | Select-Object -First 1)
            $text = if ($reason) { "Yanked on PyPI: $reason" } else { 'Yanked on PyPI (no reason given).' }
            $notices.Add((New-WheelhouseNotice -Kind 'Yanked' -Package $name -Version $version -File $files -Message $text))
        }
        $checked.Add([PSCustomObject]@{ Package = $name; Version = $version; Yanked = $isYanked; Reason = $reason })
    }

    foreach ($notice in $notices) {
        Write-Log "  $($notice.Kind): $($notice.Package)==$($notice.Version) - $($notice.Message)" 'WARN'
    }
    $errors = @()
    if ($unreadable.Count -gt 0) {
        $errors = @("PyPI yanked check could not be completed for $($unreadable.Count) package(s): $($unreadable -join '; ')")
        Write-Log $errors[0] 'ERROR'
    }
    return @{ Notices = $notices.ToArray(); Errors = [string[]]$errors; Checked = $checked.ToArray() }
}

function Invoke-WheelhouseToolProbe {
    # The version a tool reports, or $null if it is missing, fails or does not answer within
    # 15 seconds (e.g. the Microsoft Store "python.exe" stub waiting for the Store). Mock seam
    # for Get-WheelhouseToolStatus.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('python', 'pip-audit', 'uv')]
        [string]$Name
    )

    $command = Get-Command $(if ($Name -eq 'uv') { 'uv' } else { 'python' }) -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { return $null }
    $arguments = if ($Name -eq 'pip-audit') { '-m pip_audit --version' } else { '--version' }
    $process = $null
    try {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new($command.Source, $arguments)
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        # An inherited stdin that never closes (a background job, the UI's host) can keep a
        # child waiting; give it an empty one.
        $startInfo.RedirectStandardInput = $true
        $startInfo.CreateNoWindow = $true
        $process = [System.Diagnostics.Process]::Start($startInfo)
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) {
            try { $process.Kill() } catch { Write-Verbose "Could not stop $($command.Source): $($_.Exception.Message)" }
            return $null
        }
        if ($process.ExitCode -ne 0) { return $null }
        $text = (($stdout.Result + "`n" + $stderr.Result) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
        if ($text -match '(\d+(\.\d+)+)') { return $Matches[1] }
        return [string]$text
    }
    catch {
        return $null
    }
    finally {
        if ($process) { $process.Dispose() }
    }
}

function Get-WheelhouseToolStatus {
    # Whether the tools the scripts need are usable by the account running the UI:
    # python (every audit, download and check), pip-audit (installed by the first run if
    # missing) and uv (resolving requirements.in). One { name; available; version; level
    # ok|warn|bad; message } per tool.
    [CmdletBinding()]
    param()

    $python = Invoke-WheelhouseToolProbe -Name 'python'
    $pipAudit = if ($python) { Invoke-WheelhouseToolProbe -Name 'pip-audit' } else { $null }
    $uv = Invoke-WheelhouseToolProbe -Name 'uv'

    [PSCustomObject]@{
        name      = 'python'
        available = [bool]$python
        version   = [string]$python
        level     = $(if ($python) { 'ok' } else { 'bad' })
        message   = $(if ($python) { '' } else { 'Python was not found on the PATH of the account running the UI. Audits, publishing, scans of new downloads and the weekly check cannot run. Install Python on this server and restart the UI.' })
    }
    [PSCustomObject]@{
        name      = 'pip-audit'
        available = [bool]$pipAudit
        version   = [string]$pipAudit
        level     = $(if ($pipAudit) { 'ok' } elseif ($python) { 'warn' } else { 'bad' })
        message   = $(if ($pipAudit) { '' } elseif ($python) { 'pip-audit is not installed for this Python. The first audit or update installs it (needs access to PyPI).' } else { 'pip-audit cannot run without Python.' })
    }
    [PSCustomObject]@{
        name      = 'uv'
        available = [bool]$uv
        version   = [string]$uv
        level     = $(if ($uv) { 'ok' } else { 'bad' })
        message   = $(if ($uv) { '' } else { 'uv was not found on the PATH of the account running the UI. Adding packages (resolving requirements.in with Update-Requirement.ps1) does not work. Install uv on this server and restart the UI.' })
    }
}

function Get-PyPIProjectRelease {
    # Every release of a project on PyPI (https://pypi.org/pypi/<name>/json): { Version;
    # FirstUploadUtc; Yanked } - Yanked when every file of the release is yanked. Releases
    # without files are left out. Throws if PyPI cannot be read.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    Enable-WheelhouseTls12
    $response = Invoke-RestMethod -Uri "https://pypi.org/pypi/$([uri]::EscapeDataString($Name))/json" -TimeoutSec 60 -ErrorAction Stop
    foreach ($property in $response.releases.PSObject.Properties) {
        $files = @(@($property.Value) | Where-Object { $_ })
        if ($files.Count -eq 0) { continue }
        $times = @($files | ForEach-Object { ConvertTo-OptionalUtcDateTime -Value $_.upload_time_iso_8601 } | Where-Object { $_ } | Sort-Object)
        [PSCustomObject]@{
            Version        = [string]$property.Name
            FirstUploadUtc = $(if ($times.Count -gt 0) { $times[0] } else { $null })
            Yanked         = (@($files | Where-Object { -not $_.yanked }).Count -eq 0)
        }
    }
}

function Get-AuditChunk {
    # The published versions packed into the fewest requirement sets pip-audit accepts: one
    # version per package name per set, so set 1 holds every package's first version, set 2
    # every second version, and so on. Returns ordered name -> version hashtables.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest
    )

    $versions = [ordered]@{}
    # Name and version, so the sets are the same on every run (5.1's sort is not stable).
    foreach ($entry in ($Manifest | Sort-Object name, version)) {
        $name = Get-NormalizedPackageName ([string]$entry.name)
        if (-not $versions.Contains($name)) { $versions[$name] = [System.Collections.Generic.List[string]]::new() }
        if (-not $versions[$name].Contains([string]$entry.version)) { $versions[$name].Add([string]$entry.version) }
    }
    $chunks = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $versions.Keys) {
        for ($i = 0; $i -lt $versions[$name].Count; $i++) {
            if ($chunks.Count -le $i) { $chunks.Add([ordered]@{}) }
            $chunks[$i][$name] = $versions[$name][$i]
        }
    }
    Write-Output -NoEnumerate $chunks.ToArray()
}

function Invoke-PublishedAudit {
    # Audits published versions in as few pip-audit runs as possible: Get-AuditChunk packs
    # them into sets (usually one or two, whatever the number of group files), each written to
    # <reports>\audit-sets\<Stage>\published-<n>.txt and audited against every service with
    # Invoke-GroupAudit. Results are per package version (Update-CatalogAuditResult), so it
    # does not matter which set a version was in. Returns AuditResults (-NoEnumerate).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [Parameter(Mandatory)]
        [string[]]$Services,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z]+$')]
        [string]$Stage,

        [Parameter(Mandatory)]
        [string]$ReportsFolder
    )

    $chunks = Get-AuditChunk -Manifest $Manifest
    $results = [System.Collections.Generic.List[object]]::new()
    if ($chunks.Count -eq 0) {
        Write-Output -NoEnumerate $results.ToArray()
        return
    }
    $folder = Join-Path (Join-Path $ReportsFolder 'audit-sets') $Stage
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    $count = @($chunks | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    Write-Log "Auditing $count published version(s) in $($chunks.Count) set(s) x $($Services.Count) service(s)..."
    for ($i = 0; $i -lt $chunks.Count; $i++) {
        $file = Join-Path $folder "published-$($i + 1).txt"
        Write-TextFileAtomic -Path $file -Content (($chunks[$i].Keys | ForEach-Object { "$_==$($chunks[$i][$_])" }) -join "`r`n")
        foreach ($result in (Invoke-GroupAudit -GroupFile $file -Services $Services -Stage $Stage -ReportsFolder $ReportsFolder)) { $results.Add($result) }
    }
    Write-Output -NoEnumerate $results.ToArray()
}
