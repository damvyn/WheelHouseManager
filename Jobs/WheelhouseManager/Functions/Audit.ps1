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
        & python -m pip install --upgrade $tool | Out-Host
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
        & python -m pip install pip-audit | Out-Host
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
    & python @pipAuditArgs | Out-Host
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
    & python -m pip_audit -r $RequirementsFilePath --vulnerability-service pypi --progress-spinner off --fix --dry-run | Out-Host
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

function Test-PackageAge {
    # Checks each package's PyPI publish date against the minimum age. Unresolvable
    # packages fail closed.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Packages,

        [Parameter(Mandatory)]
        [int]$MinimumAgeDays
    )

    $tooNew = [System.Collections.Generic.List[string]]::new()
    $results = [System.Collections.Generic.List[object]]::new()
    $nowUtc = (Get-Date).ToUniversalTime()

    # Windows PowerShell 5.1 on older .NET Framework defaults to TLS 1.0/1.1, which
    # pypi.org rejects - every age check would then fail closed.
    if ($PSVersionTable.PSEdition -ne 'Core') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    foreach ($name in ($Packages.Keys | Sort-Object)) {
        $version = $Packages[$name]
        try {
            $response = Invoke-RestMethod -Uri "https://pypi.org/pypi/$name/$version/json" -ErrorAction Stop

            if (-not $response.urls -or @($response.urls).Count -eq 0) {
                throw 'No release files found for this version.'
            }

            $uploadTimeUtc = [DateTimeOffset]::Parse($response.urls[0].upload_time_iso_8601).UtcDateTime
            $ageDays = [math]::Floor(($nowUtc - $uploadTimeUtc).TotalDays)
            $passed = $ageDays -ge $MinimumAgeDays

            $results.Add([PSCustomObject]@{
                    Package             = $name
                    Version             = $version
                    UploadDateUtc       = $uploadTimeUtc
                    AgeDays             = $ageDays
                    MinimumRequiredDays = $MinimumAgeDays
                    Passed              = $passed
                })

            if ($passed) {
                Write-Log "Age check OK: $name==$version was published $ageDays day(s) ago (>= $MinimumAgeDays)." 'OK'
            }
            else {
                Write-Log "Age check FAILED: $name==$version was published only $ageDays day(s) ago (requires $MinimumAgeDays)." 'WARN'
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
                    Passed              = $false
                    Error               = $_.Exception.Message
                })
            $tooNew.Add("$name==$version (could not verify publish date)")
        }
    }

    return @{ TooNew = $tooNew.ToArray(); Results = $results.ToArray() }
}
