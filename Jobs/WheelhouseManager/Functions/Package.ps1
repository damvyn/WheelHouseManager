# ---------------------------------------------------------------------------
# Package-level operations (used by the UI): inventory, per-package audit status,
# removal / quarantine / restore, and adding requirements to requirements.in
# ---------------------------------------------------------------------------

$script:QuarantineFolderName = '_quarantine'
$script:PackageSpecPattern = '^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?\s*((==|>=|<=|~=|!=|<|>)\s*[A-Za-z0-9._*+!-]+(\s*,\s*(==|>=|<=|~=|!=|<|>)\s*[A-Za-z0-9._*+!-]+)*)?$'

function ConvertTo-IsoTimestamp {
    # PowerShell 7's ConvertFrom-Json turns ISO date strings into [datetime]; Windows
    # PowerShell 5.1 leaves them as text. Either way the UI gets one ISO 8601 string.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    return [string]$Value
}

function Get-WheelhouseQuarantinePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    return Join-Path $WheelhousePath $script:QuarantineFolderName
}

function Get-PackageAuditStatus {
    # Latest known audit result per package, taken from the audit reports in the
    # reports folder (newest first, until every package has been seen by both
    # services or -MaxReports files were read). A package no report mentions is
    # 'Unknown' - never 'Passed'.
    # Returns a hashtable: "name==version" -> { Status; Vulnerabilities; LastAudit }.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$ReportsFolder,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Package,

        # The configured services; a package is fully known once each has reported on it.
        [string[]]$Services = @('osv', 'pypi'),

        [int]$MaxReports = 300
    )

    $serviceCount = [math]::Max(1, @($Services | Where-Object { $_ } | Select-Object -Unique).Count)
    $wanted = @{}
    foreach ($item in $Package) { $wanted["$($item.Name)==$($item.Version)"] = $true }
    $seen = @{}
    $result = @{}
    foreach ($key in $wanted.Keys) {
        $seen[$key] = @{}
        $result[$key] = [PSCustomObject]@{ Status = 'Unknown'; Vulnerabilities = @(); LastAudit = '' }
    }
    if ($wanted.Count -eq 0 -or -not (Test-Path -Path $ReportsFolder)) { return $result }

    $reports = @(Get-ChildItem -Path $ReportsFolder -Filter 'Report_*.json' -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                $info = Get-AuditReportInfo -Path $_.FullName
                if ($info) { [PSCustomObject]@{ Path = $_.FullName; Info = $info } }
            } |
            Sort-Object { $_.Info.Timestamp } -Descending |
            Select-Object -First $MaxReports)

    $fullySeen = 0
    foreach ($report in $reports) {
        if ($fullySeen -ge $wanted.Count) { break }
        try { $dependencies = Get-PipAuditReport -Path $report.Path } catch { continue }
        $service = $report.Info.Service
        $stamp = [datetime]::ParseExact($report.Info.Timestamp, 'yyyyMMdd_HHmmss', [System.Globalization.CultureInfo]::InvariantCulture).ToString('yyyy-MM-dd HH:mm:ss')

        foreach ($dependency in $dependencies) {
            if ($null -eq $dependency.name -or $null -ne $dependency.skip_reason) { continue }
            $key = "$(Get-NormalizedPackageName $dependency.name)==$($dependency.version)"
            if (-not $wanted.ContainsKey($key) -or $seen[$key].ContainsKey($service)) { continue }

            $seen[$key][$service] = $true
            $ids = @(@($dependency.vulns) | Where-Object { $_ } | ForEach-Object { [string]$_.id })
            $current = $result[$key]
            $status = if ($ids.Count -gt 0 -or $current.Status -eq 'Vulnerable') { 'Vulnerable' } else { 'Passed' }
            $result[$key] = [PSCustomObject]@{
                Status          = $status
                Vulnerabilities = @($current.Vulnerabilities + $ids | Select-Object -Unique)
                LastAudit       = $(if ($current.LastAudit -gt $stamp) { $current.LastAudit } else { $stamp })
            }
            if ($seen[$key].Count -eq $serviceCount) { $fullySeen++ }
        }
    }
    return $result
}

function Get-PackageScanStatus {
    # Latest known Defender result per wheel file, from Report_Scan_*.json. A file
    # that no scan covered is 'Unknown'. Returns file name -> { Status; LastScan }.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$ReportsFolder,

        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$File,

        [int]$MaxReports = 50
    )

    $result = @{}
    foreach ($name in $File) { $result[$name] = [PSCustomObject]@{ Status = 'Unknown'; LastScan = '' } }
    if ($File.Count -eq 0 -or -not (Test-Path -Path $ReportsFolder)) { return $result }

    $wheelhouseFull = [System.IO.Path]::GetFullPath($WheelhousePath).TrimEnd('\')
    $reports = @(Get-ChildItem -Path $ReportsFolder -Filter 'Report_Scan_*.json' -File -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First $MaxReports)
    $pending = [System.Collections.Generic.HashSet[string]]::new([string[]]$File, [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($reportFile in $reports) {
        if ($pending.Count -eq 0) { break }
        try { $report = Get-Content -Path $reportFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if ($report.Status -eq 'Error') { continue }

        $scanned = @(@($report.ScannedPaths) | Where-Object { $_ } | ForEach-Object { [System.IO.Path]::GetFullPath([string]$_).TrimEnd('\') })
        $threats = @(@($report.Threats) | Where-Object { $_ })
        foreach ($name in @($pending)) {
            $fullPath = Join-Path $wheelhouseFull $name
            $covered = $false
            foreach ($path in $scanned) {
                if ([string]::Equals($path, $fullPath, [System.StringComparison]::OrdinalIgnoreCase) -or
                    [string]::Equals($path, $wheelhouseFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $covered = $true
                    break
                }
            }
            if (-not $covered) { continue }

            $hit = @($threats | Where-Object { ([string]$_.Resource).IndexOf($fullPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 })
            $result[$name] = [PSCustomObject]@{
                Status   = $(if ($hit.Count -gt 0) { 'Threat' } else { 'Clean' })
                LastScan = [string]$report.ScanTime
            }
            [void]$pending.Remove($name)
        }
    }
    return $result
}

function ConvertTo-WheelhouseUiFinding {
    # A record's unresolved findings for the UI: id, severity, due date, status
    # (Open / Overdue / Waived) and waiver.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Record,

        [datetime]$NowUtc = (Get-Date).ToUniversalTime()
    )

    foreach ($finding in @($Record.findings)) {
        if ($null -eq $finding -or $finding.resolved_utc) { continue }
        # Plain assignments: one-element arrays must stay lists in the JSON.
        $aliases = @($finding.aliases)
        $fixVersions = @($finding.fix_versions)
        $waiver = $null
        if ($finding.waiver) {
            $waiver = @{ reason = [string]$finding.waiver.reason; by = [string]$finding.waiver.by; expires_utc = [string]$finding.waiver.expires_utc }
        }
        @{
            id           = $finding.id
            aliases      = $aliases
            summary      = $finding.summary
            fix_versions = $fixVersions
            severity     = $finding.severity
            score        = $finding.score
            first_seen   = $finding.first_seen
            due          = $finding.due
            status       = (Get-CatalogFindingStatus -Finding $finding -NowUtc $NowUtc)
            waiver       = $waiver
        }
    }
}

function Get-WheelhousePackage {
    # The wheelhouse inventory: one row per wheel file in manifest.json, with the
    # group files that list it, its latest audit, Defender and PyPI (yanked) status from
    # the catalog, its open findings (worst severity, earliest due date, overdue, waived),
    # and whether the denylist blocks it. Also returns the untracked wheel files, the
    # groups and when the scheduled check last completed.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [AllowEmptyCollection()]
        [object[]]$Denylist = @(),

        [string[]]$Services = @('osv', 'pypi')
    )

    $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
    $groupFiles = Get-WheelhouseGroupFile -WheelhousePath $WheelhousePath
    $untracked = Get-UntrackedWheelFile -Manifest $manifest -WheelhousePath $WheelhousePath

    $groupsByPin = @{}
    $groupNames = [System.Collections.Generic.List[string]]::new()
    foreach ($groupFile in $groupFiles) {
        $groupName = [System.IO.Path]::GetFileNameWithoutExtension($groupFile)
        $groupNames.Add($groupName)
        $pins = Read-RequirementFile -FilePath $groupFile
        foreach ($name in $pins.Keys) {
            $key = "$name==$($pins[$name])"
            if (-not $groupsByPin.ContainsKey($key)) { $groupsByPin[$key] = [System.Collections.Generic.List[string]]::new() }
            $groupsByPin[$key].Add($groupName)
        }
    }

    # Status comes from the catalog. A wheelhouse that has no catalog yet (no writer has
    # run since the upgrade) falls back to reading the latest report files.
    $catalog = Read-WheelhouseCatalog -WheelhousePath $WheelhousePath
    $auditStatus = @{}
    $scanStatus = @{}
    $pypiStatus = @{}
    $findingStatus = @{}
    $now = (Get-Date).ToUniversalTime()
    if ($catalog.Exists) {
        foreach ($key in $catalog.Records.Keys) {
            $record = $catalog.Records[$key]
            $audit = $record.checks.audit
            $auditStatus[$key] = [PSCustomObject]@{
                Status          = $(if ($audit -and $audit.status) { [string]$audit.status } else { 'Unknown' })
                Vulnerabilities = @($(if ($audit) { @($audit.vulnerabilities) } else { @() }) | Where-Object { $_ })
                LastAudit       = $(if ($audit) { ConvertTo-IsoTimestamp -Value $audit.last_run } else { '' })
            }
            $scan = $record.checks.scan
            foreach ($file in $record.files) {
                $scanStatus[$file] = [PSCustomObject]@{
                    Status   = $(if (-not $scan) { 'Unknown' } elseif (@($scan.threat_files) -contains $file) { 'Threat' } else { 'Clean' })
                    LastScan = $(if ($scan) { ConvertTo-IsoTimestamp -Value $scan.last_run } else { '' })
                }
            }
            if ($record.checks.pypi) { $pypiStatus[$key] = $record.checks.pypi }
            $findings = @(ConvertTo-WheelhouseUiFinding -Record $record -NowUtc $now)
            $open = @($findings | Where-Object { $_.status -in 'Open', 'Overdue' })
            $worst = $open | Sort-Object @{ Expression = { Get-SeverityRank -Severity $_.severity }; Descending = $true } | Select-Object -First 1
            $earliest = $open | Sort-Object { $_.due } | Select-Object -First 1
            $findingStatus[$key] = [PSCustomObject]@{
                Severity = $(if ($worst) { [string]$worst.severity } else { '' })
                Due      = $(if ($earliest) { [string]$earliest.due } else { '' })
                Overdue  = [bool]($open | Where-Object { $_.status -eq 'Overdue' })
                Open     = $open.Count
                Waived   = @($findings | Where-Object { $_.status -eq 'Waived' }).Count
            }
        }
    }
    else {
        $reportsFolder = Join-Path $WheelhousePath 'reports'
        $packageKeys = @($manifest | ForEach-Object { [PSCustomObject]@{ Name = [string]$_.name; Version = [string]$_.version } })
        $auditStatus = Get-PackageAuditStatus -ReportsFolder $reportsFolder -Package $packageKeys -Services $Services
        $scanStatus = Get-PackageScanStatus -ReportsFolder $reportsFolder -WheelhousePath $WheelhousePath -File @($manifest | ForEach-Object { [string]$_.file })
    }
    $unknownAudit = [PSCustomObject]@{ Status = 'Unknown'; Vulnerabilities = @(); LastAudit = '' }
    $unknownScan = [PSCustomObject]@{ Status = 'Unknown'; LastScan = '' }

    $rows = foreach ($entry in ($manifest | Sort-Object name, version, file)) {
        $key = "$($entry.name)==$($entry.version)"
        $filePath = Join-Path $WheelhousePath ([string]$entry.file)
        # Plain assignments: a one-element array inside $(...) would be unrolled to a scalar, and the
        # JSON the UI receives would then hold a string instead of a list.
        $rowGroups = @()
        if ($groupsByPin.ContainsKey($key)) { $rowGroups = @($groupsByPin[$key]) }
        $deny = Get-DenylistMatch -Name $entry.name -Version $entry.version -Denylist $Denylist
        $audit = if ($auditStatus.ContainsKey($key)) { $auditStatus[$key] } else { $unknownAudit }
        $scan = if ($scanStatus.ContainsKey([string]$entry.file)) { $scanStatus[[string]$entry.file] } else { $unknownScan }
        $pypi = $pypiStatus[$key]
        $finding = $findingStatus[$key]
        $vulnerabilities = @($audit.Vulnerabilities)
        [PSCustomObject]@{
            name            = [string]$entry.name
            version         = [string]$entry.version
            file            = [string]$entry.file
            sha256          = [string]$entry.sha256
            platform_tag    = [string]$entry.platform_tag
            downloaded_utc  = ConvertTo-IsoTimestamp -Value $entry.downloaded_utc
            size_bytes      = $(if (Test-Path -Path $filePath) { (Get-Item -Path $filePath).Length } else { $null })
            file_missing    = -not (Test-Path -Path $filePath)
            groups          = $rowGroups
            audit_status    = $audit.Status
            vulnerabilities = $vulnerabilities
            last_audit      = $audit.LastAudit
            scan_status     = $scan.Status
            last_scan       = $scan.LastScan
            denylisted      = $(if ($deny) { [string]$deny.reason } else { $null })
            yanked          = $(if ($pypi -and $pypi.status -eq 'Yanked') { $(if ($pypi.reason) { [string]$pypi.reason } else { 'yanked' }) } else { $null })
            severity        = $(if ($finding) { $finding.Severity } else { '' })
            due             = $(if ($finding) { $finding.Due } else { '' })
            overdue         = [bool]($finding -and $finding.Overdue)
            open_findings   = $(if ($finding) { $finding.Open } else { 0 })
            waived_findings = $(if ($finding) { $finding.Waived } else { 0 })
        }
    }

    return [PSCustomObject]@{
        Packages          = @($rows)
        Groups            = $groupNames.ToArray()
        Untracked         = @($untracked)
        ScheduledCheckUtc = $catalog.ScheduledCheckUtc
    }
}

function Invoke-PackageAudit {
    # Audits a chosen set of pinned packages (name -> version) against every service.
    # Returns the Wheelhouse.AuditResult objects. The reports are named
    # Report_<Stage>-selection-<SERVICE>_<timestamp>.json.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Packages,

        [Parameter(Mandatory)]
        [string[]]$Services,

        [Parameter(Mandatory)]
        [string]$ReportsFolder,

        [string]$Stage = 'Manual'
    )

    $workFolder = Join-Path ([System.IO.Path]::GetTempPath()) ('wheelhouse-audit-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $workFolder -Force | Out-Null
    try {
        $selectionFile = Join-Path $workFolder 'selection.txt'
        Set-Content -Path $selectionFile -Value @($Packages.Keys | Sort-Object | ForEach-Object { "$_==$($Packages[$_])" }) -Encoding ascii
        $results = Invoke-GroupAudit -GroupFile $selectionFile -Services $Services -Stage $Stage -ReportsFolder $ReportsFolder
    }
    finally {
        Remove-Item -Path $workFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Output -NoEnumerate @($results)
}

function Remove-RequirementFromGroupFile {
    # Removes the "name==version" pin (and the --hash continuation lines that belong
    # to it) from a group file. Returns $true if the pin was found.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$GroupFile,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version
    )

    $normalized = Get-NormalizedPackageName $Name
    $kept = [System.Collections.Generic.List[string]]::new()
    $removed = $false
    $skipContinuation = $false

    foreach ($line in @(Get-Content -Path $GroupFile -ErrorAction Stop)) {
        if ($skipContinuation) {
            $skipContinuation = $line.TrimEnd().EndsWith('\')
            if ($line.Trim().StartsWith('--hash')) { continue }
        }
        $isPin = $line -match '^\s*(?<name>[A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(\[[^\]]*\])?\s*==\s*(?<version>[A-Za-z0-9_.\-+!]+)'
        if ($isPin -and (Get-NormalizedPackageName $Matches['name']) -eq $normalized -and $Matches['version'] -eq $Version) {
            $removed = $true
            $skipContinuation = $line.TrimEnd().EndsWith('\')
            continue
        }
        $kept.Add($line)
    }

    if ($removed -and $PSCmdlet.ShouldProcess($GroupFile, "Remove $normalized==$Version")) {
        Write-TextFileAtomic -Path $GroupFile -Content ($kept -join "`r`n")
    }
    return $removed
}

function Read-QuarantineRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $recordPath = Join-Path (Get-WheelhouseQuarantinePath -WheelhousePath $WheelhousePath) 'quarantine.json'
    $records = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -Path $recordPath) {
        $content = Get-Content -Path $recordPath -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($content)) {
            try { $parsed = ConvertFrom-Json -InputObject $content -ErrorAction Stop }
            catch { throw "quarantine.json could not be parsed ($($_.Exception.Message)). Refusing to continue until it is resolved manually." }
            foreach ($record in $parsed) { $records.Add($record) }
        }
    }
    return $records.ToArray()
}

function Save-QuarantineRecord {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Record
    )

    $folder = Get-WheelhouseQuarantinePath -WheelhousePath $WheelhousePath
    if (-not (Test-Path -Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    if ($PSCmdlet.ShouldProcess($folder, 'Save quarantine records')) {
        Write-JsonFile -Path (Join-Path $folder 'quarantine.json') -InputObject @($Record) -Depth 6
    }
}

function Get-QuarantinedPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    return @(Read-QuarantineRecord -WheelhousePath $WheelhousePath | Sort-Object quarantined_utc -Descending)
}

function Remove-WheelhousePackage {
    # Takes name==version out of the wheelhouse:
    #   - the pin is removed from every group file that lists it, so clients stop
    #     seeing it;
    #   - the wheel file(s) are removed from manifest.json;
    #   - the wheel file(s) are deleted (default) or moved to <wheelhouse>\_quarantine
    #     with -Quarantine, where Restore-WheelhousePackage can bring them back;
    #   - unless -NoDenylist, name==version is added to the denylist so the next
    #     Update-Wheelhouse run does not download it again;
    #   - the catalog records the new state, the history the reason.
    # Runs under the write lock (Open-WheelhouseWrite, or the caller's with -LockHeld)
    # and with a journal: if a step before the file removal fails, the earlier steps are
    # undone; if the process dies, the next writer finishes the removal.
    # Returns a summary object; throws on failure.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version,

        [switch]$Quarantine,

        [string]$Reason = '',

        [switch]$NoDenylist,

        [string]$DenylistPath = (Get-WheelhouseDenylistPath),

        # The caller already holds the write lock (Update-Wheelhouse.ps1).
        [switch]$LockHeld
    )

    $normalized = Get-NormalizedPackageName $Name
    $label = "$normalized==$Version"
    $mode = if ($Quarantine) { 'Quarantine' } else { 'Delete' }
    if (-not $PSCmdlet.ShouldProcess($label, "$mode package")) { return }

    $lock = if ($LockHeld) { $null } else { Open-WheelhouseWrite -WheelhousePath $WheelhousePath -DenylistPath $DenylistPath }
    $undo = [System.Collections.Generic.List[scriptblock]]::new()
    $journal = $null
    try {
        $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
        $entries = @($manifest | Where-Object { $_.name -eq $normalized -and $_.version -eq $Version })
        if ($entries.Count -eq 0) {
            throw [System.Collections.Generic.KeyNotFoundException]::new("$label is not in the wheelhouse manifest.")
        }

        $id = "$(Get-Date -Format 'yyyyMMdd_HHmmss')_${normalized}_$Version" -replace '[^A-Za-z0-9._-]', '_'
        $quarantineFolder = Join-Path (Get-WheelhouseQuarantinePath -WheelhousePath $WheelhousePath) $id
        $allGroups = Get-WheelhouseGroupFile -WheelhousePath $WheelhousePath
        $affectedGroups = @($allGroups | Where-Object {
                (Read-RequirementFile -FilePath $_)[$normalized] -eq $Version
            })
        $user = if ($env:USERNAME) { $env:USERNAME } else { 'unknown' }
        # "Deleting" a version whose wheels are already gone (e.g. the file server's
        # antivirus took them) only takes it out of the group files and the manifest.
        $alreadyGone = (-not $Quarantine) -and -not ($entries | Where-Object { Test-Path -LiteralPath (Join-Path $WheelhousePath ([string]$_.file)) })
        $verb = if ($Quarantine) { 'quarantined' } elseif ($alreadyGone) { 'taken out' } else { 'deleted' }
        $denyReason = if ($Reason) { "$Reason ($verb)" } else { "$verb from the wheelhouse" }
        $denySource = if ($Quarantine) { 'quarantined' } else { 'removed' }
        $existingDeny = if ($NoDenylist) { $null } else { Get-DenylistMatch -Name $normalized -Version $Version -Denylist @(Read-WheelhouseDenylist -Path $DenylistPath) }
        $record = $null
        if ($Quarantine) {
            $record = [PSCustomObject]@{
                id              = $id
                name            = $normalized
                version         = $Version
                files           = @($entries)
                groups          = @($affectedGroups | ForEach-Object { Split-Path -Path $_ -Leaf })
                reason          = $Reason
                quarantined_utc = (Get-Date).ToUniversalTime().ToString('o')
                quarantined_by  = $user
                denylisted      = (-not $NoDenylist)
            }
        }

        Write-Log "$mode $label (wheel file(s): $(($entries | ForEach-Object { $_.file }) -join ', '); groups: $(($affectedGroups | ForEach-Object { Split-Path -Path $_ -Leaf }) -join ', '))..."

        $journal = New-WheelhouseJournal -WheelhousePath $WheelhousePath -Operation 'remove' -Data ([ordered]@{
                name              = $normalized
                version           = $Version
                mode              = $mode
                files             = @($entries | ForEach-Object { [string]$_.file })
                groups            = @($affectedGroups)
                quarantine_folder = $quarantineFolder
                quarantine_record = $record
                deny              = (-not $NoDenylist)
                deny_reason       = $denyReason
                deny_source       = $denySource
            })

        # 1. Denylist first: it only ever blocks more, so it is safe to leave on an abort.
        $denyEntry = $null
        if (-not $NoDenylist) {
            $denyEntry = Add-WheelhouseDenylistEntry -Name $normalized -Version $Version -Reason $denyReason -Source $denySource -Path $DenylistPath
            if ($null -eq $existingDeny) {
                $undo.Add({ [void](Remove-WheelhouseDenylistEntry -Name $normalized -Version $Version -Path $DenylistPath) }.GetNewClosure())
            }
        }

        # 2. Quarantine record (written before any file moves, so a record never
        # lags behind the files).
        if ($Quarantine) {
            $records = @(Read-QuarantineRecord -WheelhousePath $WheelhousePath)
            Save-QuarantineRecord -WheelhousePath $WheelhousePath -Record (@($records) + $record)
            $undo.Add({ Save-QuarantineRecord -WheelhousePath $WheelhousePath -Record $records }.GetNewClosure())
        }

        # 3. Group files, then manifest.
        foreach ($groupFile in $affectedGroups) {
            # Set-Content appends the final newline, so the saved copy drops its own.
            $original = (Get-Content -Path $groupFile -Raw).TrimEnd("`r", "`n")
            [void](Remove-RequirementFromGroupFile -GroupFile $groupFile -Name $normalized -Version $Version)
            $undo.Add({ Write-TextFileAtomic -Path $groupFile -Content $original }.GetNewClosure())
        }
        $newManifest = @($manifest | Where-Object { -not ($_.name -eq $normalized -and $_.version -eq $Version) })
        Save-WheelhouseManifest -Manifest $newManifest -WheelhousePath $WheelhousePath
        $undo.Add({ Save-WheelhouseManifest -Manifest $manifest -WheelhousePath $WheelhousePath }.GetNewClosure())

        # 4. Files.
        if ($Quarantine) {
            New-Item -ItemType Directory -Path $quarantineFolder -Force | Out-Null
            foreach ($entry in $entries) {
                $source = Join-Path $WheelhousePath ([string]$entry.file)
                if (-not (Test-Path -Path $source)) {
                    Write-Log "Wheel file is already missing, nothing to move: $($entry.file)" 'WARN'
                    continue
                }
                $destination = Join-Path $quarantineFolder ([string]$entry.file)
                Move-Item -Path $source -Destination $destination -ErrorAction Stop
                $undo.Add({ Move-Item -Path $destination -Destination $source -Force }.GetNewClosure())
            }
        }
    }
    catch {
        $failure = $_
        for ($i = $undo.Count - 1; $i -ge 0; $i--) {
            try { & $undo[$i] } catch { Write-Log "Could not undo a step of the failed $label operation: $($_.Exception.Message)" 'ERROR' }
        }
        # Everything is back as it was, so there is nothing for a repair to finish.
        Remove-WheelhouseJournal -Path $journal
        Exit-WheelhouseLock -Lock $lock
        throw $failure
    }

    # Deleting cannot be undone, so it is the very last step. If it fails, the journal
    # stays and the next writer finishes the deletion.
    try {
        if (-not $Quarantine) {
            foreach ($entry in $entries) {
                $source = Join-Path $WheelhousePath ([string]$entry.file)
                if (Test-Path -Path $source) {
                    Remove-Item -Path $source -Force -ErrorAction Stop
                }
            }
        }
        $detail = "$verb by $user" + $(if ($Reason) { ": $Reason" } else { '' }) +
            " (files: $(($entries | ForEach-Object { $_.file }) -join ', '); groups: $((@($affectedGroups | ForEach-Object { Split-Path -Path $_ -Leaf }) -join ', ')))"
        $change = [PSCustomObject]@{
            Name    = $normalized
            Version = $Version
            State   = $(if ($Quarantine) { 'Quarantined' } else { 'Removed' })
            Action  = $(if ($Quarantine) { 'Quarantined' } elseif ($alreadyGone) { 'TakenOut' } else { 'Deleted' })
            Detail  = $detail
        }
        Set-WheelhouseCatalogState -WheelhousePath $WheelhousePath -Change @($change)
        Remove-WheelhouseJournal -Path $journal
    }
    finally {
        Exit-WheelhouseLock -Lock $lock
    }

    Write-Log "$label removed from the wheelhouse ($verb)." 'OK'
    return [PSCustomObject]@{
        Name         = $normalized
        Version      = $Version
        Mode         = $mode
        Files        = @($entries | ForEach-Object { [string]$_.file })
        Groups       = @($affectedGroups | ForEach-Object { Split-Path -Path $_ -Leaf })
        QuarantineId = $(if ($Quarantine) { $id } else { $null })
        Denylisted   = [bool]$denyEntry
    }
}

function Resolve-WheelhouseIntegrityProblem {
    # Deals with wheels that were removed or changed outside the manager - the problems
    # Assert-WheelhouseIntegrity -AllowChangedFiles returns - one package version at a time.
    # Virus scanning of the share belongs to the file server's own antivirus; when it moves
    # a wheel to its quarantine, this is how the manager finds out and catches up:
    #   with -AutoQuarantine: a version with a Modified file is quarantined (the changed
    #     file is kept in _quarantine as evidence; Restore refuses it, its hash no longer
    #     matches); a version whose files are only Missing is taken out (pins and manifest
    #     entries removed). Both are denylisted, so no update downloads them again before
    #     someone has looked at why.
    #   without it: nothing is changed; the notices say what to do.
    # Returns one Wheelhouse.Notice (FileModified / FileMissing) per version. Call it while
    # holding the write lock.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Problem,

        [switch]$AutoQuarantine,

        [string]$DenylistPath = (Get-WheelhouseDenylistPath)
    )

    $byPin = [ordered]@{}
    foreach ($item in $Problem) {
        if ($null -eq $item -or $item.Kind -notin 'Missing', 'Modified') { continue }
        $key = "$($item.Entry.name)==$($item.Entry.version)"
        if (-not $byPin.Contains($key)) { $byPin[$key] = [System.Collections.Generic.List[object]]::new() }
        $byPin[$key].Add($item)
    }

    foreach ($key in $byPin.Keys) {
        $items = $byPin[$key]
        $name = [string]$items[0].Entry.name
        $version = [string]$items[0].Entry.version
        $files = @($items | ForEach-Object { [string]$_.Entry.file })
        $modified = [bool]($items | Where-Object { $_.Kind -eq 'Modified' })
        $kind = if ($modified) { 'FileModified' } else { 'FileMissing' }

        if ($AutoQuarantine -and $PSCmdlet.ShouldProcess($key, $(if ($modified) { 'Quarantine changed wheel' } else { 'Take out missing wheel' }))) {
            $reason = if ($modified) { 'content changed outside the manager (hash mismatch)' } else { "removed from the share outside the manager (e.g. by the file server's antivirus)" }
            try {
                $removeParams = @{
                    WheelhousePath = $WheelhousePath
                    Name           = $name
                    Version        = $version
                    Quarantine     = $modified
                    Reason         = $reason
                    DenylistPath   = $DenylistPath
                    LockHeld       = $true
                }
                $done = Remove-WheelhousePackage @removeParams
                $groups = @($done.Groups).Count
                if ($modified) {
                    $message = "The published wheel's content changed (its hash no longer matches). The version was quarantined - the changed file is kept as evidence - taken out of $groups group file(s) and denylisted."
                    $action = 'Find out who or what changed the file; do not restore it. If the package is needed, remove the version from the denylist and run Update-Wheelhouse.ps1 to download a verified copy.'
                }
                else {
                    $message = "The published wheel disappeared from the share - most likely the file server's antivirus moved it to its own quarantine. The version was taken out of $groups group file(s) and the manifest, and denylisted."
                    $action = "Check the file server's antivirus log and quarantine for this file. If it was a false positive, remove the version from the denylist and run Update-Wheelhouse.ps1 to download a verified copy; otherwise keep it blocked and pin another version."
                }
                Write-Log "${key}: $message" 'ERROR'
                Write-WheelhouseEventLog -Id 1003 -Message "${key}: $message"
            }
            catch {
                $message = "The published wheel was $(if ($modified) { 'changed' } else { 'removed' }) outside the manager, and it could not be taken out automatically: $($_.Exception.Message)"
                $action = 'Quarantine or delete the version by hand (UI: Packages tab).'
                Write-Log "${key}: $message" 'ERROR'
            }
        }
        else {
            if ($modified) {
                $message = "The published wheel's content changed (its hash no longer matches); clients may install a file that is not the one that was checked. Nothing was changed automatically (AutoQuarantine is off)."
            }
            else {
                $message = "The published wheel disappeared from the share - most likely the file server's antivirus moved it to its own quarantine. Clients installing its group file will fail. Nothing was changed automatically (AutoQuarantine is off)."
            }
            $action = 'Quarantine or delete the version (UI: Packages tab), or turn AutoQuarantine on. Update-Wheelhouse.ps1 refuses to run until this is resolved.'
        }
        New-WheelhouseNotice -Kind $kind -Package $name -Version $version -File $files -Message $message -Action $action
    }
}

function Move-UntrackedWheelFile {
    # Wheels in the wheelhouse folder that the manifest does not know were never checked
    # (copied in by hand, left over from an old tool), yet clients can install them from
    # the flat index. With -AutoQuarantine they are moved to <wheelhouse>\_untracked\<time>\
    # (uv does not read subfolders); without it they stay. Either way one Wheelhouse.Notice
    # (Untracked) lists them; nothing is returned when there are none. A pin that needs one
    # of them is downloaded and verified by the next Update-Wheelhouse.ps1 run. Call it
    # while holding the write lock, and never on first-time setup (an empty manifest), when
    # the wheels already there are adopted instead.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [switch]$AutoQuarantine
    )

    $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
    if ($manifest.Count -eq 0) { return }
    $untracked = Get-UntrackedWheelFile -Manifest $manifest -WheelhousePath $WheelhousePath
    if ($untracked.Count -eq 0) { return }

    $moved = [System.Collections.Generic.List[string]]::new()
    $failed = [System.Collections.Generic.List[string]]::new()
    $folder = Join-Path (Join-Path $WheelhousePath '_untracked') (Get-Date -Format 'yyyyMMdd_HHmmss')
    if ($AutoQuarantine -and $PSCmdlet.ShouldProcess($WheelhousePath, "Move $($untracked.Count) untracked wheel(s) to $folder")) {
        foreach ($file in $untracked) {
            try {
                if (-not (Test-Path -Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
                Move-Item -LiteralPath (Join-Path $WheelhousePath $file) -Destination (Join-Path $folder $file) -ErrorAction Stop
                $moved.Add($file)
            }
            catch {
                $failed.Add("$file ($($_.Exception.Message))")
            }
        }
        if ($moved.Count -gt 0) {
            Write-WheelhouseEventLog -Id 1003 -Message "$($moved.Count) wheel(s) not published by the manager were moved out of the index to ${folder}: $($moved -join ', ')"
            Write-WheelhouseEvent -WheelhousePath $WheelhousePath -Action 'UntrackedMoved' -Detail "$($moved.Count) wheel(s) not in the manifest moved to $folder`: $($moved -join ', ')"
        }
    }

    if ($moved.Count -gt 0) {
        $message = "$($moved.Count) wheel file(s) that were not published by the manager (not in manifest.json, never checked) were moved out of the index to $folder."
        if ($failed.Count -gt 0) { $message += " Could not move: $($failed -join '; ')." }
        $action = 'Find out who copied them in. If a package is needed, add it to requirements.in and publish it the normal way (it is downloaded and verified again); otherwise delete the folder.'
    }
    else {
        $message = "$($untracked.Count) wheel file(s) are in the wheelhouse folder but not in manifest.json - they were never checked, yet clients can install them."
        if ($failed.Count -gt 0) { $message += " Moving them failed: $($failed -join '; ')." }
        $action = 'Remove them from the folder (or turn AutoQuarantine on to move them out automatically) and publish the packages you need through Update-Wheelhouse.ps1.'
    }
    Write-Log $message 'WARN'
    New-WheelhouseNotice -Kind 'Untracked' -File @($untracked) -Message $message -Action $action
}

function Resolve-MaliciousPackage {
    # Deals with published versions that OSV lists as malicious packages (MAL-* advisories
    # recorded in the catalog, Get-CatalogMaliciousRecord). With -AutoQuarantine each one is
    # quarantined and denylisted; without it nothing is changed. A waived MAL advisory (a
    # confirmed false positive) is left alone. Returns one Wheelhouse.Notice (Malicious)
    # per version. Call it while holding the write lock.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [switch]$AutoQuarantine,

        [string]$DenylistPath = (Get-WheelhouseDenylistPath)
    )

    $catalog = Read-WheelhouseCatalog -WheelhousePath $WheelhousePath
    foreach ($item in @(Get-CatalogMaliciousRecord -Catalog $catalog)) {
        $record = $item.Record
        $key = "$($record.name)==$($record.version)"
        $ids = $item.Ids -join ', '
        if ($AutoQuarantine -and $PSCmdlet.ShouldProcess($key, 'Quarantine malicious package')) {
            try {
                $removeParams = @{
                    WheelhousePath = $WheelhousePath
                    Name           = $record.name
                    Version        = $record.version
                    Quarantine     = $true
                    Reason         = "malicious package advisory $ids"
                    DenylistPath   = $DenylistPath
                    LockHeld       = $true
                }
                $done = Remove-WheelhousePackage @removeParams
                $message = "OSV lists this version as a malicious package ($ids). It was quarantined, taken out of $(@($done.Groups).Count) group file(s) and denylisted."
                Write-WheelhouseEventLog -Id 1003 -Message "${key}: $message"
                $action = 'Find out which clients installed it (uv pip list) and treat those machines as compromised. Do not restore it unless the advisory is withdrawn.'
            }
            catch {
                $message = "OSV lists this version as a malicious package ($ids), and it could not be quarantined automatically: $($_.Exception.Message)"
                $action = 'Quarantine the version by hand now (UI: Packages tab).'
            }
        }
        else {
            $message = "OSV lists this version as a malicious package ($ids). It is still published - nothing was changed automatically (AutoQuarantine is off)."
            $action = 'Quarantine the version now (UI: Packages tab) and find out which clients installed it.'
        }
        Write-Log "${key}: $message" 'ERROR'
        New-WheelhouseNotice -Kind 'Malicious' -Package $record.name -Version $record.version -File @($record.files) -Message $message -Action $action
    }
}

function Restore-WheelhousePackage {
    # Brings a quarantined package back: verifies every file against the hash
    # recorded when it was quarantined, moves it back, re-adds the manifest entries and
    # the pins. The denylist entry that quarantining created is removed (unless
    # -KeepDenylist); a denylist entry added by hand is left alone. Runs under the write
    # lock with a journal, so an interrupted restore is finished by the next writer.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [string]$Id,

        [switch]$KeepDenylist,

        [string]$DenylistPath = (Get-WheelhouseDenylistPath)
    )

    if (-not $PSCmdlet.ShouldProcess($Id, 'Restore quarantined package')) { return }

    $lock = Open-WheelhouseWrite -WheelhousePath $WheelhousePath -DenylistPath $DenylistPath
    try {
        $records = @(Read-QuarantineRecord -WheelhousePath $WheelhousePath)
        $record = $records | Where-Object { $_.id -eq $Id } | Select-Object -First 1
        if (-not $record) {
            throw [System.Collections.Generic.KeyNotFoundException]::new("No quarantine record with id '$Id'.")
        }

        $folder = Join-Path (Get-WheelhouseQuarantinePath -WheelhousePath $WheelhousePath) $Id
        $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath

        # Verify everything before touching anything.
        foreach ($entry in @($record.files)) {
            $source = Join-Path $folder ([string]$entry.file)
            $destination = Join-Path $WheelhousePath ([string]$entry.file)
            if (Test-Path -Path $destination) {
                throw [System.InvalidOperationException]::new("Cannot restore: '$($entry.file)' already exists in the wheelhouse.")
            }
            if ($manifest | Where-Object { $_.file -eq $entry.file }) {
                throw [System.InvalidOperationException]::new("Cannot restore: '$($entry.file)' is already in the manifest.")
            }
            if (-not (Test-Path -Path $source)) {
                throw [System.IO.FileNotFoundException]::new("Quarantined file is missing: $source")
            }
            $hash = (Get-FileHash -Path $source -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($hash -ne $entry.sha256) {
                throw "Cannot restore '$($entry.file)': its hash changed while in quarantine (expected $($entry.sha256), got $hash)."
            }
        }

        $data = [ordered]@{ id = $Id; name = [string]$record.name; version = [string]$record.version; record = $record; folder = $folder; keep_denylist = [bool]$KeepDenylist }
        $journal = New-WheelhouseJournal -WheelhousePath $WheelhousePath -Operation 'restore' -Data $data
        $denyRemoved = Complete-WheelhouseRestoreJournal -WheelhousePath $WheelhousePath -Data $data -DenylistPath $DenylistPath
        $user = if ($env:USERNAME) { $env:USERNAME } else { 'unknown' }
        $change = [PSCustomObject]@{
            Name    = [string]$record.name
            Version = [string]$record.version
            State   = 'Published'
            Action  = 'Restored'
            Detail  = "restored from quarantine by $user" + $(if ($denyRemoved) { '; denylist entry removed' } else { '' })
        }
        Set-WheelhouseCatalogState -WheelhousePath $WheelhousePath -Change @($change)
        Remove-WheelhouseJournal -Path $journal

        Write-Log "$($record.name)==$($record.version) restored from quarantine." 'OK'
        return [PSCustomObject]@{
            Name            = [string]$record.name
            Version         = [string]$record.version
            Files           = @($record.files | ForEach-Object { [string]$_.file })
            DenylistRemoved = $denyRemoved
        }
    }
    finally {
        Exit-WheelhouseLock -Lock $lock
    }
}

function Test-PackageSpec {
    # True for a plain requirement such as "numpy", "pandas>=2.0,<3" or "requests==2.32.3".
    # Anything else - options (-r, --index-url), URLs, paths, environment markers -
    # is refused: the spec ends up in requirements.in, which uv reads as a whole.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Spec
    )

    return ($Spec.Length -le 200) -and ($Spec.Trim() -match $script:PackageSpecPattern)
}

function Add-RequirementInLine {
    # Appends requirement specs to requirements.in. Refuses invalid specs, packages
    # the denylist blocks outright, and names that are already listed - unless -Replace,
    # which then swaps the listed line for the new spec (to change a version range that
    # makes the resolve fail). Returns @{ Added = string[]; Replaced = string[];
    # Skipped = [{Spec; Reason; Replaceable; AlreadyListed}] }; AlreadyListed marks a spec
    # that is in requirements.in exactly as entered. Nothing is written if nothing changes.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string[]]$Spec,

        [AllowEmptyCollection()]
        [object[]]$Denylist = @(),

        [switch]$Replace
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $existingText = ''
    if (Test-Path -Path $Path) {
        $existingText = Get-Content -Path $Path -Raw -ErrorAction Stop
        if ($null -eq $existingText) { $existingText = '' }
        foreach ($line in ($existingText -split "`r?`n")) { $lines.Add($line) }
        if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '') { $lines.RemoveAt($lines.Count - 1) }
    }

    $added = [System.Collections.Generic.List[string]]::new()
    $replaced = [System.Collections.Generic.List[string]]::new()
    $skipped = [System.Collections.Generic.List[object]]::new()
    foreach ($raw in $Spec) {
        $item = ([string]$raw).Trim()
        if (-not (Test-PackageSpec -Spec $item)) {
            $skipped.Add([PSCustomObject]@{ Spec = $item; Reason = 'not a valid requirement (use a name with an optional version, e.g. numpy or pandas>=2.0)'; Replaceable = $false; AlreadyListed = $false })
            continue
        }
        $null = $item -match '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(?<rest>.*)$'
        $name = Get-NormalizedPackageName $Matches['name']
        $rest = $Matches['rest'].Replace(' ', '')

        $current = Get-RequirementInLine -Lines $lines.ToArray() -Name $name
        if ($current) {
            $listed = ($current.Line -replace '(^|\s)#.*$', '').Trim()
            $same = $listed.Replace(' ', '') -eq $item.Replace(' ', '')
            if ($same -or -not $Replace) {
                $skipped.Add([PSCustomObject]@{ Spec = $item; Reason = "'$name' is already listed in requirements.in as '$listed'"; Replaceable = (-not $same); AlreadyListed = $same })
                continue
            }
        }
        $pinned = if ($rest -match '^==(?<v>[^,*]+)$') { $Matches['v'] } else { $null }
        $blocked = if ($pinned) { Get-DenylistMatch -Name $name -Version $pinned -Denylist $Denylist } else { Get-DenylistMatch -Name $name -Version '*' -Denylist @($Denylist | Where-Object { $_.version -eq '*' }) }
        if ($blocked) {
            $skipped.Add([PSCustomObject]@{ Spec = $item; Reason = "blocked by the denylist ($($blocked.version)): $($blocked.reason)"; Replaceable = $false; AlreadyListed = $false })
            continue
        }

        if ($current) {
            $lines[$current.Index] = $item
            $replaced.Add($item)
        }
        else {
            $lines.Add($item)
            $added.Add($item)
        }
    }

    if (($added.Count + $replaced.Count) -gt 0 -and $PSCmdlet.ShouldProcess($Path, "Add $($added.Count), replace $($replaced.Count) requirement(s)")) {
        $folder = Split-Path -Path $Path -Parent
        if ($folder -and -not (Test-Path -Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        Write-TextFileAtomic -Path $Path -Content ($lines -join "`r`n")
    }
    return @{ Added = $added.ToArray(); Replaced = $replaced.ToArray(); Skipped = $skipped.ToArray() }
}

function Remove-RequirementInLine {
    # Takes packages out of requirements.in (every line that names one; names compare
    # normalized) and returns the removed lines. Throws, before writing, when a package is
    # not listed - it is then a dependency of another requirement.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string[]]$Name
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $Path) { foreach ($item in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) { $lines.Add([string]$item) } }
    $removed = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Name) {
        $found = $false
        while ($true) {
            $current = Get-RequirementInLine -Lines $lines.ToArray() -Name $item
            if (-not $current) { break }
            $found = $true
            $removed.Add($current.Line.Trim())
            $lines.RemoveAt($current.Index)
        }
        if (-not $found) {
            throw [System.Collections.Generic.KeyNotFoundException]::new("'$(Get-NormalizedPackageName $item)' is not listed in requirements.in: another requirement depends on it. Remove or change that requirement instead.")
        }
    }
    if ($PSCmdlet.ShouldProcess($Path, "Remove $($Name -join ', ')")) {
        Write-TextFileAtomic -Path $Path -Content ($lines -join "`r`n")
    }
    Write-Output -NoEnumerate $removed.ToArray()
}
