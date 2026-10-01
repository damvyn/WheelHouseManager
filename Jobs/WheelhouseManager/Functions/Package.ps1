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

        [int]$MaxReports = 300
    )

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
            if ($seen[$key].Count -eq 2) { $fullySeen++ }
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

function Get-WheelhousePackage {
    # The wheelhouse inventory: one row per wheel file in manifest.json, with the
    # group files that list it, its latest audit and Defender status, and whether the
    # denylist blocks it. Also returns the untracked wheel files and the groups.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [AllowEmptyCollection()]
        [object[]]$Denylist = @()
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

    $reportsFolder = Join-Path $WheelhousePath 'reports'
    $packageKeys = @($manifest | ForEach-Object { [PSCustomObject]@{ Name = [string]$_.name; Version = [string]$_.version } })
    $auditStatus = Get-PackageAuditStatus -ReportsFolder $reportsFolder -Package $packageKeys
    $scanStatus = Get-PackageScanStatus -ReportsFolder $reportsFolder -WheelhousePath $WheelhousePath -File @($manifest | ForEach-Object { [string]$_.file })

    $rows = foreach ($entry in ($manifest | Sort-Object name, version, file)) {
        $key = "$($entry.name)==$($entry.version)"
        $filePath = Join-Path $WheelhousePath ([string]$entry.file)
        # Plain assignments: a one-element array inside $(...) would be unrolled to a scalar, and the
        # JSON the UI receives would then hold a string instead of a list.
        $rowGroups = @()
        if ($groupsByPin.ContainsKey($key)) { $rowGroups = @($groupsByPin[$key]) }
        $deny = Get-DenylistMatch -Name $entry.name -Version $entry.version -Denylist $Denylist
        $audit = $auditStatus[$key]
        $scan = $scanStatus[[string]$entry.file]
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
            vulnerabilities = @($audit.Vulnerabilities)
            last_audit      = $audit.LastAudit
            scan_status     = $scan.Status
            last_scan       = $scan.LastScan
            denylisted      = $(if ($deny) { [string]$deny.reason } else { $null })
        }
    }

    return [PSCustomObject]@{
        Packages  = @($rows)
        Groups    = $groupNames.ToArray()
        Untracked = @($untracked)
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
    #     Update-Wheelhouse run does not download it again.
    # Runs under the wheelhouse lock. If a step before the file removal fails, the
    # earlier steps are undone. Returns a summary object; throws on failure.
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

        [string]$DenylistPath = (Get-WheelhouseDenylistPath)
    )

    $normalized = Get-NormalizedPackageName $Name
    $label = "$normalized==$Version"
    $mode = if ($Quarantine) { 'Quarantine' } else { 'Delete' }
    if (-not $PSCmdlet.ShouldProcess($label, "$mode package")) { return }

    $lock = Enter-WheelhouseLock -WheelhousePath $WheelhousePath
    $undo = [System.Collections.Generic.List[scriptblock]]::new()
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

        Write-Log "$mode $label (wheel file(s): $(($entries | ForEach-Object { $_.file }) -join ', '); groups: $(($affectedGroups | ForEach-Object { Split-Path -Path $_ -Leaf }) -join ', '))..."

        # 1. Denylist first: it only ever blocks more, so it is safe to leave on an abort.
        $denyEntry = $null
        if (-not $NoDenylist) {
            $denyReason = if ($Reason) { "$Reason ($($mode.ToLowerInvariant())d)" } else { "$($mode.ToLowerInvariant())d from the wheelhouse" }
            $existing = Get-DenylistMatch -Name $normalized -Version $Version -Denylist @(Read-WheelhouseDenylist -Path $DenylistPath)
            $denySource = if ($Quarantine) { 'quarantined' } else { 'removed' }
            $denyEntry = Add-WheelhouseDenylistEntry -Name $normalized -Version $Version -Reason $denyReason -Source $denySource -Path $DenylistPath
            if ($null -eq $existing) {
                $undo.Add({ [void](Remove-WheelhouseDenylistEntry -Name $normalized -Version $Version -Path $DenylistPath) }.GetNewClosure())
            }
        }

        # 2. Quarantine record (written before any file moves, so a record never
        # lags behind the files).
        if ($Quarantine) {
            $records = @(Read-QuarantineRecord -WheelhousePath $WheelhousePath)
            $record = [PSCustomObject]@{
                id              = $id
                name            = $normalized
                version         = $Version
                files           = @($entries)
                groups          = @($affectedGroups | ForEach-Object { Split-Path -Path $_ -Leaf })
                reason          = $Reason
                quarantined_utc = (Get-Date).ToUniversalTime().ToString('o')
                quarantined_by  = $(if ($env:USERNAME) { $env:USERNAME } else { 'unknown' })
                denylisted      = [bool]$denyEntry
            }
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
        Exit-WheelhouseLock -Lock $lock
        throw $failure
    }

    # Deleting cannot be undone, so it is the very last step.
    $deletedFiles = [System.Collections.Generic.List[string]]::new()
    try {
        if (-not $Quarantine) {
            foreach ($entry in $entries) {
                $source = Join-Path $WheelhousePath ([string]$entry.file)
                if (Test-Path -Path $source) {
                    Remove-Item -Path $source -Force -ErrorAction Stop
                    $deletedFiles.Add([string]$entry.file)
                }
            }
        }
    }
    finally {
        Exit-WheelhouseLock -Lock $lock
    }

    Write-Log "$label removed from the wheelhouse ($($mode.ToLowerInvariant()))." 'OK'
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

function Restore-WheelhousePackage {
    # Brings a quarantined package back: verifies every file against the hash
    # recorded when it was quarantined, moves it back, re-adds the manifest entries and
    # the pins. The denylist entry that quarantining created is removed (unless
    # -KeepDenylist); a denylist entry added by hand is left alone.
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

    $lock = Enter-WheelhouseLock -WheelhousePath $WheelhousePath
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

        foreach ($entry in @($record.files)) {
            Move-Item -Path (Join-Path $folder ([string]$entry.file)) -Destination (Join-Path $WheelhousePath ([string]$entry.file)) -ErrorAction Stop
        }
        Save-WheelhouseManifest -Manifest (@($manifest) + @($record.files)) -WheelhousePath $WheelhousePath

        foreach ($groupName in @($record.groups)) {
            $groupFile = Join-Path $WheelhousePath "$groupName"
            $listed = if (Test-Path -Path $groupFile) { Read-RequirementFile -FilePath $groupFile } else { @{} }
            if ($listed[[string]$record.name] -ne $record.version) {
                Add-RequirementToGroupFile -GroupFile $groupFile -Name $record.name -Version $record.version
            }
        }

        Save-QuarantineRecord -WheelhousePath $WheelhousePath -Record @($records | Where-Object { $_.id -ne $Id })
        if ((Test-Path -Path $folder) -and -not (Get-ChildItem -Path $folder -Force)) {
            Remove-Item -Path $folder -Force
        }

        $denyRemoved = $false
        if (-not $KeepDenylist) {
            $denyRemoved = Remove-WheelhouseDenylistEntry -Name $record.name -Version $record.version -OnlySource 'quarantined' -Path $DenylistPath
        }
        Write-Log "$($record.name)==$($record.version) restored from quarantine." 'OK'
        return [PSCustomObject]@{
            Name             = [string]$record.name
            Version          = [string]$record.version
            Files            = @($record.files | ForEach-Object { [string]$_.file })
            DenylistRemoved  = $denyRemoved
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
    # the denylist blocks outright, and names that are already listed. Returns
    # @{ Added = string[]; Skipped = [{Spec; Reason}] }; nothing is written if
    # nothing is added.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string[]]$Spec,

        [AllowEmptyCollection()]
        [object[]]$Denylist = @()
    )

    $existingNames = @{}
    $existingText = ''
    if (Test-Path -Path $Path) {
        $existingText = Get-Content -Path $Path -Raw -ErrorAction Stop
        foreach ($line in ($existingText -split "`r?`n")) {
            $clean = ($line -replace '(^|\s)#.*$', '').Trim()
            if ($clean -match '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)') {
                $existingNames[(Get-NormalizedPackageName $Matches['name'])] = $clean
            }
        }
    }

    $added = [System.Collections.Generic.List[string]]::new()
    $skipped = [System.Collections.Generic.List[object]]::new()
    foreach ($raw in $Spec) {
        $item = ([string]$raw).Trim()
        if (-not (Test-PackageSpec -Spec $item)) {
            $skipped.Add([PSCustomObject]@{ Spec = $item; Reason = 'not a valid requirement (use a name with an optional version, e.g. numpy or pandas>=2.0)' })
            continue
        }
        $null = $item -match '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(?<rest>.*)$'
        $name = Get-NormalizedPackageName $Matches['name']
        $rest = $Matches['rest'].Replace(' ', '')

        if ($existingNames.ContainsKey($name)) {
            $skipped.Add([PSCustomObject]@{ Spec = $item; Reason = "'$name' is already listed in requirements.in as '$($existingNames[$name])'" })
            continue
        }
        $pinned = if ($rest -match '^==(?<v>[^,*]+)$') { $Matches['v'] } else { $null }
        $blocked = if ($pinned) { Get-DenylistMatch -Name $name -Version $pinned -Denylist $Denylist } else { Get-DenylistMatch -Name $name -Version '*' -Denylist @($Denylist | Where-Object { $_.version -eq '*' }) }
        if ($blocked) {
            $skipped.Add([PSCustomObject]@{ Spec = $item; Reason = "blocked by the denylist ($($blocked.version)): $($blocked.reason)" })
            continue
        }

        $existingNames[$name] = $item
        $added.Add($item)
    }

    if ($added.Count -gt 0 -and $PSCmdlet.ShouldProcess($Path, "Add $($added.Count) requirement(s)")) {
        $prefix = if ($existingText -and -not $existingText.EndsWith("`n")) { "`r`n" } else { '' }
        $folder = Split-Path -Path $Path -Parent
        if ($folder -and -not (Test-Path -Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        Add-Content -Path $Path -Value ($prefix + ($added -join "`r`n")) -Encoding utf8 -ErrorAction Stop
    }
    return @{ Added = $added.ToArray(); Skipped = $skipped.ToArray() }
}
