# ---------------------------------------------------------------------------
# Package catalog (<wheelhouse>\catalog.json) and history (<wheelhouse>\events.jsonl)
# ---------------------------------------------------------------------------
# manifest.json records the bytes (file + sha256). The catalog records what is known
# about each package version: its state, the group files that list it, and the latest
# result of every check. Every writer reconciles it with the manifest, the group files
# and the quarantine records (Sync-WheelhouseCatalog), so it can always be rebuilt from
# them - only the check results start again then.
#
# Record:
#   name, version, state (Published / Quarantined / Removed), state_since, state_reason,
#   groups[] (group file names), files[] (wheel file names), published_utc,
#   checks.audit = { status Passed|Vulnerable|Unknown; last_run; last_ok; vulnerabilities[];
#                    services: { <service>: { status; last_run; vulnerabilities[]; last_error; error } } }
#   checks.scan  = { status Clean|Threat; last_run; threat_files[] }
#   checks.pypi  = { status Ok|Yanked; last_run; reason }
# History: one JSON object per line - ts, user, action, package, version, detail.
#
# Only write either file while holding the write lock (Open-WheelhouseWrite).

$script:CatalogSchemaVersion = 1

function Get-WheelhouseCatalogPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    return Join-Path $WheelhousePath 'catalog.json'
}

function Get-WheelhouseEventLogPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    return Join-Path $WheelhousePath 'events.jsonl'
}

function ConvertTo-CatalogCheck {
    # One check result (checks.audit / scan / pypi) rebuilt with ISO timestamp strings and
    # real lists. PowerShell 7's ConvertFrom-Json turns timestamps into [datetime], which
    # a [string] cast would render as "10/31/2026 15:55:17"; this keeps them ISO on both
    # editions. Returns $null for no result.
    [CmdletBinding()]
    param(
        [ValidateSet('audit', 'scan', 'pypi')]
        [string]$Kind,

        [AllowNull()]
        $Check
    )

    if ($null -eq $Check) { return $null }
    switch ($Kind) {
        'audit' {
            $services = [ordered]@{}
            if ($Check.services) {
                $source = $Check.services
                $names = if ($source -is [System.Collections.IDictionary]) { @($source.Keys) } else { @($source.PSObject.Properties | ForEach-Object { $_.Name }) }
                foreach ($name in $names) {
                    $service = if ($source -is [System.Collections.IDictionary]) { $source[$name] } else { $source.$name }
                    $services[[string]$name] = [ordered]@{
                        status          = [string]$service.status
                        last_run        = ConvertTo-IsoTimestamp -Value $service.last_run
                        vulnerabilities = @(@($service.vulnerabilities) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                        last_error      = ConvertTo-IsoTimestamp -Value $service.last_error
                        error           = [string]$service.error
                    }
                }
            }
            return [ordered]@{
                status          = [string]$Check.status
                last_run        = ConvertTo-IsoTimestamp -Value $Check.last_run
                last_ok         = ConvertTo-IsoTimestamp -Value $Check.last_ok
                vulnerabilities = @(@($Check.vulnerabilities) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                services        = $services
            }
        }
        'scan' {
            return [ordered]@{
                status       = [string]$Check.status
                last_run     = ConvertTo-IsoTimestamp -Value $Check.last_run
                threat_files = @(@($Check.threat_files) | Where-Object { $_ } | ForEach-Object { [string]$_ })
            }
        }
        'pypi' {
            return [ordered]@{
                status   = [string]$Check.status
                last_run = ConvertTo-IsoTimestamp -Value $Check.last_run
                reason   = [string]$Check.reason
            }
        }
    }
}

function ConvertTo-CatalogRecord {
    # A catalog record with every property present (an older catalog.json may lack some),
    # so callers can assign properties without checking first.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $InputObject
    )

    $checks = $InputObject.checks
    return [PSCustomObject]@{
        name          = Get-NormalizedPackageName ([string]$InputObject.name)
        version       = [string]$InputObject.version
        state         = $(if ($InputObject.state) { [string]$InputObject.state } else { 'Published' })
        state_since   = ConvertTo-IsoTimestamp -Value $InputObject.state_since
        state_reason  = [string]$InputObject.state_reason
        groups        = @(foreach ($group in @($InputObject.groups)) { if ($group) { [string]$group } })
        files         = @(foreach ($file in @($InputObject.files)) { if ($file) { [string]$file } })
        published_utc = ConvertTo-IsoTimestamp -Value $InputObject.published_utc
        checks        = [PSCustomObject]@{
            audit = ConvertTo-CatalogCheck -Kind 'audit' -Check $(if ($checks) { $checks.audit } else { $null })
            scan  = ConvertTo-CatalogCheck -Kind 'scan' -Check $(if ($checks) { $checks.scan } else { $null })
            pypi  = ConvertTo-CatalogCheck -Kind 'pypi' -Check $(if ($checks) { $checks.pypi } else { $null })
        }
    }
}

function New-CatalogRecord {
    # Only builds an object - nothing to confirm.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version,

        [ValidateSet('Published', 'Quarantined', 'Removed')]
        [string]$State = 'Published',

        [string]$Reason = ''
    )

    $now = (Get-Date).ToUniversalTime().ToString('o')
    return ConvertTo-CatalogRecord -InputObject ([PSCustomObject]@{
            name          = $Name
            version       = $Version
            state         = $State
            state_since   = $now
            state_reason  = $Reason
            published_utc = $(if ($State -eq 'Published') { $now } else { '' })
        })
}

function Read-WheelhouseCatalog {
    # Returns { Path; WheelhousePath; Exists; Records } - Records maps "name==version" to a
    # record. A missing file gives an empty catalog (Exists = $false); a damaged one
    # throws - it is never read as empty.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $path = Get-WheelhouseCatalogPath -WheelhousePath $WheelhousePath
    $records = [ordered]@{}
    $exists = Test-Path -Path $path
    if ($exists) {
        $content = Get-Content -Path $path -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($content)) {
            try {
                $parsed = ConvertFrom-Json -InputObject $content -ErrorAction Stop
            }
            catch {
                throw "catalog.json exists but could not be parsed ($($_.Exception.Message)). Restore it from a backup, or delete it to rebuild it from manifest.json (the check results start again)."
            }
            if ([int]$parsed.schema -gt $script:CatalogSchemaVersion) {
                throw "catalog.json was written by a newer version of the wheelhouse manager (schema $($parsed.schema)). Update this installation with Setup.ps1."
            }
            foreach ($item in @($parsed.packages)) {
                if ($null -eq $item) { continue }
                $record = ConvertTo-CatalogRecord -InputObject $item
                $records["$($record.name)==$($record.version)"] = $record
            }
        }
    }
    return [PSCustomObject]@{ Path = $path; WheelhousePath = $WheelhousePath; Exists = $exists; Records = $records }
}

function Save-WheelhouseCatalog {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog
    )

    $packages = @($Catalog.Records.Keys | Sort-Object | ForEach-Object { $Catalog.Records[$_] })
    $document = [ordered]@{
        schema      = $script:CatalogSchemaVersion
        updated_utc = (Get-Date).ToUniversalTime().ToString('o')
        packages    = $packages
    }
    if ($PSCmdlet.ShouldProcess($Catalog.Path, 'Save catalog')) {
        Write-JsonFile -Path $Catalog.Path -InputObject $document -Depth 12
        $Catalog.Exists = $true
    }
}

function Write-WheelhouseEvent {
    # Appends one line to the history. History is informational: a failure to write it is
    # logged, never fatal to the change it describes.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [string]$Action,

        [string]$Package = '',

        [string]$Version = '',

        [string]$Detail = ''
    )

    $line = ConvertTo-Json -Compress -InputObject ([ordered]@{
            ts      = (Get-Date).ToUniversalTime().ToString('o')
            user    = $(if ($env:USERNAME) { $env:USERNAME } else { 'unknown' })
            action  = $Action
            package = $Package
            version = $Version
            detail  = $Detail
        })
    $path = Get-WheelhouseEventLogPath -WheelhousePath $WheelhousePath
    if (-not $PSCmdlet.ShouldProcess($path, "Record event $Action")) { return }
    try {
        [System.IO.File]::AppendAllText($path, $line + "`n", [System.Text.UTF8Encoding]::new($false))
    }
    catch {
        Write-Log "Could not write to the history ($path): $($_.Exception.Message)" 'WARN'
    }
}

function Read-WheelhouseEvent {
    # The newest history entries first, optionally for one package (and version).
    # Unreadable lines are skipped with a warning.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [string]$Package,

        [string]$Version,

        [ValidateRange(1, 100000)]
        [int]$Last = 200
    )

    $path = Get-WheelhouseEventLogPath -WheelhousePath $WheelhousePath
    if (-not (Test-Path -Path $path)) { return @() }

    # Writers append while this reads.
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
        $lines = $reader.ReadToEnd() -split "`r?`n"
    }
    finally {
        $stream.Dispose()
    }

    $name = if ($Package) { Get-NormalizedPackageName $Package } else { $null }
    $result = [System.Collections.Generic.List[object]]::new()
    $bad = 0
    for ($i = $lines.Count - 1; $i -ge 0 -and $result.Count -lt $Last; $i--) {
        if ([string]::IsNullOrWhiteSpace($lines[$i])) { continue }
        try { $item = ConvertFrom-Json -InputObject $lines[$i] -ErrorAction Stop } catch { $bad++; continue }
        if ($name -and $item.package -ne $name) { continue }
        if ($Version -and $item.version -ne $Version) { continue }
        $result.Add([PSCustomObject]@{
                ts      = ConvertTo-IsoTimestamp -Value $item.ts
                user    = [string]$item.user
                action  = [string]$item.action
                package = [string]$item.package
                version = [string]$item.version
                detail  = [string]$item.detail
            })
    }
    if ($bad -gt 0) { Write-Log "Skipped $bad unreadable line(s) in $path." 'WARN' }
    return $result.ToArray()
}

function Set-CatalogRecordState {
    # Changes a record's state and records the change in the history (unless -NoEvent).
    # Returns $true if the state changed.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        $Record,

        [Parameter(Mandatory)]
        [ValidateSet('Published', 'Quarantined', 'Removed')]
        [string]$State,

        [string]$Reason = '',

        # History action; defaults to the new state.
        [string]$Action,

        [switch]$NoEvent
    )

    if ($Record.state -eq $State) { return $false }
    if (-not $PSCmdlet.ShouldProcess("$($Record.name)==$($Record.version)", "Set state $State")) { return $false }

    $previous = $Record.state
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $Record.state = $State
    $Record.state_since = $now
    $Record.state_reason = $Reason
    if ($State -eq 'Published' -and -not $Record.published_utc) { $Record.published_utc = $now }
    if (-not $NoEvent) {
        $detail = "$previous -> $State" + $(if ($Reason) { ": $Reason" } else { '' })
        Write-WheelhouseEvent -WheelhousePath $Catalog.WheelhousePath -Action $(if ($Action) { $Action } else { $State }) -Package $Record.name -Version $Record.version -Detail $detail
    }
    return $true
}

function Sync-WheelhouseCatalog {
    # Reconciles the catalog with manifest.json, the group files and the quarantine
    # records: every version in the manifest is Published, with its files and groups; a
    # version that left the manifest is Quarantined (a quarantine record exists) or
    # Removed. The first run creates the catalog and imports the latest audit and scan
    # results from the report files. Returns $true if anything changed; the caller saves.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Catalog
    )

    $wheelhousePath = $Catalog.WheelhousePath
    $manifest = Read-WheelhouseManifest -WheelhousePath $wheelhousePath
    $groupFiles = Get-WheelhouseGroupFile -WheelhousePath $wheelhousePath
    $quarantined = @(Read-QuarantineRecord -WheelhousePath $wheelhousePath)
    $isNew = (-not $Catalog.Exists) -and $Catalog.Records.Count -eq 0
    $changed = $false

    $groupsByPin = @{}
    foreach ($groupFile in $groupFiles) {
        $pins = Read-RequirementFile -FilePath $groupFile
        foreach ($name in $pins.Keys) {
            $key = "$name==$($pins[$name])"
            if (-not $groupsByPin.ContainsKey($key)) { $groupsByPin[$key] = [System.Collections.Generic.List[string]]::new() }
            $groupsByPin[$key].Add((Split-Path -Path $groupFile -Leaf))
        }
    }

    $filesByPin = [ordered]@{}
    foreach ($entry in ($manifest | Sort-Object name, version, file)) {
        $key = "$($entry.name)==$($entry.version)"
        if (-not $filesByPin.Contains($key)) { $filesByPin[$key] = [System.Collections.Generic.List[string]]::new() }
        $filesByPin[$key].Add([string]$entry.file)
    }

    if (-not $PSCmdlet.ShouldProcess($Catalog.Path, 'Reconcile catalog')) { return $false }

    foreach ($key in $filesByPin.Keys) {
        $record = $Catalog.Records[$key]
        if (-not $record) {
            $name, $version = $key -split '==', 2
            $record = New-CatalogRecord -Name $name -Version $version
            $Catalog.Records[$key] = $record
            if (-not $isNew) {
                Write-WheelhouseEvent -WheelhousePath $wheelhousePath -Action 'Discovered' -Package $name -Version $version -Detail 'found in manifest.json without a catalog record'
            }
            $changed = $true
        }
        elseif ($record.state -ne 'Published') {
            [void](Set-CatalogRecordState -Catalog $Catalog -Record $record -State 'Published' -Reason 'back in manifest.json' -Action 'Reconciled')
            $changed = $true
        }
        $files = @($filesByPin[$key])
        if ((@($record.files) -join '|') -ne ($files -join '|')) { $record.files = $files; $changed = $true }
        $groups = @(if ($groupsByPin.ContainsKey($key)) { $groupsByPin[$key] | Sort-Object })
        if ((@($record.groups) -join '|') -ne ($groups -join '|')) { $record.groups = $groups; $changed = $true }
    }

    # Versions in quarantine that the catalog does not know yet (e.g. quarantined before
    # the catalog existed).
    foreach ($item in $quarantined) {
        $key = "$($item.name)==$($item.version)"
        if ($filesByPin.Contains($key) -or $Catalog.Records.Contains($key)) { continue }
        $record = New-CatalogRecord -Name ([string]$item.name) -Version ([string]$item.version) -State 'Quarantined' -Reason ([string]$item.reason)
        $record.files = @($item.files | Where-Object { $_ } | ForEach-Object { [string]$_.file })
        $Catalog.Records[$key] = $record
        if (-not $isNew) {
            Write-WheelhouseEvent -WheelhousePath $wheelhousePath -Action 'Discovered' -Package $record.name -Version $record.version -Detail 'found in quarantine without a catalog record'
        }
        $changed = $true
    }

    foreach ($key in @($Catalog.Records.Keys)) {
        if ($filesByPin.Contains($key)) { continue }
        $record = $Catalog.Records[$key]
        $inQuarantine = [bool]($quarantined | Where-Object { $_.name -eq $record.name -and $_.version -eq $record.version })
        $target = if ($inQuarantine) { 'Quarantined' } else { 'Removed' }
        if ($record.state -ne $target) {
            [void](Set-CatalogRecordState -Catalog $Catalog -Record $record -State $target -Reason 'no longer in manifest.json' -Action 'Reconciled')
            $changed = $true
        }
        if (@($record.groups).Count -gt 0) { $record.groups = @(); $changed = $true }
    }

    if ($isNew) {
        # Keep what the UI already showed: the latest audit and scan results from the reports.
        $reportsFolder = Join-Path $wheelhousePath 'reports'
        $keys = @($Catalog.Records.Keys | ForEach-Object { $name, $version = $_ -split '==', 2; [PSCustomObject]@{ Name = $name; Version = $version } })
        $audit = Get-PackageAuditStatus -ReportsFolder $reportsFolder -Package $keys
        $scan = Get-PackageScanStatus -ReportsFolder $reportsFolder -WheelhousePath $wheelhousePath -File @($manifest | ForEach-Object { [string]$_.file })
        foreach ($key in @($Catalog.Records.Keys)) {
            $record = $Catalog.Records[$key]
            $known = $audit[$key]
            if ($known -and $known.Status -ne 'Unknown') {
                $when = [datetime]::ParseExact($known.LastAudit, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime().ToString('o')
                $record.checks.audit = [ordered]@{
                    status          = $known.Status
                    last_run        = $when
                    last_ok         = $(if ($known.Status -eq 'Passed') { $when } else { '' })
                    vulnerabilities = @($known.Vulnerabilities)
                    services        = [ordered]@{}
                }
            }
            $fileScans = @($record.files | ForEach-Object { $scan[$_] } | Where-Object { $_ -and $_.Status -ne 'Unknown' })
            if ($fileScans.Count -gt 0) {
                $threatFiles = @($record.files | Where-Object { $scan[$_] -and $scan[$_].Status -eq 'Threat' })
                $record.checks.scan = [ordered]@{
                    status       = $(if ($threatFiles.Count -gt 0) { 'Threat' } else { 'Clean' })
                    last_run     = [string]$fileScans[0].LastScan
                    threat_files = $threatFiles
                }
            }
        }
        Write-WheelhouseEvent -WheelhousePath $wheelhousePath -Action 'CatalogCreated' -Detail "$($Catalog.Records.Count) package version(s) imported from manifest.json and the latest reports"
        $changed = $true
    }
    return $changed
}

function Get-CatalogServiceMap {
    # A record's per-service audit results as an ordered hashtable (JSON gives a
    # PSCustomObject; a fresh record has none).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Record
    )

    $map = [ordered]@{}
    $audit = $Record.checks.audit
    if ($audit -and $audit.services) {
        $services = $audit.services
        if ($services -is [System.Collections.IDictionary]) {
            foreach ($key in @($services.Keys)) { $map[[string]$key] = $services[$key] }
        }
        else {
            foreach ($property in $services.PSObject.Properties) { $map[[string]$property.Name] = $property.Value }
        }
    }
    return $map
}

function Update-CatalogAuditResult {
    # Records pip-audit results per package version and service. A Passed or
    # Vulnerable result updates every package its report lists. An Error result (no
    # usable report) is recorded as the service's last error for the pins of its group
    # file - it never turns a status into Passed. The overall status is Vulnerable if any
    # configured service reports a vulnerability, Passed only if every configured service
    # passed, Unknown otherwise. A change of the overall status goes into the history.
    # Versions the catalog does not know (e.g. rejected candidates) are skipped.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$AuditResult,

        [string[]]$Services = @('osv', 'pypi')
    )

    if (-not $PSCmdlet.ShouldProcess($Catalog.Path, 'Record audit results')) { return }
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $touched = [System.Collections.Generic.HashSet[string]]::new()
    # Versions a service actually completed an audit for in this update; only these get
    # a new last_run / last_ok - a failed audit must never look like a fresh pass.
    $completed = [System.Collections.Generic.HashSet[string]]::new()
    $maps = @{}
    $getMap = {
        param($Key)
        if (-not $maps.ContainsKey($Key)) { $maps[$Key] = Get-CatalogServiceMap -Record $Catalog.Records[$Key] }
        return $maps[$Key]
    }

    foreach ($result in $AuditResult) {
        if ($null -eq $result) { continue }
        $service = ([string]$result.Service).ToLowerInvariant()
        if ($result.Status -in 'Passed', 'Vulnerable') {
            try { $dependencies = Get-PipAuditReport -Path $result.ReportPath } catch { continue }
            foreach ($dependency in $dependencies) {
                if ($null -eq $dependency.name -or $null -ne $dependency.skip_reason) { continue }
                $key = "$(Get-NormalizedPackageName $dependency.name)==$($dependency.version)"
                if (-not $Catalog.Records.Contains($key)) { continue }
                $ids = @(@($dependency.vulns) | Where-Object { $_ } | ForEach-Object { [string]$_.id } | Select-Object -Unique)
                $map = & $getMap $key
                $map[$service] = [ordered]@{
                    status          = $(if ($ids.Count -gt 0) { 'Vulnerable' } else { 'Passed' })
                    last_run        = $now
                    vulnerabilities = $ids
                    last_error      = ''
                    error           = ''
                }
                [void]$touched.Add($key)
                [void]$completed.Add($key)
            }
        }
        elseif ($result.Status -eq 'Error' -and $result.GroupFile -and (Test-Path -Path $result.GroupFile)) {
            $pins = Read-RequirementFile -FilePath $result.GroupFile
            foreach ($name in $pins.Keys) {
                $key = "$name==$($pins[$name])"
                if (-not $Catalog.Records.Contains($key)) { continue }
                $map = & $getMap $key
                $previous = $map[$service]
                $map[$service] = [ordered]@{
                    status          = $(if ($previous) { [string]$previous.status } else { 'Unknown' })
                    last_run        = $(if ($previous) { [string]$previous.last_run } else { '' })
                    vulnerabilities = @($(if ($previous) { @($previous.vulnerabilities) } else { @() }))
                    last_error      = $now
                    error           = [string]$result.Message
                }
                [void]$touched.Add($key)
            }
        }
    }

    $configured = @($Services | ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique)
    foreach ($key in $touched) {
        $record = $Catalog.Records[$key]
        $map = $maps[$key]
        $statuses = @(foreach ($service in $configured) { if ($map.Contains($service)) { [string]$map[$service].status } else { 'Unknown' } })
        $status = if ($statuses -contains 'Vulnerable') { 'Vulnerable' } elseif (@($statuses | Where-Object { $_ -ne 'Passed' }).Count -eq 0) { 'Passed' } else { 'Unknown' }
        $vulnerabilities = @(foreach ($service in $configured) { if ($map.Contains($service)) { @($map[$service].vulnerabilities) } }) | Where-Object { $_ } | Select-Object -Unique
        $previous = $record.checks.audit
        $previousStatus = if ($previous) { [string]$previous.status } else { 'Unknown' }
        $fresh = $completed.Contains($key)
        $previousRun = if ($previous) { ConvertTo-IsoTimestamp -Value $previous.last_run } else { '' }
        $previousOk = if ($previous) { ConvertTo-IsoTimestamp -Value $previous.last_ok } else { '' }
        $record.checks.audit = [ordered]@{
            status          = $status
            last_run        = $(if ($fresh) { $now } else { $previousRun })
            last_ok         = $(if ($fresh -and $status -eq 'Passed') { $now } else { $previousOk })
            vulnerabilities = @($vulnerabilities)
            services        = $map
        }
        if ($status -ne $previousStatus) {
            $detail = "$previousStatus -> $status" + $(if (@($vulnerabilities).Count -gt 0) { ": $(@($vulnerabilities) -join ', ')" } else { '' })
            Write-WheelhouseEvent -WheelhousePath $Catalog.WheelhousePath -Action 'AuditChanged' -Package $record.name -Version $record.version -Detail $detail
        }
    }
}

function Update-CatalogScanResult {
    # Records a Defender scan for every published version whose files it covered (the
    # file itself or the whole wheelhouse folder was scanned). A scan that could not be
    # completed (Error) records nothing.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        $ScanResult
    )

    if ($ScanResult.Status -notin 'Clean', 'Threat') { return }
    if (-not $PSCmdlet.ShouldProcess($Catalog.Path, 'Record scan result')) { return }

    $now = (Get-Date).ToUniversalTime().ToString('o')
    $wheelhouseFull = [System.IO.Path]::GetFullPath($Catalog.WheelhousePath).TrimEnd('\')
    $scanned = @(@($ScanResult.ScannedPaths) | Where-Object { $_ } | ForEach-Object { [System.IO.Path]::GetFullPath([string]$_).TrimEnd('\') })
    $threats = @(@($ScanResult.Threats) | Where-Object { $_ })

    foreach ($record in @($Catalog.Records.Values)) {
        if ($record.state -ne 'Published') { continue }
        $paths = @($record.files | ForEach-Object { Join-Path $wheelhouseFull $_ })
        $covered = @($scanned | Where-Object { $path = $_; [string]::Equals($path, $wheelhouseFull, [System.StringComparison]::OrdinalIgnoreCase) -or @($paths | Where-Object { [string]::Equals($_, $path, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0 })
        if ($covered.Count -eq 0) { continue }

        $threatFiles = @($record.files | Where-Object { $full = Join-Path $wheelhouseFull $_; @($threats | Where-Object { ([string]$_.Resource).IndexOf($full, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count -gt 0 })
        $status = if ($threatFiles.Count -gt 0) { 'Threat' } else { 'Clean' }
        $previous = if ($record.checks.scan) { [string]$record.checks.scan.status } else { '' }
        $record.checks.scan = [ordered]@{ status = $status; last_run = $now; threat_files = $threatFiles }
        if ($status -ne $previous -and ($previous -or $status -eq 'Threat')) {
            Write-WheelhouseEvent -WheelhousePath $Catalog.WheelhousePath -Action 'ScanChanged' -Package $record.name -Version $record.version -Detail "$(if ($previous) { $previous } else { 'Unknown' }) -> $status"
        }
    }
}

function Update-CatalogPyPIResult {
    # Records PyPI's yanked flag for published versions (Get-DeployedPackageNotice's
    # Checked list: { Package; Version; Yanked; Reason }).
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Checked
    )

    if (-not $PSCmdlet.ShouldProcess($Catalog.Path, 'Record PyPI results')) { return }
    $now = (Get-Date).ToUniversalTime().ToString('o')
    foreach ($item in $Checked) {
        if ($null -eq $item) { continue }
        $record = $Catalog.Records["$($item.Package)==$($item.Version)"]
        if (-not $record) { continue }
        $status = if ($item.Yanked) { 'Yanked' } else { 'Ok' }
        $previous = if ($record.checks.pypi) { [string]$record.checks.pypi.status } else { '' }
        $record.checks.pypi = [ordered]@{ status = $status; last_run = $now; reason = [string]$item.Reason }
        if ($status -ne $previous -and ($previous -or $status -eq 'Yanked')) {
            Write-WheelhouseEvent -WheelhousePath $Catalog.WheelhousePath -Action 'PyPIChanged' -Package $record.name -Version $record.version -Detail "$(if ($previous) { $previous } else { 'Unknown' }) -> $status$(if ($item.Reason) { ": $($item.Reason)" })"
        }
    }
}

function Update-WheelhouseCatalog {
    # Opens the catalog under the write lock, reconciles it (Sync-WheelhouseCatalog), lets
    # -Update change it ({ param($Catalog) ... }), and saves it. -LockHeld when the caller
    # already holds the write lock. Scripts use this to record check results.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [scriptblock]$Update,

        [switch]$LockHeld,

        [ValidateRange(0, 3600)]
        [int]$TimeoutSeconds = 300,

        [string]$DenylistPath = (Get-WheelhouseDenylistPath)
    )

    if (-not $PSCmdlet.ShouldProcess($WheelhousePath, 'Update catalog')) { return }
    $lock = if ($LockHeld) { $null } else { Open-WheelhouseWrite -WheelhousePath $WheelhousePath -TimeoutSeconds $TimeoutSeconds -DenylistPath $DenylistPath }
    try {
        $catalog = Read-WheelhouseCatalog -WheelhousePath $WheelhousePath
        [void](Sync-WheelhouseCatalog -Catalog $catalog)
        if ($Update) { & $Update $catalog }
        Save-WheelhouseCatalog -Catalog $catalog
    }
    finally {
        Exit-WheelhouseLock -Lock $lock
    }
}

function Set-WheelhouseCatalogState {
    # Records state changes made by an operation (publish, quarantine, delete, restore)
    # in the history and the catalog, under the write lock the caller holds. -Change is a
    # list of { Name; Version; State; Action; Detail }. The change itself has already
    # happened, so a failure here is only logged - the next writer reconciles the catalog.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Change,

        # Also record this scan (e.g. the intake scan of what was just published).
        $ScanResult
    )

    if ($Change.Count -eq 0 -or -not $PSCmdlet.ShouldProcess($WheelhousePath, 'Record state changes')) { return }
    try {
        $catalog = Read-WheelhouseCatalog -WheelhousePath $WheelhousePath
        # A first-time catalog is built (and the reports imported) before the change.
        if (-not $catalog.Exists) { [void](Sync-WheelhouseCatalog -Catalog $catalog) }
        foreach ($item in $Change) {
            $name = Get-NormalizedPackageName $item.Name
            Write-WheelhouseEvent -WheelhousePath $WheelhousePath -Action $item.Action -Package $name -Version $item.Version -Detail $item.Detail
            $key = "$name==$($item.Version)"
            $record = $catalog.Records[$key]
            if (-not $record) {
                $record = New-CatalogRecord -Name $name -Version $item.Version -State $item.State -Reason $item.Detail
                $catalog.Records[$key] = $record
            }
            else {
                [void](Set-CatalogRecordState -Catalog $catalog -Record $record -State $item.State -Reason $item.Detail -NoEvent)
            }
        }
        [void](Sync-WheelhouseCatalog -Catalog $catalog)
        if ($ScanResult) { Update-CatalogScanResult -Catalog $catalog -ScanResult $ScanResult }
        Save-WheelhouseCatalog -Catalog $catalog
    }
    catch {
        Write-Log "The package catalog could not be updated ($($_.Exception.Message)); the next run reconciles it." 'WARN'
    }
}
