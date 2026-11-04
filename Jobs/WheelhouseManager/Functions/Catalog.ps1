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
#   requires[] = the wheel's Requires-Dist without extras: { name; spec } (Update-CatalogRequirement),
#   requires_checked (true once read - requires[] may be empty),
#   checks.audit = { status Passed|Vulnerable|Unknown; last_run; last_ok; vulnerabilities[];
#                    services: { <service>: { status; last_run; vulnerabilities[]; last_error; error } } }
#   checks.scan  = { status Clean|Threat; last_run; threat_files[] }
#   checks.pypi  = { status Ok|Yanked; last_run; reason }
#   findings[]   = one per advisory the audits report: { id; aliases[]; summary; fix_versions[];
#                  severity Critical|High|Medium|Low|Unknown; score; severity_source;
#                  first_seen; due; resolved_utc; waiver { reason; by; expires_utc } | null;
#                  notified (the level last alerted: New|Overdue|Waived|Resolved); notified_utc }
# Document: schema, updated_utc, scheduled_check_utc (last completed Test-Wheelhouse.ps1 run),
# packages[].
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

function ConvertTo-CatalogFinding {
    # One finding with every property present and ISO timestamps (see the header).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $InputObject
    )

    $waiver = $null
    if ($InputObject.waiver -and $InputObject.waiver.expires_utc) {
        $waiver = [ordered]@{
            reason      = [string]$InputObject.waiver.reason
            by          = [string]$InputObject.waiver.by
            expires_utc = ConvertTo-IsoTimestamp -Value $InputObject.waiver.expires_utc
        }
    }
    return [PSCustomObject]@{
        id              = [string]$InputObject.id
        aliases         = @(@($InputObject.aliases) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        summary         = [string]$InputObject.summary
        fix_versions    = @(@($InputObject.fix_versions) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        severity        = $(if ($InputObject.severity) { [string]$InputObject.severity } else { 'Unknown' })
        score           = $(if ($null -ne $InputObject.score -and "$($InputObject.score)" -ne '') { [double]$InputObject.score } else { $null })
        severity_source = [string]$InputObject.severity_source
        first_seen      = ConvertTo-IsoTimestamp -Value $InputObject.first_seen
        due             = ConvertTo-IsoTimestamp -Value $InputObject.due
        resolved_utc    = ConvertTo-IsoTimestamp -Value $InputObject.resolved_utc
        waiver          = $waiver
        notified        = [string]$InputObject.notified
        notified_utc    = ConvertTo-IsoTimestamp -Value $InputObject.notified_utc
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
        requires      = @(foreach ($requirement in @($InputObject.requires)) { if ($requirement -and $requirement.name) { [PSCustomObject]@{ name = [string]$requirement.name; spec = [string]$requirement.spec } } })
        requires_checked = [bool]$InputObject.requires_checked
        findings      = @(foreach ($finding in @($InputObject.findings)) { if ($finding -and $finding.id) { ConvertTo-CatalogFinding -InputObject $finding } })
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
    # Returns { Path; WheelhousePath; Exists; Records; ScheduledCheckUtc } - Records maps "name==version" to a
    # record. A missing file gives an empty catalog (Exists = $false); a damaged one
    # throws - it is never read as empty.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $path = Get-WheelhouseCatalogPath -WheelhousePath $WheelhousePath
    $records = [ordered]@{}
    $scheduledCheck = ''
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
            $scheduledCheck = ConvertTo-IsoTimestamp -Value $parsed.scheduled_check_utc
            foreach ($item in @($parsed.packages)) {
                if ($null -eq $item) { continue }
                $record = ConvertTo-CatalogRecord -InputObject $item
                $records["$($record.name)==$($record.version)"] = $record
            }
        }
    }
    return [PSCustomObject]@{ Path = $path; WheelhousePath = $WheelhousePath; Exists = $exists; Records = $records; ScheduledCheckUtc = $scheduledCheck }
}

function Save-WheelhouseCatalog {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog
    )

    $packages = @($Catalog.Records.Keys | Sort-Object | ForEach-Object { $Catalog.Records[$_] })
    $document = [ordered]@{
        schema              = $script:CatalogSchemaVersion
        updated_utc         = (Get-Date).ToUniversalTime().ToString('o')
        scheduled_check_utc = $(if ($Catalog.PSObject.Properties['ScheduledCheckUtc']) { [string]$Catalog.ScheduledCheckUtc } else { '' })
        packages            = $packages
    }
    if ($PSCmdlet.ShouldProcess($Catalog.Path, 'Save catalog')) {
        Write-JsonFile -Path $Catalog.Path -InputObject $document -Depth 12
        $Catalog.Exists = $true
        # Clients' view of the same state (Client Install\Test-PythonEnvironment.ps1).
        try { Export-WheelhouseAdvisory -Catalog $Catalog }
        catch { Write-Log "advisories.json could not be written: $($_.Exception.Message)" 'WARN' }
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

    # What each published version needs (read once per version from its wheel).
    if (Update-CatalogRequirement -Catalog $Catalog) { $changed = $true }

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
    # The record's findings follow its vulnerabilities (Update-CatalogRecordFinding), with
    # the severities from -Severity (Get-AuditResultSeverity) and due dates from -DueDays;
    # -Waiver (Read-WheelhouseWaiver) is then applied to every record.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$AuditResult,

        [string[]]$Services = @('osv', 'pypi'),

        # Advisory ID -> { Severity; Score; Source; Error }.
        [hashtable]$Severity = @{},

        [hashtable]$DueDays = (Get-WheelhouseDueDayTable),

        [AllowEmptyCollection()]
        [object[]]$Waiver
    )

    if (-not $PSCmdlet.ShouldProcess($Catalog.Path, 'Record audit results')) { return }
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $touched = [System.Collections.Generic.HashSet[string]]::new()
    # Versions a service actually completed an audit for in this update; only these get
    # a new last_run / last_ok - a failed audit must never look like a fresh pass.
    $completed = [System.Collections.Generic.HashSet[string]]::new()
    $maps = @{}
    # "name==version" -> advisory ID -> { aliases; summary; fix_versions } from the reports.
    $details = @{}
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
                if (-not $details.ContainsKey($key)) { $details[$key] = @{} }
                foreach ($vuln in @($dependency.vulns)) {
                    if ($null -eq $vuln -or -not $vuln.id) { continue }
                    $summary = [string]$vuln.description
                    if ($summary.Length -gt 300) { $summary = $summary.Substring(0, 297) + '...' }
                    $details[$key][[string]$vuln.id] = @{
                        aliases      = @(@($vuln.aliases) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                        summary      = $summary
                        fix_versions = @(@($vuln.fix_versions) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                    }
                }
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
        $findingParams = @{
            Catalog  = $Catalog
            Record   = $record
            Id       = [string[]]@($vulnerabilities)
            Detail   = $(if ($details.ContainsKey($key)) { $details[$key] } else { @{} })
            Severity = $Severity
            DueDays  = $DueDays
        }
        Update-CatalogRecordFinding @findingParams
    }
    if ($PSBoundParameters.ContainsKey('Waiver')) {
        Set-CatalogFindingWaiver -Catalog $Catalog -Waiver $Waiver
    }
}

function Update-CatalogRecordFinding {
    # Brings a record's findings in line with the advisories its audits report now (-Id):
    # a new advisory becomes a finding (first_seen now), a known one keeps its first_seen
    # and gets the latest details and severity, one no longer reported is marked resolved
    # (it is dropped once the resolution has been alerted, Set-CatalogFindingNotified).
    # The due date is first_seen plus -DueDays for the severity, so it follows both a
    # re-rated advisory and changed settings. New, resolved and re-rated findings go into
    # the history. A failed lookup (Unknown with an Error) never replaces a known severity.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        $Record,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Id,

        # Advisory ID -> { aliases; summary; fix_versions }.
        [hashtable]$Detail = @{},

        [hashtable]$Severity = @{},

        [hashtable]$DueDays = (Get-WheelhouseDueDayTable)
    )

    if (-not $PSCmdlet.ShouldProcess("$($Record.name)==$($Record.version)", 'Update findings')) { return }
    $now = (Get-Date).ToUniversalTime()
    $nowText = $now.ToString('o')
    $current = @{}
    foreach ($item in $Id) { if ($item) { $current[$item] = $true } }
    $findings = [System.Collections.Generic.List[object]]::new()
    $known = @{}
    foreach ($finding in @($Record.findings)) {
        if ($null -eq $finding) { continue }
        $findings.Add($finding)
        $known[$finding.id] = $finding
    }
    $wheelhousePath = $Catalog.WheelhousePath
    $log = {
        param($Action, $Text)
        Write-WheelhouseEvent -WheelhousePath $wheelhousePath -Action $Action -Package $Record.name -Version $Record.version -Detail $Text
    }

    foreach ($item in @($current.Keys | Sort-Object)) {
        $finding = $known[$item]
        $isNew = -not $finding
        if ($isNew) {
            $finding = ConvertTo-CatalogFinding -InputObject ([PSCustomObject]@{ id = $item; first_seen = $nowText })
            $findings.Add($finding)
        }
        elseif ($finding.resolved_utc) {
            # Reported again: open again, and alerted again as new.
            $finding.resolved_utc = ''
            $finding.notified = ''
            $finding.notified_utc = ''
            & $log 'FindingReopened' "$item is reported again"
        }
        if ($Detail.ContainsKey($item)) {
            $info = $Detail[$item]
            if (@($info.aliases).Count -gt 0) { $finding.aliases = @($info.aliases) }
            if ($info.summary) { $finding.summary = [string]$info.summary }
            $finding.fix_versions = @($info.fix_versions)
        }
        $previousSeverity = $finding.severity
        if ($Severity.ContainsKey($item)) {
            $looked = $Severity[$item]
            $failed = $looked.Severity -eq 'Unknown' -and $looked.Error
            if (-not ($failed -and $finding.severity -ne 'Unknown')) {
                $finding.severity = [string]$looked.Severity
                $finding.score = $looked.Score
                $finding.severity_source = [string]$looked.Source
            }
        }
        $firstSeen = ConvertTo-OptionalUtcDateTime -Value $finding.first_seen
        if (-not $firstSeen) { $firstSeen = $now; $finding.first_seen = $nowText }
        $days = if ($DueDays.ContainsKey($finding.severity)) { [int]$DueDays[$finding.severity] } else { [int]$DueDays['High'] }
        $finding.due = $firstSeen.AddDays($days).ToString('o')
        if ($isNew) {
            & $log 'FindingNew' "$item ($($finding.severity)), due $($finding.due.Substring(0, 10))"
        }
        elseif ($previousSeverity -ne $finding.severity) {
            & $log 'SeverityChanged' "${item}: $previousSeverity -> $($finding.severity), due $($finding.due.Substring(0, 10))"
        }
    }

    foreach ($finding in $findings) {
        if ($current.ContainsKey($finding.id) -or $finding.resolved_utc) { continue }
        $finding.resolved_utc = $nowText
        & $log 'FindingResolved' "$($finding.id) is no longer reported"
    }
    $Record.findings = @($findings | Sort-Object id)
}

function Set-CatalogFindingWaiver {
    # Applies the waivers (Read-WheelhouseWaiver) to every open finding: an unexpired
    # waiver for the same version and advisory is copied onto the finding; a waiver that
    # expired or was removed is taken off. Both changes go into the history.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Waiver
    )

    if (-not $PSCmdlet.ShouldProcess($Catalog.Path, 'Apply waivers')) { return }
    $now = (Get-Date).ToUniversalTime()
    foreach ($record in @($Catalog.Records.Values)) {
        foreach ($finding in @($record.findings)) {
            if ($null -eq $finding -or $finding.resolved_utc) { continue }
            $match = Get-WaiverMatch -Name $record.name -Version $record.version -Id $finding.id -Waiver $Waiver -NowUtc $now
            $had = $finding.waiver
            if ($match) {
                $same = $had -and $had.expires_utc -eq $match.expires_utc -and $had.reason -eq $match.reason
                if (-not $same) {
                    $finding.waiver = [ordered]@{ reason = [string]$match.reason; by = [string]$match.added_by; expires_utc = [string]$match.expires_utc }
                    Write-WheelhouseEvent -WheelhousePath $Catalog.WheelhousePath -Action 'Waived' -Package $record.name -Version $record.version -Detail "$($finding.id) accepted by $($match.added_by) until $($match.expires_utc.Substring(0, 10)): $($match.reason)"
                }
            }
            elseif ($had) {
                $finding.waiver = $null
                $expires = ConvertTo-OptionalUtcDateTime -Value $had.expires_utc
                $why = if ($expires -and $expires -le $now) { 'expired' } else { 'removed' }
                Write-WheelhouseEvent -WheelhousePath $Catalog.WheelhousePath -Action 'WaiverEnded' -Package $record.name -Version $record.version -Detail "$($finding.id): waiver $why"
            }
        }
    }
}

function Get-CatalogFindingStatus {
    # Resolved, Waived, Overdue (past its due date) or Open.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        $Finding,

        [datetime]$NowUtc = (Get-Date).ToUniversalTime()
    )

    if ($Finding.resolved_utc) { return 'Resolved' }
    if ($Finding.waiver) { return 'Waived' }
    $due = ConvertTo-OptionalUtcDateTime -Value $Finding.due
    if ($due -and $due -le $NowUtc) { return 'Overdue' }
    return 'Open'
}

function Get-CatalogFindingAlert {
    # Every finding of a published version, with what the alert should say about it.
    # Alerts are stateful: each finding's "notified" holds the level last alerted, so
    #   AlertReason New           - open, never alerted
    #               Overdue       - its due date passed since the last alert
    #               Reminder      - still overdue, last alerted -ReminderDays or more ago
    #               WaiverExpired - open again after a waiver ended
    #               Resolved      - no longer reported (alerted once, then dropped)
    #               $null         - nothing new to say (still open, or waived)
    # Returns objects shaped like Get-VulnerabilityFinding's (for the alert) plus Key,
    # Severity, Score, FirstSeen, Due, Status, Level, Notified, AlertReason and Waiver.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [ValidateRange(1, 3650)]
        [int]$ReminderDays = 7,

        [datetime]$NowUtc = (Get-Date).ToUniversalTime()
    )

    foreach ($key in @($Catalog.Records.Keys | Sort-Object)) {
        $record = $Catalog.Records[$key]
        if ($record.state -ne 'Published') { continue }
        $serviceMap = Get-CatalogServiceMap -Record $record
        $neededBy = $null
        foreach ($finding in @($record.findings)) {
            if ($null -eq $neededBy) { $neededBy = Format-CatalogDependent -Dependent (Get-CatalogDependent -Catalog $Catalog -Name $record.name -Version $record.version) }
            if ($null -eq $finding) { continue }
            $services = [System.Collections.Generic.List[string]]::new()
            foreach ($service in $serviceMap.Keys) {
                if (@($serviceMap[$service].vulnerabilities) -contains $finding.id) { $services.Add($(if ($service -eq 'osv') { 'OSV' } else { 'PyPI' })) }
            }
            $status = Get-CatalogFindingStatus -Finding $finding -NowUtc $NowUtc
            $level = if ($status -eq 'Open') { 'New' } else { $status }
            $notifiedUtc = ConvertTo-OptionalUtcDateTime -Value $finding.notified_utc
            $reason = $null
            switch ($status) {
                'Resolved' { if ($finding.notified -and $finding.notified -ne 'Resolved') { $reason = 'Resolved' } }
                'Overdue' {
                    if ($finding.notified -ne 'Overdue') { $reason = 'Overdue' }
                    elseif (-not $notifiedUtc -or ($NowUtc - $notifiedUtc).TotalDays -ge $ReminderDays) { $reason = 'Reminder' }
                }
                'Open' {
                    if (-not $finding.notified) { $reason = 'New' }
                    elseif ($finding.notified -eq 'Waived') { $reason = 'WaiverExpired' }
                }
            }
            [PSCustomObject]@{
                Key            = $key
                Package        = $record.name
                NormalizedName = $record.name
                Version        = $record.version
                VulnId         = $finding.id
                Aliases        = @($finding.aliases) -join ', '
                Description    = $finding.summary
                FixVersions    = @($finding.fix_versions) -join ', '
                Services       = $services
                GroupFiles     = [System.Collections.Generic.List[string]]::new([string[]]@($record.groups))
                Deployed       = $true
                Severity       = $finding.severity
                Score          = $finding.score
                FirstSeen      = $finding.first_seen
                Due            = $finding.due
                Status         = $status
                Level          = $level
                Notified       = $finding.notified
                AlertReason    = $reason
                Waiver         = $finding.waiver
                # Published packages that need this version (Get-CatalogDependent).
                NeededBy       = $neededBy
            }
        }
    }
}

function Set-CatalogFindingNotified {
    # Records that these findings (Get-CatalogFindingAlert output) were alerted - call it
    # only after the alert was delivered, so a failed delivery is retried by the next run.
    # A waived finding is marked silently. Resolved findings are dropped once alerted
    # (or never alerted, or their version is no longer published).
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Finding,

        [datetime]$NowUtc = (Get-Date).ToUniversalTime()
    )

    if (-not $PSCmdlet.ShouldProcess($Catalog.Path, 'Record alerted findings')) { return }
    $now = $NowUtc.ToString('o')
    foreach ($item in $Finding) {
        if ($null -eq $item -or -not ($item.AlertReason -or ($item.Level -eq 'Waived' -and $item.Notified -ne 'Waived'))) { continue }
        $record = $Catalog.Records[$item.Key]
        if (-not $record) { continue }
        # Not $finding: that is the -Finding parameter (names are case-insensitive).
        $target = @($record.findings) | Where-Object { $_.id -eq $item.VulnId } | Select-Object -First 1
        if (-not $target) { continue }
        $target.notified = $item.Level
        $target.notified_utc = $now
    }
    foreach ($record in @($Catalog.Records.Values)) {
        $kept = @($record.findings | Where-Object { $_ -and -not ($_.resolved_utc -and ($_.notified -in '', 'Resolved' -or $record.state -ne 'Published')) })
        if ($kept.Count -ne @($record.findings).Count) { $record.findings = $kept }
    }
}

function Get-CatalogUnverifiedRecord {
    # Published versions whose last completed audit is older than -FreshnessDays (or that
    # were never audited although published that long ago): their status is no longer
    # known to be current.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        [ValidateRange(1, 3650)]
        [int]$FreshnessDays,

        [datetime]$NowUtc = (Get-Date).ToUniversalTime()
    )

    $limit = $NowUtc.AddDays(-$FreshnessDays)
    foreach ($record in @($Catalog.Records.Values)) {
        if ($record.state -ne 'Published') { continue }
        $lastRun = if ($record.checks.audit) { ConvertTo-OptionalUtcDateTime -Value $record.checks.audit.last_run } else { $null }
        if ($lastRun -and $lastRun -ge $limit) { continue }
        $published = ConvertTo-OptionalUtcDateTime -Value $record.published_utc
        if (-not $lastRun -and $published -and $published -ge $limit) { continue }
        $record
    }
}

function Get-CatalogMaliciousRecord {
    # Published versions with an open (not waived, not resolved) malicious-package
    # advisory (OSV MAL-*): { Record; Ids }.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Catalog
    )

    foreach ($record in @($Catalog.Records.Values)) {
        if ($record.state -ne 'Published') { continue }
        $ids = @($record.findings | Where-Object { $_ -and (Test-MaliciousAdvisoryId -Id $_.id) -and -not $_.resolved_utc -and -not $_.waiver } | ForEach-Object { $_.id })
        if ($ids.Count -gt 0) { [PSCustomObject]@{ Record = $record; Ids = $ids } }
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
            Write-WheelhouseEventLog -Id 1004 -Message "$($item.Action): $name==$($item.Version) - $($item.Detail)"
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
