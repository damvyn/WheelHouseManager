# ---------------------------------------------------------------------------
# Status, health check ("doctor") and advisories.json for clients
# ---------------------------------------------------------------------------
# Get-WheelhouseStatus summarizes the catalog for whm status and the UI's Overview tab;
# Test-WheelhouseHealth checks the installation (whm doctor, Setup.ps1);
# Export-WheelhouseAdvisory writes <wheelhouse>\advisories.json - every published version
# with an open problem and every quarantined or removed one - which the optional client
# script Client Install\Test-PythonEnvironment.ps1 reads offline.

function Get-WheelhouseStatus {
    # { Published; Packages; Groups; Open; Overdue; Waived; Yanked; Quarantined; Unverified;
    #   Untracked; LastCheckUtc; CheckOverdue; Proposal; Attention[] } - Attention items are
    #   { Level bad|warn; Text; Target (UI tab[:filter]) }, worst first.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [ValidateRange(1, 3650)]
        [int]$FreshnessDays = 8,

        # Older audits than this: an Attention item (whm and the UI then start one).
        [ValidateRange(1, 3650)]
        [int]$AuditMaxAgeDays = 7,

        [string]$ProposalPath = (Get-WheelhouseProposalPath)
    )

    $catalog = Read-WheelhouseCatalog -WheelhousePath $WheelhousePath
    $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
    if (-not $catalog.Exists) {
        # No writer has created the catalog yet: count what the manifest publishes (read
        # only - creating the catalog is a writer's job, under the lock).
        foreach ($entry in $manifest) {
            $key = "$($entry.name)==$($entry.version)"
            if (-not $catalog.Records.Contains($key)) { $catalog.Records[$key] = New-CatalogRecord -Name ([string]$entry.name) -Version ([string]$entry.version) }
        }
    }
    $now = (Get-Date).ToUniversalTime()
    $published = @($catalog.Records.Values | Where-Object { $_.state -eq 'Published' })
    $findings = @(foreach ($record in $published) {
            foreach ($finding in @($record.findings)) {
                if ($finding -and -not $finding.resolved_utc) {
                    [PSCustomObject]@{ Key = "$($record.name)==$($record.version)"; Id = $finding.id; Severity = $finding.severity; Due = $finding.due; Status = (Get-CatalogFindingStatus -Finding $finding -NowUtc $now) }
                }
            }
        })
    $open = @($findings | Where-Object { $_.Status -in 'Open', 'Overdue' })
    $overdue = @($open | Where-Object { $_.Status -eq 'Overdue' })
    $yanked = @($published | Where-Object { $_.checks.pypi -and $_.checks.pypi.status -eq 'Yanked' })
    $unverified = @(Get-CatalogUnverifiedRecord -Catalog $catalog -FreshnessDays $FreshnessDays -NowUtc $now)
    $untracked = Get-UntrackedWheelFile -Manifest $manifest -WheelhousePath $WheelhousePath
    [string[]]$groups = Get-WheelhouseGroupFile -WheelhousePath $WheelhousePath
    $lastCheck = ConvertTo-OptionalUtcDateTime -Value $catalog.ScheduledCheckUtc
    $checkOverdue = $published.Count -gt 0 -and (-not $lastCheck -or ($now - $lastCheck).TotalDays -gt $FreshnessDays)
    $proposal = $null
    try { $proposal = Read-WheelhouseProposal -Path $ProposalPath } catch { Write-Verbose "proposal.json unreadable: $($_.Exception.Message)" }

    $attention = [System.Collections.Generic.List[object]]::new()
    $add = { param($Level, $Text, $Target) $attention.Add([PSCustomObject]@{ Level = $Level; Text = $Text; Target = $Target }) }
    if ($overdue.Count -gt 0) {
        & $add 'bad' "$($overdue.Count) vulnerability finding(s) are past their fix-by date ($(@($overdue | ForEach-Object { $_.Key } | Select-Object -Unique) -join ', ')). Fix or quarantine them, or accept the risk." 'packages:overdue'
    }
    if ($checkOverdue) {
        & $add 'bad' $(if ($lastCheck) { "The weekly check last completed on $($lastCheck.ToString('yyyy-MM-dd')) - more than $FreshnessDays day(s) ago." } else { 'The weekly check has never completed for this wheelhouse.' }) 'schedule'
    }
    $auditAge = Get-WheelhouseAuditAge -Catalog $catalog -MaxAgeDays $AuditMaxAgeDays -NowUtc $now
    if ($auditAge.Stale) {
        & $add 'warn' $auditAge.Message 'packages:unaudited'
    }
    if ($unverified.Count -gt 0) {
        & $add 'bad' "$($unverified.Count) published version(s) have no completed audit in the last $FreshnessDays day(s) (Unverified)." 'packages:unaudited'
    }
    $notOverdue = $open.Count - $overdue.Count
    if ($notOverdue -gt 0) {
        & $add 'warn' "$notOverdue open vulnerability finding(s) within their fix-by date." 'packages:vulnerable'
    }
    if ($yanked.Count -gt 0) { & $add 'warn' "$($yanked.Count) published version(s) were yanked on PyPI." 'packages:yanked' }
    if ($untracked.Count -gt 0) { & $add 'warn' "$($untracked.Count) wheel file(s) in the wheelhouse are not in the manifest." 'packages' }
    if ($proposal -and $proposal.state -in 'Proposed', 'Approved') {
        & $add 'warn' "Proposal $($proposal.id) ($($proposal.kind)) by $($proposal.requested_by) is $($proposal.state.ToLowerInvariant()) and not published yet." 'add'
    }

    return [PSCustomObject]@{
        Published    = $published.Count
        Packages     = @($published | ForEach-Object { $_.name } | Select-Object -Unique).Count
        Groups       = $groups.Count
        Open         = $open.Count
        Overdue      = $overdue.Count
        Waived       = @($findings | Where-Object { $_.Status -eq 'Waived' }).Count
        Yanked       = $yanked.Count
        Quarantined  = @($catalog.Records.Values | Where-Object { $_.state -eq 'Quarantined' }).Count
        Unverified   = $unverified.Count
        Untracked    = $untracked.Count
        LastCheckUtc = [string]$catalog.ScheduledCheckUtc
        CheckOverdue = [bool]$checkOverdue
        AuditStale   = [bool]$auditAge.Stale
        OldestAuditUtc = $(if ($auditAge.OldestUtc) { $auditAge.OldestUtc.ToString('o') } else { '' })
        Proposal     = $proposal
        Attention    = $attention.ToArray()
    }
}

function Get-WheelhouseAuditAge {
    # How old the audits of the published versions are: { Stale; OldestUtc (the oldest
    # version's latest completed audit, $null when one was never audited); Never (versions
    # without any completed audit); Published; Message }. Stale when a published version has
    # had no completed audit for -MaxAgeDays. Updates audit only their new packages, so this
    # is what tells whm and the UI to start a full audit.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [ValidateRange(1, 3650)]
        [int]$MaxAgeDays = 7,

        [datetime]$NowUtc = (Get-Date).ToUniversalTime()
    )

    $published = @($Catalog.Records.Values | Where-Object { $_.state -eq 'Published' })
    $oldest = $null
    $never = 0
    foreach ($record in $published) {
        $last = $null
        if ($record.checks -and $record.checks.audit -and $record.checks.audit.last_run) {
            $last = ConvertTo-OptionalUtcDateTime -Value $record.checks.audit.last_run
        }
        if (-not $last) { $never++; continue }
        if ($null -eq $oldest -or $last -lt $oldest) { $oldest = $last }
    }
    $stale = $published.Count -gt 0 -and ($never -gt 0 -or ($NowUtc - $oldest).TotalDays -gt $MaxAgeDays)
    $message = ''
    if ($stale) {
        $message = if ($never -gt 0) {
            "$never published version(s) have never been audited."
        }
        else {
            "The oldest audit of a published version is from $($oldest.ToString('yyyy-MM-dd')) - more than $MaxAgeDays day(s) ago."
        }
        $message += ' Updates audit only their new packages - the weekly check audits the rest; whm and the UI start it now.'
    }
    return [PSCustomObject]@{
        Stale     = [bool]$stale
        OldestUtc = $oldest
        Never     = $never
        Published = $published.Count
        Message   = $message
    }
}

function Start-WheelhouseBackgroundAudit {
    # Runs the weekly check (Test-Wheelhouse.ps1: integrity, denylist, yanked, audit of every
    # published version, malicious packages; results into the catalog and the UI; alert by
    # email, or Alert_*.html in the reports folder) now, without waiting for it:
    #   - the registered Scheduled Task when there is one for this installation, so it runs
    #     as its account exactly like a scheduled run;
    #   - otherwise Test-Wheelhouse.ps1 as a hidden child process of this PowerShell, as the
    #     current user.
    # Alerts are stateful, so an early run sends nothing twice. Only one at a time:
    # <manager root>\state\background-audit.json remembers the start; while that run is still
    # going (at most -MaxHours) nothing new is started. Returns { Started; Via (Task|Process);
    # ProcessId; Message }.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [string]$ManagerRoot = $script:ManagerRoot,

        [ValidateRange(1, 48)]
        [int]$MaxHours = 6
    )

    $stateFolder = Join-Path $ManagerRoot 'state'
    $statePath = Join-Path $stateFolder 'background-audit.json'
    $now = (Get-Date).ToUniversalTime()

    $task = $null
    try {
        $registered = Get-WheelhouseScheduledCheck -ManagerRoot $ManagerRoot
        if ($registered.Registered -and $registered.ForThisInstallation) { $task = $registered }
    }
    catch { Write-Verbose "No Scheduled Task available: $($_.Exception.Message)" }

    if (Test-Path -LiteralPath $statePath) {
        try {
            $previous = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            $since = ConvertTo-OptionalUtcDateTime -Value $previous.started_utc
            $running = if ([string]$previous.via -eq 'Task') { [bool]($task -and $task.State -eq 'Running') }
            else { [bool](Get-Process -Id ([int]$previous.pid) -ErrorAction SilentlyContinue) }
            if ($running -and $since -and ($now - $since).TotalHours -lt $MaxHours) {
                return [PSCustomObject]@{ Started = $false; Via = [string]$previous.via; ProcessId = $previous.pid; Message = "The weekly check is already running (started $($since.ToLocalTime().ToString('yyyy-MM-dd HH:mm')))." }
            }
        }
        catch { Write-Verbose "Unreadable $statePath - starting a new check: $($_.Exception.Message)" }
    }
    if (-not $PSCmdlet.ShouldProcess($WheelhousePath, 'Run the weekly check now')) {
        return [PSCustomObject]@{ Started = $false; Via = ''; ProcessId = $null; Message = 'Not started (WhatIf).' }
    }
    New-Item -ItemType Directory -Path $stateFolder -Force | Out-Null

    if ($task) {
        if ($task.State -eq 'Running') {
            return [PSCustomObject]@{ Started = $false; Via = 'Task'; ProcessId = $null; Message = "The weekly check's Scheduled Task is already running." }
        }
        try {
            Start-WheelhouseScheduledCheck
            Write-JsonFile -Path $statePath -InputObject ([ordered]@{ via = 'Task'; pid = $null; started_utc = $now.ToString('o'); wheelhouse = $WheelhousePath })
            return [PSCustomObject]@{ Started = $true; Via = 'Task'; ProcessId = $null; Message = "The weekly check's Scheduled Task was started now (as $($task.User)). Its results appear in the UI, and its alert is emailed or saved as Alert_*.html in the reports folder." }
        }
        catch { Write-Log "The Scheduled Task could not be started ($($_.Exception.Message)) - running the weekly check as this user instead." 'WARN' }
    }

    $script = Join-Path (Join-Path $ManagerRoot 'Jobs') 'Test-Wheelhouse.ps1'
    if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
        return [PSCustomObject]@{ Started = $false; Via = ''; ProcessId = $null; Message = "Cannot start the weekly check: $script not found." }
    }
    $startParams = @{
        FilePath     = (Get-Process -Id $PID).Path
        ArgumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -WheelhousePath `"$WheelhousePath`""
        PassThru     = $true
    }
    if ($PSVersionTable.PSEdition -ne 'Core' -or $IsWindows) { $startParams['WindowStyle'] = 'Hidden' }
    $process = Start-Process @startParams
    Write-JsonFile -Path $statePath -InputObject ([ordered]@{ via = 'Process'; pid = $process.Id; started_utc = $now.ToString('o'); wheelhouse = $WheelhousePath })
    return [PSCustomObject]@{ Started = $true; Via = 'Process'; ProcessId = $process.Id; Message = "The weekly check (Test-Wheelhouse.ps1) was started in the background as $(if ($env:USERNAME) { $env:USERNAME } else { 'this user' }) (process $($process.Id)) - no Scheduled Task is registered for this installation. Its results appear in the UI, and its alert is emailed or saved as Alert_*.html in the reports folder." }
}

function Invoke-WheelhouseAuditFreshnessCheck {
    # whm and the web UI call this on start: when the audits are older than -MaxAgeDays
    # (Get-WheelhouseAuditAge), runs the weekly check now (Start-WheelhouseBackgroundAudit,
    # unless -NoStart). Returns { Stale; Message; Started; StartMessage }. Never throws: a
    # problem is returned in Message.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [ValidateRange(1, 3650)]
        [int]$MaxAgeDays = 7,

        [switch]$NoStart,

        [string]$ManagerRoot = $script:ManagerRoot
    )

    try {
        $catalog = Read-WheelhouseCatalog -WheelhousePath $WheelhousePath
        $age = Get-WheelhouseAuditAge -Catalog $catalog -MaxAgeDays $MaxAgeDays
        $start = $null
        if ($age.Stale -and -not $NoStart -and $PSCmdlet.ShouldProcess($WheelhousePath, 'Run the weekly check now')) {
            $start = Start-WheelhouseBackgroundAudit -WheelhousePath $WheelhousePath -ManagerRoot $ManagerRoot
        }
        return [PSCustomObject]@{
            Stale        = [bool]$age.Stale
            Message      = $age.Message
            Started      = [bool]($start -and $start.Started)
            StartMessage = $(if ($start) { $start.Message } else { '' })
        }
    }
    catch {
        return [PSCustomObject]@{ Stale = $false; Message = "Could not check the age of the audits: $($_.Exception.Message)"; Started = $false; StartMessage = '' }
    }
}

function Invoke-WheelhouseStartupAuditCheck {
    # The audit-age check whm and the web UI run when they start: reads WheelhousePath and
    # AuditMaxAgeDays from the settings, runs Invoke-WheelhouseAuditFreshnessCheck and logs
    # what it found (WARN) and whether an audit was started. Returns its result, or $null
    # when no wheelhouse is configured.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$ManagerRoot = $script:ManagerRoot
    )

    $settings = Get-WheelhouseDefaultSetting -ManagerRoot $ManagerRoot
    $stored = Get-WheelhouseSetting -SettingsPath (Get-WheelhouseSettingsPath -ManagerRoot $ManagerRoot)
    foreach ($key in @($stored.Keys)) { if ($null -ne $stored[$key] -and "$($stored[$key])" -ne '') { $settings[$key] = $stored[$key] } }
    $wheelhouse = [string]$settings.WheelhousePath
    if (-not $wheelhouse -or -not (Test-Path -LiteralPath $wheelhouse -PathType Container)) { return $null }
    if (-not $PSCmdlet.ShouldProcess($wheelhouse, 'Check the age of the audits')) { return $null }
    $check = Invoke-WheelhouseAuditFreshnessCheck -WheelhousePath $wheelhouse -MaxAgeDays ([int]$settings.AuditMaxAgeDays) -ManagerRoot $ManagerRoot
    if ($check.Message) { Write-Log $check.Message 'WARN' }
    if ($check.StartMessage) { Write-Log $check.StartMessage $(if ($check.Started) { 'OK' } else { 'WARN' }) }
    return $check
}

function Get-WheelhouseAdvisoryItem {
    # The versions clients should know about, from the catalog: every published version with
    # an open (or waived) vulnerability or a yank, and every quarantined or removed one - each
    # { name; version; status quarantined|removed|overdue|vulnerable|waived|yanked; reason;
    # advisories[]; recommended } where recommended is the highest problem-free published
    # version of the same package that is newer. advisories.json and index.html show these.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Catalog
    )

    $now = (Get-Date).ToUniversalTime()
    $records = @($Catalog.Records.Values)
    $problems = @{}
    foreach ($record in $records) {
        $open = @($record.findings | Where-Object { $_ -and -not $_.resolved_utc })
        $yanked = $record.checks.pypi -and $record.checks.pypi.status -eq 'Yanked'
        $problems["$($record.name)==$($record.version)"] = ($record.state -ne 'Published') -or $yanked -or $open.Count -gt 0
    }
    foreach ($record in ($records | Sort-Object name, version)) {
        $key = "$($record.name)==$($record.version)"
        if (-not $problems[$key]) { continue }
        $open = @($record.findings | Where-Object { $_ -and -not $_.resolved_utc })
        $statuses = @($open | ForEach-Object { Get-CatalogFindingStatus -Finding $_ -NowUtc $now })
        $status = if ($record.state -eq 'Quarantined') { 'quarantined' }
        elseif ($record.state -eq 'Removed') { 'removed' }
        elseif ($statuses -contains 'Overdue') { 'overdue' }
        elseif ($statuses -contains 'Open') { 'vulnerable' }
        elseif ($statuses -contains 'Waived') { 'waived' }
        else { 'yanked' }
        $better = @($records | Where-Object {
                $_.name -eq $record.name -and $_.state -eq 'Published' -and -not $problems["$($_.name)==$($_.version)"] -and
                (ConvertTo-PackageVersionKey -Version $_.version) -and (ConvertTo-PackageVersionKey -Version $record.version) -and
                (Compare-PackageVersion -Left $_.version -Right $record.version) -gt 0
            } | ForEach-Object { $_.version })
        $recommended = ''
        foreach ($candidate in $better) { if (-not $recommended -or (Compare-PackageVersion -Left $candidate -Right $recommended) -gt 0) { $recommended = $candidate } }
        [ordered]@{
            name        = $record.name
            version     = $record.version
            status      = $status
            reason      = $(if ($record.state -ne 'Published') { [string]$record.state_reason } elseif ($status -eq 'yanked') { "yanked on PyPI: $($record.checks.pypi.reason)" } else { '' })
            advisories  = @($open | ForEach-Object { [ordered]@{ id = $_.id; severity = $_.severity; due = $_.due; fix_versions = @($_.fix_versions) } })
            recommended = $recommended
        }
    }
}

function Export-WheelhouseAdvisory {
    # Writes <wheelhouse>\advisories.json (Get-WheelhouseAdvisoryItem) for the client check
    # (Client Install\Test-PythonEnvironment.ps1) and <wheelhouse>\index.html for people
    # (Export-WheelhouseIndexPage). Called on every catalog save.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog
    )

    $items = @(Get-WheelhouseAdvisoryItem -Catalog $Catalog)
    $document = [ordered]@{
        schema        = 1
        generated_utc = (Get-Date).ToUniversalTime().ToString('o')
        note          = 'Package versions in this wheelhouse that need attention. Generated by Wheelhouse Manager; check an environment with Client Install\Test-PythonEnvironment.ps1.'
        packages      = $items
    }
    $path = Join-Path $Catalog.WheelhousePath 'advisories.json'
    if (-not $PSCmdlet.ShouldProcess($path, 'Write advisories and index.html')) { return }
    Write-JsonFile -Path $path -InputObject $document -Depth 6
    Export-WheelhouseIndexPage -Catalog $Catalog -Advisory $items
}

function Export-WheelhouseIndexPage {
    # Writes <wheelhouse>\index.html: a static, read-only page for the people who install
    # from the share - what is available (package, versions, group files), what to avoid and
    # what to use instead, how to install, and when the wheelhouse was last checked. Plain
    # HTML and CSS, no script, so it opens from a file share in any browser.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [AllowEmptyCollection()]
        [object[]]$Advisory = @()
    )

    $now = Get-Date
    $published = @($Catalog.Records.Values | Where-Object { $_.state -eq 'Published' } | Sort-Object name)
    $flagged = @{}
    foreach ($item in $Advisory) { $flagged["$($item.name)==$($item.version)"] = $item }
    $lastCheck = ConvertTo-OptionalUtcDateTime -Value $Catalog.ScheduledCheckUtc
    $share = [string]$Catalog.WheelhousePath

    $groups = @{}
    foreach ($record in $published) { foreach ($group in @($record.groups)) { if ($group) { $groups[$group] = 1 + [int]$groups[$group] } } }
    $groupRows = @(foreach ($group in ($groups.Keys | Sort-Object { Get-GroupFileNumber -Path $_ })) {
            "<tr><td><code>$(ConvertTo-HtmlSafe $group)</code></td><td>$($groups[$group])</td><td><code>uv pip install -r &quot;$(ConvertTo-HtmlSafe (Join-Path $share $group))&quot;</code></td></tr>"
        })

    $attentionRows = @(foreach ($item in ($Advisory | Where-Object { $_.status -ne 'removed' })) {
            $worst = @($item.advisories) | Sort-Object { Get-SeverityRank -Severity $_.severity } -Descending | Select-Object -First 1
            $instead = if ($item.recommended) { "<code>$(ConvertTo-HtmlSafe "$($item.name)==$($item.recommended)")</code>" } else { '<span class="muted">none yet - ask the wheelhouse administrators</span>' }
            $ids = (@($item.advisories) | ForEach-Object { ConvertTo-HtmlSafe $_.id }) -join ', '
            $severity = if ($worst) { ConvertTo-HtmlSafe $worst.severity } else { '' }
            "<tr><td><code>$(ConvertTo-HtmlSafe "$($item.name)==$($item.version)")</code></td><td><span class=`"tag $($item.status)`">$(ConvertTo-HtmlSafe $item.status)</span></td><td>$severity</td><td>$ids</td><td>$instead</td></tr>"
        })

    $byName = [ordered]@{}
    foreach ($record in $published) {
        if (-not $byName.Contains($record.name)) { $byName[$record.name] = [System.Collections.Generic.List[object]]::new() }
        $byName[$record.name].Add($record)
    }
    $packageRows = @(foreach ($name in $byName.Keys) {
            $versions = (@($byName[$name] | ForEach-Object {
                        $item = $flagged["$($_.name)==$($_.version)"]
                        $mark = if ($item) { " <span class=`"tag $($item.status)`">$(ConvertTo-HtmlSafe $item.status)</span>" } else { '' }
                        "<code>$(ConvertTo-HtmlSafe $_.version)</code>$mark"
                    })) -join '<br>'
            $inGroups = (@($byName[$name] | ForEach-Object { @($_.groups) } | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { ConvertTo-HtmlSafe $_ })) -join ', '
            $since = @($byName[$name] | ForEach-Object { [string]$_.published_utc } | Where-Object { $_ } | Sort-Object) | Select-Object -Last 1
            "<tr><td><b>$(ConvertTo-HtmlSafe $name)</b></td><td>$versions</td><td>$inGroups</td><td>$(if ($since) { $since.Substring(0, 10) })</td></tr>"
        })

    $checkText = if ($lastCheck) { "Last weekly check: $($lastCheck.ToLocalTime().ToString('yyyy-MM-dd HH:mm'))." } else { 'The weekly check has not run yet.' }
    $attentionHtml = if ($attentionRows.Count -eq 0) { '<p>No published version needs attention.</p>' }
    else {
        "<p>These versions have known problems or were taken out. If you installed one, install the version shown instead.</p>`n" +
        "<table><tr><th>Version</th><th>Status</th><th>Severity</th><th>Advisories</th><th>Install instead</th></tr>`n$($attentionRows -join "`n")`n</table>"
    }
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Python wheelhouse</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; font-size: 14px; color: #1c2330; margin: 24px; max-width: 1200px; }
  h1 { font-size: 22px; margin-bottom: 4px; } h2 { font-size: 17px; margin-top: 28px; }
  .muted { color: #667085; } code { font-family: Consolas, monospace; font-size: 13px; background: #f1f3f6; padding: 1px 4px; border-radius: 3px; }
  table { border-collapse: collapse; width: 100%; margin-top: 8px; }
  th { text-align: left; background: #eef1f5; padding: 6px 8px; font-size: 12.5px; }
  td { border-top: 1px solid #e3e6eb; padding: 6px 8px; vertical-align: top; }
  td:first-child code { white-space: nowrap; }
  .tag { display: inline-block; padding: 0 6px; border-radius: 8px; font-size: 12px; background: #fff3d1; color: #9a6700; }
  .tag.overdue, .tag.quarantined, .tag.removed { background: #fde7e4; color: #b42318; }
  .tag.waived { background: #eceff3; color: #475467; }
</style>
</head>
<body>
<h1>Python wheelhouse</h1>
<p class="muted">$(ConvertTo-HtmlSafe $share) - updated $($now.ToString('yyyy-MM-dd HH:mm')). $(ConvertTo-HtmlSafe $checkText) $($published.Count) published version(s) of $($byName.Count) package(s).</p>

<h2>How to install</h2>
<p>uv on this computer installs from this wheelhouse only. Install a package by name, or a whole group file - a set of exact versions that were checked together:</p>
<p><code>uv pip install &lt;package&gt;</code> &nbsp; or &nbsp; <code>uv pip install -r &lt;group file&gt;</code></p>
<p>A package that is not listed below is not available yet - ask the wheelhouse administrators to add it.</p>

<h2>Do not use ($($attentionRows.Count))</h2>
$attentionHtml

<h2>Group files ($($groups.Count))</h2>
<table><tr><th>File</th><th>Packages</th><th>Install all of them</th></tr>
$($groupRows -join "`n")
</table>

<h2>Packages ($($byName.Count))</h2>
<table><tr><th>Package</th><th>Versions</th><th>Group files</th><th>Last published</th></tr>
$($packageRows -join "`n")
</table>

<p class="muted">Generated by Wheelhouse Manager. Check an environment for affected packages with Test-PythonEnvironment.ps1 (Client Install).</p>
</body>
</html>
"@
    $path = Join-Path $Catalog.WheelhousePath 'index.html'
    if ($PSCmdlet.ShouldProcess($path, 'Write index.html')) {
        Write-TextFileAtomic -Path $path -Content $html
    }
}

function Test-WheelhouseHealth {
    # The installation checked from end to end ("whm doctor"): settings, wheelhouse access,
    # tools, network (PyPI, OSV), data files, interrupted operations, the weekly check and
    # alert delivery. Returns { Name; Level ok|warn|bad; Message; Fix } per check; never throws.
    [CmdletBinding()]
    param(
        [string]$ManagerRoot = $script:ManagerRoot,

        # Skip the network checks (PyPI, OSV).
        [switch]$Offline
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $report = { param($Name, $Level, $Message, $Fix) $results.Add([PSCustomObject]@{ Name = $Name; Level = $Level; Message = $Message; Fix = $(if ($Fix) { $Fix } else { '' }) }) }

    $settingsPath = Get-WheelhouseSettingsPath -ManagerRoot $ManagerRoot
    $settings = @{}
    if (Test-Path -LiteralPath $settingsPath) {
        try { $settings = Import-PowerShellDataFile -Path $settingsPath -ErrorAction Stop; & $report 'Settings' 'ok' $settingsPath }
        catch { & $report 'Settings' 'bad' "$settingsPath cannot be read: $($_.Exception.Message)" 'Fix the file, or delete it and run Setup.ps1 again.' }
    }
    else { & $report 'Settings' 'warn' "$settingsPath does not exist - defaults are used." 'Run Setup.ps1 -WheelhousePath ...' }
    $cfg = Resolve-WheelhouseParameter -BoundParameters @{} -Name @((Get-WheelhouseDefaultSetting -ManagerRoot $ManagerRoot).Keys) -Settings $settings
    $wheelhouse = [string]$cfg.WheelhousePath

    $reachable = $false
    if (-not $wheelhouse) {
        & $report 'Wheelhouse' 'bad' 'WheelhousePath is not set.' 'Run Setup.ps1 -WheelhousePath \\server\share\wheelhouse, or set it in the UI.'
    }
    elseif (-not (Test-Path -LiteralPath $wheelhouse -PathType Container)) {
        & $report 'Wheelhouse' 'bad' "$wheelhouse does not exist or is not reachable." 'Check the path and this account''s access to the share.'
    }
    else {
        $reachable = $true
        $probe = Join-Path $wheelhouse ".doctor-$([guid]::NewGuid().ToString('N')).tmp"
        try {
            [System.IO.File]::WriteAllText($probe, 'doctor')
            Remove-Item -LiteralPath $probe -Force
            & $report 'Wheelhouse' 'ok' "$wheelhouse is reachable and writable."
        }
        catch { & $report 'Wheelhouse' 'bad' "$wheelhouse is reachable but not writable: $($_.Exception.Message)" 'Give this account write access to the share.' }
        $drive = Get-WheelhouseNetworkDrive -Path $wheelhouse
        if ($drive) { & $report 'Wheelhouse path' 'warn' "$wheelhouse is on the mapped drive $($drive.Drive); the Scheduled Task will not see it." "Use the UNC path $($drive.Unc) (UI: Schedule tab, or Setup.ps1 -WheelhousePath)." }
    }

    foreach ($tool in @(Get-WheelhouseToolStatus)) {
        & $report "Tool: $($tool.name)" $tool.level $(if ($tool.available) { "$($tool.name) $($tool.version)" } else { $tool.message }) $(if ($tool.level -ne 'ok') { $tool.message } else { '' })
    }

    if (-not $Offline) {
        Enable-WheelhouseTls12
        foreach ($site in @(@('PyPI', 'https://pypi.org/pypi/pip/json'), @('OSV', 'https://api.osv.dev/v1/vulns/GHSA-j8r2-6x86-q33q'))) {
            try {
                [void](Invoke-RestMethod -Uri $site[1] -TimeoutSec 20 -ErrorAction Stop)
                & $report "Network: $($site[0])" 'ok' "$($site[1]) answers."
            }
            catch {
                $level = if ($site[0] -eq 'PyPI') { 'bad' } else { 'warn' }
                & $report "Network: $($site[0])" $level "$($site[1]) cannot be reached: $($_.Exception.Message)" 'Allow this server (and the weekly check''s account) to reach it, through the proxy if there is one.'
            }
        }
    }

    $readers = @(
        @('Denylist', { [void](Read-WheelhouseDenylist -Path (Get-WheelhouseDenylistPath -ManagerRoot $ManagerRoot)) }),
        @('Waivers', { [void](Read-WheelhouseWaiver -Path (Get-WheelhouseWaiverPath -ManagerRoot $ManagerRoot)) }),
        @('Proposal', { [void](Read-WheelhouseProposal -Path (Get-WheelhouseProposalPath -ManagerRoot $ManagerRoot)) })
    )
    if ($reachable) {
        $readers += , @('Manifest', { [void](Read-WheelhouseManifest -WheelhousePath $wheelhouse) })
        $readers += , @('Catalog', { [void](Read-WheelhouseCatalog -WheelhousePath $wheelhouse) })
        $readers += , @('Quarantine records', { [void](Read-QuarantineRecord -WheelhousePath $wheelhouse) })
    }
    foreach ($reader in $readers) {
        try { & $reader[1]; & $report "Data: $($reader[0])" 'ok' 'readable' }
        catch { & $report "Data: $($reader[0])" 'bad' $_.Exception.Message 'Fix or restore the file - it is never read as empty.' }
    }

    if ($reachable) {
        $journals = @(Get-ChildItem -LiteralPath (Get-WheelhouseJournalFolder -WheelhousePath $wheelhouse) -Filter '*.json' -File -ErrorAction SilentlyContinue)
        if ($journals.Count -gt 0) { & $report 'Interrupted operations' 'warn' "$($journals.Count) journal(s) of an interrupted operation are waiting: $(($journals | ForEach-Object { $_.Name }) -join ', ')." 'The next change finishes them automatically; if one keeps failing, see Troubleshooting in the README.' }
        else { & $report 'Interrupted operations' 'ok' 'none' }

        try {
            $status = Get-WheelhouseStatus -WheelhousePath $wheelhouse -FreshnessDays ([int]$cfg.AuditFreshnessDays) -AuditMaxAgeDays ([int]$cfg.AuditMaxAgeDays) -ProposalPath (Get-WheelhouseProposalPath -ManagerRoot $ManagerRoot)
            if ($status.Published -eq 0) { & $report 'Weekly check' 'ok' 'Nothing is published yet.' }
            elseif ($status.CheckOverdue) { & $report 'Weekly check' 'bad' $(if ($status.LastCheckUtc) { "Last completed $(([string]$status.LastCheckUtc).Substring(0, 10)) - more than $($cfg.AuditFreshnessDays) day(s) ago." } else { 'Never completed.' }) 'Register the Scheduled Task (UI: Schedule tab, or Setup.ps1 -RegisterScheduledTask) and check its last result.' }
            else { & $report 'Weekly check' 'ok' "Last completed $(([string]$status.LastCheckUtc).Substring(0, 10))." }
        }
        catch { & $report 'Weekly check' 'warn' "The status could not be read: $($_.Exception.Message)" '' }
    }

    try {
        $task = Get-WheelhouseScheduledCheck -ManagerRoot $ManagerRoot
        if (-not $task.Registered) { & $report 'Scheduled Task' 'warn' "'$($task.TaskName)' is not registered." 'UI: Schedule tab, or Setup.ps1 -RegisterScheduledTask.' }
        elseif (-not $task.ForThisInstallation) { & $report 'Scheduled Task' 'warn' "'$($task.TaskName)' does not run $($task.Script)." 'Register it again from this installation.' }
        elseif ($task.LastResult -in 2, 2147943645) { & $report 'Scheduled Task' 'bad' "Last run: $($task.LastResultText)" 'Open the latest Log_Audit_*.txt in the reports folder, or re-enter the password (UI: Schedule tab).' }
        else { & $report 'Scheduled Task' 'ok' "$($task.State), runs $($task.Days -join ', ') at $($task.Time) as $($task.User); last run: $($task.LastResultText)." }
    }
    catch { & $report 'Scheduled Task' 'warn' "Task Scheduler could not be read: $($_.Exception.Message)" '' }

    if ([string]::IsNullOrWhiteSpace([string]$cfg.SmtpServer)) {
        & $report 'Alerts' 'warn' "No SmtpServer: alerts are saved as HTML files in the reports folder, nobody is emailed." 'Set SmtpServer and MailTo (UI: Settings).'
    }
    else { & $report 'Alerts' 'ok' "Emailed to $($cfg.MailTo) via $($cfg.SmtpServer)." }

    return $results.ToArray()
}
