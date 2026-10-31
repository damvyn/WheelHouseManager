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
        Proposal     = $proposal
        Attention    = $attention.ToArray()
    }
}

function Export-WheelhouseAdvisory {
    # Writes <wheelhouse>\advisories.json from the catalog: every published version with an
    # open (or waived) vulnerability or a yank, and every quarantined or removed version,
    # each with what to install instead (the highest published version of the same package
    # without such a problem, if it is newer). Clients read it with
    # Client Install\Test-PythonEnvironment.ps1. Called on every catalog save.
    [CmdletBinding(SupportsShouldProcess)]
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
    $items = foreach ($record in ($records | Sort-Object name, version)) {
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
        $advisories = @($open | ForEach-Object { [ordered]@{ id = $_.id; severity = $_.severity; due = $_.due; fix_versions = @($_.fix_versions) } })
        [ordered]@{
            name        = $record.name
            version     = $record.version
            status      = $status
            reason      = $(if ($record.state -ne 'Published') { [string]$record.state_reason } elseif ($status -eq 'yanked') { "yanked on PyPI: $($record.checks.pypi.reason)" } else { '' })
            advisories  = $advisories
            recommended = $recommended
        }
    }
    $document = [ordered]@{
        schema        = 1
        generated_utc = $now.ToString('o')
        note          = 'Package versions in this wheelhouse that need attention. Generated by Wheelhouse Manager; check an environment with Client Install\Test-PythonEnvironment.ps1.'
        packages      = @($items)
    }
    $path = Join-Path $Catalog.WheelhousePath 'advisories.json'
    if ($PSCmdlet.ShouldProcess($path, 'Write advisories')) {
        Write-JsonFile -Path $path -InputObject $document -Depth 6
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
        if ($PSVersionTable.PSEdition -ne 'Core') {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
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
            $status = Get-WheelhouseStatus -WheelhousePath $wheelhouse -FreshnessDays ([int]$cfg.AuditFreshnessDays) -ProposalPath (Get-WheelhouseProposalPath -ManagerRoot $ManagerRoot)
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
