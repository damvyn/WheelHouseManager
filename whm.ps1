<#
.SYNOPSIS
    Wheelhouse Manager - one command for everything: whm <command> [options].

.DESCRIPTION
    Overview
      status                     what needs attention now (findings, overdue, weekly check, proposal)
      doctor [-Offline]          check the installation end to end (exit 1 warnings, 2 problems)
      list [text] [-Vulnerable] [-Overdue]
                                 published packages with their audit status
      info <name> [<version>]    one package: state, groups, checks, vulnerabilities, history

    Changing the wheelhouse (these run the scripts in Jobs\ - same options)
      resolve                    requirements.in -> requirements.txt   (Update-Requirement.ps1)
      approve [-Note text]       approve the current proposal
      reject <reason>            reject the current proposal
      publish                    check and publish the approved proposal (Update-Wheelhouse.ps1)
      fix <name==version> [-ExpediteReason text]
                                 prepare the fix of a vulnerable version (Invoke-WheelhouseRemediation.ps1)
      quarantine <name==version> [-Reason text]
      restore <quarantine id>
      waive <name==version> <advisory> <days> <reason>
      unwaive <name==version> <advisory>

    Checks and tools
      check                      the weekly check now, with alerts   (Test-Wheelhouse.ps1)
      audit [-Package a==1,b==2] audit, no alert                      (Test-WheelhousePackage.ps1)
      scan [-File x.whl]         Defender scan of local copies        (Invoke-WheelhouseScan.ps1)
      schedule                   the weekly check's Scheduled Task
      ui [-Port n]               start the web UI                     (Start-WheelhouseUI.ps1)
      help                       this text

    Exit codes as for every script: 0 OK, 1 needs attention, 2 error, 3 busy.

.EXAMPLE
    .\whm.ps1 status

.EXAMPLE
    .\whm.ps1 fix requests==2.19.0

.EXAMPLE
    .\whm.ps1 publish -ExpeditePackage requests==2.32.4 -ExpediteReason "CVE fix"
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Command = 'help',

    [Parameter(ValueFromRemainingArguments)]
    [object[]]$Rest = @()
)

$jobs = Join-Path $PSScriptRoot 'Jobs'
Import-Module (Join-Path $jobs 'WheelhouseManager') -ErrorAction Stop

function ConvertTo-WhmArgument {
    # The remaining command-line words as { Named = @{ name = value }; Positional = @() }:
    # "-Name value" is a named value, "-Name" followed by another option (or nothing) a
    # switch, anything else positional. A comma list arrives as an array and is kept.
    param([object[]]$Words)

    $named = @{}
    $positional = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $Words.Count; $i++) {
        $word = $Words[$i]
        if ($word -is [string] -and $word -match '^-(?<name>[A-Za-z][A-Za-z0-9]*):?$') {
            $next = if ($i + 1 -lt $Words.Count) { $Words[$i + 1] } else { $null }
            if ($null -eq $next -or ($next -is [string] -and $next -match '^-[A-Za-z]')) { $named[$Matches['name']] = $true }
            else { $named[$Matches['name']] = $next; $i++ }
        }
        else { $positional.Add($word) }
    }
    return @{ Named = $named; Positional = $positional.ToArray() }
}

function Invoke-WhmScript {
    # Runs a script from Jobs\ with the named options; returns its exit code.
    param([string]$Name, [hashtable]$Named)

    & (Join-Path $jobs $Name) @Named | Out-Host
    return $LASTEXITCODE
}

function Get-WhmPin {
    param($Value)
    $pins = @(ConvertTo-WheelhousePin -Pin ([string]$Value))
    if ($pins.Count -ne 1) { throw "Give one package as name==version, not '$Value'." }
    return $pins[0]
}

function Write-WhmLine {
    param([string]$Text, [string]$Level = 'ok')
    $color = switch ($Level) { 'bad' { 'Red' } 'warn' { 'Yellow' } 'ok' { 'Green' } default { 'Gray' } }
    Write-Host $Text -ForegroundColor $color
}

$parsed = ConvertTo-WhmArgument -Words $Rest
$named = $parsed.Named
$positional = $parsed.Positional
$exitCode = 0

try {
    $cfg = Resolve-WheelhouseParameter -BoundParameters @{} -Name @((Get-WheelhouseDefaultSetting).Keys)
    switch ($Command.ToLowerInvariant()) {
        'status' {
            if (-not $cfg.WheelhousePath) { throw 'WheelhousePath is not set - run Setup.ps1 -WheelhousePath ... or whm doctor.' }
            $status = Get-WheelhouseStatus -WheelhousePath $cfg.WheelhousePath -FreshnessDays ([int]$cfg.AuditFreshnessDays)
            Write-Host "Wheelhouse $($cfg.WheelhousePath)"
            Write-Host ("  {0} package(s), {1} published version(s) in {2} group file(s); {3} quarantined" -f $status.Packages, $status.Published, $status.Groups, $status.Quarantined)
            Write-Host ("  Vulnerabilities: {0} open ({1} overdue), {2} waived; {3} yanked; {4} unverified" -f $status.Open, $status.Overdue, $status.Waived, $status.Yanked, $status.Unverified)
            Write-Host "  Weekly check last completed: $(if ($status.LastCheckUtc) { (ConvertTo-UtcDateTime $status.LastCheckUtc).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } else { 'never' })"
            if ($status.Attention.Count -eq 0) { Write-WhmLine 'Nothing needs attention.' 'ok' }
            foreach ($item in $status.Attention) { Write-WhmLine "  [$($item.Level.ToUpperInvariant())] $($item.Text)" $item.Level }
            $exitCode = if ($status.Attention | Where-Object { $_.Level -eq 'bad' }) { 2 } elseif ($status.Attention.Count -gt 0) { 1 } else { 0 }
        }
        'doctor' {
            $checks = @(Test-WheelhouseHealth -Offline:([bool]$named['Offline']))
            foreach ($check in $checks) {
                Write-WhmLine ("  {0,-4} {1,-24} {2}" -f $check.Level.ToUpperInvariant(), $check.Name, $check.Message) $check.Level
                if ($check.Fix -and $check.Level -ne 'ok') { Write-Host "       -> $($check.Fix)" }
            }
            $exitCode = if ($checks | Where-Object { $_.Level -eq 'bad' }) { 2 } elseif ($checks | Where-Object { $_.Level -eq 'warn' }) { 1 } else { 0 }
        }
        'list' {
            if (-not $cfg.WheelhousePath) { throw 'WheelhousePath is not set.' }
            $inventory = Get-WheelhousePackage -WheelhousePath $cfg.WheelhousePath -Denylist @(Read-WheelhouseDenylist) -Services ([string[]]$cfg.VulnerabilityServices)
            $rows = @($inventory.Packages | Sort-Object name, version -Unique)
            if ($positional.Count -gt 0) { $text = [string]$positional[0]; $rows = @($rows | Where-Object { "$($_.name) $($_.version)" -like "*$text*" }) }
            if ($named['Vulnerable']) { $rows = @($rows | Where-Object { $_.open_findings -gt 0 -or $_.audit_status -eq 'Vulnerable' }) }
            if ($named['Overdue']) { $rows = @($rows | Where-Object { $_.overdue }) }
            $rows | Select-Object name, version, @{ n = 'groups'; e = { @($_.groups) -join ',' } }, @{ n = 'audit'; e = { if ($_.open_findings -gt 0) { "$($_.severity)$(if ($_.overdue) { ' OVERDUE' } else { " fix by $(([string]$_.due).Substring(0, 10))" })" } else { $_.audit_status } } },
                @{ n = 'scan'; e = { $_.scan_status } }, @{ n = 'notes'; e = { @($(if ($_.yanked) { 'yanked' }), $(if ($_.denylisted) { 'denylisted' }), $(if ($_.waived_findings) { "$($_.waived_findings) waived" })) -join ' ' } } |
                Format-Table -AutoSize | Out-Host
            Write-Host "$($rows.Count) version(s)."
        }
        'info' {
            if ($positional.Count -lt 1) { throw 'Usage: whm info <name> [<version>]' }
            $name = Get-NormalizedPackageName ([string]$positional[0])
            $catalog = Read-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath
            $records = @($catalog.Records.Values | Where-Object { $_.name -eq $name -and ($positional.Count -lt 2 -or $_.version -eq [string]$positional[1]) })
            if ($records.Count -eq 0) { throw "Nothing is known about $name$(if ($positional.Count -gt 1) { "==$($positional[1])" })." }
            foreach ($record in $records) {
                Write-Host ''
                Write-WhmLine "$($record.name)==$($record.version)  $($record.state)$(if ($record.state_reason) { " - $($record.state_reason)" })" $(if ($record.state -eq 'Published') { 'ok' } else { 'warn' })
                Write-Host "  groups: $(@($record.groups) -join ', ')   files: $(@($record.files) -join ', ')"
                if ($record.checks.audit) { Write-Host "  audit: $($record.checks.audit.status) (last run $($record.checks.audit.last_run))" }
                if ($record.checks.scan) { Write-Host "  scan: $($record.checks.scan.status) (last run $($record.checks.scan.last_run))" }
                if ($record.checks.pypi) { Write-Host "  PyPI: $($record.checks.pypi.status) $($record.checks.pypi.reason)" }
                foreach ($finding in @($record.findings | Where-Object { $_ -and -not $_.resolved_utc })) {
                    $state = Get-CatalogFindingStatus -Finding $finding
                    Write-WhmLine "  $($finding.id) $($finding.severity) - $state, fix by $(([string]$finding.due).Substring(0, 10)); fixed in $(@($finding.fix_versions) -join ', ')$(if ($finding.waiver) { "; waived until $(([string]$finding.waiver.expires_utc).Substring(0, 10)): $($finding.waiver.reason)" })" $(if ($state -eq 'Overdue') { 'bad' } else { 'warn' })
                }
                foreach ($entry in @(Read-WheelhouseEvent -WheelhousePath $cfg.WheelhousePath -Package $record.name -Version $record.version -Last 10)) {
                    Write-Host "    $($entry.ts.Substring(0, 16))  $($entry.action)  $($entry.user)  $($entry.detail)"
                }
            }
        }
        'resolve' { $exitCode = Invoke-WhmScript 'Update-Requirement.ps1' $named }
        'publish' { $exitCode = Invoke-WhmScript 'Update-Wheelhouse.ps1' $named }
        'check' { $exitCode = Invoke-WhmScript 'Test-Wheelhouse.ps1' $named }
        'audit' { $exitCode = Invoke-WhmScript 'Test-WheelhousePackage.ps1' $named }
        'scan' { $exitCode = Invoke-WhmScript 'Invoke-WheelhouseScan.ps1' $named }
        'ui' { $exitCode = Invoke-WhmScript 'Start-WheelhouseUI.ps1' $named }
        'fix' {
            if ($positional.Count -lt 1) { throw 'Usage: whm fix <name==version> [-ExpediteReason text]' }
            $named['Package'] = [string]$positional[0]
            $exitCode = Invoke-WhmScript 'Invoke-WheelhouseRemediation.ps1' $named
        }
        'approve' {
            $proposal = Read-WheelhouseProposal
            if (-not $proposal) { throw 'There is no proposal - run whm resolve first.' }
            $approved = Approve-WheelhouseProposal -Id $proposal.id -Mode ([string]$cfg.ApprovalMode) -Note ([string]$named['Note'])
            Write-WhmLine "Proposal $($approved.id) ($($approved.kind), requested by $($approved.requested_by)) approved by $($approved.approved_by). Publish it with: whm publish" 'ok'
        }
        'reject' {
            $proposal = Read-WheelhouseProposal
            if (-not $proposal) { throw 'There is no proposal.' }
            $rejected = Deny-WheelhouseProposal -Id $proposal.id -Reason (($positional | ForEach-Object { [string]$_ }) -join ' ')
            Write-WhmLine "Proposal $($rejected.id) rejected." 'warn'
        }
        'quarantine' {
            if ($positional.Count -lt 1) { throw 'Usage: whm quarantine <name==version> [-Reason text]' }
            $pin = Get-WhmPin $positional[0]
            $done = Remove-WheelhousePackage -WheelhousePath $cfg.WheelhousePath -Name $pin.Name -Version $pin.Version -Quarantine -Reason ([string]$named['Reason']) -Confirm:$false
            Write-WhmLine "$($done.Name)==$($done.Version) quarantined (id $($done.QuarantineId)); denylisted: $($done.Denylisted)." 'ok'
        }
        'restore' {
            if ($positional.Count -lt 1) { throw 'Usage: whm restore <quarantine id>   (ids: whm info <name>, or the UI''s Quarantine tab)' }
            [void](Restore-WheelhousePackage -WheelhousePath $cfg.WheelhousePath -Id ([string]$positional[0]) -Confirm:$false)
            Write-WhmLine "Restored $($positional[0]). Audit it before clients use it: whm audit" 'ok'
        }
        'waive' {
            if ($positional.Count -lt 4) { throw 'Usage: whm waive <name==version> <advisory id> <days> <reason>' }
            $pin = Get-WhmPin $positional[0]
            $waiverParams = @{
                Name = $pin.Name; Version = $pin.Version; Id = [string]$positional[1]; Days = [int]$positional[2]
                Reason = (($positional | Select-Object -Skip 3 | ForEach-Object { [string]$_ }) -join ' '); MaxDays = [int]$cfg.WaiverMaxDays
            }
            Update-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath -TimeoutSeconds 30 -Update ({
                    param($catalog)
                    [void](Add-WheelhouseWaiver @waiverParams)
                    Set-CatalogFindingWaiver -Catalog $catalog -Waiver @(Read-WheelhouseWaiver)
                }.GetNewClosure())
            Write-WhmLine "$($positional[1]) accepted for $($pin.Name)==$($pin.Version) for $($positional[2]) day(s)." 'ok'
        }
        'unwaive' {
            if ($positional.Count -lt 2) { throw 'Usage: whm unwaive <name==version> <advisory id>' }
            $pin = Get-WhmPin $positional[0]
            $id = [string]$positional[1]
            $result = @{ Removed = $false }
            Update-WheelhouseCatalog -WheelhousePath $cfg.WheelhousePath -TimeoutSeconds 30 -Update ({
                    param($catalog)
                    $result.Removed = Remove-WheelhouseWaiver -Name $pin.Name -Version $pin.Version -Id $id
                    Set-CatalogFindingWaiver -Catalog $catalog -Waiver @(Read-WheelhouseWaiver)
                }.GetNewClosure())
            if (-not $result.Removed) { throw 'No such waiver.' }
            Write-WhmLine "Waiver removed - $id is alerted again." 'ok'
        }
        'schedule' {
            $task = Get-WheelhouseScheduledCheck
            if (-not $task.Registered) {
                Write-WhmLine "'$($task.TaskName)' is not registered. Register it in the UI (Schedule tab) or with Setup.ps1 -RegisterScheduledTask." 'warn'
                $exitCode = 1
            }
            else {
                Write-Host "$($task.TaskName): $($task.State), $($task.Days -join ', ') at $($task.Time) as $($task.User)"
                Write-Host "  last run: $(if ($task.LastRunTime) { (ConvertTo-UtcDateTime $task.LastRunTime).ToLocalTime() } else { 'never' }) - $($task.LastResultText)"
                Write-Host "  next run: $(if ($task.NextRunTime) { (ConvertTo-UtcDateTime $task.NextRunTime).ToLocalTime() } else { '-' })"
                if (-not $task.ForThisInstallation) { Write-WhmLine "  It does not run $($task.Script)." 'warn'; $exitCode = 1 }
            }
        }
        { $_ -in 'help', '-h', '--help', '/?', '-?' } { Get-Help $PSCommandPath -Detailed | Out-Host }
        default {
            Write-WhmLine "Unknown command '$Command'. Run: whm help" 'bad'
            $exitCode = 2
        }
    }
}
catch {
    Write-WhmLine $_.Exception.Message 'bad'
    $exitCode = Get-WheelhouseExitCode -ErrorRecord $_
}

exit $exitCode
