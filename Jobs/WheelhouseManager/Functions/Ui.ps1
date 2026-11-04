# ---------------------------------------------------------------------------
# Local web UI: HTTP API (Invoke-WheelhouseUiApi), background jobs that run the
# Jobs\*.ps1 scripts as child processes, and the HttpListener loop
# ---------------------------------------------------------------------------
# The UI listens on localhost only. Every /api request needs the session token that
# Start-WheelhouseUI.ps1 puts into the URL it opens; state-changing requests must
# also be JSON and come from the same origin. Long operations (audit, scan, add)
# run as child powershell processes - never inside this module's scope - and the
# browser follows their log.

$script:UiWebRoot = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Web'
$script:UiJobs = [System.Collections.Generic.List[object]]::new()
$script:UiJobCounter = 0
$script:UiShutdown = $false
$script:UiToolStatus = $null
$script:UiToolStatusTime = [DateTime]::MinValue
$script:UiMaxJobHistory = 30
$script:UiMimeTypes = @{
    '.html' = 'text/html; charset=utf-8'
    '.js'   = 'application/javascript; charset=utf-8'
    '.css'  = 'text/css; charset=utf-8'
}
$script:UiStaticFiles = @{
    '/'          = 'index.html'
    '/app.js'    = 'app.js'
    '/style.css' = 'style.css'
}

# --- Context -----------------------------------------------------------------

function Get-WheelhouseUiContext {
    # The effective settings (settings.psd1 over the defaults), read fresh for every
    # request so a change in the Settings tab takes effect immediately.
    [CmdletBinding()]
    param(
        [string]$ManagerRoot = $script:ManagerRoot
    )

    $settingsPath = Get-WheelhouseSettingsPath -ManagerRoot $ManagerRoot
    $settings = Get-WheelhouseSetting -SettingsPath $settingsPath
    $names = @((Get-WheelhouseDefaultSetting -ManagerRoot $ManagerRoot).Keys)
    $effective = Resolve-WheelhouseParameter -BoundParameters @{} -Name $names -Settings $settings

    $wheelhousePath = [string]$effective.WheelhousePath
    return [PSCustomObject]@{
        ManagerRoot    = $ManagerRoot
        JobsPath       = (Join-Path $ManagerRoot 'Jobs')
        SettingsPath   = $settingsPath
        DenylistPath   = (Get-WheelhouseDenylistPath -ManagerRoot $ManagerRoot)
        WaiverPath     = (Get-WheelhouseWaiverPath -ManagerRoot $ManagerRoot)
        ProposalPath   = (Get-WheelhouseProposalPath -ManagerRoot $ManagerRoot)
        Settings       = $effective
        WheelhousePath = $wheelhousePath
        ReportsFolder  = $(if ($wheelhousePath) { Join-Path $wheelhousePath 'reports' } else { '' })
    }
}

function Get-WheelhouseUiToolStatus {
    # Get-WheelhouseToolStatus, remembered for 30 seconds: it starts three processes, and the
    # page asks for the state after every job (a job may have installed pip-audit).
    [CmdletBinding()]
    param()

    $now = [DateTime]::UtcNow
    if ($null -eq $script:UiToolStatus -or ($now - $script:UiToolStatusTime).TotalSeconds -ge 30) {
        $script:UiToolStatus = @(Get-WheelhouseToolStatus)
        $script:UiToolStatusTime = $now
    }
    return $script:UiToolStatus
}

function Get-WheelhouseUiPendingPin {
    # What publishing requirements.txt would add: its pins (-Pin, name -> version) that are not
    # in the wheelhouse yet, as { name; version; rejected (the latest update's reason or $null);
    # retryable (rejected only for the cooldown, so publishing again can pass); direct (listed
    # in requirements.in - otherwise a dependency of another requirement) }. Without a
    # reachable wheelhouse every pin is pending.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [hashtable]$Pin
    )

    $published = @{}
    $rejected = @{}
    if ($Context.WheelhousePath -and (Test-Path -Path $Context.WheelhousePath -PathType Container)) {
        $manifest = Read-WheelhouseManifest -WheelhousePath $Context.WheelhousePath
        foreach ($entry in $manifest) { $published["$($entry.name)==$($entry.version)"] = $true }
        $latest = Get-ChildItem -Path $Context.ReportsFolder -Filter 'Report_Rejected_*.json' -File -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($latest) {
            try {
                foreach ($item in (Get-Content -Path $latest.FullName -Raw | ConvertFrom-Json)) {
                    $rejected["$(Get-NormalizedPackageName ([string]$item.Package))==$($item.Version)"] = [string]$item.Reason
                }
            }
            catch { Write-Verbose "Unreadable rejection report: $($latest.Name)" }
        }
    }
    $inLines = @()
    $inPath = [string]$Context.Settings.RequirementsInPath
    if ($inPath -and (Test-Path -LiteralPath $inPath -PathType Leaf)) { $inLines = @(Get-Content -LiteralPath $inPath) }
    foreach ($name in ($Pin.Keys | Sort-Object)) {
        $key = "$name==$($Pin[$name])"
        if ($published.ContainsKey($key)) { continue }
        $reason = $(if ($rejected.ContainsKey($key)) { $rejected[$key] } else { $null })
        @{
            name      = $name
            version   = [string]$Pin[$name]
            rejected  = $reason
            retryable = [bool]($reason -and $reason -match '^cooldown')
            direct    = [bool](Get-RequirementInLine -Lines ([string[]]$inLines) -Name $name)
        }
    }
}

function Invoke-WheelhouseUiRequirementRemoval {
    # Takes -Name out of requirements.in, then resolves requirements.txt again as a job. When no
    # requirement is left there is nothing to resolve: requirements.txt is emptied instead.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string[]]$Name,

        [Parameter(Mandatory)]
        [string]$Title
    )

    if (-not $PSCmdlet.ShouldProcess($Context.Settings.RequirementsInPath, $Title)) { return }
    $inPath = [string]$Context.Settings.RequirementsInPath
    [string[]]$removedLines = Remove-RequirementInLine -Path $inPath -Name $Name
    $left = @(Get-Content -LiteralPath $inPath | Where-Object { ($_ -replace '(^|\s)#.*$', '').Trim() })
    if ($left.Count -eq 0) {
        $txt = [string]$Context.Settings.LocalRequirementsPath
        if ($txt) { Write-TextFileAtomic -Path $txt -Content '# requirements.in lists no package' }
        return @{ Status = 200; Body = @{ removed = $removedLines; job = $null } }
    }
    $job = Start-WheelhouseUiJob -Title $Title -Kind 'remove' -Detail $removedLines -Context $Context -Steps @(@{ Script = 'Update-Requirement.ps1'; Arguments = @() })
    return @{ Status = 200; Body = @{ removed = $removedLines; job = (ConvertTo-WheelhouseUiJobSummary -Job $job) } }
}

function ConvertTo-WheelhouseUiAuditReport {
    # One pip-audit report (Report_<Stage>-<Group>-<SERVICE>_<timestamp>.json) for the Audit
    # tab: { file; stage; group; service; time (local, as in the name); packages; vulnerable;
    # advisories; skipped; error } and, with -IncludeDependency, every audited package with
    # its advisories (vulnerable ones first). An unreadable report is returned with its error.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,

        [switch]$IncludeDependency
    )

    $info = Get-AuditReportInfo -Path $File.FullName
    if (-not $info) { return $null }
    $time = [datetime]::ParseExact($info.Timestamp, 'yyyyMMdd_HHmmss', [System.Globalization.CultureInfo]::InvariantCulture).ToString('yyyy-MM-ddTHH:mm:ss')
    $summary = [ordered]@{
        file       = $File.Name
        stage      = $info.Stage
        group      = [string]$info.Group
        service    = $info.Service
        time       = $time
        packages   = 0
        vulnerable = 0
        advisories = 0
        skipped    = 0
        error      = $null
    }
    try {
        $dependencies = Get-PipAuditReport -Path $File.FullName
    }
    catch {
        $summary['error'] = $_.Exception.Message
        if ($IncludeDependency) { $summary['dependencies'] = @() }
        return $summary
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($dependency in $dependencies) {
        if ($null -eq $dependency.name) { continue }
        if ($null -ne $dependency.skip_reason) {
            $summary['skipped'] += 1
            $rows.Add([ordered]@{ name = [string]$dependency.name; version = [string]$dependency.version; skipped = [string]$dependency.skip_reason; vulns = @() })
            continue
        }
        $summary['packages'] += 1
        $vulns = @(foreach ($vuln in @($dependency.vulns)) {
                if (-not $vuln) { continue }
                $description = [string]$vuln.description
                if ($description.Length -gt 600) { $description = $description.Substring(0, 600) + '...' }
                [ordered]@{
                    id           = [string]$vuln.id
                    aliases      = @(foreach ($alias in @($vuln.aliases)) { if ($alias) { [string]$alias } })
                    fix_versions = @(foreach ($fix in @($vuln.fix_versions)) { if ($fix) { [string]$fix } })
                    description  = $description
                }
            })
        if ($vulns.Count -gt 0) {
            $summary['vulnerable'] += 1
            $summary['advisories'] += $vulns.Count
        }
        $rows.Add([ordered]@{ name = [string]$dependency.name; version = [string]$dependency.version; skipped = $null; vulns = $vulns })
    }
    if ($IncludeDependency) {
        $summary['dependencies'] = @($rows | Sort-Object @{ Expression = { @($_.vulns).Count -gt 0 }; Descending = $true }, @{ Expression = { $_.name } })
    }
    return $summary
}

function Get-WheelhouseUiApproval {
    # The proposal state for the review card: the current proposal (if any), whether it is
    # for requirements.txt as it is now, and what this user may do with it under the
    # ApprovalMode (approve, reject, publish - publishing approves when allowed).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RequirementsPath
    )

    $mode = [string]$Context.Settings.ApprovalMode
    if ($script:ApprovalModes -notcontains $mode) { $mode = 'SamePersonAllowed' }
    $user = Get-WheelhouseCurrentUser
    $proposal = Read-WheelhouseProposal -Path $Context.ProposalPath
    $current = [bool]($proposal -and $RequirementsPath -and $proposal.requirements_sha256 -eq (Get-RequirementFileHash -Path $RequirementsPath))
    $refusal = if ($proposal) { Test-WheelhouseApprovalAllowed -Proposal $proposal -User $user -Mode $mode } else { $null }
    $canApprove = $current -and $proposal.state -eq 'Proposed' -and -not $refusal
    $canPublish = if ($current) { $proposal.state -in 'Approved', 'Published' -or $canApprove } else { $mode -eq 'SamePersonAllowed' }
    $summary = $null
    if ($proposal) {
        # Plain assignments: one-element lists must stay lists in the JSON.
        $replace = @($proposal.replace | ForEach-Object { @{ name = $_.name; from = $_.from; to = $_.to } })
        $retire = @($proposal.retire | ForEach-Object { @{ name = $_.name; version = $_.version; ids = @($_.ids) } })
        $summary = @{
            id = $proposal.id; kind = $proposal.kind; state = $proposal.state; requested_by = $proposal.requested_by
            requested_utc = $proposal.requested_utc; approved_by = $proposal.approved_by; approved_utc = $proposal.approved_utc
            rejected_by = $proposal.rejected_by; decision_note = $proposal.decision_note; note = $proposal.note
            replace = $replace; retire = $retire; expedite_reason = $proposal.expedite_reason; outcome = $proposal.outcome
        }
    }
    return @{
        mode         = $mode
        current_user = $user
        proposal     = $summary
        current      = $current
        can_approve  = [bool]$canApprove
        can_reject   = [bool]($current -and $proposal.state -in 'Proposed', 'Approved')
        can_publish  = [bool]$canPublish
        blocked_by   = $(if ($current -and $proposal.state -eq 'Rejected') { "Rejected by $($proposal.rejected_by): $($proposal.decision_note)" } elseif ($current -and $proposal.state -eq 'Proposed' -and $refusal) { $refusal } elseif (-not $current -and $mode -eq 'SeparateApprover') { 'requirements.txt has no proposal (or changed since it was proposed). Propose it, then another person approves it.' } else { '' })
    }
}

function Assert-WheelhouseUiConfigured {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if ([string]::IsNullOrWhiteSpace($Context.WheelhousePath)) {
        throw [System.InvalidOperationException]::new('The wheelhouse folder is not set. Open the Settings tab and enter it first.')
    }
    if (-not (Test-Path -Path $Context.WheelhousePath -PathType Container)) {
        throw [System.InvalidOperationException]::new("The wheelhouse folder does not exist or is not reachable: $($Context.WheelhousePath)")
    }
}

function Get-UiBodyValue {
    [CmdletBinding()]
    param(
        $Body,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Body) { return $null }
    $property = $Body.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Resolve-UiPackageSelection {
    # Turns the "packages" list of a request into unique { Name; Version } pairs and
    # checks that every one is really in the manifest.
    [CmdletBinding()]
    param(
        $Body,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [int]$Max = 500
    )

    $items = @(foreach ($item in @(Get-UiBodyValue -Body $Body -Name 'packages')) { $item })
    if ($items.Count -eq 0) { throw [System.ArgumentException]::new('Select at least one package.') }
    if ($items.Count -gt $Max) { throw [System.ArgumentException]::new("Too many packages selected (at most $Max at once).") }

    $selection = [ordered]@{}
    foreach ($item in $items) {
        $name = [string](Get-UiBodyValue -Body $item -Name 'name')
        $version = [string](Get-UiBodyValue -Body $item -Name 'version')
        if (-not (Test-WheelhousePackageName $name) -or -not (Test-WheelhousePackageVersion $version)) {
            throw [System.ArgumentException]::new('Invalid package name or version in the selection.')
        }
        $normalized = Get-NormalizedPackageName $name
        if (-not ($Manifest | Where-Object { $_.name -eq $normalized -and $_.version -eq $version })) {
            throw [System.Collections.Generic.KeyNotFoundException]::new("$normalized==$version is not in the wheelhouse manifest.")
        }
        $selection["$normalized==$version"] = [PSCustomObject]@{ Name = $normalized; Version = $version }
    }
    return @($selection.Values)
}

# --- Jobs --------------------------------------------------------------------

function ConvertTo-UiArgument {
    # One command-line argument for a child powershell. Quotes are refused rather
    # than escaped: every value comes from a validated name, never free text.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    if ($Value.Contains('"')) { throw [System.ArgumentException]::new('A quote character is not allowed in a job argument.') }
    if ($Value -match '\s') { return '"' + $Value + '"' }
    return $Value
}

function Get-WheelhouseUiRunningJob {
    [CmdletBinding()]
    param()

    return $script:UiJobs | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1
}

function Start-WheelhouseUiJobStep {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Job
    )

    $step = $Job.Steps[$Job.StepIndex]
    if (-not $PSCmdlet.ShouldProcess($step.Script, 'Start job step')) { return }
    $scriptPath = Join-Path $Job.JobsPath $step.Script
    if (-not (Test-Path -Path $scriptPath)) {
        throw "Job script not found: $scriptPath"
    }

    $arguments = @('-NoProfile', '-File', (ConvertTo-UiArgument -Value $scriptPath)) + @($step.Arguments | ForEach-Object { ConvertTo-UiArgument -Value ([string]$_) })
    $step.OutLog = Join-Path $Job.LogFolder ("job{0}-step{1}.out.txt" -f $Job.Id, ($Job.StepIndex + 1))
    $step.ErrLog = Join-Path $Job.LogFolder ("job{0}-step{1}.err.txt" -f $Job.Id, ($Job.StepIndex + 1))
    $hostExe = (Get-Process -Id $PID).Path

    $startParams = @{
        FilePath               = $hostExe
        ArgumentList           = ($arguments -join ' ')
        PassThru               = $true
        WindowStyle            = 'Hidden'
        RedirectStandardOutput = $step.OutLog
        RedirectStandardError  = $step.ErrLog
    }
    $step.Process = Start-Process @startParams
    # Touching the handle makes Windows PowerShell 5.1 keep the exit code available.
    $null = $step.Process.Handle
    Write-Log "UI job $($Job.Id) step $($Job.StepIndex + 1)/$($Job.Steps.Count): $($step.Script) started (pid $($step.Process.Id))."
}

function Start-WheelhouseUiJob {
    # Starts a background job: a list of steps (each one Jobs\<Script> with its
    # arguments) that run one after another; the job stops at the first step that
    # exits non-zero. Only one job runs at a time (they share the wheelhouse).
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$Kind,

        # What the job works on (package pins, file names): the UI shows the title alone
        # and lists these on demand.
        [string[]]$Detail = @(),

        [Parameter(Mandatory)]
        [object[]]$Steps,

        [Parameter(Mandatory)]
        $Context
    )

    if (Get-WheelhouseUiRunningJob) {
        throw [System.InvalidOperationException]::new('Another job is still running. Wait for it to finish or cancel it first.')
    }
    if (-not $PSCmdlet.ShouldProcess($Title, 'Start job')) { return }

    $logFolder = Join-Path (Join-Path $Context.ManagerRoot 'logs') 'ui'
    New-Item -ItemType Directory -Path $logFolder -Force | Out-Null

    $script:UiJobCounter++
    $job = [PSCustomObject]@{
        Id         = $script:UiJobCounter
        Title      = $Title
        Kind       = $Kind
        Detail     = @($Detail)
        Status     = 'Running'
        StepIndex  = 0
        Steps      = [System.Collections.Generic.List[object]]::new()
        StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
        EndedUtc   = $null
        ExitCode   = $null
        Message    = ''
        JobsPath   = $Context.JobsPath
        LogFolder  = $logFolder
    }
    foreach ($step in $Steps) {
        $job.Steps.Add([PSCustomObject]@{
                Script    = [string]$step.Script
                Arguments = @($step.Arguments)
                OutLog    = $null
                ErrLog    = $null
                Process   = $null
                ExitCode  = $null
            })
    }

    Start-WheelhouseUiJobStep -Job $job
    $script:UiJobs.Add($job)
    while ($script:UiJobs.Count -gt $script:UiMaxJobHistory) { $script:UiJobs.RemoveAt(0) }
    return $job
}

function Sync-WheelhouseUiJob {
    # Advances the running job: when its current step has exited, starts the next
    # step or finishes the job. Called by the server loop and before job queries.
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $job = Get-WheelhouseUiRunningJob
    if (-not $job) { return }
    $step = $job.Steps[$job.StepIndex]
    if (-not $step.Process.HasExited) { return }
    if (-not $PSCmdlet.ShouldProcess("job $($job.Id)", 'Advance')) { return }

    $step.ExitCode = $step.Process.ExitCode
    Write-Log "UI job $($job.Id) step $($job.StepIndex + 1) ($($step.Script)) exited with code $($step.ExitCode)."

    $finish = {
        param($Status, $Message)
        $job.Status = $Status
        $job.Message = $Message
        $job.ExitCode = $step.ExitCode
        $job.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }

    # Exit codes: see Get-WheelhouseExitCode. 1 is a normal outcome that needs a look
    # (findings, rejected packages); later steps still do not run.
    if ($step.ExitCode -eq 1) {
        # What exit code 1 means differs per script; say it in its terms.
        $meaning = switch ($step.Script) {
            'Update-Requirement.ps1' { 'could not resolve requirements.in (no fitting wheel, or the check of the result failed); requirements.txt was not changed. The log says which package.' }
            'Update-Wheelhouse.ps1' { 'finished, but some packages were rejected or need attention.' }
            'Test-WheelhousePackage.ps1' { 'found vulnerabilities.' }
            'Invoke-WheelhouseScan.ps1' { 'found a threat.' }
            default { 'finished with findings. Read the log for details.' }
        }
        & $finish 'Attention' "$($step.Script) $meaning"
    }
    elseif ($step.ExitCode -eq 3) {
        & $finish 'Failed' "$($step.Script) did not run: another wheelhouse operation holds the lock. Try again when it has finished."
    }
    elseif ($step.ExitCode -ne 0) {
        & $finish 'Failed' "$($step.Script) failed (exit code $($step.ExitCode)). Read the log for details."
    }
    elseif ($job.StepIndex + 1 -lt $job.Steps.Count) {
        $job.StepIndex++
        try { Start-WheelhouseUiJobStep -Job $job }
        catch { & $finish 'Failed' $_.Exception.Message }
    }
    else {
        & $finish 'Succeeded' 'Finished.'
    }
}

function Stop-WheelhouseUiJob {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [int]$Id
    )

    $job = $script:UiJobs | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
    if (-not $job) { throw [System.Collections.Generic.KeyNotFoundException]::new("No job with id $Id.") }
    if ($job.Status -ne 'Running') { return $job }

    $step = $job.Steps[$job.StepIndex]
    if ($PSCmdlet.ShouldProcess("job $Id", 'Cancel')) {
        if (-not $step.Process.HasExited) {
            # taskkill /T also ends python and pip started by the script.
            & taskkill.exe /PID $step.Process.Id /T /F 2>&1 | Out-Null
        }
        $job.Status = 'Cancelled'
        $job.Message = 'Cancelled by the user.'
        $job.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Write-Log "UI job $Id cancelled." 'WARN'
    }
    return $job
}

function Read-UiLogFile {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Path,

        [int]$MaxChars = 200000
    )

    if (-not $Path -or -not (Test-Path -Path $Path)) { return '' }
    # The child process still has the file open for writing.
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
        $text = $reader.ReadToEnd()
    }
    finally {
        $stream.Dispose()
    }
    if ($text.Length -gt $MaxChars) { return '[... earlier output omitted ...]' + "`n" + $text.Substring($text.Length - $MaxChars) }
    return $text
}

function ConvertTo-WheelhouseUiJobSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Job,

        [switch]$IncludeLog
    )

    $summary = [ordered]@{
        id          = $Job.Id
        title       = $Job.Title
        detail      = @($Job.Detail | Where-Object { $_ })
        kind        = $Job.Kind
        status      = $Job.Status
        message     = $Job.Message
        exit_code   = $Job.ExitCode
        started_utc = $Job.StartedUtc
        ended_utc   = $Job.EndedUtc
        step        = $Job.StepIndex + 1
        steps       = $Job.Steps.Count
    }
    if ($IncludeLog) {
        $parts = foreach ($step in $Job.Steps) {
            if (-not $step.OutLog) { continue }
            $stepText = "=== $($step.Script) ===`n" + (Read-UiLogFile -Path $step.OutLog)
            $errorText = Read-UiLogFile -Path $step.ErrLog
            if ($errorText.Trim()) { $stepText += "`n--- errors ---`n$errorText" }
            $stepText
        }
        $summary['log'] = ($parts -join "`n")
    }
    return $summary
}

# --- Request checks ----------------------------------------------------------

function Get-WheelhouseUiRandomToken {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $bytes = [byte[]]::new(24)
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-WheelhouseUiRequest {
    # Decides whether a request may be served. Returns $null if it may, otherwise
    # @{ Status; Message }.
    #   - Host must be localhost / 127.0.0.1 on our port (blocks DNS rebinding).
    #   - /api needs the session token; state-changing methods also need a JSON body
    #     content type and, if the browser sent an Origin, our own origin (CSRF).
    #   - The page itself (/) needs the token in its URL, so another local user who
    #     finds the port cannot even load it.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Path,

        [string]$HostHeader,
        [string]$Origin,
        [string]$ContentType,
        [string]$SuppliedToken,

        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter(Mandatory)]
        [int]$Port
    )

    $allowedHosts = @("localhost:$Port", "127.0.0.1:$Port")
    if ($allowedHosts -notcontains $HostHeader) {
        return @{ Status = 403; Message = 'Forbidden host.' }
    }

    $tokenOk = (-not [string]::IsNullOrEmpty($SuppliedToken)) -and ($SuppliedToken -ceq $Token)
    if ($Path.StartsWith('/api/')) {
        if (-not $tokenOk) { return @{ Status = 401; Message = 'Missing or invalid session token.' } }
        if ($Method -ne 'GET') {
            if ($Origin -and (@("http://localhost:$Port", "http://127.0.0.1:$Port") -notcontains $Origin)) {
                return @{ Status = 403; Message = 'Forbidden origin.' }
            }
            if ($ContentType -notlike 'application/json*') {
                return @{ Status = 415; Message = 'Requests that change state must be application/json.' }
            }
        }
        return $null
    }

    if ($Method -ne 'GET') { return @{ Status = 405; Message = 'Method not allowed.' } }
    if ($Path -eq '/' -and -not $tokenOk) {
        return @{ Status = 403; Message = 'Open the address printed by Start-WheelhouseUI.ps1 (it contains the session token).' }
    }
    return $null
}

# --- API ---------------------------------------------------------------------
# One entry per endpoint:
#   Method, Pattern - matched against the request (named groups reach the handler as $Match)
#   Wheelhouse      - needs a configured, reachable wheelhouse (Assert-WheelhouseUiConfigured)
#   Idle            - refused (409, with this message) while a background job runs
#   Handler         - { param($Context, $Body, $Match) ... } returning @{ Status; Body }
# Handlers throw ArgumentException (400), KeyNotFoundException (404) or
# InvalidOperationException (409); Invoke-WheelhouseUiApi maps them.

function Get-WheelhouseUiRoute {
    # The route table (see above). Every handler takes the same three parameters, used or not.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Uniform route handler signature.')]
    [CmdletBinding()]
    param()

    return @(
        @{
            Method  = 'GET'
            Pattern = '^/api/state$'
            Handler = {
                param($Context, $Body, $Match)
                $running = Get-WheelhouseUiRunningJob
                $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
                return @{ Status = 200; Body = @{
                        wheelhouse_path = $Context.WheelhousePath
                        configured      = [bool]$Context.WheelhousePath
                        reachable       = [bool]($Context.WheelhousePath -and (Test-Path -Path $Context.WheelhousePath -PathType Container))
                        defender        = (Test-WheelhouseDefenderAvailable)
                        is_admin        = $isAdmin
                        python_version  = [string]$Context.Settings.PythonVersion
                        platform        = [string]$Context.Settings.Platform
                        tools           = @(Get-WheelhouseUiToolStatus)
                        running_job     = $(if ($running) { ConvertTo-WheelhouseUiJobSummary -Job $running } else { $null })
                    }
                }
            }
        }

        @{
            Method     = 'GET'
            Pattern    = '^/api/overview$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                $status = Get-WheelhouseStatus -WheelhousePath $Context.WheelhousePath -FreshnessDays ([int]$Context.Settings.AuditFreshnessDays) -ProposalPath $Context.ProposalPath
                $task = $null
                try { $task = Get-WheelhouseScheduledCheck -ManagerRoot $Context.ManagerRoot } catch { Write-Verbose "Task Scheduler unreadable: $($_.Exception.Message)" }
                # Plain assignment: one-element lists must stay lists in the JSON.
                $attention = @($status.Attention | ForEach-Object { @{ level = $_.Level; text = $_.Text; target = $_.Target } })
                return @{ Status = 200; Body = @{
                        published      = $status.Published
                        packages       = $status.Packages
                        groups         = $status.Groups
                        open           = $status.Open
                        overdue        = $status.Overdue
                        waived         = $status.Waived
                        yanked         = $status.Yanked
                        quarantined    = $status.Quarantined
                        unverified     = $status.Unverified
                        untracked      = $status.Untracked
                        last_check_utc = $status.LastCheckUtc
                        check_overdue  = $status.CheckOverdue
                        attention      = $attention
                        task           = $(if ($task -and $task.Registered) { @{ state = $task.State; next_run_utc = $task.NextRunTime; last_result = $task.LastResultText; for_this_installation = [bool]$task.ForThisInstallation } } else { $null })
                    }
                }
            }
        }

        @{
            Method     = 'GET'
            Pattern    = '^/api/packages$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                $inventoryParams = @{
                    WheelhousePath = $Context.WheelhousePath
                    Denylist       = @(Read-WheelhouseDenylist -Path $Context.DenylistPath)
                    Services       = [string[]]@($Context.Settings.VulnerabilityServices)
                }
                $inventory = Get-WheelhousePackage @inventoryParams
                $lastCheck = ConvertTo-OptionalUtcDateTime -Value $inventory.ScheduledCheckUtc
                $freshness = [int]$Context.Settings.AuditFreshnessDays
                return @{ Status = 200; Body = @{
                        packages             = @($inventory.Packages)
                        groups               = @($inventory.Groups)
                        untracked            = @($inventory.Untracked)
                        last_check_utc       = [string]$inventory.ScheduledCheckUtc
                        check_overdue        = [bool](@($inventory.Packages).Count -gt 0 -and (-not $lastCheck -or ((Get-Date).ToUniversalTime() - $lastCheck).TotalDays -gt $freshness))
                        audit_freshness_days = $freshness
                    }
                }
            }
        }

        @{
            Method     = 'GET'
            Pattern    = '^/api/packages/(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)/(?<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)/history$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                $name = Get-NormalizedPackageName $Match['name']
                $version = $Match['version']
                $catalog = Read-WheelhouseCatalog -WheelhousePath $Context.WheelhousePath
                $record = $catalog.Records["$name==$version"]
                $events = @(Read-WheelhouseEvent -WheelhousePath $Context.WheelhousePath -Package $name -Version $version -Last 500)
                if (-not $record -and $events.Count -eq 0) {
                    throw [System.Collections.Generic.KeyNotFoundException]::new("Nothing is known about $name==$version.")
                }
                $state = $null
                if ($record) {
                    $state = @{
                        state         = $record.state
                        state_since   = $record.state_since
                        state_reason  = $record.state_reason
                        groups        = @($record.groups)
                        files         = @($record.files)
                        published_utc = $record.published_utc
                        checks        = $record.checks
                        findings      = @(ConvertTo-WheelhouseUiFinding -Record $record)
                    }
                }
                return @{ Status = 200; Body = @{ name = $name; version = $version; record = $state; events = $events } }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/packages/audit$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                if (Get-UiBodyValue -Body $Body -Name 'all') {
                    $job = Start-WheelhouseUiJob -Title 'Audit all packages' -Kind 'audit' -Context $Context -Steps @(@{ Script = 'Test-WheelhousePackage.ps1'; Arguments = @() })
                }
                else {
                    $manifest = Read-WheelhouseManifest -WheelhousePath $Context.WheelhousePath
                    $selection = Resolve-UiPackageSelection -Body $Body -Manifest $manifest
                    $list = ($selection | ForEach-Object { "$($_.Name)==$($_.Version)" }) -join ','
                    if ($list.Length -gt 20000) { throw [System.ArgumentException]::new('The selection is too large - use "Audit all" instead.') }
                    $job = Start-WheelhouseUiJob -Title 'Audit packages' -Kind 'audit' -Detail @($selection | ForEach-Object { "$($_.Name)==$($_.Version)" }) -Context $Context -Steps @(@{ Script = 'Test-WheelhousePackage.ps1'; Arguments = @('-Package', $list) })
                }
                return @{ Status = 202; Body = @{ job = (ConvertTo-WheelhouseUiJobSummary -Job $job) } }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/packages/scan$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                if (Get-UiBodyValue -Body $Body -Name 'all') {
                    $job = Start-WheelhouseUiJob -Title 'Scan all packages' -Kind 'scan' -Context $Context -Steps @(@{ Script = 'Invoke-WheelhouseScan.ps1'; Arguments = @() })
                }
                else {
                    $manifest = Read-WheelhouseManifest -WheelhousePath $Context.WheelhousePath
                    $files = [System.Collections.Generic.List[string]]::new()
                    foreach ($file in @(Get-UiBodyValue -Body $Body -Name 'files')) {
                        $fileName = [string]$file
                        if (-not (Test-WheelhouseWheelFileName $fileName)) { throw [System.ArgumentException]::new('Invalid file name in the selection.') }
                        if (-not ($manifest | Where-Object { $_.file -eq $fileName })) {
                            throw [System.Collections.Generic.KeyNotFoundException]::new("$fileName is not in the wheelhouse manifest.")
                        }
                        if (-not $files.Contains($fileName)) { $files.Add($fileName) }
                    }
                    if ($files.Count -eq 0) { throw [System.ArgumentException]::new('Select at least one package.') }
                    $list = $files -join ','
                    if ($list.Length -gt 20000) { throw [System.ArgumentException]::new('The selection is too large - use "Scan all" instead.') }
                    $job = Start-WheelhouseUiJob -Title 'Scan packages' -Kind 'scan' -Detail $files.ToArray() -Context $Context -Steps @(@{ Script = 'Invoke-WheelhouseScan.ps1'; Arguments = @('-File', $list) })
                }
                return @{ Status = 202; Body = @{ job = (ConvertTo-WheelhouseUiJobSummary -Job $job) } }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/packages/add$'
            Wheelhouse = $true
            Idle       = 'Another job is still running. Wait for it to finish or cancel it first.'
            Handler    = {
                param($Context, $Body, $Match)
                $specs = @(foreach ($item in @(Get-UiBodyValue -Body $Body -Name 'specs')) { [string]$item })
                if ($specs.Count -eq 0) { throw [System.ArgumentException]::new('Enter at least one package.') }
                if ($specs.Count -gt 100) { throw [System.ArgumentException]::new('Too many packages at once (at most 100).') }

                # "replace": true swaps a listed requirement's line for the new spec.
                $replace = (Get-UiBodyValue -Body $Body -Name 'replace') -eq $true
                $addResult = Add-RequirementInLine -Path $Context.Settings.RequirementsInPath -Spec $specs -Denylist @(Read-WheelhouseDenylist -Path $Context.DenylistPath) -Replace:$replace
                $job = $null
                $changed = @($addResult.Added) + @($addResult.Replaced)
                if ($changed.Count -gt 0) {
                    $steps = @(@{ Script = 'Update-Requirement.ps1'; Arguments = @() })
                    # By default the job stops at requirements.txt, so the resolved pins can
                    # be reviewed before anything is downloaded. "publish": true also runs
                    # Update-Wheelhouse.ps1 (audit, cooldown, download) straight away.
                    $title = 'Add packages'
                    if ((Get-UiBodyValue -Body $Body -Name 'publish') -eq $true) {
                        $steps += @{ Script = 'Update-Wheelhouse.ps1'; Arguments = @() }
                        $title = 'Add and publish packages'
                    }
                    $job = Start-WheelhouseUiJob -Title $title -Kind 'add' -Detail $changed -Context $Context -Steps $steps
                }
                return @{ Status = 200; Body = @{ added = @($addResult.Added); replaced = @($addResult.Replaced); skipped = @($addResult.Skipped); job = $(if ($job) { ConvertTo-WheelhouseUiJobSummary -Job $job } else { $null }) } }
            }
        }

        @{
            Method  = 'GET'
            Pattern = '^/api/requirements$'
            Handler = {
                param($Context, $Body, $Match)
                # The resolved file Update-Wheelhouse.ps1 merges - shown for review.
                $path = [string]$Context.Settings.LocalRequirementsPath
                $text = ''
                $modified = ''
                if ($path -and (Test-Path -Path $path -PathType Leaf)) {
                    $item = Get-Item -Path $path
                    if ($item.Length -gt 1MB) { throw [System.InvalidOperationException]::new("requirements.txt is too large to show here: $path") }
                    $text = [System.IO.File]::ReadAllText($path)
                    $modified = $item.LastWriteTimeUtc.ToString('o')
                }
                $pins = @{}
                if ($text.Trim()) { $pins = Read-RequirementFile -FilePath $path }
                $pending = @(Get-WheelhouseUiPendingPin -Context $Context -Pin $pins)
                return @{ Status = 200; Body = @{
                        path            = $path
                        text            = $text
                        modified_utc    = $modified
                        pin_count       = $pins.Count
                        pending         = @($pending)
                        published_count = $pins.Count - @($pending).Count
                        approval        = (Get-WheelhouseUiApproval -Context $Context -RequirementsPath $path)
                    }
                }
            }
        }

        @{
            Method  = 'GET'
            Pattern = '^/api/requirements/in$'
            Handler = {
                param($Context, $Body, $Match)
                # requirements.in as it is now - the Add tab's edit box shows it.
                $path = [string]$Context.Settings.RequirementsInPath
                $text = ''
                $modified = ''
                if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
                    $item = Get-Item -LiteralPath $path
                    if ($item.Length -gt 1MB) { throw [System.InvalidOperationException]::new("requirements.in is too large to show here: $path") }
                    $text = [System.IO.File]::ReadAllText($path)
                    $modified = $item.LastWriteTimeUtc.ToString('o')
                }
                return @{ Status = 200; Body = @{ path = $path; text = $text; modified_utc = $modified } }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/requirements/in$'
            Wheelhouse = $true
            Idle       = 'Another job is still running. Wait for it to finish or cancel it first.'
            Handler    = {
                param($Context, $Body, $Match)
                # "Save and resolve": the edit box replaces requirements.in, then requirements.txt is
                # resolved again (and published too with "publish": true). Lines with a problem
                # are returned and nothing is written.
                $text = [string](Get-UiBodyValue -Body $Body -Name 'text')
                if ($text.Length -gt 100KB) { throw [System.ArgumentException]::new('requirements.in is too long (at most 100 KB).') }
                $saved = Set-RequirementInText -Path $Context.Settings.RequirementsInPath -Text $text -Denylist @(Read-WheelhouseDenylist -Path $Context.DenylistPath)
                $problems = @($saved.Problems)
                if ($problems.Count -gt 0) { return @{ Status = 200; Body = @{ saved = $false; problems = $problems; job = $null } } }
                $count = @($saved.Requirements).Count
                if ($count -eq 0) {
                    # Nothing left to resolve: nothing waits to be published either.
                    $txt = [string]$Context.Settings.LocalRequirementsPath
                    if ($txt) { Write-TextFileAtomic -Path $txt -Content '# requirements.in lists no package' }
                    return @{ Status = 200; Body = @{ saved = $true; problems = @(); job = $null } }
                }
                $steps = @(@{ Script = 'Update-Requirement.ps1'; Arguments = @() })
                $title = 'Resolve requirements.in'
                if ((Get-UiBodyValue -Body $Body -Name 'publish') -eq $true) {
                    $steps += @{ Script = 'Update-Wheelhouse.ps1'; Arguments = @() }
                    $title = 'Resolve and publish requirements.in'
                }
                $job = Start-WheelhouseUiJob -Title $title -Kind 'add' -Detail @($saved.Requirements) -Context $Context -Steps $steps
                return @{ Status = 200; Body = @{ saved = $true; problems = @(); job = (ConvertTo-WheelhouseUiJobSummary -Job $job) } }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/requirements/remove$'
            Wheelhouse = $true
            Idle       = 'Another job is still running. Wait for it to finish or cancel it first.'
            Handler    = {
                param($Context, $Body, $Match)
                # Takes one package out of requirements.in and resolves requirements.txt again, so a
                # pin that is rejected (or not wanted yet) stops waiting in "Review and publish".
                $name = [string](Get-UiBodyValue -Body $Body -Name 'name')
                if (-not (Test-WheelhousePackageName -Name $name)) { throw [System.ArgumentException]::new('Not a valid package name.') }
                return (Invoke-WheelhouseUiRequirementRemoval -Context $Context -Name @($name) -Title 'Remove packages')
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/requirements/clear$'
            Wheelhouse = $true
            Idle       = 'Another job is still running. Wait for it to finish or cancel it first.'
            Handler    = {
                param($Context, $Body, $Match)
                # "Clear list": takes every requirement whose pin is still waiting to be published out
                # of requirements.in, then resolves again. The wheelhouse does not change.
                $path = [string]$Context.Settings.LocalRequirementsPath
                $pins = @{}
                if ($path -and (Test-Path -LiteralPath $path -PathType Leaf) -and ([System.IO.File]::ReadAllText($path)).Trim()) { $pins = Read-RequirementFile -FilePath $path }
                $names = @(Get-WheelhouseUiPendingPin -Context $Context -Pin $pins | Where-Object { $_.direct } | ForEach-Object { $_.name })
                if ($names.Count -eq 0) {
                    return @{ Status = 409; Body = @{ error = 'Nothing to clear: no package waiting to be published is listed in requirements.in (the ones waiting are dependencies of published packages).' } }
                }
                return (Invoke-WheelhouseUiRequirementRemoval -Context $Context -Name $names -Title 'Clear list')
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/proposal/approve$'
            Idle    = 'A job is running. Wait for it to finish first.'
            Handler = {
                param($Context, $Body, $Match)
                $approveParams = @{
                    Id   = [string](Get-UiBodyValue -Body $Body -Name 'id')
                    Mode = [string]$Context.Settings.ApprovalMode
                    Note = [string](Get-UiBodyValue -Body $Body -Name 'note')
                    Path = $Context.ProposalPath
                }
                $proposal = Approve-WheelhouseProposal @approveParams
                return @{ Status = 200; Body = @{ id = $proposal.id; state = $proposal.state; approved_by = $proposal.approved_by } }
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/proposal/reject$'
            Idle    = 'A job is running. Wait for it to finish first.'
            Handler = {
                param($Context, $Body, $Match)
                $proposal = Deny-WheelhouseProposal -Id ([string](Get-UiBodyValue -Body $Body -Name 'id')) -Reason ([string](Get-UiBodyValue -Body $Body -Name 'reason')) -Path $Context.ProposalPath
                return @{ Status = 200; Body = @{ id = $proposal.id; state = $proposal.state } }
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/proposal/new$'
            Idle    = 'A job is running. Wait for it to finish first.'
            Handler = {
                param($Context, $Body, $Match)
                $path = [string]$Context.Settings.LocalRequirementsPath
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw [System.Collections.Generic.KeyNotFoundException]::new("requirements.txt was not found: $path") }
                $proposal = New-WheelhouseProposal -RequirementsPath $path -Kind 'manual' -Note 'proposed from the UI as the file is now' -Path $Context.ProposalPath
                return @{ Status = 200; Body = @{ id = $proposal.id; state = $proposal.state } }
            }
        }

        @{
            Method     = 'GET'
            Pattern    = '^/api/packages/(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)/(?<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)/remediation$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                $planParams = @{
                    WheelhousePath     = $Context.WheelhousePath
                    Name               = $Match['name']
                    Version            = $Match['version']
                    RequirementsInPath = [string]$Context.Settings.RequirementsInPath
                    MinimumAgeDays     = [int]$Context.Settings.MinimumPackageAgeDays
                }
                $plan = Get-WheelhouseRemediationPlan @planParams
                return @{ Status = 200; Body = @{
                        name             = $plan.Name
                        version          = $plan.Version
                        ids              = @($plan.Ids)
                        unfixable        = @($plan.Unfixable)
                        fix_version      = $plan.FixVersion
                        needs_expedite   = [bool]$plan.NeedsExpedite
                        expedite_version = $plan.ExpediteVersion
                        eligible_utc     = $plan.EligibleUtc
                        old_line         = $plan.OldLine
                        new_line         = $plan.NewLine
                        summary          = $plan.Summary
                    }
                }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/packages/remediate$'
            Wheelhouse = $true
            Idle       = 'Another job is still running. Wait for it to finish or cancel it first.'
            Handler    = {
                param($Context, $Body, $Match)
                $name = Get-NormalizedPackageName ([string](Get-UiBodyValue -Body $Body -Name 'name'))
                $version = [string](Get-UiBodyValue -Body $Body -Name 'version')
                if (-not (Test-WheelhousePackageName -Name $name) -or -not (Test-WheelhousePackageVersion -Version $version)) { throw [System.ArgumentException]::new('Not a valid package name or version.') }
                $manifest = Read-WheelhouseManifest -WheelhousePath $Context.WheelhousePath
                if (-not ($manifest | Where-Object { $_.name -eq $name -and $_.version -eq $version })) { throw [System.Collections.Generic.KeyNotFoundException]::new("$name==$version is not in the wheelhouse.") }
                $arguments = @('-Package', "$name==$version")
                $reason = ([string](Get-UiBodyValue -Body $Body -Name 'expedite_reason')).Trim()
                if ($reason) {
                    # Free text on a command line: a short, plain sentence only.
                    if ($reason -notmatch '^[A-Za-z0-9 .,:;()/#+_-]{5,200}$') { throw [System.ArgumentException]::new('Write the reason as a short sentence (5-200 letters, digits and . , : ; ( ) / # + _ -).') }
                    $arguments += @('-ExpediteReason', $reason)
                }
                $job = Start-WheelhouseUiJob -Title 'Fix package' -Kind 'remediate' -Detail @("$name==$version") -Context $Context -Steps @(@{ Script = 'Invoke-WheelhouseRemediation.ps1'; Arguments = $arguments })
                return @{ Status = 202; Body = @{ job = (ConvertTo-WheelhouseUiJobSummary -Job $job) } }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/wheelhouse/update$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                if ((Get-UiBodyValue -Body $Body -Name 'confirm') -ne $true) {
                    throw [System.ArgumentException]::new('Publishing needs an explicit confirmation.')
                }
                $job = Start-WheelhouseUiJob -Title 'Publish packages' -Kind 'update' -Context $Context -Steps @(@{ Script = 'Update-Wheelhouse.ps1'; Arguments = @() })
                return @{ Status = 202; Body = @{ job = (ConvertTo-WheelhouseUiJobSummary -Job $job) } }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/packages/remove$'
            Wheelhouse = $true
            Idle       = 'A job is running. Wait for it to finish or cancel it before removing packages.'
            Handler    = {
                param($Context, $Body, $Match)
                $mode = [string](Get-UiBodyValue -Body $Body -Name 'mode')
                if ($mode -notin 'quarantine', 'delete') { throw [System.ArgumentException]::new("mode must be 'quarantine' or 'delete'.") }
                if ($mode -eq 'delete' -and (Get-UiBodyValue -Body $Body -Name 'confirm') -ne $true) {
                    throw [System.ArgumentException]::new('Deleting needs an explicit confirmation.')
                }
                $reason = [string](Get-UiBodyValue -Body $Body -Name 'reason')
                if ($reason.Length -gt 400) { throw [System.ArgumentException]::new('The reason is too long (400 characters at most).') }

                $manifest = Read-WheelhouseManifest -WheelhousePath $Context.WheelhousePath
                $selection = Resolve-UiPackageSelection -Body $Body -Manifest $manifest -Max 200
                $outcomes = foreach ($package in $selection) {
                    try {
                        $removeParams = @{ WheelhousePath = $Context.WheelhousePath; Name = $package.Name; Version = $package.Version; Reason = $reason; DenylistPath = $Context.DenylistPath }
                        if ($mode -eq 'quarantine') { $removeParams['Quarantine'] = $true }
                        $done = Remove-WheelhousePackage @removeParams
                        @{ name = $package.Name; version = $package.Version; ok = $true; mode = $mode; quarantine_id = $done.QuarantineId; error = $null }
                    }
                    catch {
                        @{ name = $package.Name; version = $package.Version; ok = $false; mode = $mode; quarantine_id = $null; error = $_.Exception.Message }
                    }
                }
                return @{ Status = 200; Body = @{ results = @($outcomes) } }
            }
        }

        @{
            Method     = 'GET'
            Pattern    = '^/api/quarantine$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                $records = @(Get-QuarantinedPackage -WheelhousePath $Context.WheelhousePath)
                $items = foreach ($record in $records) {
                    @{
                        id              = [string]$record.id
                        name            = [string]$record.name
                        version         = [string]$record.version
                        files           = @($record.files | ForEach-Object { [string]$_.file })
                        groups          = @($record.groups)
                        reason          = [string]$record.reason
                        quarantined_utc = (ConvertTo-IsoTimestamp -Value $record.quarantined_utc)
                        quarantined_by  = [string]$record.quarantined_by
                        denylisted      = [bool]$record.denylisted
                    }
                }
                return @{ Status = 200; Body = @{ items = @($items) } }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/quarantine/restore$'
            Wheelhouse = $true
            Idle       = 'A job is running. Wait for it to finish or cancel it before restoring packages.'
            Handler    = {
                param($Context, $Body, $Match)
                $id = [string](Get-UiBodyValue -Body $Body -Name 'id')
                if ($id -notmatch '^[A-Za-z0-9._-]+$') { throw [System.ArgumentException]::new('Invalid quarantine id.') }
                $restoreParams = @{ WheelhousePath = $Context.WheelhousePath; Id = $id; DenylistPath = $Context.DenylistPath }
                if (Get-UiBodyValue -Body $Body -Name 'keep_denylist') { $restoreParams['KeepDenylist'] = $true }
                $done = Restore-WheelhousePackage @restoreParams
                return @{ Status = 200; Body = @{ name = $done.Name; version = $done.Version; denylist_removed = $done.DenylistRemoved } }
            }
        }

        @{
            Method  = 'GET'
            Pattern = '^/api/denylist$'
            Handler = {
                param($Context, $Body, $Match)
                $entries = @(Read-WheelhouseDenylist -Path $Context.DenylistPath)
                $manifest = @()
                if ($Context.WheelhousePath -and (Test-Path -Path $Context.WheelhousePath -PathType Container)) {
                    $manifest = Read-WheelhouseManifest -WheelhousePath $Context.WheelhousePath
                }
                $items = foreach ($entry in ($entries | Sort-Object name, version)) {
                    $installed = [bool]($manifest | Where-Object { $_.name -eq $entry.name -and ($entry.version -eq '*' -or $_.version -eq $entry.version) })
                    @{ name = [string]$entry.name; version = [string]$entry.version; reason = [string]$entry.reason; added_utc = (ConvertTo-IsoTimestamp -Value $entry.added_utc); added_by = [string]$entry.added_by; source = [string]$entry.source; installed = $installed }
                }
                return @{ Status = 200; Body = @{ items = @($items) } }
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/denylist/add$'
            Handler = {
                param($Context, $Body, $Match)
                $entry = Add-WheelhouseDenylistEntry -Name ([string](Get-UiBodyValue -Body $Body -Name 'name')) `
                    -Version ([string](Get-UiBodyValue -Body $Body -Name 'version')) `
                    -Reason ([string](Get-UiBodyValue -Body $Body -Name 'reason')) -Source 'manual' -Path $Context.DenylistPath
                return @{ Status = 200; Body = @{ name = $entry.name; version = $entry.version } }
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/denylist/remove$'
            Handler = {
                param($Context, $Body, $Match)
                $removed = Remove-WheelhouseDenylistEntry -Name ([string](Get-UiBodyValue -Body $Body -Name 'name')) -Version ([string](Get-UiBodyValue -Body $Body -Name 'version')) -Path $Context.DenylistPath
                if (-not $removed) { throw [System.Collections.Generic.KeyNotFoundException]::new('No such denylist entry.') }
                return @{ Status = 200; Body = @{ removed = $true } }
            }
        }

        @{
            Method  = 'GET'
            Pattern = '^/api/waivers$'
            Handler = {
                param($Context, $Body, $Match)
                $now = (Get-Date).ToUniversalTime()
                $items = foreach ($entry in (@(Read-WheelhouseWaiver -Path $Context.WaiverPath) | Sort-Object name, version, id)) {
                    $expires = ConvertTo-OptionalUtcDateTime -Value $entry.expires_utc
                    @{ name = $entry.name; version = $entry.version; id = $entry.id; reason = $entry.reason; added_utc = $entry.added_utc; added_by = $entry.added_by; expires_utc = $entry.expires_utc; expired = [bool](-not $expires -or $expires -le $now) }
                }
                return @{ Status = 200; Body = @{ items = @($items); max_days = [int]$Context.Settings.WaiverMaxDays } }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/waivers/add$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                $days = 0
                if (-not [int]::TryParse([string](Get-UiBodyValue -Body $Body -Name 'days'), [ref]$days) -or $days -lt 1) {
                    throw [System.ArgumentException]::new('Enter for how many days the risk is accepted.')
                }
                $waiverParams = @{
                    Name    = [string](Get-UiBodyValue -Body $Body -Name 'name')
                    Version = [string](Get-UiBodyValue -Body $Body -Name 'version')
                    Id      = [string](Get-UiBodyValue -Body $Body -Name 'id')
                    Reason  = [string](Get-UiBodyValue -Body $Body -Name 'reason')
                    Days    = $days
                    MaxDays = [int]$Context.Settings.WaiverMaxDays
                    Path    = $Context.WaiverPath
                }
                # Under the write lock, so the catalog (and its history) shows the waiver at once.
                # A closure gets its own scope: results come back through this table.
                $outcome = @{}
                $waiverPath = $Context.WaiverPath
                Update-WheelhouseCatalog -WheelhousePath $Context.WheelhousePath -TimeoutSeconds 0 -DenylistPath $Context.DenylistPath -Update ({
                        param($catalog)
                        $outcome.Entry = Add-WheelhouseWaiver @waiverParams
                        Set-CatalogFindingWaiver -Catalog $catalog -Waiver @(Read-WheelhouseWaiver -Path $waiverPath)
                    }.GetNewClosure())
                $entry = $outcome.Entry
                return @{ Status = 200; Body = @{ name = $entry.name; version = $entry.version; id = $entry.id; expires_utc = $entry.expires_utc } }
            }
        }

        @{
            Method     = 'POST'
            Pattern    = '^/api/waivers/remove$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                $name = [string](Get-UiBodyValue -Body $Body -Name 'name')
                $version = [string](Get-UiBodyValue -Body $Body -Name 'version')
                $id = [string](Get-UiBodyValue -Body $Body -Name 'id')
                $waiverPath = $Context.WaiverPath
                $outcome = @{ Removed = $false }
                Update-WheelhouseCatalog -WheelhousePath $Context.WheelhousePath -TimeoutSeconds 0 -DenylistPath $Context.DenylistPath -Update ({
                        param($catalog)
                        $outcome.Removed = Remove-WheelhouseWaiver -Name $name -Version $version -Id $id -Path $waiverPath
                        Set-CatalogFindingWaiver -Catalog $catalog -Waiver @(Read-WheelhouseWaiver -Path $waiverPath)
                    }.GetNewClosure())
                if (-not $outcome.Removed) { throw [System.Collections.Generic.KeyNotFoundException]::new('No such waiver.') }
                return @{ Status = 200; Body = @{ removed = $true } }
            }
        }

        @{
            Method  = 'GET'
            Pattern = '^/api/schedule$'
            Handler = {
                param($Context, $Body, $Match)
                $task = Get-WheelhouseScheduledCheck -ManagerRoot $Context.ManagerRoot
                $lastCheck = ''
                if ($Context.WheelhousePath -and (Test-Path -Path $Context.WheelhousePath -PathType Container)) {
                    try { $lastCheck = [string](Read-WheelhouseCatalog -WheelhousePath $Context.WheelhousePath).ScheduledCheckUtc } catch { $lastCheck = '' }
                }
                $drive = Get-WheelhouseNetworkDrive -Path $Context.WheelhousePath
                $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                # Plain assignment: one-element lists must stay lists in the JSON.
                $days = @()
                if ($task.Registered) { $days = @($task.Days) }
                return @{ Status = 200; Body = @{
                        registered            = [bool]$task.Registered
                        task_name             = $task.TaskName
                        state                 = $(if ($task.Registered) { $task.State } else { '' })
                        user                  = $(if ($task.Registered) { $task.User } else { '' })
                        days                  = $days
                        time                  = $(if ($task.Registered) { $task.Time } else { '' })
                        last_run_utc          = $(if ($task.Registered) { $task.LastRunTime } else { '' })
                        last_result           = $(if ($task.Registered) { $task.LastResultText } else { '' })
                        next_run_utc          = $(if ($task.Registered) { $task.NextRunTime } else { '' })
                        for_this_installation = [bool]($task.Registered -and $task.ForThisInstallation)
                        script                = $task.Script
                        last_check_utc        = $lastCheck
                        current_user          = $user
                        wheelhouse_path       = $Context.WheelhousePath
                        mapped_drive          = $(if ($drive) { @{ drive = $drive.Drive; unc = $drive.Unc } } else { $null })
                    }
                }
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/schedule$'
            Handler = {
                param($Context, $Body, $Match)
                $password = [string](Get-UiBodyValue -Body $Body -Name 'password')
                $secure = [System.Security.SecureString]::new()
                foreach ($char in $password.ToCharArray()) { $secure.AppendChar($char) }
                $password = $null
                $registerParams = @{
                    DayOfWeek   = [string[]]@(Get-UiBodyValue -Body $Body -Name 'days')
                    At          = [string](Get-UiBodyValue -Body $Body -Name 'time')
                    User        = [string](Get-UiBodyValue -Body $Body -Name 'user')
                    Password    = $secure
                    ManagerRoot = $Context.ManagerRoot
                }
                $task = Register-WheelhouseScheduledCheck @registerParams
                return @{ Status = 200; Body = @{ registered = $true; next_run_utc = $task.NextRunTime } }
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/schedule/run$'
            Handler = {
                param($Context, $Body, $Match)
                Start-WheelhouseScheduledCheck
                return @{ Status = 200; Body = @{ started = $true } }
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/schedule/remove$'
            Handler = {
                param($Context, $Body, $Match)
                if (-not (Get-UiBodyValue -Body $Body -Name 'confirm')) { throw [System.ArgumentException]::new('Removing the task needs confirm.') }
                if (-not (Unregister-WheelhouseScheduledCheck)) { throw [System.Collections.Generic.KeyNotFoundException]::new('The weekly check is not registered.') }
                return @{ Status = 200; Body = @{ removed = $true } }
            }
        }

        @{
            Method  = 'GET'
            Pattern = '^/api/settings$'
            Handler = {
                param($Context, $Body, $Match)
                $schema = @(Get-WheelhouseSettingSchema)
                $values = @{}
                foreach ($item in $schema) { $values[$item.Key] = $Context.Settings[$item.Key] }
                $fields = foreach ($item in $schema) {
                    $options = @()
                    if ($item.Options) { $options = @($item.Options) }
                    @{ key = $item.Key; type = $item.Type; label = $item.Label; help = $item.Help; options = $options; min = $item.Min; max = $item.Max }
                }
                return @{ Status = 200; Body = @{ fields = @($fields); values = $values } }
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/settings$'
            Handler = {
                param($Context, $Body, $Match)
                $updates = @{}
                $incoming = Get-UiBodyValue -Body $Body -Name 'updates'
                if ($null -eq $incoming) { throw [System.ArgumentException]::new('No settings were sent.') }
                foreach ($property in $incoming.PSObject.Properties) {
                    $updates[$property.Name] = ConvertTo-WheelhouseSettingValue -Key $property.Name -Value $property.Value
                }
                if ($updates.Count -eq 0) { throw [System.ArgumentException]::new('No settings were sent.') }
                Set-WheelhouseSetting -SettingsPath $Context.SettingsPath -Updates $updates
                Write-Log "Settings changed from the UI: $(($updates.Keys | Sort-Object) -join ', ')" 'WARN'
                return @{ Status = 200; Body = @{ saved = @($updates.Keys | Sort-Object) } }
            }
        }

        @{
            Method     = 'GET'
            Pattern    = '^/api/audits$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                # The newest pip-audit reports (at most 200), with their counts.
                $files = @(Get-ChildItem -Path $Context.ReportsFolder -Filter 'Report_*.json' -File -ErrorAction SilentlyContinue |
                        Where-Object { Get-AuditReportInfo -Path $_.FullName } |
                        Sort-Object { (Get-AuditReportInfo -Path $_.FullName).Timestamp } -Descending |
                        Select-Object -First 200)
                $reports = @(foreach ($file in $files) { ConvertTo-WheelhouseUiAuditReport -File $file })
                return @{ Status = 200; Body = @{ folder = $Context.ReportsFolder; reports = $reports } }
            }
        }

        @{
            Method     = 'GET'
            Pattern    = '^/api/audits/(?<file>Report_[A-Za-z0-9._-]+\.json)$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                $name = [string]$Match['file']
                $path = Join-Path $Context.ReportsFolder $name
                if (-not (Get-AuditReportInfo -Path $path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
                    return @{ Status = 404; Body = @{ error = "No audit report named $name." } }
                }
                $report = ConvertTo-WheelhouseUiAuditReport -File (Get-Item -LiteralPath $path) -IncludeDependency
                return @{ Status = 200; Body = $report }
            }
        }

        @{
            Method     = 'GET'
            Pattern    = '^/api/rejected$'
            Wheelhouse = $true
            Handler    = {
                param($Context, $Body, $Match)
                $latest = Get-ChildItem -Path $Context.ReportsFolder -Filter 'Report_Rejected_*.json' -File -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1
                $items = @()
                if ($latest) {
                    $parsed = Get-Content -Path $latest.FullName -Raw | ConvertFrom-Json
                    $items = @(foreach ($item in $parsed) { $item })
                }
                return @{ Status = 200; Body = @{
                        file         = $(if ($latest) { $latest.Name } else { $null })
                        modified_utc = $(if ($latest) { $latest.LastWriteTimeUtc.ToString('o') } else { $null })
                        items        = $items
                    }
                }
            }
        }

        @{
            Method  = 'GET'
            Pattern = '^/api/jobs$'
            Handler = {
                param($Context, $Body, $Match)
                $jobs = @($script:UiJobs | Sort-Object Id -Descending | ForEach-Object { ConvertTo-WheelhouseUiJobSummary -Job $_ })
                return @{ Status = 200; Body = @{ jobs = $jobs } }
            }
        }

        @{
            Method  = 'GET'
            Pattern = '^/api/jobs/(?<id>\d+)$'
            Handler = {
                param($Context, $Body, $Match)
                $id = [int]$Match['id']
                $job = $script:UiJobs | Where-Object { $_.Id -eq $id } | Select-Object -First 1
                if (-not $job) { throw [System.Collections.Generic.KeyNotFoundException]::new("No job with id $id.") }
                return @{ Status = 200; Body = @{ job = (ConvertTo-WheelhouseUiJobSummary -Job $job -IncludeLog) } }
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/jobs/(?<id>\d+)/cancel$'
            Handler = {
                param($Context, $Body, $Match)
                $job = Stop-WheelhouseUiJob -Id ([int]$Match['id'])
                return @{ Status = 200; Body = @{ job = (ConvertTo-WheelhouseUiJobSummary -Job $job) } }
            }
        }

        @{
            Method  = 'POST'
            Pattern = '^/api/shutdown$'
            Handler = {
                param($Context, $Body, $Match)
                $script:UiShutdown = $true
                return @{ Status = 200; Body = @{ stopping = $true } }
            }
        }
    )
}

$script:UiRoutes = Get-WheelhouseUiRoute

function Invoke-WheelhouseUiApi {
    # Handles one API call and returns @{ Status = <int>; Body = <object> }. Pure with
    # respect to HTTP: the listener loop only moves bytes, so this is what tests call.
    # Finds the route in $script:UiRoutes, applies its Wheelhouse/Idle checks, runs it.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Path,

        $Body,

        [string]$ManagerRoot = $script:ManagerRoot
    )

    try {
        Sync-WheelhouseUiJob
        $context = Get-WheelhouseUiContext -ManagerRoot $ManagerRoot

        foreach ($route in $script:UiRoutes) {
            if ($route.Method -ne $Method -or $Path -notmatch $route.Pattern) { continue }
            $match = $Matches.Clone()
            if ($route.Wheelhouse) { Assert-WheelhouseUiConfigured -Context $context }
            if ($route.Idle -and (Get-WheelhouseUiRunningJob)) { throw [System.InvalidOperationException]::new($route.Idle) }
            return & $route.Handler $context $Body $match
        }
        return @{ Status = 404; Body = @{ error = "Unknown endpoint: $Method $Path" } }
    }
    catch [System.ArgumentException] {
        return @{ Status = 400; Body = @{ error = $_.Exception.Message } }
    }
    catch [System.Collections.Generic.KeyNotFoundException] {
        return @{ Status = 404; Body = @{ error = $_.Exception.Message } }
    }
    catch [System.InvalidOperationException] {
        return @{ Status = 409; Body = @{ error = $_.Exception.Message } }
    }
    catch {
        Write-Log "UI request $Method $Path failed: $($_.Exception.Message)" 'ERROR'
        return @{ Status = 500; Body = @{ error = $_.Exception.Message } }
    }
}

# --- HTTP server --------------------------------------------------------------

function Send-WheelhouseUiResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerResponse]$Response,

        [Parameter(Mandatory)]
        [int]$Status,

        [Parameter(Mandatory)]
        [string]$Text,

        [string]$ContentType = 'text/plain; charset=utf-8'
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $Response.StatusCode = $Status
    $Response.ContentType = $ContentType
    $Response.ContentLength64 = $bytes.Length
    $Response.Headers['Cache-Control'] = 'no-store'
    $Response.Headers['X-Content-Type-Options'] = 'nosniff'
    $Response.Headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none'"
    $Response.Headers['Referrer-Policy'] = 'no-referrer'
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
}

function Invoke-WheelhouseUiRequest {
    # Serves one HttpListener request: access checks, then a static file or an API call.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerContext]$Context,

        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter(Mandatory)]
        [int]$Port,

        [string]$ManagerRoot = $script:ManagerRoot
    )

    $request = $Context.Request
    $response = $Context.Response
    try {
        $path = $request.Url.AbsolutePath
        $suppliedToken = if ($path.StartsWith('/api/')) { $request.Headers['X-Wheelhouse-Token'] } else { $request.QueryString['t'] }
        $checkParams = @{
            Method        = $request.HttpMethod
            Path          = $path
            HostHeader    = [string]$request.Headers['Host']
            Origin        = [string]$request.Headers['Origin']
            ContentType   = [string]$request.ContentType
            SuppliedToken = [string]$suppliedToken
            Token         = $Token
            Port          = $Port
        }
        $denied = Test-WheelhouseUiRequest @checkParams
        if ($denied) {
            Send-WheelhouseUiResponse -Response $response -Status $denied.Status -Text $denied.Message
            return
        }

        if ($path.StartsWith('/api/')) {
            $body = $null
            if ($request.HttpMethod -ne 'GET' -and $request.HasEntityBody) {
                if ($request.ContentLength64 -gt 1MB) {
                    Send-WheelhouseUiResponse -Response $response -Status 413 -Text '{"error":"Request too large."}' -ContentType 'application/json; charset=utf-8'
                    return
                }
                $reader = [System.IO.StreamReader]::new($request.InputStream, [System.Text.Encoding]::UTF8)
                $raw = $reader.ReadToEnd()
                if ($raw.Trim()) {
                    try { $body = ConvertFrom-Json -InputObject $raw -ErrorAction Stop }
                    catch {
                        Send-WheelhouseUiResponse -Response $response -Status 400 -Text '{"error":"The request body is not valid JSON."}' -ContentType 'application/json; charset=utf-8'
                        return
                    }
                }
            }
            $result = Invoke-WheelhouseUiApi -Method $request.HttpMethod -Path $path -Body $body -ManagerRoot $ManagerRoot
            $json = ConvertTo-Json -InputObject $result.Body -Depth 8 -Compress
            Send-WheelhouseUiResponse -Response $response -Status $result.Status -Text $json -ContentType 'application/json; charset=utf-8'
            return
        }

        if (-not $script:UiStaticFiles.ContainsKey($path)) {
            Send-WheelhouseUiResponse -Response $response -Status 404 -Text 'Not found.'
            return
        }
        $filePath = Join-Path $script:UiWebRoot $script:UiStaticFiles[$path]
        if (-not (Test-Path -Path $filePath)) {
            Send-WheelhouseUiResponse -Response $response -Status 404 -Text "UI file missing: $($script:UiStaticFiles[$path])"
            return
        }
        $text = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::UTF8)
        Send-WheelhouseUiResponse -Response $response -Status 200 -Text $text -ContentType $script:UiMimeTypes[[System.IO.Path]::GetExtension($filePath)]
    }
    catch {
        Write-Log "UI request failed: $($_.Exception.Message)" 'ERROR'
        try { Send-WheelhouseUiResponse -Response $response -Status 500 -Text 'Internal error.' } catch { Write-Verbose 'The client had already gone away.' }
    }
    finally {
        $response.Close()
    }
}

function Start-WheelhouseUiServer {
    # Runs the UI until Ctrl+C or the Stop button. Single-threaded: the loop waits for
    # a request in 500 ms slices and advances the running job in between.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateRange(1024, 65535)]
        [int]$Port = 8765,

        [string]$Token,

        [switch]$NoBrowser,

        [string]$ManagerRoot = $script:ManagerRoot
    )

    if (-not $Token) { $Token = Get-WheelhouseUiRandomToken }
    if (-not $PSCmdlet.ShouldProcess("http://localhost:$Port/", 'Listen')) { return }

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://localhost:$Port/")
    $listener.Prefixes.Add("http://127.0.0.1:$Port/")
    try { $listener.Start() }
    catch {
        throw "Cannot listen on port $Port ($($_.Exception.Message)). Is the UI already running? Use -Port to pick another one."
    }

    $url = "http://localhost:$Port/?t=$Token"
    Write-Log "Wheelhouse UI is running. Open: $url" 'OK'
    Write-Log 'It accepts connections from this computer only. Press Ctrl+C here, or use the Stop button in the page, to stop it.'
    if (-not $NoBrowser) {
        try { Start-Process -FilePath $url } catch { Write-Log "Could not open the browser automatically: $($_.Exception.Message)" 'WARN' }
    }

    $script:UiShutdown = $false
    try {
        while ($listener.IsListening -and -not $script:UiShutdown) {
            $pending = $listener.GetContextAsync()
            while (-not $pending.AsyncWaitHandle.WaitOne(500)) {
                Sync-WheelhouseUiJob
                if ($script:UiShutdown) { break }
            }
            if (-not $pending.IsCompleted) { continue }
            Invoke-WheelhouseUiRequest -Context $pending.Result -Token $Token -Port $Port -ManagerRoot $ManagerRoot
        }
    }
    finally {
        $running = Get-WheelhouseUiRunningJob
        if ($running) { [void](Stop-WheelhouseUiJob -Id $running.Id) }
        $listener.Stop()
        $listener.Close()
        Write-Log 'Wheelhouse UI stopped.'
    }
}
