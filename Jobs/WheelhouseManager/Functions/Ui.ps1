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
$script:UiPackageNamePattern = '^[A-Za-z0-9][A-Za-z0-9._-]*$'
$script:UiPackageVersionPattern = '^[A-Za-z0-9][A-Za-z0-9._+!-]*$'
$script:UiWheelFilePattern = '^[A-Za-z0-9][A-Za-z0-9._+!-]*\.whl$'

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
    $names = @('WheelhousePath', 'RequirementsInPath', 'LocalRequirementsPath', 'PythonVersion', 'Platform',
        'MinimumPackageAgeDays', 'VulnerabilityServices', 'ReportRetentionMonths', 'SmtpServer', 'MailTo', 'MailFrom')
    $effective = Resolve-WheelhouseParameter -BoundParameters @{} -Name $names -Settings $settings

    $wheelhousePath = [string]$effective.WheelhousePath
    return [PSCustomObject]@{
        ManagerRoot    = $ManagerRoot
        JobsPath       = (Join-Path $ManagerRoot 'Jobs')
        SettingsPath   = $settingsPath
        DenylistPath   = (Get-WheelhouseDenylistPath -ManagerRoot $ManagerRoot)
        Settings       = $effective
        WheelhousePath = $wheelhousePath
        ReportsFolder  = $(if ($wheelhousePath) { Join-Path $wheelhousePath 'reports' } else { '' })
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
        if ($name -notmatch $script:UiPackageNamePattern -or $version -notmatch $script:UiPackageVersionPattern) {
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

    if ($step.ExitCode -ne 0) {
        & $finish 'Failed' "$($step.Script) finished with exit code $($step.ExitCode). Read the log for details."
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

function Invoke-WheelhouseUiApi {
    # Handles one API call and returns @{ Status = <int>; Body = <object> }. Pure with
    # respect to HTTP: the listener loop only moves bytes, so this is what tests call.
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
        $route = "$Method $Path"

        switch -Regex ($route) {
            '^GET /api/state$' {
                $running = Get-WheelhouseUiRunningJob
                $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
                return @{ Status = 200; Body = @{
                        wheelhouse_path   = $context.WheelhousePath
                        configured        = [bool]$context.WheelhousePath
                        reachable         = [bool]($context.WheelhousePath -and (Test-Path -Path $context.WheelhousePath -PathType Container))
                        defender          = (Test-WheelhouseDefenderAvailable)
                        is_admin          = $isAdmin
                        python_version    = [string]$context.Settings.PythonVersion
                        platform          = [string]$context.Settings.Platform
                        running_job       = $(if ($running) { ConvertTo-WheelhouseUiJobSummary -Job $running } else { $null })
                    }
                }
            }

            '^GET /api/packages$' {
                Assert-WheelhouseUiConfigured -Context $context
                $inventory = Get-WheelhousePackage -WheelhousePath $context.WheelhousePath -Denylist @(Read-WheelhouseDenylist -Path $context.DenylistPath)
                return @{ Status = 200; Body = @{ packages = @($inventory.Packages); groups = @($inventory.Groups); untracked = @($inventory.Untracked) } }
            }

            '^POST /api/packages/audit$' {
                Assert-WheelhouseUiConfigured -Context $context
                if (Get-UiBodyValue -Body $Body -Name 'all') {
                    $job = Start-WheelhouseUiJob -Title 'Audit: whole index' -Kind 'audit' -Context $context -Steps @(@{ Script = 'Test-WheelhousePackage.ps1'; Arguments = @() })
                }
                else {
                    $manifest = Read-WheelhouseManifest -WheelhousePath $context.WheelhousePath
                    $selection = Resolve-UiPackageSelection -Body $Body -Manifest $manifest
                    $list = ($selection | ForEach-Object { "$($_.Name)==$($_.Version)" }) -join ','
                    if ($list.Length -gt 20000) { throw [System.ArgumentException]::new('The selection is too large - use "Audit all" instead.') }
                    $job = Start-WheelhouseUiJob -Title "Audit: $($selection.Count) selected package(s)" -Kind 'audit' -Context $context -Steps @(@{ Script = 'Test-WheelhousePackage.ps1'; Arguments = @('-Package', $list) })
                }
                return @{ Status = 202; Body = @{ job = (ConvertTo-WheelhouseUiJobSummary -Job $job) } }
            }

            '^POST /api/packages/scan$' {
                Assert-WheelhouseUiConfigured -Context $context
                if (Get-UiBodyValue -Body $Body -Name 'all') {
                    $job = Start-WheelhouseUiJob -Title 'Defender scan: whole wheelhouse' -Kind 'scan' -Context $context -Steps @(@{ Script = 'Invoke-WheelhouseScan.ps1'; Arguments = @() })
                }
                else {
                    $manifest = Read-WheelhouseManifest -WheelhousePath $context.WheelhousePath
                    $files = [System.Collections.Generic.List[string]]::new()
                    foreach ($file in @(Get-UiBodyValue -Body $Body -Name 'files')) {
                        $fileName = [string]$file
                        if ($fileName -notmatch $script:UiWheelFilePattern) { throw [System.ArgumentException]::new('Invalid file name in the selection.') }
                        if (-not ($manifest | Where-Object { $_.file -eq $fileName })) {
                            throw [System.Collections.Generic.KeyNotFoundException]::new("$fileName is not in the wheelhouse manifest.")
                        }
                        if (-not $files.Contains($fileName)) { $files.Add($fileName) }
                    }
                    if ($files.Count -eq 0) { throw [System.ArgumentException]::new('Select at least one package.') }
                    $list = $files -join ','
                    if ($list.Length -gt 20000) { throw [System.ArgumentException]::new('The selection is too large - use "Scan all" instead.') }
                    $job = Start-WheelhouseUiJob -Title "Defender scan: $($files.Count) file(s)" -Kind 'scan' -Context $context -Steps @(@{ Script = 'Invoke-WheelhouseScan.ps1'; Arguments = @('-File', $list) })
                }
                return @{ Status = 202; Body = @{ job = (ConvertTo-WheelhouseUiJobSummary -Job $job) } }
            }

            '^POST /api/packages/add$' {
                Assert-WheelhouseUiConfigured -Context $context
                if (Get-WheelhouseUiRunningJob) {
                    throw [System.InvalidOperationException]::new('Another job is still running. Wait for it to finish or cancel it first.')
                }
                $specs = @(foreach ($item in @(Get-UiBodyValue -Body $Body -Name 'specs')) { [string]$item })
                if ($specs.Count -eq 0) { throw [System.ArgumentException]::new('Enter at least one package.') }
                if ($specs.Count -gt 100) { throw [System.ArgumentException]::new('Too many packages at once (at most 100).') }

                $addResult = Add-RequirementInLine -Path $context.Settings.RequirementsInPath -Spec $specs -Denylist @(Read-WheelhouseDenylist -Path $context.DenylistPath)
                $job = $null
                if ($addResult.Added.Count -gt 0) {
                    $steps = @(@{ Script = 'Update-Requirement.ps1'; Arguments = @() })
                    # By default the new pins also go straight into the wheelhouse
                    # (audit, cooldown, download); "resolve only" stops at requirements.txt.
                    if (-not (Get-UiBodyValue -Body $Body -Name 'resolve_only')) { $steps += @{ Script = 'Update-Wheelhouse.ps1'; Arguments = @() } }
                    $job = Start-WheelhouseUiJob -Title "Add: $($addResult.Added -join ', ')" -Kind 'add' -Context $context -Steps $steps
                }
                return @{ Status = 200; Body = @{ added = @($addResult.Added); skipped = @($addResult.Skipped); job = $(if ($job) { ConvertTo-WheelhouseUiJobSummary -Job $job } else { $null }) } }
            }

            '^POST /api/packages/remove$' {
                Assert-WheelhouseUiConfigured -Context $context
                if (Get-WheelhouseUiRunningJob) {
                    throw [System.InvalidOperationException]::new('A job is running. Wait for it to finish or cancel it before removing packages.')
                }
                $mode = [string](Get-UiBodyValue -Body $Body -Name 'mode')
                if ($mode -notin 'quarantine', 'delete') { throw [System.ArgumentException]::new("mode must be 'quarantine' or 'delete'.") }
                if ($mode -eq 'delete' -and (Get-UiBodyValue -Body $Body -Name 'confirm') -ne $true) {
                    throw [System.ArgumentException]::new('Deleting needs an explicit confirmation.')
                }
                $reason = [string](Get-UiBodyValue -Body $Body -Name 'reason')
                if ($reason.Length -gt 400) { throw [System.ArgumentException]::new('The reason is too long (400 characters at most).') }

                $manifest = Read-WheelhouseManifest -WheelhousePath $context.WheelhousePath
                $selection = Resolve-UiPackageSelection -Body $Body -Manifest $manifest -Max 200
                $outcomes = foreach ($package in $selection) {
                    try {
                        $removeParams = @{ WheelhousePath = $context.WheelhousePath; Name = $package.Name; Version = $package.Version; Reason = $reason; DenylistPath = $context.DenylistPath }
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

            '^GET /api/quarantine$' {
                Assert-WheelhouseUiConfigured -Context $context
                $records = @(Get-QuarantinedPackage -WheelhousePath $context.WheelhousePath)
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

            '^POST /api/quarantine/restore$' {
                Assert-WheelhouseUiConfigured -Context $context
                if (Get-WheelhouseUiRunningJob) {
                    throw [System.InvalidOperationException]::new('A job is running. Wait for it to finish or cancel it before restoring packages.')
                }
                $id = [string](Get-UiBodyValue -Body $Body -Name 'id')
                if ($id -notmatch '^[A-Za-z0-9._-]+$') { throw [System.ArgumentException]::new('Invalid quarantine id.') }
                $restoreParams = @{ WheelhousePath = $context.WheelhousePath; Id = $id; DenylistPath = $context.DenylistPath }
                if (Get-UiBodyValue -Body $Body -Name 'keep_denylist') { $restoreParams['KeepDenylist'] = $true }
                $done = Restore-WheelhousePackage @restoreParams
                return @{ Status = 200; Body = @{ name = $done.Name; version = $done.Version; denylist_removed = $done.DenylistRemoved } }
            }

            '^GET /api/denylist$' {
                $entries = @(Read-WheelhouseDenylist -Path $context.DenylistPath)
                $manifest = @()
                if ($context.WheelhousePath -and (Test-Path -Path $context.WheelhousePath -PathType Container)) {
                    $manifest = Read-WheelhouseManifest -WheelhousePath $context.WheelhousePath
                }
                $items = foreach ($entry in ($entries | Sort-Object name, version)) {
                    $installed = [bool]($manifest | Where-Object { $_.name -eq $entry.name -and ($entry.version -eq '*' -or $_.version -eq $entry.version) })
                    @{ name = [string]$entry.name; version = [string]$entry.version; reason = [string]$entry.reason; added_utc = (ConvertTo-IsoTimestamp -Value $entry.added_utc); added_by = [string]$entry.added_by; source = [string]$entry.source; installed = $installed }
                }
                return @{ Status = 200; Body = @{ items = @($items) } }
            }

            '^POST /api/denylist/add$' {
                $entry = Add-WheelhouseDenylistEntry -Name ([string](Get-UiBodyValue -Body $Body -Name 'name')) `
                    -Version ([string](Get-UiBodyValue -Body $Body -Name 'version')) `
                    -Reason ([string](Get-UiBodyValue -Body $Body -Name 'reason')) -Source 'manual' -Path $context.DenylistPath
                return @{ Status = 200; Body = @{ name = $entry.name; version = $entry.version } }
            }

            '^POST /api/denylist/remove$' {
                $removed = Remove-WheelhouseDenylistEntry -Name ([string](Get-UiBodyValue -Body $Body -Name 'name')) -Version ([string](Get-UiBodyValue -Body $Body -Name 'version')) -Path $context.DenylistPath
                if (-not $removed) { throw [System.Collections.Generic.KeyNotFoundException]::new('No such denylist entry.') }
                return @{ Status = 200; Body = @{ removed = $true } }
            }

            '^GET /api/settings$' {
                $schema = @(Get-WheelhouseSettingSchema)
                $values = @{}
                foreach ($item in $schema) { $values[$item.Key] = $context.Settings[$item.Key] }
                $fields = foreach ($item in $schema) {
                    $options = @()
                    if ($item.Options) { $options = @($item.Options) }
                    @{ key = $item.Key; type = $item.Type; label = $item.Label; help = $item.Help; options = $options; min = $item.Min; max = $item.Max }
                }
                return @{ Status = 200; Body = @{ fields = @($fields); values = $values } }
            }

            '^POST /api/settings$' {
                $updates = @{}
                $incoming = Get-UiBodyValue -Body $Body -Name 'updates'
                if ($null -eq $incoming) { throw [System.ArgumentException]::new('No settings were sent.') }
                foreach ($property in $incoming.PSObject.Properties) {
                    $updates[$property.Name] = ConvertTo-WheelhouseSettingValue -Key $property.Name -Value $property.Value
                }
                if ($updates.Count -eq 0) { throw [System.ArgumentException]::new('No settings were sent.') }
                Set-WheelhouseSetting -SettingsPath $context.SettingsPath -Updates $updates
                Write-Log "Settings changed from the UI: $(($updates.Keys | Sort-Object) -join ', ')" 'WARN'
                return @{ Status = 200; Body = @{ saved = @($updates.Keys | Sort-Object) } }
            }

            '^GET /api/rejected$' {
                Assert-WheelhouseUiConfigured -Context $context
                $latest = Get-ChildItem -Path $context.ReportsFolder -Filter 'Report_Rejected_*.json' -File -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1
                $items = @()
                if ($latest) {
                    $parsed = Get-Content -Path $latest.FullName -Raw | ConvertFrom-Json
                    $items = @(foreach ($item in $parsed) { $item })
                }
                return @{ Status = 200; Body = @{ file = $(if ($latest) { $latest.Name } else { $null }); items = $items } }
            }

            '^GET /api/jobs$' {
                $jobs = @($script:UiJobs | Sort-Object Id -Descending | ForEach-Object { ConvertTo-WheelhouseUiJobSummary -Job $_ })
                return @{ Status = 200; Body = @{ jobs = $jobs } }
            }

            '^GET /api/jobs/(?<id>\d+)$' {
                $id = [int]$Matches['id']
                $job = $script:UiJobs | Where-Object { $_.Id -eq $id } | Select-Object -First 1
                if (-not $job) { throw [System.Collections.Generic.KeyNotFoundException]::new("No job with id $id.") }
                return @{ Status = 200; Body = @{ job = (ConvertTo-WheelhouseUiJobSummary -Job $job -IncludeLog) } }
            }

            '^POST /api/jobs/(?<id>\d+)/cancel$' {
                $job = Stop-WheelhouseUiJob -Id ([int]$Matches['id'])
                return @{ Status = 200; Body = @{ job = (ConvertTo-WheelhouseUiJobSummary -Job $job) } }
            }

            '^POST /api/shutdown$' {
                $script:UiShutdown = $true
                return @{ Status = 200; Body = @{ stopping = $true } }
            }

            default {
                return @{ Status = 404; Body = @{ error = "Unknown endpoint: $route" } }
            }
        }
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
