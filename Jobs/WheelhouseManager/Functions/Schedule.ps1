# ---------------------------------------------------------------------------
# The weekly check as a Windows Scheduled Task (Test-Wheelhouse.ps1)
# ---------------------------------------------------------------------------
# The task runs under an account with a stored password ("Run whether user is logged on or
# not"): only such a logon has network credentials for the share. S4U or SYSTEM would reach
# the share as the computer account, which often has no access to a share on another server.
# The password goes to Task Scheduler only; the manager never stores or logs it.

$script:ScheduledCheckTaskName = 'Wheelhouse Weekly Check'
$script:ScheduledCheckDays = @('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')

function Get-WheelhouseScheduledCheckScript {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$ManagerRoot = $script:ManagerRoot
    )

    return Join-Path (Join-Path $ManagerRoot 'Jobs') 'Test-Wheelhouse.ps1'
}

function ConvertTo-ScheduledCheckResultText {
    # Task Scheduler's "Last Run Result" in words (the script's exit codes, and the
    # Task Scheduler codes an administrator meets most often).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        $Code
    )

    if ($null -eq $Code) { return '' }
    switch ([long]$Code) {
        0 { return 'OK' }
        1 { return 'Findings - an alert was sent' }
        2 { return 'A check could not be completed, or the run aborted - see Log_Audit_*.txt' }
        3 { return 'The wheelhouse was busy - try again' }
        267008 { return 'Ready' }
        267009 { return 'Running now' }
        267011 { return 'Has not run yet' }
        2147943645 { return 'Not started: the account could not log on (password changed?)' }
        default { return "Code $Code" }
    }
}

function Get-WheelhouseNetworkDrive {
    # For a path on a mapped network drive (Z:\...), the UNC path it maps to; $null for a UNC
    # path or a local drive. A Scheduled Task does not see the drive mappings of an
    # interactive session, so the task needs the UNC path.
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Path
    )

    if ($Path -notmatch '^(?<drive>[A-Za-z]):(?<rest>.*)$') { return $null }
    $letter = $Matches['drive']
    $rest = $Matches['rest']
    $root = $null
    try {
        $drive = Get-PSDrive -Name $letter -PSProvider FileSystem -ErrorAction Stop
        if ($drive.DisplayRoot -and $drive.DisplayRoot.StartsWith('\\')) { $root = $drive.DisplayRoot }
    }
    catch {
        Write-Verbose "Drive ${letter}: is not known in this session."
    }
    if (-not $root) {
        try {
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${letter}:'" -ErrorAction Stop
            if ($disk -and [int]$disk.DriveType -eq 4 -and $disk.ProviderName) { $root = [string]$disk.ProviderName }
        }
        catch {
            Write-Verbose "Could not read drive ${letter}: from WMI."
        }
    }
    if (-not $root) { return $null }
    $unc = $root.TrimEnd('\')
    if ($rest -and $rest -ne '\') { $unc += '\' + $rest.TrimStart('\') }
    return [PSCustomObject]@{ Path = $Path; Drive = "${letter}:"; Unc = $unc }
}

function Get-WheelhouseScheduledCheck {
    # The weekly check's Scheduled Task: { Registered; TaskName; State; User; Days[]; Time;
    # LastRunTime; LastResult; LastResultText; NextRunTime; Script; ForThisInstallation }.
    [CmdletBinding()]
    param(
        [string]$ManagerRoot = $script:ManagerRoot
    )

    $scriptPath = Get-WheelhouseScheduledCheckScript -ManagerRoot $ManagerRoot
    $task = Get-ScheduledTask -TaskName $script:ScheduledCheckTaskName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $task) {
        return [PSCustomObject]@{ Registered = $false; TaskName = $script:ScheduledCheckTaskName; Script = $scriptPath }
    }
    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    $trigger = @($task.Triggers) | Select-Object -First 1
    $days = @()
    $time = ''
    if ($trigger) {
        # A weekly trigger's DaysOfWeek is a bit mask, Sunday = 1 ... Saturday = 64.
        $mask = 0
        if ($trigger.PSObject.Properties['DaysOfWeek'] -and $null -ne $trigger.DaysOfWeek) { $mask = [int]$trigger.DaysOfWeek }
        $order = @('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
        $days = @(for ($i = 0; $i -lt 7; $i++) { if ($mask -band (1 -shl $i)) { $order[$i] } })
        # StartBoundary is local time, e.g. 2026-11-01T02:00:00.
        if ([string]$trigger.StartBoundary -match 'T(\d\d:\d\d)') { $time = $Matches[1] }
    }
    $arguments = (@($task.Actions) | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
    $lastRun = if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 2000) { $info.LastRunTime.ToUniversalTime().ToString('o') } else { '' }
    $nextRun = if ($info -and $info.NextRunTime -and $info.NextRunTime.Year -gt 2000) { $info.NextRunTime.ToUniversalTime().ToString('o') } else { '' }
    $lastResult = if ($info -and $lastRun) { $info.LastTaskResult } else { $null }
    return [PSCustomObject]@{
        Registered          = $true
        TaskName            = $script:ScheduledCheckTaskName
        State               = [string]$task.State
        User                = [string]$task.Principal.UserId
        Days                = $days
        Time                = $time
        LastRunTime         = $lastRun
        LastResult          = $lastResult
        LastResultText      = $(if ($lastRun) { ConvertTo-ScheduledCheckResultText -Code $lastResult } else { 'Has not run yet' })
        NextRunTime         = $nextRun
        Script              = $scriptPath
        ForThisInstallation = ($arguments.IndexOf($scriptPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    }
}

function Register-WheelhouseScheduledCheck {
    # Creates or replaces the weekly check's task: Test-Wheelhouse.ps1 of this installation,
    # weekly on -DayOfWeek at -At (HH:mm, local time), as -User with -Password ("run whether
    # the user is logged on or not"), started late if a run was missed, never twice at once,
    # stopped after 4 hours. Throws ArgumentException for invalid input and for a logon
    # Task Scheduler refuses; InvalidOperationException when Windows denies the change.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string[]]$DayOfWeek,

        [Parameter(Mandatory)]
        [string]$At,

        [Parameter(Mandatory)]
        [string]$User,

        [Parameter(Mandatory)]
        [securestring]$Password,

        [string]$ManagerRoot = $script:ManagerRoot,

        # The PowerShell that runs the script (default: the one running this).
        [string]$PowerShellPath = (Get-Process -Id $PID).Path
    )

    $days = @($DayOfWeek | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -Unique)
    if ($days.Count -eq 0) { throw [System.ArgumentException]::new('Choose at least one day.') }
    foreach ($day in $days) {
        if ($script:ScheduledCheckDays -notcontains $day) { throw [System.ArgumentException]::new("Not a day of the week: '$day'.") }
    }
    if ($At -notmatch '^([01]\d|2[0-3]):[0-5]\d$') { throw [System.ArgumentException]::new('Enter the time as HH:mm, for example 02:00.') }
    if ($User -notmatch '^[^"<>|*?/:;,=+\[\]\x00-\x1f]{1,64}(\\[^"<>|*?/:;,=+\[\]\x00-\x1f\\]{1,104})?$' -and $User -notmatch '^[^"<>|\s\\]+@[^"<>|\s\\]+$') {
        throw [System.ArgumentException]::new('Enter the account as DOMAIN\user or user@domain.')
    }
    $plain = [System.Net.NetworkCredential]::new('', $Password).Password
    if ([string]::IsNullOrEmpty($plain)) { throw [System.ArgumentException]::new("Enter the account's password - Task Scheduler needs it to reach the share while nobody is logged on.") }

    $scriptPath = Get-WheelhouseScheduledCheckScript -ManagerRoot $ManagerRoot
    if (-not (Test-Path -Path $scriptPath)) { throw [System.InvalidOperationException]::new("Test-Wheelhouse.ps1 was not found at $scriptPath.") }
    if (-not $PSCmdlet.ShouldProcess($script:ScheduledCheckTaskName, "Register weekly check as $User")) { return }

    $time = [datetime]::ParseExact($At, 'HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    $action = New-ScheduledTaskAction -Execute $PowerShellPath -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -WorkingDirectory (Split-Path -Path $scriptPath -Parent)
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $days -At $time
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 4)
    $registerParams = @{
        TaskName    = $script:ScheduledCheckTaskName
        Action      = $action
        Trigger     = $trigger
        Settings    = $settings
        User        = $User
        Password    = $plain
        RunLevel    = 'Limited'
        Description = 'Wheelhouse Manager: weekly check of every published package (integrity, vulnerabilities, yanked, denylist) with alerts. Created from the UI.'
        Force       = $true
        ErrorAction = 'Stop'
    }
    try {
        [void](Register-ScheduledTask @registerParams)
    }
    catch {
        $text = $_.Exception.Message
        if ($text -match 'user name or password|logon failure|0x8007052E') {
            throw [System.ArgumentException]::new("Task Scheduler refused the account or password for $User. Check both and try again.")
        }
        if ($text -match 'Access is denied|0x80070005') {
            throw [System.InvalidOperationException]::new("Windows denied the change ($text). Registering a task for another account, or replacing a task someone else created, needs an elevated (Run as administrator) PowerShell for Start-WheelhouseUI.ps1.")
        }
        throw [System.InvalidOperationException]::new("The task could not be registered: $text")
    }
    finally {
        $plain = $null
    }
    Write-Log "Scheduled task '$($script:ScheduledCheckTaskName)' registered: $($days -join ', ') at $At as $User." 'OK'
    return Get-WheelhouseScheduledCheck -ManagerRoot $ManagerRoot
}

function Start-WheelhouseScheduledCheck {
    # Runs the registered task now (as its account, like a scheduled run).
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $task = Get-ScheduledTask -TaskName $script:ScheduledCheckTaskName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $task) { throw [System.Collections.Generic.KeyNotFoundException]::new('The weekly check is not registered yet.') }
    if ($PSCmdlet.ShouldProcess($script:ScheduledCheckTaskName, 'Run now')) {
        Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
    }
}

function Unregister-WheelhouseScheduledCheck {
    # Returns $true if the task existed and was removed.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    $task = Get-ScheduledTask -TaskName $script:ScheduledCheckTaskName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $task) { return $false }
    if (-not $PSCmdlet.ShouldProcess($script:ScheduledCheckTaskName, 'Remove scheduled task')) { return $false }
    try {
        Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
    }
    catch {
        throw [System.InvalidOperationException]::new("The task could not be removed ($($_.Exception.Message)). A task someone else created can only be removed from an elevated PowerShell.")
    }
    Write-Log "Scheduled task '$($script:ScheduledCheckTaskName)' removed." 'WARN'
    return $true
}
