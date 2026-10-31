<#
.SYNOPSIS
    Deploys the wheelhouse manager scripts to a local folder and initializes its
    configuration and input files. Safe to re-run.

.DESCRIPTION
    Copies Jobs\ (the WheelhouseManager module, Update-Wheelhouse.ps1,
    Update-Requirement.ps1, Test-Wheelhouse.ps1, Test-WheelhousePackage.ps1,
    Invoke-WheelhouseScan.ps1, Start-WheelhouseUI.ps1, Send-VulnerabilityAlert.ps1; the module
    folder includes the UI's Web\ files) and
    Invoke-WheelhousePipeline.ps1 and whm.ps1 (deployed to the destination root, not Jobs\)
    from next to this script into -DestinationPath, creates config\settings.psd1
    if it doesn't exist yet, and creates an empty Input\requirements.in and
    Input\requirements.txt if they don't exist yet.

    Idempotent: re-running this script always refreshes the Jobs\ scripts (so a
    newer script package gets redeployed), but NEVER overwrites settings.psd1 keys
    you didn't pass, and NEVER overwrites an existing requirements.in/.txt - both
    of those are user data, not code.

.PARAMETER DestinationPath
    Where to deploy to (default: C:\WheelHouseManager).

.PARAMETER WheelhousePath
    UNC or local path to the central wheelhouse. If supplied, written into
    config\settings.psd1 as the default for the other scripts. Optional on a
    re-run if it's already set - omit it to leave the existing value untouched.

.PARAMETER RegisterScheduledTask
    Also register (or replace) the weekly check's Scheduled Task, 'Wheelhouse Weekly Check',
    running the deployed Jobs\Test-Wheelhouse.ps1 as -TaskCredential (asked for if omitted).
    The account needs read/write access to the share and network access to PyPI and OSV;
    its password is handed to Task Scheduler only.

.PARAMETER TaskCredential
    The account the weekly check runs as (DOMAIN\user and password).

.PARAMETER TaskDays
    Days of the week for the weekly check (default Sunday).

.PARAMETER TaskTime
    Local time of day, HH:mm (default 02:00).

.PARAMETER SkipDoctor
    Do not run the installation check ("whm doctor") at the end.

.EXAMPLE
    .\Setup.ps1 -WheelhousePath "\\server\share\wheelhouse"

.EXAMPLE
    # Deploy and schedule the weekly check (asks for the account's password)
    .\Setup.ps1 -WheelhousePath "\\server\share\wheelhouse" -RegisterScheduledTask -TaskDays Sunday, Wednesday

.EXAMPLE
    # Custom destination folder
    .\Setup.ps1 -DestinationPath "D:\WheelHouseManager" -WheelhousePath "\\server\share\wheelhouse"

.NOTES
    Requires the WheelhouseManager module (Jobs\WheelhouseManager next to this script).
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$DestinationPath = "C:\WheelHouseManager",

    [string]$WheelhousePath,

    [switch]$RegisterScheduledTask,

    [System.Management.Automation.PSCredential]$TaskCredential,

    [ValidateSet('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')]
    [string[]]$TaskDays = @('Sunday'),

    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$TaskTime = '02:00',

    [switch]$SkipDoctor
)

$sourceJobsPath = Join-Path $PSScriptRoot 'Jobs'
Import-Module (Join-Path $sourceJobsPath 'WheelhouseManager') -ErrorAction Stop

Write-Log "=== Wheelhouse manager setup started ==="
Write-Log "Destination: $DestinationPath"

# ---------------------------------------------------------------------------
# Step 1: deploy Jobs\ (always refreshed - these are code, not user data)
# ---------------------------------------------------------------------------

$destJobsPath = Join-Path $DestinationPath 'Jobs'
New-Item -ItemType Directory -Path $destJobsPath -Force | Out-Null

# The scripts plus the WheelhouseManager module folder. The module folder is
# replaced as a whole so function files removed from the package don't linger.
$isSameFolder = [string]::Equals(
    [System.IO.Path]::GetFullPath($sourceJobsPath).TrimEnd('\', '/'),
    [System.IO.Path]::GetFullPath($destJobsPath).TrimEnd('\', '/'),
    [System.StringComparison]::OrdinalIgnoreCase)
if ($isSameFolder) {
    Write-Log "Source and destination Jobs\ folders are the same - nothing to copy." "WARN"
}
else {
    Copy-Item -Path (Join-Path $sourceJobsPath '*.ps1') -Destination $destJobsPath -Force
    $destModulePath = Join-Path $destJobsPath 'WheelhouseManager'
    if (Test-Path -Path $destModulePath) {
        Remove-Item -Path $destModulePath -Recurse -Force
    }
    Copy-Item -Path (Join-Path $sourceJobsPath 'WheelhouseManager') -Destination $destJobsPath -Recurse -Force
}
Write-Log "Deployed Jobs\ scripts and the WheelhouseManager module to: $destJobsPath" "OK"

foreach ($rootScript in 'Invoke-WheelhousePipeline.ps1', 'whm.ps1') {
    $source = Join-Path $PSScriptRoot $rootScript
    if (-not (Test-Path -Path $source)) {
        Write-Log "$rootScript not found next to Setup.ps1 - skipped." "WARN"
    }
    elseif (-not $isSameFolder) {
        Copy-Item -Path $source -Destination $DestinationPath -Force
        Write-Log "Deployed $rootScript to: $DestinationPath" "OK"
    }
}

# ---------------------------------------------------------------------------
# Step 2: config\settings.psd1 (created once, merged thereafter - never clobbered)
# ---------------------------------------------------------------------------

$inputPath = Join-Path $DestinationPath "Input"
$configPath = Join-Path $DestinationPath "config"
New-Item -ItemType Directory -Path $configPath -Force | Out-Null
$settingsPath = Join-Path $configPath "settings.psd1"

if (-not (Test-Path -Path $settingsPath)) {
    $defaultSettings = Get-WheelhouseDefaultSetting -ManagerRoot $DestinationPath
    Save-WheelhouseSetting -SettingsPath $settingsPath -Settings $defaultSettings
    Write-Log "Created default settings file: $settingsPath" "OK"
}
else {
    Write-Log "Settings file already exists, leaving other keys untouched: $settingsPath"
}

if (-not [string]::IsNullOrWhiteSpace($WheelhousePath)) {
    Set-WheelhouseSetting -SettingsPath $settingsPath -Updates @{ WheelhousePath = $WheelhousePath }
    Write-Log "WheelhousePath set to: $WheelhousePath" "OK"
}
else {
    $currentSettings = Get-WheelhouseSetting -SettingsPath $settingsPath
    if ([string]::IsNullOrWhiteSpace($currentSettings["WheelhousePath"])) {
        Write-Log "No -WheelhousePath supplied and none is set yet in settings.psd1 - the other scripts will require it explicitly until this is set." "WARN"
    }
}

# ---------------------------------------------------------------------------
# Step 3: Input\ (created once - requirements.in/.txt are user data, never overwritten)
# ---------------------------------------------------------------------------

New-Item -ItemType Directory -Path $inputPath -Force | Out-Null

$requirementsInDefault = @"
# Add the packages you need, one per line, unpinned or with a version range.
# Example:
#   numpy
#   pandas>=2.0
"@

Initialize-ManagerFile -Path (Join-Path $inputPath "requirements.in") -DefaultContent $requirementsInDefault
Initialize-ManagerFile -Path (Join-Path $inputPath "requirements.txt") -DefaultContent ""

# ---------------------------------------------------------------------------
# Step 4 (optional): the weekly check's Scheduled Task
# ---------------------------------------------------------------------------

$setupFailed = $false
if ($RegisterScheduledTask) {
    if (-not $TaskCredential) {
        $TaskCredential = Get-Credential -Message 'Account for the weekly check (needs read/write access to the wheelhouse share)' -UserName ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    }
    if (-not $TaskCredential) {
        Write-Log 'No account given - the Scheduled Task was not registered.' 'WARN'
    }
    else {
        try {
            $taskParams = @{
                DayOfWeek   = $TaskDays
                At          = $TaskTime
                User        = $TaskCredential.UserName
                Password    = $TaskCredential.Password
                ManagerRoot = $DestinationPath
            }
            $task = Register-WheelhouseScheduledCheck @taskParams
            Write-Log "Weekly check registered: $($TaskDays -join ', ') at $TaskTime as $($TaskCredential.UserName); next run $($task.NextRunTime)." 'OK'
        }
        catch {
            Write-Log "The Scheduled Task could not be registered: $($_.Exception.Message)" 'ERROR'
            $setupFailed = $true
        }
    }
}

# ---------------------------------------------------------------------------
# Step 5: check the installation ("whm doctor")
# ---------------------------------------------------------------------------

if (-not $SkipDoctor) {
    Write-Log 'Checking the installation (whm doctor)...'
    foreach ($check in @(Test-WheelhouseHealth -ManagerRoot $DestinationPath)) {
        $level = switch ($check.Level) { 'ok' { 'OK' } 'warn' { 'WARN' } default { 'ERROR' } }
        Write-Log ("{0,-24} {1}" -f $check.Name, $check.Message) $level
        if ($check.Fix -and $check.Level -ne 'ok') { Write-Log "    -> $($check.Fix)" $level }
    }
}

Write-Log "=== Wheelhouse manager setup finished ==="
Write-Log "Next step: edit $(Join-Path $inputPath 'requirements.in'), then run: $(Join-Path $DestinationPath 'whm.ps1') resolve   (whm help lists every command)"
if ($setupFailed) { exit 2 }
