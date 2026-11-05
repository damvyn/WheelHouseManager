<#
.SYNOPSIS
    Starts the local web UI of the wheelhouse manager.

.DESCRIPTION
    Serves a small web application on http://localhost:<Port>/ for this computer only:
    browse the packages of the wheelhouse, audit and virus-scan all or selected ones,
    add packages, remove or quarantine packages, edit the denylist and the settings.

    The UI is a thin layer: every action calls the same module functions and scripts
    (Test-WheelhousePackage.ps1, Invoke-WheelhouseScan.ps1, Update-Requirement.ps1,
    Update-Wheelhouse.ps1) that you can run by hand. Long actions run as background
    jobs and their log is shown live in the page.

    A random session token is generated at every start and is part of the URL this
    script opens. Keep the console window open while you use the UI; Ctrl+C (or the
    Stop button in the page) stops it.

.PARAMETER Port
    TCP port to listen on (default 8765).

.PARAMETER NoBrowser
    Print the URL but do not open the browser.

.PARAMETER KeepInput
    Keep Input\requirements.in and requirements.txt as they are. Without it they are emptied at
    start (requirements.in keeps its comment header), so every UI session starts with a fresh
    Add packages tab. Use it when a requirements.txt waits for a second person's approval.

.EXAMPLE
    .\Start-WheelhouseUI.ps1

.NOTES
    Defender scans need an elevated PowerShell (Start-MpScan requires administrator
    rights); everything else works without elevation.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8765,

    [switch]$NoBrowser,

    [switch]$KeepInput
)

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

try {
    if (-not $KeepInput) {
        $inputFiles = Resolve-WheelhouseParameter -BoundParameters @{} -Name RequirementsInPath, LocalRequirementsPath
        [string[]]$reset = Reset-WheelhouseInput -RequirementsInPath ([string]$inputFiles.RequirementsInPath) -RequirementsTxtPath ([string]$inputFiles.LocalRequirementsPath)
        if ($reset.Count -gt 0) { Write-Log "Fresh start: emptied $($reset -join ', ') (use -KeepInput to keep them)." }
    }
    Start-WheelhouseUiServer -Port $Port -NoBrowser:$NoBrowser
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    exit 2
}
exit 0
