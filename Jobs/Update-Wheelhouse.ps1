<#
.SYNOPSIS
    Server-side maintenance script for an offline uv/pip "wheelhouse" package repository,
    backed by a SHA256 manifest for integrity verification.

.DESCRIPTION
    Automatically picks the right mode - no flag needed. The wheelhouse can hold
    MULTIPLE versions of the same package side by side across separate group files
    (requirements-1.txt, requirements-2.txt, ...) - one group file never contains two
    versions of the same package name, since pip's requirements format can't express
    that, but different group files can each pin a different version of it.

      - Verifies wheelhouse integrity against manifest.json first (every tracked file's
        hash must still match, across the whole wheelhouse). Any mismatch stops the
        script immediately, before any merge or per-group processing happens.

      - If the local requirements file (-LocalRequirementsPath, or config\settings.psd1's
        LocalRequirementsPath - by default Input\requirements.txt) exists and has
        content, a merge is PLANNED for its entries: an exact duplicate (same
        name==version already listed anywhere) is skipped; a new package name goes to
        the first group that doesn't already use that name; a name already pinned to a
        DIFFERENT version everywhere goes to a new group file. Nothing is written yet.

      - Anything new is merged only for an APPROVED proposal of exactly that
        requirements.txt (Update-Requirement.ps1 or Invoke-WheelhouseRemediation.ps1 record
        one). With ApprovalMode SamePersonAllowed (default) running this script approves a
        pending proposal - recorded under your name. With SeparateApprover, another person
        must approve it first (UI: Add packages tab); otherwise the run stops with exit
        code 1 and changes nothing. A remediation proposal swaps the fixed version into the
        group files that list the vulnerable one, then quarantines the vulnerable version.

      - For EACH group, the candidates - the planned new pins plus any pins the group
        already lists without a wheel in the wheelhouse - go through the denylist, the
        vulnerability audit, PyPI's yanked flag, the package-age (cooldown) check and
        the download into a staging folder outside the wheelhouse. Each downloaded file
        must match the sha256 PyPI publishes for it and pass a Microsoft Defender scan
        (unless the setting DefenderScanAtIntake is off) before it is copied into the
        wheelhouse - clients never see an unchecked file. A package that fails a step is
        rejected with the reason (log + Report_Rejected_<timestamp>.json), and so is every
        package that needs it (the "# via" lines of requirements.txt, category
        "dependency"), in any group; the others are published. Every group is checked
        before any is published. Only packages whose wheel was actually downloaded are written into the
        group file - a group file never lists a package that isn't in the wheelhouse.
        A rejected new package stays in the local requirements file and is simply
        tried again on the next run (e.g. once its cooldown has passed).

      - Only the new packages are audited and scanned. Published versions are re-audited
        by the weekly check (Test-Wheelhouse.ps1), and whm / the web UI start an audit in
        the background when the last one is older than AuditMaxAgeDays.

      - Downloads use pip's --no-deps: group files come from `uv pip compile`, so every
        transitive dependency is already pinned in them and goes through the same
        audit and cooldown checks. Nothing unpinned is ever pulled in.

      - The wheels published for a group are added to the manifest right after that
        group (existing entries are kept unchanged). The share itself is not virus-scanned:
        that is the file server's antivirus' job; new wheels are scanned at intake.

      - A published wheel that disappeared from the share (e.g. the file server's
        antivirus moved it to its own quarantine) or whose content changed does not block
        the run while AutoQuarantine is on: the missing one is taken out of the group files
        and the manifest, the changed one is quarantined, both are denylisted, and a notice
        is raised. With AutoQuarantine off, the run stops instead.

    Writes one Wheelhouse.AuditResult object per audit and one Wheelhouse.Notice per
    finding that is not an audit (wheels missing or changed on the share, blocked
    downloads) to the output stream, so a caller (Invoke-WheelhousePipeline.ps1) can alert on exactly
    this run's findings.

    Exit codes: 0 OK; 1 rejected packages, vulnerabilities, threats, or a change still
    waiting for approval (needs attention);
    2 aborted or an audit could not be completed; 3 another operation holds the lock.

    Function definitions live in the WheelhouseManager module next to this script.

.PARAMETER WheelhousePath
    UNC or local path to the network-shared Wheelhouse folder.
    manifest.json and the requirements-N.txt group files are created/maintained
    automatically in the same folder. Optional if already set in config\settings.psd1
    (one level up from this script) - errors out if neither is set.

.PARAMETER LocalRequirementsPath
    A locally-resolved requirements.txt (typically produced by Update-Requirement.ps1)
    whose entries get merged into the wheelhouse's group files before processing.
    Defaults to config\settings.psd1's LocalRequirementsPath (Setup.ps1 sets it to
    Input\requirements.txt under the manager root) - i.e. a plain run merges whatever
    is in Input\requirements.txt. If that file is missing or empty, no merge happens.
    Pass an explicit empty string ("") to skip the merge even if settings.psd1 has a
    value set.

.PARAMETER PythonVersion
    Target Python version for downloads and manifest tag matching (default: 3.14, tag "cp314").

.PARAMETER Platform
    Target platform tag for downloads and manifest tag matching (default: win_amd64).

.PARAMETER MinimumPackageAgeDays
    Minimum days a package version must be published on PyPI before it can be downloaded
    (default: 10). Applies only to new/changed packages. For an urgent fix, prefer
    -ExpeditePackage: it skips the cooldown for that one pin only.

.PARAMETER VulnerabilityServices
    pip-audit vulnerability service(s) to check (default: osv, pypi).

.PARAMETER ExpeditePackage
    name==version pins whose cooldown is skipped in this run (e.g. a security fix that is
    only a few days old). Every other check still applies. Needs -ExpediteReason.

.PARAMETER ExpediteReason
    Why the cooldown is skipped; logged with the user name.

.PARAMETER AutoQuarantine
    On or Off for this run, overriding the AutoQuarantine setting (default On): whether a
    wheel removed or changed outside the manager is taken out automatically, or stops the run.

.EXAMPLE
    # Process existing group files only - no merge
    .\Update-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse" -LocalRequirementsPath ""

.EXAMPLE
    # Merge an approved local requirements.txt, then process every group
    .\Update-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse" -LocalRequirementsPath "C:\WheelHouseManager\Input\requirements.txt"

.EXAMPLE
    # Urgent security fix published 2 days ago: skip the cooldown for this pin only
    .\Update-Wheelhouse.ps1 -ExpeditePackage requests==2.32.4 -ExpediteReason "CVE-2026-1234 fix"

.NOTES
    Start-MpScan (Defender scan) typically requires administrative privileges - deliberately
    NOT declared via #Requires -RunAsAdministrator, since the audit-only branch (nothing to
    download) doesn't need it at all; the script checks for and gracefully skips the Defender
    step instead of refusing to run entirely when not elevated.

    The work itself is Invoke-WheelhouseSync in the WheelhouseManager module. Only one
    update runs at a time (exit code 3 for a second one). The write lock that quarantine,
    restore and the scheduled check also need is held only while files change, so they can
    run during an update; every change is journaled and recorded in catalog.json and
    events.jsonl.
    Requires the WheelhouseManager module folder next to this script.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$WheelhousePath,

    [string]$LocalRequirementsPath,

    [ValidateNotNullOrEmpty()]
    [string]$PythonVersion,

    [ValidateNotNullOrEmpty()]
    [string]$Platform,

    [ValidateRange(0, 3650)]
    [int]$MinimumPackageAgeDays,

    [ValidateSet('osv', 'pypi')]
    [string[]]$VulnerabilityServices,

    [string[]]$ExpeditePackage,

    [string]$ExpediteReason,

    [ValidateSet('On', 'Off')]
    [string]$AutoQuarantine
)

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$cfg = Resolve-WheelhouseParameter -BoundParameters $PSBoundParameters `
    -Name WheelhousePath, LocalRequirementsPath, PythonVersion, Platform, MinimumPackageAgeDays, VulnerabilityServices, ReportRetentionMonths, DefenderScanAtIntake, RequireDefenderScanAtIntake, AutoQuarantine, DueDaysCritical, DueDaysHigh, DueDaysMedium, DueDaysLow, AuditFreshnessDays, ApprovalMode

$title = 'Wheelhouse maintenance script'
$outcome = $null
$exitCode = 0
$result = $null

try {
    $reportsFolder = Start-WheelhouseRun -WheelhousePath $cfg.WheelhousePath -Title $title -LogPrefix 'Log' -RetentionMonths $cfg.ReportRetentionMonths

    # Pins whose cooldown is skipped in this run - validated before anything else happens.
    $expedite = @{}
    foreach ($pin in @(ConvertTo-WheelhousePin -Pin $ExpeditePackage)) { $expedite[$pin.Name] = $pin.Version }
    if ($expedite.Count -gt 0) {
        if ([string]::IsNullOrWhiteSpace($ExpediteReason)) {
            throw '-ExpeditePackage needs -ExpediteReason: say why the cooldown is skipped.'
        }
        $user = if ($env:USERNAME) { $env:USERNAME } else { 'unknown' }
        Write-Log "Cooldown is skipped for $(($expedite.Keys | Sort-Object | ForEach-Object { "$_==$($expedite[$_])" }) -join ', ') - requested by $user. Reason: $ExpediteReason" 'WARN'
    }

    Confirm-PythonAndTooling

    $syncParams = @{
        WheelhousePath        = $cfg.WheelhousePath
        ReportsFolder         = $reportsFolder
        LocalRequirementsPath = $cfg.LocalRequirementsPath
        PythonVersion         = $cfg.PythonVersion
        Platform              = $cfg.Platform
        MinimumAgeDays        = $cfg.MinimumPackageAgeDays
        Services              = $cfg.VulnerabilityServices
        Expedite              = $expedite
        ExpediteReason        = [string]$ExpediteReason
        RequireDefenderScan   = [bool]$cfg.RequireDefenderScanAtIntake
        SkipDefenderScan      = -not (ConvertTo-WheelhouseBoolean $cfg.DefenderScanAtIntake)
        # -AutoQuarantine On|Off wins over the setting (a bool).
        AutoQuarantine        = ConvertTo-WheelhouseBoolean $cfg.AutoQuarantine
        ApprovalMode          = [string]$cfg.ApprovalMode
        DueDays               = Get-WheelhouseDueDayTable -Settings $cfg
        AuditFreshnessDays    = [int]$cfg.AuditFreshnessDays
    }
    $result = Invoke-WheelhouseSync @syncParams

    if ($result.Outcome -eq 'Error') {
        $exitCode = Get-WheelhouseExitCode -Outcome Error
        $outcome = 'an audit could not be completed'
    }
    elseif ($result.Outcome -eq 'Attention') {
        $exitCode = Get-WheelhouseExitCode -Outcome Attention
        $outcome = 'with failures'
    }
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    $exitCode = Get-WheelhouseExitCode -ErrorRecord $_
    $outcome = $(if ($exitCode -eq 3) { 'BUSY' } elseif ($_.Exception.Data['WheelhouseAwaitingApproval']) { 'WAITING FOR APPROVAL - nothing was published' } else { 'ABORTED' })
}
finally {
    Stop-WheelhouseRun -Title $title -Outcome $outcome -ExitCode $exitCode
}

if ($result) {
    $result.AuditResults
    $result.Notices
}
exit $exitCode
