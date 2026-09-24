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

      - For EACH group, the candidates - the planned new pins plus any pins the group
        already lists without a wheel in the wheelhouse - go through the vulnerability
        audit, the package-age (cooldown) check and the download, one package at a
        time as far as the outcome goes. A package that fails a step is rejected with
        the reason (log + Report_Rejected_<timestamp>.json) and never holds back the
        others. Only packages whose wheel was actually downloaded are written into the
        group file - a group file never lists a package that isn't in the wheelhouse.
        A rejected new package stays in the local requirements file and is simply
        tried again on the next run (e.g. once its cooldown has passed).

      - Every group that already existed is then audited as deployed (vulnerability
        check, no download).

      - Downloads use pip's --no-deps: group files come from `uv pip compile`, so every
        transitive dependency is already pinned in them and goes through the same
        audit and cooldown checks. Nothing unpinned is ever pulled in.

      - After all groups are processed, new wheel files are hashed and added to the
        manifest (existing entries are kept unchanged), and a single Microsoft Defender
        scan covers the whole wheelhouse folder.

    Writes one Wheelhouse.AuditResult object per audit to the output stream, so a
    caller (Invoke-WheelhousePipeline.ps1) can alert on exactly this run's findings.

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
    (default: 10). Applies only to new/changed packages.

.PARAMETER VulnerabilityServices
    pip-audit vulnerability service(s) to check (default: osv, pypi).

.EXAMPLE
    # Process existing group files only - no merge
    .\Update-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse" -LocalRequirementsPath ""

.EXAMPLE
    # Merge an approved local requirements.txt, then process every group
    .\Update-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse" -LocalRequirementsPath "C:\WheelHouseManager\Input\requirements.txt"

.NOTES
    Start-MpScan (Defender scan) typically requires administrative privileges - deliberately
    NOT declared via #Requires -RunAsAdministrator, since the audit-only branch (nothing to
    download) doesn't need it at all; the script checks for and gracefully skips the Defender
    step instead of refusing to run entirely when not elevated.
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
    [string[]]$VulnerabilityServices
)

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$cfg = Resolve-WheelhouseParameter -BoundParameters $PSBoundParameters `
    -Name WheelhousePath, LocalRequirementsPath, PythonVersion, Platform, MinimumPackageAgeDays, VulnerabilityServices, ReportRetentionMonths

$title = 'Wheelhouse maintenance script'
$outcome = $null
$exitCode = 0
$auditResults = [System.Collections.Generic.List[object]]::new()

try {
    $reportsFolder = Start-WheelhouseRun -WheelhousePath $cfg.WheelhousePath -Title $title -LogPrefix 'Log' -RetentionMonths $cfg.ReportRetentionMonths

    Confirm-PythonAndTooling

    # -----------------------------------------------------------------------
    # Step 1: manifest integrity check - must pass before anything else happens
    # -----------------------------------------------------------------------

    Write-Log "Loading manifest: $(Get-WheelhouseManifestPath -WheelhousePath $cfg.WheelhousePath)"
    $manifest = Read-WheelhouseManifest -WheelhousePath $cfg.WheelhousePath
    Write-Log "Manifest contains $($manifest.Count) tracked file(s)."

    if ($manifest.Count -eq 0) {
        Write-Log 'Manifest is empty - assuming first-time setup.' 'OK'
    }
    Assert-WheelhouseIntegrity -Manifest $manifest -WheelhousePath $cfg.WheelhousePath -ReportsFolder $reportsFolder

    # Snapshot taken after the integrity check: anything that appears after this
    # point was downloaded by this run.
    $preRunFiles = [string[]]@(Get-ChildItem -Path $cfg.WheelhousePath -Filter '*.whl' -File -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Name })

    # -----------------------------------------------------------------------
    # Step 2: plan the merge of local requirements - nothing is written yet
    # -----------------------------------------------------------------------

    [string[]]$groupFiles = Get-WheelhouseGroupFile -WheelhousePath $cfg.WheelhousePath
    $additionsByGroup = @{}

    $localPath = $cfg.LocalRequirementsPath
    $localPackages = @{}
    if (-not [string]::IsNullOrWhiteSpace($localPath) -and (Test-Path -Path $localPath)) {
        $localPackages = Read-RequirementFile -FilePath $localPath
    }

    if ($localPackages.Count -gt 0) {
        Write-Log "Planning merge of $($localPackages.Count) package(s) from local requirements: $localPath"
        $mergePlan = Get-RequirementMergePlan -LocalPackages $localPackages -GroupFiles $groupFiles -WheelhousePath $cfg.WheelhousePath

        foreach ($dup in $mergePlan.Duplicates) {
            Write-Log "  Already listed, skipped: $dup"
        }
        foreach ($add in $mergePlan.Additions) {
            $label = if ($add.IsNewGroup) { 'new group' } else { 'existing group' }
            Write-Log "  Candidate: $($add.Name)==$($add.Version) for $(Split-Path -Path $add.GroupFile -Leaf) ($label)"
            if (-not $additionsByGroup.ContainsKey($add.GroupFile)) { $additionsByGroup[$add.GroupFile] = @{} }
            $additionsByGroup[$add.GroupFile][$add.Name] = $add.Version
        }
        if ($mergePlan.Additions.Count -eq 0) {
            Write-Log 'Nothing new to merge - every local package is already listed in a group.' 'OK'
        }
        else {
            Write-Log 'Candidates are only written to their group file after passing the audit, the cooldown and the download.'
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($localPath)) {
        Write-Log "No local requirements to merge (file missing or empty): $localPath"
    }

    # Existing groups first, then planned new groups in number order.
    $targetGroups = @($groupFiles) + @($additionsByGroup.Keys | Where-Object { $groupFiles -notcontains $_ } |
            Sort-Object { Get-GroupFileNumber -Path $_ })
    if ($targetGroups.Count -eq 0) {
        Write-Log 'Run Update-Requirement.ps1 and re-run this script with -LocalRequirementsPath to create the first group.' 'ERROR'
        throw 'Wheelhouse has no requirement group files yet, and no local requirements were supplied to bootstrap one.'
    }
    Write-Log "Processing $($targetGroups.Count) requirement group file(s)."

    # -----------------------------------------------------------------------
    # Step 3: per group - take candidates through audit, cooldown and download,
    # write only the accepted ones, then audit the group as deployed
    # -----------------------------------------------------------------------

    $expectedPythonTag = 'cp' + ($cfg.PythonVersion -replace '\.', '')
    Write-Log "Target tag for matching: $expectedPythonTag / $($cfg.Platform)"

    $overallPassed = $true
    $anyDownloadHappened = $false
    $rejectedAll = [System.Collections.Generic.List[object]]::new()

    foreach ($groupFile in $targetGroups) {
        $groupName = [System.IO.Path]::GetFileNameWithoutExtension($groupFile)
        Write-Log "--- Group: $groupName ($groupFile) ---"

        $groupExisted = Test-Path -Path $groupFile
        $listed = if ($groupExisted) { Read-RequirementFile -FilePath $groupFile } else { @{} }
        $additions = if ($additionsByGroup.ContainsKey($groupFile)) { $additionsByGroup[$groupFile] } else { @{} }

        # Pins the group already lists but whose wheel is not in the wheelhouse yet
        # (e.g. a group file edited by hand, or left over from before this check existed).
        $missing = @{}
        if ($listed.Count -gt 0) {
            $compareParams = @{
                Required            = $listed
                Manifest            = $manifest
                ExpectedPythonTag   = $expectedPythonTag
                ExpectedPlatformTag = $cfg.Platform
            }
            $missing = (Compare-RequirementsAgainstManifest @compareParams).Packages
        }
        Write-Log "$($listed.Count) package(s) listed, $($missing.Count) of them without a wheel yet; $($additions.Count) new candidate(s)."

        $candidates = @{} + $missing
        foreach ($name in $additions.Keys) { $candidates[$name] = $additions[$name] }

        if ($candidates.Count -gt 0) {
            foreach ($name in ($candidates.Keys | Sort-Object)) {
                $kind = if ($additions.ContainsKey($name)) { 'new' } else { 'listed, no wheel yet' }
                Write-Log "  Candidate: $name==$($candidates[$name]) ($kind)" 'WARN'
            }

            $intakeParams = @{
                Packages       = $candidates
                GroupName      = $groupName
                WheelhousePath = $cfg.WheelhousePath
                ReportsFolder  = $reportsFolder
                Services       = $cfg.VulnerabilityServices
                MinimumAgeDays = $cfg.MinimumPackageAgeDays
                PythonVersion  = $cfg.PythonVersion
                Platform       = $cfg.Platform
            }
            $intake = Invoke-CandidateIntake @intakeParams
            foreach ($result in $intake.AuditResults) { $auditResults.Add($result) }

            if ($intake.Accepted.Count -gt 0) { $anyDownloadHappened = $true }
            foreach ($name in ($intake.Accepted.Keys | Sort-Object)) {
                if ($additions.ContainsKey($name)) {
                    Add-RequirementToGroupFile -GroupFile $groupFile -Name $name -Version $intake.Accepted[$name]
                    Write-Log "  Accepted and added to ${groupName}: $name==$($intake.Accepted[$name])" 'OK'
                }
                else {
                    Write-Log "  Accepted, wheel now downloaded: $name==$($intake.Accepted[$name])" 'OK'
                }
            }

            foreach ($item in $intake.Rejected) {
                if ($additions.ContainsKey($item.Name)) {
                    $action = "NOT added to $groupName - it stays in the local requirements file and is tried again next run"
                }
                else {
                    $action = "Still listed in $groupName without a wheel - fix or remove that line in the group file"
                }
                Write-Log "  Rejected: $($item.Name)==$($item.Version) - $($item.Reason) -> $action" 'ERROR'
                $rejectedAll.Add([PSCustomObject]@{
                        Group   = $groupName
                        Package = $item.Name
                        Version = $item.Version
                        Kind    = $(if ($additions.ContainsKey($item.Name)) { 'new' } else { 'listed' })
                        Reason  = $item.Reason
                    })
            }
            if ($intake.Rejected.Count -gt 0) { $overallPassed = $false }
        }

        # Audit what the group lists as deployed. A group created in this run holds
        # only packages that were just audited as candidates.
        if ($groupExisted -and $listed.Count -gt 0) {
            Write-Log "Auditing $groupName as deployed (no download)..."
            $groupResults = Invoke-GroupAudit -GroupFile $groupFile -Services $cfg.VulnerabilityServices -Stage 'Scheduled' -ReportsFolder $reportsFolder
            foreach ($result in $groupResults) { $auditResults.Add($result) }
            if ($groupResults | Where-Object { $_.Status -ne 'Passed' }) {
                Write-Log "$groupName has known vulnerabilities (or an incomplete audit) in listed packages." 'ERROR'
                $overallPassed = $false
            }
        }
    }

    if ($rejectedAll.Count -gt 0) {
        $rejectedReport = Join-Path $reportsFolder "Report_Rejected_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        Write-JsonFile -Path $rejectedReport -InputObject @($rejectedAll.ToArray()) -Depth 3
        Write-Log "$($rejectedAll.Count) package(s) were rejected this run - details: $rejectedReport" 'ERROR'
    }

    # -----------------------------------------------------------------------
    # Step 4: add this run's downloads to the manifest, then scan
    # -----------------------------------------------------------------------

    if ($anyDownloadHappened) {
        Write-Log "Updating manifest with this run's downloads..."
        $newManifest = Merge-WheelhouseManifest -WheelhousePath $cfg.WheelhousePath -Manifest $manifest -PreRunFiles $preRunFiles
        Save-WheelhouseManifest -Manifest $newManifest -WheelhousePath $cfg.WheelhousePath
        Write-Log "Manifest updated: $($newManifest.Count) tracked file(s) total ($($newManifest.Count - $manifest.Count) added)." 'OK'
    }
    else {
        Write-Log 'No downloads occurred this run - manifest left unchanged.'
    }

    Write-Log 'Starting Microsoft Defender scan on the wheelhouse folder...'
    if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
        try {
            Start-MpScan -ScanPath $cfg.WheelhousePath -ScanType CustomScan -ErrorAction Stop
            Write-Log 'Microsoft Defender scan completed.' 'OK'
        }
        catch {
            Write-Log "Microsoft Defender scan failed: $($_.Exception.Message)" 'ERROR'
        }
    }
    else {
        Write-Log 'Start-MpScan cmdlet is not available on this machine. Skipping Defender scan.' 'WARN'
    }

    if (-not $overallPassed) {
        $exitCode = 1
        $outcome = 'with failures'
    }
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    $exitCode = 1
    $outcome = 'ABORTED'
}
finally {
    Stop-WheelhouseRun -Title $title -Outcome $outcome
}

$auditResults.ToArray()
exit $exitCode
