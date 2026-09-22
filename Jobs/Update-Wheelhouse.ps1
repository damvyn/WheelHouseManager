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
        content, its entries are merged into the wheelhouse's group files: an exact
        duplicate (same name==version already present anywhere) is skipped and logged;
        a genuinely new package name is added to the first group that doesn't already
        use that name; a name already pinned to a DIFFERENT version everywhere gets its
        own new group file. Nothing is ever downloaded from this merge step alone - it
        only updates the group files that the steps below then process.

      - For EACH group file: if it matches the manifest (correct versions and target
        tag present), runs a lightweight audit-only pass for that group (vulnerability
        check, no download). If it does NOT match (new/changed packages in that group,
        or a first-time group), runs the full pipeline for that group: vulnerability
        audit, package-age (cooldown) check, conditional download.

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
    # Step 2: merge local requirements (if any) into the wheelhouse's group files
    # -----------------------------------------------------------------------

    $groupFiles = Get-WheelhouseGroupFile -WheelhousePath $cfg.WheelhousePath

    $localPath = $cfg.LocalRequirementsPath
    $localPackages = @{}
    if (-not [string]::IsNullOrWhiteSpace($localPath) -and (Test-Path -Path $localPath)) {
        $localPackages = Read-RequirementFile -FilePath $localPath
    }

    if ($localPackages.Count -gt 0) {
        Write-Log "Merging $($localPackages.Count) package(s) from local requirements: $localPath"
        $mergePlan = Get-RequirementMergePlan -LocalPackages $localPackages -GroupFiles $groupFiles -WheelhousePath $cfg.WheelhousePath

        foreach ($dup in $mergePlan.Duplicates) {
            Write-Log "  Duplicate, skipped: $dup"
        }
        foreach ($add in $mergePlan.Additions) {
            $label = if ($add.IsNewGroup) { 'new group' } else { 'existing group' }
            Write-Log "  Adding $($add.Name)==$($add.Version) to $(Split-Path -Path $add.GroupFile -Leaf) ($label)" 'OK'
            Add-RequirementToGroupFile -GroupFile $add.GroupFile -Name $add.Name -Version $add.Version
        }
        if ($mergePlan.Additions.Count -eq 0) {
            Write-Log 'Nothing new to merge - every local package was already present.' 'OK'
        }

        # Re-scan: a brand new group file may have been created above.
        $groupFiles = Get-WheelhouseGroupFile -WheelhousePath $cfg.WheelhousePath
    }
    elseif (-not [string]::IsNullOrWhiteSpace($localPath)) {
        Write-Log "No local requirements to merge (file missing or empty): $localPath"
    }

    if ($groupFiles.Count -eq 0) {
        Write-Log 'Run Update-Requirement.ps1 and re-run this script with -LocalRequirementsPath to create the first group.' 'ERROR'
        throw 'Wheelhouse has no requirement group files yet, and no local requirements were supplied to bootstrap one.'
    }
    Write-Log "Processing $($groupFiles.Count) requirement group file(s)."

    # -----------------------------------------------------------------------
    # Step 3: process each group file - compare, audit, cooldown, download
    # -----------------------------------------------------------------------

    $expectedPythonTag = 'cp' + ($cfg.PythonVersion -replace '\.', '')
    Write-Log "Target tag for matching: $expectedPythonTag / $($cfg.Platform)"

    $overallPassed = $true
    $anyDownloadHappened = $false

    foreach ($groupFile in $groupFiles) {
        $groupName = [System.IO.Path]::GetFileNameWithoutExtension($groupFile)
        Write-Log "--- Group: $groupName ($groupFile) ---"

        $requiredPackages = Read-RequirementFile -FilePath $groupFile
        Write-Log "Found $($requiredPackages.Count) pinned package(s) in this group."

        $compareParams = @{
            Required            = $requiredPackages
            Manifest            = $manifest
            ExpectedPythonTag   = $expectedPythonTag
            ExpectedPlatformTag = $cfg.Platform
        }
        $compareResult = Compare-RequirementsAgainstManifest @compareParams
        $isMatch = ($compareResult.Descriptions.Count -eq 0)

        if ($isMatch) {
            Write-Log "$groupName matches the manifest. Running audit-only pass (no download)." 'OK'
            $stage = 'Scheduled'
        }
        else {
            Write-Log "$groupName does NOT match the manifest:" 'WARN'
            foreach ($item in $compareResult.Descriptions) {
                Write-Log "  - $item" 'WARN'
            }
            $stage = 'PreDownload'
        }

        $groupResults = Invoke-GroupAudit -GroupFile $groupFile -Services $cfg.VulnerabilityServices -Stage $stage -ReportsFolder $reportsFolder
        foreach ($result in $groupResults) { $auditResults.Add($result) }
        $auditsPassed = -not ($groupResults | Where-Object { $_.Status -ne 'Passed' })

        if ($isMatch) {
            if (-not $auditsPassed) {
                Write-Log "$groupName has known vulnerabilities (or an incomplete audit) in already-deployed packages." 'ERROR'
                $overallPassed = $false
            }
            continue
        }

        $ageCheckPassed = $true
        if ($compareResult.Packages.Count -gt 0) {
            Write-Log "Checking minimum package age (cooldown: $($cfg.MinimumPackageAgeDays) day(s)) for $groupName..."
            $ageCheck = Test-PackageAge -Packages $compareResult.Packages -MinimumAgeDays $cfg.MinimumPackageAgeDays

            $ageReportFile = Join-Path $reportsFolder "Report_PackageAge-$($groupName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            Write-JsonFile -Path $ageReportFile -InputObject @($ageCheck.Results) -Depth 5
            Write-Log "Package age report saved to: $ageReportFile"

            if ($ageCheck.TooNew.Count -gt 0) {
                $ageCheckPassed = $false
                Write-Log "The following package(s) in $groupName do not yet satisfy the $($cfg.MinimumPackageAgeDays)-day cooldown:" 'ERROR'
                foreach ($item in $ageCheck.TooNew) {
                    Write-Log "  - $item" 'ERROR'
                }
            }
            else {
                Write-Log "All new/changed packages in $groupName satisfy the $($cfg.MinimumPackageAgeDays)-day cooldown." 'OK'
            }
        }

        if (-not ($auditsPassed -and $ageCheckPassed)) {
            if (-not $auditsPassed) {
                Write-Log "${groupName}: download SKIPPED - one or more vulnerability audits did not pass." 'ERROR'
            }
            if (-not $ageCheckPassed) {
                Write-Log "${groupName}: download SKIPPED - one or more packages do not yet satisfy the cooldown." 'ERROR'
            }
            $overallPassed = $false
            continue
        }

        Write-Log "${groupName}: audits passed and cooldown satisfied. Downloading..." 'OK'
        $pipDownloadArgs = @(
            '-m', 'pip', 'download',
            '-r', $groupFile,
            '-d', $cfg.WheelhousePath,
            '--python-version', $cfg.PythonVersion,
            '--platform', $cfg.Platform,
            '--implementation', 'cp',
            '--only-binary=:all:',
            '--no-deps'
        )
        & python @pipDownloadArgs | Out-Host

        if ($LASTEXITCODE -eq 0) {
            Write-Log "${groupName}: download completed successfully." 'OK'
            $anyDownloadHappened = $true
        }
        else {
            Write-Log "${groupName}: download FAILED. Review the pip output above." 'ERROR'
            $overallPassed = $false
        }
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
