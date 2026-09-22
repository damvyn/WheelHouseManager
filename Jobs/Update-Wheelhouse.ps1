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

      - If -LocalRequirementsPath is supplied (or resolves via config\settings.psd1/
        the manager's Input\ folder) and has content, its entries are merged into the
        wheelhouse's group files first: an exact duplicate (same name==version already
        present anywhere) is skipped and logged; a genuinely new package name is added
        to the first group that doesn't already use that name; a name already pinned to
        a DIFFERENT version everywhere gets its own new group file. Nothing is ever
        downloaded from this merge step alone - it only updates the group files that
        the steps below then process.

      - Verifies wheelhouse integrity against manifest.json first (every tracked file's
        hash must still match, across the whole wheelhouse). Any mismatch stops the
        script immediately, before any merge or per-group processing happens.

      - For EACH group file: if it matches the manifest (correct versions and target
        tag present), runs a lightweight audit-only pass for that group (vulnerability
        check, no download). If it does NOT match (new/changed packages in that group,
        or a first-time group), runs the full pipeline for that group: vulnerability
        audit, package-age (cooldown) check, conditional download.

      - After all groups are processed, the manifest is rebuilt once from the full
        wheelhouse contents (direct + transitive dependencies across every group), and
        a single Microsoft Defender scan covers the whole wheelhouse folder.

    The manifest tracks every wheel file in the wheelhouse (direct + transitive dependencies),
    with SHA256 hash, package name/version, and target Python/platform tag per file.

    Function definitions live in functions.ps1 (dot-sourced below) - this file
    contains only the main script logic.

.PARAMETER WheelhousePath
    UNC or local path to the network-shared Wheelhouse folder.
    manifest.json and the requirements-N.txt group files are created/maintained
    automatically in the same folder. Optional if already set in config\settings.psd1
    (one level up from this script) - falls back to that value, and errors out if
    neither is set.

.PARAMETER LocalRequirementsPath
    A locally-resolved requirements.txt (typically produced by Update-Requirement.ps1)
    whose entries get merged into the wheelhouse's group files before processing.
    Defaults to config\settings.psd1's LocalRequirementsPath (itself defaulting to
    Input\requirements.txt under the manager root, set by Setup.ps1). If that file is
    missing or empty, no merge happens - the script just processes the wheelhouse's
    existing group files as-is. Pass an explicit empty string ("") to force-skip the
    merge even if settings.psd1 has a value set.

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
    .\Update-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse"

.EXAMPLE
    # Merge an approved local requirements.txt, then process every group
    .\Update-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse" -LocalRequirementsPath "C:\WheelHouseManager\Input\requirements.txt"

.NOTES
    Start-MpScan (Defender scan) typically requires administrative privileges - deliberately
    NOT declared via #Requires -RunAsAdministrator, since the audit-only branch (nothing to
    download) doesn't need it at all; the script checks for and gracefully skips the Defender
    step instead of refusing to run entirely when not elevated.
    Requires functions.ps1 in the same folder as this script.
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

    [ValidateSet("osv", "pypi")]
    [string[]]$VulnerabilityServices
)

$commonPath = Join-Path $PSScriptRoot "functions.ps1"
if (-not (Test-Path -Path $commonPath)) {
    Write-Host "Required file not found: $commonPath" -ForegroundColor Red
    exit 1
}
. $commonPath

# Resolve every optional parameter: explicit -Parameter wins, then config\settings.psd1
# (one level up from Jobs\), then this script's own hardcoded fallback.
$managerRoot = Split-Path -Path $PSScriptRoot -Parent
$settingsPath = Join-Path $managerRoot "config\settings.psd1"
$settings = Get-WheelhouseSettings -SettingsPath $settingsPath

$WheelhousePath = Resolve-Setting -Name "WheelhousePath" -ExplicitValue $WheelhousePath `
    -WasBound $PSBoundParameters.ContainsKey('WheelhousePath') -Settings $settings -FallbackDefault $null
# No default for LocalRequirementsPath - merging is opt-in only (see .PARAMETER above).
$LocalRequirementsPath = Resolve-Setting -Name "LocalRequirementsPath" -ExplicitValue $LocalRequirementsPath `
    -WasBound $PSBoundParameters.ContainsKey('LocalRequirementsPath') -Settings $settings -FallbackDefault $null
$PythonVersion = Resolve-Setting -Name "PythonVersion" -ExplicitValue $PythonVersion `
    -WasBound $PSBoundParameters.ContainsKey('PythonVersion') -Settings $settings -FallbackDefault "3.14"
$Platform = Resolve-Setting -Name "Platform" -ExplicitValue $Platform `
    -WasBound $PSBoundParameters.ContainsKey('Platform') -Settings $settings -FallbackDefault "win_amd64"
$MinimumPackageAgeDays = Resolve-Setting -Name "MinimumPackageAgeDays" -ExplicitValue $MinimumPackageAgeDays `
    -WasBound $PSBoundParameters.ContainsKey('MinimumPackageAgeDays') -Settings $settings -FallbackDefault 10
$VulnerabilityServices = Resolve-Setting -Name "VulnerabilityServices" -ExplicitValue $VulnerabilityServices `
    -WasBound $PSBoundParameters.ContainsKey('VulnerabilityServices') -Settings $settings -FallbackDefault @("osv", "pypi")

if ([string]::IsNullOrWhiteSpace($WheelhousePath)) {
    Write-Log "WheelhousePath was not supplied and is not set in config\settings.psd1. Pass -WheelhousePath, or run Setup.ps1 with -WheelhousePath first." "ERROR"
    exit 1
}

# ---------------------------------------------------------------------------
# Main script
# ---------------------------------------------------------------------------

Write-Log "=== Wheelhouse maintenance script started ==="
Write-Log "Wheelhouse path: $WheelhousePath"

if (-not (Test-Path -Path $WheelhousePath)) {
    Write-Log "Wheelhouse path does not exist or is not reachable: $WheelhousePath" "ERROR"
    exit 1
}

# Reports folder + transcript set up as early as possible, before any check
# that could exit early.
$reportsFolder = Join-Path $WheelhousePath "reports"
if (-not (Test-Path -Path $reportsFolder)) {
    New-Item -ItemType Directory -Path $reportsFolder -Force | Out-Null
    Write-Log "Created reports folder: $reportsFolder"
}

$logFile = Join-Path $reportsFolder "Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
try {
    Start-Transcript -Path $logFile -Append | Out-Null
    Write-Log "Full console output for this run is also being saved to: $logFile"
}
catch {
    Write-Log "Could not start transcript logging to $logFile - continuing with console output only. ($($_.Exception.Message))" "WARN"
}

# Remove transcript logs older than 6 months. Report_*.json (audit/age/integrity
# results) are left alone.
$logRetentionCutoff = (Get-Date).AddMonths(-6)
$oldLogs = @(Get-ChildItem -Path $reportsFolder -Filter "Log_*.txt" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt $logRetentionCutoff })
if ($oldLogs.Count -gt 0) {
    Write-Log "Removing $($oldLogs.Count) log file(s) older than 6 months..."
    foreach ($oldLog in $oldLogs) {
        try {
            Remove-Item -Path $oldLog.FullName -Force
        }
        catch {
            Write-Log "Could not remove old log file '$($oldLog.Name)': $($_.Exception.Message)" "WARN"
        }
    }
}

Confirm-PythonAndTooling

$manifestPath = Join-Path $WheelhousePath "manifest.json"

# ---------------------------------------------------------------------------
# Step 1: manifest integrity check - must pass before anything else happens
# ---------------------------------------------------------------------------

Write-Log "Loading manifest: $manifestPath"

# Read the manifest directly here (no function boundary) to keep array handling simple.
$parseError = Get-ManifestParseError -ManifestPath $manifestPath
if ($null -ne $parseError) {
    Write-Log "manifest.json exists but could not be parsed: $parseError" "ERROR"
    Write-Log "manifest.json is unreadable/corrupted. Refusing to continue until this is resolved manually." "ERROR"
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    exit 1
}

$manifest = @()
if (Test-Path -Path $manifestPath) {
    $manifestContent = Get-Content -Path $manifestPath -Raw -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace($manifestContent)) {
        foreach ($entry in (ConvertFrom-Json -InputObject $manifestContent)) {
            $manifest += $entry
        }
    }
}
Write-Log "Manifest contains $($manifest.Count) tracked file(s)."

if ($manifest.Count -gt 0) {
    Write-Log "Verifying wheelhouse integrity against manifest..."
    $integrityProblems = Test-ManifestIntegrity -Manifest $manifest -WheelhousePath $WheelhousePath

    if ($integrityProblems.Count -gt 0) {
        $integrityReportFile = Join-Path $reportsFolder "Report_Integrity_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $integrityProblems | ConvertTo-Json -Depth 3 | Out-File -FilePath $integrityReportFile -Encoding utf8

        Write-Log "WHEELHOUSE INTEGRITY CHECK FAILED. The following problem(s) were found:" "ERROR"
        foreach ($item in $integrityProblems) {
            Write-Log "  - $item" "ERROR"
        }
        Write-Log "Integrity report saved to: $integrityReportFile" "ERROR"
        Write-Log "Refusing to proceed with merge/audit/download/scan until this is investigated manually." "ERROR"
        Write-Log "=== Wheelhouse maintenance script finished (ABORTED - integrity check failed) ==="
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
        exit 1
    }
    Write-Log "Wheelhouse integrity check passed. All tracked files match their recorded hash." "OK"
}
else {
    Write-Log "Manifest is empty - assuming first-time setup." "OK"
}

# ---------------------------------------------------------------------------
# Step 2: merge local requirements (if any) into the wheelhouse's group files
# ---------------------------------------------------------------------------

$groupFiles = Get-WheelhouseRequirementGroups -WheelhousePath $WheelhousePath

$hasLocalRequirements = (-not [string]::IsNullOrWhiteSpace($LocalRequirementsPath)) -and (Test-Path -Path $LocalRequirementsPath)
if ($hasLocalRequirements) {
    $localPackages = Get-RequirementsPackages -FilePath $LocalRequirementsPath
}
else {
    $localPackages = @{}
}

if ($localPackages.Count -gt 0) {
    Write-Log "Merging $($localPackages.Count) package(s) from local requirements: $LocalRequirementsPath"
    $mergeResult = Merge-LocalRequirements -LocalPackages $localPackages -GroupFiles $groupFiles -WheelhousePath $WheelhousePath

    foreach ($dup in $mergeResult.Duplicates) {
        Write-Log "  Duplicate, skipped: $dup"
    }
    foreach ($add in $mergeResult.Additions) {
        $label = if ($add.IsNewGroup) { "new group" } else { "existing group" }
        Write-Log "  Adding $($add.Name)==$($add.Version) to $(Split-Path -Path $add.GroupFile -Leaf) ($label)" "OK"
        Add-RequirementToGroupFile -GroupFile $add.GroupFile -Name $add.Name -Version $add.Version -IsNewGroup $add.IsNewGroup
    }

    if ($mergeResult.Additions.Count -eq 0) {
        Write-Log "Nothing new to merge - every local package was already present." "OK"
    }

    # Re-scan: a brand new group file may have been created above.
    $groupFiles = Get-WheelhouseRequirementGroups -WheelhousePath $WheelhousePath
}
elseif (-not [string]::IsNullOrWhiteSpace($LocalRequirementsPath)) {
    Write-Log "No local requirements to merge (file missing or empty): $LocalRequirementsPath"
}

if ($groupFiles.Count -eq 0) {
    Write-Log "Wheelhouse has no requirement group files yet, and no local requirements were supplied to bootstrap one." "ERROR"
    Write-Log "Run Update-Requirement.ps1 and re-run this script with -LocalRequirementsPath to create the first group." "ERROR"
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    exit 1
}
Write-Log "Processing $($groupFiles.Count) requirement group file(s)."

# ---------------------------------------------------------------------------
# Step 3: process each group file - compare, audit, cooldown, download
# ---------------------------------------------------------------------------

$expectedPythonTag = "cp" + ($PythonVersion -replace '\.', '')
Write-Log "Target tag for matching: $expectedPythonTag / $Platform"

$overallAuditsPassed = $true
$anyDownloadHappened = $false

foreach ($groupFile in $groupFiles) {
    $groupName = [System.IO.Path]::GetFileNameWithoutExtension($groupFile)
    Write-Log "--- Group: $groupName ($groupFile) ---"

    $requiredPackages = Get-RequirementsPackages -FilePath $groupFile
    Write-Log "Found $($requiredPackages.Count) pinned package(s) in this group."

    $compareParams = @{
        Required            = $requiredPackages
        Manifest            = $manifest
        ExpectedPythonTag   = $expectedPythonTag
        ExpectedPlatformTag = $Platform
    }
    $compareResult = Compare-RequirementsAgainstManifest @compareParams
    $isMatch = ($compareResult.Descriptions.Count -eq 0)

    if ($isMatch) {
        Write-Log "$groupName matches the manifest. Running audit-only pass (no download)." "OK"

        $allAuditsPassed = $true
        $anyVulnerabilityFound = $false
        foreach ($service in $VulnerabilityServices) {
            $result = Invoke-PipAudit -RequirementsFilePath $groupFile -ReportsFolderPath $reportsFolder -AuditName "Scheduled-$groupName" -Service $service
            if (-not $result.Success) {
                $allAuditsPassed = $false
                $anyVulnerabilityFound = $true
            }
        }
        if ($anyVulnerabilityFound) {
            Show-PipAuditFixSuggestions -RequirementsFilePath $groupFile
            Write-Log "$groupName has known vulnerabilities in one or more already-deployed packages." "ERROR"
        }
        if (-not $allAuditsPassed) { $overallAuditsPassed = $false }
        continue
    }

    Write-Log "$groupName does NOT match the manifest:" "WARN"
    foreach ($item in $compareResult.Descriptions) {
        Write-Log "  - $item" "WARN"
    }

    $allAuditsPassed = $true
    $anyVulnerabilityFound = $false
    foreach ($service in $VulnerabilityServices) {
        $result = Invoke-PipAudit -RequirementsFilePath $groupFile -ReportsFolderPath $reportsFolder -AuditName "PreDownload-$groupName" -Service $service
        if (-not $result.Success) {
            $allAuditsPassed = $false
            $anyVulnerabilityFound = $true
        }
    }
    if ($anyVulnerabilityFound) {
        Show-PipAuditFixSuggestions -RequirementsFilePath $groupFile
    }

    $ageCheckPassed = $true
    if ($compareResult.Packages.Count -gt 0) {
        Write-Log "Checking minimum package age (cooldown: $MinimumPackageAgeDays day(s)) for $groupName..."
        $ageCheck = Test-PackageAge -Packages $compareResult.Packages -MinimumAgeDays $MinimumPackageAgeDays

        $ageReportFile = Join-Path $reportsFolder "Report_PackageAge-$groupName`_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $ageCheck.Results | ConvertTo-Json -Depth 5 | Out-File -FilePath $ageReportFile -Encoding utf8
        Write-Log "Package age report saved to: $ageReportFile"

        if ($ageCheck.TooNew.Count -gt 0) {
            $ageCheckPassed = $false
            Write-Log "The following package(s) in $groupName do not yet satisfy the $MinimumPackageAgeDays-day cooldown:" "ERROR"
            foreach ($item in $ageCheck.TooNew) {
                Write-Log "  - $item" "ERROR"
            }
        }
        else {
            Write-Log "All new/changed packages in $groupName satisfy the $MinimumPackageAgeDays-day cooldown." "OK"
        }
    }

    if ($allAuditsPassed -and $ageCheckPassed) {
        Write-Log "${groupName}: audits passed and cooldown satisfied. Downloading..." "OK"
        $pipDownloadArgs = @(
            "-m", "pip", "download",
            "-r", $groupFile,
            "-d", $WheelhousePath,
            "--python-version", $PythonVersion,
            "--platform", $Platform,
            "--implementation", "cp",
            "--only-binary=:all:"
        )
        & python @pipDownloadArgs

        if ($LASTEXITCODE -eq 0) {
            Write-Log "${groupName}: download completed successfully." "OK"
            $anyDownloadHappened = $true
        }
        else {
            Write-Log "${groupName}: download FAILED. Review the pip output above." "ERROR"
            $overallAuditsPassed = $false
        }
    }
    else {
        if (-not $allAuditsPassed) {
            Write-Log "${groupName}: download SKIPPED - one or more vulnerability audits did not pass." "ERROR"
        }
        if (-not $ageCheckPassed) {
            Write-Log "${groupName}: download SKIPPED - one or more packages do not yet satisfy the cooldown." "ERROR"
        }
        $overallAuditsPassed = $false
    }
}

# ---------------------------------------------------------------------------
# Step 4: rebuild the manifest once (covers every group's downloads) and scan
# ---------------------------------------------------------------------------

if ($anyDownloadHappened) {
    Write-Log "Rebuilding manifest from the full wheelhouse contents (including transitive dependencies)..."
    $manifest = New-FullManifest -WheelhousePath $WheelhousePath
    Save-Manifest -Manifest $manifest -ManifestPath $manifestPath
    Write-Log "Manifest updated: $manifestPath ($($manifest.Count) tracked file(s) total, direct + transitive)." "OK"
}
else {
    Write-Log "No downloads occurred this run - manifest left unchanged."
}

Write-Log "Starting Microsoft Defender scan on the wheelhouse folder..."
if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
    try {
        Start-MpScan -ScanPath $WheelhousePath -ScanType CustomScan
        Write-Log "Microsoft Defender scan completed." "OK"
    }
    catch {
        Write-Log "Microsoft Defender scan failed: $($_.Exception.Message)" "ERROR"
    }
}
else {
    Write-Log "Start-MpScan cmdlet is not available on this machine. Skipping Defender scan." "WARN"
}

Write-Log "=== Wheelhouse maintenance script finished ==="
Stop-Transcript -ErrorAction SilentlyContinue | Out-Null

if (-not $overallAuditsPassed) { exit 1 }
exit 0
