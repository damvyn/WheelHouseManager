<#
.SYNOPSIS
    Server-side maintenance script for an offline uv/pip "wheelhouse" package repository,
    backed by a SHA256 manifest for integrity verification.

.DESCRIPTION
    Automatically picks the right mode - no flag needed:

      - Verifies wheelhouse integrity against manifest.json first (every tracked file's
        hash must still match). Any mismatch stops the script immediately.

      - If requirements.txt matches the manifest (correct versions and target tag present),
        runs a lightweight audit-only pass: vulnerability check, no download, no Defender scan.

      - If requirements.txt does NOT match the manifest (new/changed packages, or first-time
        setup), runs the full pipeline: vulnerability audit, package-age (cooldown) check,
        conditional download, manifest update, Microsoft Defender scan.

    The manifest tracks every wheel file in the wheelhouse (direct + transitive dependencies),
    with SHA256 hash, package name/version, and target Python/platform tag per file.

    Function definitions live in Wheelhouse-Common.ps1 (dot-sourced below) - this file
    contains only the main script logic.

.PARAMETER WheelhousePath
    UNC or local path to the network-shared Wheelhouse folder. Must contain requirements.txt.
    manifest.json is created/maintained automatically in the same folder.

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
    .\Update-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse"

.NOTES
    Start-MpScan (Defender scan) typically requires administrative privileges.
    Requires Wheelhouse-Common.ps1 in the same folder as this script.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$WheelhousePath,

    [string]$PythonVersion = "3.14",

    [string]$Platform = "win_amd64",

    [int]$MinimumPackageAgeDays = 10,

    [string[]]$VulnerabilityServices = @("osv", "pypi")
)

$commonPath = Join-Path $PSScriptRoot "Wheelhouse-Common.ps1"
if (-not (Test-Path -Path $commonPath)) {
    Write-Host "Required file not found: $commonPath" -ForegroundColor Red
    exit 1
}
. $commonPath

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

$requirementsPath = Join-Path $WheelhousePath "requirements.txt"
if (-not (Test-Path -Path $requirementsPath)) {
    Write-Log "requirements.txt was not found inside the wheelhouse folder: $requirementsPath" "ERROR"
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    exit 1
}
Write-Log "Found requirements file: $requirementsPath" "OK"

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
        Write-Log "Refusing to proceed with audit/download/scan until this is investigated manually." "ERROR"
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
# Step 2: compare requirements.txt against the manifest
# ---------------------------------------------------------------------------

Write-Log "Parsing requirements.txt..."
$requiredPackages = Get-RequirementsPackages -FilePath $requirementsPath
Write-Log "Found $($requiredPackages.Count) pinned package(s) in requirements.txt."

$expectedPythonTag = "cp" + ($PythonVersion -replace '\.', '')
Write-Log "Target tag for matching: $expectedPythonTag / $Platform"

$compareResult = Compare-RequirementsAgainstManifest -Required $requiredPackages -Manifest $manifest `
    -ExpectedPythonTag $expectedPythonTag -ExpectedPlatformTag $Platform
$isMatch = ($compareResult.Descriptions.Count -eq 0)

# ---------------------------------------------------------------------------
# Automatic mode decision:
#   isMatch = true  -> nothing new needed -> lightweight audit-only pass
#   isMatch = false -> full pipeline (audit + age check + download + manifest update + Defender)
# ---------------------------------------------------------------------------

if ($isMatch) {
    Write-Log "requirements.txt matches the manifest (correct versions and target tag present)." "OK"
    Write-Log "Running audit-only pass (no download, no Defender scan needed)."

    $allAuditsPassed = $true
    $anyVulnerabilityFound = $false
    foreach ($service in $VulnerabilityServices) {
        $result = Invoke-PipAudit -RequirementsFilePath $requirementsPath -ReportsFolderPath $reportsFolder -AuditName "Scheduled" -Service $service
        if (-not $result.Success) {
            $allAuditsPassed = $false
            $anyVulnerabilityFound = $true
        }
    }

    if ($anyVulnerabilityFound) {
        Show-PipAuditFixSuggestions -RequirementsFilePath $requirementsPath
        Write-Log "One or more audits found known vulnerabilities in packages already in the wheelhouse. Review the reports above." "ERROR"
    }
    else {
        Write-Log "Audit passed on all configured vulnerability services. No known vulnerabilities found." "OK"
    }

    Write-Log "=== Wheelhouse maintenance script finished ==="
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    exit ([int](-not $allAuditsPassed))
}

# --- Full pipeline (requirements.txt does not match the manifest) ---

Write-Log "requirements.txt does NOT match the manifest:" "WARN"
foreach ($item in $compareResult.Descriptions) {
    Write-Log "  - $item" "WARN"
}

$allAuditsPassed = $true
$anyVulnerabilityFound = $false
foreach ($service in $VulnerabilityServices) {
    $result = Invoke-PipAudit -RequirementsFilePath $requirementsPath -ReportsFolderPath $reportsFolder -AuditName "PreDownload" -Service $service
    if (-not $result.Success) {
        $allAuditsPassed = $false
        $anyVulnerabilityFound = $true
    }
}
if ($anyVulnerabilityFound) {
    Show-PipAuditFixSuggestions -RequirementsFilePath $requirementsPath
}

$ageCheckPassed = $true
if ($compareResult.Packages.Count -gt 0) {
    Write-Log "Checking minimum package age (cooldown: $MinimumPackageAgeDays day(s)) for new/changed packages..."
    $ageCheck = Test-PackageAge -Packages $compareResult.Packages -MinimumAgeDays $MinimumPackageAgeDays

    $ageReportFile = Join-Path $reportsFolder "Report_PackageAge_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $ageCheck.Results | ConvertTo-Json -Depth 5 | Out-File -FilePath $ageReportFile -Encoding utf8
    Write-Log "Package age report saved to: $ageReportFile"

    if ($ageCheck.TooNew.Count -gt 0) {
        $ageCheckPassed = $false
        Write-Log "The following package(s) do not yet satisfy the $MinimumPackageAgeDays-day cooldown:" "ERROR"
        foreach ($item in $ageCheck.TooNew) {
            Write-Log "  - $item" "ERROR"
        }
    }
    else {
        Write-Log "All new/changed packages satisfy the $MinimumPackageAgeDays-day cooldown." "OK"
    }
}

if ($allAuditsPassed -and $ageCheckPassed) {
    Write-Log "All audits passed and the cooldown period is satisfied. Proceeding to download..." "OK"
    & python -m pip download -r $requirementsPath -d $WheelhousePath `
        --python-version $PythonVersion `
        --platform $Platform `
        --implementation cp `
        --only-binary=:all:

    if ($LASTEXITCODE -eq 0) {
        Write-Log "Package download completed successfully." "OK"

        Write-Log "Rebuilding manifest from the full wheelhouse contents (including transitive dependencies)..."
        $manifest = New-FullManifest -WheelhousePath $WheelhousePath
        Save-Manifest -Manifest $manifest -ManifestPath $manifestPath
        Write-Log "Manifest updated: $manifestPath ($($manifest.Count) tracked file(s) total, direct + transitive)." "OK"
    }
    else {
        Write-Log "Package download FAILED. Review the pip output above. Manifest was NOT updated." "ERROR"
    }
}
else {
    if (-not $allAuditsPassed) {
        Write-Log "Download SKIPPED: one or more vulnerability audits did not pass." "ERROR"
    }
    if (-not $ageCheckPassed) {
        Write-Log "Download SKIPPED: one or more packages do not yet satisfy the $MinimumPackageAgeDays-day cooldown." "ERROR"
    }
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
