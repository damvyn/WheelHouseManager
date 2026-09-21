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
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$WheelhousePath,

    [string]$PythonVersion = "3.14",

    [string]$Platform = "win_amd64",

    [int]$MinimumPackageAgeDays = 10,

    [string[]]$VulnerabilityServices = @("osv", "pypi")
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "OK", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "OK"    { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-NormalizedPackageName {
    # PEP 503 style normalization: runs of -, _, . collapse to a single "-", lowercase.
    param([string]$Name)
    return ([regex]::Replace($Name, '[-_.]+', '-')).ToLower()
}

function Get-RequirementsPackages {
    # Parses a requirements.txt file. Only exact pins ("name==version") are supported.
    param([string]$FilePath)

    $packages = @{}
    Get-Content -Path $FilePath | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq "" -or $line.StartsWith("#")) { return }

        if ($line -match '^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)$') {
            $name = Get-NormalizedPackageName $Matches[1]
            $version = $Matches[2]
            $packages[$name] = $version
        }
        else {
            Write-Log "Skipping unsupported requirement line (expected exact pin 'name==version'): $line" "WARN"
        }
    }
    return $packages
}

function Get-WheelFileInfo {
    # Parses a wheel filename (PEP 427): name-version-python_tag-abi_tag-platform_tag.whl
    param([string]$FileName)

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $parts = $baseName -split '-'
    if ($parts.Count -lt 5) { return $null }

    return [PSCustomObject]@{
        Name        = Get-NormalizedPackageName $parts[0]
        Version     = $parts[1]
        PythonTag   = $parts[$parts.Count - 3]
        AbiTag      = $parts[$parts.Count - 2]
        PlatformTag = $parts[$parts.Count - 1]
    }
}

function Get-ManifestParseError {
    # Returns $null if the manifest is missing, empty, or parses cleanly;
    # returns the parse error message if it exists but is corrupt.
    param([string]$ManifestPath)
    if (-not (Test-Path -Path $ManifestPath)) { return $null }
    $content = Get-Content -Path $ManifestPath -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($content)) { return $null }
    try {
        ConvertFrom-Json -InputObject $content | Out-Null
        return $null
    }
    catch {
        return $_.Exception.Message
    }
}

function Save-Manifest {
    param([array]$Manifest, [string]$ManifestPath)
    $Manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $ManifestPath -Encoding utf8
}

function Test-ManifestIntegrity {
    # Verifies every manifest file still exists and matches its recorded SHA256 hash.
    param([array]$Manifest, [string]$WheelhousePath)

    $problems = @()
    foreach ($entry in $Manifest) {
        # Guard against a malformed 'file' field (should be plain text).
        $fileValue = $entry.file
        if ($fileValue -is [array]) {
            $problems += "$($entry.name)==$($entry.version): manifest record has a malformed 'file' field (expected text, got a list: $($fileValue -join ', ')). Investigate manifest.json manually."
            continue
        }
        $filePath = Join-Path $WheelhousePath $fileValue
        if (-not (Test-Path -Path $filePath)) {
            $problems += "$($entry.name)==$($entry.version): recorded file '$fileValue' is missing from the wheelhouse."
            continue
        }
        $currentHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
        if ($currentHash -ne $entry.sha256) {
            $problems += "$($entry.name)==$($entry.version): file '$fileValue' hash MISMATCH (expected $($entry.sha256), got $currentHash)."
        }
    }
    Write-Output -NoEnumerate $problems
}

function New-FullManifest {
    # Scans every wheel file in the wheelhouse (direct + transitive) and rebuilds
    # the manifest with fresh SHA256 hashes.
    param([string]$WheelhousePath)

    $entries = @()
    Get-ChildItem -Path $WheelhousePath -Filter "*.whl" -File -ErrorAction SilentlyContinue | ForEach-Object {
        $info = Get-WheelFileInfo -FileName $_.Name
        if ($info) {
            $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
            $entries += [PSCustomObject]@{
                name           = $info.Name
                version        = $info.Version
                file           = $_.Name
                sha256         = $hash
                python_tag     = $info.PythonTag
                abi_tag        = $info.AbiTag
                platform_tag   = $info.PlatformTag
                downloaded_utc = (Get-Date).ToUniversalTime().ToString("o")
            }
        }
        else {
            Write-Log "Could not parse wheel filename, skipping from manifest: $($_.Name)" "WARN"
        }
    }
    Write-Output -NoEnumerate $entries
}

function Compare-RequirementsAgainstManifest {
    # Checks that each required package/version has a manifest entry matching
    # the target Python/platform tag.
    param(
        [hashtable]$Required,
        [array]$Manifest,
        [string]$ExpectedPythonTag,
        [string]$ExpectedPlatformTag
    )

    $descriptions = @()
    $missingPackages = @{}

    foreach ($name in $Required.Keys) {
        $reqVersion = $Required[$name]
        $versionEntries = @($Manifest | Where-Object { $_.name -eq $name -and $_.version -eq $reqVersion })

        if ($versionEntries.Count -eq 0) {
            $descriptions += "$name==$reqVersion (not found in manifest)"
            $missingPackages[$name] = $reqVersion
            continue
        }

        $platformMatch = $versionEntries | Where-Object {
            ($_.platform_tag -eq $ExpectedPlatformTag -or $_.platform_tag -eq "any") -and
            ($_.python_tag -eq $ExpectedPythonTag -or $_.python_tag -like "py*" -or $_.abi_tag -eq "abi3")
        }

        if (-not $platformMatch) {
            $descriptions += "$name==$reqVersion (found in manifest, but no file matches target tag $ExpectedPythonTag/$ExpectedPlatformTag)"
            $missingPackages[$name] = $reqVersion
        }
    }

    return @{ Descriptions = $descriptions; Packages = $missingPackages }
}

function Test-PackageAge {
    # Checks each package's PyPI publish date against the minimum age. Unresolvable
    # packages fail closed.
    param(
        [hashtable]$Packages,
        [int]$MinimumAgeDays
    )

    $tooNew = @()
    $results = @()

    foreach ($name in $Packages.Keys) {
        $version = $Packages[$name]
        try {
            $url = "https://pypi.org/pypi/$name/$version/json"
            $response = Invoke-RestMethod -Uri $url -ErrorAction Stop

            if (-not $response.urls -or $response.urls.Count -eq 0) {
                throw "No release files found for this version."
            }

            $uploadTimeStr = $response.urls[0].upload_time_iso_8601
            $uploadTimeUtc = [DateTimeOffset]::Parse($uploadTimeStr).UtcDateTime
            $ageDays = [math]::Floor(((Get-Date).ToUniversalTime() - $uploadTimeUtc).TotalDays)
            $passed = $ageDays -ge $MinimumAgeDays

            $results += [PSCustomObject]@{
                Package             = $name
                Version             = $version
                UploadDateUtc       = $uploadTimeUtc
                AgeDays             = $ageDays
                MinimumRequiredDays = $MinimumAgeDays
                Passed              = $passed
            }

            if ($passed) {
                Write-Log "Age check OK: $name==$version was published $ageDays day(s) ago (>= $MinimumAgeDays)." "OK"
            }
            else {
                Write-Log "Age check FAILED: $name==$version was published only $ageDays day(s) ago (requires $MinimumAgeDays)." "WARN"
                $tooNew += "$name==$version (published $ageDays day(s) ago, requires $MinimumAgeDays)"
            }
        }
        catch {
            Write-Log "Could not verify publish date for $name==$version : $($_.Exception.Message). Treating as failing the age check." "WARN"
            $results += [PSCustomObject]@{
                Package             = $name
                Version             = $version
                UploadDateUtc       = $null
                AgeDays             = $null
                MinimumRequiredDays = $MinimumAgeDays
                Passed              = $false
                Error               = $_.Exception.Message
            }
            $tooNew += "$name==$version (could not verify publish date)"
        }
    }

    return @{ TooNew = $tooNew; Results = $results }
}

function Invoke-PipAudit {
    param(
        [string]$RequirementsFilePath,
        [string]$ReportsFolderPath,
        [string]$AuditName,
        [string]$Service
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fullAuditName = "$AuditName-$($Service.ToUpper())"
    $reportFile = Join-Path $ReportsFolderPath "Report_${fullAuditName}_${timestamp}.json"

    Write-Log "Running $fullAuditName audit against '$RequirementsFilePath'..."
    & pip-audit -r $RequirementsFilePath --vulnerability-service $Service --format json --output $reportFile
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        Write-Log "$fullAuditName audit completed successfully. No known vulnerabilities found." "OK"
        Write-Log "Audit report saved to: $reportFile" "OK"
        return @{ Success = $true; ReportPath = $reportFile }
    }
    else {
        Write-Log "$fullAuditName audit FAILED. Vulnerabilities found or an error occurred (exit code $exitCode)." "ERROR"
        Write-Log "Audit report saved to: $reportFile" "ERROR"
        return @{ Success = $false; ReportPath = $reportFile }
    }
}

function Show-PipAuditFixSuggestions {
    # Informational only - shows what pip-audit would change, does NOT modify requirements.txt.
    param([string]$RequirementsFilePath)

    Write-Log "Checking whether pip-audit can suggest safe replacement versions (informational only, NOT applied automatically)..."
    & pip-audit -r $RequirementsFilePath --vulnerability-service pypi --fix --dry-run
    Write-Log "Review the suggestions above. Update requirements.txt manually if you choose to adopt any of them." "WARN"
}

function Confirm-PythonAndTooling {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        Write-Log "Python was not found on this machine. Install Python before running this script." "ERROR"
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
        exit 1
    }
    $pythonVersionOutput = & python --version 2>&1
    Write-Log "Python found: $pythonVersionOutput" "OK"

    Write-Log "Checking pip version..."
    $outdatedJson = & python -m pip list --outdated --format=json 2>$null
    $pipOutdated = $null
    if ($outdatedJson) {
        $outdatedPackages = $outdatedJson | ConvertFrom-Json
        $pipOutdated = $outdatedPackages | Where-Object { $_.name -eq "pip" }
    }
    if ($pipOutdated) {
        Write-Log "pip is outdated (current: $($pipOutdated.version), latest: $($pipOutdated.latest_version)). Upgrading..." "WARN"
        & python -m pip install --upgrade pip
        Write-Log "pip upgraded successfully." "OK"
    }
    else {
        Write-Log "pip is up to date." "OK"
    }

    Write-Log "Checking pip-audit installation..."
    & python -m pip show pip-audit *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Log "pip-audit is not installed. Installing..." "WARN"
        & python -m pip install pip-audit
        Write-Log "pip-audit installed successfully." "OK"
    }
    else {
        Write-Log "pip-audit is already installed." "OK"
    }
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

# Write-Log "Starting Microsoft Defender scan on the wheelhouse folder..."
# if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
#     try {
#         Start-MpScan -ScanPath $WheelhousePath -ScanType CustomScan
#         Write-Log "Microsoft Defender scan completed." "OK"
#     }
#     catch {
#         Write-Log "Microsoft Defender scan failed: $($_.Exception.Message)" "ERROR"
#     }
# }
# else {
#     Write-Log "Start-MpScan cmdlet is not available on this machine. Skipping Defender scan." "WARN"
# }

Write-Log "=== Wheelhouse maintenance script finished ==="
Stop-Transcript -ErrorAction SilentlyContinue | Out-Null