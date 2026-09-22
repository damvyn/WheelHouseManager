<#
.SYNOPSIS
    Shared function library for the wheelhouse scripts.

.DESCRIPTION
    Dot-sourced by Update-Wheelhouse.ps1, Send-VulnerabilityAlert.ps1, and
    Invoke-WheelhousePipeline.ps1:
        . (Join-Path $PSScriptRoot "functions.ps1")
    Must live in the same folder as the scripts that use it.

    Layout: a shared block used by more than one script, followed by one block
    per script containing only the functions that script uses.
#>

#Requires -Version 5.1

# ---------------------------------------------------------------------------
# Shared functions (used by all scripts)
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

function Get-WheelhouseSettings {
    # Reads config\settings.psd1. Returns an empty hashtable (not an error) if the
    # file is missing or unreadable, so callers can fall back to their own defaults.
    param([string]$SettingsPath)

    if (-not (Test-Path -Path $SettingsPath)) {
        return @{}
    }
    try {
        return Import-PowerShellDataFile -Path $SettingsPath
    }
    catch {
        Write-Log "Could not read settings file '$SettingsPath': $($_.Exception.Message)" "WARN"
        return @{}
    }
}

function Resolve-Setting {
    # Precedence: explicit -Parameter (if the caller actually passed it) > value from
    # settings.psd1 (if present and non-empty) > the script's own hardcoded fallback.
    param(
        [string]$Name,
        $ExplicitValue,
        [bool]$WasBound,
        [hashtable]$Settings,
        $FallbackDefault
    )

    if ($WasBound) { return $ExplicitValue }

    if ($Settings.ContainsKey($Name)) {
        $settingValue = $Settings[$Name]
        $isEmpty = ($null -eq $settingValue) -or
                   ($settingValue -is [string] -and [string]::IsNullOrWhiteSpace($settingValue)) -or
                   ($settingValue -is [array] -and $settingValue.Count -eq 0)
        if (-not $isEmpty) { return $settingValue }
    }

    return $FallbackDefault
}

# ---------------------------------------------------------------------------
# Functions for Update-Wheelhouse.ps1
# ---------------------------------------------------------------------------

function Get-WheelhouseRequirementGroups {
    # Returns the wheelhouse's group requirement files (requirements-1.txt, -2.txt, ...),
    # sorted by group number. Falls back to a legacy single requirements.txt (treated as
    # the sole group) if no numbered group files exist yet, for backward compatibility
    # with wheelhouses populated before group files existed.
    param([string]$WheelhousePath)

    $numbered = @(Get-ChildItem -Path $WheelhousePath -Filter "requirements-*.txt" -File -ErrorAction SilentlyContinue |
        Sort-Object { [int]([regex]::Match($_.Name, '\d+').Value) })
    if ($numbered.Count -gt 0) {
        Write-Output -NoEnumerate @($numbered | ForEach-Object { $_.FullName })
        return
    }

    $legacy = Join-Path $WheelhousePath "requirements.txt"
    if (Test-Path -Path $legacy) {
        Write-Output -NoEnumerate @($legacy)
        return
    }
    Write-Output -NoEnumerate @()
}

function Merge-LocalRequirements {
    # Decides where each locally-requested package/version belongs among the existing
    # group files: skip if an identical name==version is already present anywhere
    # (duplicate); otherwise place it in the first group that doesn't already use that
    # package name; if every existing group already has that name pinned to a DIFFERENT
    # version, start a new group file - group files never contain two versions of the
    # same package (pip's own requirements format can't express that).
    param(
        [hashtable]$LocalPackages,
        [string[]]$GroupFiles,
        [string]$WheelhousePath
    )

    $groupPackages = @()
    foreach ($file in $GroupFiles) {
        $groupPackages += , (Get-RequirementsPackages -FilePath $file)
    }

    $duplicates = @()
    $additions = @()

    foreach ($name in $LocalPackages.Keys) {
        $version = $LocalPackages[$name]
        $handled = $false

        for ($i = 0; $i -lt $groupPackages.Count; $i++) {
            if ($groupPackages[$i].ContainsKey($name) -and $groupPackages[$i][$name] -eq $version) {
                $duplicates += "$name==$version (already in $(Split-Path -Path $GroupFiles[$i] -Leaf))"
                $handled = $true
                break
            }
        }
        if ($handled) { continue }

        for ($i = 0; $i -lt $groupPackages.Count; $i++) {
            if (-not $groupPackages[$i].ContainsKey($name)) {
                $additions += [PSCustomObject]@{
                    Name       = $name
                    Version    = $version
                    GroupFile  = $GroupFiles[$i]
                    IsNewGroup = $false
                }
                $groupPackages[$i][$name] = $version
                $handled = $true
                break
            }
        }
        if ($handled) { continue }

        $newGroupIndex = $groupPackages.Count + 1
        $newGroupFile = Join-Path $WheelhousePath "requirements-$newGroupIndex.txt"
        $additions += [PSCustomObject]@{
            Name       = $name
            Version    = $version
            GroupFile  = $newGroupFile
            IsNewGroup = $true
        }
        $groupPackages += @{ $name = $version }
        $GroupFiles += $newGroupFile
    }

    return @{ Additions = $additions; Duplicates = $duplicates }
}

function Add-RequirementToGroupFile {
    # Creates the group file (new group) or appends a line to an existing one.
    param(
        [string]$GroupFile,
        [string]$Name,
        [string]$Version,
        [bool]$IsNewGroup
    )

    if ($IsNewGroup -or -not (Test-Path -Path $GroupFile)) {
        Set-Content -Path $GroupFile -Value "$Name==$Version" -Encoding utf8
    }
    else {
        Add-Content -Path $GroupFile -Value "$Name==$Version" -Encoding utf8
    }
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
        try {
            $currentHash = (Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        catch {
            $problems += "$($entry.name)==$($entry.version): could not read '$fileValue' to verify its hash ($($_.Exception.Message))."
            continue
        }
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
# Functions for Send-VulnerabilityAlert.ps1
# ---------------------------------------------------------------------------

function Get-ServiceNameFromReportPath {
    # Infers OSV / PyPI / Unknown from the report file name.
    param([string]$Path)

    $fileName = Split-Path -Path $Path -Leaf
    if ($fileName -match '-OSV_') { return "OSV" }
    if ($fileName -match '-PYPI_') { return "PyPI" }
    return "Unknown"
}

function Get-PipAuditReport {
    # Returns an array of dependency objects ({name, version, vulns:[...]})
    # regardless of whether the JSON root is a flat array (older pip-audit)
    # or an object with a "dependencies" property (newer pip-audit).
    param([string]$Path)

    if (-not (Test-Path -Path $Path)) {
        Write-Log "Report file not found, skipping: $Path" "WARN"
        Write-Output -NoEnumerate @()
        return
    }

    try {
        $raw = Get-Content -Path $Path -Raw
        $parsed = ConvertFrom-Json -InputObject $raw
    }
    catch {
        Write-Log "Failed to parse report as JSON, skipping: $Path ($($_.Exception.Message))" "WARN"
        Write-Output -NoEnumerate @()
        return
    }

    if ($parsed -is [array]) {
        # Flat array format (most common). Checking -is [array] first avoids a
        # trap: accessing .dependencies on an array whose elements don't have
        # that property returns an array of $null (one per element), not a
        # plain $null - which would otherwise make the next check misfire.
        Write-Output -NoEnumerate $parsed
        return
    }
    if ($null -ne $parsed.dependencies) {
        Write-Output -NoEnumerate @($parsed.dependencies)
        return
    }
    Write-Output -NoEnumerate @($parsed)
}

function Get-QuarantineFileNames {
    # Resolves the exact wheel file name(s) for a package/version from manifest.json.
    # Falls back to a best-guess glob pattern if the manifest is unavailable or has no match.
    param(
        [string]$WheelhousePath,
        [string]$NormalizedName,
        [string]$Version
    )

    if ([string]::IsNullOrWhiteSpace($WheelhousePath)) {
        return @("$NormalizedName-$Version-*.whl (estimated pattern - WheelhousePath not supplied)")
    }

    $manifestPath = Join-Path $WheelhousePath "manifest.json"
    if (-not (Test-Path -Path $manifestPath)) {
        return @("$NormalizedName-$Version-*.whl (estimated pattern - manifest.json not found)")
    }

    try {
        $manifest = @(ConvertFrom-Json -InputObject (Get-Content -Path $manifestPath -Raw))
    }
    catch {
        return @("$NormalizedName-$Version-*.whl (estimated pattern - manifest.json could not be parsed)")
    }

    $matches = @($manifest | Where-Object { $_.name -eq $NormalizedName -and $_.version -eq $Version })
    if ($matches.Count -eq 0) {
        return @("$NormalizedName-$Version-*.whl (estimated pattern - no manifest entry found)")
    }

    return @($matches | ForEach-Object { $_.file })
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

# ---------------------------------------------------------------------------
# Functions for Invoke-WheelhousePipeline.ps1
# ---------------------------------------------------------------------------
# (none yet - this script currently only uses the shared block above)

# ---------------------------------------------------------------------------
# Functions for Setup.ps1
# ---------------------------------------------------------------------------

function Save-Settings {
    # Hand-rolled psd1 writer - kept deliberately simple since the schema is a
    # small, fixed set of strings/ints/string-arrays. Overwrites the whole file
    # with the given hashtable (callers merge first via Set-WheelhouseSetting).
    param(
        [string]$SettingsPath,
        [hashtable]$Settings
    )

    $lines = @('@{')
    foreach ($key in $Settings.Keys) {
        $value = $Settings[$key]
        if ($value -is [array]) {
            $quoted = ($value | ForEach-Object { "'$_'" }) -join ', '
            $lines += "    $key = @($quoted)"
        }
        elseif ($value -is [int]) {
            $lines += "    $key = $value"
        }
        else {
            $lines += "    $key = '$value'"
        }
    }
    $lines += '}'
    $lines -join "`r`n" | Out-File -FilePath $SettingsPath -Encoding utf8
}

function Set-WheelhouseSetting {
    # Merges the given key/value pairs into the existing settings.psd1 (creating it
    # if absent) without touching any key the caller didn't ask to change.
    param(
        [string]$SettingsPath,
        [hashtable]$Updates
    )

    $current = if (Test-Path -Path $SettingsPath) {
        try { Import-PowerShellDataFile -Path $SettingsPath }
        catch { @{} }
    }
    else { @{} }

    foreach ($key in $Updates.Keys) {
        $current[$key] = $Updates[$key]
    }
    Save-Settings -SettingsPath $SettingsPath -Settings $current
}

function Initialize-ManagerFile {
    # Idempotent: never overwrites a file that already exists, so a re-run of
    # Setup.ps1 never clobbers a requirements.in someone is actively editing.
    param(
        [string]$Path,
        [string]$DefaultContent = ""
    )

    if (Test-Path -Path $Path) {
        Write-Log "Already exists, leaving untouched: $Path"
        return
    }
    Set-Content -Path $Path -Value $DefaultContent -Encoding utf8
    Write-Log "Created: $Path" "OK"
}

