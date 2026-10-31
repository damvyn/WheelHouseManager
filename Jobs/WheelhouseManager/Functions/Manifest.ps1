# ---------------------------------------------------------------------------
# manifest.json: reading, writing, integrity verification, comparison
# ---------------------------------------------------------------------------

function Get-WheelFileInfo {
    # Parses a wheel filename (PEP 427): name-version(-build)?-python_tag-abi_tag-platform_tag.whl
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FileName
    )

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

function Get-WheelhouseManifestPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    return Join-Path $WheelhousePath 'manifest.json'
}

function Read-WheelhouseManifest {
    # Returns the manifest entries as an array (empty if manifest.json is missing
    # or empty). Throws if the file exists but is not valid JSON - a corrupt
    # manifest must never be silently treated as "empty".
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $manifestPath = Get-WheelhouseManifestPath -WheelhousePath $WheelhousePath
    $entries = [System.Collections.Generic.List[object]]::new()

    if (Test-Path -Path $manifestPath) {
        $content = Get-Content -Path $manifestPath -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($content)) {
            try {
                $parsed = ConvertFrom-Json -InputObject $content -ErrorAction Stop
            }
            catch {
                throw "manifest.json exists but could not be parsed ($($_.Exception.Message)). Refusing to continue until it is resolved manually."
            }
            # foreach unrolls both a JSON array and a lone object (older manifests
            # with a single entry were written as a bare object).
            foreach ($entry in $parsed) { $entries.Add($entry) }
        }
    }

    Write-Output -NoEnumerate $entries.ToArray()
}

function Save-WheelhouseManifest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $manifestPath = Get-WheelhouseManifestPath -WheelhousePath $WheelhousePath
    if ($PSCmdlet.ShouldProcess($manifestPath, 'Save manifest')) {
        Write-JsonFile -Path $manifestPath -InputObject @($Manifest) -Depth 5
    }
}

function Get-WheelhouseIntegrityProblem {
    # Compares every manifest entry with the file in the wheelhouse. Returns one object per
    # problem: { Kind; Entry; Message } with Kind
    #   Missing    - the file is gone (e.g. the file server's antivirus removed it)
    #   Modified   - the file's SHA256 differs from the one recorded when it was published
    #   Unreadable - the file could not be read to check it (network, permissions)
    #   Malformed  - the manifest record itself is broken
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    foreach ($entry in $Manifest) {
        $label = "$($entry.name)==$($entry.version)"
        # Guard against a malformed 'file' field (should be plain text).
        $fileValue = $entry.file
        if ($fileValue -is [array]) {
            [PSCustomObject]@{ Kind = 'Malformed'; Entry = $entry; Message = "${label}: manifest record has a malformed 'file' field (expected text, got a list: $($fileValue -join ', ')). Investigate manifest.json manually." }
            continue
        }
        $filePath = Join-Path $WheelhousePath $fileValue
        if (-not (Test-Path -LiteralPath $filePath)) {
            [PSCustomObject]@{ Kind = 'Missing'; Entry = $entry; Message = "${label}: recorded file '$fileValue' is missing from the wheelhouse." }
            continue
        }
        try {
            $currentHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        catch {
            [PSCustomObject]@{ Kind = 'Unreadable'; Entry = $entry; Message = "${label}: could not read '$fileValue' to verify its hash ($($_.Exception.Message))." }
            continue
        }
        if ($currentHash -ne $entry.sha256) {
            [PSCustomObject]@{ Kind = 'Modified'; Entry = $entry; Message = "${label}: file '$fileValue' hash MISMATCH (expected $($entry.sha256), got $currentHash)." }
        }
    }
}

function Test-ManifestIntegrity {
    # Verifies every manifest file still exists and matches its recorded SHA256 hash.
    # Returns a list of problem descriptions (empty if everything matches).
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $problems = @(Get-WheelhouseIntegrityProblem -Manifest $Manifest -WheelhousePath $WheelhousePath | ForEach-Object { $_.Message })
    Write-Output -NoEnumerate ([string[]]$problems)
}

function Get-UntrackedWheelFile {
    # Wheel files present in the wheelhouse folder but not recorded in the manifest.
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $tracked = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Manifest) { [void]$tracked.Add([string]$entry.file) }

    $untracked = @(Get-ChildItem -Path $WheelhousePath -Filter '*.whl' -File -ErrorAction SilentlyContinue |
            Where-Object { -not $tracked.Contains($_.Name) } |
            ForEach-Object { $_.Name })
    Write-Output -NoEnumerate ([string[]]$untracked)
}

function Assert-WheelhouseIntegrity {
    # Verifies the wheelhouse against its manifest. Writes Report_Integrity_<timestamp>.json
    # and logs every problem it finds. Untracked wheel files are reported as a warning only.
    #
    # Without -AllowChangedFiles any problem throws. With it, wheels that were removed
    # (Missing) or changed (Modified) outside the manager - typically by the file server's
    # antivirus - are returned as { Kind; Entry; Message } for the caller to deal with
    # (Resolve-WheelhouseIntegrityProblem); only Unreadable and Malformed entries still throw,
    # because nothing can be said about those files.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [string]$ReportsFolder,

        [switch]$AllowChangedFiles
    )

    if ($Manifest.Count -eq 0) { return }

    Write-Log 'Verifying wheelhouse integrity against manifest...'
    $problems = @(Get-WheelhouseIntegrityProblem -Manifest $Manifest -WheelhousePath $WheelhousePath)

    if ($problems.Count -gt 0) {
        $reportFile = Join-Path $ReportsFolder "Report_Integrity_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        Write-JsonFile -Path $reportFile -InputObject @($problems | ForEach-Object { [ordered]@{ kind = $_.Kind; package = "$($_.Entry.name)==$($_.Entry.version)"; file = [string]$_.Entry.file; message = $_.Message } }) -Depth 3
        Write-Log 'WHEELHOUSE INTEGRITY CHECK found problem(s):' 'ERROR'
        foreach ($item in $problems) {
            Write-Log "  - [$($item.Kind)] $($item.Message)" 'ERROR'
        }
        Write-Log "Integrity report saved to: $reportFile" 'ERROR'

        $blocking = @($problems | Where-Object { -not $AllowChangedFiles -or $_.Kind -in 'Unreadable', 'Malformed' })
        if ($blocking.Count -gt 0) {
            throw 'Wheelhouse integrity check failed - refusing to continue until this is investigated manually.'
        }
        Write-Log "$($problems.Count) wheel(s) were removed or changed outside the manager (e.g. by the file server's antivirus); every other tracked file matches its recorded hash." 'WARN'
    }
    else {
        Write-Log 'Wheelhouse integrity check passed. All tracked files match their recorded hash.' 'OK'
    }

    $untracked = Get-UntrackedWheelFile -Manifest $Manifest -WheelhousePath $WheelhousePath
    if ($untracked.Count -gt 0) {
        Write-Log "$($untracked.Count) wheel file(s) in the wheelhouse are NOT tracked by the manifest (not downloaded by this tooling, or left over from a failed run):" 'WARN'
        foreach ($name in $untracked) {
            Write-Log "  - $name" 'WARN'
        }
        Write-Log 'These are never added to the manifest automatically. Remove them and let Update-Wheelhouse.ps1 download them again if they are needed.' 'WARN'
    }

    if ($AllowChangedFiles) { $problems }
}

function Merge-WheelhouseManifest {
    # Returns the new manifest after a download run: every existing entry is kept
    # unchanged (including its original downloaded_utc), and only wheel files that
    # appeared during this run (i.e. not in -PreRunFiles) are hashed and added.
    # Wheel files that were already in the folder but untracked are NOT added -
    # nothing downloaded outside this tooling gets blessed silently.
    #
    # Exception: on first-time setup (empty manifest) every wheel present is added,
    # with a warning, since there is nothing to compare against yet.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$PreRunFiles
    )

    $isBootstrap = ($Manifest.Count -eq 0)
    $preRun = [System.Collections.Generic.HashSet[string]]::new([string[]]$PreRunFiles, [System.StringComparer]::OrdinalIgnoreCase)
    $entries = [System.Collections.Generic.List[object]]::new()
    $tracked = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($entry in $Manifest) {
        $entries.Add($entry)
        [void]$tracked.Add([string]$entry.file)
    }

    $nowUtc = (Get-Date).ToUniversalTime().ToString('o')
    foreach ($file in (Get-ChildItem -Path $WheelhousePath -Filter '*.whl' -File -ErrorAction SilentlyContinue)) {
        if ($tracked.Contains($file.Name)) { continue }

        if ($preRun.Contains($file.Name) -and -not $isBootstrap) {
            Write-Log "Untracked wheel was already present before this run, NOT adding it to the manifest: $($file.Name)" 'WARN'
            continue
        }
        if ($preRun.Contains($file.Name)) {
            Write-Log "First-time setup: adding pre-existing wheel to the manifest: $($file.Name)" 'WARN'
        }

        $info = Get-WheelFileInfo -FileName $file.Name
        if (-not $info) {
            Write-Log "Could not parse wheel filename, skipping from manifest: $($file.Name)" 'WARN'
            continue
        }
        $entries.Add([PSCustomObject]@{
                name           = $info.Name
                version        = $info.Version
                file           = $file.Name
                sha256         = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                python_tag     = $info.PythonTag
                abi_tag        = $info.AbiTag
                platform_tag   = $info.PlatformTag
                downloaded_utc = $nowUtc
            })
    }

    Write-Output -NoEnumerate $entries.ToArray()
}

function Compare-RequirementsAgainstManifest {
    # Checks that each required package/version has a manifest entry matching
    # the target Python/platform tag.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Required,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [Parameter(Mandatory)]
        [string]$ExpectedPythonTag,

        [Parameter(Mandatory)]
        [string]$ExpectedPlatformTag
    )

    # name==version -> entries, built once instead of scanning the manifest per package.
    $index = @{}
    foreach ($entry in $Manifest) {
        $key = "$($entry.name)==$($entry.version)"
        if (-not $index.ContainsKey($key)) { $index[$key] = [System.Collections.Generic.List[object]]::new() }
        $index[$key].Add($entry)
    }

    $descriptions = [System.Collections.Generic.List[string]]::new()
    $missingPackages = @{}

    foreach ($name in ($Required.Keys | Sort-Object)) {
        $reqVersion = $Required[$name]
        $versionEntries = $index["$name==$reqVersion"]

        if (-not $versionEntries) {
            $descriptions.Add("$name==$reqVersion (not found in manifest)")
            $missingPackages[$name] = $reqVersion
            continue
        }

        $platformMatch = $versionEntries | Where-Object {
            ($_.platform_tag -eq $ExpectedPlatformTag -or $_.platform_tag -eq 'any') -and
            ($_.python_tag -eq $ExpectedPythonTag -or $_.python_tag -like 'py*' -or $_.abi_tag -eq 'abi3')
        }

        if (-not $platformMatch) {
            $descriptions.Add("$name==$reqVersion (found in manifest, but no file matches target tag $ExpectedPythonTag/$ExpectedPlatformTag)")
            $missingPackages[$name] = $reqVersion
        }
    }

    return @{ Descriptions = $descriptions.ToArray(); Packages = $missingPackages }
}

function Get-QuarantineFileName {
    # Resolves the exact wheel file name(s) for a package/version from manifest.json.
    # Falls back to a best-guess glob pattern if the manifest is unavailable or has no match.
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowEmptyString()]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [string]$NormalizedName,

        [Parameter(Mandatory)]
        [string]$Version,

        # Pass an already-loaded manifest to avoid re-reading it for every finding.
        [object[]]$Manifest
    )

    $pattern = "$($NormalizedName -replace '-', '_')-$Version-*.whl"

    if ($null -eq $Manifest) {
        if ([string]::IsNullOrWhiteSpace($WheelhousePath)) {
            return @("$pattern (estimated pattern - WheelhousePath not supplied)")
        }
        try {
            $Manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
        }
        catch {
            return @("$pattern (estimated pattern - manifest.json could not be parsed)")
        }
    }
    if ($Manifest.Count -eq 0) {
        return @("$pattern (estimated pattern - manifest.json not found or empty)")
    }

    $manifestMatches = @($Manifest | Where-Object { $_.name -eq $NormalizedName -and $_.version -eq $Version })
    if ($manifestMatches.Count -eq 0) {
        return @("$pattern (estimated pattern - no manifest entry found)")
    }

    return @($manifestMatches | ForEach-Object { [string]$_.file })
}

function Get-UndownloadedPin {
    # Pins that a group file lists but whose wheel (for the target Python / platform)
    # is not in the manifest - i.e. entries clients would expect but can't install.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$GroupFiles,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Manifest,

        [Parameter(Mandatory)]
        [string]$PythonVersion,

        [Parameter(Mandatory)]
        [string]$Platform
    )

    $pythonTag = 'cp' + ($PythonVersion -replace '\.', '')
    foreach ($groupFile in $GroupFiles) {
        $compareParams = @{
            Required            = (Read-RequirementFile -FilePath $groupFile)
            Manifest            = $Manifest
            ExpectedPythonTag   = $pythonTag
            ExpectedPlatformTag = $Platform
        }
        $missing = (Compare-RequirementsAgainstManifest @compareParams).Packages
        foreach ($name in ($missing.Keys | Sort-Object)) {
            [PSCustomObject]@{
                Group   = [System.IO.Path]::GetFileNameWithoutExtension($groupFile)
                Package = $name
                Version = $missing[$name]
            }
        }
    }
}
