# ---------------------------------------------------------------------------
# requirements.txt parsing and wheelhouse group files (requirements-N.txt)
# ---------------------------------------------------------------------------

$script:GroupFilePattern = '^requirements-(\d+)\.txt$'
$script:LegacyGroupFileName = 'requirements.txt'

function Read-RequirementFile {
    # Parses a pinned requirements file (as produced by `uv pip compile`) into a
    # hashtable of normalized name -> version. Only exact pins are supported;
    # extras ("pkg[x]==1.0") and environment markers ("; python_version...") are
    # accepted and dropped - group files only ever record "name==version".
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $packages = @{}
    foreach ($rawLine in (Get-Content -Path $FilePath -ErrorAction Stop)) {
        # Strip inline comments and a trailing line-continuation backslash.
        $line = ($rawLine -replace '(^|\s)#.*$', '').Trim().TrimEnd('\').Trim()
        if ($line -eq '') { continue }
        # Hash lines belong to the preceding pin (uv --generate-hashes output).
        if ($line.StartsWith('--hash')) { continue }

        if ($line -match '^(?<name>[A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(\[[^\]]*\])?\s*==\s*(?<version>[A-Za-z0-9_.\-+!]+)\s*(--hash\S*\s*)*(;.*)?$') {
            $packages[(Get-NormalizedPackageName $Matches['name'])] = $Matches['version']
        }
        else {
            Write-Log "Skipping unsupported requirement line (expected exact pin 'name==version'): $line" 'WARN'
        }
    }
    return $packages
}

function Get-GroupFileNumber {
    # requirements-3.txt -> 3; the legacy requirements.txt -> 0; anything else -> -1.
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $leaf = Split-Path -Path $Path -Leaf
    if ($leaf -match $script:GroupFilePattern) { return [int]$Matches[1] }
    if ($leaf -eq $script:LegacyGroupFileName) { return 0 }
    return -1
}

function Get-WheelhouseGroupFile {
    # Returns the wheelhouse's group requirement files: the legacy single
    # requirements.txt first (if present, for wheelhouses populated before group
    # files existed), then requirements-1.txt, -2.txt, ... in numeric order.
    # Files like requirements-torch.txt are deliberately NOT groups.
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $files = @(Get-ChildItem -Path $WheelhousePath -Filter 'requirements*.txt' -File -ErrorAction SilentlyContinue |
            Where-Object { (Get-GroupFileNumber -Path $_.Name) -ge 0 } |
            Sort-Object { Get-GroupFileNumber -Path $_.Name } |
            ForEach-Object { $_.FullName })

    Write-Output -NoEnumerate ([string[]]$files)
}

function Get-RequirementMergePlan {
    # Decides where each locally-requested package/version belongs among the existing
    # group files: skip if an identical name==version is already present anywhere
    # (duplicate); otherwise place it in the first group that doesn't already use that
    # package name; if every existing group already has that name pinned to a DIFFERENT
    # version, start a new group file - group files never contain two versions of the
    # same package (pip's own requirements format can't express that).
    #
    # New group files are numbered max(existing) + 1, so a gap in the numbering
    # (requirements-1.txt, requirements-3.txt) never makes a "new" group collide with
    # an existing file. Packages are processed in name order so the plan is the same
    # on every run.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$LocalPackages,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$GroupFiles,

        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $groups = [System.Collections.Generic.List[object]]::new()
    $nextGroupNumber = 1
    foreach ($file in $GroupFiles) {
        $groups.Add([PSCustomObject]@{
                File     = $file
                Packages = (Read-RequirementFile -FilePath $file)
            })
        $nextGroupNumber = [math]::Max($nextGroupNumber, (Get-GroupFileNumber -Path $file) + 1)
    }

    $duplicates = [System.Collections.Generic.List[string]]::new()
    $additions = [System.Collections.Generic.List[object]]::new()

    foreach ($name in ($LocalPackages.Keys | Sort-Object)) {
        $version = $LocalPackages[$name]

        $existing = $groups | Where-Object { $_.Packages[$name] -eq $version } | Select-Object -First 1
        if ($existing) {
            $duplicates.Add("$name==$version (already in $(Split-Path -Path $existing.File -Leaf))")
            continue
        }

        $target = $groups | Where-Object { -not $_.Packages.ContainsKey($name) } | Select-Object -First 1
        $isNewGroup = $false
        if (-not $target) {
            $target = [PSCustomObject]@{
                File     = (Join-Path $WheelhousePath "requirements-$nextGroupNumber.txt")
                Packages = @{}
            }
            $groups.Add($target)
            $nextGroupNumber++
            $isNewGroup = $true
        }

        $target.Packages[$name] = $version
        $additions.Add([PSCustomObject]@{
                Name       = $name
                Version    = $version
                GroupFile  = $target.File
                IsNewGroup = $isNewGroup
            })
    }

    return @{ Additions = $additions.ToArray(); Duplicates = $duplicates.ToArray() }
}

function Add-RequirementToGroupFile {
    # Creates the group file (new group) or appends a line to an existing one.
    # Refuses to overwrite: a "new" group file that already exists is appended to.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GroupFile,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version
    )

    if (-not $PSCmdlet.ShouldProcess($GroupFile, "Add $Name==$Version")) { return }

    if (Test-Path -Path $GroupFile) {
        Add-Content -Path $GroupFile -Value "$Name==$Version" -Encoding utf8 -ErrorAction Stop
    }
    else {
        Set-Content -Path $GroupFile -Value "$Name==$Version" -Encoding utf8 -ErrorAction Stop
    }
}
