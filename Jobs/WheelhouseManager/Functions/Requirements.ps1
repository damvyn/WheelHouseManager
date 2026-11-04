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

function Read-RequirementDependent {
    # Reads the "# via" annotations that `uv pip compile` writes under each pin and returns
    # normalized name -> string[] of the normalized names of the pins that need it, e.g.
    #     urllib3==2.8.0
    #         # via requests
    # gives @{ urllib3 = @('requests') }. Both annotation styles are read (one line, or
    # "# via" followed by one "#   name" line per parent). Sources that are not pins
    # (-r requirements.in, -c constraints.txt) are skipped - with -IncludeSource the
    # "-r <file>" entries are kept as they are, so a caller can tell a pin that was asked for
    # from one that is only a dependency. A file compiled with --no-annotate gives an empty table.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [switch]$IncludeSource
    )

    $dependents = @{}
    $current = $null
    $inList = $false
    $add = {
        param([string]$Entry)
        $token = ($Entry.Trim() -split '\s+')[0]
        if ($IncludeSource -and $token -eq '-r') {
            $source = ($Entry.Trim() -replace '\s+', ' ')
            if (-not $dependents.ContainsKey($current)) { $dependents[$current] = @() }
            if ($dependents[$current] -notcontains $source) { $dependents[$current] = @($dependents[$current]) + $source }
            return
        }
        if (-not $token -or $token.StartsWith('-') -or $token -notmatch '^[A-Za-z0-9][A-Za-z0-9_.\-]*$') { return }
        $parent = Get-NormalizedPackageName $token
        if ($parent -eq $current) { return }
        if (-not $dependents.ContainsKey($current)) { $dependents[$current] = @() }
        if ($dependents[$current] -notcontains $parent) { $dependents[$current] = @($dependents[$current]) + $parent }
    }
    foreach ($rawLine in (Get-Content -Path $FilePath -ErrorAction Stop)) {
        $line = $rawLine.Trim()
        if ($line -match '^(?<name>[A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(\[[^\]]*\])?\s*==') {
            $current = Get-NormalizedPackageName $Matches['name']
            $inList = $false
            continue
        }
        if (-not $current -or -not $line.StartsWith('#')) {
            if ($line -ne '' -and -not $line.StartsWith('--hash')) { $inList = $false }
            continue
        }
        $comment = $line.TrimStart('#').Trim()
        if ($comment -match '^via\s*$') { $inList = $true; continue }
        if ($comment -match '^via\s+(?<entry>.+)$') { & $add $Matches['entry']; $inList = $false; continue }
        if ($inList -and $comment) { & $add $comment }
    }
    return $dependents
}

function Get-DependentRejection {
    # Packages that must be held back because a pin they need was rejected. -Rejected are
    # rejection objects ({Name; Version; Reason}); -Dependents is Read-RequirementDependent's
    # table; -Pins the versions requirements.txt resolved (name -> version) - only a rejection
    # of exactly that version holds anything back; -Candidates the packages still on their
    # way in (name -> version). Follows the chain upwards: a package that needs a held-back
    # package is held back too. Returns [PSCustomObject]@{Name; Version; Category =
    # 'dependency'; Reason; Dependency = 'name==version' of the rejected pin it needs}.
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowEmptyCollection()]
        [object[]]$Rejected = @(),

        [hashtable]$Dependents = @{},

        [hashtable]$Pins = @{},

        [hashtable]$Candidates = @{}
    )

    $held = [System.Collections.Generic.List[object]]::new()
    $done = @{}
    $queue = [System.Collections.Generic.Queue[object]]::new()
    foreach ($item in @($Rejected)) {
        if ($null -eq $item) { continue }
        $name = Get-NormalizedPackageName ([string]$item.Name)
        if (-not $Pins.ContainsKey($name) -or [string]$Pins[$name] -ne [string]$item.Version -or $done.ContainsKey($name)) { continue }
        $done[$name] = $true
        $queue.Enqueue([PSCustomObject]@{ Name = $name; Version = [string]$item.Version; Reason = [string]$item.Reason })
    }
    while ($queue.Count -gt 0) {
        $failed = $queue.Dequeue()
        foreach ($parent in @($Dependents[$failed.Name] | Sort-Object)) {
            if (-not $parent -or $done.ContainsKey($parent)) { continue }
            if (-not $Candidates.ContainsKey($parent) -or -not $Pins.ContainsKey($parent) -or [string]$Candidates[$parent] -ne [string]$Pins[$parent]) { continue }
            $done[$parent] = $true
            $entry = [PSCustomObject]@{
                Name       = $parent
                Version    = [string]$Pins[$parent]
                Category   = 'dependency'
                Reason     = "needs $($failed.Name)==$($failed.Version), which was rejected ($($failed.Reason))"
                Dependency = "$($failed.Name)==$($failed.Version)"
            }
            $held.Add($entry)
            $queue.Enqueue($entry)
        }
    }
    return $held.ToArray()
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

function ConvertTo-UvPythonPlatform {
    # Maps the wheel platform tag used by pip (settings.psd1's Platform) to the target
    # triple that `uv pip compile --python-platform` expects.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Platform
    )

    switch ($Platform) {
        'win_amd64' { return 'x86_64-pc-windows-msvc' }
        'win_arm64' { return 'aarch64-pc-windows-msvc' }
        'win32' { return 'i686-pc-windows-msvc' }
        default { throw "Platform '$Platform' has no known uv --python-platform equivalent. Supported: win_amd64, win_arm64, win32." }
    }
}

function Invoke-PipPinRetry {
    # Runs a pip command against a set of exact pins and works out which pins pip
    # rejects. pip stops at the first pin it can't satisfy ("No matching distribution
    # found for X"), so that pin is dropped and the command repeated until it succeeds
    # for everything left - one run reports every failing pin, and the rest are not
    # held back by them.
    #
    # -PipArguments is the pip command without "-r <file>" (e.g. '-m','pip','download',...);
    # the pins are written to a temporary requirements file which is appended as -r.
    # Returns @{ Succeeded = @{name=version}; Failed = 'name==version', ...; Error = $null
    # or a message when pip failed without naming a pin (network, proxy, ...) - in that
    # case the pins not yet attributed are neither in Succeeded nor in Failed }.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [hashtable]$Packages,

        [Parameter(Mandatory)]
        [string[]]$PipArguments
    )

    $remaining = @{} + $Packages
    $failed = [System.Collections.Generic.List[string]]::new()
    $workFolder = Join-Path ([System.IO.Path]::GetTempPath()) ("wheelhouse-pip-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $workFolder -Force | Out-Null

    try {
        while ($remaining.Count -gt 0) {
            $pinFile = Join-Path $workFolder 'requirements.txt'
            Set-Content -Path $pinFile -Value @($remaining.Keys | Sort-Object | ForEach-Object { "$_==$($remaining[$_])" }) -Encoding ascii

            $output = Invoke-NativeCommand -FilePath python -ArgumentList (@($PipArguments) + @('-r', $pinFile)) -PassThru
            if ($LASTEXITCODE -eq 0) {
                return @{ Succeeded = $remaining; Failed = $failed.ToArray(); Error = $null }
            }

            $failedName = $null
            foreach ($line in $output) {
                if ($line -match 'No matching distribution found for\s+(?<pin>[A-Za-z0-9][A-Za-z0-9_.\-]*)') {
                    $failedName = Get-NormalizedPackageName $Matches['pin']
                    break
                }
            }
            if (-not $failedName -or -not $remaining.ContainsKey($failedName)) {
                return @{
                    Succeeded = @{}
                    Failed    = $failed.ToArray()
                    Error     = "pip exited with code $LASTEXITCODE without naming an unavailable package - see the pip output above (network or proxy problem?)."
                }
            }

            $failed.Add("$failedName==$($remaining[$failedName])")
            $remaining.Remove($failedName)
        }
        return @{ Succeeded = @{}; Failed = $failed.ToArray(); Error = $null }
    }
    finally {
        Remove-Item -Path $workFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Test-RequirementWheelAvailability {
    # Checks that every pin in a requirements file can be downloaded exactly the way
    # Update-Wheelhouse.ps1 downloads it: a binary wheel for the target Python version
    # and platform, with Requires-Python satisfied. `uv pip compile` can pick versions
    # that fail this (it accepts source-only releases unless told otherwise, and it
    # ignores upper bounds on Requires-Python), so the resolved file is checked with
    # pip itself, via `pip install --dry-run` - nothing is installed.
    # Returns @{ Passed; Unavailable = 'name==version', ...; Error = message or $null }.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$RequirementsFilePath,

        [Parameter(Mandatory)]
        [string]$PythonVersion,

        [Parameter(Mandatory)]
        [string]$Platform
    )

    $targetFolder = Join-Path ([System.IO.Path]::GetTempPath()) ("wheelhouse-check-" + [guid]::NewGuid().ToString('N'))
    try {
        $pipArgs = @(
            '-m', 'pip', 'install',
            '--dry-run', '--no-deps', '--ignore-installed',
            '--only-binary=:all:',
            '--python-version', $PythonVersion,
            '--platform', $Platform,
            '--implementation', 'cp',
            '--target', $targetFolder,
            '--disable-pip-version-check'
        )
        $result = Invoke-PipPinRetry -Packages (Read-RequirementFile -FilePath $RequirementsFilePath) -PipArguments $pipArgs
    }
    finally {
        Remove-Item -Path $targetFolder -Recurse -Force -ErrorAction SilentlyContinue
    }

    foreach ($pin in $result.Failed) {
        Write-Log "No wheel for Python $PythonVersion / $($Platform): $pin" 'WARN'
    }
    return @{
        Passed      = ($result.Failed.Count -eq 0 -and -not $result.Error)
        Unavailable = $result.Failed
        Error       = $result.Error
    }
}

function ConvertTo-PackageVersionKey {
    # A PEP 440 version split into comparable parts: epoch, release numbers, and a rank for
    # dev < pre-release (a < b < rc) < final < post. Local versions (+...) are ignored.
    # Returns $null for text that is not a version.
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Version
    )

    $text = $Version.Trim().ToLowerInvariant() -replace '^v', '' -replace '\+.*$', ''
    $pattern = '^(?:(?<epoch>\d+)!)?(?<release>\d+(?:\.\d+)*)(?:[-_.]?(?<pre>a|alpha|b|beta|rc|c|pre|preview)[-_.]?(?<pren>\d*))?(?:(?:[-_.]?(?:post|rev|r)[-_.]?(?<post>\d*))|(?:-(?<post2>\d+)))?(?:[-_.]?dev[-_.]?(?<dev>\d*))?$'
    if ($text -notmatch $pattern) { return $null }
    $pre = switch ($Matches['pre']) {
        { $_ -in 'a', 'alpha' } { 1 }
        { $_ -in 'b', 'beta' } { 2 }
        { $_ -in 'rc', 'c', 'pre', 'preview' } { 3 }
        default { 4 }
    }
    $hasPost = [bool]($Matches['post'] -or $Matches['post2'] -or $text -match '(post|rev|r)\d*$')
    $hasDev = $text -match 'dev\d*$'
    return [PSCustomObject]@{
        Epoch   = $(if ($Matches['epoch']) { [long]$Matches['epoch'] } else { 0 })
        Release = [long[]]@($Matches['release'] -split '\.' | ForEach-Object { [long]$_ })
        # A dev release of a final version sorts before its pre-releases.
        Phase   = $(if ($hasDev -and $pre -eq 4 -and -not $hasPost) { 0 } else { $pre })
        PhaseN  = $(if ($Matches['pren']) { [long]$Matches['pren'] } else { 0 })
        Post    = $(if ($hasPost) { 1 + $(if ($Matches['post']) { [long]$Matches['post'] } elseif ($Matches['post2']) { [long]$Matches['post2'] } else { 0 }) } else { 0 })
        Dev     = $(if ($hasDev) { $(if ($Matches['dev']) { [long]$Matches['dev'] } else { 0 }) } else { [long]::MaxValue })
    }
}

function Compare-PackageVersion {
    # -1, 0 or 1 like a comparer, for two PEP 440 versions. Throws for text that is not a
    # version.
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string]$Left,

        [Parameter(Mandatory)]
        [string]$Right
    )

    $a = ConvertTo-PackageVersionKey -Version $Left
    $b = ConvertTo-PackageVersionKey -Version $Right
    if ($null -eq $a) { throw [System.ArgumentException]::new("Not a version: '$Left'.") }
    if ($null -eq $b) { throw [System.ArgumentException]::new("Not a version: '$Right'.") }
    if ($a.Epoch -ne $b.Epoch) { return [math]::Sign($a.Epoch - $b.Epoch) }
    $length = [math]::Max($a.Release.Count, $b.Release.Count)
    for ($i = 0; $i -lt $length; $i++) {
        $x = if ($i -lt $a.Release.Count) { $a.Release[$i] } else { 0 }
        $y = if ($i -lt $b.Release.Count) { $b.Release[$i] } else { 0 }
        if ($x -ne $y) { return [math]::Sign($x - $y) }
    }
    foreach ($part in 'Phase', 'PhaseN', 'Post') {
        if ($a.$part -ne $b.$part) { return [math]::Sign($a.$part - $b.$part) }
    }
    if ($a.Dev -ne $b.Dev) { return $(if ($a.Dev -lt $b.Dev) { -1 } else { 1 }) }
    return 0
}

function Set-RequirementInGroupFile {
    # Replaces the pin of -Name in a group file with name==-Version (or adds it if the file
    # does not list the name). Used when a remediation swaps a vulnerable version for its
    # fix in the groups clients install from, instead of adding a second group.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GroupFile,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version
    )

    $normalized = Get-NormalizedPackageName $Name
    if (-not $PSCmdlet.ShouldProcess($GroupFile, "Set $normalized==$Version")) { return }
    $listed = if (Test-Path -Path $GroupFile) { Read-RequirementFile -FilePath $GroupFile } else { @{} }
    if ($listed[$normalized] -eq $Version) { return }
    if ($listed.ContainsKey($normalized)) {
        [void](Remove-RequirementFromGroupFile -GroupFile $GroupFile -Name $normalized -Version $listed[$normalized])
    }
    Add-RequirementToGroupFile -GroupFile $GroupFile -Name $normalized -Version $Version
}
