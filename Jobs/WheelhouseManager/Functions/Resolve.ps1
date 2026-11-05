# ---------------------------------------------------------------------------
# Resolving requirements.in: one run finds every requirement that cannot be resolved
# ---------------------------------------------------------------------------
# `uv pip compile` stops at the first requirement it cannot resolve, so a list with five
# problems took five rounds of "fix one line, resolve again". Invoke-RequirementResolve
# resolves, reads which requirement uv's error names ("... you require X ..."), sets that
# requirement aside with the reason (too new for the cooldown, no usable wheel, not on
# PyPI, a conflict), and resolves the rest again - until what is left resolves. Pins pip
# finds unusable for the target (uv ignores upper Requires-Python bounds) are excluded with
# a "name!=version" constraint first, so uv can pick another version; only when no version
# fits is the requirement set aside. The set-aside requirements are listed in the Add tab's
# "Review and publish" step; the rest becomes requirements.txt.

function Invoke-UvCompile {
    # One `uv pip compile` of -InputPath into -OutputPath. -Argument holds the options
    # (cooldown, Python, platform, ...); -ConstraintPath is added when given. Returns
    # @{ ExitCode; Output = string[] }. Kept apart so tests can replace uv.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$InputPath,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [AllowEmptyCollection()]
        [string[]]$Argument = @(),

        [string]$ConstraintPath = ''
    )

    $uvArgs = @('pip', 'compile', $InputPath) + @($Argument) + @('-o', $OutputPath)
    if ($ConstraintPath) { $uvArgs += @('--constraints', $ConstraintPath) }
    [string[]]$output = Invoke-NativeCommand -FilePath uv -ArgumentList $uvArgs -PassThru
    return @{ ExitCode = $LASTEXITCODE; Output = $output }
}

function Get-UvRequiredName {
    # The requirements uv's error output blames: every "you require X", then every "X was not
    # found in the package registry" (normalized, each once). Empty when the output names none.
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowEmptyCollection()]
        [string[]]$Output = @()
    )

    $text = (@($Output) -join ' ') -replace '\s+', ' '
    $names = [System.Collections.Generic.List[string]]::new()
    $patterns = @(
        '(?i)you require (?<name>[A-Za-z0-9][A-Za-z0-9._-]*)'
        '(?i)because (?<name>[A-Za-z0-9][A-Za-z0-9._-]*) was not found in the package registry'
    )
    foreach ($pattern in $patterns) {
        foreach ($match in [regex]::Matches($text, $pattern)) {
            $name = Get-NormalizedPackageName $match.Groups['name'].Value
            if (-not $names.Contains($name)) { $names.Add($name) }
        }
    }
    Write-Output -NoEnumerate $names.ToArray()
}

function Get-UvResolveReason {
    # Why uv could not resolve -Name, in plain words, from its error output: { Reason; Kind
    # (cooldown | no-wheel | not-found | no-version | conflict); Expedite (name==version
    # whose cooldown would have to be skipped, or '') }. -Unusable (name -> version) are
    # pins pip found unusable for -Target earlier in the same resolve.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [AllowEmptyCollection()]
        [string[]]$Output = @(),

        [hashtable]$Unusable = @{},

        [string]$Target = '',

        [int]$MinimumAgeDays = 0
    )

    $name = Get-NormalizedPackageName $Name
    $text = (@($Output) -join ' ') -replace '\s+', ' '
    $needs = {
        param([string]$Other)
        if ($Other -and $Other -ne $name) { " - $name needs it" } else { '' }
    }

    # The cooldown: uv's hint names the package, the version and its upload time.
    $hint = [regex]::Match($text, '(?i)`(?<pkg>[^`]+)` was filtered by `exclude-newer`.*?The requested version, v?(?<ver>[^\s,]+), was published at (?<pub>\d{4}-\d{2}-\d{2}T[0-9:.]+Z?)')
    if ($hint.Success) {
        $pkg = Get-NormalizedPackageName $hint.Groups['pkg'].Value
        $version = $hint.Groups['ver'].Value.TrimEnd('.')
        $published = $null
        try { $published = ConvertTo-UtcDateTime -Value $hint.Groups['pub'].Value } catch { $published = $null }
        $when = if ($published) {
            " on $($published.ToString('yyyy-MM-dd')); the cooldown of $MinimumAgeDays day(s) allows it from $($published.AddDays($MinimumAgeDays).ToString('yyyy-MM-dd'))"
        }
        else { " less than $MinimumAgeDays day(s) ago (cooldown)" }
        return @{ Reason = "too new: $pkg==$version was uploaded$when$(& $needs $pkg)"; Kind = 'cooldown'; Expedite = "$pkg==$version" }
    }
    # A pin pip found unusable earlier, now excluded.
    foreach ($key in @($Unusable.Keys | Sort-Object)) {
        if ($key -eq $name -or $text -match "(?i)(?<![A-Za-z0-9._-])$([regex]::Escape($key))(?![A-Za-z0-9_-])") {
            return @{ Reason = "$key==$($Unusable[$key]) has no usable wheel$(if ($Target) { " for $Target" }) (no compatible wheel, or Requires-Python excludes it), and no other version fits$(& $needs $key)"; Kind = 'no-wheel'; Expedite = '' }
        }
    }
    $noWheel = [regex]::Match($text, '(?i)(?<pkg>[A-Za-z0-9][A-Za-z0-9._-]*)==(?<ver>[^\s,]+) has no usable wheels')
    if ($noWheel.Success) {
        $pkg = Get-NormalizedPackageName $noWheel.Groups['pkg'].Value
        return @{ Reason = "$pkg==$($noWheel.Groups['ver'].Value) has no wheel$(if ($Target) { " for $Target" }) (only a source archive, and building from source is off)$(& $needs $pkg)"; Kind = 'no-wheel'; Expedite = '' }
    }
    $notFound = [regex]::Match($text, '(?i)because (?<pkg>[A-Za-z0-9][A-Za-z0-9._-]*) was not found in the package registry')
    if ($notFound.Success) {
        $pkg = Get-NormalizedPackageName $notFound.Groups['pkg'].Value
        return @{ Reason = "$pkg was not found on PyPI - check the name$(& $needs $pkg)"; Kind = 'not-found'; Expedite = '' }
    }
    $noVersion = [regex]::Match($text, '(?i)there is no version of (?<pkg>[A-Za-z0-9][A-Za-z0-9._-]*)(?<spec>[=<>!~][^\s,]*)?')
    if ($noVersion.Success) {
        $pkg = Get-NormalizedPackageName $noVersion.Groups['pkg'].Value
        return @{ Reason = "no version of $pkg$($noVersion.Groups['spec'].Value) is available$(if ($Target) { " for $Target" })$(& $needs $pkg)"; Kind = 'no-version'; Expedite = '' }
    }
    $cause = [regex]::Match($text, '(?i)because (?<why>.+?)(we can conclude|hint:|$)')
    $why = if ($cause.Success) { "because $($cause.Groups['why'].Value.Trim())" } else { 'see the job log' }
    if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
    return @{ Reason = "cannot be resolved: $why"; Kind = 'conflict'; Expedite = '' }
}

function Invoke-RequirementResolve {
    # Resolves -Requirement ({ name; spec; source }, in priority order - a requirement kept
    # from an earlier resolve before a new one) into -OutputPath, setting aside each
    # requirement that cannot be resolved instead of failing on the first (see the top of
    # this file). Each round either resolves, excludes an unusable pin (-WheelCheck) or sets
    # a requirement aside, so it ends. Returns @{ Ok; Resolved = the requirements in
    # -OutputPath; SetAside = [{ name; spec; source; reason; kind; expedite }]; Error =
    # message when it stopped without a result (requirements.txt must not change) }.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Requirement,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        # uv options without the input, -o and --constraints.
        [AllowEmptyCollection()]
        [string[]]$Argument = @(),

        # Constraint lines (e.g. denylisted versions as "name!=version").
        [AllowEmptyCollection()]
        [string[]]$ConstraintLine = @(),

        # A requirements.txt whose pins uv should keep where they still fit (-PreferCurrent).
        [string]$PreferPath = '',

        [Parameter(Mandatory)]
        [string]$PythonVersion,

        [Parameter(Mandatory)]
        [string]$Platform,

        [int]$MinimumAgeDays = 0,

        # Check the result with pip (Test-RequirementWheelAvailability). Off only in tests.
        [bool]$WheelCheck = $true
    )

    $target = "Python $PythonVersion / $Platform"
    $active = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Requirement) { if ($item) { $active.Add($item) } }
    $setAside = [System.Collections.Generic.List[object]]::new()
    $constraints = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $ConstraintLine) { if ($line) { $constraints.Add($line) } }
    $unusable = @{}
    $uvArgument = @($Argument)
    $prefer = $PreferPath
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("wheelhouse-resolve-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null

    $compile = {
        param([object[]]$Items, [string]$Into)
        $inputPath = Join-Path $work 'requirements.in'
        Set-Content -LiteralPath $inputPath -Value @($Items | ForEach-Object { $_.spec }) -Encoding utf8
        $constraintPath = ''
        if ($constraints.Count -gt 0) {
            $constraintPath = Join-Path $work 'constraints.txt'
            Set-Content -LiteralPath $constraintPath -Value $constraints.ToArray() -Encoding ascii
        }
        Remove-Item -LiteralPath $Into -Force -ErrorAction SilentlyContinue
        if ($prefer -and (Test-Path -LiteralPath $prefer -PathType Leaf)) { Copy-Item -LiteralPath $prefer -Destination $Into -Force }
        return (Invoke-UvCompile -InputPath $inputPath -OutputPath $Into -Argument $uvArgument -ConstraintPath $constraintPath)
    }
    $putAside = {
        param($Item, [hashtable]$Why)
        [void]$active.Remove($Item)
        $setAside.Add([PSCustomObject]@{ name = $Item.name; spec = $Item.spec; source = $Item.source; reason = $Why.Reason; kind = $Why.Kind; expedite = $Why.Expedite })
        Write-Log "  Set aside: $($Item.spec) - $($Why.Reason)" 'WARN'
    }

    try {
        $limit = 3 * $active.Count + 10
        for ($round = 1; $round -le $limit; $round++) {
            if ($active.Count -eq 0) {
                Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
                return @{ Ok = $true; Resolved = @(); SetAside = $setAside.ToArray(); Error = $null }
            }
            $run = & $compile $active.ToArray() $OutputPath
            if ($run.ExitCode -eq 0) {
                if (-not $WheelCheck) { return @{ Ok = $true; Resolved = $active.ToArray(); SetAside = $setAside.ToArray(); Error = $null } }
                Write-Log "Checking with pip that every resolved package has a usable wheel for $target..."
                $check = Test-RequirementWheelAvailability -RequirementsFilePath $OutputPath -PythonVersion $PythonVersion -Platform $Platform
                if ($check.Passed) { return @{ Ok = $true; Resolved = $active.ToArray(); SetAside = $setAside.ToArray(); Error = $null } }
                if ($check.Error) { return @{ Ok = $false; Resolved = @(); SetAside = $setAside.ToArray(); Error = $check.Error } }
                # uv picked versions pip cannot use: exclude them, so uv picks others.
                $excluded = $false
                foreach ($pin in @($check.Unavailable)) {
                    $parts = ([string]$pin) -split '==', 2
                    $pinName = Get-NormalizedPackageName $parts[0]
                    $line = "$pinName!=$($parts[1])"
                    if ($constraints.Contains($line)) { continue }
                    $constraints.Add($line)
                    $unusable[$pinName] = $parts[1]
                    $excluded = $true
                    Write-Log "  $pinName==$($parts[1]) has no usable wheel for $target - resolving again without it." 'WARN'
                }
                if ($excluded) { continue }
                return @{ Ok = $false; Resolved = @(); SetAside = $setAside.ToArray(); Error = "pip still finds unusable pins after excluding them: $(@($check.Unavailable) -join ', ')" }
            }

            # uv failed: which requirement(s) does it blame?
            $activeNames = @($active | ForEach-Object { $_.name })
            [string[]]$named = Get-UvRequiredName -Output $run.Output
            $blamed = @($active | Where-Object { $named -contains $_.name })
            if ($blamed.Count -eq 1) {
                & $putAside $blamed[0] (Get-UvResolveReason -Name $blamed[0].name -Output $run.Output -Unusable $unusable -Target $target -MinimumAgeDays $MinimumAgeDays)
                continue
            }
            # Several (or none): try the suspects one by one; whichever fails on its own goes.
            $suspects = if ($blamed.Count -gt 1) { $blamed } else { @($active.ToArray()) }
            $probeOut = Join-Path $work 'probe.txt'
            $failedAlone = 0
            foreach ($item in $suspects) {
                $probe = & $compile @($item) $probeOut
                if ($probe.ExitCode -ne 0) {
                    & $putAside $item (Get-UvResolveReason -Name $item.name -Output $probe.Output -Unusable $unusable -Target $target -MinimumAgeDays $MinimumAgeDays)
                    $failedAlone++
                }
            }
            if ($failedAlone -gt 0) { continue }
            if ($blamed.Count -gt 1) {
                # Each resolves on its own, not together: keep the first, set aside the others.
                $keep = $blamed[0]
                $why = Get-UvResolveReason -Name $keep.name -Output $run.Output -Unusable $unusable -Target $target -MinimumAgeDays $MinimumAgeDays
                foreach ($item in @($blamed | Select-Object -Skip 1)) {
                    & $putAside $item @{ Reason = "conflicts with $($keep.spec): $($why.Reason -replace '^cannot be resolved: ', '')"; Kind = 'conflict'; Expedite = '' }
                }
                continue
            }
            $message = @($run.Output | Where-Object { $_ -match '(?i)error|because|no solution' } | Select-Object -First 3) -join ' '
            return @{ Ok = $false; Resolved = @(); SetAside = $setAside.ToArray(); Error = $(if ($message) { $message } else { "uv pip compile failed (exit code $($run.ExitCode)) without naming a requirement ($($activeNames -join ', '))." }) }
        }
        return @{ Ok = $false; Resolved = @(); SetAside = $setAside.ToArray(); Error = "Gave up after $limit attempts to resolve - see the job log." }
    }
    finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function ConvertFrom-RequirementSpec {
    # "pandas[excel] >= 2.0 # comment" -> { name = 'pandas'; spec = 'pandas[excel] >= 2.0';
    # specifier = '>=2.0' }, or $null for a blank or comment line.
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Line
    )

    $spec = ($Line -replace '(^|\s)#.*$', '').Trim()
    if ($spec -eq '' -or $spec -notmatch '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(?<rest>.*)$') { return $null }
    return [PSCustomObject]@{ name = (Get-NormalizedPackageName $Matches['name']); spec = $spec; specifier = $Matches['rest'].Replace(' ', '') }
}

function Get-RequirementResolveInput {
    # What a resolve of requirements.in starts from: { Requirements = [{ name; spec; source }]
    # (kept pins first, then the new lines); Ignored = [{ spec; pin }]; SetAside = the earlier
    # set-aside entries still open }. requirements.txt keeps growing until it is published:
    #   - every pin of the current requirements.txt that was asked for (not only a dependency)
    #     is kept as "name==version" (source 'kept'); its dependencies are resolved again;
    #   - a new line for a package requirements.txt already pins at a version the line
    #     accepts is ignored - the pin stays (and counts as asked for);
    #   - a new line for a package pinned at a version it does not accept replaces the pin;
    #   - a new line for a set-aside package tries it again (the set-aside entry goes).
    # Pins the denylist blocks are dropped.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowEmptyCollection()]
        [string[]]$InLine = @(),

        [AllowEmptyString()]
        [string]$RequirementsTxtPath = '',

        [AllowEmptyCollection()]
        [object[]]$Denylist = @(),

        [AllowEmptyCollection()]
        [object[]]$SetAside = @()
    )

    $new = [ordered]@{}
    foreach ($line in $InLine) {
        $item = ConvertFrom-RequirementSpec -Line $line
        if ($item -and -not $new.Contains($item.name)) { $new[$item.name] = $item }
    }
    $pins = @{}
    $sources = @{}
    if ($RequirementsTxtPath -and (Test-Path -LiteralPath $RequirementsTxtPath -PathType Leaf) -and ([System.IO.File]::ReadAllText($RequirementsTxtPath)).Trim()) {
        $pins = Read-RequirementFile -FilePath $RequirementsTxtPath
        $sources = Read-RequirementDependent -FilePath $RequirementsTxtPath -IncludeSource
    }

    $requirements = [System.Collections.Generic.List[object]]::new()
    $ignored = [System.Collections.Generic.List[object]]::new()
    foreach ($name in @($pins.Keys | Sort-Object)) {
        $version = [string]$pins[$name]
        if (Get-DenylistMatch -Name $name -Version $version -Denylist $Denylist) { continue }
        [string[]]$from = @()
        if ($sources.ContainsKey($name)) { $from = $sources[$name] }
        if ($new.Contains($name)) {
            if ($true -ne (Test-VersionSpecifier -Version $version -Specifier $new[$name].specifier)) { continue }
            $ignored.Add([PSCustomObject]@{ spec = $new[$name].spec; pin = "$name==$version" })
            $new.Remove($name)
        }
        elseif (-not (Test-RequirementTxtDirect -Source $from)) { continue }
        $requirements.Add([PSCustomObject]@{ name = $name; spec = "$name==$version"; source = 'kept' })
    }
    foreach ($name in $new.Keys) { $requirements.Add([PSCustomObject]@{ name = $name; spec = $new[$name].spec; source = 'input' }) }
    $requested = @{}
    foreach ($item in $requirements) { $requested[$item.name] = $true }
    $open = @(foreach ($item in $SetAside) { if ($item -and -not $requested.ContainsKey([string]$item.name)) { $item } })
    return @{ Requirements = $requirements.ToArray(); Ignored = $ignored.ToArray(); SetAside = $open }
}
