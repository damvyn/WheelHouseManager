# ---------------------------------------------------------------------------
# Remediation: replace a vulnerable published version with a fixed one
# ---------------------------------------------------------------------------
# Get-WheelhouseRemediationPlan works out the fix from the catalog's findings (their fix
# versions) and PyPI's release list: the lowest version that fixes every open advisory, and
# whether a version at least that high is old enough for the cooldown. The requirements.in
# line becomes "name>=fix" (upper bounds kept), so the resolver picks the newest fixed
# version the cooldown allows; when none is old enough, the plan pins "name==fix" and the
# publish must expedite it (with a reason). Invoke-WheelhouseRemediation.ps1 applies the
# plan: edit requirements.in, resolve, and propose the result as a remediation, which the
# update run publishes in place of the vulnerable version and then quarantines that.

function Get-RequirementInLine {
    # The requirements.in line for a package: { Index; Line; Name; Extras; Clauses[] } or
    # $null. Comments and blank lines are skipped; names compare normalized.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Lines,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $normalized = Get-NormalizedPackageName $Name
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $clean = ($Lines[$i] -replace '(^|\s)#.*$', '').Trim()
        if ($clean -notmatch '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?<extras>\[[^\]]*\])?\s*(?<rest>.*)$') { continue }
        if ((Get-NormalizedPackageName $Matches['name']) -ne $normalized) { continue }
        $rest = $Matches['rest'].Replace(' ', '')
        return [PSCustomObject]@{
            Index   = $i
            Line    = $Lines[$i]
            Name    = $Matches['name']
            Extras  = [string]$Matches['extras']
            Clauses = @($rest -split ',' | Where-Object { $_ })
        }
    }
    return $null
}

function Get-WheelhouseRemediationPlan {
    # Plans the fix for a published, vulnerable name==version. Returns { Name; Version;
    # Ids[]; Unfixable[] (advisories without a fix version); FixVersion (lowest version that
    # fixes every fixable advisory); Eligible (versions >= FixVersion, not yanked, older than
    # the cooldown); NeedsExpedite; ExpediteVersion; EligibleUtc; OldLine; NewLine; Summary }.
    # Throws when the version has no open finding or nothing can fix it.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version,

        [Parameter(Mandatory)]
        [string]$RequirementsInPath,

        [ValidateRange(0, 3650)]
        [int]$MinimumAgeDays = 10
    )

    $normalized = Get-NormalizedPackageName $Name
    $catalog = Read-WheelhouseCatalog -WheelhousePath $WheelhousePath
    $record = $catalog.Records["$normalized==$Version"]
    if (-not $record -or $record.state -ne 'Published') { throw [System.Collections.Generic.KeyNotFoundException]::new("$normalized==$Version is not a published version.") }
    $open = @($record.findings | Where-Object { $_ -and -not $_.resolved_utc })
    if ($open.Count -eq 0) { throw [System.InvalidOperationException]::new("$normalized==$Version has no open vulnerability to fix.") }

    $floors = [System.Collections.Generic.List[string]]::new()
    $unfixable = [System.Collections.Generic.List[string]]::new()
    foreach ($finding in $open) {
        $higher = @($finding.fix_versions | Where-Object { $_ -and (ConvertTo-PackageVersionKey -Version $_) -and (Compare-PackageVersion -Left $_ -Right $Version) -gt 0 })
        if ($higher.Count -eq 0) { $unfixable.Add($finding.id); continue }
        $lowest = $higher[0]
        foreach ($candidate in $higher) { if ((Compare-PackageVersion -Left $candidate -Right $lowest) -lt 0) { $lowest = $candidate } }
        $floors.Add($lowest)
    }
    if ($floors.Count -eq 0) {
        throw [System.InvalidOperationException]::new("No fixed version of $normalized is known for $($unfixable -join ', '). Remove the package, pin another one, or accept the risk with a waiver.")
    }
    $fix = $floors[0]
    foreach ($floor in $floors) { if ((Compare-PackageVersion -Left $floor -Right $fix) -gt 0) { $fix = $floor } }

    $now = (Get-Date).ToUniversalTime()
    $releases = @(Get-PyPIProjectRelease -Name $normalized | Where-Object {
            (ConvertTo-PackageVersionKey -Version $_.Version) -and -not $_.Yanked -and (Compare-PackageVersion -Left $_.Version -Right $fix) -ge 0
        })
    # Final releases only, unless the fix itself is a pre-release.
    $fixKey = ConvertTo-PackageVersionKey -Version $fix
    if ($fixKey.Phase -eq 4) { $releases = @($releases | Where-Object { (ConvertTo-PackageVersionKey -Version $_.Version).Phase -eq 4 }) }
    if ($releases.Count -eq 0) { throw [System.InvalidOperationException]::new("PyPI has no usable release of $normalized at or above $fix (all yanked, or not published yet).") }
    $eligible = @($releases | Where-Object { $_.FirstUploadUtc -and ($now - $_.FirstUploadUtc).TotalDays -ge $MinimumAgeDays })
    $lowestRelease = $releases[0]
    foreach ($release in $releases) { if ((Compare-PackageVersion -Left $release.Version -Right $lowestRelease.Version) -lt 0) { $lowestRelease = $release } }
    $needsExpedite = $eligible.Count -eq 0

    $lines = @()
    if (Test-Path -LiteralPath $RequirementsInPath) { $lines = @(Get-Content -LiteralPath $RequirementsInPath -ErrorAction Stop) }
    $current = Get-RequirementInLine -Lines $lines -Name $normalized
    $keep = @()
    $extras = ''
    $label = $normalized
    if ($current) {
        $label = $current.Name
        $extras = $current.Extras
        # Upper bounds and exclusions stay; every lower bound or pin is replaced by the fix.
        $keep = @($current.Clauses | Where-Object { $_ -match '^(<|!=)' })
    }
    $bound = if ($needsExpedite) { "==$($lowestRelease.Version)" } else { ">=$fix" }
    $newLine = "$label$extras" + (@($bound) + @($keep) -join ',')

    $ids = @($open | ForEach-Object { $_.id })
    $summary = if ($needsExpedite) {
        "Fix $normalized==$Version ($($ids -join ', ')): $($lowestRelease.Version) is the lowest fixed release, but no fixed release is older than the $MinimumAgeDays-day cooldown yet (eligible $($lowestRelease.FirstUploadUtc.AddDays($MinimumAgeDays).ToString('yyyy-MM-dd'))). Publishing it now needs an expedite reason."
    }
    else {
        "Fix $normalized==$Version ($($ids -join ', ')): requirements.in gets '$newLine'; the resolver picks the newest fixed release the cooldown allows ($(@($eligible | ForEach-Object { $_.Version } | Select-Object -Last 3) -join ', ') ...)."
    }
    if ($unfixable.Count -gt 0) { $summary += " No fix is known yet for $($unfixable -join ', '); those stay open." }

    return [PSCustomObject]@{
        Name            = $normalized
        Version         = $Version
        Ids             = $ids
        Unfixable       = $unfixable.ToArray()
        FixVersion      = $fix
        Eligible        = @($eligible | ForEach-Object { $_.Version })
        NeedsExpedite   = $needsExpedite
        ExpediteVersion = $(if ($needsExpedite) { $lowestRelease.Version } else { '' })
        EligibleUtc     = $(if ($needsExpedite -and $lowestRelease.FirstUploadUtc) { $lowestRelease.FirstUploadUtc.AddDays($MinimumAgeDays).ToString('o') } else { '' })
        OldLine         = $(if ($current) { $current.Line.Trim() } else { '' })
        NewLine         = $newLine
        Summary         = $summary
    }
}

function Set-RequirementInSpec {
    # Writes -Line for the package in requirements.in: replaces the package's line, or appends
    # it (with -Comment above it) when the package is not listed - a dependency pulled in by
    # something else then becomes a direct requirement so the fix sticks.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Line,

        [string]$Comment = ''
    )

    if (-not (Test-PackageSpec -Spec $Line)) { throw [System.ArgumentException]::new("Not a valid requirement line: '$Line'.") }
    $lines = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $Path) { foreach ($item in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) { $lines.Add([string]$item) } }
    $current = Get-RequirementInLine -Lines $lines.ToArray() -Name $Name
    if (-not $PSCmdlet.ShouldProcess($Path, "Set $Line")) { return }
    if ($current) {
        $lines[$current.Index] = $Line
    }
    else {
        if ($Comment) { $lines.Add("# $Comment") }
        $lines.Add($Line)
    }
    Write-TextFileAtomic -Path $Path -Content ($lines -join "`r`n")
}
