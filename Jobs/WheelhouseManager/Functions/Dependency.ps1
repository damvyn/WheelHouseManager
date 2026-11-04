# ---------------------------------------------------------------------------
# Dependencies between published packages (Requires-Dist of each wheel)
# ---------------------------------------------------------------------------
# Intake holds back a package whose dependency is rejected (Get-DependentRejection, from
# requirements.txt's "# via" annotations). Once published, a dependency can still fail a
# later check (a new advisory, yanked, denylisted, removed or changed on the share). The
# packages that need it stay published - they are installed on clients, and the fix is a
# new version of the dependency (remediation) - but every finding and notice names them, so
# an administrator sees what else is affected. The catalog records each published version's
# Requires-Dist (read once from its wheel) for this.

function Read-WheelRequirement {
    # The Requires-Dist entries of a wheel's METADATA as [PSCustomObject]@{ name (normalized);
    # spec (version specifier, '' for any); marker }. Entries that apply only to an extra
    # (marker "extra == ...") are left out: installing the package does not pull them in.
    # Throws when the file is not a readable wheel.
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entry = @($zip.Entries | Where-Object { $_.FullName -match '^[^/]+\.dist-info/METADATA$' })[0]
        if ($null -eq $entry) { throw "No .dist-info/METADATA in $(Split-Path -Path $Path -Leaf)." }
        $reader = [System.IO.StreamReader]::new($entry.Open(), [System.Text.Encoding]::UTF8)
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    }
    finally {
        $zip.Dispose()
    }

    $requires = [System.Collections.Generic.List[object]]::new()
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -eq '') { break }   # the headers end at the first blank line
        if ($line -notmatch '^Requires-Dist:\s*(?<value>.+)$') { continue }
        $value = $Matches['value']
        $requirement, $marker = $value -split ';', 2
        $marker = if ($marker) { $marker.Trim() } else { '' }
        if ($marker -match '\bextra\s*==') { continue }
        if ($requirement -notmatch '^\s*(?<name>[A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(?<spec>.*)$') { continue }
        $requires.Add([PSCustomObject]@{
                name   = Get-NormalizedPackageName $Matches['name']
                spec   = $Matches['spec'].Trim().TrimStart('(').TrimEnd(')').Trim()
                marker = $marker
            })
    }
    return $requires.ToArray()
}

function Test-VersionSpecifier {
    # Whether -Version satisfies a PEP 440 specifier such as ">=1.21.1,<3" or "~=2.0" or
    # "==2.*". $true / $false, or $null when a clause cannot be evaluated (then the caller
    # should assume it may match). An empty specifier matches any version.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Version,

        [AllowEmptyString()]
        [string]$Specifier = ''
    )

    $unknown = $false
    foreach ($clause in ($Specifier -split ',')) {
        $clause = $clause.Trim()
        if ($clause -eq '') { continue }
        if ($clause -notmatch '^(?<op>~=|===|==|!=|<=|>=|<|>)\s*(?<v>\S+)$') { $unknown = $true; continue }
        $op = $Matches['op']
        $target = $Matches['v']
        if ($op -eq '===') {
            if ($Version -ne $target) { return $false }
            continue
        }
        try {
            if ($target.EndsWith('.*')) {
                if ($op -notin '==', '!=') { $unknown = $true; continue }
                $prefix = ConvertTo-PackageVersionKey -Version $target.Substring(0, $target.Length - 2)
                $key = ConvertTo-PackageVersionKey -Version $Version
                if ($null -eq $prefix -or $null -eq $key) { $unknown = $true; continue }
                $same = $key.Epoch -eq $prefix.Epoch
                for ($i = 0; $same -and $i -lt $prefix.Release.Count; $i++) {
                    $part = if ($i -lt $key.Release.Count) { $key.Release[$i] } else { 0 }
                    if ($part -ne $prefix.Release[$i]) { $same = $false }
                }
                if (($op -eq '==') -ne $same) { return $false }
                continue
            }
            $cmp = Compare-PackageVersion -Left $Version -Right $target
            $ok = switch ($op) {
                '==' { $cmp -eq 0 }
                '!=' { $cmp -ne 0 }
                '<=' { $cmp -le 0 }
                '>=' { $cmp -ge 0 }
                '<' { $cmp -lt 0 }
                '>' { $cmp -gt 0 }
                '~=' {
                    $parts = @($target -split '\.')
                    if ($parts.Count -lt 2) { $null }
                    else {
                        $compatible = Test-VersionSpecifier -Version $Version -Specifier "==$(($parts[0..($parts.Count - 2)]) -join '.').*"
                        if ($null -eq $compatible) { $null } else { $cmp -ge 0 -and $compatible }
                    }
                }
            }
            if ($null -eq $ok) { $unknown = $true }
            elseif (-not $ok) { return $false }
        }
        catch {
            $unknown = $true
        }
    }
    if ($unknown) { return $null }
    return $true
}

function Update-CatalogRequirement {
    # Fills "requires" (Read-WheelRequirement) for every Published record that has not been
    # read yet - once per version, from its first wheel file. A wheel that cannot be read is
    # tried again next time. Returns $true if any record changed; the caller saves.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Catalog
    )

    $changed = $false
    foreach ($key in @($Catalog.Records.Keys)) {
        $record = $Catalog.Records[$key]
        if ($record.state -ne 'Published' -or $record.requires_checked -or @($record.files).Count -eq 0) { continue }
        $path = Join-Path $Catalog.WheelhousePath ([string]@($record.files)[0])
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        if (-not $PSCmdlet.ShouldProcess($key, 'Record Requires-Dist')) { continue }
        try {
            $record.requires = @(Read-WheelRequirement -Path $path | ForEach-Object { [PSCustomObject]@{ name = $_.name; spec = $_.spec } })
            $record.requires_checked = $true
            $changed = $true
        }
        catch {
            Write-Verbose "Could not read the dependencies of ${key}: $($_.Exception.Message)"
        }
    }
    return $changed
}

function Get-CatalogDependent {
    # The published versions that need -Name at -Version: their recorded Requires-Dist names
    # it, with a specifier that accepts -Version (or one that cannot be evaluated). Returns
    # [PSCustomObject]@{ Name; Version; Requirement = "name spec" }, sorted.
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        $Catalog,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version
    )

    $name = Get-NormalizedPackageName $Name
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($key in @($Catalog.Records.Keys | Sort-Object)) {
        $record = $Catalog.Records[$key]
        if ($record.state -ne 'Published' -or $record.name -eq $name) { continue }
        foreach ($requirement in @($record.requires)) {
            if ($null -eq $requirement -or $requirement.name -ne $name) { continue }
            if ($false -eq (Test-VersionSpecifier -Version $Version -Specifier ([string]$requirement.spec))) { continue }
            $found.Add([PSCustomObject]@{
                    Name        = $record.name
                    Version     = $record.version
                    Requirement = ("$name $($requirement.spec)").Trim()
                })
            break
        }
    }
    return $found.ToArray()
}

function Format-CatalogDependent {
    # "requests==2.32.3 (needs urllib3<3,>=1.21.1)" for each Get-CatalogDependent result.
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowEmptyCollection()]
        [object[]]$Dependent = @()
    )

    return [string[]]@(foreach ($item in $Dependent) { "$($item.Name)==$($item.Version) (needs $($item.Requirement))" })
}

function Add-WheelhouseNoticeDependent {
    # Adds the published packages that need a notice's package (Get-CatalogDependent) to
    # every notice about a published version that clients can no longer trust or install
    # (Denylisted, Yanked, FileMissing, FileModified, Malicious): sets NeededBy and appends
    # them to the Message. Returns the notices.
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Notice = @(),

        [Parameter(Mandatory)]
        $Catalog
    )

    foreach ($item in $Notice) {
        if ($null -eq $item) { continue }
        if ($item.Kind -in 'Denylisted', 'Yanked', 'FileMissing', 'FileModified', 'Malicious' -and $item.Package -and $item.Version) {
            $neededBy = Format-CatalogDependent -Dependent (Get-CatalogDependent -Catalog $Catalog -Name $item.Package -Version $item.Version)
            if ($neededBy.Count -gt 0) {
                $item.NeededBy = $neededBy
                $item.Message = "$($item.Message) Published package(s) that need it: $($neededBy -join '; '). They stay published - check that they still install, and update them together with this one."
            }
        }
        $item
    }
}
