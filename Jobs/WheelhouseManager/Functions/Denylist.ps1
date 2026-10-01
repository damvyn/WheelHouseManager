# ---------------------------------------------------------------------------
# config\denylist.json: packages that must never enter the wheelhouse
# ---------------------------------------------------------------------------
# One entry per blocked package:
#   name       normalized package name
#   version    exact version, or '*' for every version
#   reason     free text
#   added_utc  ISO 8601 timestamp
#   added_by   Windows user that added it
#   source     'manual' (typed in the UI), 'removed' or 'quarantined' (added
#              automatically when a package was taken out of the wheelhouse)

$script:DenylistNamePattern = '^[A-Za-z0-9][A-Za-z0-9._-]*$'
$script:DenylistVersionPattern = '^(\*|[A-Za-z0-9][A-Za-z0-9._+!-]*)$'

function Get-WheelhouseDenylistPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$ManagerRoot = $script:ManagerRoot
    )

    return Join-Path (Join-Path $ManagerRoot 'config') 'denylist.json'
}

function Read-WheelhouseDenylist {
    # Returns the denylist entries (empty if the file does not exist). Throws if the
    # file exists but cannot be parsed: a damaged denylist must never be silently
    # treated as "nothing is blocked".
    [CmdletBinding()]
    param(
        [string]$Path = (Get-WheelhouseDenylistPath)
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -Path $Path) {
        $content = Get-Content -Path $Path -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($content)) {
            try {
                $parsed = ConvertFrom-Json -InputObject $content -ErrorAction Stop
            }
            catch {
                throw "denylist.json exists but could not be parsed ($($_.Exception.Message)). Fix or remove '$Path' before continuing."
            }
            foreach ($entry in $parsed) { $entries.Add($entry) }
        }
    }
    # Plain return (no -NoEnumerate): callers wrap the call in @() as usual.
    return $entries.ToArray()
}

function Get-DenylistMatch {
    # Returns the first denylist entry that blocks name==version, or $null.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version,

        [AllowEmptyCollection()]
        [object[]]$Denylist = @()
    )

    $normalized = Get-NormalizedPackageName $Name
    foreach ($entry in $Denylist) {
        if ($entry.name -ne $normalized) { continue }
        if ($entry.version -eq '*' -or [string]::Equals([string]$entry.version, $Version, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $entry
        }
    }
    return $null
}

function Add-WheelhouseDenylistEntry {
    # Adds a package to the denylist, or updates the reason of an existing entry for
    # the same name and version. Returns the entry.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Version = '*',

        [string]$Reason = '',

        [ValidateSet('manual', 'removed', 'quarantined')]
        [string]$Source = 'manual',

        [string]$Path = (Get-WheelhouseDenylistPath)
    )

    if ($Name -notmatch $script:DenylistNamePattern) {
        throw [System.ArgumentException]::new("Invalid package name: '$Name'.")
    }
    if ([string]::IsNullOrWhiteSpace($Version)) { $Version = '*' }
    $Version = $Version.Trim()
    if ($Version -notmatch $script:DenylistVersionPattern) {
        throw [System.ArgumentException]::new("Invalid version: '$Version'. Use an exact version such as 1.2.3, or * for every version.")
    }
    if ($null -eq $Reason) { $Reason = '' }
    if ($Reason.Length -gt 500) {
        throw [System.ArgumentException]::new('The reason is too long (500 characters at most).')
    }

    $normalized = Get-NormalizedPackageName $Name
    $entry = [PSCustomObject]@{
        name      = $normalized
        version   = $Version
        reason    = $Reason.Trim()
        added_utc = (Get-Date).ToUniversalTime().ToString('o')
        added_by  = $(if ($env:USERNAME) { $env:USERNAME } else { 'unknown' })
        source    = $Source
    }

    $entries = @(Read-WheelhouseDenylist -Path $Path | Where-Object {
            -not ($_.name -eq $normalized -and [string]::Equals([string]$_.version, $Version, [System.StringComparison]::OrdinalIgnoreCase))
        })
    $entries += $entry

    if ($PSCmdlet.ShouldProcess($Path, "Deny $normalized $Version")) {
        $folder = Split-Path -Path $Path -Parent
        if ($folder -and -not (Test-Path -Path $folder)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
        }
        Write-JsonFile -Path $Path -InputObject @($entries | Sort-Object name, version) -Depth 3
        Write-Log "Denylist: $normalized $Version blocked ($Source)." 'WARN'
    }
    return $entry
}

function Remove-WheelhouseDenylistEntry {
    # Removes the entry for name + version. Returns $true if an entry was removed.
    # With -OnlySource, an entry from a different source is left alone.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Version = '*',

        [ValidateSet('manual', 'removed', 'quarantined')]
        [string[]]$OnlySource,

        [string]$Path = (Get-WheelhouseDenylistPath)
    )

    if ([string]::IsNullOrWhiteSpace($Version)) { $Version = '*' }
    $normalized = Get-NormalizedPackageName $Name
    $all = @(Read-WheelhouseDenylist -Path $Path)
    $sources = @($OnlySource | Where-Object { $_ })

    $isTarget = {
        param($entry)
        $entry.name -eq $normalized -and
        [string]::Equals([string]$entry.version, $Version, [System.StringComparison]::OrdinalIgnoreCase) -and
        (($sources.Count -eq 0) -or ($sources -contains $entry.source))
    }
    $remaining = @($all | Where-Object { -not (& $isTarget $_) })
    if ($remaining.Count -eq $all.Count) { return $false }

    if ($PSCmdlet.ShouldProcess($Path, "Allow $normalized $Version again")) {
        Write-JsonFile -Path $Path -InputObject $remaining -Depth 3
        Write-Log "Denylist: $normalized $Version removed from the denylist." 'OK'
    }
    return $true
}

function Get-DenylistConstraintLine {
    # "name!=version" lines for `uv pip compile --constraints`, so the resolver
    # steers around a blocked version where a different one satisfies requirements.in.
    # Entries that block every version cannot be expressed as a constraint; the
    # intake check rejects those.
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowEmptyCollection()]
        [object[]]$Denylist = @()
    )

    $lines = @($Denylist | Where-Object { $_.version -ne '*' } | ForEach-Object { "$($_.name)!=$($_.version)" })
    Write-Output -NoEnumerate ([string[]]$lines)
}
