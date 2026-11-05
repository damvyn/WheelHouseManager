<#
.SYNOPSIS
    Resolves requirements.in into a pinned requirements.txt using uv.

.DESCRIPTION
    Runs `uv pip compile` against -RequirementsInPath, applying the cooldown
    (-MinimumPackageAgeDays), target Python version and target platform, and writes
    the result to -RequirementsTxtPath. Does not touch the central wheelhouse - this
    only prepares the local file for review before Update-Wheelhouse.ps1 merges it in.

    The resolved file must be downloadable the way Update-Wheelhouse.ps1 downloads
    it (binary wheels only, for PythonVersion / Platform):
      - uv resolves with --only-binary :all: and --python-platform, so versions that
        only exist as source archives (e.g. numpy 1.26.4 on Python 3.14) are never
        picked.
      - uv ignores upper bounds on Requires-Python (e.g. "<3.14"), so the result is
        then checked with pip (`pip install --dry-run`, metadata only) - pip applies
        exactly the same rules as the later download.
    One run finds every requirement that cannot be resolved (Invoke-RequirementResolve):
    when uv fails, the requirement its error names is set aside with the reason (too new for
    the cooldown, no usable wheel, not on PyPI, a conflict) and the rest is resolved again.
    A pin pip cannot use is first excluded so uv can pick another version. What resolves is
    written to -RequirementsTxtPath; the set-aside requirements are recorded in
    requirements.status.json next to it and listed in the UI's "Review and publish" step
    (Remove them, or Expedite one that is only too new). When nothing usable comes out (uv
    fails without naming a requirement, pip cannot run), requirements.txt is left
    untouched and the result is saved as requirements.rejected.txt.

    When it resolved the configured requirements.in (settings RequirementsInPath), the pins
    of the current requirements.txt that were asked for are resolved together with it
    (requirements.txt grows until it is published), a new line for a package requirements.txt
    already pins at a fitting version is ignored, and afterwards requirements.in is emptied
    down to its comment lines: it only ever lists what is new.

    Exit codes: 0 written (possibly with set-aside requirements); 1 nothing could be
    resolved, or -NoSetAside and something was set aside - change requirements.in and run
    again; 2 the input file, python, uv or the platform mapping is missing.

    If called with no path parameters, both default to the Input\ folder next to
    this script's deployment (WheelHouseManager\Input\requirements.in / .txt) -
    the same files Setup.ps1 creates.

.PARAMETER RequirementsInPath
    Source file to resolve (default: <manager root>\Input\requirements.in).

.PARAMETER RequirementsTxtPath
    Where to write the resolved, pinned file (default: <manager root>\Input\requirements.txt).

.PARAMETER PythonVersion
    Target Python version (major.minor). Defaults to the value in config\settings.psd1,
    falling back to 3.14 if that's not set either.

.PARAMETER Platform
    Target wheel platform tag (default: settings.psd1's Platform, else win_amd64).

.PARAMETER PreferCurrent
    Kept for Invoke-WheelhouseRemediation.ps1. Every resolve now keeps the versions of the
    current requirements.txt wherever they still fit, so only what has to change changes.

.PARAMETER NoProposal
    Do not record a proposal for the result (Invoke-WheelhouseRemediation.ps1 records its
    own, with what to replace and retire).

.PARAMETER NoSetAside
    Fail (exit code 1, nothing written) instead of setting a requirement aside - for a fix,
    whose one requirement must resolve.

.PARAMETER ExpeditePackage
    name==version pins whose cooldown is skipped in the resolve (uv --exclude-newer-package,
    and the pin is kept at or below that version). The proposal records them, so the publish
    skips their cooldown too. Needs -ExpediteReason. What the current proposal expedited
    stays expedited.

.PARAMETER ExpediteReason
    Why the cooldown is skipped; recorded in the proposal.

.PARAMETER MinimumPackageAgeDays
    Cooldown window passed to `uv pip compile --exclude-newer`. Defaults to the value
    in config\settings.psd1, falling back to 10 if that's not set either.

.EXAMPLE
    .\Update-Requirement.ps1

.EXAMPLE
    .\Update-Requirement.ps1 -RequirementsInPath "C:\temp\requirements.in" -RequirementsTxtPath "C:\temp\requirements.txt"

.NOTES
    Requires the WheelhouseManager module folder next to this script, and config\settings.psd1
    one level up (<manager root>\config\settings.psd1).
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$RequirementsInPath,

    [ValidateNotNullOrEmpty()]
    [string]$RequirementsTxtPath,

    [ValidateNotNullOrEmpty()]
    [string]$PythonVersion,

    [ValidateNotNullOrEmpty()]
    [string]$Platform,

    [ValidateRange(0, 3650)]
    [int]$MinimumPackageAgeDays,

    [switch]$PreferCurrent,

    [switch]$NoProposal,

    [switch]$NoSetAside,

    [string[]]$ExpeditePackage,

    [string]$ExpediteReason
)

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$paramNames = @('RequirementsInPath', 'RequirementsTxtPath', 'PythonVersion', 'Platform', 'MinimumPackageAgeDays', 'WheelhousePath')
$whlParams = @{
    'BoundParameters' = $PSBoundParameters
    'Name' = $paramNames
    'SettingName' = @{ RequirementsTxtPath = 'LocalRequirementsPath' }
}
$cfg = Resolve-WheelhouseParameter @whlParams

Write-Log "=== Update-Requirement started ==="
Write-Log "Source (requirements.in): $($cfg.RequirementsInPath)"
Write-Log "Target (requirements.txt): $($cfg.RequirementsTxtPath)"
Write-Log "Target Python: $($cfg.PythonVersion) / $($cfg.Platform) | Cooldown: $($cfg.MinimumPackageAgeDays) day(s)"

if (-not (Test-Path -Path $cfg.RequirementsInPath)) {
    Write-Log "requirements.in not found: $($cfg.RequirementsInPath)" "ERROR"
    Write-Log "Run Setup.ps1 first, or pass -RequirementsInPath explicitly." "ERROR"
    exit 2
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Log "Python was not found on this machine - it is needed to verify the resolved packages." "ERROR"
    exit 2
}
if (-not (Get-Command uv -CommandType Application -ErrorAction SilentlyContinue)) {
    Write-Log "uv was not found on the PATH of this account - it resolves requirements.in. Install uv (https://docs.astral.sh/uv/) on this server; requirements.txt was not changed." "ERROR"
    exit 2
}

try {
    $uvPlatform = ConvertTo-UvPythonPlatform -Platform $cfg.Platform
}
catch {
    Write-Log $_.Exception.Message "ERROR"
    exit 2
}

# Resolve into a temporary file first - the real requirements.txt is only replaced
# once the result has passed the wheel check.
$targetFolder = Split-Path -Path $cfg.RequirementsTxtPath -Parent
$candidatePath = Join-Path $targetFolder "requirements.candidate.txt"
$rejectedPath = Join-Path $targetFolder "requirements.rejected.txt"
$target = "Python $($cfg.PythonVersion) / $($cfg.Platform)"

# requirements.in is emptied after every successful resolve of the configured file, so it
# only lists what is new; requirements.txt keeps what was asked for before (until it is
# published) and is resolved again together with it.
$configuredIn = (Get-WheelhouseDefaultSetting).RequirementsInPath
$configuredSetting = (Get-WheelhouseSetting)['RequirementsInPath']
if ($configuredSetting) { $configuredIn = $configuredSetting }
$clearInput = [bool]$configuredIn -and ([System.IO.Path]::GetFullPath($cfg.RequirementsInPath) -eq [System.IO.Path]::GetFullPath([string]$configuredIn))
$denylist = @(Read-WheelhouseDenylist)
[string[]]$inLines = @(Get-Content -LiteralPath $cfg.RequirementsInPath)
$previous = $null
try { $previous = Read-RequirementResolveStatus -RequirementsTxtPath $cfg.RequirementsTxtPath } catch { $previous = $null }
$inputParams = @{
    InLine              = $inLines
    RequirementsTxtPath = $(if ($clearInput) { $cfg.RequirementsTxtPath } else { '' })
    Denylist            = $denylist
    SetAside            = $(if ($clearInput -and $previous) { @($previous.set_aside) } else { @() })
}
$resolveInput = Get-RequirementResolveInput @inputParams
foreach ($item in $resolveInput.Ignored) { Write-Log "Already in requirements.txt as $($item.pin) - '$($item.spec)' is ignored." }
$kept = @($resolveInput.Requirements | Where-Object { $_.source -eq 'kept' })
if ($kept.Count -gt 0) { Write-Log "Kept from the current requirements.txt (asked for earlier, not published yet): $(($kept | ForEach-Object { $_.spec }) -join ', ')" }

# Cooldown skipped for single packages: -ExpeditePackage, and what the current proposal
# for requirements.txt expedited (it stays expedited while its pin is kept).
$expedite = @{}
$expediteWhy = [string]$ExpediteReason
foreach ($pin in @(ConvertTo-WheelhousePin -Pin @($ExpeditePackage | Where-Object { $_ }))) { $expedite[$pin.Name] = $pin.Version }
if ($expedite.Count -gt 0 -and [string]::IsNullOrWhiteSpace($expediteWhy)) {
    Write-Log '-ExpeditePackage needs -ExpediteReason: say why the cooldown is skipped.' 'ERROR'
    exit 2
}
if ($clearInput -and (Test-Path -LiteralPath $cfg.RequirementsTxtPath -PathType Leaf)) {
    try {
        $current = Read-WheelhouseProposal
        if ($current -and $current.requirements_sha256 -eq (Get-RequirementFileHash -Path $cfg.RequirementsTxtPath)) {
            foreach ($name in $current.expedite.Keys) { if (-not $expedite.ContainsKey($name)) { $expedite[$name] = [string]$current.expedite[$name] } }
            if (-not $expediteWhy) { $expediteWhy = $current.expedite_reason }
        }
    }
    catch { Write-Log "The current proposal could not be read ($($_.Exception.Message)); earlier expedited packages are not expedited again." 'WARN' }
}

$compileArgs = @(
    "--exclude-newer", "$($cfg.MinimumPackageAgeDays) days",
    "--python-version", $cfg.PythonVersion,
    "--python-platform", $uvPlatform,
    "--only-binary", ":all:",
    "--custom-compile-command", ".\Update-Requirement.ps1"
)
# Steer the resolver away from versions on the denylist (config\denylist.json).
# Intake rejects them anyway; this lets uv pick a different version where one fits.
[string[]]$constraintLines = Get-DenylistConstraintLine -Denylist $denylist
if ($constraintLines.Count -gt 0) { Write-Log "Excluding $($constraintLines.Count) denylisted version(s) from resolution." }
if ($expedite.Count -gt 0) {
    $now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    foreach ($name in ($expedite.Keys | Sort-Object)) {
        $compileArgs += @('--exclude-newer-package', "$name=$now")
        $constraintLines = @($constraintLines) + "$name<=$($expedite[$name])"
    }
    Write-Log "Cooldown skipped for $(($expedite.Keys | Sort-Object | ForEach-Object { "$_==$($expedite[$_])" }) -join ', '). Reason: $expediteWhy" 'WARN'
}

$preferPath = ''
if ((Test-Path -LiteralPath $cfg.RequirementsTxtPath -PathType Leaf) -and ([System.IO.File]::ReadAllText($cfg.RequirementsTxtPath)).Trim()) {
    # uv keeps the pins of the current requirements.txt where they still fit.
    $preferPath = Join-Path $targetFolder 'requirements.prefer.tmp'
    Copy-Item -LiteralPath $cfg.RequirementsTxtPath -Destination $preferPath -Force
    if ($PreferCurrent) { Write-Log 'Keeping the current versions wherever they still fit (only what has to change changes).' }
}

Write-Log "Resolving $(@($resolveInput.Requirements).Count) requirement(s) with uv (binary wheels only, $($cfg.PythonVersion) / $uvPlatform)..."
$resolveParams = @{
    Requirement    = @($resolveInput.Requirements)
    OutputPath     = $candidatePath
    Argument       = $compileArgs
    ConstraintLine = $constraintLines
    PreferPath     = $preferPath
    PythonVersion  = $cfg.PythonVersion
    Platform       = $cfg.Platform
    MinimumAgeDays = [int]$cfg.MinimumPackageAgeDays
}
try { $resolved = Invoke-RequirementResolve @resolveParams }
finally { if ($preferPath) { Remove-Item -LiteralPath $preferPath -Force -ErrorAction SilentlyContinue } }

$setAside = @($resolved.SetAside)
if ($resolved.Ok -and $setAside.Count -gt 0 -and $NoSetAside) {
    $resolved = @{ Ok = $false; Resolved = @(); SetAside = $setAside; Error = "Could not resolve $(($setAside | ForEach-Object { "$($_.spec) ($($_.reason))" }) -join '; ')." }
}
if (-not $resolved.Ok) {
    if (Test-Path -LiteralPath $candidatePath) { Move-Item -LiteralPath $candidatePath -Destination $rejectedPath -Force }
    Write-Log "Could not resolve requirements.in: $($resolved.Error)" 'ERROR'
    Write-Log "requirements.txt was NOT changed. Fix requirements.in and run this script again." 'ERROR'
    try {
        $problems = @(Get-RequirementResolveProblem -Lines $inLines -ToolOutput @([string]$resolved.Error) -Target $target)
        foreach ($item in $setAside) { $problems += [PSCustomObject]@{ spec = $item.spec; ok = $false; status = $item.reason } }
        Write-RequirementResolveStatus -RequirementsTxtPath $cfg.RequirementsTxtPath -Failed -Message ([string]$resolved.Error) -Problem $problems
    }
    catch { Write-Log "Could not record the resolve problems: $($_.Exception.Message)" 'WARN' }
    exit 1
}

if (@($resolved.Resolved).Count -gt 0) {
    Move-Item -Path $candidatePath -Destination $cfg.RequirementsTxtPath -Force
    Write-Log "requirements.txt written successfully: $($cfg.RequirementsTxtPath)" "OK"
}
else {
    Write-TextFileAtomic -Path $cfg.RequirementsTxtPath -Content ''
    Write-Log 'Nothing could be resolved - requirements.txt is empty.' 'WARN'
}
Remove-Item -Path $rejectedPath -Force -ErrorAction SilentlyContinue

# Set aside now, plus earlier set-aside requirements nobody removed or asked for again.
$allAside = @($setAside) + @($resolveInput.SetAside)
if ($setAside.Count -gt 0) {
    Write-Log "$($setAside.Count) requirement(s) could not be resolved and were set aside - the rest is in requirements.txt. Review them in the Add tab (Remove, or Expedite one that is only too new):" 'WARN'
    foreach ($item in $setAside) { Write-Log "  $($item.spec): $($item.reason)" 'WARN' }
}
Write-RequirementResolveStatus -RequirementsTxtPath $cfg.RequirementsTxtPath -SetAside $allAside
if ($clearInput) {
    try {
        [string[]]$cleared = Clear-RequirementInFile -Path $cfg.RequirementsInPath
        if ($cleared.Count -gt 0) { Write-Log "requirements.in emptied - its requirement(s) are now in requirements.txt$(if ($setAside.Count -gt 0) { ' or set aside' })." 'OK' }
    }
    catch { Write-Log "Could not empty requirements.in: $($_.Exception.Message)" 'WARN' }
}
if (-not $NoProposal -and @($resolved.Resolved).Count -gt 0) {
    try {
        $pinned = Read-RequirementFile -FilePath $cfg.RequirementsTxtPath
        $expedited = @{}
        foreach ($name in $expedite.Keys) { if ($pinned[$name] -eq $expedite[$name]) { $expedited[$name] = $expedite[$name] } }
        $proposalParams = @{ RequirementsPath = $cfg.RequirementsTxtPath; Kind = 'resolve' }
        if ($expedited.Count -gt 0) { $proposalParams['Expedite'] = $expedited; $proposalParams['ExpediteReason'] = $expediteWhy }
        [void](New-WheelhouseProposal @proposalParams)
    }
    catch {
        Write-Log "The proposal could not be recorded ($($_.Exception.Message)); publishing will propose the file itself." 'WARN'
    }
}
Write-Log "Review it, get it approved (UI: Add packages tab), then run Update-Wheelhouse.ps1 to merge it into the central wheelhouse."
Write-Log "=== Update-Requirement finished ==="
exit 0
