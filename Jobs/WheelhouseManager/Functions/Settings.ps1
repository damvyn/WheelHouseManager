# ---------------------------------------------------------------------------
# config\settings.psd1: defaults, reading, parameter resolution, writing
# ---------------------------------------------------------------------------

function Get-WheelhouseDefaultSetting {
    # The single source of truth for every setting's fallback value. Setup.ps1 writes
    # these into a new settings.psd1; every script falls back to them when neither
    # an explicit -Parameter nor settings.psd1 supplies a value.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$ManagerRoot = $script:ManagerRoot
    )

    $inputPath = Join-Path $ManagerRoot 'Input'
    return @{
        WheelhousePath        = ''
        RequirementsInPath    = (Join-Path $inputPath 'requirements.in')
        LocalRequirementsPath = (Join-Path $inputPath 'requirements.txt')
        PythonVersion         = '3.14'
        Platform              = 'win_amd64'
        MinimumPackageAgeDays = 10
        VulnerabilityServices = @('osv', 'pypi')
        ReportRetentionMonths = 6
        SmtpServer            = ''
        MailTo                = 'servicedesk@company.com'
        MailFrom              = 'NoReply@company.com'
    }
}

function Get-WheelhouseSettingsPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$ManagerRoot = $script:ManagerRoot
    )

    return Join-Path (Join-Path $ManagerRoot 'config') 'settings.psd1'
}

function Get-WheelhouseSetting {
    # Reads config\settings.psd1. Returns an empty hashtable (not an error) if the
    # file is missing or unreadable, so callers can fall back to the defaults.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$SettingsPath = (Get-WheelhouseSettingsPath)
    )

    if (-not (Test-Path -Path $SettingsPath)) {
        return @{}
    }
    try {
        return Import-PowerShellDataFile -Path $SettingsPath -ErrorAction Stop
    }
    catch {
        Write-Log "Could not read settings file '$SettingsPath': $($_.Exception.Message)" 'WARN'
        return @{}
    }
}

function Resolve-Setting {
    # Precedence: explicit -Parameter (if the caller actually passed it) > value from
    # settings.psd1 (if present and non-empty) > the fallback default.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        $ExplicitValue,

        [bool]$WasBound,

        [hashtable]$Settings = @{},

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

function Resolve-WheelhouseParameter {
    # Resolves a whole set of script parameters in one call and returns them as a
    # hashtable keyed by parameter name:
    #     $cfg = Resolve-WheelhouseParameter -BoundParameters $PSBoundParameters `
    #         -Name WheelhousePath, PythonVersion
    #
    # -SettingName maps a parameter to a differently-named settings.psd1 key
    # (e.g. To -> MailTo). -Default overrides the module-wide fallback for this
    # script only (e.g. LocalRequirementsPath -> $null).
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        # $PSBoundParameters (a Dictionary, not a Hashtable) or a hashtable.
        [System.Collections.IDictionary]$BoundParameters,

        [Parameter(Mandatory)]
        [string[]]$Name,

        [hashtable]$SettingName = @{},

        [hashtable]$Default = @{},

        [hashtable]$Settings
    )

    if ($null -eq $Settings) { $Settings = Get-WheelhouseSetting }
    $moduleDefaults = Get-WheelhouseDefaultSetting

    $resolved = @{}
    foreach ($parameterName in $Name) {
        $key = if ($SettingName.ContainsKey($parameterName)) { $SettingName[$parameterName] } else { $parameterName }
        $fallback = if ($Default.ContainsKey($parameterName)) { $Default[$parameterName] } else { $moduleDefaults[$key] }

        $resolveParams = @{
            Name            = $key
            ExplicitValue   = $BoundParameters[$parameterName]
            WasBound        = $BoundParameters.ContainsKey($parameterName)
            Settings        = $Settings
            FallbackDefault = $fallback
        }
        $resolved[$parameterName] = Resolve-Setting @resolveParams
    }
    return $resolved
}

function ConvertTo-Psd1Literal {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return "''" }
    if ($Value -is [bool]) { return $(if ($Value) { '$true' } else { '$false' }) }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
        return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [array]) {
        $items = foreach ($item in $Value) { ConvertTo-Psd1Literal -Value $item }
        return "@($($items -join ', '))"
    }
    # Single-quoted psd1 strings only need embedded single quotes doubled.
    return "'" + ([string]$Value -replace "'", "''") + "'"
}

function Save-WheelhouseSetting {
    # Hand-rolled psd1 writer - the schema is a small, fixed set of strings, numbers,
    # booleans and string arrays. Overwrites the whole file with the given hashtable
    # (callers merge first via Set-WheelhouseSetting). Keys are sorted so the file
    # diffs cleanly between runs.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SettingsPath,

        [Parameter(Mandatory)]
        [hashtable]$Settings
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('@{')
    foreach ($key in ($Settings.Keys | Sort-Object)) {
        $lines.Add("    $key = $(ConvertTo-Psd1Literal -Value $Settings[$key])")
    }
    $lines.Add('}')

    if ($PSCmdlet.ShouldProcess($SettingsPath, 'Save settings')) {
        Write-TextFileAtomic -Path $SettingsPath -Content ($lines -join "`r`n")
    }
}

function Set-WheelhouseSetting {
    # Merges the given key/value pairs into the existing settings.psd1 (creating it
    # if absent) without touching any key the caller didn't ask to change.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SettingsPath,

        [Parameter(Mandatory)]
        [hashtable]$Updates
    )

    $current = Get-WheelhouseSetting -SettingsPath $SettingsPath
    foreach ($key in $Updates.Keys) {
        $current[$key] = $Updates[$key]
    }
    if ($PSCmdlet.ShouldProcess($SettingsPath, 'Update settings')) {
        Save-WheelhouseSetting -SettingsPath $SettingsPath -Settings $current
    }
}

function Initialize-ManagerFile {
    # Idempotent: never overwrites a file that already exists, so a re-run of
    # Setup.ps1 never clobbers a requirements.in someone is actively editing.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$DefaultContent = ''
    )

    if (Test-Path -Path $Path) {
        Write-Log "Already exists, leaving untouched: $Path"
        return
    }
    if ($PSCmdlet.ShouldProcess($Path, 'Create file')) {
        Set-Content -Path $Path -Value $DefaultContent -Encoding utf8 -ErrorAction Stop
        Write-Log "Created: $Path" 'OK'
    }
}
