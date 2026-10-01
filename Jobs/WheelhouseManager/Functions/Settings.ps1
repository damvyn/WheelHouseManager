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

function Get-WheelhouseSettingSchema {
    # The settings the UI may edit, with the kind of value each takes. Defaults come
    # from Get-WheelhouseDefaultSetting; this only describes how to present and
    # validate them.
    [CmdletBinding()]
    param()

    $schema = @(
        @{ Key = 'WheelhousePath'; Type = 'path'; Label = 'Wheelhouse folder'; Help = 'UNC or local path of the wheelhouse (must exist).' }
        @{ Key = 'RequirementsInPath'; Type = 'file'; Label = 'requirements.in'; Help = 'Where the packages you ask for are listed.' }
        @{ Key = 'LocalRequirementsPath'; Type = 'file'; Label = 'requirements.txt'; Help = 'The resolved, pinned file that Update-Wheelhouse merges.' }
        @{ Key = 'PythonVersion'; Type = 'string'; Label = 'Python version'; Help = 'Target version, for example 3.14.' }
        @{ Key = 'Platform'; Type = 'choice'; Label = 'Platform'; Options = @('win_amd64', 'win_arm64', 'win32'); Help = 'Wheel platform tag.' }
        @{ Key = 'MinimumPackageAgeDays'; Type = 'int'; Label = 'Cooldown (days)'; Min = 0; Max = 3650; Help = 'A version must be on PyPI this long before it is downloaded.' }
        @{ Key = 'VulnerabilityServices'; Type = 'multichoice'; Label = 'Vulnerability services'; Options = @('osv', 'pypi'); Help = 'pip-audit services used for every audit.' }
        @{ Key = 'ReportRetentionMonths'; Type = 'int'; Label = 'Report retention (months)'; Min = 1; Max = 1200; Help = 'Logs and reports older than this are removed.' }
        @{ Key = 'SmtpServer'; Type = 'string'; Label = 'SMTP server'; Help = 'Empty: alerts are saved as HTML instead of emailed.' }
        @{ Key = 'MailTo'; Type = 'string'; Label = 'Alert recipient'; Help = 'Where vulnerability alerts go.' }
        @{ Key = 'MailFrom'; Type = 'string'; Label = 'Alert sender'; Help = 'From address of alert mails.' }
    )
    foreach ($item in $schema) { [PSCustomObject]$item }
}

function ConvertTo-WheelhouseSettingValue {
    # Validates and converts one value coming from the UI. Returns the value to store;
    # throws ArgumentException with a readable message otherwise.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,

        [AllowNull()]
        $Value
    )

    $definition = Get-WheelhouseSettingSchema | Where-Object { $_.Key -eq $Key } | Select-Object -First 1
    if (-not $definition) {
        throw [System.ArgumentException]::new("Unknown setting: '$Key'.")
    }
    $fail = { param($Text) throw [System.ArgumentException]::new("$($definition.Label): $Text") }

    switch ($definition.Type) {
        'int' {
            $number = 0
            if (-not [int]::TryParse([string]$Value, [ref]$number)) { & $fail 'must be a whole number.' }
            if ($number -lt $definition.Min -or $number -gt $definition.Max) { & $fail "must be between $($definition.Min) and $($definition.Max)." }
            return $number
        }
        'choice' {
            if ($definition.Options -notcontains [string]$Value) { & $fail "must be one of: $($definition.Options -join ', ')." }
            if ($Key -eq 'Platform') {
                # Same mapping Update-Requirement.ps1 needs; throws for an unsupported tag.
                try { [void](ConvertTo-UvPythonPlatform -Platform ([string]$Value)) } catch { & $fail $_.Exception.Message }
            }
            return [string]$Value
        }
        'multichoice' {
            # foreach (not @()) flattens the list on every PowerShell version.
            $items = @(foreach ($item in @($Value)) { [string]$item })
            if ($items.Count -eq 0) { & $fail 'select at least one.' }
            foreach ($item in $items) {
                if ($definition.Options -notcontains $item) { & $fail "'$item' is not one of: $($definition.Options -join ', ')." }
            }
            return , @($items | Select-Object -Unique)
        }
        { $_ -in 'path', 'file' } {
            $text = ([string]$Value).Trim()
            if ($text -eq '' -or $text -match '["<>|*?]' -or $text -match '[\x00-\x1f]') { & $fail 'enter a valid path.' }
            if ($definition.Type -eq 'path' -and -not (Test-Path -Path $text -PathType Container)) { & $fail "folder not found or not reachable: $text" }
            return $text
        }
        default {
            $text = ([string]$Value).Trim()
            if ($text -match '[\x00-\x1f]' -or $text.Length -gt 300) { & $fail 'contains invalid characters or is too long.' }
            switch ($Key) {
                'PythonVersion' { if ($text -notmatch '^\d+\.\d+$') { & $fail 'use the form 3.14.' } }
                'SmtpServer' { if ($text -ne '' -and $text -notmatch '^[A-Za-z0-9.\-]+(:\d+)?$') { & $fail 'enter a host name or IP address, optionally with :port.' } }
                { $_ -in 'MailTo', 'MailFrom' } { if ($text -ne '' -and $text -notmatch '^[^@\s;,]+@[^@\s;,]+$') { & $fail 'enter an email address.' } }
            }
            return $text
        }
    }
}
