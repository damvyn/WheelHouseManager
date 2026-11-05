<#
.SYNOPSIS
    Prepares the fix for a published, vulnerable package version: a proposal that replaces it
    with a fixed version and then quarantines it.

.DESCRIPTION
    1. Works out the fix from the package catalog (the fix versions of the version's open
       vulnerabilities) and PyPI: the lowest version that fixes them all
       (Get-WheelhouseRemediationPlan).
    2. Changes the package's line in requirements.in to "name>=fix" (upper bounds kept) - or
       adds it, when the package is only a dependency. When no fixed release is older than
       the cooldown yet, the line pins the lowest fixed release instead, and -ExpediteReason
       is required: only that package skips the cooldown, at resolve and at publish.
    3. Runs Update-Requirement.ps1 -PreferCurrent to resolve requirements.txt, keeping every
       other version where it still fits. If that fails, requirements.in is put back as it was.
    4. Records a remediation proposal: which pins change, and which vulnerable version to
       quarantine once its replacement is published.

    Nothing is published here. After the proposal is approved, Update-Wheelhouse.ps1 (UI:
    Add packages -> Publish) checks the fixed version like any other, swaps it into the
    group files that list the vulnerable version - the files clients install from - and
    quarantines the vulnerable version.

    Exit codes: 0 proposal recorded; 1 nothing could be proposed (no fix known, the fix
    needs -ExpediteReason, or the resolve failed - requirements.in unchanged); 2 error.

.PARAMETER Package
    The vulnerable version, name==version (must be published).

.PARAMETER ExpediteReason
    Required when the fix is newer than the cooldown: why it cannot wait.

.PARAMETER WheelhousePath
.PARAMETER RequirementsInPath
.PARAMETER LocalRequirementsPath
.PARAMETER MinimumPackageAgeDays
    Optional; default to config\settings.psd1.

.EXAMPLE
    .\Invoke-WheelhouseRemediation.ps1 -Package requests==2.19.0

.EXAMPLE
    .\Invoke-WheelhouseRemediation.ps1 -Package requests==2.32.3 -ExpediteReason "CVE-2026-1234 is exploited"
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Package,

    [string]$ExpediteReason,

    [ValidateNotNullOrEmpty()]
    [string]$WheelhousePath,

    [ValidateNotNullOrEmpty()]
    [string]$RequirementsInPath,

    [ValidateNotNullOrEmpty()]
    [string]$LocalRequirementsPath,

    [ValidateRange(0, 3650)]
    [int]$MinimumPackageAgeDays
)

Import-Module (Join-Path $PSScriptRoot 'WheelhouseManager') -ErrorAction Stop

$whlParams = @{
    'BoundParameters' = $PSBoundParameters
    'Name' = @('WheelhousePath', 'RequirementsInPath', 'LocalRequirementsPath', 'MinimumPackageAgeDays', 'ReportRetentionMonths')
}
$cfg = Resolve-WheelhouseParameter @whlParams

$title = 'Wheelhouse remediation'
$outcome = $null
$exitCode = 0
$originalIn = $null

try {
    # One pass; "break" stops early (a "return" here would skip the exit code below).
    do {
        $whlRunParams = @{
            'WheelhousePath' = $cfg.WheelhousePath
            'Title' = $title
            'LogPrefix' = 'Log_Remediation'
            'RetentionMonths' = $cfg.ReportRetentionMonths
        }
        [void](Start-WheelhouseRun @whlRunParams)

        $pin = @(ConvertTo-WheelhousePin -Pin $Package)
        if ($pin.Count -ne 1) { throw "Give exactly one package as name==version, not '$Package'." }
        $name = $pin[0].Name
        $version = $pin[0].Version

        # 1. The plan.
        $planParams = @{
            WheelhousePath     = $cfg.WheelhousePath
            Name               = $name
            Version            = $version
            RequirementsInPath = $cfg.RequirementsInPath
            MinimumAgeDays     = [int]$cfg.MinimumPackageAgeDays
        }
        $plan = Get-WheelhouseRemediationPlan @planParams
        Write-Log $plan.Summary
        if ($plan.NeedsExpedite -and [string]::IsNullOrWhiteSpace($ExpediteReason)) {
            Write-Log "No fixed release of $name is older than the $($cfg.MinimumPackageAgeDays)-day cooldown yet. Wait until $(([string]$plan.EligibleUtc).Substring(0, 10)), or run again with -ExpediteReason to publish $name==$($plan.ExpediteVersion) now." 'ERROR'
            $exitCode = Get-WheelhouseExitCode -Outcome Attention
            $outcome = 'needs an expedite reason'
            break
        }

        # 2. requirements.in, keeping the original to put back if the resolve fails.
        $before = @{}
        if (Test-Path -LiteralPath $cfg.LocalRequirementsPath) { $before = Read-RequirementFile -FilePath $cfg.LocalRequirementsPath }
        if (Test-Path -LiteralPath $cfg.RequirementsInPath) { $originalIn = [System.IO.File]::ReadAllText($cfg.RequirementsInPath) } else { $originalIn = '' }
        $comment = "added by remediation of $name==$version ($($plan.Ids -join ', ')) on $(Get-Date -Format 'yyyy-MM-dd')"
        Set-RequirementInSpec -Path $cfg.RequirementsInPath -Name $name -Line $plan.NewLine -Comment $comment
        Write-Log "requirements.in: '$($plan.OldLine)' -> '$($plan.NewLine)'" 'OK'

        # 3. Resolve. Expedited: the cooldown is lifted for the resolve; the line pins the one
        # fixed release, and intake still applies the cooldown to every other package.
        $resolveParams = @{
            RequirementsInPath  = $cfg.RequirementsInPath
            RequirementsTxtPath = $cfg.LocalRequirementsPath
            NoProposal          = $true
            NoSetAside          = $true
            PreferCurrent       = $true
        }
        if ($plan.NeedsExpedite) { $resolveParams['MinimumPackageAgeDays'] = 0 }
        & (Join-Path $PSScriptRoot 'Update-Requirement.ps1') @resolveParams | Out-Host
        $resolveCode = $LASTEXITCODE
        if ($resolveCode -ne 0) {
            [System.IO.File]::WriteAllText($cfg.RequirementsInPath, $originalIn, [System.Text.UTF8Encoding]::new($false))
            Write-Log "The resolve failed (exit code $resolveCode) - requirements.in was put back as it was; nothing was proposed. The log above says why (often: the fixed version has no wheel for the target Python, or conflicts with an upper bound)." 'ERROR'
            $exitCode = $(if ($resolveCode -eq 1) { Get-WheelhouseExitCode -Outcome Attention } else { Get-WheelhouseExitCode -Outcome Error })
            $outcome = 'resolve failed'
            break
        }
        $originalIn = $null

        # 4. The proposal: every pin that changed or is new, the version to retire.
        $after = Read-RequirementFile -FilePath $cfg.LocalRequirementsPath
        $newVersion = $after[$name]
        if (-not $newVersion -or (Compare-PackageVersion -Left $newVersion -Right $plan.FixVersion) -lt 0) {
            throw "The resolve did not pick a fixed version of $name (got '$newVersion', need >= $($plan.FixVersion))."
        }
        $replace = @(foreach ($key in ($after.Keys | Sort-Object)) {
                if ($before[$key] -ne $after[$key]) { [PSCustomObject]@{ name = $key; from = [string]$before[$key]; to = $after[$key] } }
            })
        $proposalParams = @{
            RequirementsPath = $cfg.LocalRequirementsPath
            Kind             = 'remediation'
            Replace          = $replace
            Retire           = @([PSCustomObject]@{ name = $name; version = $version; ids = $plan.Ids })
            Note             = "Fix $name==$version ($($plan.Ids -join ', ')) with $name==$newVersion; $($replace.Count) pin(s) change."
        }
        if ($plan.NeedsExpedite) {
            $proposalParams['Expedite'] = @{ $name = $newVersion }
            $proposalParams['ExpediteReason'] = $ExpediteReason
        }
        $proposal = New-WheelhouseProposal @proposalParams
        foreach ($item in $replace) { Write-Log "  $($item.name): $(if ($item.from) { $item.from } else { '(new)' }) -> $($item.to)" }
        Write-Log "Remediation proposal $($proposal.id) recorded. Approve and publish it (UI: Add packages tab, or Update-Wheelhouse.ps1); $name==$version is quarantined once $name==$newVersion is published in its place." 'OK'
        $outcome = "proposal $($proposal.id)"
    } while ($false)
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    $exitCode = Get-WheelhouseExitCode -ErrorRecord $_
    $outcome = 'ABORTED'
}
finally {
    if ($null -ne $originalIn) {
        # Stopped between the edit and the resolve result: put requirements.in back.
        try { [System.IO.File]::WriteAllText($cfg.RequirementsInPath, $originalIn, [System.Text.UTF8Encoding]::new($false)) } catch { Write-Log "Could not restore requirements.in: $($_.Exception.Message)" 'ERROR' }
    }
    Stop-WheelhouseRun -Title $title -Outcome $outcome -ExitCode $exitCode
}

exit $exitCode
