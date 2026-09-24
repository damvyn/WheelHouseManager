# ---------------------------------------------------------------------------
# Candidate intake: the checks a package must pass before it enters a group file
# ---------------------------------------------------------------------------

function Invoke-CandidateIntake {
    # Takes the packages that are about to enter one group file through every check -
    # vulnerability audit, cooldown, download - and decides per package:
    #   Accepted - passed everything; its wheel is now in the wheelhouse.
    #   Rejected - failed a step (with the reason); nothing about it was written.
    # A package that fails never holds back the others. The caller writes only the
    # accepted packages into the group file, so a group file never lists a package
    # whose wheel was not downloaded.
    #
    # Candidates are the new pins from the local requirements file for this group,
    # plus pins the group already lists that still have no wheel in the wheelhouse.
    # Returns @{ Accepted = @{name=version}; Rejected = [PSCustomObject]@{Name;Version;Reason}, ...;
    #            AuditResults = Wheelhouse.AuditResult, ... }.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Packages,

        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [string]$ReportsFolder,

        [Parameter(Mandatory)]
        [string[]]$Services,

        [Parameter(Mandatory)]
        [int]$MinimumAgeDays,

        [Parameter(Mandatory)]
        [string]$PythonVersion,

        [Parameter(Mandatory)]
        [string]$Platform
    )

    $remaining = @{} + $Packages
    $rejected = [System.Collections.Generic.List[object]]::new()
    $auditResults = [System.Collections.Generic.List[object]]::new()

    $reject = {
        param([string]$Name, [string]$Reason)
        if (-not $remaining.ContainsKey($Name)) { return }
        $rejected.Add([PSCustomObject]@{ Name = $Name; Version = $remaining[$Name]; Reason = $Reason })
        $remaining.Remove($Name)
    }

    # --- 1. Vulnerability audit ------------------------------------------------
    # Report files are named after the candidate file: Report_PreDownload-<group>-candidates-...
    $workFolder = Join-Path ([System.IO.Path]::GetTempPath()) ("wheelhouse-intake-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $workFolder -Force | Out-Null
    try {
        $candidateFile = Join-Path $workFolder "$GroupName-candidates.txt"
        Set-Content -Path $candidateFile -Value @($remaining.Keys | Sort-Object | ForEach-Object { "$_==$($remaining[$_])" }) -Encoding ascii

        $results = Invoke-GroupAudit -GroupFile $candidateFile -Services $Services -Stage 'PreDownload' -ReportsFolder $ReportsFolder
        foreach ($result in $results) { $auditResults.Add($result) }
    }
    finally {
        Remove-Item -Path $workFolder -Recurse -Force -ErrorAction SilentlyContinue
    }

    foreach ($result in $auditResults) {
        $service = $result.Service.ToUpperInvariant()
        if ($result.Status -eq 'Vulnerable') {
            foreach ($dependency in (Get-PipAuditReport -Path $result.ReportPath)) {
                $vulns = @(@($dependency.vulns) | Where-Object { $_ })
                if ($vulns.Count -eq 0) { continue }
                $ids = ($vulns | ForEach-Object { $_.id }) -join ', '
                & $reject (Get-NormalizedPackageName $dependency.name) "known vulnerability ($service): $ids"
            }
        }
        elseif ($result.Status -eq 'Error') {
            # Without a completed audit nothing can be declared safe.
            foreach ($name in @($remaining.Keys)) {
                & $reject $name "vulnerability audit could not be completed ($service): $($result.Message)"
            }
        }
    }

    # --- 2. Cooldown -------------------------------------------------------------
    if ($remaining.Count -gt 0) {
        Write-Log "Checking minimum package age (cooldown: $MinimumAgeDays day(s)) for $($remaining.Count) candidate(s) of $GroupName..."
        $ageCheck = Test-PackageAge -Packages $remaining -MinimumAgeDays $MinimumAgeDays

        $ageReportFile = Join-Path $ReportsFolder "Report_PackageAge-$($GroupName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        Write-JsonFile -Path $ageReportFile -InputObject @($ageCheck.Results) -Depth 5
        Write-Log "Package age report saved to: $ageReportFile"

        foreach ($ageResult in @($ageCheck.Results | Where-Object { -not $_.Passed })) {
            $reason = if ($null -eq $ageResult.AgeDays) {
                "cooldown: could not verify the publish date on PyPI ($($ageResult.Error))"
            }
            else {
                "cooldown: published $($ageResult.AgeDays) day(s) ago, requires $MinimumAgeDays"
            }
            & $reject $ageResult.Package $reason
        }
    }

    # --- 3. Download -------------------------------------------------------------
    $accepted = @{}
    if ($remaining.Count -gt 0) {
        Write-Log "Downloading $($remaining.Count) candidate(s) of $GroupName..."
        $pipArgs = @(
            '-m', 'pip', 'download',
            '-d', $WheelhousePath,
            '--python-version', $PythonVersion,
            '--platform', $Platform,
            '--implementation', 'cp',
            '--only-binary=:all:',
            '--no-deps',
            '--disable-pip-version-check'
        )
        $download = Invoke-PipPinRetry -Packages $remaining -PipArguments $pipArgs

        foreach ($pin in $download.Failed) {
            $name = ($pin -split '==')[0]
            & $reject $name "no downloadable wheel for Python $PythonVersion / $Platform (pip: no matching distribution)"
        }
        if ($download.Error) {
            foreach ($name in @($remaining.Keys)) {
                & $reject $name "download failed: $($download.Error)"
            }
        }
        $accepted = @{} + $remaining
    }

    return @{
        Accepted     = $accepted
        Rejected     = $rejected.ToArray()
        AuditResults = $auditResults.ToArray()
    }
}
