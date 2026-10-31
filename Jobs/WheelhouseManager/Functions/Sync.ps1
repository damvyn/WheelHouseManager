# ---------------------------------------------------------------------------
# The update run (Update-Wheelhouse.ps1's work): merge plan, intake, publish, audits
# ---------------------------------------------------------------------------

function Invoke-WheelhouseSync {
    # Everything Update-Wheelhouse.ps1 does, except the run frame that stays in the script
    # (transcript, tooling check, exit code):
    #   A. under the write lock: finish interrupted operations, verify integrity, take out
    #      wheels removed or changed outside the manager (-AutoQuarantine), reconcile the
    #      catalog, read the group files;
    #   B. plan the merge of -LocalRequirementsPath into the group files (nothing written);
    #   C. per group: Invoke-CandidateIntake (no lock), then Publish-CandidateIntake (write
    #      lock for the seconds the publish takes), then audit the group as deployed;
    #   D. first-time setup only: adopt the wheels the folder already held (write lock);
    #   E. record every audit in the catalog with severities, due dates and waivers, and
    #      quarantine published versions with a malicious-package advisory
    #      (-AutoQuarantine) (write lock).
    # The share itself is not virus-scanned here: that is the file server's antivirus' job.
    # When it removes a wheel, step A notices the missing file.
    # The sync lock is held for the whole run, so two runs never plan from the same state;
    # quarantine, restore and the scheduled check only wait for the short write-lock steps.
    # Returns { Outcome = Ok|Attention|Error; AuditResults; Notices; Rejected; Published }.
    # Throws when the run cannot start or must stop (busy, integrity failure, nothing to do).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [string]$ReportsFolder,

        [AllowEmptyString()]
        [AllowNull()]
        [string]$LocalRequirementsPath,

        [Parameter(Mandatory)]
        [string]$PythonVersion,

        [Parameter(Mandatory)]
        [string]$Platform,

        [Parameter(Mandatory)]
        [int]$MinimumAgeDays,

        [Parameter(Mandatory)]
        [string[]]$Services,

        # name -> version whose cooldown is skipped in this run.
        [hashtable]$Expedite = @{},

        [string]$ExpediteReason = '',

        [switch]$RequireDefenderScan,

        # Take out wheels removed or changed outside the manager instead of stopping.
        [bool]$AutoQuarantine = $true,

        [string]$DenylistPath = (Get-WheelhouseDenylistPath),

        [string]$WaiverPath = (Get-WheelhouseWaiverPath),

        # Fix-by days per severity (Get-WheelhouseDueDayTable).
        [hashtable]$DueDays = (Get-WheelhouseDueDayTable),

        # Warn when the scheduled check has not run for this long.
        [ValidateRange(1, 3650)]
        [int]$AuditFreshnessDays = 8,

        [string]$StagingRoot = (Join-Path $script:ManagerRoot 'staging'),

        # How long a write-lock step waits for a quarantine/restore/check to finish.
        [ValidateRange(0, 3600)]
        [int]$LockTimeoutSeconds = 300
    )

    $auditResults = [System.Collections.Generic.List[object]]::new()
    $notices = [System.Collections.Generic.List[object]]::new()
    $rejectedAll = [System.Collections.Generic.List[object]]::new()
    $publishedAll = [System.Collections.Generic.List[object]]::new()
    $overallPassed = $true
    $auditIncomplete = $false

    $syncLock = Enter-WheelhouseLock -WheelhousePath $WheelhousePath -Kind 'sync'
    try {
        # -------------------------------------------------------------------
        # A. Consistent starting point (write lock)
        # -------------------------------------------------------------------
        $lock = Open-WheelhouseWrite -WheelhousePath $WheelhousePath -TimeoutSeconds $LockTimeoutSeconds -DenylistPath $DenylistPath
        try {
            $denylist = @(Read-WheelhouseDenylist -Path $DenylistPath)
            if ($denylist.Count -gt 0) { Write-Log "Denylist: $($denylist.Count) blocked package entr(y/ies) will be rejected at intake." }
            $waivers = @(Read-WheelhouseWaiver -Path $WaiverPath)

            Write-Log "Loading manifest: $(Get-WheelhouseManifestPath -WheelhousePath $WheelhousePath)"
            $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
            Write-Log "Manifest contains $($manifest.Count) tracked file(s)."
            $isBootstrap = ($manifest.Count -eq 0)
            if ($isBootstrap) { Write-Log 'Manifest is empty - assuming first-time setup.' 'OK' }

            # Wheels removed or changed outside the manager (typically by the file server's
            # antivirus): with AutoQuarantine they are taken out here, so the rest keeps
            # working; without it they stop the run like any other integrity problem.
            $changed = @(Assert-WheelhouseIntegrity -Manifest $manifest -WheelhousePath $WheelhousePath -ReportsFolder $ReportsFolder -AllowChangedFiles:$AutoQuarantine)
            if ($changed.Count -gt 0) {
                foreach ($notice in @(Resolve-WheelhouseIntegrityProblem -WheelhousePath $WheelhousePath -Problem $changed -AutoQuarantine -DenylistPath $DenylistPath)) {
                    $notices.Add($notice)
                }
                $overallPassed = $false
                $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
            }
            # Wheels nobody published (never on first-time setup, which adopts them).
            foreach ($notice in @(Move-UntrackedWheelFile -WheelhousePath $WheelhousePath -AutoQuarantine:$AutoQuarantine)) {
                $notices.Add($notice)
                $overallPassed = $false
            }

            Update-WheelhouseCatalog -WheelhousePath $WheelhousePath -LockHeld -DenylistPath $DenylistPath
            if (-not $isBootstrap) {
                $lastCheck = ConvertTo-OptionalUtcDateTime -Value (Read-WheelhouseCatalog -WheelhousePath $WheelhousePath).ScheduledCheckUtc
                if (-not $lastCheck) {
                    Write-Log 'The scheduled check (Test-Wheelhouse.ps1) has never completed for this wheelhouse - published packages are only re-checked by this update. Register it as a Scheduled Task (README).' 'WARN'
                }
                elseif (((Get-Date).ToUniversalTime() - $lastCheck).TotalDays -gt $AuditFreshnessDays) {
                    Write-Log "The scheduled check (Test-Wheelhouse.ps1) last completed on $($lastCheck.ToString('yyyy-MM-dd')), more than $AuditFreshnessDays day(s) ago. Check its Scheduled Task." 'WARN'
                }
            }

            [string[]]$groupFiles = Get-WheelhouseGroupFile -WheelhousePath $WheelhousePath
            $listedByGroup = @{}
            foreach ($groupFile in $groupFiles) { $listedByGroup[$groupFile] = Read-RequirementFile -FilePath $groupFile }
        }
        finally {
            Exit-WheelhouseLock -Lock $lock
        }

        # -------------------------------------------------------------------
        # B. Merge plan - nothing is written yet
        # -------------------------------------------------------------------
        $additionsByGroup = @{}
        $localPackages = @{}
        if (-not [string]::IsNullOrWhiteSpace($LocalRequirementsPath) -and (Test-Path -Path $LocalRequirementsPath)) {
            $localPackages = Read-RequirementFile -FilePath $LocalRequirementsPath
        }
        if ($localPackages.Count -gt 0) {
            Write-Log "Planning merge of $($localPackages.Count) package(s) from local requirements: $LocalRequirementsPath"
            $mergePlan = Get-RequirementMergePlan -LocalPackages $localPackages -GroupFiles $groupFiles -WheelhousePath $WheelhousePath
            foreach ($dup in $mergePlan.Duplicates) { Write-Log "  Already listed, skipped: $dup" }
            foreach ($add in $mergePlan.Additions) {
                $label = if ($add.IsNewGroup) { 'new group' } else { 'existing group' }
                Write-Log "  Candidate: $($add.Name)==$($add.Version) for $(Split-Path -Path $add.GroupFile -Leaf) ($label)"
                if (-not $additionsByGroup.ContainsKey($add.GroupFile)) { $additionsByGroup[$add.GroupFile] = @{} }
                $additionsByGroup[$add.GroupFile][$add.Name] = $add.Version
            }
            if ($mergePlan.Additions.Count -eq 0) {
                Write-Log 'Nothing new to merge - every local package is already listed in a group.' 'OK'
            }
            else {
                Write-Log 'Candidates are only written to their group file after passing every check.'
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($LocalRequirementsPath)) {
            Write-Log "No local requirements to merge (file missing or empty): $LocalRequirementsPath"
        }

        # Existing groups first, then planned new groups in number order.
        $targetGroups = @($groupFiles) + @($additionsByGroup.Keys | Where-Object { $groupFiles -notcontains $_ } |
                Sort-Object { Get-GroupFileNumber -Path $_ })
        if ($targetGroups.Count -eq 0) {
            Write-Log 'Run Update-Requirement.ps1 and re-run this script with -LocalRequirementsPath to create the first group.' 'ERROR'
            throw 'Wheelhouse has no requirement group files yet, and no local requirements were supplied to bootstrap one.'
        }
        Write-Log "Processing $($targetGroups.Count) requirement group file(s)."

        # -------------------------------------------------------------------
        # C. Per group: check (no lock), publish (write lock), audit as deployed
        # -------------------------------------------------------------------
        $expectedPythonTag = 'cp' + ($PythonVersion -replace '\.', '')
        Write-Log "Target tag for matching: $expectedPythonTag / $Platform"
        $expediteUsed = @{}
        $eventDetail = @{}
        foreach ($name in $Expedite.Keys) { $eventDetail[$name] = "cooldown skipped (expedited): $ExpediteReason" }

        foreach ($groupFile in $targetGroups) {
            $groupName = [System.IO.Path]::GetFileNameWithoutExtension($groupFile)
            Write-Log "--- Group: $groupName ($groupFile) ---"

            $groupExisted = $listedByGroup.ContainsKey($groupFile)
            $listed = if ($groupExisted) { $listedByGroup[$groupFile] } else { @{} }
            $additions = if ($additionsByGroup.ContainsKey($groupFile)) { $additionsByGroup[$groupFile] } else { @{} }

            # Pins the group already lists but whose wheel is not in the wheelhouse yet.
            $missing = @{}
            if ($listed.Count -gt 0) {
                $compareParams = @{
                    Required            = $listed
                    Manifest            = $manifest
                    ExpectedPythonTag   = $expectedPythonTag
                    ExpectedPlatformTag = $Platform
                }
                $missing = (Compare-RequirementsAgainstManifest @compareParams).Packages
            }
            Write-Log "$($listed.Count) package(s) listed, $($missing.Count) of them without a wheel yet; $($additions.Count) new candidate(s)."

            $candidates = @{} + $missing
            foreach ($name in $additions.Keys) { $candidates[$name] = $additions[$name] }

            if ($candidates.Count -gt 0) {
                foreach ($name in ($candidates.Keys | Sort-Object)) {
                    $kind = if ($additions.ContainsKey($name)) { 'new' } else { 'listed, no wheel yet' }
                    Write-Log "  Candidate: $name==$($candidates[$name]) ($kind)" 'WARN'
                    if ($Expedite.ContainsKey($name) -and $Expedite[$name] -eq $candidates[$name]) { $expediteUsed[$name] = $true }
                }

                $intakeParams = @{
                    Packages            = $candidates
                    GroupName           = $groupName
                    ReportsFolder       = $ReportsFolder
                    Services            = $Services
                    MinimumAgeDays      = $MinimumAgeDays
                    PythonVersion       = $PythonVersion
                    Platform            = $Platform
                    Denylist            = $denylist
                    Expedite            = $Expedite
                    RequireDefenderScan = [bool]$RequireDefenderScan
                    StagingRoot         = $StagingRoot
                }
                $intake = Invoke-CandidateIntake @intakeParams
                foreach ($result in $intake.AuditResults) { $auditResults.Add($result) }

                $publishParams = @{
                    Intake         = $intake
                    WheelhousePath = $WheelhousePath
                    GroupFile      = $groupFile
                    Additions      = $additions
                    DenylistPath   = $DenylistPath
                    EventDetail    = $eventDetail
                    TimeoutSeconds = $LockTimeoutSeconds
                }
                $publish = Publish-CandidateIntake @publishParams
                if ($null -ne $publish.Manifest) { $manifest = $publish.Manifest }
                foreach ($entry in $publish.Published) { $publishedAll.Add($entry) }

                foreach ($name in ($publish.Accepted.Keys | Sort-Object)) {
                    if ($additions.ContainsKey($name)) {
                        Write-Log "  Accepted and added to ${groupName}: $name==$($publish.Accepted[$name])" 'OK'
                    }
                    else {
                        Write-Log "  Accepted, wheel now published: $name==$($publish.Accepted[$name])" 'OK'
                    }
                }

                foreach ($item in @($intake.Rejected) + @($publish.Rejected)) {
                    if ($null -eq $item) { continue }
                    $isNew = $additions.ContainsKey($item.Name)
                    $action = if ($isNew) {
                        "NOT added to $groupName - it stays in the local requirements file and is tried again next run"
                    }
                    else {
                        "Still listed in $groupName without a wheel - fix or remove that line in the group file"
                    }
                    Write-Log "  Rejected: $($item.Name)==$($item.Version) - $($item.Reason) -> $action" 'ERROR'
                    $rejectedAll.Add([PSCustomObject]@{
                            Group    = $groupName
                            Package  = $item.Name
                            Version  = $item.Version
                            Kind     = $(if ($isNew) { 'new' } else { 'listed' })
                            Category = $item.Category
                            Reason   = $item.Reason
                        })
                    # A download that differed from PyPI or was detected by Defender is a
                    # security event, not just a rejection.
                    if ($item.Category -in 'integrity', 'defender') {
                        $notices.Add((New-WheelhouseNotice -Kind 'IntakeBlocked' -Package $item.Name -Version $item.Version -Message $item.Reason))
                    }
                    if ($item.Category -eq 'audit-error') { $auditIncomplete = $true }
                    $overallPassed = $false
                }
            }

            # Audit what the group lists as deployed. A group created in this run holds
            # only packages that were just audited as candidates.
            if ($groupExisted -and $listed.Count -gt 0) {
                Write-Log "Auditing $groupName as deployed (no download)..."
                $groupResults = Invoke-GroupAudit -GroupFile $groupFile -Services $Services -Stage 'Deployed' -ReportsFolder $ReportsFolder
                foreach ($result in $groupResults) { $auditResults.Add($result) }
                if ($groupResults | Where-Object { $_.Status -ne 'Passed' }) {
                    Write-Log "$groupName has known vulnerabilities (or an incomplete audit) in listed packages." 'ERROR'
                    $overallPassed = $false
                }
                if ($groupResults | Where-Object { $_.Status -eq 'Error' }) { $auditIncomplete = $true }
            }
        }

        foreach ($name in ($Expedite.Keys | Sort-Object)) {
            if (-not $expediteUsed.ContainsKey($name)) {
                Write-Log "-ExpeditePackage $name==$($Expedite[$name]) was not a candidate in any group - nothing was expedited for it." 'WARN'
            }
        }
        if ($rejectedAll.Count -gt 0) {
            $rejectedReport = Join-Path $ReportsFolder "Report_Rejected_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            Write-JsonFile -Path $rejectedReport -InputObject @($rejectedAll.ToArray()) -Depth 3
            Write-Log "$($rejectedAll.Count) package(s) were rejected this run - details: $rejectedReport" 'ERROR'
        }

        # -------------------------------------------------------------------
        # D. First-time setup only: adopt the wheels that were already there
        # -------------------------------------------------------------------
        if ($isBootstrap -and $publishedAll.Count -gt 0) {
            $lock = Open-WheelhouseWrite -WheelhousePath $WheelhousePath -TimeoutSeconds $LockTimeoutSeconds -DenylistPath $DenylistPath
            try {
                # This run's downloads are already in the manifest (verified against PyPI);
                # this adds the wheels the folder held before the manager was set up.
                $current = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
                $adopted = Merge-WheelhouseManifest -WheelhousePath $WheelhousePath -Manifest $current -PreRunFiles @()
                if ($adopted.Count -gt $current.Count) {
                    Write-Log "First-time setup: $($adopted.Count - $current.Count) wheel(s) that were already in the folder were added to the manifest (not verified against PyPI)." 'WARN'
                    Save-WheelhouseManifest -Manifest $adopted -WheelhousePath $WheelhousePath
                    Update-WheelhouseCatalog -WheelhousePath $WheelhousePath -LockHeld -DenylistPath $DenylistPath
                }
            }
            finally {
                Exit-WheelhouseLock -Lock $lock
            }
        }
        elseif ($publishedAll.Count -eq 0) {
            Write-Log 'Nothing was published this run - manifest left unchanged.'
        }

        # -------------------------------------------------------------------
        # E. Record every audit in the catalog (write lock). Virus scanning of the
        # share itself is the file server's antivirus' job; new wheels were scanned
        # at intake.
        # -------------------------------------------------------------------
        # Outside the write lock: it may go to the network.
        $severity = Get-AuditResultSeverity -AuditResult $auditResults.ToArray() -WheelhousePath $WheelhousePath
        $lock = Open-WheelhouseWrite -WheelhousePath $WheelhousePath -TimeoutSeconds $LockTimeoutSeconds -DenylistPath $DenylistPath
        try {
            $catalog = Read-WheelhouseCatalog -WheelhousePath $WheelhousePath
            [void](Sync-WheelhouseCatalog -Catalog $catalog)
            $recordParams = @{
                Catalog     = $catalog
                AuditResult = $auditResults.ToArray()
                Services    = $Services
                Severity    = $severity
                DueDays     = $DueDays
                Waiver      = $waivers
            }
            Update-CatalogAuditResult @recordParams
            Save-WheelhouseCatalog -Catalog $catalog

            foreach ($notice in @(Resolve-MaliciousPackage -WheelhousePath $WheelhousePath -AutoQuarantine:$AutoQuarantine -DenylistPath $DenylistPath)) {
                $notices.Add($notice)
                $overallPassed = $false
            }
        }
        finally {
            Exit-WheelhouseLock -Lock $lock
        }
    }
    finally {
        Exit-WheelhouseLock -Lock $syncLock
    }

    $outcome = if ($auditIncomplete) { 'Error' } elseif (-not $overallPassed) { 'Attention' } else { 'Ok' }
    return [PSCustomObject]@{
        Outcome      = $outcome
        AuditResults = $auditResults.ToArray()
        Notices      = $notices.ToArray()
        Rejected     = $rejectedAll.ToArray()
        Published    = $publishedAll.ToArray()
    }
}
