# ---------------------------------------------------------------------------
# Candidate intake: the checks a package must pass before it enters a group file
# ---------------------------------------------------------------------------

function Invoke-CandidateIntake {
    # First half of intake: takes the packages that are about to enter one group file
    # through every check, without the write lock and without touching the wheelhouse,
    # and decides per package:
    #   Verified - passed everything; its downloaded files wait in the staging folder.
    #   Rejected - failed a step (with the reason and a category).
    # Each package is checked on its own here; Invoke-WheelhouseSync then holds back the
    # verified packages that need a rejected one (Get-DependentRejection, category
    # 'dependency') before anything is published. Publish-CandidateIntake then
    # publishes the verified ones (and deletes the staging folder), so a group file
    # never lists a package whose wheel was not published.
    #
    # Order: denylist -> vulnerability audit -> PyPI release data (yanked, cooldown) ->
    # download into a staging folder outside the wheelhouse -> every downloaded file
    # checked against PyPI (sha256, yanked, its own upload date) -> Defender scan of the
    # staged files. Clients never see a file that has not passed every check.
    #
    # Candidates are the new pins from the local requirements file for this group,
    # plus pins the group already lists that still have no wheel in the wheelhouse.
    # Returns @{ Packages = the candidates; Rejected = [PSCustomObject]@{Name;Version;Reason;Category}, ...;
    #            AuditResults = Wheelhouse.AuditResult, ...; Verified = @{name = staged FileInfo[]};
    #            StagingPath = the staging folder, or $null when nothing was verified;
    #            Scan = the Defender scan of the staged files, or $null }.
    # Categories: denylist, vulnerability, audit-error, pypi-metadata, yanked, cooldown,
    # no-wheel, download, integrity, defender (publish adds denylist and publish).
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Packages,

        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [string]$ReportsFolder,

        [Parameter(Mandatory)]
        [string[]]$Services,

        [Parameter(Mandatory)]
        [int]$MinimumAgeDays,

        [Parameter(Mandatory)]
        [string]$PythonVersion,

        [Parameter(Mandatory)]
        [string]$Platform,

        # Entries of config\denylist.json. Blocked packages are rejected before any other check.
        [AllowEmptyCollection()]
        [object[]]$Denylist = @(),

        # name -> version: the cooldown is skipped for exactly these pins (urgent fixes).
        [hashtable]$Expedite = @{},

        # Reject packages whose download could not be scanned with Defender, instead of
        # publishing them with a warning.
        [switch]$RequireDefenderScan,

        # Downloads wait here (one subfolder per run) until they passed every check. Kept
        # off the wheelhouse share, and off %TEMP%, whose 8.3 short names would not match
        # the long paths in Defender's detections.
        [string]$StagingRoot = (Join-Path $script:ManagerRoot 'staging')
    )

    $remaining = @{} + $Packages
    $rejected = [System.Collections.Generic.List[object]]::new()
    $auditResults = [System.Collections.Generic.List[object]]::new()
    $nowUtc = (Get-Date).ToUniversalTime()

    $reject = {
        param([string]$Name, [string]$Category, [string]$Reason)
        if (-not $remaining.ContainsKey($Name)) { return }
        $rejected.Add([PSCustomObject]@{ Name = $Name; Version = $remaining[$Name]; Reason = $Reason; Category = $Category })
        $remaining.Remove($Name)
    }
    $eligibleText = {
        param($Utc)
        if ($Utc) { " (eligible $((ConvertTo-UtcDateTime -Value $Utc).ToString('yyyy-MM-dd')))" } else { '' }
    }

    # --- 0. Denylist ---------------------------------------------------------------
    foreach ($name in @($remaining.Keys)) {
        $blocked = Get-DenylistMatch -Name $name -Version $remaining[$name] -Denylist $Denylist
        if ($blocked) {
            $why = if ($blocked.reason) { ": $($blocked.reason)" } else { '' }
            & $reject $name 'denylist' "denylist ($($blocked.version), $($blocked.source))$why"
        }
    }

    # --- 1. Vulnerability audit ------------------------------------------------
    # Report files are named after the candidate file: Report_PreDownload-<group>-candidates-...
    $workFolder = Join-Path ([System.IO.Path]::GetTempPath()) ("wheelhouse-intake-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $workFolder -Force | Out-Null
    try {
        if ($remaining.Count -gt 0) {
            $candidateFile = Join-Path $workFolder "$GroupName-candidates.txt"
            Set-Content -Path $candidateFile -Value @($remaining.Keys | Sort-Object | ForEach-Object { "$_==$($remaining[$_])" }) -Encoding ascii

            $results = Invoke-GroupAudit -GroupFile $candidateFile -Services $Services -Stage 'PreDownload' -ReportsFolder $ReportsFolder
            foreach ($result in $results) { $auditResults.Add($result) }
        }
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
                $ids = ($vulns | ForEach-Object { $_.id } | Select-Object -Unique) -join ', '
                & $reject (Get-NormalizedPackageName $dependency.name) 'vulnerability' "known vulnerability ($service): $ids"
            }
        }
        elseif ($result.Status -eq 'Error') {
            # Without a completed audit nothing can be declared safe.
            foreach ($name in @($remaining.Keys)) {
                & $reject $name 'audit-error' "vulnerability audit could not be completed ($service): $($result.Message)"
            }
        }
    }

    # --- 2. PyPI release data: yanked, cooldown ----------------------------------
    $releases = @{}
    $expedited = [string[]]@($Expedite.Keys | Where-Object { $remaining.ContainsKey($_) -and $remaining[$_] -eq $Expedite[$_] })
    if ($remaining.Count -gt 0) {
        foreach ($name in $expedited) {
            Write-Log "Cooldown skipped for $name==$($remaining[$name]) (expedited). Every other check still applies." 'WARN'
        }
        Write-Log "Checking PyPI release data (yanked, cooldown: $MinimumAgeDays day(s)) for $($remaining.Count) candidate(s) of $GroupName..."
        $ageCheck = Test-PackageAge -Packages $remaining -MinimumAgeDays $MinimumAgeDays -Expedite $expedited

        $ageReportFile = Join-Path $ReportsFolder "Report_PackageAge-$($GroupName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        Write-JsonFile -Path $ageReportFile -InputObject @($ageCheck.Results | Select-Object -Property * -ExcludeProperty Release) -Depth 5
        Write-Log "Package age report saved to: $ageReportFile"

        foreach ($ageResult in @($ageCheck.Results)) {
            $name = [string]$ageResult.Package
            if ($null -eq $ageResult.AgeDays) {
                & $reject $name 'pypi-metadata' "cooldown: could not verify the publish date on PyPI ($($ageResult.Error))"
            }
            elseif ($ageResult.Yanked) {
                $why = if ($ageResult.YankedReason) { ": $($ageResult.YankedReason)" } else { '' }
                & $reject $name 'yanked' "yanked on PyPI$why"
            }
            elseif (-not $ageResult.Passed) {
                & $reject $name 'cooldown' "cooldown: published $($ageResult.AgeDays) day(s) ago, requires $MinimumAgeDays$(& $eligibleText $ageResult.EligibleUtc)"
            }
            else {
                $releases[$name] = $ageResult.Release
            }
        }
    }

    if ($remaining.Count -eq 0) {
        return @{ Packages = @{} + $Packages; Rejected = $rejected.ToArray(); AuditResults = $auditResults.ToArray(); Verified = @{}; StagingPath = $null; Scan = $null }
    }

    # --- 3. Download into the staging folder ---------------------------------------
    $staging = Join-Path $StagingRoot ([guid]::NewGuid().ToString('N'))
    $scan = $null
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        Write-Log "Downloading $($remaining.Count) candidate(s) of $GroupName into a staging folder - nothing is published before every check passed..."
        $pipArgs = @(
            '-m', 'pip', 'download',
            '-d', $staging,
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
            & $reject $name 'no-wheel' "no downloadable wheel for Python $PythonVersion / $Platform (pip: no matching distribution)"
        }
        if ($download.Error) {
            foreach ($name in @($remaining.Keys)) {
                & $reject $name 'download' "download failed: $($download.Error)"
            }
        }

        # --- 4. Every downloaded file must be a file of this release on PyPI --------
        $stagedFiles = @(Get-ChildItem -Path $staging -File -ErrorAction SilentlyContinue)
        $claimed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $filesByName = @{}
        foreach ($name in @($remaining.Keys | Sort-Object)) {
            $release = $releases[$name]
            if ($null -eq $release) {
                & $reject $name 'pypi-metadata' 'no PyPI release data to verify the download against'
                continue
            }
            $mine = @($stagedFiles | Where-Object { $fileName = $_.Name; @($release.Files | Where-Object { $_.FileName -eq $fileName }).Count -gt 0 })
            foreach ($file in $mine) { [void]$claimed.Add($file.Name) }
            if ($mine.Count -eq 0) {
                & $reject $name 'integrity' 'the downloaded file is not one of the files PyPI lists for this release'
                continue
            }

            $problem = $null
            foreach ($file in $mine) {
                $meta = @($release.Files | Where-Object { $_.FileName -eq $file.Name })[0]
                $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                if ([string]::IsNullOrEmpty($meta.Sha256) -or -not [string]::Equals($hash, $meta.Sha256, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $problem = @('integrity', "sha256 of $($file.Name) does not match PyPI (expected $($meta.Sha256), got $hash)")
                    break
                }
                if ($meta.Yanked) {
                    $why = if ($meta.YankedReason) { ": $($meta.YankedReason)" } else { '' }
                    $problem = @('yanked', "$($file.Name) is yanked on PyPI$why")
                    break
                }
                # A file can be added to an existing release later; its own upload date counts.
                $fileAge = [math]::Floor(($nowUtc - $meta.UploadTimeUtc).TotalDays)
                if ($expedited -notcontains $name -and $fileAge -lt $MinimumAgeDays) {
                    $problem = @('cooldown', "cooldown: $($file.Name) was uploaded $fileAge day(s) ago, requires $MinimumAgeDays$(& $eligibleText $meta.UploadTimeUtc.AddDays($MinimumAgeDays))")
                    break
                }
            }
            if ($problem) { & $reject $name $problem[0] $problem[1] }
            else { $filesByName[$name] = $mine }
        }
        foreach ($file in $stagedFiles) {
            if (-not $claimed.Contains($file.Name)) {
                Write-Log "Downloaded file belongs to no candidate and is discarded: $($file.Name)" 'WARN'
            }
        }

        # --- 5. Defender scan of the staged files -------------------------------------
        if ($filesByName.Count -gt 0) {
            $scan = Invoke-WheelhouseDefenderScan -Path @($staging) -ReportsFolder $ReportsFolder
            if ($scan.Status -eq 'Threat') {
                $threats = @($scan.Threats)
                $matchedThreats = [System.Collections.Generic.HashSet[int]]::new()
                foreach ($name in @($filesByName.Keys | Sort-Object)) {
                    $hits = @()
                    for ($i = 0; $i -lt $threats.Count; $i++) {
                        foreach ($file in $filesByName[$name]) {
                            if (([string]$threats[$i].Resource).IndexOf($file.FullName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                [void]$matchedThreats.Add($i)
                                $hits += "$($threats[$i].ThreatName) in $($file.Name)"
                            }
                        }
                    }
                    if ($hits.Count -gt 0) {
                        & $reject $name 'defender' "Microsoft Defender detected $($hits -join '; ')"
                        $filesByName.Remove($name)
                    }
                }
                if ($matchedThreats.Count -lt $threats.Count) {
                    # A detection that names no single staged file blocks every file staged with it.
                    foreach ($name in @($filesByName.Keys)) {
                        & $reject $name 'defender' "Microsoft Defender reported a threat in the staging folder that could not be matched to one file: $($scan.Message)"
                        $filesByName.Remove($name)
                    }
                }
            }
            elseif ($scan.Status -eq 'Error') {
                if ($RequireDefenderScan) {
                    foreach ($name in @($filesByName.Keys)) {
                        & $reject $name 'defender' "the Defender scan could not be completed and RequireDefenderScanAtIntake is set: $($scan.Message)"
                        $filesByName.Remove($name)
                    }
                }
                else {
                    Write-Log "The downloads could not be scanned with Microsoft Defender ($($scan.Message)). They are published without an intake scan; set RequireDefenderScanAtIntake to reject them instead." 'WARN'
                }
            }

            # Real-time protection may have removed a file while it was staged.
            foreach ($name in @($filesByName.Keys)) {
                $gone = @($filesByName[$name] | Where-Object { -not (Test-Path -LiteralPath $_.FullName) })
                if ($gone.Count -gt 0) {
                    & $reject $name 'defender' "$($gone[0].Name) was removed by Microsoft Defender while it was staged"
                    $filesByName.Remove($name)
                }
            }
        }

    }
    catch {
        Remove-Item -Path $staging -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }

    if ($filesByName.Count -eq 0) {
        Remove-Item -Path $staging -Recurse -Force -ErrorAction SilentlyContinue
        $staging = $null
    }
    return @{
        Packages     = @{} + $Packages
        Rejected     = $rejected.ToArray()
        AuditResults = $auditResults.ToArray()
        Verified     = $filesByName
        StagingPath  = $staging
        # The Defender scan of the staged files ($null if nothing was scanned).
        Scan         = $scan
    }
}

function Publish-CandidateIntake {
    # Second half of intake: publishes what Invoke-CandidateIntake verified, under the
    # write lock (taken here unless -LockHeld; waits up to -TimeoutSeconds):
    #   1. the denylist is read again - a version blocked while the checks ran is rejected;
    #   2. a journal records what is about to be published;
    #   3. each package's staged files are copied in (Publish-StagedWheel);
    #   4. Complete-WheelhousePublishJournal adds them to the manifest and lists the pins
    #      of -Additions in -GroupFile - the same step that finishes an interrupted publish;
    #   5. the catalog marks them Published and the history records it.
    # Always deletes the staging folder. Returns @{ Accepted = @{name=version};
    # Rejected = [...] (categories denylist, publish); Published = manifest entries;
    # Manifest = the manifest afterwards ($null if nothing was verified) }.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Intake,

        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [string]$GroupFile,

        # name -> version of the new pins to list in -GroupFile once published. Other
        # verified packages are pins the group already lists (their wheel was missing).
        [hashtable]$Additions = @{},

        # name -> version the addition replaces in -GroupFile (remediation): the group's pin
        # is swapped instead of a line being added.
        [hashtable]$Replaces = @{},

        [string]$DenylistPath = (Get-WheelhouseDenylistPath),

        # name -> text added to the "Published" history entry (e.g. why the cooldown was skipped).
        [hashtable]$EventDetail = @{},

        [switch]$LockHeld,

        [ValidateRange(0, 3600)]
        [int]$TimeoutSeconds = 300
    )

    $accepted = @{}
    $rejected = [System.Collections.Generic.List[object]]::new()
    $published = [System.Collections.Generic.List[object]]::new()
    $manifestAfter = $null
    $verified = $Intake.Verified
    $versions = $Intake.Packages
    $groupName = Split-Path -Path $GroupFile -Leaf

    try {
        if (-not $verified -or $verified.Count -eq 0 -or -not $PSCmdlet.ShouldProcess($GroupFile, 'Publish verified candidates')) {
            return @{ Accepted = $accepted; Rejected = $rejected.ToArray(); Published = $published.ToArray(); Manifest = $null }
        }

        $lock = if ($LockHeld) { $null } else { Open-WheelhouseWrite -WheelhousePath $WheelhousePath -TimeoutSeconds $TimeoutSeconds -DenylistPath $DenylistPath }
        try {
            # 1. Blocked while the checks ran?
            $denylist = @(Read-WheelhouseDenylist -Path $DenylistPath)
            $plans = [ordered]@{}
            foreach ($name in @($verified.Keys | Sort-Object)) {
                $blocked = Get-DenylistMatch -Name $name -Version $versions[$name] -Denylist $denylist
                if ($blocked) {
                    $why = if ($blocked.reason) { ": $($blocked.reason)" } else { '' }
                    $rejected.Add([PSCustomObject]@{ Name = $name; Version = $versions[$name]; Category = 'denylist'; Reason = "denylisted while the checks ran ($($blocked.version), $($blocked.source))$why" })
                    continue
                }
                $plans[$name] = @(foreach ($file in $verified[$name]) {
                        $info = Get-WheelFileInfo -FileName $file.Name
                        [PSCustomObject]@{
                            name           = $(if ($info) { $info.Name } else { $name })
                            version        = $(if ($info) { $info.Version } else { $versions[$name] })
                            file           = $file.Name
                            sha256         = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
                            python_tag     = $(if ($info) { $info.PythonTag } else { '' })
                            abi_tag        = $(if ($info) { $info.AbiTag } else { '' })
                            platform_tag   = $(if ($info) { $info.PlatformTag } else { '' })
                            downloaded_utc = (Get-Date).ToUniversalTime().ToString('o')
                        }
                    })
            }

            if ($plans.Count -gt 0) {
                # 2. Journal - a crash from here on is finished by the next writer.
                $plannedAdditions = @(foreach ($name in $plans.Keys) {
                        if (-not $Additions.ContainsKey($name)) { continue }
                        $planned = [ordered]@{ name = $name; version = $versions[$name] }
                        if ($Replaces.ContainsKey($name)) { $planned['replaces'] = [string]$Replaces[$name] }
                        $planned
                    })
                $journal = New-WheelhouseJournal -WheelhousePath $WheelhousePath -Operation 'publish' -Data ([ordered]@{
                        group_file = $GroupFile
                        entries    = @(foreach ($name in $plans.Keys) { $plans[$name] })
                        additions  = $plannedAdditions
                    })

                # 3. Copy the files in.
                foreach ($name in @($plans.Keys)) {
                    $done = [System.Collections.Generic.List[object]]::new()
                    try {
                        foreach ($file in $verified[$name]) {
                            $done.Add((Publish-StagedWheel -Path $file.FullName -WheelhousePath $WheelhousePath))
                        }
                    }
                    catch {
                        $failure = $_.Exception.Message
                        foreach ($item in $done) {
                            if ($item.Created) { Remove-Item -LiteralPath (Join-Path $WheelhousePath $item.Entry.file) -Force -ErrorAction SilentlyContinue }
                        }
                        $rejected.Add([PSCustomObject]@{ Name = $name; Version = $versions[$name]; Category = 'publish'; Reason = "could not be copied into the wheelhouse: $failure" })
                        continue
                    }
                    $accepted[$name] = $versions[$name]
                    foreach ($item in $done) { $published.Add($item.Entry) }
                }

                # 4. Manifest and group file.
                $completeData = @{
                    group_file = $GroupFile
                    entries    = $published.ToArray()
                    additions  = @($plannedAdditions | Where-Object { $accepted.ContainsKey($_.name) })
                }
                Complete-WheelhousePublishJournal -WheelhousePath $WheelhousePath -Data $completeData

                # 5. Catalog and history.
                $changes = @(foreach ($name in @($accepted.Keys | Sort-Object)) {
                        $files = @($published | Where-Object { $_.name -eq $name } | ForEach-Object { $_.file })
                        $where = if ($Replaces.ContainsKey($name)) { "replaced $name==$($Replaces[$name]) in $groupName" } elseif ($Additions.ContainsKey($name)) { "added to $groupName" } else { "wheel for the pin already listed in $groupName" }
                        $extra = if ($EventDetail.ContainsKey($name)) { "; $($EventDetail[$name])" } else { '' }
                        [PSCustomObject]@{
                            Name    = $name
                            Version = $accepted[$name]
                            State   = 'Published'
                            Action  = 'Published'
                            Detail  = "$where; $($files -join ', ') verified against PyPI's sha256$extra"
                        }
                    })
                # A completed intake scan found nothing in what is now published: record it as
                # the version's scan result (a scan that could not run records nothing).
                $intakeScan = $null
                if ($Intake.Scan -and $Intake.Scan.Status -in 'Clean', 'Threat' -and $published.Count -gt 0) {
                    $intakeScan = [PSCustomObject]@{
                        Status       = 'Clean'
                        ScannedPaths = @($published | ForEach-Object { Join-Path $WheelhousePath $_.file })
                        Threats      = @()
                    }
                }
                Set-WheelhouseCatalogState -WheelhousePath $WheelhousePath -Change $changes -ScanResult $intakeScan
                Remove-WheelhouseJournal -Path $journal
            }
            $manifestAfter = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
        }
        finally {
            Exit-WheelhouseLock -Lock $lock
        }
    }
    finally {
        if ($Intake.StagingPath) { Remove-Item -Path $Intake.StagingPath -Recurse -Force -ErrorAction SilentlyContinue }
    }

    return @{ Accepted = $accepted; Rejected = $rejected.ToArray(); Published = $published.ToArray(); Manifest = $manifestAfter }
}

function Publish-StagedWheel {
    # Moves one verified wheel from the staging folder into the wheelhouse. It is copied
    # in under a temporary name (<file>.partial, which no index serves), checked, and
    # then renamed, so clients never see a half-written file. A file of the same name
    # that is already in the wheelhouse (untracked) is kept only if its content is
    # identical to the verified one.
    # Returns @{ Entry = <manifest entry>; Created = <whether this call wrote the file> }.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    $fileName = Split-Path -Path $Path -Leaf
    $info = Get-WheelFileInfo -FileName $fileName
    if (-not $info) { throw "Not a wheel file name: $fileName" }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    $destination = Join-Path $WheelhousePath $fileName
    $created = $false

    if (Test-Path -LiteralPath $destination) {
        $existingHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($existingHash -ne $hash) {
            throw "a different file named '$fileName' is already in the wheelhouse but not tracked by the manifest. Remove it, then run again."
        }
        Write-Log "$fileName was already in the wheelhouse (untracked) with identical, verified content - keeping it." 'WARN'
    }
    elseif ($PSCmdlet.ShouldProcess($destination, 'Publish wheel')) {
        $partial = "$destination.partial"
        try {
            Copy-Item -LiteralPath $Path -Destination $partial -Force -ErrorAction Stop
            if ((Get-FileHash -LiteralPath $partial -Algorithm SHA256 -ErrorAction Stop).Hash -ne $hash) {
                throw "the copy of '$fileName' in the wheelhouse does not match the verified file."
            }
            Move-Item -LiteralPath $partial -Destination $destination -ErrorAction Stop
            $created = $true
        }
        finally {
            if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue }
        }
    }

    return [PSCustomObject]@{
        Entry   = [PSCustomObject]@{
            name           = $info.Name
            version        = $info.Version
            file           = $fileName
            sha256         = $hash
            python_tag     = $info.PythonTag
            abi_tag        = $info.AbiTag
            platform_tag   = $info.PlatformTag
            downloaded_utc = (Get-Date).ToUniversalTime().ToString('o')
        }
        Created = $created
    }
}
