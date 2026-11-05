# ---------------------------------------------------------------------------
# Journal (<wheelhouse>\.journal\): crash safety for multi-step changes
# ---------------------------------------------------------------------------
# Publishing, removing and restoring a package each change several files (wheels,
# manifest, group files, quarantine, denylist). Before the first step the writer saves
# what it is about to do as a journal file, and deletes it after the last step. A journal
# that is still there means the process died part-way: the next writer finishes the
# change right after it takes the write lock (Open-WheelhouseWrite ->
# Repair-WheelhouseJournal). Every Complete-* step checks the current state first, so a
# repair can itself be interrupted and repeated. The normal publish and restore paths
# run the same Complete-* functions, so a crash is finished exactly as the run would have.
#
# An exception inside a writer is handled there (remove undoes its steps and deletes the
# journal); the journal is only for a process that never got that far.

function Get-WheelhouseJournalFolder {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath
    )

    return Join-Path $WheelhousePath '.journal'
}

function New-WheelhouseJournal {
    # Saves what an operation is about to do; returns the journal file path.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        [ValidateSet('publish', 'remove', 'restore')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Data
    )

    $folder = Get-WheelhouseJournalFolder -WheelhousePath $WheelhousePath
    $path = Join-Path $folder ("{0}_{1}_{2}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $Operation, [guid]::NewGuid().ToString('N').Substring(0, 8))
    if (-not $PSCmdlet.ShouldProcess($path, "Write $Operation journal")) { return $null }
    if (-not (Test-Path -Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    $journal = [ordered]@{
        operation   = $Operation
        started_utc = (Get-Date).ToUniversalTime().ToString('o')
        user        = (Get-WheelhouseUserName)
        pid         = $PID
        data        = $Data
    }
    Write-JsonFile -Path $path -InputObject $journal -Depth 10
    return $path
}

function Remove-WheelhouseJournal {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Path
    )

    if ($Path -and (Test-Path -LiteralPath $Path) -and $PSCmdlet.ShouldProcess($Path, 'Remove journal')) {
        Remove-Item -LiteralPath $Path -Force
    }
}

function Repair-WheelhouseJournal {
    # Finishes every operation a crashed process left half-done, oldest first, then
    # reconciles the catalog. Call it while holding the write lock. A journal that cannot
    # be read or finished throws: the wheelhouse needs a look by hand before anything
    # else changes it.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [string]$DenylistPath = (Get-WheelhouseDenylistPath)
    )

    $folder = Get-WheelhouseJournalFolder -WheelhousePath $WheelhousePath
    if (-not (Test-Path -Path $folder)) { return }
    $files = @(Get-ChildItem -Path $folder -Filter '*.json' -File | Sort-Object Name)
    if ($files.Count -eq 0 -or -not $PSCmdlet.ShouldProcess($folder, 'Finish interrupted operations')) { return }

    foreach ($file in $files) {
        try {
            $journal = Get-Content -Path $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "A journal of an interrupted operation could not be read: $($file.FullName) ($($_.Exception.Message)). Check the wheelhouse by hand, then delete that file."
        }
        Write-Log "Finishing an interrupted $($journal.operation) (started $($journal.started_utc) by $($journal.user), journal $($file.Name))..." 'WARN'
        try {
            switch ([string]$journal.operation) {
                'publish' { Complete-WheelhousePublishJournal -WheelhousePath $WheelhousePath -Data $journal.data }
                'remove' { Complete-WheelhouseRemoveJournal -WheelhousePath $WheelhousePath -Data $journal.data -DenylistPath $DenylistPath }
                'restore' { [void](Complete-WheelhouseRestoreJournal -WheelhousePath $WheelhousePath -Data $journal.data -DenylistPath $DenylistPath) }
                default { throw "unknown operation '$($journal.operation)'" }
            }
        }
        catch {
            throw "An interrupted $($journal.operation) could not be finished ($($_.Exception.Message)). Journal: $($file.FullName). Fix the cause, or check the wheelhouse by hand and delete the journal."
        }
        $detail = "finished an interrupted $($journal.operation) started $($journal.started_utc) by $($journal.user)"
        Write-WheelhouseEvent -WheelhousePath $WheelhousePath -Action 'Recovered' -Package ([string]$journal.data.name) -Version ([string]$journal.data.version) -Detail $detail
        Remove-Item -LiteralPath $file.FullName -Force
        Write-Log "Interrupted $($journal.operation) finished." 'OK'
    }
    Update-WheelhouseCatalog -WheelhousePath $WheelhousePath -LockHeld -DenylistPath $DenylistPath
}

function Complete-WheelhousePublishJournal {
    # Publish, from the files on: every journal entry whose wheel is in the wheelhouse
    # with the recorded sha256 is added to the manifest (if missing), and each addition
    # whose wheels are all there is listed in the group file (if missing). Leftover
    # *.partial copies are deleted; an entry whose wheel is missing or different is
    # left out, and so is its pin. An addition with "replaces" (a remediation) swaps the
    # group's pin of that package instead of adding a line.
    # Data: group_file; entries[] (manifest entries); additions[] ({ name; version; replaces }).
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        $Data
    )

    if (-not $PSCmdlet.ShouldProcess($WheelhousePath, 'Complete publish')) { return }
    $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $manifest) { $entries.Add($entry) }
    $tracked = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $manifest) { [void]$tracked.Add([string]$entry.file) }

    $complete = @{}
    $changed = $false
    foreach ($entry in @($Data.entries)) {
        if ($null -eq $entry) { continue }
        $path = Join-Path $WheelhousePath ([string]$entry.file)
        if (Test-Path -LiteralPath "$path.partial") { Remove-Item -LiteralPath "$path.partial" -Force }
        $name = [string]$entry.name
        if (-not $complete.ContainsKey($name)) { $complete[$name] = $true }
        $present = (Test-Path -LiteralPath $path) -and ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq [string]$entry.sha256)
        if (-not $present) {
            $complete[$name] = $false
            continue
        }
        if (-not $tracked.Contains([string]$entry.file)) {
            $entries.Add([PSCustomObject]@{
                    name           = $name
                    version        = [string]$entry.version
                    file           = [string]$entry.file
                    sha256         = [string]$entry.sha256
                    python_tag     = [string]$entry.python_tag
                    abi_tag        = [string]$entry.abi_tag
                    platform_tag   = [string]$entry.platform_tag
                    downloaded_utc = ConvertTo-IsoTimestamp -Value $entry.downloaded_utc
                })
            [void]$tracked.Add([string]$entry.file)
            $changed = $true
        }
    }
    if ($changed) { Save-WheelhouseManifest -Manifest $entries.ToArray() -WheelhousePath $WheelhousePath }

    $groupFile = [string]$Data.group_file
    foreach ($addition in @($Data.additions)) {
        if ($null -eq $addition) { continue }
        $name = Get-NormalizedPackageName ([string]$addition.name)
        if (-not $complete[$name]) { continue }
        $listed = if (Test-Path -Path $groupFile) { Read-RequirementFile -FilePath $groupFile } else { @{} }
        if ($listed[$name] -eq [string]$addition.version) { continue }
        # A dictionary (in-process) or an object (read back from a journal) - both answer .replaces.
        if ([string]$addition.replaces) {
            Set-RequirementInGroupFile -GroupFile $groupFile -Name $name -Version ([string]$addition.version)
        }
        else {
            Add-RequirementToGroupFile -GroupFile $groupFile -Name $name -Version ([string]$addition.version)
        }
    }
}

function Complete-WheelhouseRemoveJournal {
    # Remove / quarantine, rolled forward: denylist entry and quarantine record present,
    # pin out of the group files, entries out of the manifest, files moved to the
    # quarantine folder or deleted.
    # Data: name; version; mode (Quarantine/Delete); files[]; groups[] (paths);
    # quarantine_folder; quarantine_record; deny (bool); deny_reason; deny_source.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        $Data,

        [string]$DenylistPath = (Get-WheelhouseDenylistPath)
    )

    $name = [string]$Data.name
    $version = [string]$Data.version
    $quarantine = ([string]$Data.mode -eq 'Quarantine')
    if (-not $PSCmdlet.ShouldProcess("$name==$version", 'Complete removal')) { return }

    if ($Data.deny) {
        $existing = @(Read-WheelhouseDenylist -Path $DenylistPath | Where-Object { $_.name -eq $name -and [string]$_.version -eq $version })
        if ($existing.Count -eq 0) {
            [void](Add-WheelhouseDenylistEntry -Name $name -Version $version -Reason ([string]$Data.deny_reason) -Source ([string]$Data.deny_source) -Path $DenylistPath)
        }
    }
    if ($quarantine -and $Data.quarantine_record) {
        $records = @(Read-QuarantineRecord -WheelhousePath $WheelhousePath)
        if (-not ($records | Where-Object { $_.id -eq $Data.quarantine_record.id })) {
            Save-QuarantineRecord -WheelhousePath $WheelhousePath -Record (@($records) + $Data.quarantine_record)
        }
    }
    foreach ($groupFile in @($Data.groups)) {
        if ($groupFile -and (Test-Path -Path $groupFile) -and (Read-RequirementFile -FilePath $groupFile)[$name] -eq $version) {
            [void](Remove-RequirementFromGroupFile -GroupFile $groupFile -Name $name -Version $version)
        }
    }
    $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
    $kept = @($manifest | Where-Object { -not ($_.name -eq $name -and $_.version -eq $version) })
    if ($kept.Count -ne $manifest.Count) { Save-WheelhouseManifest -Manifest $kept -WheelhousePath $WheelhousePath }

    foreach ($file in @($Data.files)) {
        $source = Join-Path $WheelhousePath ([string]$file)
        if (-not (Test-Path -LiteralPath $source)) { continue }
        if ($quarantine) {
            $folder = [string]$Data.quarantine_folder
            if (-not (Test-Path -Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
            $destination = Join-Path $folder ([string]$file)
            if (Test-Path -LiteralPath $destination) {
                if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash) {
                    throw "'$file' is both in the wheelhouse and, with different content, in $folder."
                }
                Remove-Item -LiteralPath $source -Force
            }
            else {
                Move-Item -LiteralPath $source -Destination $destination -ErrorAction Stop
            }
        }
        else {
            Remove-Item -LiteralPath $source -Force -ErrorAction Stop
        }
    }
}

function Complete-WheelhouseRestoreJournal {
    # Restore, rolled forward: every recorded file back in the wheelhouse (moved from the
    # quarantine folder after its hash is checked), in the manifest and its pins in the
    # recorded group files; the quarantine record and empty folder gone; the denylist
    # entry quarantining created removed (unless keep_denylist). Returns $true if that
    # denylist entry was removed.
    # Data: id; record (the quarantine record); folder; keep_denylist (bool).
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$WheelhousePath,

        [Parameter(Mandatory)]
        $Data,

        [string]$DenylistPath = (Get-WheelhouseDenylistPath)
    )

    $record = $Data.record
    $folder = [string]$Data.folder
    if (-not $PSCmdlet.ShouldProcess("$($record.name)==$($record.version)", 'Complete restore')) { return $false }

    foreach ($entry in @($record.files)) {
        $destination = Join-Path $WheelhousePath ([string]$entry.file)
        if (Test-Path -LiteralPath $destination) { continue }
        $source = Join-Path $folder ([string]$entry.file)
        if (-not (Test-Path -LiteralPath $source)) {
            throw "Quarantined file is missing: $source"
        }
        $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($hash -ne [string]$entry.sha256) {
            throw "Cannot restore '$($entry.file)': its hash changed while in quarantine (expected $($entry.sha256), got $hash)."
        }
        Move-Item -LiteralPath $source -Destination $destination -ErrorAction Stop
    }

    $manifest = Read-WheelhouseManifest -WheelhousePath $WheelhousePath
    $missing = @($record.files | Where-Object { $file = [string]$_.file; -not ($manifest | Where-Object { $_.file -eq $file }) })
    if ($missing.Count -gt 0) { Save-WheelhouseManifest -Manifest (@($manifest) + $missing) -WheelhousePath $WheelhousePath }

    foreach ($groupName in @($record.groups)) {
        if (-not $groupName) { continue }
        $groupFile = Join-Path $WheelhousePath ([string]$groupName)
        $listed = if (Test-Path -Path $groupFile) { Read-RequirementFile -FilePath $groupFile } else { @{} }
        if ($listed[[string]$record.name] -ne [string]$record.version) {
            Add-RequirementToGroupFile -GroupFile $groupFile -Name $record.name -Version $record.version
        }
    }

    $records = @(Read-QuarantineRecord -WheelhousePath $WheelhousePath)
    if ($records | Where-Object { $_.id -eq $Data.id }) {
        Save-QuarantineRecord -WheelhousePath $WheelhousePath -Record @($records | Where-Object { $_.id -ne $Data.id })
    }
    if ((Test-Path -Path $folder) -and -not (Get-ChildItem -Path $folder -Force)) {
        Remove-Item -Path $folder -Force
    }

    if ($Data.keep_denylist) { return $false }
    return [bool](Remove-WheelhouseDenylistEntry -Name $record.name -Version $record.version -OnlySource 'quarantined' -Path $DenylistPath)
}
