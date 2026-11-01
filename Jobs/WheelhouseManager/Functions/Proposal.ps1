# ---------------------------------------------------------------------------
# Proposals: who asked for a change to the wheelhouse, and who approved it
# ---------------------------------------------------------------------------
# A resolve (Update-Requirement.ps1) or a remediation (Invoke-WheelhouseRemediation.ps1)
# ends with a proposal for the requirements.txt it wrote: Input\proposal.json, one current
# proposal; every change of it is appended to Input\proposal-history.jsonl. The update run
# merges new pins only for an approved proposal whose requirements.txt hash still matches.
#
# ApprovalMode (setting, decision D3):
#   SamePersonAllowed (default) - anyone may approve, also the requester; publishing counts
#                                 as approving, and who did it is recorded.
#   SeparateApprover            - the approver must be another account than the requester.
#
# Proposal: id; kind resolve|remediation|manual; state Proposed|Approved|Rejected|Published;
#   requested_by; requested_utc; requirements_path; requirements_sha256; pins[];
#   replace[] { name; from; to } and retire[] { name; version; ids[] } (remediation only);
#   expedite { name: version }; expedite_reason; note; approved_by; approved_utc;
#   rejected_by; rejected_utc; decision_note; published_utc; outcome.

$script:ProposalStates = @('Proposed', 'Approved', 'Rejected', 'Published')
$script:ApprovalModes = @('SamePersonAllowed', 'SeparateApprover')

function Get-WheelhouseProposalPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$ManagerRoot = $script:ManagerRoot
    )

    return Join-Path (Join-Path $ManagerRoot 'Input') 'proposal.json'
}

function Get-WheelhouseCurrentUser {
    # DOMAIN\user of this process - the name recorded for requests and approvals.
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try { return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
    catch { return $(if ($env:USERNAME) { $env:USERNAME } else { 'unknown' }) }
}

function Get-RequirementFileHash {
    # SHA256 of a requirements file, or '' if it does not exist.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Read-WheelhouseProposal {
    # The current proposal, or $null if there is none. A damaged file throws.
    [CmdletBinding()]
    param(
        [string]$Path = (Get-WheelhouseProposalPath)
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($content)) { return $null }
    try { $item = ConvertFrom-Json -InputObject $content -ErrorAction Stop }
    catch { throw "proposal.json exists but could not be parsed ($($_.Exception.Message)). Delete '$Path' and resolve again." }
    $expedite = [ordered]@{}
    if ($item.expedite) { foreach ($property in $item.expedite.PSObject.Properties) { $expedite[$property.Name] = [string]$property.Value } }
    return [PSCustomObject]@{
        id                  = [string]$item.id
        kind                = [string]$item.kind
        state               = [string]$item.state
        requested_by        = [string]$item.requested_by
        requested_utc       = ConvertTo-IsoTimestamp -Value $item.requested_utc
        requirements_path   = [string]$item.requirements_path
        requirements_sha256 = [string]$item.requirements_sha256
        pins                = @(@($item.pins) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        replace             = @(@($item.replace) | Where-Object { $_ } | ForEach-Object { [PSCustomObject]@{ name = [string]$_.name; from = [string]$_.from; to = [string]$_.to } })
        retire              = @(@($item.retire) | Where-Object { $_ } | ForEach-Object { [PSCustomObject]@{ name = [string]$_.name; version = [string]$_.version; ids = @(@($_.ids) | Where-Object { $_ } | ForEach-Object { [string]$_ }) } })
        expedite            = $expedite
        expedite_reason     = [string]$item.expedite_reason
        note                = [string]$item.note
        approved_by         = [string]$item.approved_by
        approved_utc        = ConvertTo-IsoTimestamp -Value $item.approved_utc
        rejected_by         = [string]$item.rejected_by
        rejected_utc        = ConvertTo-IsoTimestamp -Value $item.rejected_utc
        decision_note       = [string]$item.decision_note
        published_utc       = ConvertTo-IsoTimestamp -Value $item.published_utc
        outcome             = [string]$item.outcome
    }
}

function Save-WheelhouseProposal {
    # Writes the current proposal and appends it, with -Action, to the history next to it.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $Proposal,

        [Parameter(Mandatory)]
        [string]$Action,

        [string]$Path = (Get-WheelhouseProposalPath)
    )

    if (-not $PSCmdlet.ShouldProcess($Path, "Save proposal ($Action)")) { return }
    $folder = Split-Path -Path $Path -Parent
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    Write-JsonFile -Path $Path -InputObject $Proposal -Depth 6
    $line = ConvertTo-Json -Compress -Depth 6 -InputObject ([ordered]@{
            ts       = (Get-Date).ToUniversalTime().ToString('o')
            user     = Get-WheelhouseCurrentUser
            action   = $Action
            proposal = $Proposal
        })
    if ($Action -ne 'Proposed') {
        $who = if ($Proposal.approved_by -and $Action -eq 'Approved') { " by $($Proposal.approved_by)" } elseif ($Proposal.rejected_by -and $Action -eq 'Rejected') { " by $($Proposal.rejected_by)" } else { '' }
        Write-WheelhouseEventLog -Id 1004 -Message "Proposal $($Proposal.id) ($($Proposal.kind), requested by $($Proposal.requested_by)) $($Action.ToLowerInvariant())$who. $($Proposal.outcome)"
    }
    $history = Join-Path $folder 'proposal-history.jsonl'
    try { [System.IO.File]::AppendAllText($history, $line + "`n", [System.Text.UTF8Encoding]::new($false)) }
    catch { Write-Log "Could not write the proposal history ($history): $($_.Exception.Message)" 'WARN' }
}

function New-WheelhouseProposal {
    # Proposes the requirements file as it is now (replacing any earlier proposal). Returns
    # the proposal.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$RequirementsPath,

        [ValidateSet('resolve', 'remediation', 'manual')]
        [string]$Kind = 'resolve',

        [string]$RequestedBy = (Get-WheelhouseCurrentUser),

        # Remediation: { name; from; to } pins to swap in the groups that list the
        # vulnerable version, and { name; version; ids } versions to quarantine afterwards.
        [AllowEmptyCollection()]
        [object[]]$Replace = @(),

        [AllowEmptyCollection()]
        [object[]]$Retire = @(),

        # name -> version whose cooldown the publish may skip, with the reason.
        [hashtable]$Expedite = @{},

        [string]$ExpediteReason = '',

        [string]$Note = '',

        [string]$Path = (Get-WheelhouseProposalPath)
    )

    if (-not (Test-Path -LiteralPath $RequirementsPath -PathType Leaf)) { throw "Nothing to propose: $RequirementsPath does not exist." }
    if ($Expedite.Count -gt 0 -and [string]::IsNullOrWhiteSpace($ExpediteReason)) { throw [System.ArgumentException]::new('Skipping the cooldown needs a reason.') }
    $pins = Read-RequirementFile -FilePath $RequirementsPath
    $expediteMap = [ordered]@{}
    foreach ($name in ($Expedite.Keys | Sort-Object)) { $expediteMap[(Get-NormalizedPackageName $name)] = [string]$Expedite[$name] }
    $now = (Get-Date).ToUniversalTime()
    $proposal = [ordered]@{
        id                  = $now.ToString('yyyyMMdd_HHmmss')
        kind                = $Kind
        state               = 'Proposed'
        requested_by        = $RequestedBy
        requested_utc       = $now.ToString('o')
        requirements_path   = $RequirementsPath
        requirements_sha256 = Get-RequirementFileHash -Path $RequirementsPath
        pins                = @($pins.Keys | Sort-Object | ForEach-Object { "$_==$($pins[$_])" })
        replace             = @($Replace | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = (Get-NormalizedPackageName ([string]$_.name)); from = [string]$_.from; to = [string]$_.to } })
        retire              = @($Retire | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = (Get-NormalizedPackageName ([string]$_.name)); version = [string]$_.version; ids = @($_.ids) } })
        expedite            = $expediteMap
        expedite_reason     = $ExpediteReason
        note                = $Note
        approved_by         = ''
        approved_utc        = ''
        rejected_by         = ''
        rejected_utc        = ''
        decision_note       = ''
        published_utc       = ''
        outcome             = ''
    }
    if (-not $PSCmdlet.ShouldProcess($Path, "Propose $RequirementsPath")) { return }
    Save-WheelhouseProposal -Proposal $proposal -Action 'Proposed' -Path $Path
    Write-Log "Proposal $($proposal.id) ($Kind) recorded for $($proposal.pins.Count) pin(s), requested by $RequestedBy. It needs approval before it is published." 'OK'
    return Read-WheelhouseProposal -Path $Path
}

function Test-WheelhouseApprovalAllowed {
    # Whether -User may approve -Proposal under -Mode: $null if yes, else the reason.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Proposal,

        [Parameter(Mandatory)]
        [string]$User,

        [ValidateSet('SamePersonAllowed', 'SeparateApprover')]
        [string]$Mode = 'SamePersonAllowed'
    )

    if ($Mode -eq 'SeparateApprover' -and [string]::Equals($Proposal.requested_by, $User, [System.StringComparison]::OrdinalIgnoreCase)) {
        return "Approval must come from another person than the requester ($($Proposal.requested_by)) - ApprovalMode is SeparateApprover."
    }
    return $null
}

function Approve-WheelhouseProposal {
    # Approves the current proposal (-Id must match it). Refused if it is not Proposed, if
    # its requirements file changed since it was proposed, or by the ApprovalMode rule.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [string]$By = (Get-WheelhouseCurrentUser),

        [ValidateSet('SamePersonAllowed', 'SeparateApprover')]
        [string]$Mode = 'SamePersonAllowed',

        [string]$Note = '',

        [string]$Path = (Get-WheelhouseProposalPath)
    )

    $proposal = Read-WheelhouseProposal -Path $Path
    if (-not $proposal -or $proposal.id -ne $Id) { throw [System.Collections.Generic.KeyNotFoundException]::new("Proposal $Id is not the current proposal.") }
    if ($proposal.state -ne 'Proposed') { throw [System.InvalidOperationException]::new("Proposal $Id is already $($proposal.state).") }
    if ((Get-RequirementFileHash -Path $proposal.requirements_path) -ne $proposal.requirements_sha256) {
        throw [System.InvalidOperationException]::new("$($proposal.requirements_path) changed after proposal $Id was made. Resolve again (or propose the file as it is now) and approve that.")
    }
    $refusal = Test-WheelhouseApprovalAllowed -Proposal $proposal -User $By -Mode $Mode
    if ($refusal) { throw [System.InvalidOperationException]::new($refusal) }
    if (-not $PSCmdlet.ShouldProcess($Id, "Approve as $By")) { return }
    $proposal.state = 'Approved'
    $proposal.approved_by = $By
    $proposal.approved_utc = (Get-Date).ToUniversalTime().ToString('o')
    $proposal.decision_note = $Note
    Save-WheelhouseProposal -Proposal $proposal -Action 'Approved' -Path $Path
    Write-Log "Proposal $Id approved by $By." 'OK'
    return $proposal
}

function Deny-WheelhouseProposal {
    # Rejects the current proposal; nothing of it is published. -Reason is required.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Reason,

        [string]$By = (Get-WheelhouseCurrentUser),

        [string]$Path = (Get-WheelhouseProposalPath)
    )

    if ([string]::IsNullOrWhiteSpace($Reason)) { throw [System.ArgumentException]::new('Give a reason for rejecting the proposal.') }
    $proposal = Read-WheelhouseProposal -Path $Path
    if (-not $proposal -or $proposal.id -ne $Id) { throw [System.Collections.Generic.KeyNotFoundException]::new("Proposal $Id is not the current proposal.") }
    if ($proposal.state -notin 'Proposed', 'Approved') { throw [System.InvalidOperationException]::new("Proposal $Id is already $($proposal.state).") }
    if (-not $PSCmdlet.ShouldProcess($Id, "Reject as $By")) { return }
    $proposal.state = 'Rejected'
    $proposal.rejected_by = $By
    $proposal.rejected_utc = (Get-Date).ToUniversalTime().ToString('o')
    $proposal.decision_note = $Reason.Trim()
    Save-WheelhouseProposal -Proposal $proposal -Action 'Rejected' -Path $Path
    Write-Log "Proposal $Id rejected by ${By}: $Reason" 'WARN'
    return $proposal
}

function Resolve-WheelhouseProposalForPublish {
    # The approval gate of the update run, for the requirements file it is about to merge.
    # Returns { Allowed; Proposal; Reason }:
    #   approved proposal for this file             -> allowed
    #   proposed, -User may approve (mode rule)     -> approved now by publishing, allowed
    #   no proposal / file changed since proposed   -> SamePersonAllowed: proposed as 'manual'
    #                                                  and approved by -User; else refused
    #   rejected, or published already             -> refused / allowed (a re-run retries)
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$RequirementsPath,

        [ValidateSet('SamePersonAllowed', 'SeparateApprover')]
        [string]$Mode = 'SamePersonAllowed',

        [string]$User = (Get-WheelhouseCurrentUser),

        [string]$Path = (Get-WheelhouseProposalPath)
    )

    $hash = Get-RequirementFileHash -Path $RequirementsPath
    $proposal = Read-WheelhouseProposal -Path $Path
    $matches_ = $proposal -and $proposal.requirements_sha256 -eq $hash -and
        [string]::Equals([System.IO.Path]::GetFullPath($proposal.requirements_path), [System.IO.Path]::GetFullPath($RequirementsPath), [System.StringComparison]::OrdinalIgnoreCase)

    if (-not $matches_) {
        if ($Mode -eq 'SeparateApprover') {
            $why = if ($proposal) { "$RequirementsPath changed after proposal $($proposal.id) was made" } else { "there is no proposal for $RequirementsPath" }
            return [PSCustomObject]@{ Allowed = $false; Proposal = $proposal; Reason = "Not approved: $why. Resolve again (Update-Requirement.ps1 or the UI's Add packages tab) and have another person approve it." }
        }
        if (-not $PSCmdlet.ShouldProcess($RequirementsPath, 'Propose and approve')) { return [PSCustomObject]@{ Allowed = $false; Proposal = $proposal; Reason = 'WhatIf' } }
        $proposal = New-WheelhouseProposal -RequirementsPath $RequirementsPath -Kind 'manual' -RequestedBy $User -Path $Path -Note 'proposed when publishing (no proposal matched the file)'
        $proposal = Approve-WheelhouseProposal -Id $proposal.id -By $User -Mode $Mode -Note 'approved by publishing' -Path $Path
        return [PSCustomObject]@{ Allowed = $true; Proposal = $proposal; Reason = '' }
    }

    switch ($proposal.state) {
        'Approved' { return [PSCustomObject]@{ Allowed = $true; Proposal = $proposal; Reason = '' } }
        'Published' { return [PSCustomObject]@{ Allowed = $true; Proposal = $proposal; Reason = '' } }
        'Rejected' {
            return [PSCustomObject]@{ Allowed = $false; Proposal = $proposal; Reason = "Proposal $($proposal.id) was rejected by $($proposal.rejected_by): $($proposal.decision_note). Change requirements.in and resolve again." }
        }
        default {
            $refusal = Test-WheelhouseApprovalAllowed -Proposal $proposal -User $User -Mode $Mode
            if ($refusal) {
                return [PSCustomObject]@{ Allowed = $false; Proposal = $proposal; Reason = "Proposal $($proposal.id) is waiting for approval. $refusal" }
            }
            if (-not $PSCmdlet.ShouldProcess($proposal.id, 'Approve by publishing')) { return [PSCustomObject]@{ Allowed = $false; Proposal = $proposal; Reason = 'WhatIf' } }
            $proposal = Approve-WheelhouseProposal -Id $proposal.id -By $User -Mode $Mode -Note 'approved by publishing' -Path $Path
            return [PSCustomObject]@{ Allowed = $true; Proposal = $proposal; Reason = '' }
        }
    }
}

function Set-WheelhouseProposalPublished {
    # Records that the update run merged the proposal, with a one-line outcome.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [string]$Outcome = '',

        [string]$Path = (Get-WheelhouseProposalPath)
    )

    $proposal = Read-WheelhouseProposal -Path $Path
    if (-not $proposal -or $proposal.id -ne $Id) { return }
    if (-not $PSCmdlet.ShouldProcess($Id, 'Mark published')) { return }
    $proposal.state = 'Published'
    $proposal.published_utc = (Get-Date).ToUniversalTime().ToString('o')
    $proposal.outcome = $Outcome
    Save-WheelhouseProposal -Proposal $proposal -Action 'Published' -Path $Path
}
