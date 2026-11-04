# Pester tests for the WheelhouseManager module (Pester 5; also runs on Pester 4.10).
#   Invoke-Pester -Path .\Tests

# Mock bodies run in the module's scope, so test-case values reach them via globals.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
# New-TestRelease only builds a test object.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
param()

Describe 'WheelhouseManager' {
    BeforeAll {
        $modulePath = Join-Path (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Jobs') 'WheelhouseManager'
        Import-Module $modulePath -Force
        # No test reaches the real OSV API; the severity tests mock it themselves.
        Mock -ModuleName WheelhouseManager -CommandName Get-OsvVulnerability -MockWith { throw 'OSV is not reachable from the tests.' }
        # Proposals go to the test drive, never to the repository's Input folder.
        $global:WhmProposalPath = Join-Path $TestDrive 'proposal.json'
        Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseProposalPath -MockWith { $global:WhmProposalPath }
        # The integrity cache too (it lives on the manager server, here the test drive).
        $global:WhmStateDir = Join-Path $TestDrive 'state'
        Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseIntegrityCachePath -MockWith { Join-Path $global:WhmStateDir ("integrity-" + [Math]::Abs($WheelhousePath.ToLowerInvariant().GetHashCode()) + '.json') }

        function Get-TestFolder {
            $path = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $path | Out-Null
            return $path
        }

        # Writes a pip-audit JSON report with one vulnerable package; returns its path.
        function Write-TestAuditReport {
            param([string]$Path)
            $report = '{"dependencies":[{"name":"requests","version":"2.19.0","vulns":[{"id":"PYSEC-2018-28","aliases":["CVE-2018-18074"],"fix_versions":["2.20.0"],"description":"Credentials leak on redirect."}]},{"name":"six","version":"1.16.0","vulns":[]}],"fixes":[]}'
            Set-Content -Path $Path -Value $report
            return $Path
        }

        # A wheelhouse with two tracked wheels (six, attrs) listed in requirements-1.txt.
        function Get-TestWheelhouse {
            $wheelhouse = Get-TestFolder
            $entries = foreach ($spec in @(@('six', '1.16.0'), @('attrs', '23.1.0'))) {
                $file = "$($spec[0])-$($spec[1])-py3-none-any.whl"
                Set-Content -Path (Join-Path $wheelhouse $file) -Value "wheel $file"
                [PSCustomObject]@{
                    name           = $spec[0]
                    version        = $spec[1]
                    file           = $file
                    sha256         = (Get-FileHash -Path (Join-Path $wheelhouse $file) -Algorithm SHA256).Hash
                    python_tag     = 'py3'
                    abi_tag        = 'none'
                    platform_tag   = 'any'
                    downloaded_utc = '2026-01-01T00:00:00Z'
                }
            }
            Save-WheelhouseManifest -Manifest @($entries) -WheelhousePath $wheelhouse
            Set-Content -Path (Join-Path $wheelhouse 'requirements-1.txt') -Value @('six==1.16.0', 'attrs==23.1.0')
            return $wheelhouse
        }

        # A fake PyPI release (as Get-PyPIReleaseInfo returns it) with one wheel whose
        # content - and therefore sha256 - is known. The intake mocks below "download" it.
        function New-TestRelease {
            param(
                [string]$Name,
                [string]$Version = '1.0',
                [int]$UploadDaysAgo = 400,
                # Upload age of the wheel file itself, if it differs from the release's.
                [int]$FileUploadDaysAgo = -1,
                [switch]$Yanked,
                [switch]$FileYanked
            )
            $content = "wheel $Name $Version"
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $hash = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($content))) -replace '-', '').ToLowerInvariant()
            $now = (Get-Date).ToUniversalTime()
            $fileAge = if ($FileUploadDaysAgo -ge 0) { $FileUploadDaysAgo } else { $UploadDaysAgo }
            return [PSCustomObject]@{
                Name           = $Name
                Version        = $Version
                Files          = @([PSCustomObject]@{
                        FileName      = "$($Name -replace '-', '_')-$Version-py3-none-any.whl"
                        Sha256        = $hash
                        UploadTimeUtc = $now.AddDays(-$fileAge)
                        Yanked        = [bool]$FileYanked
                        YankedReason  = $(if ($FileYanked) { 'bad file' } else { '' })
                    })
                FirstUploadUtc = $now.AddDays(-$UploadDaysAgo)
                Yanked         = [bool]$Yanked
                YankedReason   = $(if ($Yanked) { 'broken build' } else { '' })
                Content        = $content
            }
        }

        # Mock bodies for Invoke-CandidateIntake, driven by globals (mock bodies run in
        # module scope and cannot see this file's functions):
        #   WhmReleases       name -> New-TestRelease (missing = PyPI unreachable)
        #   WhmNoWheel        names pip finds no wheel for
        #   WhmWheelOverride  name -> content actually "downloaded" (tampered file)
        #   WhmScanStatus     Clean / Error / Threat; WhmThreatPackage = name detected
        $script:intakeAgeMock = {
            $now = (Get-Date).ToUniversalTime()
            $rows = foreach ($name in $Packages.Keys) {
                $release = $global:WhmReleases[$name]
                if (-not $release) {
                    [PSCustomObject]@{ Package = $name; Version = $Packages[$name]; AgeDays = $null; Passed = $false; Release = $null; Error = 'PyPI unreachable' }
                    continue
                }
                $age = [math]::Floor(($now - $release.FirstUploadUtc).TotalDays)
                $expedited = @($Expedite) -contains $name
                [PSCustomObject]@{
                    Package = $name; Version = $Packages[$name]; AgeDays = $age; MinimumRequiredDays = $MinimumAgeDays
                    EligibleUtc = $release.FirstUploadUtc.AddDays($MinimumAgeDays).ToString('o'); Expedited = $expedited
                    Passed = ($expedited -or $age -ge $MinimumAgeDays); Yanked = $release.Yanked; YankedReason = $release.YankedReason; Release = $release
                }
            }
            @{ TooNew = @(); Results = @($rows) }
        }
        $script:intakeDownloadMock = {
            $dir = $PipArguments[[array]::IndexOf($PipArguments, '-d') + 1]
            $global:WhmIntakeDownloaded = @($Packages.Keys | Sort-Object)
            $ok = @{}
            $failed = @()
            foreach ($name in $Packages.Keys) {
                if (@($global:WhmNoWheel) -contains $name) { $failed += "$name==$($Packages[$name])"; continue }
                $release = $global:WhmReleases[$name]
                $content = if ($global:WhmWheelOverride -and $global:WhmWheelOverride.ContainsKey($name)) { $global:WhmWheelOverride[$name] } else { $release.Content }
                [System.IO.File]::WriteAllText((Join-Path $dir $release.Files[0].FileName), $content)
                $ok[$name] = $Packages[$name]
            }
            @{ Succeeded = $ok; Failed = $failed; Error = $null }
        }
        $script:intakeScanMock = {
            $status = if ($global:WhmScanStatus) { $global:WhmScanStatus } else { 'Clean' }
            $threats = @()
            if ($status -eq 'Threat') {
                $file = Get-ChildItem -Path $Path[0] -File | Where-Object { $_.Name -like "$($global:WhmThreatPackage)-*" } | Select-Object -First 1
                $threats = @([PSCustomObject]@{ Resource = "file:_$($file.FullName)"; ThreatName = 'Trojan:Test'; ThreatId = '1'; ActionSuccess = $false })
            }
            [PSCustomObject]@{ Status = $status; Message = "scan $status"; Threats = $threats; ScannedPaths = @($Path) }
        }

        # Both halves of intake, the way Invoke-WheelhouseSync runs them: check, then publish
        # into <WheelhousePath>\requirements-1.txt with every candidate as a new pin.
        function Invoke-TestIntake {
            param([hashtable]$Params)
            # Intake never touches the wheelhouse; only publishing needs its path.
            $intakeParams = @{} + $Params
            $intakeParams.Remove('WheelhousePath')
            $intake = Invoke-CandidateIntake @intakeParams
            $publishParams = @{
                Intake         = $intake
                WheelhousePath = $Params.WheelhousePath
                GroupFile      = (Join-Path $Params.WheelhousePath 'requirements-1.txt')
                Additions      = $Params.Packages
                DenylistPath   = (Join-Path $Params.WheelhousePath 'denylist.json')
            }
            $publish = Publish-CandidateIntake @publishParams
            return @{
                Accepted     = $publish.Accepted
                Rejected     = @($intake.Rejected) + @($publish.Rejected)
                Published    = $publish.Published
                AuditResults = $intake.AuditResults
                Intake       = $intake
            }
        }

        # A real (minimal) wheel: a zip with <name>-<version>.dist-info/METADATA.
        function New-TestWheel {
            param([string]$Folder, [string]$Name, [string]$Version, [string[]]$RequiresDist = @())
            Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
            $file = "$Name-$Version-py3-none-any.whl"
            $path = Join-Path $Folder $file
            $zip = [System.IO.Compression.ZipFile]::Open($path, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                $writer = [System.IO.StreamWriter]::new($zip.CreateEntry("$Name-$Version.dist-info/METADATA").Open())
                $writer.Write((@('Metadata-Version: 2.1', "Name: $Name", "Version: $Version") + @($RequiresDist | ForEach-Object { "Requires-Dist: $_" }) + @('', 'Requires-Dist: not-a-header')) -join "`n")
                $writer.Dispose()
            }
            finally { $zip.Dispose() }
            return [PSCustomObject]@{
                name = $Name; version = $Version; file = $file; sha256 = (Get-FileHash -Path $path -Algorithm SHA256).Hash
                python_tag = 'py3'; abi_tag = 'none'; platform_tag = 'any'; downloaded_utc = '2026-01-01T00:00:00Z'
            }
        }

        # Pester 5 can only mock commands that exist; provide a stub on machines
        # without Python so the pip-audit tests still run.
        $script:addedPythonStub = $false
        if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
            function global:python { }
            $script:addedPythonStub = $true
        }
    }

    AfterAll {
        if ($script:addedPythonStub) { Remove-Item -Path Function:\python -ErrorAction SilentlyContinue }
        Remove-Variable -Name WhmMockExitCode, WhmMockReport, WhmPipInstalls, WhmPipChecks, WhmIntakeAudit, WhmIntakeDownloaded, WhmIntakeCandidates, WhmScanDetections, WhmUiJobSteps,
            WhmReleases, WhmNoWheel, WhmWheelOverride, WhmScanStatus, WhmThreatPackage, WhmRestResponse, WhmPyPI, WhmScannedPath,
            WhmOsvCalls, WhmOsvRecords, WhmOsvOffline, WhmProposalPath, WhmStateDir, WhmEventLog, WhmTask, WhmTaskRegistered, WhmTaskError, WhmTaskCalls, WhmTaskStarted -Scope Global -ErrorAction SilentlyContinue
    }

    Context 'Get-NormalizedPackageName' {
        It 'collapses separators and lowercases (PEP 503)' {
            Get-NormalizedPackageName 'Foo__Bar.baz-Qux' | Should -Be 'foo-bar-baz-qux'
        }
    }

    Context 'Read-RequirementFile' {
        It 'parses pins and ignores comments, extras, markers and hashes' {
            $file = Join-Path (Get-TestFolder) 'req.txt'
            Set-Content -Path $file -Value @(
                '# header comment',
                'anyio==4.15.1',
                '    # via httpx',
                'Pillow[extra]==12.3.0 ; python_version >= "3.10"',
                'colorama==0.4.6 ; sys_platform == "win32"  # inline comment',
                'requests==2.32.3 \',
                '    --hash=sha256:abc \',
                '    --hash=sha256:def',
                ''
            )
            $packages = Read-RequirementFile -FilePath $file
            $packages.Count | Should -Be 4
            $packages['anyio'] | Should -Be '4.15.1'
            $packages['pillow'] | Should -Be '12.3.0'
            $packages['colorama'] | Should -Be '0.4.6'
            $packages['requests'] | Should -Be '2.32.3'
        }

        It 'skips unpinned lines' {
            $file = Join-Path (Get-TestFolder) 'req.txt'
            Set-Content -Path $file -Value @('numpy>=2.0', 'pandas==2.3.0')
            $packages = Read-RequirementFile -FilePath $file
            $packages.Count | Should -Be 1
            $packages.ContainsKey('numpy') | Should -Be $false
        }
    }

    Context 'Get-WheelhouseGroupFile' {
        It 'returns the legacy file first, then numbered groups in numeric order, and ignores other requirements files' {
            $wheelhouse = Get-TestFolder
            foreach ($name in 'requirements-10.txt', 'requirements-2.txt', 'requirements.txt', 'requirements-torch.txt', 'requirements-1.txt') {
                Set-Content -Path (Join-Path $wheelhouse $name) -Value 'a==1'
            }
            $groups = Get-WheelhouseGroupFile -WheelhousePath $wheelhouse | ForEach-Object { Split-Path -Path $_ -Leaf }
            ($groups -join ',') | Should -Be 'requirements.txt,requirements-1.txt,requirements-2.txt,requirements-10.txt'
        }

        It 'returns an empty array for an empty wheelhouse' {
            $groups = Get-WheelhouseGroupFile -WheelhousePath (Get-TestFolder)
            $groups.Count | Should -Be 0
        }
    }

    Context 'Get-RequirementMergePlan' {
        It 'skips duplicates, fills the first free group, and numbers new groups after the highest existing one' {
            $wheelhouse = Get-TestFolder
            $group1 = Join-Path $wheelhouse 'requirements-1.txt'
            $group3 = Join-Path $wheelhouse 'requirements-3.txt'
            Set-Content -Path $group1 -Value @('numpy==1.26.4', 'pandas==2.2.0')
            Set-Content -Path $group3 -Value @('numpy==2.0.0', 'scipy==1.14.0')

            $plan = Get-RequirementMergePlan -WheelhousePath $wheelhouse -GroupFiles @($group1, $group3) -LocalPackages @{
                'numpy'  = '2.5.3'   # different version everywhere -> new group
                'pandas' = '2.2.0'   # exact duplicate
                'scipy'  = '1.15.0'  # group 1 has no scipy
            }

            $plan.Duplicates.Count | Should -Be 1
            $plan.Duplicates[0] | Should -Match 'pandas==2.2.0'

            $numpy = $plan.Additions | Where-Object { $_.Name -eq 'numpy' }
            $numpy.IsNewGroup | Should -Be $true
            Split-Path -Path $numpy.GroupFile -Leaf | Should -Be 'requirements-4.txt'

            $scipy = $plan.Additions | Where-Object { $_.Name -eq 'scipy' }
            $scipy.IsNewGroup | Should -Be $false
            $scipy.GroupFile | Should -Be $group1
        }

        It 'puts two new versions of the same package into the same new group only once' {
            $wheelhouse = Get-TestFolder
            $group1 = Join-Path $wheelhouse 'requirements-1.txt'
            Set-Content -Path $group1 -Value 'numpy==1.26.4'

            $plan = Get-RequirementMergePlan -WheelhousePath $wheelhouse -GroupFiles @($group1) -LocalPackages @{ 'numpy' = '2.0.0'; 'attrs' = '25.1.0' }
            @($plan.Additions | Where-Object { $_.IsNewGroup }).Count | Should -Be 1
            ($plan.Additions | Where-Object { $_.Name -eq 'attrs' }).GroupFile | Should -Be $group1
        }

        It 'creates requirements-1.txt for an empty wheelhouse' {
            $wheelhouse = Get-TestFolder
            $plan = Get-RequirementMergePlan -WheelhousePath $wheelhouse -GroupFiles @() -LocalPackages @{ 'a' = '1'; 'b' = '2' }
            $plan.Additions.Count | Should -Be 2
            @($plan.Additions | ForEach-Object { Split-Path -Path $_.GroupFile -Leaf } | Select-Object -Unique) | Should -Be @('requirements-1.txt')
        }
    }

    Context 'Add-RequirementToGroupFile' {
        It 'appends instead of overwriting an existing file' {
            $file = Join-Path (Get-TestFolder) 'requirements-1.txt'
            Add-RequirementToGroupFile -GroupFile $file -Name 'a' -Version '1'
            Add-RequirementToGroupFile -GroupFile $file -Name 'b' -Version '2'
            (Get-Content -Path $file) | Should -Be @('a==1', 'b==2')
        }
    }

    Context 'Get-WheelFileInfo' {
        It 'parses a PEP 427 wheel filename' {
            $info = Get-WheelFileInfo -FileName 'Pillow-12.3.0-cp314-cp314-win_amd64.whl'
            $info.Name | Should -Be 'pillow'
            $info.Version | Should -Be '12.3.0'
            $info.PythonTag | Should -Be 'cp314'
            $info.AbiTag | Should -Be 'cp314'
            $info.PlatformTag | Should -Be 'win_amd64'
        }

        It 'returns $null for a non-wheel name' {
            Get-WheelFileInfo -FileName 'readme.whl' | Should -BeNullOrEmpty
        }
    }

    Context 'Manifest read / write / integrity' {
        It 'reads a missing manifest as empty' {
            $manifest = Read-WheelhouseManifest -WheelhousePath (Get-TestFolder)
            $manifest.Count | Should -Be 0
        }

        It 'throws on a corrupt manifest' {
            $wheelhouse = Get-TestFolder
            Set-Content -Path (Join-Path $wheelhouse 'manifest.json') -Value '{ not json'
            { Read-WheelhouseManifest -WheelhousePath $wheelhouse } | Should -Throw
        }

        It 'reads a legacy single-object manifest as one entry and writes it back as a JSON array' {
            $wheelhouse = Get-TestFolder
            Set-Content -Path (Join-Path $wheelhouse 'manifest.json') -Value '{"name":"a","version":"1","file":"a-1-py3-none-any.whl","sha256":"X"}'
            $manifest = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            $manifest.Count | Should -Be 1

            Save-WheelhouseManifest -Manifest $manifest -WheelhousePath $wheelhouse
            (Get-Content -Path (Join-Path $wheelhouse 'manifest.json') -Raw).Trim() | Should -Match '^\['
            Test-Path -Path (Join-Path $wheelhouse 'manifest.json.tmp') | Should -Be $false
        }

        It 'reports missing files and hash mismatches' {
            $wheelhouse = Get-TestFolder
            $wheel = Join-Path $wheelhouse 'a-1-py3-none-any.whl'
            Set-Content -Path $wheel -Value 'content'
            $hash = (Get-FileHash -Path $wheel -Algorithm SHA256).Hash
            $manifest = @(
                [PSCustomObject]@{ name = 'a'; version = '1'; file = 'a-1-py3-none-any.whl'; sha256 = $hash },
                [PSCustomObject]@{ name = 'b'; version = '1'; file = 'b-1-py3-none-any.whl'; sha256 = 'X' }
            )
            $problems = Test-ManifestIntegrity -Manifest $manifest -WheelhousePath $wheelhouse
            $problems.Count | Should -Be 1
            $problems[0] | Should -Match 'missing'

            Set-Content -Path $wheel -Value 'tampered'
            $problems = Test-ManifestIntegrity -Manifest $manifest[0] -WheelhousePath $wheelhouse
            $problems[0] | Should -Match 'MISMATCH'
        }

        It 'Assert-WheelhouseIntegrity writes a report and throws on a mismatch' {
            $wheelhouse = Get-TestFolder
            $reports = Get-TestFolder
            $manifest = @([PSCustomObject]@{ name = 'b'; version = '1'; file = 'b-1-py3-none-any.whl'; sha256 = 'X' })
            { Assert-WheelhouseIntegrity -Manifest $manifest -WheelhousePath $wheelhouse -ReportsFolder $reports } | Should -Throw
            @(Get-ChildItem -Path $reports -Filter 'Report_Integrity_*.json').Count | Should -Be 1
        }
    }

    Context 'Batched audits' {
        It 'packs published versions into the fewest sets with one version per package' {
            $manifest = @(
                [PSCustomObject]@{ name = 'Six'; version = '1.16.0'; file = 'six-1.16.0-a.whl' },
                [PSCustomObject]@{ name = 'six'; version = '1.16.0'; file = 'six-1.16.0-b.whl' },
                [PSCustomObject]@{ name = 'attrs'; version = '23.1.0'; file = 'a1.whl' },
                [PSCustomObject]@{ name = 'attrs'; version = '24.0'; file = 'a2.whl' },
                [PSCustomObject]@{ name = 'numpy'; version = '2.3.1'; file = 'n.whl' })
            $chunks = Get-AuditChunk -Manifest $manifest
            $chunks.Count | Should -Be 2
            (($chunks[0].Keys | ForEach-Object { "$_==$($chunks[0][$_])" }) -join ',') | Should -Be 'attrs==23.1.0,numpy==2.3.1,six==1.16.0'
            (($chunks[1].Keys | ForEach-Object { "$_==$($chunks[1][$_])" }) -join ',') | Should -Be 'attrs==24.0'
            (Get-AuditChunk -Manifest @()).Count | Should -Be 0
        }

        It 'audits each set once per service and leaves the set files for the catalog' {
            $reports = Get-TestFolder
            $global:WhmAuditedFiles = [System.Collections.Generic.List[string]]::new()
            Mock -ModuleName WheelhouseManager -CommandName Invoke-GroupAudit -MockWith {
                $global:WhmAuditedFiles.Add((Get-Content -Path $GroupFile) -join ',')
                , @(foreach ($service in $Services) { [PSCustomObject]@{ PSTypeName = 'Wheelhouse.AuditResult'; Stage = $Stage; GroupFile = $GroupFile; Service = $service; Status = 'Passed'; ReportPath = 'x' } })
            }
            $manifest = @([PSCustomObject]@{ name = 'six'; version = '1.16.0' }, [PSCustomObject]@{ name = 'attrs'; version = '23.1.0' }, [PSCustomObject]@{ name = 'attrs'; version = '24.0' })
            $results = Invoke-PublishedAudit -Manifest $manifest -Services @('osv', 'pypi') -Stage 'Scheduled' -ReportsFolder $reports
            $results.Count | Should -Be 4
            $global:WhmAuditedFiles -join ' | ' | Should -Be 'attrs==23.1.0,six==1.16.0 | attrs==24.0'
            Test-Path -Path (Join-Path $reports 'audit-sets\Scheduled\published-2.txt') | Should -Be $true
            Remove-Variable -Name WhmAuditedFiles -Scope Global
        }
    }

    Context 'Quick integrity check' {
        It 'hashes only files changed since their last verification; the full check hashes all' {
            $wheelhouse = Get-TestWheelhouse
            $manifest = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            $cache = Join-Path (Get-TestFolder) 'integrity.json'
            $stats = @{}
            @(Get-WheelhouseIntegrityProblem -Manifest $manifest -WheelhousePath $wheelhouse -CachePath $cache -Quick -Statistics $stats).Count | Should -Be 0
            $stats['Hashed'] | Should -Be 2
            @(Get-WheelhouseIntegrityProblem -Manifest $manifest -WheelhousePath $wheelhouse -CachePath $cache -Quick -Statistics $stats).Count | Should -Be 0
            "$($stats['Hashed'])/$($stats['Skipped'])" | Should -Be '0/2'

            # A different size is noticed by the quick check.
            $six = Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl'
            Add-Content -Path $six -Value 'tampered'
            $problems = @(Get-WheelhouseIntegrityProblem -Manifest $manifest -WheelhousePath $wheelhouse -CachePath $cache -Quick -Statistics $stats)
            $problems[0].Kind | Should -Be 'Modified'

            # Same size and a restored timestamp slip past the quick check - the full check
            # (the weekly one) catches them.
            $attrs = Get-Item -Path (Join-Path $wheelhouse 'attrs-23.1.0-py3-none-any.whl')
            $stamp = $attrs.LastWriteTimeUtc
            $bytes = [System.IO.File]::ReadAllBytes($attrs.FullName); $bytes[0] = $bytes[0] -bxor 1
            [System.IO.File]::WriteAllBytes($attrs.FullName, $bytes)
            (Get-Item -Path $attrs.FullName).LastWriteTimeUtc = $stamp
            @(Get-WheelhouseIntegrityProblem -Manifest $manifest -WheelhousePath $wheelhouse -CachePath $cache -Quick | Where-Object { $_.Entry.name -eq 'attrs' }).Count | Should -Be 0
            @(Get-WheelhouseIntegrityProblem -Manifest $manifest -WheelhousePath $wheelhouse -CachePath $cache | Where-Object { $_.Entry.name -eq 'attrs' })[0].Kind | Should -Be 'Modified'
        }
    }

    Context 'Merge-WheelhouseManifest' {
        It 'keeps existing entries, adds files downloaded this run, and never adds untracked pre-existing files' {
            $wheelhouse = Get-TestFolder
            foreach ($name in 'old-1-py3-none-any.whl', 'stray-1-py3-none-any.whl') {
                Set-Content -Path (Join-Path $wheelhouse $name) -Value $name
            }
            $existing = [PSCustomObject]@{ name = 'old'; version = '1'; file = 'old-1-py3-none-any.whl'; sha256 = 'H'; downloaded_utc = '2020-01-01T00:00:00Z' }
            $preRun = @('old-1-py3-none-any.whl', 'stray-1-py3-none-any.whl')
            Set-Content -Path (Join-Path $wheelhouse 'new-2-cp314-cp314-win_amd64.whl') -Value 'new'

            $manifest = Merge-WheelhouseManifest -WheelhousePath $wheelhouse -Manifest @($existing) -PreRunFiles $preRun

            ($manifest.file | Sort-Object) -join ',' | Should -Be 'new-2-cp314-cp314-win_amd64.whl,old-1-py3-none-any.whl'
            ($manifest | Where-Object { $_.name -eq 'old' }).downloaded_utc | Should -Be '2020-01-01T00:00:00Z'
            ($manifest | Where-Object { $_.name -eq 'new' }).platform_tag | Should -Be 'win_amd64'
        }

        It 'adds every wheel on first-time setup (empty manifest)' {
            $wheelhouse = Get-TestFolder
            Set-Content -Path (Join-Path $wheelhouse 'a-1-py3-none-any.whl') -Value 'a'
            $manifest = Merge-WheelhouseManifest -WheelhousePath $wheelhouse -Manifest @() -PreRunFiles @('a-1-py3-none-any.whl')
            $manifest.Count | Should -Be 1
        }
    }

    Context 'Compare-RequirementsAgainstManifest' {
        It 'flags missing packages and tag mismatches only' {
            $manifest = @(
                [PSCustomObject]@{ name = 'ok'; version = '1'; python_tag = 'cp314'; abi_tag = 'cp314'; platform_tag = 'win_amd64' },
                [PSCustomObject]@{ name = 'pure'; version = '1'; python_tag = 'py3'; abi_tag = 'none'; platform_tag = 'any' },
                [PSCustomObject]@{ name = 'linux'; version = '1'; python_tag = 'cp314'; abi_tag = 'cp314'; platform_tag = 'manylinux_2_28_x86_64' }
            )
            $result = Compare-RequirementsAgainstManifest -Manifest $manifest -ExpectedPythonTag 'cp314' -ExpectedPlatformTag 'win_amd64' -Required @{
                'ok' = '1'; 'pure' = '1'; 'linux' = '1'; 'missing' = '1'; 'ok-other' = '2'
            }
            ($result.Packages.Keys | Sort-Object) -join ',' | Should -Be 'linux,missing,ok-other'
        }
    }

    Context 'Settings' {
        It 'resolves explicit > settings.psd1 > default, honouring key mapping and ignoring empty settings' {
            $settings = @{ PythonVersion = '3.13'; MailTo = 'team@example.com'; SmtpServer = '' }
            $bound = @{ Platform = 'win_arm64' }
            $cfg = Resolve-WheelhouseParameter -BoundParameters $bound -Settings $settings `
                -Name PythonVersion, Platform, To, SmtpServer, MinimumPackageAgeDays, LocalRequirementsPath `
                -SettingName @{ To = 'MailTo' } -Default @{ LocalRequirementsPath = $null }

            $cfg.Platform | Should -Be 'win_arm64'
            $cfg.PythonVersion | Should -Be '3.13'
            $cfg.To | Should -Be 'team@example.com'
            $cfg.SmtpServer | Should -Be ''
            $cfg.MinimumPackageAgeDays | Should -Be 10
            $cfg.LocalRequirementsPath | Should -BeNullOrEmpty
        }

        It 'lets an explicitly passed empty string win over settings.psd1' {
            $cfg = Resolve-WheelhouseParameter -BoundParameters @{ LocalRequirementsPath = '' } -Settings @{ LocalRequirementsPath = 'C:\x.txt' } -Name LocalRequirementsPath
            $cfg.LocalRequirementsPath | Should -Be ''
        }

        It 'round-trips values with quotes, numbers, booleans and arrays through settings.psd1' {
            $path = Join-Path (Get-TestFolder) 'settings.psd1'
            $values = @{
                WheelhousePath        = "\\srv\O'Brien\wheelhouse"
                MinimumPackageAgeDays = 7
                Enabled               = $true
                VulnerabilityServices = @('osv', 'pypi')
            }
            Save-WheelhouseSetting -SettingsPath $path -Settings $values
            $read = Get-WheelhouseSetting -SettingsPath $path

            $read.WheelhousePath | Should -Be "\\srv\O'Brien\wheelhouse"
            $read.MinimumPackageAgeDays | Should -Be 7
            $read.Enabled | Should -Be $true
            $read.VulnerabilityServices | Should -Be @('osv', 'pypi')
        }

        It 'Set-WheelhouseSetting only changes the given keys' {
            $path = Join-Path (Get-TestFolder) 'settings.psd1'
            Save-WheelhouseSetting -SettingsPath $path -Settings @{ A = 'a'; B = 'b' }
            Set-WheelhouseSetting -SettingsPath $path -Updates @{ B = 'changed' }
            $read = Get-WheelhouseSetting -SettingsPath $path
            $read.A | Should -Be 'a'
            $read.B | Should -Be 'changed'
        }
    }

    Context 'Audit report naming' {
        It 'round-trips Get-AuditReportPath through Get-AuditReportInfo' {
            $path = Get-AuditReportPath -ReportsFolder $TestDrive -Stage 'Scheduled' -Group 'requirements-2' -Service 'pypi'
            $info = Get-AuditReportInfo -Path $path
            $info.Stage | Should -Be 'Scheduled'
            $info.Group | Should -Be 'requirements-2'
            $info.Service | Should -Be 'PyPI'
        }

        It 'parses report names without a group and ignores other files' {
            (Get-AuditReportInfo -Path 'Report_Scheduled-OSV_20260921_153000.json').Service | Should -Be 'OSV'
            (Get-AuditReportInfo -Path 'Report_Scheduled-OSV_20260921_153000.json').Group | Should -BeNullOrEmpty
            Get-AuditReportInfo -Path 'Report_Integrity_20260921_153000.json' | Should -BeNullOrEmpty
            Get-AuditReportInfo -Path 'Report_PackageAge-requirements-1_20260921_153000.json' | Should -BeNullOrEmpty
        }
    }

    Context 'Get-VulnerabilityFinding' {
        It 'merges the same vulnerability from several reports and reports unreadable files as errors' {
            $reports = Get-TestFolder
            $example = Write-TestAuditReport -Path (Join-Path $reports 'example.json')
            $osv = Join-Path $reports 'Report_Scheduled-requirements-1-OSV_20260921_153000.json'
            $pypi = Join-Path $reports 'Report_Scheduled-requirements-2-PYPI_20260921_153000.json'
            Copy-Item -Path $example -Destination $osv
            Copy-Item -Path $example -Destination $pypi

            $result = Get-VulnerabilityFinding -ReportPaths @($osv, $pypi, (Join-Path $reports 'missing.json'))

            $single = Get-VulnerabilityFinding -ReportPaths @($example)
            $result.Findings.Count | Should -Be $single.Findings.Count
            $result.Findings[0].Services -join ',' | Should -Be 'OSV,PyPI'
            $result.Findings[0].GroupFiles -join ',' | Should -Be 'requirements-1.txt,requirements-2.txt'
            $result.Errors.Count | Should -Be 1
        }

        It 'produces HTML naming the group file and the audit errors' {
            $reports = Get-TestFolder
            $osv = Join-Path $reports 'Report_Scheduled-requirements-3-OSV_20260921_153000.json'
            Write-TestAuditReport -Path $osv | Out-Null
            $result = Get-VulnerabilityFinding -ReportPaths @($osv)
            $html = ConvertTo-VulnerabilityAlertHtml -Findings $result.Findings -AuditErrors @('requirements-1 / OSV: <boom>') -WheelhousePath ''
            $html | Should -Match 'requirements-3\.txt'
            $html | Should -Match '&lt;boom&gt;'
        }
    }

    Context 'Invoke-PipAudit status' {
        It 'returns <Expected> when pip-audit exits <Code> and writes <Report>' -TestCases @(
            @{ Code = 0; Report = 'clean'; Expected = 'Passed' },
            @{ Code = 1; Report = 'vulnerable'; Expected = 'Vulnerable' },
            @{ Code = 1; Report = 'clean'; Expected = 'Error' },
            @{ Code = 1; Report = 'none'; Expected = 'Error' }
        ) {
            param($Code, $Report, $Expected)

            $reports = Get-TestFolder
            $global:WhmMockExitCode = $Code
            $global:WhmMockReport = $Report
            Mock -ModuleName WheelhouseManager -CommandName python -MockWith {
                $outputIndex = [array]::IndexOf($args, '--output')
                $reportPath = $args[$outputIndex + 1]
                switch ($global:WhmMockReport) {
                    'clean' { Set-Content -Path $reportPath -Value '{"dependencies":[{"name":"a","version":"1","vulns":[]}],"fixes":[]}' }
                    'vulnerable' { Set-Content -Path $reportPath -Value '{"dependencies":[{"name":"a","version":"1","vulns":[{"id":"X"}]}],"fixes":[]}' }
                }
                $global:LASTEXITCODE = $global:WhmMockExitCode
            }

            $result = Invoke-PipAudit -RequirementsFilePath (Join-Path $reports 'requirements-1.txt') -ReportsFolder $reports -Stage 'Scheduled' -Service 'osv'
            $result.Status | Should -Be $Expected
            $result.Group | Should -Be 'requirements-1'
        }
    }

    Context 'Tool status' {
        It 'reports python, pip-audit and uv with what is affected when one is missing' {
            Mock -ModuleName WheelhouseManager -CommandName Invoke-WheelhouseToolProbe -MockWith { if ($Name -eq 'python') { '3.14.7' } else { $null } }
            $tools = @(Get-WheelhouseToolStatus)
            ($tools | ForEach-Object { "$($_.name)=$($_.level)" }) -join ',' | Should -Be 'python=ok,pip-audit=warn,uv=bad'
            $tools[0].version | Should -Be '3.14.7'
            $tools[1].message | Should -Match 'installs it'
            $tools[2].message | Should -Match 'Adding packages'

            Mock -ModuleName WheelhouseManager -CommandName Invoke-WheelhouseToolProbe -MockWith { $null }
            $none = @(Get-WheelhouseToolStatus)
            $none[0].level | Should -Be 'bad'
            $none[1].level | Should -Be 'bad'
        }

        It 'answers $null for a tool that is not on PATH' {
            $saved = $env:PATH
            try {
                $env:PATH = (Get-TestFolder)
                Invoke-WheelhouseToolProbe -Name 'uv' | Should -BeNullOrEmpty
            }
            finally {
                $env:PATH = $saved
            }
        }
    }

    Context 'Weekly check as a Scheduled Task' {
        BeforeEach {
            $global:WhmTask = $null
            $global:WhmTaskRegistered = $null
            $global:WhmTaskError = $null
            $global:WhmTaskCalls = [System.Collections.Generic.List[string]]::new()
            Mock -ModuleName WheelhouseManager -CommandName Get-ScheduledTask -MockWith { $global:WhmTask }
            Mock -ModuleName WheelhouseManager -CommandName Get-ScheduledTaskInfo -MockWith {
                [PSCustomObject]@{ LastRunTime = [datetime]'2026-10-25 02:00'; LastTaskResult = 1; NextRunTime = [datetime]'2026-11-01 02:00' }
            }
            Mock -ModuleName WheelhouseManager -CommandName Register-ScheduledTask -MockWith {
                if ($global:WhmTaskError) { throw $global:WhmTaskError }
                $global:WhmTaskRegistered = @{ TaskName = $TaskName; User = $User; Password = $Password; Execute = $Action.Execute; Arguments = $Action.Arguments; RunLevel = [string]$RunLevel }
            }
            Mock -ModuleName WheelhouseManager -CommandName Start-ScheduledTask -MockWith { $global:WhmTaskCalls.Add("start $TaskName") }
            Mock -ModuleName WheelhouseManager -CommandName Unregister-ScheduledTask -MockWith { $global:WhmTaskCalls.Add("remove $TaskName") }
            $script:repoRoot = Split-Path -Path $PSScriptRoot -Parent
            $script:taskPassword = [System.Security.SecureString]::new()
            foreach ($char in 'secret'.ToCharArray()) { $script:taskPassword.AppendChar($char) }
        }

        It 'registers Test-Wheelhouse.ps1 of this installation with the given account' {
            $params = @{ DayOfWeek = @('Sunday', 'Wednesday'); At = '02:30'; User = 'CONTOSO\svc-wheelhouse'; Password = $script:taskPassword; ManagerRoot = $script:repoRoot; PowerShellPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' }
            Mock -ModuleName WheelhouseManager -CommandName Get-ScheduledTask -MockWith { if ($global:WhmTaskRegistered) { $global:WhmTask } }
            [void](Register-WheelhouseScheduledCheck @params)
            $global:WhmTaskRegistered.TaskName | Should -Be 'Wheelhouse Weekly Check'
            $global:WhmTaskRegistered.User | Should -Be 'CONTOSO\svc-wheelhouse'
            $global:WhmTaskRegistered.Password | Should -Be 'secret'
            $global:WhmTaskRegistered.RunLevel | Should -Be 'Limited'
            $global:WhmTaskRegistered.Execute | Should -Match 'powershell\.exe$'
            $global:WhmTaskRegistered.Arguments | Should -Match ([regex]::Escape((Join-Path $script:repoRoot 'Jobs\Test-Wheelhouse.ps1')))
        }

        It 'refuses invalid input and explains refused logons' {
            $base = @{ DayOfWeek = @('Sunday'); At = '02:00'; User = 'CONTOSO\svc'; Password = $script:taskPassword; ManagerRoot = $script:repoRoot }
            $bad = $base.Clone(); $bad.DayOfWeek = @('Funday')
            { Register-WheelhouseScheduledCheck @bad } | Should -Throw '*day of the week*'
            $bad = $base.Clone(); $bad.At = '25:00'
            { Register-WheelhouseScheduledCheck @bad } | Should -Throw '*HH:mm*'
            $bad = $base.Clone(); $bad.User = 'bad"user'
            { Register-WheelhouseScheduledCheck @bad } | Should -Throw '*DOMAIN\user*'
            $bad = $base.Clone(); $bad.Password = [System.Security.SecureString]::new()
            { Register-WheelhouseScheduledCheck @bad } | Should -Throw '*password*'
            $global:WhmTaskRegistered | Should -BeNullOrEmpty

            $global:WhmTaskError = 'The user name or password is incorrect. (0x8007052E)'
            $refused = $null
            try { Register-WheelhouseScheduledCheck @base } catch { $refused = $_.Exception }
            $refused | Should -BeOfType [System.ArgumentException]
            $global:WhmTaskError = 'Access is denied. (0x80070005)'
            try { Register-WheelhouseScheduledCheck @base } catch { $refused = $_.Exception }
            $refused | Should -BeOfType [System.InvalidOperationException]
            $refused.Message | Should -Match 'administrator'
        }

        It 'reads the task back: days, time, account, last result' {
            Get-WheelhouseScheduledCheck -ManagerRoot $script:repoRoot | ForEach-Object { $_.Registered } | Should -Be $false
            $script = Join-Path $script:repoRoot 'Jobs\Test-Wheelhouse.ps1'
            $global:WhmTask = [PSCustomObject]@{
                TaskName  = 'Wheelhouse Weekly Check'; TaskPath = '\'; State = 'Ready'
                Principal = [PSCustomObject]@{ UserId = 'CONTOSO\svc' }
                Triggers  = @([PSCustomObject]@{ DaysOfWeek = 9; StartBoundary = '2026-11-01T02:30:00' })
                Actions   = @([PSCustomObject]@{ Execute = 'powershell.exe'; Arguments = "-NoProfile -File `"$script`"" })
            }
            $task = Get-WheelhouseScheduledCheck -ManagerRoot $script:repoRoot
            $task.Registered | Should -Be $true
            $task.Days -join ',' | Should -Be 'Sunday,Wednesday'
            $task.Time | Should -Be '02:30'
            $task.User | Should -Be 'CONTOSO\svc'
            $task.LastResultText | Should -Match 'alert was sent'
            $task.ForThisInstallation | Should -Be $true
            (Get-WheelhouseScheduledCheck -ManagerRoot (Get-TestFolder)).ForThisInstallation | Should -Be $false

            Start-WheelhouseScheduledCheck
            Unregister-WheelhouseScheduledCheck | Should -Be $true
            $global:WhmTaskCalls -join ';' | Should -Be 'start Wheelhouse Weekly Check;remove Wheelhouse Weekly Check'
            $global:WhmTask = $null
            Unregister-WheelhouseScheduledCheck | Should -Be $false
            { Start-WheelhouseScheduledCheck } | Should -Throw '*not registered*'
        }

        It 'finds the UNC path behind a mapped network drive' {
            Mock -ModuleName WheelhouseManager -CommandName Get-PSDrive -MockWith { [PSCustomObject]@{ Name = 'Z'; DisplayRoot = '\\srv\share' } }
            $drive = Get-WheelhouseNetworkDrive -Path 'Z:\wheelhouse'
            $drive.Drive | Should -Be 'Z:'
            $drive.Unc | Should -Be '\\srv\share\wheelhouse'
            (Get-WheelhouseNetworkDrive -Path 'Z:\').Unc | Should -Be '\\srv\share'
            Get-WheelhouseNetworkDrive -Path '\\srv\share\wheelhouse' | Should -BeNullOrEmpty
            Mock -ModuleName WheelhouseManager -CommandName Get-PSDrive -MockWith { [PSCustomObject]@{ Name = 'C'; DisplayRoot = $null } }
            Mock -ModuleName WheelhouseManager -CommandName Get-CimInstance -MockWith { [PSCustomObject]@{ DriveType = 3; ProviderName = $null } }
            Get-WheelhouseNetworkDrive -Path 'C:\wheelhouse' | Should -BeNullOrEmpty
        }
    }

    Context 'Confirm-PythonAndTooling' {
        It 'upgrades only the tools that pip reports as outdated' {
            # Regression: Windows PowerShell 5.1's ConvertFrom-Json emits a JSON array as one
            # object; unflattened, every outdated package would look like "pip".
            $global:WhmPipInstalls = [System.Collections.Generic.List[string]]::new()
            Mock -ModuleName WheelhouseManager -CommandName python -MockWith {
                $global:LASTEXITCODE = 0
                if ($args -contains '--version') { return 'Python 3.14.0' }
                if ($args -contains 'list') { return '[{"name": "requests", "version": "1.0", "latest_version": "2.0"}, {"name": "pip-audit", "version": "2.7", "latest_version": "2.8"}]' }
                if ($args -contains 'install') { $global:WhmPipInstalls.Add($args[-1]) }
            }

            Confirm-PythonAndTooling

            ($global:WhmPipInstalls -join ',') | Should -Be 'pip-audit'
        }
    }

    Context 'Invoke-NativeCommand' {
        It 'records stdout and stderr of a native program in the transcript and keeps its exit code' {
            # Regression: Windows PowerShell 5.1's transcript missed stderr (pip's "ERROR:" lines).
            $shell = (Get-Process -Id $PID).Path
            $log = Join-Path (Get-TestFolder) 'transcript.txt'

            Start-Transcript -Path $log | Out-Null
            try {
                Invoke-NativeCommand -FilePath $shell -ArgumentList '-NoProfile', '-Command', "[Console]::Out.WriteLine('stdout-line'); [Console]::Error.WriteLine('ERROR: stderr-line'); exit 3"
                $exitCode = $LASTEXITCODE
            }
            finally {
                Stop-Transcript | Out-Null
            }

            $exitCode | Should -Be 3
            $content = Get-Content -Path $log -Raw
            $content | Should -Match 'stdout-line'
            $content | Should -Match 'ERROR: stderr-line'
        }
    }

    Context 'Invoke-NativeCommand with Python' {
        It 'records a Python program''s stderr (like pip "ERROR:" lines) in the transcript and returns lines with -PassThru' {
            $python = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $python) {
                Set-ItResult -Skipped -Because 'python is not installed'
                return
            }
            $log = Join-Path (Get-TestFolder) 'transcript.txt'

            Start-Transcript -Path $log | Out-Null
            try {
                $lines = Invoke-NativeCommand -FilePath $python.Source -PassThru -ArgumentList '-c', "import sys; print('Collecting x==1'); sys.stderr.write('ERROR: No matching distribution found for x==1\n'); sys.exit(1)"
                $exitCode = $LASTEXITCODE
            }
            finally {
                Stop-Transcript | Out-Null
            }

            $exitCode | Should -Be 1
            ($lines -join "`n") | Should -Match 'No matching distribution found for x==1'
            (Get-Content -Path $log -Raw) | Should -Match 'ERROR: No matching distribution found for x==1'
        }
    }

    Context 'ConvertTo-UvPythonPlatform' {
        It 'maps pip platform tags to uv target triples' {
            ConvertTo-UvPythonPlatform -Platform 'win_amd64' | Should -Be 'x86_64-pc-windows-msvc'
            ConvertTo-UvPythonPlatform -Platform 'win_arm64' | Should -Be 'aarch64-pc-windows-msvc'
            { ConvertTo-UvPythonPlatform -Platform 'manylinux_2_28_x86_64' } | Should -Throw
        }
    }

    Context 'Test-RequirementWheelAvailability' {
        It 'reports every pin pip cannot download, re-checking after dropping each one' {
            $file = Join-Path (Get-TestFolder) 'requirements.txt'
            Set-Content -Path $file -Value @('good==1.0', 'pyqtdarktheme2==2.1.2', 'numpy==1.26.4')
            $global:WhmPipChecks = [System.Collections.Generic.List[string]]::new()

            Mock -ModuleName WheelhouseManager -CommandName Invoke-NativeCommand -MockWith {
                $reqFile = $ArgumentList[[array]::IndexOf($ArgumentList, '-r') + 1]
                $pins = @(Get-Content -Path $reqFile)
                $global:WhmPipChecks.Add($pins -join ',')
                # Like pip: stop at the first pin (in file order) that has no usable wheel.
                $bad = $pins | Where-Object { $_ -in 'numpy==1.26.4', 'pyqtdarktheme2==2.1.2' } | Select-Object -First 1
                if ($bad) {
                    $global:LASTEXITCODE = 1
                    return @('ERROR: Could not find a version that satisfies the requirement ' + $bad, 'ERROR: No matching distribution found for ' + $bad)
                }
                $global:LASTEXITCODE = 0
                return @('Would install ' + ($pins -join ' '))
            }

            $result = Test-RequirementWheelAvailability -RequirementsFilePath $file -PythonVersion '3.14' -Platform 'win_amd64'

            $result.Passed | Should -Be $false
            ($result.Unavailable | Sort-Object) -join ',' | Should -Be 'numpy==1.26.4,pyqtdarktheme2==2.1.2'
            $result.Error | Should -BeNullOrEmpty
            $global:WhmPipChecks.Count | Should -Be 3
            $global:WhmPipChecks[2] | Should -Be 'good==1.0'
        }

        It 'passes a clean file and reports a pip failure it cannot attribute as an error' {
            $file = Join-Path (Get-TestFolder) 'requirements.txt'
            Set-Content -Path $file -Value 'good==1.0'

            Mock -ModuleName WheelhouseManager -CommandName Invoke-NativeCommand -MockWith { $global:LASTEXITCODE = 0; return @('Would install good-1.0') }
            (Test-RequirementWheelAvailability -RequirementsFilePath $file -PythonVersion '3.14' -Platform 'win_amd64').Passed | Should -Be $true

            Mock -ModuleName WheelhouseManager -CommandName Invoke-NativeCommand -MockWith { $global:LASTEXITCODE = 1; return @('ERROR: Could not fetch URL https://pypi.org/simple/good/: connection error') }
            $result = Test-RequirementWheelAvailability -RequirementsFilePath $file -PythonVersion '3.14' -Platform 'win_amd64'
            $result.Passed | Should -Be $false
            $result.Error | Should -Match 'network or proxy'
        }
    }

    Context 'Invoke-CandidateIntake' {
        BeforeAll {
            function Get-IntakeParam {
                param([hashtable]$Packages, [string]$Folder)
                return @{
                    Packages       = $Packages
                    GroupName      = 'requirements-1'
                    WheelhousePath = $Folder
                    ReportsFolder  = $Folder
                    Services       = @('osv')
                    MinimumAgeDays = 10
                    PythonVersion  = '3.14'
                    Platform       = 'win_amd64'
                    StagingRoot    = (Join-Path $Folder 'staging')
                }
            }
            function Get-RejectReason {
                param($Result)
                $reasons = @{}
                foreach ($item in $Result.Rejected) { $reasons[$item.Name] = "[$($item.Category)] $($item.Reason)" }
                return $reasons
            }
        }

        BeforeEach {
            $global:WhmReleases = @{}
            $global:WhmNoWheel = @()
            $global:WhmWheelOverride = @{}
            $global:WhmScanStatus = 'Clean'
            $global:WhmThreatPackage = $null
            $global:WhmIntakeDownloaded = $null
            $global:WhmIntakeAudit = $null
            Mock -ModuleName WheelhouseManager -CommandName Invoke-GroupAudit -MockWith {
                if ($global:WhmIntakeAudit) { return , $global:WhmIntakeAudit }
                , @([PSCustomObject]@{ Stage = 'PreDownload'; Group = 'g'; Service = 'osv'; Status = 'Passed'; ReportPath = 'none'; Message = 'm' })
            }
            Mock -ModuleName WheelhouseManager -CommandName Test-PackageAge -MockWith $script:intakeAgeMock
            Mock -ModuleName WheelhouseManager -CommandName Invoke-PipPinRetry -MockWith $script:intakeDownloadMock
            Mock -ModuleName WheelhouseManager -CommandName Invoke-WheelhouseDefenderScan -MockWith $script:intakeScanMock
        }

        It 'rejects each failing package with its reason and publishes only what passed everything' {
            $folder = Get-TestFolder
            $vulnReport = Join-Path $folder 'Report_PreDownload-requirements-1-candidates-OSV_20260101_000000.json'
            Set-Content -Path $vulnReport -Value '{"dependencies":[{"name":"VulnPkg","version":"1.0","vulns":[{"id":"PYSEC-1"}]},{"name":"good","version":"1.0","vulns":[]}]}'
            $global:WhmIntakeAudit = @([PSCustomObject]@{ Stage = 'PreDownload'; Group = 'requirements-1-candidates'; Service = 'osv'; Status = 'Vulnerable'; ReportPath = $vulnReport; Message = 'm' })
            foreach ($name in 'good', 'vulnpkg', 'nowheel') { $global:WhmReleases[$name] = New-TestRelease -Name $name }
            $global:WhmReleases['fresh'] = New-TestRelease -Name 'fresh' -UploadDaysAgo 2
            $global:WhmNoWheel = @('nowheel')

            $params = Get-IntakeParam -Folder $folder -Packages @{ good = '1.0'; vulnpkg = '1.0'; fresh = '1.0'; nowheel = '1.0' }
            $result = Invoke-TestIntake -Params $params

            ($result.Accepted.Keys -join ',') | Should -Be 'good'
            $reasons = Get-RejectReason -Result $result
            ($reasons.Keys | Sort-Object) -join ',' | Should -Be 'fresh,nowheel,vulnpkg'
            $reasons['vulnpkg'] | Should -Match '^\[vulnerability\].*PYSEC-1'
            $reasons['fresh'] | Should -Match '^\[cooldown\] .*published 2 day.*eligible \d{4}-\d{2}-\d{2}'
            $reasons['nowheel'] | Should -Match '^\[no-wheel\] no downloadable wheel'
            # Rejected packages are never passed on to the next step.
            ($global:WhmIntakeDownloaded -join ',') | Should -Be 'good,nowheel'

            # The accepted wheel is in the wheelhouse, with the hash PyPI publishes, and
            # nothing else is left behind.
            @($result.Published).Count | Should -Be 1
            $entry = $result.Published[0]
            $entry.file | Should -Be 'good-1.0-py3-none-any.whl'
            $entry.sha256 | Should -Be $global:WhmReleases['good'].Files[0].Sha256
            (Get-FileHash -Path (Join-Path $folder $entry.file) -Algorithm SHA256).Hash | Should -Be $entry.sha256
            @(Get-ChildItem -Path $folder -Filter '*.whl*').Count | Should -Be 1
            @(Get-ChildItem -Path (Join-Path $folder 'staging') -Force).Count | Should -Be 0
        }

        It 'rejects a download whose sha256 differs from PyPI, and never publishes it' {
            $folder = Get-TestFolder
            $global:WhmReleases['tampered'] = New-TestRelease -Name 'tampered'
            $global:WhmReleases['fine'] = New-TestRelease -Name 'fine'
            $global:WhmWheelOverride = @{ tampered = 'not what PyPI published' }

            $params = Get-IntakeParam -Folder $folder -Packages @{ tampered = '1.0'; fine = '1.0' }
            $result = Invoke-TestIntake -Params $params

            ($result.Accepted.Keys -join ',') | Should -Be 'fine'
            (Get-RejectReason -Result $result)['tampered'] | Should -Match '^\[integrity\] sha256 of tampered-1.0-py3-none-any.whl does not match PyPI'
            Test-Path -Path (Join-Path $folder 'tampered-1.0-py3-none-any.whl') | Should -Be $false
        }

        It 'rejects yanked releases and yanked files' {
            $folder = Get-TestFolder
            $global:WhmReleases['gone'] = New-TestRelease -Name 'gone' -Yanked
            $global:WhmReleases['badfile'] = New-TestRelease -Name 'badfile' -FileYanked

            $params = Get-IntakeParam -Folder $folder -Packages @{ gone = '1.0'; badfile = '1.0' }
            $result = Invoke-TestIntake -Params $params

            $result.Accepted.Count | Should -Be 0
            $reasons = Get-RejectReason -Result $result
            $reasons['gone'] | Should -Match '^\[yanked\] yanked on PyPI: broken build'
            $reasons['badfile'] | Should -Match '^\[yanked\] badfile-1.0-py3-none-any.whl is yanked'
            # The yanked release is rejected before it is downloaded.
            ($global:WhmIntakeDownloaded -join ',') | Should -Be 'badfile'
        }

        It 'applies the cooldown to the downloaded file, and skips it only for expedited pins' {
            $folder = Get-TestFolder
            # An old release with a wheel that was added to it two days ago.
            $global:WhmReleases['late'] = New-TestRelease -Name 'late' -UploadDaysAgo 400 -FileUploadDaysAgo 2
            $global:WhmReleases['urgent'] = New-TestRelease -Name 'urgent' -UploadDaysAgo 1
            $global:WhmReleases['other'] = New-TestRelease -Name 'other' -UploadDaysAgo 1

            $params = Get-IntakeParam -Folder $folder -Packages @{ late = '1.0'; urgent = '1.0'; other = '1.0' }
            # Expediting a different version than the candidate has no effect.
            $params['Expedite'] = @{ urgent = '1.0'; other = '9.9' }
            $result = Invoke-TestIntake -Params $params

            ($result.Accepted.Keys -join ',') | Should -Be 'urgent'
            $reasons = Get-RejectReason -Result $result
            $reasons['late'] | Should -Match '^\[cooldown\] .*late-1.0-py3-none-any.whl was uploaded 2 day'
            $reasons['other'] | Should -Match '^\[cooldown\] .*published 1 day'
        }

        It 'rejects only the package Defender detects, and handles a scan that could not run' {
            $folder = Get-TestFolder
            $global:WhmReleases['evil'] = New-TestRelease -Name 'evil'
            $global:WhmReleases['clean'] = New-TestRelease -Name 'clean'
            $global:WhmScanStatus = 'Threat'
            $global:WhmThreatPackage = 'evil'

            $params = Get-IntakeParam -Folder $folder -Packages @{ evil = '1.0'; clean = '1.0' }
            $result = Invoke-TestIntake -Params $params
            ($result.Accepted.Keys -join ',') | Should -Be 'clean'
            (Get-RejectReason -Result $result)['evil'] | Should -Match '^\[defender\] Microsoft Defender detected Trojan:Test in evil-1.0'
            Test-Path -Path (Join-Path $folder 'evil-1.0-py3-none-any.whl') | Should -Be $false

            # Scan unavailable: published with a warning by default...
            $global:WhmScanStatus = 'Error'
            $other = Get-TestFolder
            $params = Get-IntakeParam -Folder $other -Packages @{ clean = '1.0' }
            (Invoke-TestIntake -Params $params).Accepted.Count | Should -Be 1

            # ...and rejected when a scan is required.
            $strict = Get-TestFolder
            $params = Get-IntakeParam -Folder $strict -Packages @{ clean = '1.0' }
            $params['RequireDefenderScan'] = $true
            $required = Invoke-TestIntake -Params $params
            $required.Accepted.Count | Should -Be 0
            (Get-RejectReason -Result $required)['clean'] | Should -Match '^\[defender\] the Defender scan could not be completed'
            @(Get-ChildItem -Path $strict -Filter '*.whl').Count | Should -Be 0

            # Turned off (setting DefenderScanAtIntake): no scan at all, published - also
            # when a scan would find something.
            $global:WhmScanStatus = 'Threat'
            $global:WhmThreatPackage = 'clean'
            $off = Get-TestFolder
            $params = Get-IntakeParam -Folder $off -Packages @{ clean = '1.0' }
            $params['SkipDefenderScan'] = $true
            $params['RequireDefenderScan'] = $true
            $skipped = Invoke-TestIntake -Params $params
            $skipped.Accepted.Count | Should -Be 1
            $skipped.Intake.Scan | Should -BeNullOrEmpty
        }

        It 'fails closed when PyPI release data is unavailable' {
            $folder = Get-TestFolder
            $params = Get-IntakeParam -Folder $folder -Packages @{ unknown = '1.0' }
            $result = Invoke-TestIntake -Params $params
            $result.Accepted.Count | Should -Be 0
            (Get-RejectReason -Result $result)['unknown'] | Should -Match '^\[pypi-metadata\] cooldown: could not verify'
            $global:WhmIntakeDownloaded | Should -BeNullOrEmpty
        }

        It 'accepts nothing when the audit could not be completed' {
            $folder = Get-TestFolder
            $global:WhmIntakeAudit = @([PSCustomObject]@{ Stage = 'PreDownload'; Group = 'requirements-1-candidates'; Service = 'osv'; Status = 'Error'; ReportPath = 'none'; Message = 'm' })
            Mock -ModuleName WheelhouseManager -CommandName Invoke-GroupAudit -MockWith { , $global:WhmIntakeAudit }
            Mock -ModuleName WheelhouseManager -CommandName Test-PackageAge -MockWith { throw 'must not be called' }
            Mock -ModuleName WheelhouseManager -CommandName Invoke-PipPinRetry -MockWith { throw 'must not be called' }

            $intakeParams = @{
                Packages       = @{ a = '1'; b = '2' }
                GroupName      = 'requirements-1'
                ReportsFolder  = $folder
                Services       = @('osv')
                MinimumAgeDays = 10
                PythonVersion  = '3.14'
                Platform       = 'win_amd64'
            }
            $result = Invoke-CandidateIntake @intakeParams

            $result.Verified.Count | Should -Be 0
            $result.StagingPath | Should -BeNullOrEmpty
            @($result.Rejected).Count | Should -Be 2
            $result.Rejected[0].Reason | Should -Match 'could not be completed'
        }
    }

    Context 'Dependencies of candidates' {
        It 'reads both styles of uv "# via" annotations, skipping -r and -c sources' {
            $file = Join-Path (Get-TestFolder) 'requirements.txt'
            Set-Content -Path $file -Value @(
                '# This file was autogenerated by uv via the following command:',
                '#    .\Update-Requirement.ps1',
                'Requests==2.32.3',
                '    # via -r requirements.in',
                'urllib3==2.8.0',
                '    # via requests',
                'idna==3.20',
                '    # via',
                '    #   -r requirements.in',
                '    #   anyio',
                '    #   requests',
                'Typing_Extensions==4.0 ; python_version < "3.13"',
                '    # via',
                '    #   -c constraints.txt',
                '    #   anyio')
            $dependents = Read-RequirementDependent -FilePath $file
            ($dependents.Keys | Sort-Object) -join ',' | Should -Be 'idna,typing-extensions,urllib3'
            $dependents['urllib3'] -join ',' | Should -Be 'requests'
            $dependents['idna'] -join ',' | Should -Be 'anyio,requests'
            $dependents['typing-extensions'] -join ',' | Should -Be 'anyio'
        }

        It 'holds back every candidate that needs a rejected pin, up the chain, and only for that version' {
            $rejected = @([PSCustomObject]@{ Name = 'urllib3'; Version = '2.8.0'; Reason = 'cooldown: published 2 day(s) ago' })
            $params = @{
                Rejected   = $rejected
                Dependents = @{ urllib3 = @('requests'); requests = @('app', 'tool'); idna = @('requests') }
                Pins       = @{ urllib3 = '2.8.0'; requests = '2.32.3'; app = '1.0'; tool = '2.0'; idna = '3.20' }
                Candidates = @{ requests = '2.32.3'; app = '1.0'; tool = '1.9'; idna = '3.20' }
            }
            $held = @(Get-DependentRejection @params)
            ($held | ForEach-Object { "$($_.Name)==$($_.Version)" }) -join ',' | Should -Be 'requests==2.32.3,app==1.0'
            $held[0].Category | Should -Be 'dependency'
            $held[0].Dependency | Should -Be 'urllib3==2.8.0'
            $held[0].Reason | Should -Be 'needs urllib3==2.8.0, which was rejected (cooldown: published 2 day(s) ago)'
            $held[1].Reason | Should -Match '^needs requests==2\.32\.3, which was rejected \(needs urllib3'

            # A rejection of another version than requirements.txt resolved holds nothing back.
            $params.Rejected = @([PSCustomObject]@{ Name = 'urllib3'; Version = '1.0'; Reason = 'x' })
            @(Get-DependentRejection @params).Count | Should -Be 0
        }
    }

    Context 'Dependencies of published packages' {
        It 'reads Requires-Dist without extras and evaluates version specifiers' {
            $folder = Get-TestFolder
            $entry = New-TestWheel -Folder $folder -Name 'requests' -Version '2.32.3' -RequiresDist @('urllib3 (<3,>=1.21.1)', 'Charset_Normalizer<4,>=2', 'PySocks!=1.5.7,>=1.5.6; extra == "socks"', 'win-inet-pton; sys_platform == "win32"')
            $requires = @(Read-WheelRequirement -Path (Join-Path $folder $entry.file))
            ($requires | ForEach-Object { "$($_.name)|$($_.spec)" }) -join ',' | Should -Be 'urllib3|<3,>=1.21.1,charset-normalizer|<4,>=2,win-inet-pton|'

            Test-VersionSpecifier -Version '2.8.0' -Specifier '<3,>=1.21.1' | Should -Be $true
            Test-VersionSpecifier -Version '3.0' -Specifier '<3,>=1.21.1' | Should -Be $false
            Test-VersionSpecifier -Version '2.8.0' -Specifier '' | Should -Be $true
            Test-VersionSpecifier -Version '2.8.0' -Specifier '==2.*' | Should -Be $true
            Test-VersionSpecifier -Version '3.1' -Specifier '!=3.*' | Should -Be $false
            Test-VersionSpecifier -Version '2.5' -Specifier '~=2.2' | Should -Be $true
            Test-VersionSpecifier -Version '3.0' -Specifier '~=2.2' | Should -Be $false
            Test-VersionSpecifier -Version '2.8.0' -Specifier '>=banana' | Should -Be $null
        }

        It 'records what each published version needs and names its dependents in notices and finding alerts' {
            $wheelhouse = Get-TestFolder
            $entries = @(
                (New-TestWheel -Folder $wheelhouse -Name 'urllib3' -Version '2.8.0'),
                (New-TestWheel -Folder $wheelhouse -Name 'requests' -Version '2.32.3' -RequiresDist @('urllib3 (<3,>=1.21.1)')),
                (New-TestWheel -Folder $wheelhouse -Name 'oldclient' -Version '1.0' -RequiresDist @('urllib3<2')),
                (New-TestWheel -Folder $wheelhouse -Name 'extras' -Version '1.0' -RequiresDist @('urllib3; extra == "http"')))
            Save-WheelhouseManifest -Manifest $entries -WheelhousePath $wheelhouse
            Set-Content -Path (Join-Path $wheelhouse 'requirements-1.txt') -Value @('urllib3==2.8.0', 'requests==2.32.3', 'oldclient==1.0', 'extras==1.0')
            $deny = Join-Path $wheelhouse 'denylist.json'

            Update-WheelhouseCatalog -WheelhousePath $wheelhouse -DenylistPath $deny
            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $catalog.Records['requests==2.32.3'].requires_checked | Should -Be $true
            $catalog.Records['requests==2.32.3'].requires[0].name | Should -Be 'urllib3'
            $catalog.Records['urllib3==2.8.0'].requires_checked | Should -Be $true
            @($catalog.Records['urllib3==2.8.0'].requires).Count | Should -Be 0

            # oldclient needs urllib3<2, so 2.8.0 is not its version; extras needs it only with an extra.
            $dependents = @(Get-CatalogDependent -Catalog $catalog -Name 'urllib3' -Version '2.8.0')
            ($dependents | ForEach-Object { "$($_.Name)==$($_.Version)" }) -join ',' | Should -Be 'requests==2.32.3'
            Format-CatalogDependent -Dependent $dependents | Should -Be 'requests==2.32.3 (needs urllib3 <3,>=1.21.1)'

            $notice = New-WheelhouseNotice -Kind 'Malicious' -Package 'urllib3' -Version '2.8.0' -Message 'OSV lists this version as a malicious package (MAL-1).'
            $other = New-WheelhouseNotice -Kind 'Untracked' -File @('x.whl') -Message 'untracked'
            [void](Add-WheelhouseNoticeDependent -Notice @($notice, $other) -Catalog $catalog)
            $notice.NeededBy -join ',' | Should -Be 'requests==2.32.3 (needs urllib3 <3,>=1.21.1)'
            $notice.Message | Should -Match 'Published package\(s\) that need it: requests==2\.32\.3'
            @($other.NeededBy).Count | Should -Be 0

            $catalog.Records['urllib3==2.8.0'].findings = @(ConvertTo-CatalogFinding -InputObject ([PSCustomObject]@{ id = 'GHSA-1'; severity = 'High'; first_seen = '2026-01-01T00:00:00Z'; due = '2099-01-01T00:00:00Z' }))
            Save-WheelhouseCatalog -Catalog $catalog
            $alert = @(Get-CatalogFindingAlert -Catalog (Read-WheelhouseCatalog -WheelhousePath $wheelhouse))
            $alert.Count | Should -Be 1
            $alert[0].NeededBy -join ',' | Should -Be 'requests==2.32.3 (needs urllib3 <3,>=1.21.1)'
            $html = ConvertTo-VulnerabilityAlertHtml -Findings $alert -WheelhousePath $wheelhouse
            $html | Should -Match 'Needed by published package\(s\):</b> requests==2\.32\.3'
        }
    }

    Context 'Get-UndownloadedPin' {
        It 'lists group entries without a matching wheel in the manifest' {
            $wheelhouse = Get-TestFolder
            $group = Join-Path $wheelhouse 'requirements-1.txt'
            Set-Content -Path $group -Value @('six==1.16.0', 'pyqtdarktheme2==2.1.2')
            $manifest = @([PSCustomObject]@{ name = 'six'; version = '1.16.0'; python_tag = 'py3'; abi_tag = 'none'; platform_tag = 'any' })

            $result = @(Get-UndownloadedPin -GroupFiles @($group) -Manifest $manifest -PythonVersion '3.14' -Platform 'win_amd64')

            $result.Count | Should -Be 1
            $result[0].Group | Should -Be 'requirements-1'
            "$($result[0].Package)==$($result[0].Version)" | Should -Be 'pyqtdarktheme2==2.1.2'
        }
    }

    Context 'Vulnerability alert for blocked candidates' {
        It 'marks a finding from a candidate audit as blocked, not deployed' {
            $reports = Get-TestFolder
            $report = Join-Path $reports 'Report_PreDownload-requirements-2-candidates-OSV_20260921_153000.json'
            Write-TestAuditReport -Path $report | Out-Null

            $result = Get-VulnerabilityFinding -ReportPaths @($report)
            $result.Findings[0].Deployed | Should -Be $false
            $result.Findings[0].GroupFiles -join ',' | Should -Be 'requirements-2.txt'

            $html = ConvertTo-VulnerabilityAlertHtml -Findings $result.Findings -WheelhousePath ''
            $html | Should -Match 'Blocked before download'
            $html | Should -Not -Match 'quarantine folder'
        }
    }

    Context 'Remove-ExpiredReport' {
        It 'removes only old log/report/alert files' {
            $reports = Get-TestFolder
            $old = (Get-Date).AddMonths(-7)
            foreach ($name in 'Log_1.txt', 'Report_x.json', 'Alert_1.html', 'keep.txt', 'Log_new.txt') {
                Set-Content -Path (Join-Path $reports $name) -Value 'x'
                if ($name -ne 'Log_new.txt') { (Get-Item -Path (Join-Path $reports $name)).LastWriteTime = $old }
            }
            Remove-ExpiredReport -ReportsFolder $reports -RetentionMonths 6
            (Get-ChildItem -Path $reports | ForEach-Object { $_.Name } | Sort-Object) -join ',' | Should -Be 'keep.txt,Log_new.txt'
        }
    }

    Context 'Wheelhouse lock' {
        It 'allows one holder at a time and releases the lock file' {
            $wheelhouse = Get-TestFolder
            $lock = Enter-WheelhouseLock -WheelhousePath $wheelhouse
            { Enter-WheelhouseLock -WheelhousePath $wheelhouse } | Should -Throw -ExceptionType ([System.InvalidOperationException])
            Exit-WheelhouseLock -Lock $lock
            Test-Path -Path (Join-Path $wheelhouse '.wheelhouse.lock') | Should -Be $false
            $again = Enter-WheelhouseLock -WheelhousePath $wheelhouse
            Exit-WheelhouseLock -Lock $again
        }
    }

    Context 'Denylist' {
        It 'adds, matches (exact version and wildcard), updates and removes entries' {
            $path = Join-Path (Get-TestFolder) 'denylist.json'
            [void](Add-WheelhouseDenylistEntry -Name 'Bad_Pkg' -Version '1.0' -Reason 'cve' -Source 'removed' -Path $path)
            [void](Add-WheelhouseDenylistEntry -Name 'evil' -Reason 'malware' -Path $path)
            [void](Add-WheelhouseDenylistEntry -Name 'bad.pkg' -Version '1.0' -Reason 'updated reason' -Source 'removed' -Path $path)

            $entries = @(Read-WheelhouseDenylist -Path $path)
            $entries.Count | Should -Be 2
            (Get-DenylistMatch -Name 'Bad-Pkg' -Version '1.0' -Denylist $entries).reason | Should -Be 'updated reason'
            Get-DenylistMatch -Name 'bad-pkg' -Version '1.1' -Denylist $entries | Should -BeNullOrEmpty
            (Get-DenylistMatch -Name 'EVIL' -Version '7.7' -Denylist $entries).source | Should -Be 'manual'

            Remove-WheelhouseDenylistEntry -Name 'evil' -OnlySource 'removed' -Path $path | Should -Be $false
            Remove-WheelhouseDenylistEntry -Name 'evil' -OnlySource 'manual' -Path $path | Should -Be $true
            @(Read-WheelhouseDenylist -Path $path).Count | Should -Be 1
        }

        It 'reads a missing file as empty and refuses a damaged one' {
            $folder = Get-TestFolder
            @(Read-WheelhouseDenylist -Path (Join-Path $folder 'none.json')).Count | Should -Be 0
            $bad = Join-Path $folder 'bad.json'
            Set-Content -Path $bad -Value '{ not json'
            { Read-WheelhouseDenylist -Path $bad } | Should -Throw '*could not be parsed*'
        }

        It 'validates names and versions' {
            $path = Join-Path (Get-TestFolder) 'denylist.json'
            { Add-WheelhouseDenylistEntry -Name 'bad name;' -Path $path } | Should -Throw -ExceptionType ([System.ArgumentException])
            { Add-WheelhouseDenylistEntry -Name 'ok' -Version '1 2' -Path $path } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It 'builds uv constraints for exact versions only' {
            $entries = @(
                [PSCustomObject]@{ name = 'a'; version = '1.0' },
                [PSCustomObject]@{ name = 'b'; version = '*' })
            [string[]]$lines = Get-DenylistConstraintLine -Denylist $entries
            $lines -join ',' | Should -Be 'a!=1.0'
        }
    }

    Context 'Invoke-CandidateIntake denylist' {
        It 'rejects blocked packages before any other check and audits only the rest' {
            $folder = Get-TestFolder
            $global:WhmIntakeCandidates = $null
            Mock -ModuleName WheelhouseManager -CommandName Invoke-GroupAudit -MockWith {
                $global:WhmIntakeCandidates = @(Get-Content -Path $GroupFile)
                , @([PSCustomObject]@{ Stage = 'PreDownload'; Group = 'g'; Service = 'osv'; Status = 'Passed'; ReportPath = 'none'; Message = 'm' })
            }
            $global:WhmReleases = @{ fine = (New-TestRelease -Name 'fine' -Version '2.0') }
            $global:WhmNoWheel = @()
            $global:WhmWheelOverride = @{}
            $global:WhmScanStatus = 'Clean'
            Mock -ModuleName WheelhouseManager -CommandName Test-PackageAge -MockWith $script:intakeAgeMock
            Mock -ModuleName WheelhouseManager -CommandName Invoke-PipPinRetry -MockWith $script:intakeDownloadMock
            Mock -ModuleName WheelhouseManager -CommandName Invoke-WheelhouseDefenderScan -MockWith $script:intakeScanMock

            $deny = @(
                [PSCustomObject]@{ name = 'evil'; version = '*'; reason = 'malware'; source = 'manual' },
                [PSCustomObject]@{ name = 'old'; version = '1.0'; reason = 'cve'; source = 'removed' })
            $intakeParams = @{
                Packages       = @{ evil = '9.9'; old = '1.0'; fine = '2.0' }
                GroupName      = 'requirements-1'
                WheelhousePath = $folder
                ReportsFolder  = $folder
                Services       = @('osv')
                MinimumAgeDays = 10
                PythonVersion  = '3.14'
                Platform       = 'win_amd64'
                Denylist       = $deny
                StagingRoot    = (Join-Path $folder 'staging')
            }
            $result = Invoke-TestIntake -Params $intakeParams

            ($result.Accepted.Keys -join ',') | Should -Be 'fine'
            $reasons = @{}
            foreach ($item in $result.Rejected) { $reasons[$item.Name] = $item.Reason }
            $reasons['evil'] | Should -Match 'denylist.*malware'
            $reasons['old'] | Should -Match 'denylist.*cve'
            ($global:WhmIntakeCandidates -join ',') | Should -Be 'fine==2.0'
        }

        It 'skips the audit when every candidate is blocked' {
            $folder = Get-TestFolder
            Mock -ModuleName WheelhouseManager -CommandName Invoke-GroupAudit -MockWith { throw 'must not be called' }
            Mock -ModuleName WheelhouseManager -CommandName Test-PackageAge -MockWith { throw 'must not be called' }
            Mock -ModuleName WheelhouseManager -CommandName Invoke-PipPinRetry -MockWith { throw 'must not be called' }
            $intakeParams = @{
                Packages       = @{ evil = '1.0' }
                GroupName      = 'requirements-1'
                ReportsFolder  = $folder
                Services       = @('osv')
                MinimumAgeDays = 10
                PythonVersion  = '3.14'
                Platform       = 'win_amd64'
                Denylist       = @([PSCustomObject]@{ name = 'evil'; version = '*'; reason = ''; source = 'manual' })
            }
            $result = Invoke-CandidateIntake @intakeParams
            $result.Verified.Count | Should -Be 0
            @($result.Rejected).Count | Should -Be 1
        }
    }

    Context 'PyPI release data' {
        It 'reads files, digests, upload times and yanked flags, whether dates arrive as text or [datetime]' {
            $global:WhmRestResponse = [PSCustomObject]@{
                info = [PSCustomObject]@{ yanked = $true; yanked_reason = 'broken' }
                urls = @(
                    [PSCustomObject]@{ filename = 'a-1.0-py3-none-any.whl'; digests = [PSCustomObject]@{ sha256 = 'aa11' }; upload_time_iso_8601 = '2026-01-05T10:00:00.000000Z'; yanked = $false; yanked_reason = $null },
                    [PSCustomObject]@{ filename = 'a-1.0.tar.gz'; digests = [PSCustomObject]@{ sha256 = 'bb22' }; upload_time_iso_8601 = [datetime]::new(2026, 1, 2, 0, 0, 0, [System.DateTimeKind]::Utc); yanked = $true; yanked_reason = 'sdist' })
            }
            Mock -ModuleName WheelhouseManager -CommandName Invoke-RestMethod -MockWith { $global:WhmRestResponse }

            $release = Get-PyPIReleaseInfo -Name 'a' -Version '1.0'

            @($release.Files).Count | Should -Be 2
            $release.Files[0].Sha256 | Should -Be 'aa11'
            $release.Files[0].UploadTimeUtc | Should -Be ([datetime]::new(2026, 1, 5, 10, 0, 0, [System.DateTimeKind]::Utc))
            $release.Files[1].Yanked | Should -Be $true
            $release.FirstUploadUtc | Should -Be ([datetime]::new(2026, 1, 2, 0, 0, 0, [System.DateTimeKind]::Utc))
            $release.Yanked | Should -Be $true
            $release.YankedReason | Should -Be 'broken'

            $global:WhmRestResponse = [PSCustomObject]@{ info = [PSCustomObject]@{ yanked = $false }; urls = @() }
            { Get-PyPIReleaseInfo -Name 'a' -Version '1.0' } | Should -Throw '*No release files*'
        }

        It 'checks the age, gives the eligible date, honours expedite and fails closed' {
            $global:WhmPyPI = @{
                fresh  = (New-TestRelease -Name 'fresh' -UploadDaysAgo 3)
                urgent = (New-TestRelease -Name 'urgent' -UploadDaysAgo 3)
                old    = (New-TestRelease -Name 'old' -UploadDaysAgo 30)
            }
            Mock -ModuleName WheelhouseManager -CommandName Get-PyPIReleaseInfo -MockWith {
                if (-not $global:WhmPyPI.ContainsKey($Name)) { throw 'HTTP 404' }
                $global:WhmPyPI[$Name]
            }

            $check = Test-PackageAge -Packages @{ fresh = '1.0'; urgent = '1.0'; old = '1.0'; gone = '1.0' } -MinimumAgeDays 10 -Expedite @('urgent')
            $byName = @{}
            foreach ($row in $check.Results) { $byName[$row.Package] = $row }

            $byName['fresh'].Passed | Should -Be $false
            (ConvertTo-UtcDateTime -Value $byName['fresh'].EligibleUtc).Date | Should -Be ((Get-Date).ToUniversalTime().AddDays(7).Date)
            $byName['urgent'].Passed | Should -Be $true
            $byName['urgent'].Expedited | Should -Be $true
            $byName['old'].Passed | Should -Be $true
            $byName['old'].Release.Name | Should -Be 'old'
            $byName['gone'].Passed | Should -Be $false
            $byName['gone'].Release | Should -BeNullOrEmpty
            $byName['gone'].Error | Should -Match '404'
        }
    }

    Context 'Publish-StagedWheel' {
        It 'publishes atomically, keeps an identical untracked file and refuses a different one' {
            $staging = Get-TestFolder
            $wheelhouse = Get-TestFolder
            $staged = Join-Path $staging 'pkg-1.0-py3-none-any.whl'
            Set-Content -Path $staged -Value 'verified bytes'

            $first = Publish-StagedWheel -Path $staged -WheelhousePath $wheelhouse
            $first.Created | Should -Be $true
            $first.Entry.name | Should -Be 'pkg'
            $first.Entry.sha256 | Should -Be (Get-FileHash -Path $staged -Algorithm SHA256).Hash
            (Get-FileHash -Path (Join-Path $wheelhouse 'pkg-1.0-py3-none-any.whl') -Algorithm SHA256).Hash | Should -Be $first.Entry.sha256

            $again = Publish-StagedWheel -Path $staged -WheelhousePath $wheelhouse
            $again.Created | Should -Be $false

            Set-Content -Path (Join-Path $wheelhouse 'pkg-1.0-py3-none-any.whl') -Value 'someone else''s file'
            { Publish-StagedWheel -Path $staged -WheelhousePath $wheelhouse } | Should -Throw '*different file*'
            @(Get-ChildItem -Path $wheelhouse -Filter '*.partial').Count | Should -Be 0
        }
    }

    Context 'Published packages that fail a check later' {
        It 'reports deployed versions that are denylisted or yanked, and an unreadable release as an error' {
            $manifest = @(
                [PSCustomObject]@{ name = 'six'; version = '1.16.0'; file = 'six-1.16.0-py3-none-any.whl' },
                [PSCustomObject]@{ name = 'attrs'; version = '23.1.0'; file = 'attrs-23.1.0-py3-none-any.whl' },
                [PSCustomObject]@{ name = 'fine'; version = '1.0'; file = 'fine-1.0-py3-none-any.whl' })
            $deny = @([PSCustomObject]@{ name = 'attrs'; version = '23.1.0'; reason = 'cve'; source = 'manual' })
            $global:WhmPyPI = @{
                six  = (New-TestRelease -Name 'six' -Version '1.16.0' -FileYanked)
                fine = (New-TestRelease -Name 'fine')
            }
            Mock -ModuleName WheelhouseManager -CommandName Get-PyPIReleaseInfo -MockWith {
                if (-not $global:WhmPyPI.ContainsKey($Name)) { throw 'timeout' }
                $global:WhmPyPI[$Name]
            }

            $result = Get-DeployedPackageNotice -Manifest $manifest -Denylist $deny

            $kinds = @($result.Notices | ForEach-Object { "$($_.Kind):$($_.Package)" } | Sort-Object)
            $kinds -join ',' | Should -Be 'Denylisted:attrs,Yanked:six'
            ($result.Notices | Where-Object { $_.Kind -eq 'Yanked' }).Message | Should -Match 'bad file'
            @($result.Errors).Count | Should -Be 1
            $result.Errors[0] | Should -Match 'attrs==23.1.0 \(timeout\)'

            $offline = Get-DeployedPackageNotice -Manifest $manifest -Denylist $deny -SkipYanked
            (@($offline.Notices).Count, @($offline.Errors).Count) -join ',' | Should -Be '1,0'
        }

        It 'classifies wheels removed or changed on the share, and still stops on anything else' {
            $wheelhouse = Get-TestWheelhouse
            $reports = Get-TestFolder
            $manifest = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            # The file server's antivirus took six away and "cleaned" attrs.
            Remove-Item -Path (Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl')
            Set-Content -Path (Join-Path $wheelhouse 'attrs-23.1.0-py3-none-any.whl') -Value 'cleaned by antivirus'

            $problems = @(Get-WheelhouseIntegrityProblem -Manifest $manifest -WheelhousePath $wheelhouse)
            ($problems | ForEach-Object { "$($_.Kind):$($_.Entry.name)" } | Sort-Object) -join ',' | Should -Be 'Missing:six,Modified:attrs'

            # Without the switch any problem stops the run (fail closed)...
            { Assert-WheelhouseIntegrity -Manifest $manifest -WheelhousePath $wheelhouse -ReportsFolder $reports } | Should -Throw '*integrity check failed*'
            # ...with it, Missing and Modified are handed back to deal with.
            $changed = @(Assert-WheelhouseIntegrity -Manifest $manifest -WheelhousePath $wheelhouse -ReportsFolder $reports -AllowChangedFiles)
            $changed.Count | Should -Be 2
            @(Get-ChildItem -Path $reports -Filter 'Report_Integrity_*.json').Count | Should -BeGreaterOrEqual 1

            # A broken manifest record still stops it.
            $broken = @($manifest) + [PSCustomObject]@{ name = 'x'; version = '1'; file = @('a', 'b'); sha256 = 'X' }
            { Assert-WheelhouseIntegrity -Manifest $broken -WheelhousePath $wheelhouse -ReportsFolder $reports -AllowChangedFiles } | Should -Throw '*integrity check failed*'
        }

        It 'takes out a missing wheel and quarantines a changed one, or only reports them' {
            $wheelhouse = Get-TestWheelhouse
            $reports = Get-TestFolder
            $denyPath = Join-Path $wheelhouse 'denylist.json'
            $manifest = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            Remove-Item -Path (Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl')
            Set-Content -Path (Join-Path $wheelhouse 'attrs-23.1.0-py3-none-any.whl') -Value 'cleaned by antivirus'
            $changed = @(Assert-WheelhouseIntegrity -Manifest $manifest -WheelhousePath $wheelhouse -ReportsFolder $reports -AllowChangedFiles)

            # AutoQuarantine off: nothing changes, the notices say what to do.
            $reportOnly = @(Resolve-WheelhouseIntegrityProblem -WheelhousePath $wheelhouse -Problem $changed -DenylistPath $denyPath)
            ($reportOnly | ForEach-Object { "$($_.Kind):$($_.Package)" } | Sort-Object) -join ',' | Should -Be 'FileMissing:six,FileModified:attrs'
            $reportOnly[0].Message | Should -Match 'AutoQuarantine is off'
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'six==1.16.0,attrs==23.1.0'

            # AutoQuarantine on: both are taken out and blocked.
            $lock = Open-WheelhouseWrite -WheelhousePath $wheelhouse -DenylistPath $denyPath
            try {
                $notices = @(Resolve-WheelhouseIntegrityProblem -WheelhousePath $wheelhouse -Problem $changed -AutoQuarantine -DenylistPath $denyPath)
            }
            finally {
                Exit-WheelhouseLock -Lock $lock
            }
            ($notices | Where-Object { $_.Kind -eq 'FileMissing' }).Message | Should -Match "file server's antivirus"
            Test-Path -Path (Join-Path $wheelhouse 'requirements-1.txt') | Should -Be $true
            @(Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')).Count | Should -Be 0
            (Read-WheelhouseManifest -WheelhousePath $wheelhouse).Count | Should -Be 0
            $deny = @(Read-WheelhouseDenylist -Path $denyPath)
            ($deny | ForEach-Object { "$($_.name):$($_.source)" } | Sort-Object) -join ',' | Should -Be 'attrs:quarantined,six:removed'
            # The manager deleted nothing: the history and the denylist say "taken out".
            ($deny | Where-Object { $_.name -eq 'six' }).reason | Should -Match '\(taken out\)$'
            (Read-WheelhouseEvent -WheelhousePath $wheelhouse -Package 'six')[0].action | Should -Be 'TakenOut'
            # The changed file is kept as evidence; restoring it is refused.
            $record = @(Get-QuarantinedPackage -WheelhousePath $wheelhouse)[0]
            $record.name | Should -Be 'attrs'
            { Restore-WheelhousePackage -WheelhousePath $wheelhouse -Id $record.id -DenylistPath $denyPath } | Should -Throw '*hash changed*'
            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $catalog.Records['six==1.16.0'].state | Should -Be 'Removed'
            $catalog.Records['attrs==23.1.0'].state | Should -Be 'Quarantined'
        }

        It 'lets the lock holder clean up a removed wheel' {
            $wheelhouse = Get-TestWheelhouse
            $denyPath = Join-Path (Get-TestFolder) 'denylist.json'
            Remove-Item -Path (Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl')
            $lock = Enter-WheelhouseLock -WheelhousePath $wheelhouse
            try {
                $done = Remove-WheelhousePackage -WheelhousePath $wheelhouse -Name 'six' -Version '1.16.0' -Reason 'removed by Microsoft Defender: X' -DenylistPath $denyPath -LockHeld
            }
            finally {
                Exit-WheelhouseLock -Lock $lock
            }
            $done.Groups -join ',' | Should -Be 'requirements-1.txt'
            @((Read-WheelhouseManifest -WheelhousePath $wheelhouse).name) -join ',' | Should -Be 'attrs'
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'attrs==23.1.0'
            (Read-WheelhouseDenylist -Path $denyPath)[0].reason | Should -Match 'Microsoft Defender'
        }
    }

    Context 'Alert notices' {
        It 'alerts on notices alone and lists them with a recommended action' {
            $notice = New-WheelhouseNotice -Kind 'Yanked' -Package 'six' -Version '1.16.0' -File @('six-1.16.0-py3-none-any.whl') -Message 'Yanked on PyPI: <bad>'
            $notice.PSObject.TypeNames | Should -Contain 'Wheelhouse.Notice'
            $notice.Action | Should -Match 'quarantine'

            Get-VulnerabilityAlertParameter -AuditResult @() | Should -BeNullOrEmpty
            $params = Get-VulnerabilityAlertParameter -AuditResult @() -Notice @($notice) -CheckError @('PyPI yanked check could not be completed') -AlertParameters @{ SmtpServer = 'x' }
            @($params.Notices).Count | Should -Be 1
            $params.AuditErrors -join '|' | Should -Be 'PyPI yanked check could not be completed'
            $params.SmtpServer | Should -Be 'x'

            $html = ConvertTo-VulnerabilityAlertHtml -Notices @($notice) -AuditErrors @() -WheelhousePath ''
            $html | Should -Match 'Packages that need attention \(1\)'
            $html | Should -Match 'six==1.16.0'
            $html | Should -Match '&lt;bad&gt;'
        }
    }

    Context 'Exit codes' {
        It 'maps outcomes and errors, with a separate code for a busy lock' {
            Get-WheelhouseExitCode | Should -Be 0
            Get-WheelhouseExitCode -Outcome Attention | Should -Be 1
            Get-WheelhouseExitCode -Outcome Error | Should -Be 2
            $wheelhouse = Get-TestFolder
            $lock = Enter-WheelhouseLock -WheelhousePath $wheelhouse
            try {
                try { Enter-WheelhouseLock -WheelhousePath $wheelhouse } catch { $busy = $_ }
            }
            finally {
                Exit-WheelhouseLock -Lock $lock
            }
            Get-WheelhouseExitCode -ErrorRecord $busy | Should -Be 3
            try { throw 'anything else' } catch { $other = $_ }
            Get-WheelhouseExitCode -ErrorRecord $other | Should -Be 2
        }
    }

    Context 'Script hygiene' {
        It 'never assigns to a validated parameter (variable names are case-insensitive)' {
            # Regression: "$autoQuarantine = <bool>" in a script with a ValidateSet('On','Off')
            # -AutoQuarantine parameter failed validation, left the value empty and silently
            # turned automatic quarantine off.
            $root = Split-Path -Path $PSScriptRoot -Parent
            $scripts = @(Get-ChildItem -Path (Join-Path $root 'Jobs') -Filter '*.ps1') + @(Get-ChildItem -Path $root -Filter '*.ps1')
            $offenders = foreach ($file in $scripts) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
                if (-not $ast.ParamBlock) { continue }
                $validated = @($ast.ParamBlock.Parameters | Where-Object {
                        $_.Attributes | Where-Object { $_.TypeName.Name -like 'Validate*' }
                    } | ForEach-Object { $_.Name.VariablePath.UserPath })
                $assignments = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
                foreach ($assignment in $assignments) {
                    $name = $assignment.Left.VariablePath.UserPath
                    if ($validated | Where-Object { $_ -eq $name }) { "$($file.Name):$($assignment.Extent.StartLineNumber) `$$name" }
                }
            }
            @($offenders) | Should -BeNullOrEmpty
        }

        It 'never makes a closure in a script (Windows PowerShell 5.1 re-validates unbound parameters)' {
            # Regression: the Scheduled Task runs Test-Wheelhouse.ps1 without -WheelhousePath;
            # in 5.1 "{ ... }.GetNewClosure()" copied the empty [ValidateNotNullOrEmpty()]
            # parameter into the closure, failed, and no result reached the catalog. A script
            # block from a script sees the script's variables without a closure.
            $root = Split-Path -Path $PSScriptRoot -Parent
            $scripts = @(Get-ChildItem -Path (Join-Path $root 'Jobs') -Filter '*.ps1') + @(Get-ChildItem -Path $root -Filter '*.ps1')
            $offenders = foreach ($file in $scripts) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
                $calls = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'GetNewClosure' }, $true)
                foreach ($call in $calls) { "$($file.Name):$($call.Extent.StartLineNumber)" }
            }
            @($offenders) | Should -BeNullOrEmpty
        }
    }

    Context 'Shared validation' {
        It 'parses pins from arrays and comma/semicolon lists and refuses anything else' {
            $pins = @(ConvertTo-WheelhousePin -Pin @('Numpy_Core==2.0.1, pandas==2.2.3', 'x==1!2.0+local'))
            ($pins | ForEach-Object { "$($_.Name)==$($_.Version)" }) -join '|' | Should -Be 'numpy-core==2.0.1|pandas==2.2.3|x==1!2.0+local'
            @(ConvertTo-WheelhousePin -Pin @()).Count | Should -Be 0
            { ConvertTo-WheelhousePin -Pin 'numpy>=2' } | Should -Throw -ExceptionType ([System.ArgumentException])
            { ConvertTo-WheelhousePin -Pin 'a==1;rm -rf' } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It 'accepts bare wheel file names only' {
            Test-WheelhouseWheelFileName 'six-1.16.0-py3-none-any.whl' | Should -Be $true
            Test-WheelhouseWheelFileName '..\six-1.16.0-py3-none-any.whl' | Should -Be $false
            Test-WheelhouseWheelFileName 'sub/six.whl' | Should -Be $false
            Test-WheelhouseWheelFileName 'six.zip' | Should -Be $false
        }
    }

    Context 'Locks' {
        It 'waits up to the timeout for a busy lock, keeps the sync lock separate, and reports a missing folder' {
            $wheelhouse = Get-TestFolder
            $write = Enter-WheelhouseLock -WheelhousePath $wheelhouse
            try {
                $started = Get-Date
                try { Enter-WheelhouseLock -WheelhousePath $wheelhouse -TimeoutSeconds 1 } catch { $busy = $_ }
                ((Get-Date) - $started).TotalSeconds | Should -BeGreaterOrEqual 0.9
                $busy.Exception.Data['WheelhouseLockBusy'] | Should -Be $true

                $sync = Enter-WheelhouseLock -WheelhousePath $wheelhouse -Kind sync
                { Enter-WheelhouseLock -WheelhousePath $wheelhouse -Kind sync } | Should -Throw '*Update-Wheelhouse run is already in progress*'
                Exit-WheelhouseLock -Lock $sync
            }
            finally {
                Exit-WheelhouseLock -Lock $write
            }
            try { Enter-WheelhouseLock -WheelhousePath (Join-Path $wheelhouse 'missing') } catch { $missing = $_ }
            $missing.Exception.Message | Should -Match 'does not exist'
            $missing.Exception.Data['WheelhouseLockBusy'] | Should -BeNullOrEmpty
        }
    }

    Context 'Catalog' {
        It 'is created from the manifest, the group files and the latest reports, then reconciled' {
            $wheelhouse = Get-TestWheelhouse
            $reports = Join-Path $wheelhouse 'reports'
            New-Item -ItemType Directory -Path $reports | Out-Null
            Set-Content -Path (Join-Path $reports 'Report_Scheduled-requirements-1-OSV_20260101_000000.json') -Value '{"dependencies":[{"name":"six","version":"1.16.0","vulns":[]},{"name":"attrs","version":"23.1.0","vulns":[{"id":"PYSEC-9"}]}]}'

            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $catalog.Exists | Should -Be $false
            Sync-WheelhouseCatalog -Catalog $catalog | Should -Be $true
            Save-WheelhouseCatalog -Catalog $catalog

            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            ($catalog.Records.Keys | Sort-Object) -join ',' | Should -Be 'attrs==23.1.0,six==1.16.0'
            $attrs = $catalog.Records['attrs==23.1.0']
            $attrs.state | Should -Be 'Published'
            $attrs.groups -join ',' | Should -Be 'requirements-1.txt'
            $attrs.files -join ',' | Should -Be 'attrs-23.1.0-py3-none-any.whl'
            $attrs.checks.audit.status | Should -Be 'Vulnerable'
            @($attrs.checks.audit.vulnerabilities) -join ',' | Should -Be 'PYSEC-9'
            (Read-WheelhouseEvent -WheelhousePath $wheelhouse)[0].action | Should -Be 'CatalogCreated'

            # attrs leaves the manifest with a quarantine record, six without one.
            Save-WheelhouseManifest -Manifest @() -WheelhousePath $wheelhouse
            Save-QuarantineRecord -WheelhousePath $wheelhouse -Record @([PSCustomObject]@{ id = 'q1'; name = 'attrs'; version = '23.1.0'; files = @(); groups = @() })
            Sync-WheelhouseCatalog -Catalog $catalog | Should -Be $true
            $catalog.Records['attrs==23.1.0'].state | Should -Be 'Quarantined'
            $catalog.Records['six==1.16.0'].state | Should -Be 'Removed'
            @($catalog.Records['six==1.16.0'].groups).Count | Should -Be 0
            $events = @(Read-WheelhouseEvent -WheelhousePath $wheelhouse -Package 'Six')
            $events[0].action | Should -Be 'Reconciled'
            $events[0].detail | Should -Match 'Published -> Removed'
            Sync-WheelhouseCatalog -Catalog $catalog | Should -Be $false
        }

        It 'records audit, scan and PyPI results and their changes' {
            $wheelhouse = Get-TestWheelhouse
            $reports = Get-TestFolder
            Update-WheelhouseCatalog -WheelhousePath $wheelhouse -DenylistPath (Join-Path $reports 'deny.json')
            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse

            $clean = Join-Path $reports 'clean.json'
            Set-Content -Path $clean -Value '{"dependencies":[{"name":"six","version":"1.16.0","vulns":[]},{"name":"attrs","version":"23.1.0","vulns":[]}]}'
            $passed = @(
                [PSCustomObject]@{ Service = 'osv'; Status = 'Passed'; ReportPath = $clean; GroupFile = 'x' },
                [PSCustomObject]@{ Service = 'pypi'; Status = 'Passed'; ReportPath = $clean; GroupFile = 'x' })
            Update-CatalogAuditResult -Catalog $catalog -AuditResult $passed
            $catalog.Records['six==1.16.0'].checks.audit.status | Should -Be 'Passed'
            $catalog.Records['six==1.16.0'].checks.audit.last_ok | Should -Not -BeNullOrEmpty

            # Only one service ran: one service's Passed is not enough on its own...
            $fresh = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            Update-CatalogAuditResult -Catalog $fresh -AuditResult @($passed[0])
            $fresh.Records['six==1.16.0'].checks.audit.status | Should -Be 'Unknown'

            # ...a vulnerability from one service is.
            $bad = Join-Path $reports 'bad.json'
            Set-Content -Path $bad -Value '{"dependencies":[{"name":"attrs","version":"23.1.0","vulns":[{"id":"GHSA-1"}]}]}'
            Update-CatalogAuditResult -Catalog $catalog -AuditResult @([PSCustomObject]@{ Service = 'osv'; Status = 'Vulnerable'; ReportPath = $bad; GroupFile = 'x' })
            $catalog.Records['attrs==23.1.0'].checks.audit.status | Should -Be 'Vulnerable'
            @($catalog.Records['attrs==23.1.0'].checks.audit.vulnerabilities) -join ',' | Should -Be 'GHSA-1'
            @(Read-WheelhouseEvent -WheelhousePath $wheelhouse -Package 'attrs' | Where-Object { $_.action -eq 'AuditChanged' })[0].detail | Should -Match 'Passed -> Vulnerable: GHSA-1'

            # An audit that could not run never turns a status into Passed.
            $groupFile = Join-Path $wheelhouse 'requirements-1.txt'
            Update-CatalogAuditResult -Catalog $catalog -AuditResult @([PSCustomObject]@{ Service = 'osv'; Status = 'Error'; ReportPath = 'none'; GroupFile = $groupFile; Message = 'timeout' })
            $catalog.Records['attrs==23.1.0'].checks.audit.status | Should -Be 'Vulnerable'
            $catalog.Records['attrs==23.1.0'].checks.audit.services['osv'].error | Should -Be 'timeout'

            # A whole-wheelhouse scan covers every file; a scan of another folder covers none.
            $attrsPath = Join-Path $wheelhouse 'attrs-23.1.0-py3-none-any.whl'
            Update-CatalogScanResult -Catalog $catalog -ScanResult ([PSCustomObject]@{ Status = 'Threat'; ScannedPaths = @($wheelhouse); Threats = @([PSCustomObject]@{ Resource = "file:_$attrsPath"; ThreatName = 'X' }) })
            $catalog.Records['attrs==23.1.0'].checks.scan.status | Should -Be 'Threat'
            $catalog.Records['six==1.16.0'].checks.scan.status | Should -Be 'Clean'
            Update-CatalogScanResult -Catalog $catalog -ScanResult ([PSCustomObject]@{ Status = 'Clean'; ScannedPaths = @((Get-TestFolder)); Threats = @() })
            $catalog.Records['attrs==23.1.0'].checks.scan.status | Should -Be 'Threat'
            Update-CatalogScanResult -Catalog $catalog -ScanResult ([PSCustomObject]@{ Status = 'Error'; ScannedPaths = @($wheelhouse); Threats = @() })
            $catalog.Records['attrs==23.1.0'].checks.scan.status | Should -Be 'Threat'

            Update-CatalogPyPIResult -Catalog $catalog -Checked @([PSCustomObject]@{ Package = 'six'; Version = '1.16.0'; Yanked = $true; Reason = 'broken' })
            Save-WheelhouseCatalog -Catalog $catalog

            # The UI's inventory reads all of it from the catalog.
            $rows = @{}
            foreach ($row in (Get-WheelhousePackage -WheelhousePath $wheelhouse).Packages) { $rows[$row.name] = $row }
            $rows['attrs'].audit_status | Should -Be 'Vulnerable'
            $rows['attrs'].scan_status | Should -Be 'Threat'
            $rows['six'].yanked | Should -Be 'broken'
            $rows['six'].scan_status | Should -Be 'Clean'
        }

        It 'keeps timestamps ISO through a read and save (PowerShell 7 parses them into [datetime])' {
            # Regression: [string] of a parsed [datetime] gave "01/01/2026 00:00:00".
            $wheelhouse = Get-TestWheelhouse
            Update-WheelhouseCatalog -WheelhousePath $wheelhouse -DenylistPath (Join-Path $wheelhouse 'd.json')
            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $catalog.Records['six==1.16.0'].checks.audit = [ordered]@{
                status = 'Passed'; last_run = '2026-01-01T00:00:00.0000000Z'; last_ok = '2026-01-01T00:00:00.0000000Z'; vulnerabilities = @()
                services = [ordered]@{ osv = [ordered]@{ status = 'Passed'; last_run = '2026-01-01T00:00:00.0000000Z'; vulnerabilities = @(); last_error = ''; error = '' } }
            }
            Save-WheelhouseCatalog -Catalog $catalog

            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $catalog.Records['six==1.16.0'].checks.audit.last_ok | Should -Be '2026-01-01T00:00:00.0000000Z'
            $failedAudit = [PSCustomObject]@{ Service = 'osv'; Status = 'Error'; ReportPath = 'none'; GroupFile = (Join-Path $wheelhouse 'requirements-1.txt'); Message = 'down' }
            Update-CatalogAuditResult -Catalog $catalog -AuditResult @($failedAudit) -Services @('osv')
            # A failed audit records the error but does not count as a fresh audit.
            $catalog.Records['six==1.16.0'].checks.audit.last_run | Should -Be '2026-01-01T00:00:00.0000000Z'
            $catalog.Records['six==1.16.0'].checks.audit.services['osv'].error | Should -Be 'down'
            Save-WheelhouseCatalog -Catalog $catalog

            $raw = Get-Content -Path (Get-WheelhouseCatalogPath -WheelhousePath $wheelhouse) -Raw
            $raw | Should -Match '"last_ok":\s*"2026-01-01T00:00:00'
            $raw | Should -Not -Match '01/01/2026'
        }

        It 'refuses a damaged catalog and skips unreadable history lines' {
            $wheelhouse = Get-TestFolder
            Set-Content -Path (Join-Path $wheelhouse 'catalog.json') -Value '{ broken'
            { Read-WheelhouseCatalog -WheelhousePath $wheelhouse } | Should -Throw '*could not be parsed*'

            Write-WheelhouseEvent -WheelhousePath $wheelhouse -Action 'One' -Package 'a' -Version '1'
            Add-Content -Path (Join-Path $wheelhouse 'events.jsonl') -Value 'not json'
            Write-WheelhouseEvent -WheelhousePath $wheelhouse -Action 'Two' -Package 'b' -Version '1'
            (@(Read-WheelhouseEvent -WheelhousePath $wheelhouse) | ForEach-Object { $_.action }) -join ',' | Should -Be 'Two,One'
            (@(Read-WheelhouseEvent -WheelhousePath $wheelhouse -Package 'A') | ForEach-Object { $_.action }) -join ',' | Should -Be 'One'
        }
    }

    Context 'Severity, findings and waivers' {
        BeforeAll {
            # A catalog for the test wheelhouse with audit results recorded from a report
            # that lists the given advisory IDs for attrs==23.1.0.
            function New-TestFindingCatalog {
                param([string[]]$Id, [hashtable]$Severity = @{}, [object[]]$Waiver = @(), [string]$Wheelhouse)
                if (-not $Wheelhouse) { $Wheelhouse = Get-TestWheelhouse }
                Update-WheelhouseCatalog -WheelhousePath $Wheelhouse -DenylistPath (Join-Path $Wheelhouse 'deny.json')
                $catalog = Read-WheelhouseCatalog -WheelhousePath $Wheelhouse
                Write-TestFindingAudit -Catalog $catalog -Id $Id -Severity $Severity -Waiver $Waiver
                return $catalog
            }
            function Write-TestFindingAudit {
                param($Catalog, [string[]]$Id, [hashtable]$Severity = @{}, [object[]]$Waiver = @())
                $vulns = @($Id | ForEach-Object { @{ id = $_; aliases = @("CVE-$_"); fix_versions = @('99.0'); description = "Problem $_" } })
                $report = Join-Path (Get-TestFolder) 'report.json'
                ConvertTo-Json -Depth 6 -InputObject @{ dependencies = @(@{ name = 'attrs'; version = '23.1.0'; vulns = $vulns }, @{ name = 'six'; version = '1.16.0'; vulns = @() }) } | Set-Content -Path $report
                $status = if ($Id.Count -gt 0) { 'Vulnerable' } else { 'Passed' }
                $results = @('osv', 'pypi' | ForEach-Object { [PSCustomObject]@{ Service = $_; Status = $status; ReportPath = $report; GroupFile = 'x' } })
                Update-CatalogAuditResult -Catalog $Catalog -AuditResult $results -Severity $Severity -Waiver $Waiver
            }
            function Get-TestAlert {
                param($Catalog, [datetime]$NowUtc = (Get-Date).ToUniversalTime())
                @(Get-CatalogFindingAlert -Catalog $Catalog -ReminderDays 7 -NowUtc $NowUtc)
            }
        }

        BeforeEach {
            $global:WhmOsvCalls = [System.Collections.Generic.List[string]]::new()
            $global:WhmOsvRecords = @{}
            $global:WhmOsvOffline = $false
            Mock -ModuleName WheelhouseManager -CommandName Get-OsvVulnerability -MockWith {
                $global:WhmOsvCalls.Add($Id)
                if ($global:WhmOsvOffline) { throw 'The remote name could not be resolved: api.osv.dev' }
                if ($global:WhmOsvRecords.ContainsKey($Id)) { return $global:WhmOsvRecords[$Id] }
                $exception = [System.Exception]::new('Not Found')
                $exception | Add-Member -NotePropertyName Response -NotePropertyValue ([PSCustomObject]@{ StatusCode = 404 })
                throw $exception
            }
        }

        It 'scores CVSS 3 vectors and maps scores to severities' {
            ConvertTo-CvssV3BaseScore -Vector 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' | Should -Be 9.8
            ConvertTo-CvssV3BaseScore -Vector 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N' | Should -Be 6.4
            ConvertTo-CvssV3BaseScore -Vector 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H' | Should -Be 9.6
            ConvertTo-CvssV3BaseScore -Vector 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N' | Should -Be 1.8
            ConvertTo-CvssV3BaseScore -Vector 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N' | Should -Be 0
            ConvertTo-CvssV3BaseScore -Vector 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' | Should -BeNullOrEmpty
            ConvertTo-CvssV3BaseScore -Vector 'CVSS:3.1/AV:N/AC:L' | Should -BeNullOrEmpty
            ConvertTo-SeverityFromScore -Score 9.0 | Should -Be 'Critical'
            ConvertTo-SeverityFromScore -Score 7.5 | Should -Be 'High'
            ConvertTo-SeverityFromScore -Score 4.0 | Should -Be 'Medium'
            ConvertTo-SeverityFromScore -Score 3.9 | Should -Be 'Low'
            (Get-SeverityRank -Severity 'Unknown') | Should -Be (Get-SeverityRank -Severity 'High')
        }

        It 'reads a severity from an OSV record' {
            (Get-OsvRecordSeverity -Record ([PSCustomObject]@{ id = 'MAL-2024-1' })).Severity | Should -Be 'Critical'
            $cvss = Get-OsvRecordSeverity -Record ([PSCustomObject]@{ id = 'GHSA-a'; severity = @([PSCustomObject]@{ type = 'CVSS_V3'; score = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }) })
            $cvss.Severity | Should -Be 'Critical'
            $cvss.Score | Should -Be 9.8
            (Get-OsvRecordSeverity -Record ([PSCustomObject]@{ id = 'GHSA-b'; database_specific = [PSCustomObject]@{ severity = 'MODERATE' } })).Severity | Should -Be 'Medium'
            (Get-OsvRecordSeverity -Record ([PSCustomObject]@{ id = 'GHSA-c'; affected = @([PSCustomObject]@{ ecosystem_specific = [PSCustomObject]@{ severity = 'LOW' } }) })).Severity | Should -Be 'Low'
            Get-OsvRecordSeverity -Record ([PSCustomObject]@{ id = 'PYSEC-1' }) | Should -BeNullOrEmpty
        }

        It 'follows aliases, caches answers and survives OSV being unreachable' {
            $cache = Join-Path (Get-TestFolder) 'osv-cache.json'
            $global:WhmOsvRecords['PYSEC-1'] = [PSCustomObject]@{ id = 'PYSEC-1'; aliases = @('GHSA-x') }
            $global:WhmOsvRecords['GHSA-x'] = [PSCustomObject]@{ id = 'GHSA-x'; database_specific = [PSCustomObject]@{ severity = 'HIGH' } }
            $result = Get-VulnerabilitySeverity -Advisory @{ 'PYSEC-1' = @(); 'GHSA-gone' = @(); 'MAL-2024-9' = @() } -CachePath $cache
            $result['PYSEC-1'].Severity | Should -Be 'High'
            $result['PYSEC-1'].Source | Should -Match 'GHSA-x'
            $result['GHSA-gone'].Severity | Should -Be 'Unknown'
            $result['GHSA-gone'].Error | Should -BeNullOrEmpty
            $result['MAL-2024-9'].Severity | Should -Be 'Critical'
            $global:WhmOsvCalls -contains 'MAL-2024-9' | Should -Be $false

            # Cached: no second lookup.
            $global:WhmOsvCalls.Clear()
            (Get-VulnerabilitySeverity -Advisory @{ 'PYSEC-1' = @() } -CachePath $cache)['PYSEC-1'].Severity | Should -Be 'High'
            $global:WhmOsvCalls.Count | Should -Be 0

            # Offline: an expired cached answer is still used; an unknown ID is Unknown with
            # an error, and only one lookup is tried.
            $global:WhmOsvOffline = $true
            $offline = Get-VulnerabilitySeverity -Advisory @{ 'PYSEC-1' = @(); 'GHSA-new1' = @(); 'GHSA-new2' = @() } -CachePath $cache -MaxAgeDays 0
            $offline['PYSEC-1'].Severity | Should -Be 'High'
            $offline['GHSA-new1'].Severity | Should -Be 'Unknown'
            $offline['GHSA-new1'].Error | Should -Match 'OSV lookup failed'
            $offline['GHSA-new2'].Error | Should -Match 'OSV lookup failed'
            $global:WhmOsvCalls.Count | Should -Be 1

            # A damaged cache is rebuilt, not fatal.
            Set-Content -Path $cache -Value '{ broken'
            $global:WhmOsvOffline = $false
            (Get-VulnerabilitySeverity -Advisory @{ 'PYSEC-1' = @() } -CachePath $cache)['PYSEC-1'].Severity | Should -Be 'High'
        }

        It 'tracks a finding from new to overdue, waived, expired and resolved' {
            $due = @{ Critical = 3; High = 7; Medium = 30; Low = 90; Unknown = 7 }
            $severity = @{ 'GHSA-1' = [PSCustomObject]@{ Severity = 'High'; Score = 7.5; Source = 'test'; Error = '' } }
            $catalog = New-TestFindingCatalog -Id @() -Severity $severity
            @(Get-TestAlert -Catalog $catalog).Count | Should -Be 0

            # New CVE: a finding with a due date, alerted once.
            Write-TestFindingAudit -Catalog $catalog -Id @('GHSA-1') -Severity $severity
            $finding = $catalog.Records['attrs==23.1.0'].findings[0]
            $finding.severity | Should -Be 'High'
            $finding.aliases -join ',' | Should -Be 'CVE-GHSA-1'
            $finding.fix_versions -join ',' | Should -Be '99.0'
            ((ConvertTo-UtcDateTime $finding.due) - (ConvertTo-UtcDateTime $finding.first_seen)).TotalDays | Should -Be $due.High
            $alerts = @(Get-TestAlert -Catalog $catalog)
            $alerts.Count | Should -Be 1
            $alerts[0].AlertReason | Should -Be 'New'
            $alerts[0].Status | Should -Be 'Open'
            $alerts[0].GroupFiles -join ',' | Should -Be 'requirements-1.txt'
            Set-CatalogFindingNotified -Catalog $catalog -Finding $alerts
            (Get-TestAlert -Catalog $catalog)[0].AlertReason | Should -BeNullOrEmpty
            # The next audit keeps first_seen.
            $firstSeen = $finding.first_seen
            Write-TestFindingAudit -Catalog $catalog -Id @('GHSA-1') -Severity $severity
            $catalog.Records['attrs==23.1.0'].findings[0].first_seen | Should -Be $firstSeen

            # Breach: alerted as overdue, then reminded after a week, not before.
            $late = (ConvertTo-UtcDateTime $finding.due).AddDays(1)
            $alerts = @(Get-TestAlert -Catalog $catalog -NowUtc $late)
            $alerts[0].AlertReason | Should -Be 'Overdue'
            Set-CatalogFindingNotified -Catalog $catalog -Finding $alerts -NowUtc $late
            (Get-TestAlert -Catalog $catalog -NowUtc $late)[0].AlertReason | Should -BeNullOrEmpty
            $catalog.Records['attrs==23.1.0'].findings[0].notified_utc = $late.AddDays(-8).ToString('o')
            (Get-TestAlert -Catalog $catalog -NowUtc $late)[0].AlertReason | Should -Be 'Reminder'

            # A waiver silences it; once it expires the finding is alerted again.
            $waiverPath = Join-Path (Get-TestFolder) 'waivers.json'
            [void](Add-WheelhouseWaiver -Name 'Attrs' -Version '23.1.0' -Id 'GHSA-1' -Reason 'not reachable in our use' -Days 30 -Path $waiverPath)
            Set-CatalogFindingWaiver -Catalog $catalog -Waiver @(Read-WheelhouseWaiver -Path $waiverPath)
            $alerts = @(Get-TestAlert -Catalog $catalog)
            $alerts[0].Status | Should -Be 'Waived'
            $alerts[0].AlertReason | Should -BeNullOrEmpty
            Set-CatalogFindingNotified -Catalog $catalog -Finding $alerts
            $catalog.Records['attrs==23.1.0'].findings[0].notified | Should -Be 'Waived'
            $expired = @(Read-WheelhouseWaiver -Path $waiverPath | ForEach-Object { $_.expires_utc = (Get-Date).ToUniversalTime().AddDays(-1).ToString('o'); $_ })
            Set-CatalogFindingWaiver -Catalog $catalog -Waiver $expired
            $catalog.Records['attrs==23.1.0'].findings[0].waiver | Should -BeNullOrEmpty
            (Get-TestAlert -Catalog $catalog)[0].AlertReason | Should -Be 'WaiverExpired'
            (Get-TestAlert -Catalog $catalog -NowUtc $late)[0].AlertReason | Should -Be 'Overdue'
            $events = @(Read-WheelhouseEvent -WheelhousePath $catalog.WheelhousePath -Package 'attrs' | ForEach-Object { $_.action })
            $events | Should -Contain 'FindingNew'
            $events | Should -Contain 'Waived'
            $events | Should -Contain 'WaiverEnded'

            # Resolved: alerted once, then dropped.
            Set-CatalogFindingNotified -Catalog $catalog -Finding (Get-TestAlert -Catalog $catalog)
            Write-TestFindingAudit -Catalog $catalog -Id @() -Severity $severity
            $alerts = @(Get-TestAlert -Catalog $catalog)
            $alerts[0].AlertReason | Should -Be 'Resolved'
            Set-CatalogFindingNotified -Catalog $catalog -Finding $alerts
            @($catalog.Records['attrs==23.1.0'].findings).Count | Should -Be 0
            @(Read-WheelhouseEvent -WheelhousePath $catalog.WheelhousePath -Package 'attrs' | ForEach-Object { $_.action }) | Should -Contain 'FindingResolved'
        }

        It 'keeps a known severity when a lookup fails, and survives a save' {
            $catalog = New-TestFindingCatalog -Id @('GHSA-2') -Severity @{ 'GHSA-2' = [PSCustomObject]@{ Severity = 'Critical'; Score = 9.8; Source = 'test'; Error = '' } }
            Write-TestFindingAudit -Catalog $catalog -Id @('GHSA-2') -Severity @{ 'GHSA-2' = [PSCustomObject]@{ Severity = 'Unknown'; Score = $null; Source = ''; Error = 'offline' } }
            $catalog.Records['attrs==23.1.0'].findings[0].severity | Should -Be 'Critical'
            Save-WheelhouseCatalog -Catalog $catalog
            $again = Read-WheelhouseCatalog -WheelhousePath $catalog.WheelhousePath
            $finding = $again.Records['attrs==23.1.0'].findings[0]
            $finding.severity | Should -Be 'Critical'
            $finding.score | Should -Be 9.8
            $finding.due | Should -Match '^\d{4}-\d\d-\d\dT'
            # A re-rated advisory moves the due date and is recorded.
            Write-TestFindingAudit -Catalog $again -Id @('GHSA-2') -Severity @{ 'GHSA-2' = [PSCustomObject]@{ Severity = 'Low'; Score = 2.0; Source = 'test'; Error = '' } }
            $low = $again.Records['attrs==23.1.0'].findings[0]
            ((ConvertTo-UtcDateTime $low.due) - (ConvertTo-UtcDateTime $low.first_seen)).TotalDays | Should -Be 90
            @(Read-WheelhouseEvent -WheelhousePath $again.WheelhousePath -Package 'attrs' | ForEach-Object { $_.action }) | Should -Contain 'SeverityChanged'
        }

        It 'validates waivers and only matches unexpired, exact ones' {
            $path = Join-Path (Get-TestFolder) 'waivers.json'
            { Add-WheelhouseWaiver -Name 'six' -Version '1.16.0' -Id 'GHSA-1' -Reason '' -Days 10 -Path $path } | Should -Throw '*reason*'
            { Add-WheelhouseWaiver -Name 'six' -Version '*' -Id 'GHSA-1' -Reason 'x' -Days 10 -Path $path } | Should -Throw '*exact version*'
            { Add-WheelhouseWaiver -Name 'six' -Version '1.16.0' -Id 'all' -Reason 'x' -Days 10 -Path $path } | Should -Throw '*advisory ID*'
            { Add-WheelhouseWaiver -Name 'six' -Version '1.16.0' -Id 'GHSA-1' -Reason 'x' -Days 91 -MaxDays 90 -Path $path } | Should -Throw '*at most 90*'
            $entry = Add-WheelhouseWaiver -Name 'Six' -Version '1.16.0' -Id 'GHSA-1' -Reason 'ok' -Days 10 -Path $path
            $entry.name | Should -Be 'six'
            [void](Add-WheelhouseWaiver -Name 'six' -Version '1.16.0' -Id 'GHSA-1' -Reason 'renewed' -Days 20 -Path $path)
            $all = @(Read-WheelhouseWaiver -Path $path)
            $all.Count | Should -Be 1
            $all[0].reason | Should -Be 'renewed'
            (Get-WaiverMatch -Name 'six' -Version '1.16.0' -Id 'GHSA-1' -Waiver $all).reason | Should -Be 'renewed'
            Get-WaiverMatch -Name 'six' -Version '1.17.0' -Id 'GHSA-1' -Waiver $all | Should -BeNullOrEmpty
            Get-WaiverMatch -Name 'six' -Version '1.16.0' -Id 'GHSA-1' -Waiver $all -NowUtc (Get-Date).ToUniversalTime().AddDays(30) | Should -BeNullOrEmpty
            Remove-WheelhouseWaiver -Name 'six' -Version '1.16.0' -Id 'GHSA-1' -Path $path | Should -Be $true
            Remove-WheelhouseWaiver -Name 'six' -Version '1.16.0' -Id 'GHSA-1' -Path $path | Should -Be $false
            Set-Content -Path $path -Value '[ broken'
            { Read-WheelhouseWaiver -Path $path } | Should -Throw '*could not be parsed*'
        }

        It 'quarantines a published version with a malicious-package advisory only under AutoQuarantine' {
            $wheelhouse = Get-TestWheelhouse
            $deny = Join-Path (Get-TestFolder) 'deny.json'
            $catalog = New-TestFindingCatalog -Wheelhouse $wheelhouse -Id @('MAL-2026-7')
            Save-WheelhouseCatalog -Catalog $catalog
            $catalog.Records['attrs==23.1.0'].findings[0].severity | Should -Be 'Unknown'

            $report = @(Resolve-MaliciousPackage -WheelhousePath $wheelhouse -DenylistPath $deny)
            $report.Count | Should -Be 1
            $report[0].Kind | Should -Be 'Malicious'
            (Read-WheelhouseCatalog -WheelhousePath $wheelhouse).Records['attrs==23.1.0'].state | Should -Be 'Published'

            $lock = Open-WheelhouseWrite -WheelhousePath $wheelhouse -DenylistPath $deny
            try { $done = @(Resolve-MaliciousPackage -WheelhousePath $wheelhouse -AutoQuarantine -DenylistPath $deny) } finally { Exit-WheelhouseLock -Lock $lock }
            $done[0].Message | Should -Match 'quarantined'
            (Read-WheelhouseCatalog -WheelhousePath $wheelhouse).Records['attrs==23.1.0'].state | Should -Be 'Quarantined'
            (Get-DenylistMatch -Name 'attrs' -Version '23.1.0' -Denylist @(Read-WheelhouseDenylist -Path $deny)) | Should -Not -BeNullOrEmpty
            Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt') | Should -Not -Contain 'attrs==23.1.0'
            @(Resolve-MaliciousPackage -WheelhousePath $wheelhouse -AutoQuarantine -DenylistPath $deny).Count | Should -Be 0
        }

        It 'moves wheels nobody published out of the index only under AutoQuarantine' {
            $wheelhouse = Get-TestWheelhouse
            Set-Content -Path (Join-Path $wheelhouse 'stray-1.0-py3-none-any.whl') -Value 'unchecked'
            $report = @(Move-UntrackedWheelFile -WheelhousePath $wheelhouse)
            $report.Count | Should -Be 1
            $report[0].Kind | Should -Be 'Untracked'
            $report[0].Files -join ',' | Should -Be 'stray-1.0-py3-none-any.whl'
            Test-Path (Join-Path $wheelhouse 'stray-1.0-py3-none-any.whl') | Should -Be $true

            $moved = @(Move-UntrackedWheelFile -WheelhousePath $wheelhouse -AutoQuarantine)
            $moved[0].Message | Should -Match '_untracked'
            Test-Path (Join-Path $wheelhouse 'stray-1.0-py3-none-any.whl') | Should -Be $false
            @(Get-ChildItem -Path (Join-Path $wheelhouse '_untracked') -Recurse -Filter '*.whl').Count | Should -Be 1
            (Read-WheelhouseEvent -WheelhousePath $wheelhouse)[0].action | Should -Be 'UntrackedMoved'
            @(Move-UntrackedWheelFile -WheelhousePath $wheelhouse -AutoQuarantine).Count | Should -Be 0

            # First-time setup (empty manifest) adopts wheels instead.
            $fresh = Get-TestFolder
            Set-Content -Path (Join-Path $fresh 'old-1.0-py3-none-any.whl') -Value 'old'
            @(Move-UntrackedWheelFile -WheelhousePath $fresh -AutoQuarantine).Count | Should -Be 0
            Test-Path (Join-Path $fresh 'old-1.0-py3-none-any.whl') | Should -Be $true
        }

        It 'lists published versions without a recent completed audit as unverified' {
            $catalog = New-TestFindingCatalog -Id @()
            @(Get-CatalogUnverifiedRecord -Catalog $catalog -FreshnessDays 8).Count | Should -Be 0
            $catalog.Records['six==1.16.0'].checks.audit.last_run = (Get-Date).ToUniversalTime().AddDays(-9).ToString('o')
            $stale = @(Get-CatalogUnverifiedRecord -Catalog $catalog -FreshnessDays 8)
            $stale.Count | Should -Be 1
            $stale[0].name | Should -Be 'six'
            # Never audited, published long ago.
            $catalog.Records['attrs==23.1.0'].checks.audit = $null
            $catalog.Records['attrs==23.1.0'].published_utc = (Get-Date).ToUniversalTime().AddDays(-30).ToString('o')
            @(Get-CatalogUnverifiedRecord -Catalog $catalog -FreshnessDays 8).Count | Should -Be 2
        }

        It 'alerts tracked findings only when there is something new to say' {
            $catalog = New-TestFindingCatalog -Id @('GHSA-3') -Severity @{ 'GHSA-3' = [PSCustomObject]@{ Severity = 'Medium'; Score = 5.0; Source = 'test'; Error = '' } }
            $vulnerable = @([PSCustomObject]@{ Status = 'Vulnerable'; ReportPath = 'r.json'; Group = 'requirements-1'; Service = 'osv' })
            $alerts = @(Get-TestAlert -Catalog $catalog)
            $params = Get-VulnerabilityAlertParameter -AuditResult $vulnerable -Finding $alerts
            $params.Findings.Count | Should -Be 1
            $params.ContainsKey('ReportPaths') | Should -Be $false
            Set-CatalogFindingNotified -Catalog $catalog -Finding $alerts
            Get-VulnerabilityAlertParameter -AuditResult $vulnerable -Finding (Get-TestAlert -Catalog $catalog) | Should -BeNullOrEmpty
            # Without tracked findings the reports are alerted as before.
            (Get-VulnerabilityAlertParameter -AuditResult $vulnerable).ReportPaths | Should -Be 'r.json'
            # Candidates blocked before publishing are always reported.
            $candidate = @([PSCustomObject]@{ Status = 'Vulnerable'; Stage = 'PreDownload'; ReportPath = 'c.json'; Group = 'requirements-1'; Service = 'osv' })
            (Get-VulnerabilityAlertParameter -AuditResult (@($vulnerable) + $candidate) -Finding (Get-TestAlert -Catalog $catalog)).ReportPaths | Should -Be 'c.json'

            $html = ConvertTo-VulnerabilityAlertHtml -Findings @($alerts) -WheelhousePath $catalog.WheelhousePath
            $html | Should -Match '<th>Severity</th>'
            $html | Should -Match 'Medium \(5\)'
            $html | Should -Match '>NEW<'
            $resolved = $alerts[0].PSObject.Copy()
            $resolved.AlertReason = 'Resolved'
            ConvertTo-VulnerabilityAlertHtml -Findings @($resolved) | Should -Match 'Resolved since the last alert'
        }

        It 'records the due days from the settings' {
            $days = Get-WheelhouseDueDayTable -Settings @{ DueDaysCritical = 1; DueDaysHigh = '' }
            $days.Critical | Should -Be 1
            $days.High | Should -Be 7
            $days.Unknown | Should -Be 7
            $days.Low | Should -Be 90
        }
    }

    Context 'Proposals and approval' {
        BeforeEach {
            $script:proposalFile = Join-Path (Get-TestFolder) 'proposal.json'
            $script:resolved = Join-Path (Get-TestFolder) 'requirements.txt'
            Set-Content -Path $script:resolved -Value @('six==1.16.0', 'attrs==24.0')
        }

        It 'orders versions like PEP 440' {
            Compare-PackageVersion -Left '2.32.4' -Right '2.32.3' | Should -Be 1
            Compare-PackageVersion -Left '2.0' -Right '10.0' | Should -Be -1
            Compare-PackageVersion -Left '1.0' -Right '1.0.0' | Should -Be 0
            Compare-PackageVersion -Left '1.0rc1' -Right '1.0' | Should -Be -1
            Compare-PackageVersion -Left '1.0.dev1' -Right '1.0a1' | Should -Be -1
            Compare-PackageVersion -Left '1.0.post1' -Right '1.0' | Should -Be 1
            Compare-PackageVersion -Left '1!1.0' -Right '9.0' | Should -Be 1
            { Compare-PackageVersion -Left 'abc' -Right '1.0' } | Should -Throw '*Not a version*'
        }

        It 'records who proposed and who approved, and keeps a history' {
            $proposal = New-WheelhouseProposal -RequirementsPath $script:resolved -RequestedBy 'CONTOSO\alice' -Path $script:proposalFile
            $proposal.state | Should -Be 'Proposed'
            $proposal.pins -join ',' | Should -Be 'attrs==24.0,six==1.16.0'
            $approved = Approve-WheelhouseProposal -Id $proposal.id -By 'CONTOSO\alice' -Path $script:proposalFile
            $approved.state | Should -Be 'Approved'
            $approved.approved_by | Should -Be 'CONTOSO\alice'
            { Approve-WheelhouseProposal -Id $proposal.id -By 'CONTOSO\bob' -Path $script:proposalFile } | Should -Throw '*already Approved*'
            $history = @(Get-Content -Path (Join-Path (Split-Path $script:proposalFile) 'proposal-history.jsonl') | ForEach-Object { ($_ | ConvertFrom-Json).action })
            $history -join ',' | Should -Be 'Proposed,Approved'
        }

        It 'needs another person under SeparateApprover, and refuses a file changed since' {
            $proposal = New-WheelhouseProposal -RequirementsPath $script:resolved -RequestedBy 'CONTOSO\alice' -Path $script:proposalFile
            { Approve-WheelhouseProposal -Id $proposal.id -By 'contoso\ALICE' -Mode SeparateApprover -Path $script:proposalFile } | Should -Throw '*another person*'
            Add-Content -Path $script:resolved -Value 'newpkg==1.0'
            { Approve-WheelhouseProposal -Id $proposal.id -By 'CONTOSO\bob' -Mode SeparateApprover -Path $script:proposalFile } | Should -Throw '*changed after proposal*'

            $proposal = New-WheelhouseProposal -RequirementsPath $script:resolved -RequestedBy 'CONTOSO\alice' -Path $script:proposalFile
            (Approve-WheelhouseProposal -Id $proposal.id -By 'CONTOSO\bob' -Mode SeparateApprover -Path $script:proposalFile).approved_by | Should -Be 'CONTOSO\bob'
            { Deny-WheelhouseProposal -Id $proposal.id -Reason '' -Path $script:proposalFile } | Should -Throw '*reason*'
            (Deny-WheelhouseProposal -Id $proposal.id -Reason 'not needed' -By 'CONTOSO\carol' -Path $script:proposalFile).state | Should -Be 'Rejected'
        }

        It 'gates publishing by the approval mode' {
            # No proposal: SamePersonAllowed proposes and approves it as the publisher.
            $gate = Resolve-WheelhouseProposalForPublish -RequirementsPath $script:resolved -User 'CONTOSO\alice' -Path $script:proposalFile
            $gate.Allowed | Should -Be $true
            $gate.Proposal.kind | Should -Be 'manual'
            $gate.Proposal.approved_by | Should -Be 'CONTOSO\alice'

            # SeparateApprover: the requester cannot publish (= approve) it; someone else can.
            $proposal = New-WheelhouseProposal -RequirementsPath $script:resolved -RequestedBy 'CONTOSO\alice' -Path $script:proposalFile
            $gate = Resolve-WheelhouseProposalForPublish -RequirementsPath $script:resolved -Mode SeparateApprover -User 'CONTOSO\alice' -Path $script:proposalFile
            $gate.Allowed | Should -Be $false
            $gate.Reason | Should -Match 'waiting for approval'
            $gate = Resolve-WheelhouseProposalForPublish -RequirementsPath $script:resolved -Mode SeparateApprover -User 'CONTOSO\bob' -Path $script:proposalFile
            $gate.Allowed | Should -Be $true
            $gate.Proposal.approved_by | Should -Be 'CONTOSO\bob'

            # A hand-edited file under SeparateApprover, and a rejected proposal, are refused.
            Add-Content -Path $script:resolved -Value 'newpkg==1.0'
            (Resolve-WheelhouseProposalForPublish -RequirementsPath $script:resolved -Mode SeparateApprover -User 'CONTOSO\bob' -Path $script:proposalFile).Reason | Should -Match 'changed after proposal'
            $proposal = New-WheelhouseProposal -RequirementsPath $script:resolved -RequestedBy 'CONTOSO\alice' -Path $script:proposalFile
            [void](Deny-WheelhouseProposal -Id $proposal.id -Reason 'too big' -Path $script:proposalFile)
            (Resolve-WheelhouseProposalForPublish -RequirementsPath $script:resolved -User 'CONTOSO\alice' -Path $script:proposalFile).Reason | Should -Match 'rejected'
        }

        It 'plans a fix: the lowest version that fixes every advisory, kept upper bounds, expedite when too new' {
            $wheelhouse = Get-TestWheelhouse
            Update-WheelhouseCatalog -WheelhousePath $wheelhouse -DenylistPath (Join-Path $wheelhouse 'deny.json') -Update {
                param($catalog)
                $report = Join-Path $wheelhouse 'report.json'
                Set-Content -Path $report -Value '{"dependencies":[{"name":"attrs","version":"23.1.0","vulns":[{"id":"GHSA-a","fix_versions":["23.2.0"]},{"id":"GHSA-b","fix_versions":["22.0","24.1.0"]},{"id":"GHSA-c","fix_versions":[]}]}]}'
                Update-CatalogAuditResult -Catalog $catalog -AuditResult @('osv', 'pypi' | ForEach-Object { [PSCustomObject]@{ Service = $_; Status = 'Vulnerable'; ReportPath = $report; GroupFile = 'x' } })
            }
            $in = Join-Path $wheelhouse 'requirements.in'
            Set-Content -Path $in -Value @('six', 'attrs[tests]>=20,<30,!=25.0')
            Mock -ModuleName WheelhouseManager -CommandName Get-PyPIProjectRelease -MockWith {
                foreach ($item in @(@('23.2.0', 200), @('24.1.0', 100), @('24.2.0', 50), @('25.0', 20), @('26.0rc1', 5))) {
                    [PSCustomObject]@{ Version = $item[0]; FirstUploadUtc = (Get-Date).ToUniversalTime().AddDays(-$item[1]); Yanked = $false }
                }
            }
            $plan = Get-WheelhouseRemediationPlan -WheelhousePath $wheelhouse -Name 'attrs' -Version '23.1.0' -RequirementsInPath $in -MinimumAgeDays 10
            $plan.FixVersion | Should -Be '24.1.0'
            $plan.Unfixable -join ',' | Should -Be 'GHSA-c'
            $plan.NeedsExpedite | Should -Be $false
            $plan.NewLine | Should -Be 'attrs[tests]>=24.1.0,<30,!=25.0'
            $plan.Eligible -join ',' | Should -Be '24.1.0,24.2.0,25.0'

            # Nothing fixed is old enough: pin the lowest fixed release, to be expedited.
            $tooNew = Get-WheelhouseRemediationPlan -WheelhousePath $wheelhouse -Name 'attrs' -Version '23.1.0' -RequirementsInPath $in -MinimumAgeDays 365
            $tooNew.NeedsExpedite | Should -Be $true
            $tooNew.NewLine | Should -Be 'attrs[tests]==24.1.0,<30,!=25.0'

            Set-RequirementInSpec -Path $in -Name 'attrs' -Line $plan.NewLine
            Set-RequirementInSpec -Path $in -Name 'urllib3' -Line 'urllib3>=2.5' -Comment 'added by remediation'
            (Get-Content -Path $in) -join '|' | Should -Be 'six|attrs[tests]>=24.1.0,<30,!=25.0|# added by remediation|urllib3>=2.5'
            { Get-WheelhouseRemediationPlan -WheelhousePath $wheelhouse -Name 'six' -Version '1.16.0' -RequirementsInPath $in } | Should -Throw '*no open vulnerability*'
        }

        It 'swaps a pin in place when finishing a journal, from an object read back' {
            $wheelhouse = Get-TestWheelhouse
            $group = Join-Path $wheelhouse 'requirements-1.txt'
            $data = '{"group_file":"' + ($group -replace '\\', '\\') + '","entries":[],"additions":[{"name":"attrs","version":"24.0","replaces":"23.1.0"},{"name":"newpkg","version":"1.0"}]}' | ConvertFrom-Json
            # No wheels arrived: nothing is listed.
            Complete-WheelhousePublishJournal -WheelhousePath $wheelhouse -Data $data
            (Get-Content -Path $group) -join ',' | Should -Be 'six==1.16.0,attrs==23.1.0'
            Set-RequirementInGroupFile -GroupFile $group -Name 'Attrs' -Version '24.0'
            (Get-Content -Path $group) -join ',' | Should -Be 'six==1.16.0,attrs==24.0'
        }
    }

    Context 'Status, doctor, advisories and whm' {
        BeforeAll {
            function New-TestVulnerableWheelhouse {
                $wheelhouse = Get-TestWheelhouse
                Update-WheelhouseCatalog -WheelhousePath $wheelhouse -DenylistPath (Join-Path $wheelhouse 'deny.json') -Update {
                    param($catalog)
                    $report = Join-Path $wheelhouse 'report.json'
                    Set-Content -Path $report -Value '{"dependencies":[{"name":"attrs","version":"23.1.0","vulns":[{"id":"GHSA-s","fix_versions":["24.0"]}]},{"name":"six","version":"1.16.0","vulns":[]}]}'
                    Update-CatalogAuditResult -Catalog $catalog -AuditResult @('osv', 'pypi' | ForEach-Object { [PSCustomObject]@{ Service = $_; Status = 'Vulnerable'; ReportPath = $report; GroupFile = 'x' } }) -Severity @{ 'GHSA-s' = [PSCustomObject]@{ Severity = 'High'; Score = 8.0; Source = 't'; Error = '' } }
                }
                return $wheelhouse
            }
        }

        It 'tells when the audits of published versions are too old, and starts one audit at a time' {
            $wheelhouse = New-TestVulnerableWheelhouse
            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $now = (Get-Date).ToUniversalTime()
            $age = Get-WheelhouseAuditAge -Catalog $catalog -MaxAgeDays 7 -NowUtc $now
            $age.Stale | Should -Be $false
            $age.Published | Should -Be 2
            (Get-WheelhouseAuditAge -Catalog $catalog -MaxAgeDays 7 -NowUtc $now.AddDays(8)).Stale | Should -Be $true
            (Get-WheelhouseAuditAge -Catalog $catalog -MaxAgeDays 7 -NowUtc $now.AddDays(8)).Message | Should -Match 'more than 7 day'
            $catalog.Records['six==1.16.0'].checks.audit = $null
            $never = Get-WheelhouseAuditAge -Catalog $catalog -MaxAgeDays 7 -NowUtc $now
            $never.Stale | Should -Be $true
            $never.Never | Should -Be 1
            (Get-WheelhouseStatus -WheelhousePath $wheelhouse -AuditMaxAgeDays 7 -ProposalPath (Join-Path (Get-TestFolder) 'none.json')).AuditStale | Should -Be $false

            # The weekly check now: without a registered task, Test-Wheelhouse.ps1 as one
            # background process at a time, remembered in state\.
            Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseScheduledCheck -MockWith { [PSCustomObject]@{ Registered = $false } }
            $root = Get-TestFolder
            New-Item -ItemType Directory -Path (Join-Path $root 'Jobs') | Out-Null
            Set-Content -Path (Join-Path (Join-Path $root 'Jobs') 'Test-Wheelhouse.ps1') -Value 'Start-Sleep -Seconds 20'
            $first = Start-WheelhouseBackgroundAudit -WheelhousePath $wheelhouse -ManagerRoot $root
            try {
                $first.Started | Should -Be $true
                $first.Via | Should -Be 'Process'
                $second = Start-WheelhouseBackgroundAudit -WheelhousePath $wheelhouse -ManagerRoot $root
                $second.Started | Should -Be $false
                $second.Message | Should -Match 'already running'
                (Get-Content -Path (Join-Path (Join-Path $root 'state') 'background-audit.json') -Raw | ConvertFrom-Json).pid | Should -Be $first.ProcessId
            }
            finally { Stop-Process -Id $first.ProcessId -Force -ErrorAction SilentlyContinue }

            # With the task registered for this installation, the task itself is started.
            $global:WhmTaskStarted = 0
            Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseScheduledCheck -MockWith { [PSCustomObject]@{ Registered = $true; ForThisInstallation = $true; State = 'Ready'; User = 'CONTOSO\svc' } }
            Mock -ModuleName WheelhouseManager -CommandName Start-WheelhouseScheduledCheck -MockWith { $global:WhmTaskStarted++ }
            $viaTask = Start-WheelhouseBackgroundAudit -WheelhousePath $wheelhouse -ManagerRoot (Get-TestFolder)
            $viaTask.Started | Should -Be $true
            $viaTask.Via | Should -Be 'Task'
            $viaTask.Message | Should -Match 'Scheduled Task was started now \(as CONTOSO\\svc\)'
            $global:WhmTaskStarted | Should -Be 1

            # The freshness check starts nothing while the audits are recent.
            $fresh = Invoke-WheelhouseAuditFreshnessCheck -WheelhousePath $wheelhouse -MaxAgeDays 7 -ManagerRoot $root
            $fresh.Stale | Should -Be $false
            $fresh.Started | Should -Be $false
        }

        It 'summarizes what needs attention' {
            $wheelhouse = New-TestVulnerableWheelhouse
            $status = Get-WheelhouseStatus -WheelhousePath $wheelhouse -ProposalPath (Join-Path (Get-TestFolder) 'none.json')
            $status.Published | Should -Be 2
            $status.Open | Should -Be 1
            $status.Overdue | Should -Be 0
            $status.CheckOverdue | Should -Be $true
            @($status.Attention | ForEach-Object { $_.Target }) -join ',' | Should -Be 'schedule,packages:vulnerable'

            Update-WheelhouseCatalog -WheelhousePath $wheelhouse -DenylistPath (Join-Path $wheelhouse 'deny.json') -Update {
                param($catalog)
                $catalog.Records['attrs==23.1.0'].findings[0].due = (Get-Date).ToUniversalTime().AddDays(-1).ToString('o')
                $catalog.ScheduledCheckUtc = (Get-Date).ToUniversalTime().ToString('o')
            }
            $status = Get-WheelhouseStatus -WheelhousePath $wheelhouse -ProposalPath (Join-Path (Get-TestFolder) 'none.json')
            $status.Overdue | Should -Be 1
            $status.Attention[0].Level | Should -Be 'bad'
            $status.Attention[0].Target | Should -Be 'packages:overdue'
        }

        It 'writes advisories.json with what to install instead' {
            $wheelhouse = New-TestVulnerableWheelhouse
            $advisories = Get-Content -Path (Join-Path $wheelhouse 'advisories.json') -Raw | ConvertFrom-Json
            $item = @($advisories.packages)[0]
            "$($item.name)==$($item.version) $($item.status)" | Should -Be 'attrs==23.1.0 vulnerable'
            @($item.advisories)[0].id | Should -Be 'GHSA-s'
            $item.recommended | Should -BeNullOrEmpty
            @($advisories.packages).Count | Should -Be 1

            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $catalog.Records['attrs==24.0'] = New-CatalogRecord -Name 'attrs' -Version '24.0'
            $catalog.Records['six==1.16.0'].state = 'Quarantined'
            Export-WheelhouseAdvisory -Catalog $catalog
            $advisories = Get-Content -Path (Join-Path $wheelhouse 'advisories.json') -Raw | ConvertFrom-Json
            (@($advisories.packages) | Where-Object { $_.name -eq 'attrs' }).recommended | Should -Be '24.0'
            (@($advisories.packages) | Where-Object { $_.name -eq 'six' }).status | Should -Be 'quarantined'
        }

        It 'writes a static index.html for the people who install from the share' {
            $wheelhouse = New-TestVulnerableWheelhouse
            $html = Get-Content -Path (Join-Path $wheelhouse 'index.html') -Raw
            $html | Should -Match 'Do not use \(1\)'
            $html | Should -Match 'attrs==23\.1\.0'
            $html | Should -Match 'GHSA-s'
            $html | Should -Match 'requirements-1\.txt'
            $html | Should -Match 'Packages \(2\)'
            $html | Should -Not -Match '<script'
            # Text from outside is escaped.
            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $catalog.Records['six==1.16.0'].groups = @('<b>x</b>.txt')
            Export-WheelhouseIndexPage -Catalog $catalog -Advisory @()
            Get-Content -Path (Join-Path $wheelhouse 'index.html') -Raw | Should -Match '&lt;b&gt;x&lt;/b&gt;'
        }

        It 'writes Event Log entries only when enabled, and stops after a failure' {
            $global:WhmEventLog = [System.Collections.Generic.List[string]]::new()
            Mock -ModuleName WheelhouseManager -CommandName Write-WheelhouseEventLogEntry -MockWith { $global:WhmEventLog.Add("$Id $Level $Message") }
            & (Get-Module WheelhouseManager) { $script:EventLogState = $false }
            Stop-WheelhouseRun -Title 'Test run' -Outcome 'x' -ExitCode 1 -Confirm:$false
            $global:WhmEventLog.Count | Should -Be 0

            & (Get-Module WheelhouseManager) { $script:EventLogState = $true }
            Stop-WheelhouseRun -Title 'Test run' -Outcome 'findings' -ExitCode 1 -Confirm:$false
            Stop-WheelhouseRun -Title 'Test run' -ExitCode 0 -Confirm:$false
            $wheelhouse = Get-TestWheelhouse
            Set-WheelhouseCatalogState -WheelhousePath $wheelhouse -Change @([PSCustomObject]@{ Name = 'six'; Version = '1.16.0'; State = 'Quarantined'; Action = 'Quarantined'; Detail = 'by test' })
            $global:WhmEventLog[0] | Should -Match '^1001 Warning Test run finished - needs attention'
            $global:WhmEventLog[1] | Should -Match '^1000 Information'
            $global:WhmEventLog[2] | Should -Match '^1004 Information Quarantined: six==1.16.0'

            Mock -ModuleName WheelhouseManager -CommandName Write-WheelhouseEventLogEntry -MockWith { $global:WhmEventLog.Add('tried'); throw 'source missing' }
            Write-WheelhouseEventLog -Id 1002 -Message 'one'
            Write-WheelhouseEventLog -Id 1002 -Message 'two'
            @($global:WhmEventLog | Where-Object { $_ -eq 'tried' }).Count | Should -Be 1
            & (Get-Module WheelhouseManager) { $script:EventLogState = $null }
        }

        It 'checks the installation and says how to fix each problem' {
            $root = Get-TestFolder
            New-Item -ItemType Directory -Path (Join-Path $root 'config') | Out-Null
            $wheelhouse = Get-TestWheelhouse
            Save-WheelhouseSetting -SettingsPath (Join-Path $root 'config\settings.psd1') -Settings @{ WheelhousePath = $wheelhouse }
            Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseToolStatus -MockWith {
                [PSCustomObject]@{ name = 'python'; available = $true; version = '3.14.0'; level = 'ok'; message = '' }
                [PSCustomObject]@{ name = 'uv'; available = $false; version = ''; level = 'bad'; message = 'uv was not found' }
            }
            Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseScheduledCheck -MockWith { [PSCustomObject]@{ Registered = $false; TaskName = 'Wheelhouse Weekly Check'; Script = 'x' } }
            $checks = @(Test-WheelhouseHealth -ManagerRoot $root -Offline)
            $byName = @{}; foreach ($check in $checks) { $byName[$check.Name] = $check }
            $byName['Wheelhouse'].Level | Should -Be 'ok'
            $byName['Tool: uv'].Level | Should -Be 'bad'
            $byName['Data: Catalog'].Level | Should -Be 'ok'
            $byName['Scheduled Task'].Level | Should -Be 'warn'
            $byName['Scheduled Task'].Fix | Should -Match 'Schedule tab'
            $byName['Alerts'].Level | Should -Be 'warn'
            $byName.ContainsKey('Network: PyPI') | Should -Be $false

            Set-Content -Path (Join-Path $wheelhouse 'catalog.json') -Value '{ broken'
            (@(Test-WheelhouseHealth -ManagerRoot $root -Offline) | Where-Object { $_.Name -eq 'Data: Catalog' }).Level | Should -Be 'bad'
            Save-WheelhouseSetting -SettingsPath (Join-Path $root 'config\settings.psd1') -Settings @{ WheelhousePath = (Join-Path $root 'missing') }
            (@(Test-WheelhouseHealth -ManagerRoot $root -Offline) | Where-Object { $_.Name -eq 'Wheelhouse' }).Level | Should -Be 'bad'
        }

        It 'whm answers unknown commands and missing arguments with exit codes' {
            $whm = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'whm.ps1'
            $host_ = (Get-Process -Id $PID).Path
            $output = & $host_ -NoProfile -File $whm bogus 2>&1 | Out-String
            $LASTEXITCODE | Should -Be 2
            $output | Should -Match 'Unknown command'
            $output = & $host_ -NoProfile -File $whm fix 2>&1 | Out-String
            $LASTEXITCODE | Should -Be 2
            $output | Should -Match 'Usage: whm fix'
        }

        It 'the client check lists installed versions the advisories mention' {
            $wheelhouse = New-TestVulnerableWheelhouse
            $installed = Join-Path (Get-TestFolder) 'installed.json'
            Set-Content -Path $installed -Value '[{"name":"Attrs","version":"23.1.0"},{"name":"six","version":"1.16.0"}]'
            $client = Join-Path (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Client Install') 'Test-PythonEnvironment.ps1'
            $host_ = (Get-Process -Id $PID).Path
            $output = & $host_ -NoProfile -File $client -AdvisoriesPath (Join-Path $wheelhouse 'advisories.json') -InstalledJson $installed 2>&1 | Out-String
            $LASTEXITCODE | Should -Be 1
            $output | Should -Match 'Attrs==23.1.0\s+VULNERABLE \(High\)'
            Set-Content -Path $installed -Value '[{"name":"six","version":"1.16.0"}]'
            $output = & $host_ -NoProfile -File $client -AdvisoriesPath (Join-Path $wheelhouse 'advisories.json') -InstalledJson $installed 2>&1 | Out-String
            $LASTEXITCODE | Should -Be 0
            $output | Should -Match 'Nothing installed is affected'
        }
    }

    Context 'Journal' {
        It 'finishes an interrupted publish: manifest and pin only for wheels that arrived intact' {
            $wheelhouse = Get-TestWheelhouse
            $denyPath = Join-Path $wheelhouse 'denylist.json'
            $group = Join-Path $wheelhouse 'requirements-1.txt'
            # newpkg was copied in; brokenpkg's copy never completed.
            Set-Content -Path (Join-Path $wheelhouse 'newpkg-1.0-py3-none-any.whl') -Value 'new wheel'
            Set-Content -Path (Join-Path $wheelhouse 'brokenpkg-1.0-py3-none-any.whl.partial') -Value 'half'
            $entry = { param($n, $hash) [ordered]@{ name = $n; version = '1.0'; file = "$n-1.0-py3-none-any.whl"; sha256 = $hash; python_tag = 'py3'; abi_tag = 'none'; platform_tag = 'any'; downloaded_utc = '2026-01-01T00:00:00Z' } }
            $data = [ordered]@{
                group_file = $group
                entries    = @((& $entry 'newpkg' (Get-FileHash -Path (Join-Path $wheelhouse 'newpkg-1.0-py3-none-any.whl')).Hash), (& $entry 'brokenpkg' 'ABC'))
                additions  = @([ordered]@{ name = 'newpkg'; version = '1.0' }, [ordered]@{ name = 'brokenpkg'; version = '1.0' })
            }
            [void](New-WheelhouseJournal -WheelhousePath $wheelhouse -Operation 'publish' -Data $data)

            $lock = Open-WheelhouseWrite -WheelhousePath $wheelhouse -DenylistPath $denyPath
            Exit-WheelhouseLock -Lock $lock

            @((Read-WheelhouseManifest -WheelhousePath $wheelhouse).name) -join ',' | Should -Be 'six,attrs,newpkg'
            (Get-Content -Path $group) -join ',' | Should -Be 'six==1.16.0,attrs==23.1.0,newpkg==1.0'
            Test-Path -Path (Join-Path $wheelhouse 'brokenpkg-1.0-py3-none-any.whl.partial') | Should -Be $false
            @(Get-ChildItem -Path (Get-WheelhouseJournalFolder -WheelhousePath $wheelhouse) -Filter '*.json').Count | Should -Be 0
            (Read-WheelhouseCatalog -WheelhousePath $wheelhouse).Records['newpkg==1.0'].state | Should -Be 'Published'
            @(Read-WheelhouseEvent -WheelhousePath $wheelhouse | Where-Object { $_.action -eq 'Recovered' }).Count | Should -Be 1
        }

        It 'finishes an interrupted quarantine' {
            $wheelhouse = Get-TestWheelhouse
            $denyPath = Join-Path $wheelhouse 'denylist.json'
            $manifest = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            $folder = Join-Path (Get-WheelhouseQuarantinePath -WheelhousePath $wheelhouse) 'q1'
            $record = [ordered]@{ id = 'q1'; name = 'six'; version = '1.16.0'; files = @($manifest | Where-Object { $_.name -eq 'six' }); groups = @('requirements-1.txt'); reason = 'test' }
            [void](New-WheelhouseJournal -WheelhousePath $wheelhouse -Operation 'remove' -Data ([ordered]@{
                        name = 'six'; version = '1.16.0'; mode = 'Quarantine'; files = @('six-1.16.0-py3-none-any.whl')
                        groups = @((Join-Path $wheelhouse 'requirements-1.txt')); quarantine_folder = $folder; quarantine_record = $record
                        deny = $true; deny_reason = 'test (quarantined)'; deny_source = 'quarantined'
                    }))

            Repair-WheelhouseJournal -WheelhousePath $wheelhouse -DenylistPath $denyPath

            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'attrs==23.1.0'
            @((Read-WheelhouseManifest -WheelhousePath $wheelhouse).name) -join ',' | Should -Be 'attrs'
            Test-Path -Path (Join-Path $folder 'six-1.16.0-py3-none-any.whl') | Should -Be $true
            @(Get-QuarantinedPackage -WheelhousePath $wheelhouse).Count | Should -Be 1
            (Get-DenylistMatch -Name 'six' -Version '1.16.0' -Denylist @(Read-WheelhouseDenylist -Path $denyPath)).source | Should -Be 'quarantined'
            (Read-WheelhouseCatalog -WheelhousePath $wheelhouse).Records['six==1.16.0'].state | Should -Be 'Quarantined'
        }

        It 'stops, and releases the lock, when a journal cannot be read' {
            $wheelhouse = Get-TestFolder
            $folder = Get-WheelhouseJournalFolder -WheelhousePath $wheelhouse
            New-Item -ItemType Directory -Path $folder | Out-Null
            Set-Content -Path (Join-Path $folder '20260101_000000_publish_x.json') -Value '{ broken'
            { Open-WheelhouseWrite -WheelhousePath $wheelhouse -DenylistPath (Join-Path $wheelhouse 'd.json') } | Should -Throw '*could not be read*'
            Test-Path -Path (Join-Path $wheelhouse '.wheelhouse.lock') | Should -Be $false
        }

        It 'leaves no journal behind after a normal remove and restore, and records the history' {
            $wheelhouse = Get-TestWheelhouse
            $denyPath = Join-Path $wheelhouse 'denylist.json'
            $done = Remove-WheelhousePackage -WheelhousePath $wheelhouse -Name 'six' -Version '1.16.0' -Quarantine -Reason 'suspicious' -DenylistPath $denyPath
            (Read-WheelhouseCatalog -WheelhousePath $wheelhouse).Records['six==1.16.0'].state | Should -Be 'Quarantined'
            [void](Restore-WheelhousePackage -WheelhousePath $wheelhouse -Id $done.QuarantineId -DenylistPath $denyPath)
            (Read-WheelhouseCatalog -WheelhousePath $wheelhouse).Records['six==1.16.0'].state | Should -Be 'Published'
            @(Get-ChildItem -Path (Get-WheelhouseJournalFolder -WheelhousePath $wheelhouse) -Filter '*.json').Count | Should -Be 0
            $actions = @(Read-WheelhouseEvent -WheelhousePath $wheelhouse -Package 'six' | ForEach-Object { $_.action })
            $actions -join ',' | Should -Be 'Restored,Quarantined'
            (Read-WheelhouseEvent -WheelhousePath $wheelhouse -Package 'six')[1].detail | Should -Match 'suspicious'
        }
    }

    Context 'Invoke-WheelhouseSync' {
        BeforeEach {
            $global:WhmReleases = @{
                newpkg = (New-TestRelease -Name 'newpkg')
                attrs  = (New-TestRelease -Name 'attrs' -Version '24.0')
            }
            $global:WhmNoWheel = @()
            $global:WhmWheelOverride = @{}
            $global:WhmScanStatus = 'Clean'
            $global:WhmThreatPackage = $null
            Mock -ModuleName WheelhouseManager -CommandName Invoke-GroupAudit -MockWith {
                , @([PSCustomObject]@{ PSTypeName = 'Wheelhouse.AuditResult'; Stage = $Stage; Group = 'g'; GroupFile = $GroupFile; Service = 'osv'; Status = 'Passed'; ReportPath = 'none'; Message = 'm' })
            }
            Mock -ModuleName WheelhouseManager -CommandName Test-PackageAge -MockWith $script:intakeAgeMock
            Mock -ModuleName WheelhouseManager -CommandName Invoke-PipPinRetry -MockWith $script:intakeDownloadMock
            Mock -ModuleName WheelhouseManager -CommandName Invoke-WheelhouseDefenderScan -MockWith $script:intakeScanMock
        }

        It 'merges, checks and publishes, a second version into a new group, and records everything' {
            $wheelhouse = Get-TestWheelhouse
            $work = Get-TestFolder
            $local = Join-Path $work 'requirements.txt'
            Set-Content -Path $local -Value @('newpkg==1.0', 'six==1.16.0', 'attrs==24.0')
            $syncParams = @{
                WheelhousePath        = $wheelhouse
                ReportsFolder         = $work
                LocalRequirementsPath = $local
                PythonVersion         = '3.14'
                Platform              = 'win_amd64'
                MinimumAgeDays        = 10
                Services              = @('osv')
                DenylistPath          = (Join-Path $work 'denylist.json')
                StagingRoot           = (Join-Path $work 'staging')
            }
            $result = Invoke-WheelhouseSync @syncParams

            $result.Outcome | Should -Be 'Ok'
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'six==1.16.0,attrs==23.1.0,newpkg==1.0'
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-2.txt')) -join ',' | Should -Be 'attrs==24.0'
            $manifest = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            @($manifest | ForEach-Object { "$($_.name)==$($_.version)" } | Sort-Object) -join ',' |
                Should -Be 'attrs==23.1.0,attrs==24.0,newpkg==1.0,six==1.16.0'
            @($result.Published).Count | Should -Be 2
            # Only the candidates are audited; what was published before is the weekly check's job.
            @($result.AuditResults | Where-Object { $_.Stage -eq 'Deployed' }).Count | Should -Be 0
            @($result.AuditResults | Where-Object { $_.Stage -eq 'PreDownload' }).Count | Should -BeGreaterThan 0

            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $catalog.Records['attrs==24.0'].state | Should -Be 'Published'
            $catalog.Records['attrs==24.0'].groups -join ',' | Should -Be 'requirements-2.txt'
            # The intake scan of the staged download is the published wheel's scan result.
            $catalog.Records['attrs==24.0'].checks.scan.status | Should -Be 'Clean'
            @(Read-WheelhouseEvent -WheelhousePath $wheelhouse -Package 'newpkg')[0].action | Should -Be 'Published'

            foreach ($name in '.wheelhouse.lock', '.wheelhouse-sync.lock') { Test-Path -Path (Join-Path $wheelhouse $name) | Should -Be $false }
            @(Get-ChildItem -Path (Join-Path $work 'staging') -Force).Count | Should -Be 0
            @(Get-ChildItem -Path (Get-WheelhouseJournalFolder -WheelhousePath $wheelhouse) -Filter '*.json').Count | Should -Be 0
        }

        It 'holds back every package that needs a rejected dependency, across groups and up the chain' {
            $wheelhouse = Get-TestWheelhouse
            $work = Get-TestFolder
            $local = Join-Path $work 'requirements.txt'
            Set-Content -Path $local -Value @(
                'top==1.0', '    # via -r requirements.in',
                'newapp==1.0', '    # via top',
                'attrs==24.0', '    # via newapp',
                'other==1.0', '    # via -r requirements.in')
            foreach ($name in 'top', 'newapp', 'other') { $global:WhmReleases[$name] = New-TestRelease -Name $name }
            # attrs 24.0 goes to a new group (requirements-1.txt lists 23.1.0) and has no wheel.
            $global:WhmNoWheel = @('attrs')
            $syncParams = @{
                WheelhousePath = $wheelhouse; ReportsFolder = $work; LocalRequirementsPath = $local; PythonVersion = '3.14'; Platform = 'win_amd64'
                MinimumAgeDays = 10; Services = @('osv'); DenylistPath = (Join-Path $work 'denylist.json'); StagingRoot = (Join-Path $work 'staging')
            }
            $result = Invoke-WheelhouseSync @syncParams

            $result.Outcome | Should -Be 'Attention'
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'six==1.16.0,attrs==23.1.0,other==1.0'
            Test-Path -Path (Join-Path $wheelhouse 'requirements-2.txt') | Should -Be $false
            ($result.Published | ForEach-Object { "$($_.name)==$($_.version)" }) -join ',' | Should -Be 'other==1.0'
            $rejected = @{}
            foreach ($item in $result.Rejected) { $rejected[$item.Package] = $item }
            ($rejected.Keys | Sort-Object) -join ',' | Should -Be 'attrs,newapp,top'
            $rejected['attrs'].Category | Should -Be 'no-wheel'
            $rejected['newapp'].Category | Should -Be 'dependency'
            $rejected['newapp'].Dependency | Should -Be 'attrs==24.0'
            $rejected['top'].Reason | Should -Match '^needs newapp==1\.0, which was rejected \(needs attrs==24\.0'
            @(Get-ChildItem -Path $wheelhouse -Filter 'newapp*').Count | Should -Be 0
            @(Get-ChildItem -Path (Join-Path $work 'staging') -Force).Count | Should -Be 0
        }

        It 'merges only an approved proposal, and records it in the history' {
            $wheelhouse = Get-TestWheelhouse
            $work = Get-TestFolder
            $local = Join-Path $work 'requirements.txt'
            Set-Content -Path $local -Value @('newpkg==1.0', 'six==1.16.0')
            $proposalFile = Join-Path $work 'proposal.json'
            $syncParams = @{
                WheelhousePath = $wheelhouse; ReportsFolder = $work; LocalRequirementsPath = $local; PythonVersion = '3.14'; Platform = 'win_amd64'
                MinimumAgeDays = 10; Services = @('osv'); DenylistPath = (Join-Path $work 'denylist.json'); StagingRoot = (Join-Path $work 'staging')
                ApprovalMode = 'SeparateApprover'; ProposalPath = $proposalFile
            }
            $proposal = New-WheelhouseProposal -RequirementsPath $local -Path $proposalFile
            $refused = $null
            try { [void](Invoke-WheelhouseSync @syncParams) } catch { $refused = $_ }
            $refused.Exception.Data['WheelhouseAwaitingApproval'] | Should -Be $true
            Get-WheelhouseExitCode -ErrorRecord $refused | Should -Be 1
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'six==1.16.0,attrs==23.1.0'
            Test-Path -Path (Join-Path $wheelhouse '.wheelhouse-sync.lock') | Should -Be $false

            [void](Approve-WheelhouseProposal -Id $proposal.id -By 'CONTOSO\approver' -Mode SeparateApprover -Path $proposalFile)
            $result = Invoke-WheelhouseSync @syncParams
            $result.Outcome | Should -Be 'Ok'
            $result.Proposal.id | Should -Be $proposal.id
            (Read-WheelhouseProposal -Path $proposalFile).state | Should -Be 'Published'
            @(Read-WheelhouseEvent -WheelhousePath $wheelhouse -Package 'newpkg')[0].detail | Should -Match 'approved by CONTOSO\\approver'
        }

        It 'swaps a remediated version into the groups that listed it, then quarantines the old one' {
            $wheelhouse = Get-TestWheelhouse
            $work = Get-TestFolder
            $local = Join-Path $work 'requirements.txt'
            Set-Content -Path $local -Value @('six==1.16.0', 'attrs==24.0')
            $proposalFile = Join-Path $work 'proposal.json'
            $deny = Join-Path $work 'denylist.json'
            $remediation = @{
                RequirementsPath = $local; Kind = 'remediation'; Path = $proposalFile
                Replace = @([PSCustomObject]@{ name = 'attrs'; from = '23.1.0'; to = '24.0' })
                Retire = @([PSCustomObject]@{ name = 'attrs'; version = '23.1.0'; ids = @('GHSA-1') })
            }
            [void](New-WheelhouseProposal @remediation)
            $syncParams = @{
                WheelhousePath = $wheelhouse; ReportsFolder = $work; LocalRequirementsPath = $local; PythonVersion = '3.14'; Platform = 'win_amd64'
                MinimumAgeDays = 10; Services = @('osv'); DenylistPath = $deny; StagingRoot = (Join-Path $work 'staging'); ProposalPath = $proposalFile
            }
            $result = Invoke-WheelhouseSync @syncParams

            $result.Outcome | Should -Be 'Ok'
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'six==1.16.0,attrs==24.0'
            Test-Path -Path (Join-Path $wheelhouse 'requirements-2.txt') | Should -Be $false
            $result.Retired -join ',' | Should -Be 'attrs==23.1.0'
            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $catalog.Records['attrs==23.1.0'].state | Should -Be 'Quarantined'
            $catalog.Records['attrs==24.0'].groups -join ',' | Should -Be 'requirements-1.txt'
            Get-DenylistMatch -Name 'attrs' -Version '23.1.0' -Denylist @(Read-WheelhouseDenylist -Path $deny) | Should -Not -BeNullOrEmpty
            @(Read-WheelhouseEvent -WheelhousePath $wheelhouse -Package 'attrs' -Version '24.0')[0].detail | Should -Match 'replaced attrs==23.1.0'
            (Read-WheelhouseProposal -Path $proposalFile).outcome | Should -Match 'quarantined attrs==23.1.0'
        }

        It 'keeps the vulnerable version when its replacement is rejected' {
            $wheelhouse = Get-TestWheelhouse
            $work = Get-TestFolder
            $local = Join-Path $work 'requirements.txt'
            Set-Content -Path $local -Value @('six==1.16.0', 'attrs==24.0')
            $proposalFile = Join-Path $work 'proposal.json'
            $deny = Join-Path $work 'denylist.json'
            [void](Add-WheelhouseDenylistEntry -Name 'attrs' -Version '24.0' -Reason 'test' -Source 'manual' -Path $deny)
            $remediation = @{
                RequirementsPath = $local; Kind = 'remediation'; Path = $proposalFile
                Replace = @([PSCustomObject]@{ name = 'attrs'; from = '23.1.0'; to = '24.0' })
                Retire = @([PSCustomObject]@{ name = 'attrs'; version = '23.1.0'; ids = @('GHSA-1') })
            }
            [void](New-WheelhouseProposal @remediation)
            $syncParams = @{
                WheelhousePath = $wheelhouse; ReportsFolder = $work; LocalRequirementsPath = $local; PythonVersion = '3.14'; Platform = 'win_amd64'
                MinimumAgeDays = 10; Services = @('osv'); DenylistPath = $deny; StagingRoot = (Join-Path $work 'staging'); ProposalPath = $proposalFile
            }
            $result = Invoke-WheelhouseSync @syncParams
            $result.Outcome | Should -Be 'Attention'
            @($result.Retired).Count | Should -Be 0
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'six==1.16.0,attrs==23.1.0'
            (Read-WheelhouseCatalog -WheelhousePath $wheelhouse).Records['attrs==23.1.0'].state | Should -Be 'Published'
        }

        It 'takes out a wheel the file server removed and carries on - or stops when AutoQuarantine is off' {
            $wheelhouse = Get-TestWheelhouse
            $work = Get-TestFolder
            Remove-Item -Path (Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl')
            $syncParams = @{
                WheelhousePath = $wheelhouse; ReportsFolder = $work; LocalRequirementsPath = ''; PythonVersion = '3.14'; Platform = 'win_amd64'
                MinimumAgeDays = 10; Services = @('osv'); DenylistPath = (Join-Path $work 'denylist.json'); StagingRoot = (Join-Path $work 'staging')
            }

            $syncParams['AutoQuarantine'] = $false
            { Invoke-WheelhouseSync @syncParams } | Should -Throw '*integrity check failed*'
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'six==1.16.0,attrs==23.1.0'

            $syncParams['AutoQuarantine'] = $true
            $result = Invoke-WheelhouseSync @syncParams
            $result.Outcome | Should -Be 'Attention'
            ($result.Notices | ForEach-Object { "$($_.Kind):$($_.Package)" }) -join ',' | Should -Be 'FileMissing:six'
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'attrs==23.1.0'
            (Get-DenylistMatch -Name 'six' -Version '1.16.0' -Denylist @(Read-WheelhouseDenylist -Path (Join-Path $work 'denylist.json'))).reason | Should -Match "file server's antivirus"
            (Read-WheelhouseCatalog -WheelhousePath $wheelhouse).Records['six==1.16.0'].state | Should -Be 'Removed'
            # The share is not virus-scanned by the update run.
            @(Get-ChildItem -Path $work -Filter 'Report_Scan_*.json').Count | Should -Be 0
        }

        It 'reports rejections as needing attention and refuses a second run' {
            $wheelhouse = Get-TestWheelhouse
            $work = Get-TestFolder
            $local = Join-Path $work 'requirements.txt'
            Set-Content -Path $local -Value @('newpkg==1.0')
            $global:WhmNoWheel = @('newpkg')
            $syncParams = @{
                WheelhousePath = $wheelhouse; ReportsFolder = $work; LocalRequirementsPath = $local; PythonVersion = '3.14'; Platform = 'win_amd64'
                MinimumAgeDays = 10; Services = @('osv'); DenylistPath = (Join-Path $work 'denylist.json'); StagingRoot = (Join-Path $work 'staging')
            }
            $result = Invoke-WheelhouseSync @syncParams
            $result.Outcome | Should -Be 'Attention'
            $result.Rejected[0].Category | Should -Be 'no-wheel'
            @(Get-ChildItem -Path $work -Filter 'Report_Rejected_*.json').Count | Should -Be 1

            $sync = Enter-WheelhouseLock -WheelhousePath $wheelhouse -Kind sync
            try {
                try { Invoke-WheelhouseSync @syncParams } catch { $busy = $_ }
            }
            finally {
                Exit-WheelhouseLock -Lock $sync
            }
            Get-WheelhouseExitCode -ErrorRecord $busy | Should -Be 3
        }

        It 'does not publish a version that was denylisted while its checks ran' {
            $wheelhouse = Get-TestWheelhouse
            $work = Get-TestFolder
            $denyPath = Join-Path $work 'denylist.json'
            $intakeParams = @{
                Packages = @{ newpkg = '1.0' }; GroupName = 'requirements-1'; ReportsFolder = $work; Services = @('osv')
                MinimumAgeDays = 10; PythonVersion = '3.14'; Platform = 'win_amd64'; StagingRoot = (Join-Path $work 'staging')
            }
            $intake = Invoke-CandidateIntake @intakeParams
            $intake.Verified.Count | Should -Be 1
            [void](Add-WheelhouseDenylistEntry -Name 'newpkg' -Version '1.0' -Reason 'bad news' -Path $denyPath)

            $publish = Publish-CandidateIntake -Intake $intake -WheelhousePath $wheelhouse -GroupFile (Join-Path $wheelhouse 'requirements-1.txt') -Additions @{ newpkg = '1.0' } -DenylistPath $denyPath
            $publish.Accepted.Count | Should -Be 0
            $publish.Rejected[0].Reason | Should -Match 'denylisted while the checks ran.*bad news'
            Test-Path -Path (Join-Path $wheelhouse 'newpkg-1.0-py3-none-any.whl') | Should -Be $false
            Test-Path -Path $intake.StagingPath | Should -Be $false
        }
    }

    Context 'Remove-RequirementFromGroupFile' {
        It 'removes the pin and its hash lines and leaves the rest' {
            $file = Join-Path (Get-TestFolder) 'requirements-1.txt'
            Set-Content -Path $file -Value @('anyio==4.0.0 \', '    --hash=sha256:abc \', '    --hash=sha256:def', 'six==1.16.0', 'Other_Pkg==2.0')
            Remove-RequirementFromGroupFile -GroupFile $file -Name 'ANYIO' -Version '4.0.0' | Should -Be $true
            Remove-RequirementFromGroupFile -GroupFile $file -Name 'six' -Version '9.9' | Should -Be $false
            (Get-Content -Path $file) -join ',' | Should -Be 'six==1.16.0,Other_Pkg==2.0'
        }

        It 'leaves an empty file when the last pin goes, so the next pin is not preceded by a blank line' {
            $file = Join-Path (Get-TestFolder) 'requirements-1.txt'
            Set-Content -Path $file -Value 'six==1.16.0'
            Remove-RequirementFromGroupFile -GroupFile $file -Name 'six' -Version '1.16.0' | Should -Be $true
            # (Windows PowerShell 5.1 still writes a UTF-8 BOM - no content, no line.)
            @(Get-Content -Path $file).Count | Should -Be 0
            Add-RequirementToGroupFile -GroupFile $file -Name 'attrs' -Version '23.1.0'
            @(Get-Content -Path $file) -join '|' | Should -Be 'attrs==23.1.0'
        }
    }

    Context 'Package inventory and removal' {
        It 'combines manifest, groups, audit reports, scan reports and the denylist' {
            $wheelhouse = Get-TestWheelhouse
            $reports = Join-Path $wheelhouse 'reports'
            New-Item -ItemType Directory -Path $reports | Out-Null
            Set-Content -Path (Join-Path $reports 'Report_Scheduled-requirements-1-OSV_20260101_000000.json') -Value '{"dependencies":[{"name":"six","version":"1.16.0","vulns":[]},{"name":"attrs","version":"23.1.0","vulns":[{"id":"PYSEC-9"}]}]}'
            $scan = @{ Status = 'Threat'; ScanTime = '2026-01-02 10:00:00'; ScannedPaths = @($wheelhouse); Threats = @(@{ Resource = "file:_$(Join-Path $wheelhouse 'attrs-23.1.0-py3-none-any.whl')"; ThreatName = 'X' }) }
            Set-Content -Path (Join-Path $reports 'Report_Scan_20260102_100000.json') -Value ($scan | ConvertTo-Json -Depth 4)
            Set-Content -Path (Join-Path $wheelhouse 'stray-1.0-py3-none-any.whl') -Value 'x'
            Remove-Item -Path (Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl')

            $deny = @([PSCustomObject]@{ name = 'attrs'; version = '23.1.0'; reason = 'old'; source = 'manual' })
            $inventory = Get-WheelhousePackage -WheelhousePath $wheelhouse -Denylist $deny

            $attrs = $inventory.Packages | Where-Object { $_.name -eq 'attrs' }
            $six = $inventory.Packages | Where-Object { $_.name -eq 'six' }
            $attrs.audit_status | Should -Be 'Vulnerable'
            $attrs.vulnerabilities -join ',' | Should -Be 'PYSEC-9'
            $attrs.scan_status | Should -Be 'Threat'
            $attrs.denylisted | Should -Be 'old'
            $attrs.groups -join ',' | Should -Be 'requirements-1'
            $attrs.groups -is [array] | Should -Be $true
            $six.audit_status | Should -Be 'Passed'
            $six.scan_status | Should -Be 'Clean'
            $six.file_missing | Should -Be $true
            $six.denylisted | Should -BeNullOrEmpty
            $inventory.Untracked -join ',' | Should -Be 'stray-1.0-py3-none-any.whl'
            $inventory.Groups -join ',' | Should -Be 'requirements-1'
        }

        It 'reports Unknown, never Passed, for packages no report mentions' {
            $wheelhouse = Get-TestWheelhouse
            $inventory = Get-WheelhousePackage -WheelhousePath $wheelhouse
            @($inventory.Packages | Where-Object { $_.audit_status -ne 'Unknown' -or $_.scan_status -ne 'Unknown' }).Count | Should -Be 0
        }

        It 'quarantines a package, then restores it' {
            $wheelhouse = Get-TestWheelhouse
            $denyPath = Join-Path (Get-TestFolder) 'denylist.json'
            $file = 'attrs-23.1.0-py3-none-any.whl'

            $done = Remove-WheelhousePackage -WheelhousePath $wheelhouse -Name 'Attrs' -Version '23.1.0' -Quarantine -Reason 'test' -DenylistPath $denyPath

            $done.Mode | Should -Be 'Quarantine'
            Test-Path -Path (Join-Path $wheelhouse $file) | Should -Be $false
            Test-Path -Path (Join-Path (Join-Path (Join-Path $wheelhouse '_quarantine') $done.QuarantineId) $file) | Should -Be $true
            $manifest = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            ($manifest | ForEach-Object { $_.name }) -join ',' | Should -Be 'six'
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'six==1.16.0'
            $deny = @(Read-WheelhouseDenylist -Path $denyPath)
            $deny.Count | Should -Be 1
            $deny[0].source | Should -Be 'quarantined'
            @(Get-QuarantinedPackage -WheelhousePath $wheelhouse).Count | Should -Be 1
            Test-Path -Path (Join-Path $wheelhouse '.wheelhouse.lock') | Should -Be $false
            (Test-ManifestIntegrity -Manifest $manifest -WheelhousePath $wheelhouse).Count | Should -Be 0

            $restored = Restore-WheelhousePackage -WheelhousePath $wheelhouse -Id $done.QuarantineId -DenylistPath $denyPath

            $restored.DenylistRemoved | Should -Be $true
            Test-Path -Path (Join-Path $wheelhouse $file) | Should -Be $true
            $manifest = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            ($manifest | ForEach-Object { $_.name } | Sort-Object) -join ',' | Should -Be 'attrs,six'
            ((Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) | Sort-Object) -join ',' | Should -Be 'attrs==23.1.0,six==1.16.0'
            @(Read-WheelhouseDenylist -Path $denyPath).Count | Should -Be 0
            @(Get-QuarantinedPackage -WheelhousePath $wheelhouse).Count | Should -Be 0
            (Test-ManifestIntegrity -Manifest $manifest -WheelhousePath $wheelhouse).Count | Should -Be 0
        }

        It 'refuses to restore a file whose hash changed in quarantine' {
            $wheelhouse = Get-TestWheelhouse
            $denyPath = Join-Path (Get-TestFolder) 'denylist.json'
            $done = Remove-WheelhousePackage -WheelhousePath $wheelhouse -Name 'six' -Version '1.16.0' -Quarantine -DenylistPath $denyPath
            Set-Content -Path (Join-Path (Join-Path (Join-Path $wheelhouse '_quarantine') $done.QuarantineId) 'six-1.16.0-py3-none-any.whl') -Value 'tampered'

            { Restore-WheelhousePackage -WheelhousePath $wheelhouse -Id $done.QuarantineId -DenylistPath $denyPath } | Should -Throw '*hash changed*'
            Test-Path -Path (Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl') | Should -Be $false
        }

        It 'deletes a package and denylists it unless asked not to' {
            $wheelhouse = Get-TestWheelhouse
            $denyPath = Join-Path (Get-TestFolder) 'denylist.json'

            [void](Remove-WheelhousePackage -WheelhousePath $wheelhouse -Name 'six' -Version '1.16.0' -DenylistPath $denyPath)
            [void](Remove-WheelhousePackage -WheelhousePath $wheelhouse -Name 'attrs' -Version '23.1.0' -NoDenylist -DenylistPath $denyPath)

            Get-ChildItem -Path $wheelhouse -Filter '*.whl' | Should -BeNullOrEmpty
            $tracked = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            $tracked.Count | Should -Be 0
            $deny = @(Read-WheelhouseDenylist -Path $denyPath)
            $deny.Count | Should -Be 1
            $deny[0].name | Should -Be 'six'
            $deny[0].source | Should -Be 'removed'
        }

        It 'throws for a package that is not in the manifest' {
            $wheelhouse = Get-TestWheelhouse
            { Remove-WheelhousePackage -WheelhousePath $wheelhouse -Name 'nope' -Version '1' -DenylistPath (Join-Path $wheelhouse 'd.json') } |
                Should -Throw -ExceptionType ([System.Collections.Generic.KeyNotFoundException])
        }

        It 'changes nothing while another operation holds the lock' {
            $wheelhouse = Get-TestWheelhouse
            $denyPath = Join-Path (Get-TestFolder) 'denylist.json'
            $lock = Enter-WheelhouseLock -WheelhousePath $wheelhouse
            try {
                { Remove-WheelhousePackage -WheelhousePath $wheelhouse -Name 'six' -Version '1.16.0' -DenylistPath $denyPath } |
                    Should -Throw -ExceptionType ([System.InvalidOperationException])
            }
            finally { Exit-WheelhouseLock -Lock $lock }
            $tracked = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            $tracked.Count | Should -Be 2
            Test-Path -Path $denyPath | Should -Be $false
        }

        It 'undoes the earlier steps when moving the file fails' {
            $wheelhouse = Get-TestWheelhouse
            $denyPath = Join-Path (Get-TestFolder) 'denylist.json'
            # An open handle without FileShare.Delete makes the final file move fail, after the
            # denylist, group file and manifest steps already ran.
            $held = [System.IO.File]::Open((Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl'), 'Open', 'Read', 'None')
            try {
                { Remove-WheelhousePackage -WheelhousePath $wheelhouse -Name 'six' -Version '1.16.0' -Quarantine -DenylistPath $denyPath } | Should -Throw
            }
            finally { $held.Dispose() }

            $tracked = Read-WheelhouseManifest -WheelhousePath $wheelhouse
            $tracked.Count | Should -Be 2
            (Get-Content -Path (Join-Path $wheelhouse 'requirements-1.txt')) -join ',' | Should -Be 'six==1.16.0,attrs==23.1.0'
            @(Read-WheelhouseDenylist -Path $denyPath).Count | Should -Be 0
            @(Get-QuarantinedPackage -WheelhousePath $wheelhouse).Count | Should -Be 0
            Test-Path -Path (Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl') | Should -Be $true
            Test-Path -Path (Join-Path $wheelhouse '.wheelhouse.lock') | Should -Be $false
        }
    }

    Context 'Add-RequirementInLine' {
        It 'adds valid specs and refuses options, URLs, markers, duplicates and denylisted packages' {
            $folder = Get-TestFolder
            $path = Join-Path $folder 'requirements.in'
            [IO.File]::WriteAllText($path, "# comment`r`nnumpy>=2.0")
            $deny = @(
                [PSCustomObject]@{ name = 'evil'; version = '*'; reason = 'malware'; source = 'manual' },
                [PSCustomObject]@{ name = 'old'; version = '1.0'; reason = 'cve'; source = 'removed' })
            $specs = @('Pandas>=2.0,<3', 'numpy', '-r other.txt', '--index-url http://x', 'foo @ http://x/foo.zip', 'bar; python_version < "3"', 'evil', 'old==1.0', 'old>=1.1', 'requests==2.32.3')

            $result = Add-RequirementInLine -Path $path -Spec $specs -Denylist $deny

            $result.Added -join '|' | Should -Be 'Pandas>=2.0,<3|old>=1.1|requests==2.32.3'
            @($result.Skipped).Count | Should -Be 7
            ($result.Skipped | Where-Object { $_.Spec -eq 'numpy' }).Reason | Should -Match 'already listed'
            ($result.Skipped | Where-Object { $_.Spec -eq 'evil' }).Reason | Should -Match 'denylist'
            ($result.Skipped | Where-Object { $_.Spec -eq 'old==1.0' }).Reason | Should -Match 'denylist'
            (Get-Content -Path $path) -join '|' | Should -Be '# comment|numpy>=2.0|Pandas>=2.0,<3|old>=1.1|requests==2.32.3'
        }

        It 'replaces a listed requirement only with -Replace and only when the spec differs' {
            $path = Join-Path (Get-TestFolder) 'requirements.in'
            [IO.File]::WriteAllText($path, "# comment`r`nhuggingface-hub>=0.24,<1.dev0  # old`r`nnumpy")

            $offer = Add-RequirementInLine -Path $path -Spec @('huggingface_hub~=1.5', 'numpy')
            @($offer.Added).Count + @($offer.Replaced).Count | Should -Be 0
            ($offer.Skipped | Where-Object { $_.Spec -eq 'huggingface_hub~=1.5' }).Replaceable | Should -Be $true
            ($offer.Skipped | Where-Object { $_.Spec -eq 'numpy' }).Replaceable | Should -Be $false

            $result = Add-RequirementInLine -Path $path -Spec @('huggingface_hub~=1.5', 'numpy', 'pandas') -Replace
            $result.Replaced -join '|' | Should -Be 'huggingface_hub~=1.5'
            $result.Added -join '|' | Should -Be 'pandas'
            (Get-Content -Path $path) -join '|' | Should -Be '# comment|huggingface_hub~=1.5|numpy|pandas'
        }

        It 'does not touch the file when nothing is added' {
            $path = Join-Path (Get-TestFolder) 'requirements.in'
            $result = Add-RequirementInLine -Path $path -Spec @('-e .')
            @($result.Added).Count | Should -Be 0
            Test-Path -Path $path | Should -Be $false
        }
    }

    Context 'Remove-RequirementInLine' {
        It 'removes the package by its normalized name and keeps the other lines' {
            $path = Join-Path (Get-TestFolder) 'requirements.in'
            [IO.File]::WriteAllText($path, "# comment`r`nnumpy>=2.0`r`nRequests == 2.32.3  # pinned`r`npandas")

            [string[]]$removed = Remove-RequirementInLine -Path $path -Name 'requests'

            $removed -join '|' | Should -Be 'Requests == 2.32.3  # pinned'
            (Get-Content -Path $path) -join '|' | Should -Be '# comment|numpy>=2.0|pandas'
        }

        It 'removes several packages, and nothing when one of them is not listed' {
            $path = Join-Path (Get-TestFolder) 'requirements.in'
            [IO.File]::WriteAllText($path, "# comment`r`nnumpy>=2.0`r`npandas")
            { Remove-RequirementInLine -Path $path -Name @('numpy', 'urllib3') } | Should -Throw '*depends on it*'
            (Get-Content -Path $path) -join '|' | Should -Be '# comment|numpy>=2.0|pandas'

            [string[]]$removed = Remove-RequirementInLine -Path $path -Name @('numpy', 'pandas')
            $removed -join '|' | Should -Be 'numpy>=2.0|pandas'
            (Get-Content -Path $path) -join '|' | Should -Be '# comment'
        }
    }

    Context 'Settings validation for the UI' {
        It 'coerces and validates values' {
            ConvertTo-WheelhouseSettingValue -Key 'MinimumPackageAgeDays' -Value '14' | Should -Be 14
            { ConvertTo-WheelhouseSettingValue -Key 'MinimumPackageAgeDays' -Value '-1' } | Should -Throw -ExceptionType ([System.ArgumentException])
            { ConvertTo-WheelhouseSettingValue -Key 'MinimumPackageAgeDays' -Value 'abc' } | Should -Throw -ExceptionType ([System.ArgumentException])
            ConvertTo-WheelhouseSettingValue -Key 'Platform' -Value 'win_arm64' | Should -Be 'win_arm64'
            { ConvertTo-WheelhouseSettingValue -Key 'Platform' -Value 'linux' } | Should -Throw -ExceptionType ([System.ArgumentException])
            ConvertTo-WheelhouseSettingValue -Key 'PythonVersion' -Value '3.13' | Should -Be '3.13'
            { ConvertTo-WheelhouseSettingValue -Key 'PythonVersion' -Value '3' } | Should -Throw -ExceptionType ([System.ArgumentException])
            { ConvertTo-WheelhouseSettingValue -Key 'MailTo' -Value 'not an address' } | Should -Throw -ExceptionType ([System.ArgumentException])
            { ConvertTo-WheelhouseSettingValue -Key 'Nope' -Value 'x' } | Should -Throw -ExceptionType ([System.ArgumentException])
            { ConvertTo-WheelhouseSettingValue -Key 'WheelhousePath' -Value (Join-Path $TestDrive 'does-not-exist') } | Should -Throw -ExceptionType ([System.ArgumentException])
            ConvertTo-WheelhouseSettingValue -Key 'WheelhousePath' -Value (Get-TestFolder) | Should -Not -BeNullOrEmpty
            ConvertTo-WheelhouseSettingValue -Key 'RequireDefenderScanAtIntake' -Value $true | Should -Be $true
            ConvertTo-WheelhouseSettingValue -Key 'AutoQuarantine' -Value 'false' | Should -Be $false
            { ConvertTo-WheelhouseSettingValue -Key 'AutoQuarantine' -Value 'sometimes' } | Should -Throw -ExceptionType ([System.ArgumentException])
            # Settings hold a bool, command lines On/Off.
            (@($true, 'On', 'on', 'True', '1', 'Yes') | ForEach-Object { ConvertTo-WheelhouseBoolean $_ }) -join ',' | Should -Be 'True,True,True,True,True,True'
            (@($false, 'Off', '', $null, 'no') | ForEach-Object { ConvertTo-WheelhouseBoolean $_ }) -join ',' | Should -Be 'False,False,False,False,False'
        }

        It 'returns services as an array and refuses an empty or unknown selection' {
            $services = ConvertTo-WheelhouseSettingValue -Key 'VulnerabilityServices' -Value @('osv', 'pypi', 'osv')
            $services -join ',' | Should -Be 'osv,pypi'
            $services -is [array] | Should -Be $true
            $single = ConvertTo-WheelhouseSettingValue -Key 'VulnerabilityServices' -Value @('osv')
            $single -is [array] | Should -Be $true
            { ConvertTo-WheelhouseSettingValue -Key 'VulnerabilityServices' -Value @() } | Should -Throw -ExceptionType ([System.ArgumentException])
            { ConvertTo-WheelhouseSettingValue -Key 'VulnerabilityServices' -Value @('bing') } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }

    Context 'Invoke-WheelhouseDefenderScan' {
        It 'is an Error, not Clean, when Defender is unavailable' {
            Mock -ModuleName WheelhouseManager -CommandName Test-WheelhouseDefenderAvailable -MockWith { $false }
            $result = Invoke-WheelhouseDefenderScan -Path (Get-TestFolder)
            $result.Status | Should -Be 'Error'
        }

        It 'reports a threat found at the scanned path and saves a report' {
            $wheelhouse = Get-TestFolder
            $reports = Join-Path $wheelhouse 'reports'
            New-Item -ItemType Directory -Path $reports | Out-Null
            $global:WhmScanDetections = @(
                [PSCustomObject]@{ Resource = "file:_$wheelhouse\bad-1.0-py3-none-any.whl"; ThreatName = 'Trojan:Test'; ThreatId = '1'; ActionSuccess = $true },
                [PSCustomObject]@{ Resource = 'file:_C:\elsewhere\other.exe'; ThreatName = 'Other'; ThreatId = '2'; ActionSuccess = $true })
            Mock -ModuleName WheelhouseManager -CommandName Test-WheelhouseDefenderAvailable -MockWith { $true }
            Mock -ModuleName WheelhouseManager -CommandName Invoke-MpScan -MockWith { }
            Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseThreatDetection -MockWith { $global:WhmScanDetections }

            $result = Invoke-WheelhouseDefenderScan -Path $wheelhouse -ReportsFolder $reports

            $result.Status | Should -Be 'Threat'
            @($result.Threats).Count | Should -Be 1
            $result.Threats[0].ThreatName | Should -Be 'Trojan:Test'
            Test-Path -Path $result.ReportPath | Should -Be $true
            $status = Get-PackageScanStatus -ReportsFolder $reports -WheelhousePath $wheelhouse -File @('bad-1.0-py3-none-any.whl', 'good-1.0-py3-none-any.whl')
            $status['bad-1.0-py3-none-any.whl'].Status | Should -Be 'Threat'
            $status['good-1.0-py3-none-any.whl'].Status | Should -Be 'Clean'
        }

        It 'scans hash-checked local copies, reports the share files, and skips changed ones' {
            $wheelhouse = Get-TestWheelhouse
            $reports = Join-Path $wheelhouse 'reports'
            New-Item -ItemType Directory -Path $reports | Out-Null
            Set-Content -Path (Join-Path $wheelhouse 'attrs-23.1.0-py3-none-any.whl') -Value 'changed on the share'
            $global:WhmScanDetections = $null
            Mock -ModuleName WheelhouseManager -CommandName Test-WheelhouseDefenderAvailable -MockWith { $true }
            # Defender is pointed at the local copy and "finds" six in it.
            Mock -ModuleName WheelhouseManager -CommandName Invoke-MpScan -MockWith { $global:WhmScannedPath = $Path; $global:WhmScanDetections = @(Get-ChildItem -Path $Path -Filter 'six-*') }
            Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseThreatDetection -MockWith {
                @($global:WhmScanDetections | ForEach-Object { [PSCustomObject]@{ Resource = "file:_$($_.FullName)"; ThreatName = 'Trojan:Test'; ThreatId = '1'; ActionSuccess = $true } })
            }

            $result = Invoke-WheelhouseCopyScan -WheelhousePath $wheelhouse -ReportsFolder $reports -StagingRoot (Join-Path (Get-TestFolder) 'staging')

            $result.Status | Should -Be 'Threat'
            $result.Threats[0].Resource | Should -Be "file:_$(Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl')"
            @($result.ScannedPaths) -join ',' | Should -Be (Join-Path $wheelhouse 'six-1.16.0-py3-none-any.whl')
            @($result.NotScanned).Count | Should -Be 1
            $result.NotScanned[0] | Should -Match 'attrs-23.1.0.*does not match its recorded hash'
            Test-Path -Path $result.ReportPath | Should -Be $true
            # Defender scanned the local copy, never the share; recording the result marks the share file.
            $global:WhmScannedPath | Should -Not -BeLike "$wheelhouse*"
            $recorded = $result
            Update-WheelhouseCatalog -WheelhousePath $wheelhouse -DenylistPath (Join-Path $reports 'd.json') -Update ({ param($c) Update-CatalogScanResult -Catalog $c -ScanResult $recorded }.GetNewClosure())
            $catalog = Read-WheelhouseCatalog -WheelhousePath $wheelhouse
            $catalog.Records['six==1.16.0'].checks.scan.status | Should -Be 'Threat'
            $catalog.Records['attrs==23.1.0'].checks.scan | Should -BeNullOrEmpty

            { Invoke-WheelhouseCopyScan -WheelhousePath $wheelhouse -File @('ghost-1.0-py3-none-any.whl') -StagingRoot (Join-Path (Get-TestFolder) 'staging') } |
                Should -Throw -ExceptionType ([System.Collections.Generic.KeyNotFoundException])
        }

        It 'is Clean when the scan finished without detections, and Error when a scan failed' {
            Mock -ModuleName WheelhouseManager -CommandName Test-WheelhouseDefenderAvailable -MockWith { $true }
            Mock -ModuleName WheelhouseManager -CommandName Invoke-MpScan -MockWith { }
            Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseThreatDetection -MockWith { @() }
            (Invoke-WheelhouseDefenderScan -Path (Get-TestFolder)).Status | Should -Be 'Clean'

            Mock -ModuleName WheelhouseManager -CommandName Invoke-MpScan -MockWith { throw 'access denied' }
            $failed = Invoke-WheelhouseDefenderScan -Path (Get-TestFolder)
            $failed.Status | Should -Be 'Error'
            $failed.Message | Should -Match 'access denied'
        }
    }

    Context 'UI request checks' {
        It 'enforces host, token, origin and content type' {
            $base = @{ Token = 'secret'; Port = 8765; HostHeader = 'localhost:8765' }
            (Test-WheelhouseUiRequest -Method GET -Path '/api/state' -SuppliedToken 'secret' @base) | Should -BeNullOrEmpty
            (Test-WheelhouseUiRequest -Method GET -Path '/api/state' -SuppliedToken 'wrong' @base).Status | Should -Be 401
            (Test-WheelhouseUiRequest -Method GET -Path '/api/state' -SuppliedToken 'SECRET' @base).Status | Should -Be 401
            (Test-WheelhouseUiRequest -Method GET -Path '/api/state' -SuppliedToken 'secret' -Token 'secret' -Port 8765 -HostHeader 'evil.example:8765').Status | Should -Be 403
            (Test-WheelhouseUiRequest -Method POST -Path '/api/denylist/add' -SuppliedToken 'secret' -ContentType 'application/json' @base) | Should -BeNullOrEmpty
            (Test-WheelhouseUiRequest -Method POST -Path '/api/denylist/add' -SuppliedToken 'secret' -ContentType 'text/plain' @base).Status | Should -Be 415
            (Test-WheelhouseUiRequest -Method POST -Path '/api/denylist/add' -SuppliedToken 'secret' -ContentType 'application/json' -Origin 'http://evil.example' @base).Status | Should -Be 403
            (Test-WheelhouseUiRequest -Method POST -Path '/api/denylist/add' -SuppliedToken 'secret' -ContentType 'application/json' -Origin 'http://localhost:8765' @base) | Should -BeNullOrEmpty
        }

        It 'serves the page only with the token and static files without it' {
            $base = @{ Token = 'secret'; Port = 8765; HostHeader = '127.0.0.1:8765' }
            (Test-WheelhouseUiRequest -Method GET -Path '/' @base).Status | Should -Be 403
            (Test-WheelhouseUiRequest -Method GET -Path '/' -SuppliedToken 'secret' @base) | Should -BeNullOrEmpty
            (Test-WheelhouseUiRequest -Method GET -Path '/app.js' @base) | Should -BeNullOrEmpty
            (Test-WheelhouseUiRequest -Method POST -Path '/app.js' @base).Status | Should -Be 405
        }

        It 'generates distinct tokens' {
            $a = Get-WheelhouseUiRandomToken
            $b = Get-WheelhouseUiRandomToken
            $a.Length | Should -Be 48
            $a | Should -Not -Be $b
        }

        It 'refuses quotes in job arguments and quotes values with spaces' {
            { ConvertTo-UiArgument -Value 'a"b' } | Should -Throw -ExceptionType ([System.ArgumentException])
            ConvertTo-UiArgument -Value 'C:\a b\c.ps1' | Should -Be '"C:\a b\c.ps1"'
            ConvertTo-UiArgument -Value 'x==1,y==2' | Should -Be 'x==1,y==2'
        }
    }

    Context 'UI API' {
        BeforeAll {
            function Get-TestManager {
                $root = Get-TestFolder
                New-Item -ItemType Directory -Path (Join-Path $root 'config') | Out-Null
                $wheelhouse = Get-TestWheelhouse
                Save-WheelhouseSetting -SettingsPath (Join-Path (Join-Path $root 'config') 'settings.psd1') -Settings @{
                    WheelhousePath     = $wheelhouse
                    RequirementsInPath = (Join-Path $root 'requirements.in')
                }
                return @{ Root = $root; Wheelhouse = $wheelhouse }
            }
            function ConvertFrom-TestJson { param([string]$Json) return ($Json | ConvertFrom-Json) }
        }

        BeforeEach {
            $global:WhmUiJobSteps = $null
            # The state route checks python / pip-audit / uv; no real processes in API tests.
            & (Get-Module WheelhouseManager) { $script:UiToolStatus = $null }
            Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseToolStatus -MockWith {
                [PSCustomObject]@{ name = 'python'; available = $true; version = '3.14.0'; level = 'ok'; message = '' }
                [PSCustomObject]@{ name = 'uv'; available = $false; version = ''; level = 'bad'; message = 'uv was not found' }
            }
            Mock -ModuleName WheelhouseManager -CommandName Start-WheelhouseUiJob -MockWith {
                $global:WhmUiJobSteps = @($Steps | ForEach-Object { "$($_.Script) $($_.Arguments -join ' ')".Trim() })
                [PSCustomObject]@{ Id = 1; Title = $Title; Kind = $Kind; Status = 'Running'; StepIndex = 0; Steps = @($Steps); Message = ''; ExitCode = $null; StartedUtc = ''; EndedUtc = $null }
            }
        }

        It 'lists packages and the state' {
            $m = Get-TestManager
            $packages = Invoke-WheelhouseUiApi -Method GET -Path '/api/packages' -ManagerRoot $m.Root
            $packages.Status | Should -Be 200
            @($packages.Body.packages).Count | Should -Be 2
            $state = Invoke-WheelhouseUiApi -Method GET -Path '/api/state' -ManagerRoot $m.Root
            $state.Body.configured | Should -Be $true
            $state.Body.reachable | Should -Be $true
            @($state.Body.tools).Count | Should -Be 2
            @($state.Body.tools | Where-Object { $_.name -eq 'uv' })[0].level | Should -Be 'bad'
        }

        It 'adds and removes waivers and shows findings with their deadline' {
            $m = Get-TestManager
            Update-WheelhouseCatalog -WheelhousePath $m.Wheelhouse -DenylistPath (Join-Path $m.Root 'config\denylist.json') -Update {
                param($catalog)
                $report = Join-Path $m.Root 'report.json'
                Set-Content -Path $report -Value '{"dependencies":[{"name":"attrs","version":"23.1.0","vulns":[{"id":"GHSA-9","fix_versions":["24.0"]}]}]}'
                $results = @('osv', 'pypi' | ForEach-Object { [PSCustomObject]@{ Service = $_; Status = 'Vulnerable'; ReportPath = $report; GroupFile = 'x' } })
                Update-CatalogAuditResult -Catalog $catalog -AuditResult $results -Severity @{ 'GHSA-9' = [PSCustomObject]@{ Severity = 'High'; Score = 8.1; Source = 'test'; Error = '' } }
            }
            $packages = (Invoke-WheelhouseUiApi -Method GET -Path '/api/packages' -ManagerRoot $m.Root).Body
            $attrs = @($packages.packages | Where-Object { $_.name -eq 'attrs' })[0]
            $attrs.severity | Should -Be 'High'
            $attrs.open_findings | Should -Be 1
            $attrs.overdue | Should -Be $false
            $packages.check_overdue | Should -Be $true

            $add = Invoke-WheelhouseUiApi -Method POST -Path '/api/waivers/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"attrs","version":"23.1.0","id":"GHSA-9","reason":"not used","days":"14"}')
            $add.Status | Should -Be 200
            $history = (Invoke-WheelhouseUiApi -Method GET -Path '/api/packages/attrs/23.1.0/history' -ManagerRoot $m.Root).Body
            $finding = @($history.record.findings)[0]
            $finding.status | Should -Be 'Waived'
            @($finding.fix_versions) -join ',' | Should -Be '24.0'
            @($history.events | ForEach-Object { $_.action }) | Should -Contain 'Waived'
            $attrs = @((Invoke-WheelhouseUiApi -Method GET -Path '/api/packages' -ManagerRoot $m.Root).Body.packages | Where-Object { $_.name -eq 'attrs' })[0]
            $attrs.open_findings | Should -Be 0
            $attrs.waived_findings | Should -Be 1
            @((Invoke-WheelhouseUiApi -Method GET -Path '/api/waivers' -ManagerRoot $m.Root).Body.items).Count | Should -Be 1

            (Invoke-WheelhouseUiApi -Method POST -Path '/api/waivers/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"attrs","version":"23.1.0","id":"GHSA-9","reason":"","days":"14"}')).Status | Should -Be 400
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/waivers/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"attrs","version":"23.1.0","id":"GHSA-9","reason":"x","days":"365"}')).Status | Should -Be 400
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/waivers/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"attrs","version":"23.1.0","id":"GHSA-9"}')).Status | Should -Be 200
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/waivers/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"attrs","version":"23.1.0","id":"GHSA-9"}')).Status | Should -Be 404
            @((Invoke-WheelhouseUiApi -Method GET -Path '/api/packages/attrs/23.1.0/history' -ManagerRoot $m.Root).Body.record.findings)[0].status | Should -Be 'Open'
        }

        It 'gives the overview' {
            $m = Get-TestManager
            Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseScheduledCheck -MockWith { [PSCustomObject]@{ Registered = $false; TaskName = 'x'; Script = 'x' } }
            $overview = Invoke-WheelhouseUiApi -Method GET -Path '/api/overview' -ManagerRoot $m.Root
            $overview.Status | Should -Be 200
            $overview.Body.published | Should -Be 2
            $overview.Body.check_overdue | Should -Be $true
            @($overview.Body.attention)[0].target | Should -Be 'schedule'
            $overview.Body.task | Should -BeNullOrEmpty
        }

        It 'lists only the resolved pins that are not in the wheelhouse yet, with the last rejection' {
            $m = Get-TestManager
            $resolved = Join-Path $m.Root 'requirements.txt'
            Set-Content -Path $resolved -Value @('six==1.16.0', 'attrs==23.1.0', 'requests==2.32.3', 'numpy==2.3.1')
            Set-WheelhouseSetting -SettingsPath (Join-Path $m.Root 'config\settings.psd1') -Updates @{ LocalRequirementsPath = $resolved }
            New-Item -ItemType Directory -Path (Join-Path $m.Wheelhouse 'reports') -Force | Out-Null
            Set-Content -Path (Join-Path $m.Wheelhouse 'reports\Report_Rejected_20261101_100000.json') -Value '[{"Group":"requirements-1","Package":"requests","Version":"2.32.3","Category":"vulnerability","Reason":"known vulnerability GHSA-9hjg"}]'
            $body = (Invoke-WheelhouseUiApi -Method GET -Path '/api/requirements' -ManagerRoot $m.Root).Body
            $body.pin_count | Should -Be 4
            $body.published_count | Should -Be 2
            (@($body.pending) | ForEach-Object { "$($_.name)==$($_.version)" }) -join ',' | Should -Be 'numpy==2.3.1,requests==2.32.3'
            @($body.pending | Where-Object { $_.name -eq 'requests' })[0].rejected | Should -Match 'GHSA-9hjg'
            @($body.pending | Where-Object { $_.name -eq 'numpy' })[0].rejected | Should -BeNullOrEmpty
        }

        It 'shows the proposal and what this user may do under SeparateApprover' {
            $m = Get-TestManager
            $resolved = Join-Path $m.Root 'requirements.txt'
            Set-Content -Path $resolved -Value @('six==1.16.0', 'numpy==2.3.1')
            Set-WheelhouseSetting -SettingsPath (Join-Path $m.Root 'config\settings.psd1') -Updates @{ LocalRequirementsPath = $resolved; ApprovalMode = 'SeparateApprover' }
            Remove-Item -Path $global:WhmProposalPath -ErrorAction SilentlyContinue

            $approval = (Invoke-WheelhouseUiApi -Method GET -Path '/api/requirements' -ManagerRoot $m.Root).Body.approval
            $approval.mode | Should -Be 'SeparateApprover'
            $approval.can_publish | Should -Be $false
            $approval.blocked_by | Should -Match 'Propose it'

            (Invoke-WheelhouseUiApi -Method POST -Path '/api/proposal/new' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{}')).Status | Should -Be 200
            $approval = (Invoke-WheelhouseUiApi -Method GET -Path '/api/requirements' -ManagerRoot $m.Root).Body.approval
            $approval.current | Should -Be $true
            $approval.proposal.state | Should -Be 'Proposed'
            $approval.can_approve | Should -Be $false
            $approval.can_publish | Should -Be $false
            $id = $approval.proposal.id
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/proposal/approve' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson "{`"id`":`"$id`"}")).Status | Should -Be 409

            [void](Approve-WheelhouseProposal -Id $id -By 'CONTOSO\other' -Mode SeparateApprover -Path $global:WhmProposalPath)
            $approval = (Invoke-WheelhouseUiApi -Method GET -Path '/api/requirements' -ManagerRoot $m.Root).Body.approval
            $approval.can_publish | Should -Be $true
            $approval.proposal.approved_by | Should -Be 'CONTOSO\other'
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/proposal/reject' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson "{`"id`":`"$id`",`"reason`":`"`"}")).Status | Should -Be 400
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/proposal/reject' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson "{`"id`":`"$id`",`"reason`":`"no`"}")).Status | Should -Be 200
            (Invoke-WheelhouseUiApi -Method GET -Path '/api/requirements' -ManagerRoot $m.Root).Body.approval.blocked_by | Should -Match 'Rejected'
        }

        It 'starts a fix job only for a published version, with a plain expedite reason' {
            $m = Get-TestManager
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/remediate' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"nope","version":"1.0"}')).Status | Should -Be 404
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/remediate' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"attrs","version":"23.1.0","expedite_reason":"bad\" quote"}')).Status | Should -Be 400
            $started = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/remediate' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"Attrs","version":"23.1.0","expedite_reason":"CVE-2026-1 is exploited"}')
            $started.Status | Should -Be 202
            $global:WhmUiJobSteps -join ';' | Should -Be 'Invoke-WheelhouseRemediation.ps1 -Package attrs==23.1.0 -ExpediteReason CVE-2026-1 is exploited'
        }

        It 'shows, registers and removes the weekly check task' {
            $m = Get-TestManager
            $global:WhmTaskRegistered = $null
            Mock -ModuleName WheelhouseManager -CommandName Get-WheelhouseScheduledCheck -MockWith { [PSCustomObject]@{ Registered = $false; TaskName = 'Wheelhouse Weekly Check'; Script = 'x' } }
            Mock -ModuleName WheelhouseManager -CommandName Register-WheelhouseScheduledCheck -MockWith {
                $global:WhmTaskRegistered = @{ Days = @($DayOfWeek); At = $At; User = $User; Password = [System.Net.NetworkCredential]::new('', $Password).Password }
                [PSCustomObject]@{ NextRunTime = '2026-11-01T01:00:00Z' }
            }
            Mock -ModuleName WheelhouseManager -CommandName Unregister-WheelhouseScheduledCheck -MockWith { $false }
            $status = Invoke-WheelhouseUiApi -Method GET -Path '/api/schedule' -ManagerRoot $m.Root
            $status.Status | Should -Be 200
            $status.Body.registered | Should -Be $false
            $status.Body.current_user | Should -Not -BeNullOrEmpty
            $status.Body.mapped_drive | Should -BeNullOrEmpty

            $saved = Invoke-WheelhouseUiApi -Method POST -Path '/api/schedule' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"days":["Sunday"],"time":"03:00","user":"CONTOSO\\svc","password":"pw"}')
            $saved.Status | Should -Be 200
            $global:WhmTaskRegistered.Password | Should -Be 'pw'
            $global:WhmTaskRegistered.Days -join ',' | Should -Be 'Sunday'
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/schedule/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{}')).Status | Should -Be 400
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/schedule/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"confirm":true}')).Status | Should -Be 404
        }

        It 'answers 409 when the wheelhouse is not configured' {
            $root = Get-TestFolder
            New-Item -ItemType Directory -Path (Join-Path $root 'config') | Out-Null
            Save-WheelhouseSetting -SettingsPath (Join-Path (Join-Path $root 'config') 'settings.psd1') -Settings @{ WheelhousePath = '' }
            (Invoke-WheelhouseUiApi -Method GET -Path '/api/packages' -ManagerRoot $root).Status | Should -Be 409
        }

        It 'starts audit and scan jobs for validated selections only' {
            $m = Get-TestManager
            $all = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/audit' -Body (ConvertFrom-TestJson '{"all":true}') -ManagerRoot $m.Root
            $all.Status | Should -Be 202
            $global:WhmUiJobSteps -join '|' | Should -Be 'Test-WheelhousePackage.ps1'

            $some = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/audit' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"packages":[{"name":"Six","version":"1.16.0"},{"name":"attrs","version":"23.1.0"}]}')
            $some.Status | Should -Be 202
            $global:WhmUiJobSteps -join '|' | Should -Be 'Test-WheelhousePackage.ps1 -Package six==1.16.0,attrs==23.1.0'

            (Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/audit' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"packages":[{"name":"nope","version":"1"}]}')).Status | Should -Be 404
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/audit' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"packages":[{"name":"six;rm","version":"1"}]}')).Status | Should -Be 400
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/audit' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"packages":[]}')).Status | Should -Be 400

            $scan = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/scan' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"files":["six-1.16.0-py3-none-any.whl"]}')
            $scan.Status | Should -Be 202
            $global:WhmUiJobSteps -join '|' | Should -Be 'Invoke-WheelhouseScan.ps1 -File six-1.16.0-py3-none-any.whl'
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/scan' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"files":["..\\evil.whl"]}')).Status | Should -Be 400
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/scan' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"files":["ghost-1.0-py3-none-any.whl"]}')).Status | Should -Be 404
        }

        It 'adds packages to requirements.in and chains the resolve and update steps' {
            $m = Get-TestManager
            $result = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"specs":["numpy>=2.0","-r evil.txt"]}')
            $result.Status | Should -Be 200
            @($result.Body.added) -join ',' | Should -Be 'numpy>=2.0'
            @($result.Body.skipped).Count | Should -Be 1
            (Get-Content -Path (Join-Path $m.Root 'requirements.in')) -join '|' | Should -Be 'numpy>=2.0'
            # By default the job stops at requirements.txt, for review.
            $global:WhmUiJobSteps -join '|' | Should -Be 'Update-Requirement.ps1'

            $null = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"specs":["pandas"],"publish":true}')
            $global:WhmUiJobSteps -join '|' | Should -Be 'Update-Requirement.ps1|Update-Wheelhouse.ps1'

            $global:WhmUiJobSteps = $null
            $none = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"specs":["numpy"]}')
            $none.Body.job | Should -BeNullOrEmpty
            $global:WhmUiJobSteps | Should -BeNullOrEmpty

            $swap = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"specs":["numpy>=2.1"],"replace":true}')
            @($swap.Body.replaced) -join ',' | Should -Be 'numpy>=2.1'
            (Get-Content -Path (Join-Path $m.Root 'requirements.in')) -join '|' | Should -Be 'numpy>=2.1|pandas'
            $global:WhmUiJobSteps -join '|' | Should -Be 'Update-Requirement.ps1'
        }

        It 'lists the audit reports and shows one with its advisories' {
            $m = Get-TestManager
            $reports = Join-Path $m.Wheelhouse 'reports'
            New-Item -ItemType Directory -Path $reports -Force | Out-Null
            $json = '{"dependencies":[{"name":"six","version":"1.16.0","vulns":[]},{"name":"attrs","version":"23.1.0","vulns":[{"id":"PYSEC-1","fix_versions":["23.2.0"],"aliases":["CVE-1"],"description":"bad"}]},{"name":"local","skip_reason":"not on PyPI"}]}'
            Set-Content -Path (Join-Path $reports 'Report_Scheduled-requirements-1-OSV_20261101_100000.json') -Value $json
            Set-Content -Path (Join-Path $reports 'Report_Scheduled-requirements-1-PYPI_20261101_090000.json') -Value 'not json'
            Set-Content -Path (Join-Path $reports 'Report_Rejected_20261101_100000.json') -Value '[]'

            $list = Invoke-WheelhouseUiApi -Method GET -Path '/api/audits' -ManagerRoot $m.Root
            $list.Status | Should -Be 200
            @($list.Body.reports).Count | Should -Be 2
            $first = @($list.Body.reports)[0]
            $first.file | Should -Be 'Report_Scheduled-requirements-1-OSV_20261101_100000.json'
            $first.packages | Should -Be 2
            $first.vulnerable | Should -Be 1
            $first.skipped | Should -Be 1
            @($list.Body.reports)[1].error | Should -Match 'not valid JSON'

            $one = Invoke-WheelhouseUiApi -Method GET -Path '/api/audits/Report_Scheduled-requirements-1-OSV_20261101_100000.json' -ManagerRoot $m.Root
            $one.Status | Should -Be 200
            @($one.Body.dependencies)[0].name | Should -Be 'attrs'
            @(@($one.Body.dependencies)[0].vulns)[0].fix_versions -join ',' | Should -Be '23.2.0'

            (Invoke-WheelhouseUiApi -Method GET -Path '/api/audits/Report_Rejected_20261101_100000.json' -ManagerRoot $m.Root).Status | Should -Be 404
            (Invoke-WheelhouseUiApi -Method GET -Path '/api/audits/Report_Missing-OSV_20261101_100000.json' -ManagerRoot $m.Root).Status | Should -Be 404
        }

        It 'removes a package from requirements.in and resolves again' {
            $m = Get-TestManager
            $in = Join-Path $m.Root 'requirements.in'
            [IO.File]::WriteAllText($in, "numpy>=2.0`r`nrequests==2.32.3")
            $txt = Join-Path $m.Root 'requirements.txt'
            Set-WheelhouseSetting -SettingsPath (Join-Path (Join-Path $m.Root 'config') 'settings.psd1') -Updates @{ LocalRequirementsPath = $txt }
            Set-Content -Path $txt -Value @('numpy==2.3.1', 'requests==2.32.3', 'urllib3==2.5.0')

            $review = Invoke-WheelhouseUiApi -Method GET -Path '/api/requirements' -ManagerRoot $m.Root
            (@($review.Body.pending) | Where-Object { $_.name -eq 'requests' }).direct | Should -Be $true
            (@($review.Body.pending) | Where-Object { $_.name -eq 'urllib3' }).direct | Should -Be $false

            (Invoke-WheelhouseUiApi -Method POST -Path '/api/requirements/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"-r evil"}')).Status | Should -Be 400
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/requirements/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"urllib3"}')).Status | Should -Be 404
            $global:WhmUiJobSteps | Should -BeNullOrEmpty

            $result = Invoke-WheelhouseUiApi -Method POST -Path '/api/requirements/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"requests"}')
            $result.Status | Should -Be 200
            @($result.Body.removed) -join '|' | Should -Be 'requests==2.32.3'
            (Get-Content -Path $in) -join '|' | Should -Be 'numpy>=2.0'
            $global:WhmUiJobSteps -join '|' | Should -Be 'Update-Requirement.ps1'
        }

        It 'clears every requirement still waiting to be published' {
            $m = Get-TestManager
            $in = Join-Path $m.Root 'requirements.in'
            # six is in the test wheelhouse; requests and urllib3 (a dependency) are not.
            [IO.File]::WriteAllText($in, "six`r`nrequests==2.32.3")
            $txt = Join-Path $m.Root 'requirements.txt'
            Set-WheelhouseSetting -SettingsPath (Join-Path (Join-Path $m.Root 'config') 'settings.psd1') -Updates @{ LocalRequirementsPath = $txt }
            Set-Content -Path $txt -Value @('six==1.16.0', 'requests==2.32.3', 'urllib3==2.5.0')

            $result = Invoke-WheelhouseUiApi -Method POST -Path '/api/requirements/clear' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{}')
            $result.Status | Should -Be 200
            @($result.Body.removed) -join '|' | Should -Be 'requests==2.32.3'
            (Get-Content -Path $in) -join '|' | Should -Be 'six'
            $global:WhmUiJobSteps -join '|' | Should -Be 'Update-Requirement.ps1'

            # Nothing listed is waiting any more: refused.
            Set-Content -Path $txt -Value @('six==1.16.0', 'urllib3==2.5.0')
            $none = Invoke-WheelhouseUiApi -Method POST -Path '/api/requirements/clear' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{}')
            "$($none.Status) $($none.Body.error)" | Should -Match '^409 Nothing to clear'

            # Clearing the last requirement empties requirements.txt instead of resolving nothing.
            $global:WhmUiJobSteps = $null
            [IO.File]::WriteAllText($in, 'requests==2.32.3')
            Set-Content -Path $txt -Value @('requests==2.32.3')
            $last = Invoke-WheelhouseUiApi -Method POST -Path '/api/requirements/clear' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{}')
            $last.Status | Should -Be 200
            $last.Body.job | Should -BeNullOrEmpty
            $global:WhmUiJobSteps | Should -BeNullOrEmpty
            (Get-Content -Path $txt) -join '|' | Should -Not -Match 'requests'
        }

        It 'shows requirements.txt for review and publishes it only with a confirmation' {
            $m = Get-TestManager
            $txt = Join-Path $m.Root 'requirements.txt'
            Set-WheelhouseSetting -SettingsPath (Join-Path (Join-Path $m.Root 'config') 'settings.psd1') -Updates @{ LocalRequirementsPath = $txt }

            $empty = Invoke-WheelhouseUiApi -Method GET -Path '/api/requirements' -ManagerRoot $m.Root
            $empty.Status | Should -Be 200
            $empty.Body.pin_count | Should -Be 0

            Set-Content -Path $txt -Value @('# via uv', 'numpy==2.3.1', 'pandas==2.2.3')
            $review = Invoke-WheelhouseUiApi -Method GET -Path '/api/requirements' -ManagerRoot $m.Root
            $review.Body.pin_count | Should -Be 2
            $review.Body.text | Should -Match 'numpy==2.3.1'

            (Invoke-WheelhouseUiApi -Method POST -Path '/api/wheelhouse/update' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{}')).Status | Should -Be 400
            $global:WhmUiJobSteps | Should -BeNullOrEmpty
            $publish = Invoke-WheelhouseUiApi -Method POST -Path '/api/wheelhouse/update' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"confirm":true}')
            $publish.Status | Should -Be 202
            $global:WhmUiJobSteps -join '|' | Should -Be 'Update-Wheelhouse.ps1'
        }

        It 'saves on/off settings' {
            $m = Get-TestManager
            $saved = Invoke-WheelhouseUiApi -Method POST -Path '/api/settings' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"updates":{"AutoQuarantine":false}}')
            $saved.Status | Should -Be 200
            (Get-WheelhouseSetting -SettingsPath (Join-Path (Join-Path $m.Root 'config') 'settings.psd1')).AutoQuarantine | Should -Be $false
            $values = (Invoke-WheelhouseUiApi -Method GET -Path '/api/settings' -ManagerRoot $m.Root).Body.values
            $values['AutoQuarantine'] | Should -Be $false
            $values['RequireDefenderScanAtIntake'] | Should -Be $false
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/settings' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"updates":{"RequireDefenderScanAtIntake":"maybe"}}')).Status | Should -Be 400
        }

        It 'quarantines through the API, denylists the package and lists both' {
            $m = Get-TestManager
            $body = ConvertFrom-TestJson '{"packages":[{"name":"six","version":"1.16.0"}],"mode":"quarantine","reason":"suspicious"}'
            $removed = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/remove' -ManagerRoot $m.Root -Body $body
            $removed.Status | Should -Be 200
            $removed.Body.results[0].ok | Should -Be $true

            $quarantine = Invoke-WheelhouseUiApi -Method GET -Path '/api/quarantine' -ManagerRoot $m.Root
            @($quarantine.Body.items).Count | Should -Be 1
            $quarantine.Body.items[0].reason | Should -Be 'suspicious'
            $deny = Invoke-WheelhouseUiApi -Method GET -Path '/api/denylist' -ManagerRoot $m.Root
            @($deny.Body.items).Count | Should -Be 1
            $deny.Body.items[0].source | Should -Be 'quarantined'
            $deny.Body.items[0].installed | Should -Be $false

            $restore = Invoke-WheelhouseUiApi -Method POST -Path '/api/quarantine/restore' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson "{`"id`":`"$($quarantine.Body.items[0].id)`"}")
            $restore.Status | Should -Be 200
            @((Invoke-WheelhouseUiApi -Method GET -Path '/api/denylist' -ManagerRoot $m.Root).Body.items).Count | Should -Be 0
        }

        It 'shows a package version''s state and history' {
            $m = Get-TestManager
            $body = ConvertFrom-TestJson '{"packages":[{"name":"six","version":"1.16.0"}],"mode":"quarantine","reason":"looks odd"}'
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/remove' -ManagerRoot $m.Root -Body $body).Status | Should -Be 200

            $history = Invoke-WheelhouseUiApi -Method GET -Path '/api/packages/Six/1.16.0/history' -ManagerRoot $m.Root
            $history.Status | Should -Be 200
            $history.Body.record.state | Should -Be 'Quarantined'
            $history.Body.events[0].action | Should -Be 'Quarantined'
            $history.Body.events[0].detail | Should -Match 'looks odd'
            # The JSON the browser gets keeps lists as lists.
            ($history.Body | ConvertTo-Json -Depth 8 -Compress) | Should -Match '"events":\['

            (Invoke-WheelhouseUiApi -Method GET -Path '/api/packages/nothing/1.0/history' -ManagerRoot $m.Root).Status | Should -Be 404
            (Invoke-WheelhouseUiApi -Method GET -Path '/api/packages/six/1.0;x/history' -ManagerRoot $m.Root).Status | Should -Be 404
        }

        It 'validates removal requests' {
            $m = Get-TestManager
            $pin = '"packages":[{"name":"six","version":"1.16.0"}]'
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson "{$pin,`"mode`":`"explode`"}")).Status | Should -Be 400
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson "{$pin,`"mode`":`"delete`"}")).Status | Should -Be 400
            @((Invoke-WheelhouseUiApi -Method GET -Path '/api/packages' -ManagerRoot $m.Root).Body.packages).Count | Should -Be 2
        }

        It 'edits the denylist' {
            $m = Get-TestManager
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/denylist/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"Attrs","version":"*","reason":"policy"}')).Status | Should -Be 200
            $list = Invoke-WheelhouseUiApi -Method GET -Path '/api/denylist' -ManagerRoot $m.Root
            $list.Body.items[0].name | Should -Be 'attrs'
            $list.Body.items[0].installed | Should -Be $true
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/denylist/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"bad name"}')).Status | Should -Be 400
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/denylist/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"nothere","version":"*"}')).Status | Should -Be 404
            (Invoke-WheelhouseUiApi -Method POST -Path '/api/denylist/remove' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"name":"attrs","version":"*"}')).Status | Should -Be 200
            @((Invoke-WheelhouseUiApi -Method GET -Path '/api/denylist' -ManagerRoot $m.Root).Body.items).Count | Should -Be 0
        }

        It 'reads and saves settings, rejecting invalid values without saving anything' {
            $m = Get-TestManager
            $settings = Invoke-WheelhouseUiApi -Method GET -Path '/api/settings' -ManagerRoot $m.Root
            $settings.Body.values['WheelhousePath'] | Should -Be $m.Wheelhouse
            @($settings.Body.fields).Count | Should -BeGreaterThan 5

            $bad = Invoke-WheelhouseUiApi -Method POST -Path '/api/settings' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"updates":{"MinimumPackageAgeDays":21,"Platform":"linux"}}')
            $bad.Status | Should -Be 400
            (Get-WheelhouseSetting -SettingsPath (Join-Path (Join-Path $m.Root 'config') 'settings.psd1')).ContainsKey('MinimumPackageAgeDays') | Should -Be $false

            $good = Invoke-WheelhouseUiApi -Method POST -Path '/api/settings' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"updates":{"MinimumPackageAgeDays":21,"VulnerabilityServices":["osv"]}}')
            $good.Status | Should -Be 200
            $saved = Get-WheelhouseSetting -SettingsPath (Join-Path (Join-Path $m.Root 'config') 'settings.psd1')
            $saved.MinimumPackageAgeDays | Should -Be 21
            @($saved.VulnerabilityServices) -join ',' | Should -Be 'osv'
            $saved.WheelhousePath | Should -Be $m.Wheelhouse
        }

        It 'answers 404 for unknown endpoints and jobs' {
            $m = Get-TestManager
            (Invoke-WheelhouseUiApi -Method GET -Path '/api/nothing' -ManagerRoot $m.Root).Status | Should -Be 404
            (Invoke-WheelhouseUiApi -Method GET -Path '/api/jobs/9999' -ManagerRoot $m.Root).Status | Should -Be 404
        }
    }

    Context 'UI jobs' {
        BeforeAll {
            $script:uiRoot = Get-TestFolder
            $script:uiJobs = Join-Path $script:uiRoot 'Jobs'
            New-Item -ItemType Directory -Path $script:uiJobs | Out-Null
            Set-Content -Path (Join-Path $script:uiJobs 'ok.ps1') -Value "param([string]`$Package)`nWrite-Host `"hello from ok `$Package`"`nexit 0"
            Set-Content -Path (Join-Path $script:uiJobs 'bad.ps1') -Value "Write-Host 'bad step'`nexit 3"
            Set-Content -Path (Join-Path $script:uiJobs 'findings.ps1') -Value "Write-Host 'found something'`nexit 1"
            Set-Content -Path (Join-Path $script:uiJobs 'sleep.ps1') -Value 'Start-Sleep -Seconds 120'
            $script:uiContext = [PSCustomObject]@{ ManagerRoot = $script:uiRoot; JobsPath = $script:uiJobs }

            function Wait-UiJob {
                param($Job, [int]$TimeoutSeconds = 90)
                $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
                while ($Job.Status -eq 'Running' -and (Get-Date) -lt $deadline) {
                    Start-Sleep -Milliseconds 250
                    Sync-WheelhouseUiJob
                }
            }
        }

        It 'runs the steps in order and captures the log' {
            $steps = @(@{ Script = 'ok.ps1'; Arguments = @('-Package', 'a==1,b==2') }, @{ Script = 'ok.ps1'; Arguments = @('-Package', 'second') })
            $job = Start-WheelhouseUiJob -Title 'chain' -Kind 'test' -Steps $steps -Context $script:uiContext
            Wait-UiJob -Job $job
            $job.Status | Should -Be 'Succeeded'
            $log = (ConvertTo-WheelhouseUiJobSummary -Job $job -IncludeLog).log
            $log | Should -Match 'hello from ok a==1,b==2'
            $log | Should -Match 'hello from ok second'
        }

        It 'stops at the first failing step' {
            $job = Start-WheelhouseUiJob -Title 'fail' -Kind 'test' -Context $script:uiContext -Steps @(@{ Script = 'bad.ps1'; Arguments = @() }, @{ Script = 'ok.ps1'; Arguments = @() })
            Wait-UiJob -Job $job
            $job.Status | Should -Be 'Failed'
            $job.ExitCode | Should -Be 3
            $job.Message | Should -Match 'another wheelhouse operation'
            (ConvertTo-WheelhouseUiJobSummary -Job $job -IncludeLog).log | Should -Not -Match 'hello from ok'
        }

        It 'reports exit code 1 as needing attention and does not run later steps' {
            $job = Start-WheelhouseUiJob -Title 'findings' -Kind 'test' -Context $script:uiContext -Steps @(@{ Script = 'findings.ps1'; Arguments = @() }, @{ Script = 'ok.ps1'; Arguments = @() })
            Wait-UiJob -Job $job
            $job.Status | Should -Be 'Attention'
            $job.Message | Should -Match 'findings.ps1 finished with findings'
            (ConvertTo-WheelhouseUiJobSummary -Job $job -IncludeLog).log | Should -Not -Match 'hello from ok'
        }

        It 'runs one job at a time and can cancel a running one' {
            $job = Start-WheelhouseUiJob -Title 'sleeper' -Kind 'test' -Context $script:uiContext -Steps @(@{ Script = 'sleep.ps1'; Arguments = @() })
            { Start-WheelhouseUiJob -Title 'second' -Kind 'test' -Context $script:uiContext -Steps @(@{ Script = 'ok.ps1'; Arguments = @() }) } |
                Should -Throw -ExceptionType ([System.InvalidOperationException])
            $stopped = Stop-WheelhouseUiJob -Id $job.Id
            $stopped.Status | Should -Be 'Cancelled'
            Get-WheelhouseUiRunningJob | Should -BeNullOrEmpty
        }
    }
}
