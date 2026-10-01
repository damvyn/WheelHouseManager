# Pester tests for the WheelhouseManager module (Pester 5; also runs on Pester 4.10).
#   Invoke-Pester -Path .\Tests

# Mock bodies run in the module's scope, so test-case values reach them via globals.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
param()

Describe 'WheelhouseManager' {
    BeforeAll {
        $modulePath = Join-Path (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Jobs') 'WheelhouseManager'
        Import-Module $modulePath -Force

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
        Remove-Variable -Name WhmMockExitCode, WhmMockReport, WhmPipInstalls, WhmPipChecks, WhmIntakeAudit, WhmIntakeDownloaded, WhmIntakeCandidates, WhmScanDetections, WhmUiJobSteps -Scope Global -ErrorAction SilentlyContinue
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
        It 'rejects each failing package with its reason and accepts only what was downloaded' {
            $folder = Get-TestFolder
            $vulnReport = Join-Path $folder 'Report_PreDownload-requirements-1-candidates-OSV_20260101_000000.json'
            Set-Content -Path $vulnReport -Value '{"dependencies":[{"name":"VulnPkg","version":"1.0","vulns":[{"id":"PYSEC-1"}]},{"name":"good","version":"1.0","vulns":[]}]}'

            $global:WhmIntakeAudit = @([PSCustomObject]@{ Stage = 'PreDownload'; Group = 'requirements-1-candidates'; Service = 'osv'; Status = 'Vulnerable'; ReportPath = $vulnReport; Message = 'm' })
            Mock -ModuleName WheelhouseManager -CommandName Invoke-GroupAudit -MockWith { , $global:WhmIntakeAudit }
            Mock -ModuleName WheelhouseManager -CommandName Test-PackageAge -MockWith {
                @{
                    TooNew  = @('fresh==1.0')
                    Results = @(
                        foreach ($name in $Packages.Keys) {
                            [PSCustomObject]@{ Package = $name; Version = $Packages[$name]; AgeDays = $(if ($name -eq 'fresh') { 2 } else { 400 }); Passed = ($name -ne 'fresh') }
                        }
                    )
                }
            }
            Mock -ModuleName WheelhouseManager -CommandName Invoke-PipPinRetry -MockWith {
                $global:WhmIntakeDownloaded = @($Packages.Keys | Sort-Object)
                $ok = @{} + $Packages
                $ok.Remove('nowheel')
                @{ Succeeded = $ok; Failed = @("nowheel==$($Packages['nowheel'])"); Error = $null }
            }

            $intakeParams = @{
                Packages       = @{ good = '1.0'; vulnpkg = '1.0'; fresh = '1.0'; nowheel = '2.0' }
                GroupName      = 'requirements-1'
                WheelhousePath = $folder
                ReportsFolder  = $folder
                Services       = @('osv')
                MinimumAgeDays = 10
                PythonVersion  = '3.14'
                Platform       = 'win_amd64'
            }
            $result = Invoke-CandidateIntake @intakeParams

            ($result.Accepted.Keys -join ',') | Should -Be 'good'
            $reasons = @{}
            foreach ($item in $result.Rejected) { $reasons[$item.Name] = $item.Reason }
            ($reasons.Keys | Sort-Object) -join ',' | Should -Be 'fresh,nowheel,vulnpkg'
            $reasons['vulnpkg'] | Should -Match 'PYSEC-1'
            $reasons['fresh'] | Should -Match 'published 2 day'
            $reasons['nowheel'] | Should -Match 'no downloadable wheel'
            # Rejected packages are never passed on to the next step.
            ($global:WhmIntakeDownloaded -join ',') | Should -Be 'good,nowheel'
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
                WheelhousePath = $folder
                ReportsFolder  = $folder
                Services       = @('osv')
                MinimumAgeDays = 10
                PythonVersion  = '3.14'
                Platform       = 'win_amd64'
            }
            $result = Invoke-CandidateIntake @intakeParams

            $result.Accepted.Count | Should -Be 0
            @($result.Rejected).Count | Should -Be 2
            $result.Rejected[0].Reason | Should -Match 'could not be completed'
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
            Mock -ModuleName WheelhouseManager -CommandName Test-PackageAge -MockWith {
                @{ TooNew = @(); Results = @(foreach ($n in $Packages.Keys) { [PSCustomObject]@{ Package = $n; Version = $Packages[$n]; AgeDays = 400; Passed = $true } }) }
            }
            Mock -ModuleName WheelhouseManager -CommandName Invoke-PipPinRetry -MockWith { @{ Succeeded = $Packages; Failed = @(); Error = $null } }

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
            }
            $result = Invoke-CandidateIntake @intakeParams

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
                WheelhousePath = $folder
                ReportsFolder  = $folder
                Services       = @('osv')
                MinimumAgeDays = 10
                PythonVersion  = '3.14'
                Platform       = 'win_amd64'
                Denylist       = @([PSCustomObject]@{ name = 'evil'; version = '*'; reason = ''; source = 'manual' })
            }
            $result = Invoke-CandidateIntake @intakeParams
            $result.Accepted.Count | Should -Be 0
            @($result.Rejected).Count | Should -Be 1
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

        It 'does not touch the file when nothing is added' {
            $path = Join-Path (Get-TestFolder) 'requirements.in'
            $result = Add-RequirementInLine -Path $path -Spec @('-e .')
            @($result.Added).Count | Should -Be 0
            Test-Path -Path $path | Should -Be $false
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
            $global:WhmUiJobSteps -join '|' | Should -Be 'Update-Requirement.ps1|Update-Wheelhouse.ps1'

            $null = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"specs":["pandas"],"resolve_only":true}')
            $global:WhmUiJobSteps -join '|' | Should -Be 'Update-Requirement.ps1'

            $global:WhmUiJobSteps = $null
            $none = Invoke-WheelhouseUiApi -Method POST -Path '/api/packages/add' -ManagerRoot $m.Root -Body (ConvertFrom-TestJson '{"specs":["numpy"]}')
            $none.Body.job | Should -BeNullOrEmpty
            $global:WhmUiJobSteps | Should -BeNullOrEmpty
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
