# Pester tests for the WheelhouseManager module (Pester 5; also runs on Pester 4.10).
#   Invoke-Pester -Path .\Tests

# Mock bodies run in the module's scope, so test-case values reach them via globals.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
# $examplesPath is set in BeforeAll and used inside It blocks.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param()

Describe 'WheelhouseManager' {
    BeforeAll {
        $modulePath = Join-Path (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Jobs') 'WheelhouseManager'
        Import-Module $modulePath -Force
        $examplesPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Examples'

        function Get-TestFolder {
            $path = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $path | Out-Null
            return $path
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
        Remove-Variable -Name WhmMockExitCode, WhmMockReport, WhmPipInstalls, WhmPipChecks, WhmIntakeAudit -Scope Global -ErrorAction SilentlyContinue
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

        It 'parses the uv-generated example file' {
            $packages = Read-RequirementFile -FilePath (Join-Path $examplesPath 'requirements.txt')
            $packages['anyio'] | Should -Be '4.15.1'
            $packages.Count | Should -BeGreaterThan 10
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
            $example = Join-Path $examplesPath 'Report_Scheduled-OSV_20260921_153000.json'
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
            Copy-Item -Path (Join-Path $examplesPath 'Report_Scheduled-OSV_20260921_153000.json') -Destination $osv
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
            Assert-MockCalled -ModuleName WheelhouseManager -CommandName Invoke-PipPinRetry -Times 1 -Exactly -ParameterFilter { -not $Packages.ContainsKey('vulnpkg') -and -not $Packages.ContainsKey('fresh') }
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
            Copy-Item -Path (Join-Path $examplesPath 'Report_Scheduled-OSV_20260921_153000.json') -Destination $report

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
}
