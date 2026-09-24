@{
    RootModule        = 'WheelhouseManager.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = '5b0f7c1e-3f4e-4c8e-9a51-0c6d2f7e9a14'
    Description       = 'Shared functions for the wheelhouse manager scripts (Jobs\*.ps1, Setup.ps1, Invoke-WheelhousePipeline.ps1).'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Write-Log',
        'Get-NormalizedPackageName',
        'ConvertTo-HtmlSafe',
        'Write-TextFileAtomic',
        'Write-JsonFile',
        'Invoke-NativeCommand',
        'Get-WheelhouseDefaultSetting',
        'Get-WheelhouseSettingsPath',
        'Get-WheelhouseSetting',
        'Resolve-Setting',
        'Resolve-WheelhouseParameter',
        'ConvertTo-Psd1Literal',
        'Save-WheelhouseSetting',
        'Set-WheelhouseSetting',
        'Initialize-ManagerFile',
        'Read-RequirementFile',
        'Get-GroupFileNumber',
        'Get-WheelhouseGroupFile',
        'Get-RequirementMergePlan',
        'Add-RequirementToGroupFile',
        'ConvertTo-UvPythonPlatform',
        'Test-RequirementWheelAvailability',
        'Get-WheelFileInfo',
        'Get-WheelhouseManifestPath',
        'Read-WheelhouseManifest',
        'Save-WheelhouseManifest',
        'Test-ManifestIntegrity',
        'Get-UntrackedWheelFile',
        'Assert-WheelhouseIntegrity',
        'Merge-WheelhouseManifest',
        'Compare-RequirementsAgainstManifest',
        'Get-QuarantineFileName',
        'Confirm-PythonAndTooling',
        'Get-AuditReportPath',
        'Get-AuditReportInfo',
        'Get-PipAuditReport',
        'Get-VulnerableDependencyCount',
        'Invoke-PipAudit',
        'Show-PipAuditFixSuggestion',
        'Invoke-GroupAudit',
        'Test-PackageAge',
        'Get-VulnerabilityFinding',
        'ConvertTo-VulnerabilityAlertHtml',
        'Get-VulnerabilityAlertParameter',
        'Remove-ExpiredReport',
        'Start-WheelhouseRun',
        'Stop-WheelhouseRun'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
