# Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
@{
    ExcludeRules = @(
        # Write-Log deliberately writes to the console/transcript only, so scripts can
        # return result objects on the output stream without log lines mixed in.
        'PSAvoidUsingWriteHost',
        # Write-Log exists as a cmdlet only in a PowerShell 6.1 compatibility profile;
        # it is not part of Windows PowerShell 5.1 or PowerShell 7.
        'PSAvoidOverwritingBuiltInCmdlets',
        # False positive for 'Write-Output -NoEnumerate <value>' (value is positional).
        'PSUseCmdletCorrectly'
    )
}
