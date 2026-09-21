<#PSScriptInfo
.VERSION
    2.2
.NOTE
    N/A
.PREREQUISITES
    N/A
.EXTERNAL CONFIGURATION ITEMS
    N/A
#>

$PkgName = 'Astral-uv-0.12.16'

$ErrorActionPreference = 'Stop'

function Start-ProductInstall {
    [CmdletBinding()]
    param()

    $InstallDirectory = 'C:\Program Files\astral.sh\uv'
    $ProductVersion = "<AppVerion>"
    $ArchivePath = "$PSScriptRoot\uv-x86_64-pc-windows-msvc.zip"
    $VersionStampPath = "$InstallDirectory\.version"

    If (Test-Path $InstallDirectory) {
        $VersionParams = @{'StampPath'=$VersionStampPath; 'ExpectedVersion'=$ProductVersion}
        if (Test-VersionStamp @Versionparams) {
            Write-InstallLog -Message "$PkgName already at $InstallDirectory (v$ProductVersion)"
            return
        }
        else {
            Write-InstallLog -Message "Clearing previous $InstallDirectory"
            Remove-Item -Path "$InstallDirectory\*" -Recurse -Force
        }
    } else {
        Write-InstallLog -Message "Create $InstallDirectory"
        $null = New-Item -Path $InstallDirectory -ItemType Directory -Force
    }
    
    Write-InstallLog -Message "Expand files to $InstallDirectory"
    Expand-Archive -Path $ArchivePath -DestinationPath $InstallDirectory -Force

    if (-not (Get-ChildItem -Path $InstallDirectory )) {
        Write-InstallLog -Message "Expand produced nothing in $InstallDirectory" -isError
    }

    # Create hardlinks
    foreach ($file in @('uv.exe', 'uvw.exe', 'uvx.exe')) {
        $hardLink = Join-Path -Path "C:\Windows\System32" -ChildPath $file
        $RealPath = Join-Path -Path $InstallDirectory -ChildPath $file
        Write-InstallLog "Create hardlink for $file"
        New-Item -ItemType HardLink -Path $hardLink -Target $RealPath -Force | Out-Null
    }
        
    Set-Content -Path $VersionStampPath -Value $ProductVersion -Force
}


function Test-VersionStamp {
    param(
        [Parameter(Mandatory)] [string] $StampPath,
        [Parameter(Mandatory)] [string] $ExpectedVersion
    )

    if (-not (Test-Path -Path $StampPath)) { return $false }
    $StampedVersion = (Get-Content -Path $StampPath -Raw).Trim()
    if ($StampedVersion -eq $ExpectedVersion) { return $true }
    Write-InstallLog -Message "Version stamp says '$StampedVersion', expected '$ExpectedVersion' - reinstalling"
    return $false
}


# Logging function
function Write-InstallLog {
    [CmdletBinding()]
    param([string]$Message, [switch]$isError )

    if ($isError) {
        $Message = $Message.ToUpper()
        "$(Get-Date) ERROR: $Message".Replace("UserOutput:", '') | Out-File $LogFile -Append
        throw $Message}
    else {
        "$(Get-Date): $Message".Replace("UserOutput:", '') | Out-File $LogFile -Append
        Write-Output $Message }
}

$LogFile = "$env:WinDir\Logs\${PkgName}_Script.txt"
@"
$('='*32) $(Get-Date) $('='*32)
START INSTALLATION FOR ${PkgName}:
"@ | Out-File $LogFile -Append

# Launching main block
try {
    Start-ProductInstall -ErrorAction 'Stop'
    Write-Output "UserOutput:$PkgName setup completed! See $env:WinDir\Logs\${PkgName}_Script.txt for details."
}
catch{
    $msg = "FOUND ERRORS:`n$($_.Exception.Message)`n"
    Write-Error "$PkgName - Installation Failed!`n$msg See $env:WinDir\Logs\${PkgName}_Script.txt for details."
}