# Loads every function file under Functions\. The order below is only for
# readability - functions are resolved at call time, not at load time.

# Manager root = the folder containing Jobs\, config\ and Input\ (two levels up).
$script:ManagerRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

foreach ($file in @('Common', 'Settings', 'Requirements', 'Manifest', 'Audit', 'Alert', 'Run')) {
    . (Join-Path (Join-Path $PSScriptRoot 'Functions') "$file.ps1")
}
