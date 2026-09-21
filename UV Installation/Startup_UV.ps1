$LocalCache = 'C:\uv-cache'
# Use only managed Python installation
[System.Environment]::SetEnvironmentVariable('UV_PYTHON_DOWNLOADS', 'never', "Machine")
[System.Environment]::SetEnvironmentVariable('UV_PYTHON_PREFERENCE', 'only-system', "Machine")

# switch from global to local cache
$null = New-Item -Path $LocalCache -ItemType Directory -Force
[System.Environment]::SetEnvironmentVariable('UV_LINK_MODE', 'copy', "Machine")
[System.Environment]::SetEnvironmentVariable('UV_CACHE_DIR', $LocalCache, "Machine")
[System.Environment]::SetEnvironmentVariable('UV_NO_INDEX', 'true', "Machine")

# REPLACE \\\\server\\pathToWhellHouse
$uvConfig = @(
    '[[index]]',
    'name = "internal-wheelhouse"',
    'url = "\\\\server\\pathToWheelHouse"',
    'format = "flat"',
    'default = true',
    'no-index = true'
)
$uvConfigPath = "$env:PROGRAMDATA\uv\uv.toml"
$null = New-Item -Path $uvConfigPath -Force -ItemType File
$uvConfig -join "`n" | Out-File -FilePath $uvConfigPath -Encoding utf8