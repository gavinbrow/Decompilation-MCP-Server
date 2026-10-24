[CmdletBinding()]
param([ValidateSet('server','coordinator','check')][string]$Component='check')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Set-Location $root
$python=Join-Path $root '.venv/Scripts/python.exe'
if($Component -eq 'server'){& $python scripts/fnv-mcp-server.py --http}
elseif($Component -eq 'coordinator'){& $python scripts/coordinator.py}
else{& $python scripts/coordinator.py --check}
exit $LASTEXITCODE
