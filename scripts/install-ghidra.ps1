[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$version='12.1.4'
$archiveName='ghidra_12.1.4_PUBLIC_20260921.zip'
$sourceUrl='https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip'
$expected='ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'
$downloadFolder=Join-Path $workspace 'tools/downloads'
$installFolder=Join-Path $workspace 'tools/ghidra'
$destination=Join-Path $installFolder 'ghidra_12.1.4_PUBLIC'
$archive=Join-Path $downloadFolder $archiveName
New-Item -ItemType Directory -Path $downloadFolder -Force | Out-Null
if(!(Test-Path -LiteralPath $archive)) {
    $partial=$archive+'.partial'
    Invoke-WebRequest -Uri $sourceUrl -OutFile $partial -UseBasicParsing -TimeoutSec 600
    if((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected){throw 'Official Ghidra archive hash mismatch'}
    Move-Item -LiteralPath $partial -Destination $archive
}
if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected){throw 'Cached Ghidra archive hash mismatch'}
if(!(Test-Path -LiteralPath (Join-Path $destination 'support/analyzeHeadless.bat'))) {
    if(Test-Path -LiteralPath $destination){throw 'Incomplete installation exists; inspect it before replacing'}
    Expand-Archive -LiteralPath $archive -DestinationPath $installFolder
}
$manifest=@{version=$version;release='Ghidra_12.1.4_build';source=$sourceUrl;sha256=$expected;minimum_jdk=21;installed=$destination;scope='Workspace only; global Java configuration unchanged'}
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $installFolder 'install-manifest.json')
$manifest | ConvertTo-Json
