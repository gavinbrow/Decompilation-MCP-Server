[CmdletBinding()]
param([string]$SevenZip = 'C:\Program Files\7-Zip\7z.exe')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$downloads = Join-Path $root 'tools\downloads'
$destination = Join-Path $root 'tools\vc2008'
$iso = Join-Path $downloads 'VS2008ExpressWithSP1ENUX1504728.iso'
$url = 'https://download.microsoft.com/download/E/8/E/E8EEB394-7F42-4963-A2D8-29559B738298/VS2008ExpressWithSP1ENUX1504728.iso'
if (!(Test-Path -LiteralPath $SevenZip)) { throw '7-Zip is required; supply -SevenZip with its executable path.' }
New-Item -ItemType Directory -Path $downloads,$destination -Force | Out-Null
if (!(Test-Path -LiteralPath $iso)) {
    Invoke-WebRequest -Uri $url -OutFile "$iso.partial" -UseBasicParsing
    Move-Item -LiteralPath "$iso.partial" -Destination $iso
}
if ((Get-Item -LiteralPath $iso).Length -ne 784902144) { throw 'Unexpected compiler ISO size.' }
function Expand-Archive7([string]$Archive, [string]$Output, [string[]]$Entries = @()) {
    & $SevenZip x $Archive "-o$Output" @Entries -y -bso0
    if ($LASTEXITCODE -ne 0) { throw "Archive extraction failed: $Archive" }
}

# Read Windows Installer tables to restore names and directories without running
# setup/custom actions, changing machine settings, or requiring administrator access.
function Copy-MsiPayload([string]$Msi, [string]$Raw, [hashtable]$Anchors) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.OpenDatabase($Msi, 0)
    $dirs = @{}
    $components = @{}
    $view = $db.OpenView('SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`')
    $view.Execute()
    while ($row = $view.Fetch()) { $dirs[$row.StringData(1)] = @($row.StringData(2), $row.StringData(3)) }
    $view.Close()
    function Resolve-PayloadDirectory([string]$Id) {
        foreach ($pattern in $Anchors.Keys) { if ($Id -match $pattern) { return $Anchors[$pattern] } }
        if (!$dirs.ContainsKey($Id)) { return $null }
        $entry = $dirs[$Id]
        $parent = Resolve-PayloadDirectory $entry[0]
        if (!$parent) { return $null }
        $name = (($entry[1] -split ':')[0] -split '\|')[-1]
        if ($name -eq '.') { return $parent }
        return Join-Path $parent $name
    }
    $view = $db.OpenView('SELECT `Component`, `Directory_` FROM `Component`')
    $view.Execute()
    while ($row = $view.Fetch()) { $components[$row.StringData(1)] = $row.StringData(2) }
    $view.Close()
    $count = 0
    $view = $db.OpenView('SELECT `File`, `Component_`, `FileName` FROM `File`')
    $view.Execute()
    while ($row = $view.Fetch()) {
        $dir = Resolve-PayloadDirectory $components[$row.StringData(2)]
        if (!$dir) { continue }
        $name = ($row.StringData(3) -split '\|')[-1]
        $source = Join-Path $Raw $row.StringData(1)
        if (!(Test-Path -LiteralPath $source)) { throw "Missing MSI payload: $source" }
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination (Join-Path $dir $name) -Force
        $count++
    }
    $view.Close()
    Write-Output "Restored $count compiler/SDK files from $(Split-Path $Msi -Leaf)."
}

Expand-Archive7 $iso (Join-Path $downloads 'iso') @('VCExpress\Ixpvc.exe', 'VCExpress\eula.1033.txt', 'VCExpress\WCU\WinSDK\WinSDK_Build.exe')
$vcPackage = Join-Path $downloads 'vc-package'
Expand-Archive7 (Join-Path $downloads 'iso\VCExpress\Ixpvc.exe') $vcPackage
$vcRaw = Join-Path $downloads 'vc-raw'
Expand-Archive7 (Join-Path $vcPackage 'vs_setup.cab') $vcRaw
Copy-MsiPayload (Join-Path $vcPackage 'vs_setup.msi') $vcRaw @{
    '^VC7\.' = (Join-Path $destination 'VC')
    '^CommonIDE\.' = (Join-Path $destination 'Common7\IDE')
}
$sdkPackage = Join-Path $downloads 'sdk-package'
Expand-Archive7 (Join-Path $downloads 'iso\VCExpress\WCU\WinSDK\WinSDK_Build.exe') $sdkPackage
$sdkRaw = Join-Path $downloads 'sdk-raw'
foreach ($cab in Get-ChildItem -LiteralPath $sdkPackage -Filter '*.cab') { Expand-Archive7 $cab.FullName $sdkRaw }
Copy-MsiPayload (Join-Path $sdkPackage 'VistaClientHeadersLibs-x86.msi') $sdkRaw @{
    '^INSTALLLOCATION$' = (Join-Path $destination 'VC\PlatformSDK')
}

$bin = Join-Path $destination 'VC\bin'
foreach ($name in @('mspdb80.dll', 'mspdbsrv.exe', 'mspdbcore.dll')) {
    $source = Join-Path $destination "Common7\IDE\$name"
    if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $bin -Force }
}
$crt = Join-Path $destination 'VC\redist\x86\Microsoft.VC90.CRT'
if (Test-Path -LiteralPath $crt) {
    New-Item -ItemType Directory -Path (Join-Path $bin 'Microsoft.VC90.CRT') -Force | Out-Null
    Copy-Item -Path "$crt\*" -Destination (Join-Path $bin 'Microsoft.VC90.CRT') -Force
}
Copy-Item -LiteralPath (Join-Path $downloads 'iso\VCExpress\eula.1033.txt') -Destination (Join-Path $destination 'eula.1033.txt') -Force
$cl = Join-Path $bin 'cl.exe'
$version = ((Get-Item -LiteralPath $cl).VersionInfo.FileVersion -split '\s+')[0]
if ($version -ne '15.00.30729.01') { throw "Incorrect compiler version: $version" }
@{source_url=$url;iso_sha256=(Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash;cl_sha256=(Get-FileHash -LiteralPath $cl -Algorithm SHA256).Hash;compiler_version=$version;method='Original MSI payload extraction; no compiler modifications';installed_at_utc=[DateTimeOffset]::UtcNow.ToString('o')} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'provenance.json')
Write-Output "Official VC2008 SP1 compiler ready: $version"
