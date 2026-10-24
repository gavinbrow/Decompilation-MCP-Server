[CmdletBinding()]
param([string]$Packet = 'local/packet.json')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$packetPath = $Packet
if (![IO.Path]::IsPathRooted($packetPath)) { $packetPath = Join-Path $root $packetPath }
$metadata = Get-Content -LiteralPath $packetPath -Raw | ConvertFrom-Json
$uri = [uri]$metadata.shared_files.fnvcheck
if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'fnvdecomp.com') { throw 'Expected documented HTTPS checker URL from a saved packet.' }
$limitPath = Join-Path $root 'local/service-limit.json'
if (Test-Path -LiteralPath $limitPath) {
    $limit = Get-Content -LiteralPath $limitPath -Raw | ConvertFrom-Json
    if ([DateTimeOffset]::UtcNow -lt [DateTimeOffset]::Parse($limit.retry_at_utc)) { throw "Service paused until $($limit.retry_at_utc)." }
}
$stage = Join-Path $root ('tools/checker-staging/' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
$null = New-Item -ItemType Directory -Path $stage -Force
$secure = (Get-Content -LiteralPath (Join-Path $root 'local/api-key.dpapi') -Raw).Trim() | ConvertTo-SecureString
$credential = New-Object System.Management.Automation.PSCredential('fnv', $secure)
$archive = Join-Path $stage 'fnvcheck.tar.gz'
try {
    $null = Invoke-WebRequest -Uri $uri -Headers @{Authorization=('Bearer ' + $credential.GetNetworkCredential().Password)} -OutFile ($archive + '.partial') -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 45
} catch {
    $code = 0; $retryText = $null
    if ($_.Exception.Response) {
        $code = [int]$_.Exception.Response.StatusCode
        try { $retryText = [string]$_.Exception.Response.Headers['Retry-After'] } catch {}
        if (!$retryText) { try { $retryText = [string]$_.Exception.Response.Headers.RetryAfter } catch {} }
    }
    if ($code -in @(429,503)) {
        $seconds = 3600
        if ($retryText -match '^\d+$') { $seconds = [Math]::Max(1,[int]$retryText) }
        elseif ($retryText) { try { $seconds = [Math]::Max(1,[Math]::Ceiling(([DateTimeOffset]::Parse($retryText)-[DateTimeOffset]::UtcNow).TotalSeconds)) } catch {} }
        @{retry_at_utc=[DateTimeOffset]::UtcNow.AddSeconds($seconds).ToString('o');reason="Checker download HTTP $code"} | ConvertTo-Json | Set-Content -LiteralPath $limitPath
    }
    throw "Checker download failed (HTTP $code); no installed files changed."
}
Move-Item -LiteralPath ($archive + '.partial') -Destination $archive
$entries = @(& tar -tzf $archive)
if ($LASTEXITCODE -ne 0) { throw 'Invalid checker archive.' }
foreach ($entry in $entries) {
    if ($entry -match '(^[/\\]|^[A-Za-z]:|(^|[/\\])\.\.([/\\]|$))') { throw 'Unsafe checker archive path.' }
}
& tar -xzf $archive -C $stage
if ($LASTEXITCODE -ne 0) { throw 'Checker extraction failed.' }
$entrypoint = Get-ChildItem -LiteralPath $stage -Recurse -Filter fnvcheck.py | Select-Object -First 1
if (!$entrypoint) { throw 'Checker entry point missing.' }
$helpText = (& (Join-Path $root '.venv/Scripts/python.exe') $entrypoint.FullName --help 2>&1 | Out-String)
$helpCode = $LASTEXITCODE
$helpText | Set-Content -LiteralPath (Join-Path $stage 'help.txt')
$files = @(Get-ChildItem -LiteralPath $entrypoint.DirectoryName -Recurse -File | Where-Object { $_.Extension -ne '.pyc' } | ForEach-Object {
    @{path=[IO.Path]::GetRelativePath($entrypoint.DirectoryName,$_.FullName);sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
$report = @{utc=[DateTimeOffset]::UtcNow.ToString('o');download_url=$uri.AbsoluteUri;archive_sha256=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash;stage=$stage;entrypoint=$entrypoint.FullName;help_exit_code=$helpCode;solve_slots=($helpCode -eq 0 -and $helpText.Contains('--solve-slots'));permute=($helpCode -eq 0 -and $helpText.Contains('--permute'));installed_changed=$false;files=$files}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'local/checker-capabilities.json')
$report | Select-Object utc,stage,help_exit_code,solve_slots,permute,installed_changed | ConvertTo-Json
