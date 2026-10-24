[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Pack)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$directory=(Resolve-Path -LiteralPath $Pack).Path
$packet=Get-Content -LiteralPath (Join-Path $directory 'packet.json') -Raw | ConvertFrom-Json
$uri=[uri]$packet.pack_url
if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'fnvdecomp.com') { throw 'Unexpected context download host.' }
$limitFile=Join-Path $root 'local/service-limit.json'
if (Test-Path -LiteralPath $limitFile) {
    $limit=Get-Content -LiteralPath $limitFile -Raw | ConvertFrom-Json
    if ([DateTimeOffset]::UtcNow -lt [DateTimeOffset]::Parse([string]$limit.retry_at_utc)) {
        throw "Service requests paused until $($limit.retry_at_utc)."
    }
}
$secure=(Get-Content -LiteralPath (Join-Path $root 'local/api-key.dpapi') -Raw).Trim() | ConvertTo-SecureString
$credential=New-Object System.Management.Automation.PSCredential('fnv',$secure)
$temporary=Join-Path $directory 'pack.tar.gz.partial'
$started=[DateTimeOffset]::UtcNow
try {
    if (!$global:FNVDecompHttpSession) {
        $global:FNVDecompHttpSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    }
    Invoke-WebRequest -Uri $uri -Headers @{Authorization=('Bearer '+$credential.GetNetworkCredential().Password)} `
        -OutFile $temporary -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 45 -WebSession $global:FNVDecompHttpSession
} catch {
    $code=0
    $response=$_.Exception.Response
    if ($response) { $code=[int]$response.StatusCode }
    $retryText=$null
    if ($response) {
        try { $retryText=[string]$response.Headers.RetryAfter } catch {}
        if (!$retryText) { try { $retryText=[string]$response.Headers['Retry-After'] } catch {} }
    }
    $detail=$null
    try { $detail=$_.ErrorDetails.Message | ConvertFrom-Json } catch {}
    if ($code -eq 429 -or $code -eq 503) {
        $seconds=0
        if ($detail.retry_after_seconds) { $seconds=[int]$detail.retry_after_seconds }
        elseif ($retryText -match '^\d+$') { $seconds=[int]$retryText }
        elseif ($retryText) { try { $seconds=[int][Math]::Ceiling(([DateTimeOffset]::Parse($retryText)-[DateTimeOffset]::UtcNow).TotalSeconds) } catch {} }
        if ($seconds -le 0) { $seconds=3600; if ($code -eq 503) { $seconds=[int][Math]::Ceiling(([DateTimeOffset]::UtcNow.Date.AddDays(1)-[DateTimeOffset]::UtcNow.UtcDateTime).TotalSeconds) } }
        @{retry_at_utc=[DateTimeOffset]::UtcNow.AddSeconds($seconds).ToString('o');reason="Context download HTTP $code; respect service retry window"} | ConvertTo-Json | Set-Content -LiteralPath $limitFile
    }
    # Deliberately retain only safe diagnostics, never request headers or raw exceptions.
    @{utc=[DateTimeOffset]::UtcNow.ToString('o');http_status=$code;exception_type=$_.Exception.GetType().Name;elapsed_seconds=([DateTimeOffset]::UtcNow-$started).TotalSeconds;retry_after=$retryText} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'download-error.json')
    throw "Context download failed (HTTP $code); inspect download-error.json and local/service-limit.json before retrying."
}
Move-Item -LiteralPath $temporary -Destination (Join-Path $directory 'pack.tar.gz') -Force
& (Join-Path $root '.venv/Scripts/python.exe') (Join-Path $PSScriptRoot 'safe-extract.py') (Join-Path $directory 'pack.tar.gz') $directory
if ($LASTEXITCODE -ne 0) { throw 'Context pack extraction failed.' }
@{downloaded=$true;bytes=(Get-Item -LiteralPath (Join-Path $directory 'pack.tar.gz')).Length;seconds=([DateTimeOffset]::UtcNow-$started).TotalSeconds} | ConvertTo-Json
