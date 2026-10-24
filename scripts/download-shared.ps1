[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Packet)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$metadata=Get-Content -LiteralPath $Packet -Raw|ConvertFrom-Json
$secure=(Get-Content -LiteralPath (Join-Path $root 'local/api-key.dpapi') -Raw).Trim()|ConvertTo-SecureString
$credential=New-Object System.Management.Automation.PSCredential('fnv',$secure)
$targets=@{symbols='fnvdecomp_symbols.json';function_index='function_index.json';compiler_tips='compiler_tips.md'}
$hold=Join-Path $root 'local/service-limit.json'
if(Test-Path -LiteralPath $hold){$h=Get-Content -LiteralPath $hold -Raw|ConvertFrom-Json;if([DateTimeOffset]::UtcNow -lt [DateTimeOffset]::Parse($h.retry_at_utc)){throw 'Service hold is active; respect Retry-After.'}}
foreach($name in $targets.Keys){
    $uri=[uri]$metadata.shared_files.$name
    if($uri.Scheme -ne 'https' -or $uri.Host -ne 'fnvdecomp.com'){throw 'Unexpected shared download host.'}
    $destination=Join-Path $root ('local/shared/'+$targets[$name])
    try{
        Invoke-WebRequest -Uri $uri -Headers @{Authorization=('Bearer '+$credential.GetNetworkCredential().Password)} -OutFile ($destination+'.partial') -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 45 | Out-Null
    }catch{
        $code=if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{0}
        if($code -in @(429,503)){
            $seconds=3600
            try{$retry=[string]$_.Exception.Response.Headers['Retry-After'];if($retry -match '^\d+$'){$seconds=[Math]::Max(1,[int]$retry)}elseif($retry){$seconds=[Math]::Max(1,[Math]::Ceiling(([DateTimeOffset]::Parse($retry)-[DateTimeOffset]::UtcNow).TotalSeconds))}}catch{}
            @{retry_at_utc=[DateTimeOffset]::UtcNow.AddSeconds($seconds).ToString('o');reason="Shared download HTTP $code"}|ConvertTo-Json|Set-Content -LiteralPath $hold
        }
        throw "Shared download failed (HTTP $code); no retry was performed."
    }
    Move-Item -LiteralPath ($destination+'.partial') -Destination $destination -Force
}
Write-Output 'Shared metadata saved privately; no credentials printed.'
