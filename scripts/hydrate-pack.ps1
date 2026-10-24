[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Pack)
# READ-ONLY service requests. Never claims, gives up, or submits.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$directory=[IO.Path]::GetFullPath($Pack)
if(!$directory.StartsWith((Join-Path $root 'work\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Pack outside private work folder'}
$claim=Get-Content -LiteralPath (Join-Path $directory 'claim-state.json') -Raw|ConvertFrom-Json
if((Split-Path $directory -Leaf) -ne $claim.claim_id){throw 'Claim folder mismatch'}
if(!(Test-Path -LiteralPath (Join-Path $directory 'pack.json'))){
 $taskPacketBody=@{claim_id=$claim.claim_id}
 if($claim.context_mode -in @('lean','resume')){$taskPacketBody.context_mode=$claim.context_mode}
 $packet=(& (Join-Path $PSScriptRoot 'fnv.ps1') packet -Json ($taskPacketBody|ConvertTo-Json -Compress))|ConvertFrom-Json
 $packet|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $directory 'packet.json')
 $null=& (Join-Path $PSScriptRoot 'download-pack.ps1') -Pack $directory
}
$meta=Get-Content -LiteralPath (Join-Path $directory 'pack.json') -Raw|ConvertFrom-Json
if($meta.symbol -ne $claim.symbol -or $meta.address -ne $claim.address -or $meta.size -ne $claim.size){throw 'Downloaded packet identity mismatch'}
@{claim_id=$claim.claim_id;hydrated=$true}|ConvertTo-Json -Compress
