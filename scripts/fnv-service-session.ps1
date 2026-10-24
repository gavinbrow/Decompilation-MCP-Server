# Private stdin/stdout transport. No autonomous claims, scheduler or listener.
$ErrorActionPreference='Stop'
$taskRoot=Split-Path $PSScriptRoot -Parent
while($null -ne ($taskLine=[Console]::In.ReadLine())) {
 try {
  $taskRequest=$taskLine|ConvertFrom-Json
  $taskAllowed=@{
   'fnv.ps1'=@('Command','Json');'claim-pack.ps1'=@('Band','Prefer','ContextMode');'claim-reserve.ps1'=@('Band','Prefer','BeforeStatusFile','ContextMode');'claim-batch-reserve.ps1'=@('RequestsFile');'cpu-claim-batch-reserve.ps1'=@('RequestsFile');'download-pack.ps1'=@('Pack')
  }
  if(!$taskAllowed.ContainsKey([string]$taskRequest.script)){throw 'Unsupported helper'}
  $taskParameters=@{}
  foreach($taskProperty in $taskRequest.parameters.PSObject.Properties){
   if($taskProperty.Name -notin $taskAllowed[[string]$taskRequest.script]){throw 'Unsupported parameter'}
   $taskParameters[$taskProperty.Name]=[string]$taskProperty.Value
  }
  if($taskRequest.script -eq 'fnv.ps1' -and $taskParameters.Command -notin @('status','packet','giveup','flag','checkpoint','function_history')){throw 'Unsupported API operation'}
  if($taskRequest.script -eq 'download-pack.ps1'){
   $taskPack=[IO.Path]::GetFullPath($taskParameters.Pack)
   if(!$taskPack.StartsWith((Join-Path $taskRoot 'work\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Pack outside private work folder'}
  }
  $taskOutput=@(& (Join-Path $PSScriptRoot $taskRequest.script) @taskParameters)
  $taskValue=($taskOutput -join "`n")|ConvertFrom-Json
  [Console]::Out.WriteLine((@{id=$taskRequest.id;ok=$true;value=$taskValue}|ConvertTo-Json -Depth 40 -Compress))
 } catch {
  # Raw exceptions/headers/bodies never leave this transport.
  [Console]::Out.WriteLine((@{id=$taskRequest.id;ok=$false;error='Helper failed; inspect existing safe API/download diagnostics'}|ConvertTo-Json -Compress))
 }
}
