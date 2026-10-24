[CmdletBinding()]
param(
    [ValidateSet('doctor','prepare','finish','catalog','batch')][string]$Action = 'doctor',
    [string]$Pack,
    [string]$Candidate,
    [string]$Model,
    [ValidateSet('auto','on','off')][string]$Ghidra = 'auto',
    [switch]$CpuCheck,
    [string]$Manifest,
    [ValidateRange(1,1000)][int]$Limit = 20,
    [ValidateRange(1,4)][int]$Jobs = 2,
    [ValidateRange(1,96)][int]$Checks = 48,
    [ValidateRange(30,600)][int]$Seconds = 180
)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$arguments=@((Join-Path $PSScriptRoot 'decomp-assist.py'),$Action)
if ($Action -in @('prepare','finish')) {
    if (!$Pack) { throw '-Pack is required.' }
    $arguments+=@('--pack',$Pack,'--seconds',[string]$Seconds)
}
if ($Action -eq 'prepare') { $arguments+=@('--ghidra',$Ghidra) }
if ($Action -eq 'finish') {
    if (!$Candidate -or !$Model) { throw '-Candidate and truthful -Model attribution are required.' }
    $arguments+=@('--candidate',$Candidate,'--model',$Model,'--checks',[string]$Checks,'--jobs',[string]$Jobs)
}
if ($Action -in @('batch','catalog')) { $arguments+=@('--limit',[string]$Limit) }
if ($Action -eq 'batch') {
    if (!$Manifest) { throw '-Manifest is required; this is a finite saved-pack batch.' }
    $arguments+=@('--manifest',$Manifest,'--jobs',[string]$Jobs,'--ghidra',$Ghidra)
}
if ($CpuCheck -and $Action -in @('prepare','batch')) { $arguments+='--cpu-check' }
& (Join-Path $root '.venv/Scripts/python.exe') @arguments
exit $LASTEXITCODE
