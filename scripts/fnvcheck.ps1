param(
    [Parameter(Mandatory=$true)][string]$Pack,
    [Parameter(Mandatory=$true)][string]$Candidate,
    [string]$Worker = 'coordinator',
    [string]$Image,
    [switch]$Json,
    [switch]$Official,
    [ValidateRange(1,10000)][int]$DiffLines = 70,
    [switch]$Score,
    [switch]$SolveSlots,
    [switch]$Permute,
    [ValidateRange(1,10000)][int]$Trials = 300,
    [ValidateRange(1,8)][int]$Jobs = 2
)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$env:FNVCHECK_TOOLS = Join-Path $workspace 'tools/fnvcheck/fnvcheck'
$env:FNVCHECK_INDEX = Join-Path $workspace 'local/shared/function_index.json'
$env:FNVCHECK_SYMBOLS = Join-Path $workspace 'local/shared/fnvdecomp_symbols.json'
$settings = Get-Content (Join-Path $workspace 'local/settings.json') -Raw | ConvertFrom-Json
if ($Image) {
    $env:FNVCHECK_IMAGE = (Resolve-Path $Image).Path
} elseif ($settings.checker_image) {
    $env:FNVCHECK_IMAGE = $settings.checker_image
} else {
    $env:FNVCHECK_IMAGE = $settings.game_exe
}
$env:FNVCHECK_CACHE = Join-Path $workspace ('work/' + $Worker + '/checker-cache')
$env:FNV_MSVC9_WRAPPER = Join-Path $workspace 'scripts/vc2008.cmd'
$env:FNV_MSVC9_ROOT = Join-Path $workspace 'tools/vc2008'
$checkerArgs = @((Join-Path $PSScriptRoot 'checker-runtime.py'), '--pack', (Resolve-Path $Pack).Path, (Resolve-Path $Candidate).Path)
if ($Json) { $checkerArgs += '--json' }
if ($Official) { $checkerArgs += '--official' }
$checkerArgs += @('--diff-lines',[string]$DiffLines)
if ($Score) { $checkerArgs += '--score' }
if ($SolveSlots) { $checkerArgs += '--solve-slots' }
if ($Permute) { $checkerArgs += @('--permute','--trials',[string]$Trials,'--jobs',[string]$Jobs) }
& (Join-Path $workspace '.venv/Scripts/python.exe') @checkerArgs
exit $LASTEXITCODE
