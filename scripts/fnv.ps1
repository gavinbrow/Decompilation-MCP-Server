[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('connect', 'poll', 'status', 'list_bands', 'claim', 'packet', 'submit', 'giveup', 'flag', 'checkpoint', 'function_history')]
    [string]$Command,
    [string]$Json = '{}',
    [string]$InputFile
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$privateDir = Join-Path $root 'local/auth'
$limitFile = Join-Path $root 'local\service-limit.json'
$taskOptional = $Command -in @('flag','checkpoint','function_history')
$contributionPolicy = Join-Path $root 'local/contribution-policy.json'
if ($Command -eq 'flag' -and (Test-Path -LiteralPath $contributionPolicy)) {
    $policy = Get-Content -LiteralPath $contributionPolicy -Raw | ConvertFrom-Json
    if ($policy.flag_enabled -ne $true) { throw 'Flag reporting disabled by owner; give up normally with a precise blocker.' }
}
New-Item -ItemType Directory -Path $privateDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'local') -Force | Out-Null

function Save-PrivateString([string]$Value, [string]$Name) {
    $Value | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString |
        Set-Content -LiteralPath (Join-Path $privateDir $Name) -NoNewline
}
function Read-PrivateString([string]$Name) {
    $path = Join-Path $privateDir $Name
    if ($Name -eq 'api-key.dpapi' -and !(Test-Path -LiteralPath $path)) {
        $path = Join-Path $root 'local\api-key.dpapi'
    }
    if (!(Test-Path -LiteralPath $path)) { throw "Missing $Name; complete connect and poll first." }
    $secure = (Get-Content -LiteralPath $path -Raw).Trim() | ConvertTo-SecureString
    $credential = New-Object System.Management.Automation.PSCredential('fnv', $secure)
    return $credential.GetNetworkCredential().Password
}
function Read-Time($Value) {
    if ($Value -is [DateTime]) { return [DateTimeOffset]$Value }
    return [DateTimeOffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture)
}

foreach ($taskLimitPath in @($limitFile,(Join-Path $root ('local/service-limit-'+$Command+'.json')))) {
if (Test-Path -LiteralPath $taskLimitPath) {
    $limit = Get-Content -LiteralPath $taskLimitPath -Raw | ConvertFrom-Json
    $retryAt = Read-Time $limit.retry_at_utc
    if ([DateTimeOffset]::UtcNow -lt $retryAt -and (!$limit.command -or $limit.command -eq $Command)) {
        if ($taskOptional) {
            @{optional_unavailable=$true;feature=$Command;retry_at_utc=$retryAt.ToString('o');reason=[string]$limit.reason}|ConvertTo-Json -Compress
            return
        }
        throw "Service requests paused until $($retryAt.ToString('o')): $($limit.reason)"
    }
}

}

$headers = @{}
$endpoint = $Command
if ($InputFile) { $Json = Get-Content -LiteralPath $InputFile -Raw }
$null = $Json | ConvertFrom-Json
if ($Command -eq 'flag') {
    $taskFlagPayload=$Json|ConvertFrom-Json
    # All fleet flag calls are report-only; release remains a separate durable op.
    $taskFlagPayload|Add-Member -NotePropertyName keep_claim -NotePropertyValue $true -Force
    $Json=$taskFlagPayload|ConvertTo-Json -Depth 20 -Compress
}
if ($Command -eq 'connect') {
    $Json = @{agent_label = 'Codex FNV workspace'} | ConvertTo-Json -Compress
} elseif ($Command -eq 'poll') {
    $endpoint = 'connect/poll'
    $metaPath = Join-Path $privateDir 'connect.json'
    if (!(Test-Path -LiteralPath $metaPath)) { throw 'Run connect first.' }
    $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
    if ([DateTimeOffset]::UtcNow -ge (Read-Time $meta.expires_at_utc)) {
        throw 'Device approval expired; run connect again.'
    }
    if ([DateTimeOffset]::UtcNow -lt (Read-Time $meta.next_poll_utc)) {
        throw "Do not poll before $($meta.next_poll_utc)."
    }
    $meta.next_poll_utc = [DateTimeOffset]::UtcNow.AddSeconds([int]$meta.interval).ToString('o')
    $meta | ConvertTo-Json | Set-Content -LiteralPath $metaPath
    $Json = @{device_code = (Read-PrivateString 'device.dpapi')} | ConvertTo-Json -Compress
} else {
    $key = $env:FNVDECOMP_API_KEY
    if (!$key) { $key = Read-PrivateString 'api-key.dpapi' }
    $headers.Authorization = "Bearer $key"
}

$readRetry = 0
# Nested claim/packet/download calls can share connection pooling within this
# short-lived helper process. Credentials still come from the existing explicit
# headers; no session or authentication material is serialized.
if (!$global:FNVDecompHttpSession) {
    $global:FNVDecompHttpSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
}
while ($true) {
try {
    $taskTimeout=30
    if ($taskOptional) { $taskTimeout=8 }
    $response = Invoke-RestMethod -Method Post -Uri "https://fnvdecomp.com/api/v1/$endpoint" `
        -Headers $headers -ContentType 'application/json' -Body $Json -TimeoutSec $taskTimeout -WebSession $global:FNVDecompHttpSession
    break
} catch {
    $code = 0
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    # Safe diagnostics identify the endpoint without retaining request bodies,
    # credentials, headers, response bodies or raw exception objects.
    @{utc=[DateTimeOffset]::UtcNow.ToString('o');command=$Command;http_status=$code;exception_type=$_.Exception.GetType().Name;read_retry=$readRetry} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'local/last-api-error.json')
    if ($code -eq 429 -or $code -eq 503) {
        $seconds = 0
        $retryText = $null
        try { $retryText = [string]$_.Exception.Response.Headers['Retry-After'] } catch {}
        if (!$retryText) {
            try { $retryText = [string]$_.Exception.Response.Headers.RetryAfter } catch {}
        }
        $detail = $null
        try { $detail = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
        if ($detail.retry_after_seconds) { $seconds = [int]$detail.retry_after_seconds }
        elseif ($retryText -match '^\d+$') { $seconds = [int]$retryText }
        elseif ($retryText) {
            try { $seconds = [int][Math]::Ceiling(([DateTimeOffset]::Parse($retryText) - [DateTimeOffset]::UtcNow).TotalSeconds) } catch {}
        }
        if ($seconds -le 0) {
            if ($code -eq 503) {
                $seconds = [int][Math]::Ceiling(([DateTimeOffset]::UtcNow.Date.AddDays(1) - [DateTimeOffset]::UtcNow.UtcDateTime).TotalSeconds)
            } else { $seconds = 3600 }
        }
        $reason = "HTTP $code; respect the service retry window"
        if ($detail.error) { $reason = [string]$detail.error }
        # An optional endpoint's429 is isolated unless the response explicitly
        # says the account/shared/global API limit was hit. Hosting503 remains
        # global. Optional calls are never used to work around a shared hold.
        $limitState=@{retry_at_utc = [DateTimeOffset]::UtcNow.AddSeconds($seconds).ToString('o'); reason = $reason}
        $taskSharedLimit=([string]$detail.scope -in @('account','global','shared')) -or ($reason -match '(?i)(account.wide|global|shared|all (API )?requests|daily hosting|infrastructure limit)')
        if ($code -eq 429 -and $taskOptional -and !$taskSharedLimit) { $limitState.command=$Command }
        $taskSaveLimit=$limitFile
        if ($limitState.command) { $taskSaveLimit=Join-Path $root ('local/service-limit-'+$limitState.command+'.json') }
        $taskLimitTemp=$taskSaveLimit+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
        [IO.File]::WriteAllText($taskLimitTemp,($limitState|ConvertTo-Json))
        [IO.File]::Move($taskLimitTemp,$taskSaveLimit,$true)
        if ($taskOptional) {
            @{optional_unavailable=$true;feature=$Command;retry_at_utc=$limitState.retry_at_utc;reason=$reason;scope=$(if($limitState.command){'feature'}else{'global'})}|ConvertTo-Json -Compress
            return
        }
        throw "Service requests paused for $seconds seconds: $reason"
    }
    if ($taskOptional) {
        # No automatic retry, including ambiguous checkpoint timeouts. Persist
        # a short circuit-breaker and let normal work carry on.
        $taskUntil=[DateTimeOffset]::UtcNow.AddMinutes(5).ToString('o')
        $taskOptionalPath=Join-Path $root ('local/service-limit-'+$Command+'.json')
        $taskOptionalTemp=$taskOptionalPath+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
        [IO.File]::WriteAllText($taskOptionalTemp,(@{command=$Command;retry_at_utc=$taskUntil;reason="Optional $Command failed (HTTP $code); no replay"}|ConvertTo-Json))
        [IO.File]::Move($taskOptionalTemp,$taskOptionalPath,$true)
        @{optional_unavailable=$true;feature=$Command;retry_at_utc=$taskUntil;reason="Optional endpoint HTTP $code; continue ordinary work";uncertain=($Command -eq 'checkpoint' -and $code -eq 0)}|ConvertTo-Json -Compress
        return
    }
    # Exactly one retry of read-only operations for transient failures. Mutations
    # must be reconciled against claims/receipts instead of being replayed.
    if ($Command -in @('status','list_bands','packet') -and $code -in @(0,500,502,504) -and $readRetry -eq 0) {
        $retryHeader=$null
        try { $retryHeader=[string]$_.Exception.Response.Headers.RetryAfter } catch {}
        if ($retryHeader) { throw "Read request failed with a server retry window; inspect local/last-api-error.json before retrying." }
        $readRetry++
        Start-Sleep -Seconds 2
        continue
    }
    # Do not emit a web exception that might contain a request with secrets.
    throw "Mojave Decomp $Command request failed (HTTP $code). Check local/last-api-error.json."
}
}

if ($Command -eq 'connect') {
    if (!$response.device_code -or !$response.approve_url) { throw 'Incomplete connect response.' }
    Save-PrivateString $response.device_code 'device.dpapi'
    $interval = [Math]::Max(1, [int]$response.interval)
    $meta = @{
        user_code = $response.user_code; approve_url = $response.approve_url; interval = $interval
        expires_at_utc = [DateTimeOffset]::UtcNow.AddSeconds([int]$response.expires_in).ToString('o')
        next_poll_utc = [DateTimeOffset]::UtcNow.AddSeconds($interval).ToString('o')
    }
    $meta | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $privateDir 'connect.json')
    $meta | ConvertTo-Json
} elseif ($Command -eq 'poll' -and $response.status -eq 'approved') {
    if (!$response.api_key) { throw 'Approved response did not include an API key.' }
    Save-PrivateString $response.api_key 'api-key.dpapi'
    Remove-Item -LiteralPath (Join-Path $privateDir 'device.dpapi') -ErrorAction SilentlyContinue
    Write-Output 'Approved. API key saved with Windows DPAPI; run status next.'
} else {
    $response | ConvertTo-Json -Depth 30
}
