# Get-LEScreenshots.ps1
# PowerShell 5.x compatible
# Uses /publicApi/v7/events?direction=<asc|desc>&count=<N>
# Directory per TEST RUN: "<TestRunId>"
# Filename per event: "<EventTitle>__<EventTimestampUTC><ext>"
# Ext auto-detected by magic bytes (and Content-Type when available).
# Handles response shape with top-level {"items":[ ... ]}.

param(
    [Parameter(Mandatory=$true)]
    [string]$BaseUrl,

    [string]$OutDir = ".\LEScreenshots",

    [string]$BearerToken,
    [string]$ApiKey,

    [ValidateSet('asc','desc')]
    [string]$Direction = "desc",

    [int]$Count = 10000, # note that 10k is the max (default)

    [string]$TestRunId,            # still need to test this for test run ID filter in future
    [switch]$TrustAllCerts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- TLS handling ---
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
if ($TrustAllCerts) {
    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
@"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts {
    public static bool Validator(object sender, X509Certificate cert, X509Chain chain, System.Net.Security.SslPolicyErrors errors) {
        return true;
    }
}
"@ | Add-Type -Language CSharp
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s,$c,$ch,$e) [TrustAllCerts]::Validator($s,$c,$ch,$e) }
}

# --- Headers ---
$headers = @{ 'Accept' = 'application/json' }
if ($BearerToken) { $headers['Authorization'] = "Bearer $BearerToken" }
elseif ($ApiKey)  { $headers['Authorization'] = "Bearer $ApiKey" }

function Ensure-Directory {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { $null = New-Item -ItemType Directory -Path $Path -Force }
    return (Get-Item -LiteralPath $Path).FullName
}

function Sanitize-Name {
    param([string]$name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $name.ToCharArray()) {
        if ($invalid -contains $ch) { [void]$sb.Append('_') } else { [void]$sb.Append($ch) }
    }
    return $sb.ToString().Trim()
}

function Guess-Extension {
    param([string]$ct,[byte[]]$bytes)
    if ($ct) {
        if ($ct -match 'image/png') { return '.png' }
        if ($ct -match 'image/jpeg') { return '.jpg' }
        if ($ct -match 'image/gif') { return '.gif' }
        if ($ct -match 'application/zip') { return '.zip' }
    }
    if ($bytes -and $bytes.Length -ge 4) {
        if ($bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50 -and $bytes[2] -eq 0x4E -and $bytes[3] -eq 0x47) { return '.png' } # PNG
        if ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xD8) { return '.jpg' } # JPEG
        if ($bytes[0] -eq 0x47 -and $bytes[1] -eq 0x49 -and $bytes[2] -eq 0x46 -and $bytes[3] -eq 0x38) { return '.gif' } # GIF
        if ($bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B) { return '.zip' } # ZIP
    }
    return '.bin'
}

# --- Resolve/create OutDir ---
$OutDirFull = Ensure-Directory -Path $OutDir

# --- Build events URL with correct params ---
$eventsUrl = "$BaseUrl/publicApi/v7/events?direction=$Direction&count=$Count"
if ($TestRunId) { $eventsUrl += "&testRunId=$([uri]::EscapeDataString($TestRunId))" }

Write-Host "Fetching events from $eventsUrl"

# --- Fetch events (API returns wrapper with items) ---
$resp = Invoke-WebRequest -Uri $eventsUrl -Headers $headers -UseBasicParsing -ErrorAction Stop
$root = $resp.Content | ConvertFrom-Json

# Normalize to an array of events
$events = @()
if ($root -and ($root.PSObject.Properties.Name -contains 'items') -and $root.items) {
    $events = @($root.items)
} else {
    # some deployments may return a flat array
    if ($root -is [System.Collections.IEnumerable] -and -not ($root -is [string])) {
        $events = @($root)
    }
}

if (-not $events -or $events.Count -eq 0) { throw "Events API returned no events in 'items'." }

# --- Filter event types we want; require non-null testRunId so we can download screenshots
$wantedTypes = @('scriptScreenshot','applicationFailure')
$target = @($events | Where-Object { ($_.eventType -in $wantedTypes) -and $_.testRunId })

Write-Host ("Found {0} events total; {1} are screenshot-related with testRunId." -f $events.Count, $target.Count)

if ($target.Count -eq 0) { return }

$downloadCount = 0
$failCount     = 0

foreach ($evt in $target) {
    $eventId = $evt.id
    $runId   = $evt.testRunId
    $etype   = $evt.eventType
    $title   = if ($evt.title) { $evt.title } else { $etype }
    $tsRaw   = $evt.timestamp

    if (-not $eventId -or -not $runId) { continue }

    $safeRun = Sanitize-Name $runId
    $runDir  = Ensure-Directory -Path (Join-Path $OutDirFull $safeRun)

    $stamp = 'unknown'
    if ($tsRaw) {
        try{
            $stamp = ([DateTime]$tsRaw).ToUniversalTime().ToString('yyyy-MM-dd_HHmmssZ')
        } catch {
            $stamp = 'unknown'
        }
    }

    $safeTitle = Sanitize-Name $title
    $screensUrl = "$BaseUrl/publicApi/v7/test-runs/$runId/events/$eventId/screenshots"
    $tmp = Join-Path $runDir ("tmp_{0}" -f $eventId)

    try {
        # Attempt HEAD to get content-type (optional)
        $ct = $null
        try {
            $head = Invoke-WebRequest -Uri $screensUrl -Headers $headers -Method Head -ErrorAction Stop
            $ct = $head.Headers['Content-Type']
        } catch {}

        Invoke-WebRequest -Uri $screensUrl -Headers $headers -OutFile $tmp -ErrorAction Stop
        $bytes = [System.IO.File]::ReadAllBytes($tmp)
        $ext = Guess-Extension $ct $bytes

        $final = Join-Path $runDir ("{0}__{1}{2}" -f $safeTitle,$stamp,$ext)
        Move-Item -LiteralPath $tmp -Destination $final -Force

        Write-Host "[$etype] $eventId -> $final"
        $downloadCount++
    } catch {
        if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        Write-Warning ("Failed ${eventId}: {0}" -f $_.Exception.Message)
        $failCount++
    }
}

Write-Host ""
Write-Host ("Done. Downloads: {0}, Failures: {1}" -f $downloadCount, $failCount)
Write-Host ("Output: {0}" -f $OutDirFull)
