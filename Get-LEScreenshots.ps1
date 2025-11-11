# Get-LEScreenshots.ps1
# PowerShell 5.x compatible
# Downloads screenshots for events of type scriptScreenshot or applicationFailure.
# Directory per TEST RUN: "<TestRunId>"
# File name per event: "<EventTitle>__<EventTimestampUTC><ext>" (title sanitized; ext auto-detected via Content-Type).
#
# Example:
#   .\Get-LEScreenshots.ps1 -BaseUrl "https://nick-loginent2.nick.local" -ApiKey "eyJ..." -OutDir "C:\Temp\LE" -TrustAllCerts

param(
    [Parameter(Mandatory=$true)]
    [string]$BaseUrl,                           # e.g. https://your-le-server

    [string]$TestRunId,                         # optional: limit to one test run
    [string]$OutDir = ".\LEScreenshots",        # where to save files

    [string]$ApiKey,                            # treated as Bearer token
    [string]$BearerToken,                       # Authorization: Bearer <token>

    [switch]$TrustAllCerts,                     # ignore TLS errors (lab boxes)
    [int]$PageSize = 500                        # best-effort paging if supported
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- TLS / Cert handling for lab boxes ---
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
if ($TrustAllCerts) {
    try {
        if (-not ([System.Management.Automation.PSTypeName]'IgnoreCertPolicy').Type) {
@"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class IgnoreCertPolicy {
    public static bool Validator(object sender, X509Certificate cert, X509Chain chain, System.Net.Security.SslPolicyErrors errors) {
        return true;
    }
}
"@ | Add-Type -Language CSharp
        }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s,$c,$ch,$e) [IgnoreCertPolicy]::Validator($s,$c,$ch,$e) }
    } catch {
        Write-Warning "Could not install TrustAllCerts handler. Proceeding anyway."
    }
}

# --- Headers ---
$headers = @{ 'Accept' = 'application/json' }
if ($BearerToken) { $headers['Authorization'] = "Bearer $BearerToken" }
elseif ($ApiKey)  { $headers['Authorization'] = "Bearer $ApiKey" }

# --- Utils ---
function Join-Url { param([string]$a,[string]$b) ($a.TrimEnd('/') + '/' + $b.TrimStart('/')) }

function _HasProp { param($o,[string]$n) return ($o -is [pscustomobject]) -and ($o.PSObject.Properties.Name -contains $n) }

function Ensure-Directory {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { $null = New-Item -ItemType Directory -Path $Path -Force }
    return (Get-Item -LiteralPath $Path).FullName
}

function Get-EventsPage {
    param([string]$Url)

    $resp = Invoke-WebRequest -Uri $Url -Headers $headers -Method GET -ErrorAction Stop
    $obj  = $resp.Content | ConvertFrom-Json

    $next = $null

    # Link header pagination
    $linkHeader = $resp.Headers['Link']
    if ($linkHeader) {
        foreach ($part in ($linkHeader -split ',')) {
            if ($part -match '^\s*<([^>]+)>\s*;\s*rel="?next"?') { $next = $Matches[1]; break }
        }
    }

    # JSON pagination variants
    if (-not $next) {
        if (_HasProp $obj 'next')       { $next = $obj.next }
        elseif (_HasProp $obj 'nextUrl'){ $next = $obj.nextUrl }
        elseif (_HasProp $obj 'links') {
            $lnk = $obj.links
            if (_HasProp $lnk 'next')   { $next = $lnk.next }
        }
        elseif (_HasProp $obj 'page') {
            $pg = $obj.page
            if (_HasProp $pg 'next')    { $next = $pg.next }
        }
    }

    if ($next -and ($next -notmatch '^https?://')) { $next = ($BaseUrl.TrimEnd('/') + '/' + $next.TrimStart('/')) }

    # Normalize items
    $items = @()
    if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string]) -and -not ($obj -is [pscustomobject])) {
        $items = @($obj)
    } elseif (_HasProp $obj 'items') {
        $items = @($obj.items)
    } elseif (_HasProp $obj 'data') {
        $items = @($obj.data)
    } else {
        $items = @($obj)
    }

    [pscustomobject]@{
        Items   = $items
        NextUrl = $next
    }
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
    param([string]$contentType, [byte[]]$firstBytes)

    if ($contentType) {
        switch -regex ($contentType) {
            'application/zip'   { return '.zip' }
            'image/png'         { return '.png' }
            'image/jpeg'        { return '.jpg' }
            'image/gif'         { return '.gif' }
        }
    }

    if ($firstBytes -and $firstBytes.Length -ge 4) {
        if ($firstBytes[0] -eq 0x50 -and $firstBytes[1] -eq 0x4B -and (($firstBytes[2] -eq 0x03 -and $firstBytes[3] -eq 0x04) -or ($firstBytes[2] -eq 0x05 -and $firstBytes[3] -eq 0x06) -or ($firstBytes[2] -eq 0x07 -and $firstBytes[3] -eq 0x08))) {
            return '.zip'
        }
        if ($firstBytes[0] -eq 0xFF -and $firstBytes[1] -eq 0xD8 -and $firstBytes[2] -eq 0xFF) {
            return '.jpg'
        }
        if ($firstBytes.Length -ge 8 -and $firstBytes[0] -eq 0x89 -and $firstBytes[1] -eq 0x50 -and $firstBytes[2] -eq 0x4E -and $firstBytes[3] -eq 0x47 -and $firstBytes[4] -eq 0x0D -and $firstBytes[5] -eq 0x0A -and $firstBytes[6] -eq 0x1A -and $firstBytes[7] -eq 0x0A) {
            return '.png'
        }
        if ($firstBytes[0] -eq 0x47 -and $firstBytes[1] -eq 0x49 -and $firstBytes[2] -eq 0x46 -and $firstBytes[3] -eq 0x38) {
            return '.gif'
        }
    }

    return '.bin'
}

function Get-FilenameFromDisposition {
    param([string]$cd)
    if ($cd -and ($cd -match 'filename\*?="?([^";]+)')) { return $Matches[1] }
    return $null
}

# --- Resolve OutDir to an absolute path and ensure it exists ---
$OutDir = Ensure-Directory -Path $OutDir

# --- Build initial events URL ---
$eventsUrl = Join-Url $BaseUrl "/publicApi/v7/events/"
$qs = @()
if ($TestRunId) { $qs += "testRunId=$([uri]::EscapeDataString($TestRunId))" }
if ($PageSize  -gt 0) { $qs += "pageSize=$PageSize" }
if ($qs.Count -gt 0) { $eventsUrl = "$eventsUrl`?$($qs -join '&')" }

Write-Host "Fetching events from $eventsUrl"

# --- Pull all pages ---
$allEvents = New-Object System.Collections.ArrayList
$nextUrl   = $eventsUrl

while ($nextUrl) {
    $page = Get-EventsPage -Url $nextUrl
    [void]$allEvents.AddRange($page.Items)
    $nextUrl = $page.NextUrl
}

if ($allEvents.Count -eq 0) { throw "Events API returned nothing. Check URL/auth." }

# --- Filter the two event types we care about ---
$wantedTypes   = @('scriptScreenshot','applicationFailure')
$targetEvents  = $allEvents | Where-Object { $_.eventType -in $wantedTypes }

Write-Host ("Found {0} events total; {1} are screenshot-related." -f $allEvents.Count, $targetEvents.Count)

if ($targetEvents.Count -eq 0) {
    Write-Warning "No scriptScreenshot/applicationFailure events found. Nothing to download."
    return
}

# --- Download screenshots for each event ---
$downloadCount = 0
$failCount     = 0

foreach ($evt in $targetEvents) {
    # Safe property fetches from event payload
    $eventId = $null
    if ($evt.PSObject.Properties.Name -contains 'id' -and $evt.id)        { $eventId = $evt.id }
    elseif ($evt.PSObject.Properties.Name -contains 'eventId' -and $evt.eventId) { $eventId = $evt.eventId }

    $runId = $null
    if ($evt.PSObject.Properties.Name -contains 'testRunId' -and $evt.testRunId) { $runId = $evt.testRunId }
    elseif ($TestRunId) { $runId = $TestRunId }

    $etype = if ($evt.PSObject.Properties.Name -contains 'eventType') { $evt.eventType } else { 'event' }
    $title = if ($evt.PSObject.Properties.Name -contains 'title') { $evt.title } else { $null }
    $tsRaw = if ($evt.PSObject.Properties.Name -contains 'timestamp') { $evt.timestamp } else { $null }

    if (-not $eventId) { Write-Warning "Event missing id. Skipping."; continue }
    if (-not $runId)   { Write-Warning "Event missing testRunId. Skipping."; continue }

    # Directory PER TEST RUN ID
    $runDirName = $runId
    $runDir = Ensure-Directory -Path (Join-Path $OutDir (Sanitize-Name $runDirName))

    # Build filename: "<EventTitle>__<EventTimestampUTC><ext>"
    if (-not $title) { $title = "{0}_{1}" -f $etype, $eventId }
    $baseName = Sanitize-Name $title

    $stamp = 'unknown'
    if ($tsRaw) {
        try {
            $dt = [DateTime]$tsRaw
            $stamp = $dt.ToUniversalTime().ToString('yyyy-MM-dd_HHmmssZ')
        } catch {
            $stamp = 'unknown'
        }
    }

    $screensUrl = Join-Url $BaseUrl "/publicApi/v7/test-runs/$runId/events/$eventId/screenshots"

    try {
        # Try HEAD for filename/content-type
        $cd = $null; $ct = $null
        try {
            $head = Invoke-WebRequest -Uri $screensUrl -Headers $headers -Method Head -ErrorAction Stop
            $cd   = $head.Headers['Content-Disposition']
            $ct   = $head.Headers['Content-Type']
        } catch {
            # HEAD not supported
        }

        $tempPath = Join-Path $runDir ("tmp_{0}" -f $eventId)
        Invoke-WebRequest -Uri $screensUrl -Headers $headers -Method GET -OutFile $tempPath -ErrorAction Stop

        # Sniff first bytes
        $fs = [System.IO.File]::Open($tempPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $buf = New-Object byte[] 16
            $read = $fs.Read($buf, 0, $buf.Length)
            if ($read -lt $buf.Length -and $read -gt 0) { $buf = $buf[0..($read-1)] }
        } finally {
            $fs.Dispose()
        }

        $extFromType = Guess-Extension -contentType $ct -firstBytes $buf
        $nameFromCD  = Get-FilenameFromDisposition -cd $cd

        $finalName = $null
        if ($nameFromCD) {
            # Prefer server-provided filename, but append timestamp before extension
            $safe = Sanitize-Name $nameFromCD
            $ext  = [System.IO.Path]::GetExtension($safe)
            if (-not $ext) { $ext = $extFromType }
            $nameOnly = if ($ext) { $safe.Substring(0, $safe.Length - $ext.Length) } else { $safe }
            $finalName = "{0}__{1}{2}" -f $nameOnly, $stamp, $ext
        } else {
            $finalName = "{0}__{1}{2}" -f $baseName, $stamp, $extFromType
        }

        $outPath = Join-Path $runDir $finalName
        Move-Item -LiteralPath $tempPath -Destination $outPath -Force

        Write-Host "[$etype] $eventId  ->  $outPath"
        $downloadCount++
    } catch {
        if (Test-Path $tempPath) { Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue }
        Write-Warning "Failed to download screenshots for event $eventId (testRun $runId): $($_.Exception.Message)"
        $failCount++
        continue
    }
}

Write-Host ""
Write-Host "Done. Downloads: $downloadCount, Failures: $failCount"
Write-Host "Output: $(Resolve-Path $OutDir)"
