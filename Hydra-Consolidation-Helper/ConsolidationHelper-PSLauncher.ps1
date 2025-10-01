# ================= CONFIG =================
# URL to your published EXE
$ExeUrl = "https://github.com/nburton-loginvsi/LoginVSI-Automations/blob/main/Hydra-Consolidation-Helper/ConsolidationHelper.exe"

# Where to save it locally
$LocalPath = "C:\Temp\ConsolidationHelper.exe"

# Arguments to pass to the EXE
$Patterns   = "*Session Consolidation*,*Hydra Consolidation*"
$Poll       = 10       # seconds
$Delay      = 15       # minutes
$MaxHours   = 8
$WhatIf     = $false    # $false to actually logoff
$Targets    = "All"    # "All" or "Matched"
# ==========================================

# Ensure destination folder exists
$destDir = Split-Path $LocalPath -Parent
if (-not (Test-Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
}

Write-Host "Downloading EXE from $ExeUrl..."
Invoke-WebRequest -Uri $ExeUrl -OutFile $LocalPath -UseBasicParsing

if (-not (Test-Path $LocalPath)) {
    throw "Download failed, $LocalPath not found."
}

Write-Host "Download complete: $LocalPath"

# Build command-line arguments
$argsList = @(
    "--patterns", "`"$Patterns`"",
    "--poll", $Poll,
    "--delay", $Delay,
    "--maxhours", $MaxHours,
    "--whatif", $WhatIf,
    "--targets", $Targets
)

# Run the EXE
Write-Host "Launching watcher..."
& $LocalPath $argsList
