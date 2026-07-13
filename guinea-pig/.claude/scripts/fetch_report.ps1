#!/usr/bin/env pwsh
<#
.SYNOPSIS
Fetch a Deep Scan report by job id or upload_id; optionally wait for it (mirror of
fetch_report.py / fetch_report.sh - same CLI). Also the RECOVERY path after the MCP
call drops with `MCP server "deepscan" session expired`: the scan keeps running
server-side, so never re-scan - just fetch it here (add -Wait if it may still run).

.EXAMPLE
  pwsh -File fetch_report.ps1 42                    # JSON for Job #42 to stdout
  pwsh -File fetch_report.ps1 42 -Format md         # markdown
  pwsh -File fetch_report.ps1 <upload_id>           # newest job for that upload
  pwsh -File fetch_report.ps1 <upload_id> -Wait     # wait until done, then fetch
  pwsh -File fetch_report.ps1 42 -Wait -Interval 15 -Timeout 3600

.NOTES
API base defaults to http://127.0.0.1:8800 (override with -BaseUrl or the
DEEPSCAN_API_URL env var). PowerShell 5.1+.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0, Mandatory = $true)][string]$Id,
  [ValidateSet("json", "md", "html", "sarif", "junit")][string]$Format = "json",
  [switch]$Wait,
  [int]$Interval = 15,
  [int]$Timeout = 3600,
  [string]$BaseUrl
)
$ErrorActionPreference = "Stop"

function Coalesce($a, $b) { if ($a) { $a } else { $b } }

if (-not $BaseUrl) { $BaseUrl = Coalesce $env:DEEPSCAN_API_URL "http://127.0.0.1:8800" }
$BaseUrl = $BaseUrl.TrimEnd('/')

function Get-Scans { Invoke-RestMethod -Uri "$BaseUrl/api/scans" -TimeoutSec 15 }

# Resolve an upload_id (non-numeric) to its newest matching job id; a numeric id is
# used as the job id as-is.
if ($Id -match '^\d+$') {
  $Job = [int]$Id
}
else {
  $match = Get-Scans | Where-Object { $_.target -like "*$Id*" } | Sort-Object id | Select-Object -Last 1
  if (-not $match) { Write-Error "no job found for upload_id '$Id'"; exit 1 }
  $Job = [int]$match.id
  Write-Host "resolved upload_id '$Id' -> job #$Job" -ForegroundColor DarkGray 6>$null
  [Console]::Error.WriteLine("resolved upload_id '$Id' -> job #$Job")
}

# Optionally wait for the job to finish (recovery path after a dropped session).
if ($Wait) {
  [Console]::Error.WriteLine("waiting for job #$Job (every ${Interval}s, up to ${Timeout}s) ...")
  $elapsed = 0
  while ($true) {
    $s = Get-Scans | Where-Object { $_.id -eq $Job } | Select-Object -First 1
    $status = if ($s) { $s.status } else { "unknown" }
    if ($status -eq "done") { [Console]::Error.WriteLine("job #$Job done"); break }
    if ($status -eq "failed" -or $status -eq "error") { Write-Error "job #$Job FAILED"; exit 1 }
    [Console]::Error.WriteLine("  ... #$Job $status [${elapsed}s]")
    if ($elapsed -ge $Timeout) { Write-Error "timeout after ${Timeout}s (job still $status)"; exit 3 }
    Start-Sleep -Seconds $Interval
    $elapsed += $Interval
  }
}

$url = "$BaseUrl/api/scans/$Job/report?format=$Format"
try {
  (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
}
catch {
  Write-Error "could not fetch ${url}: $_"
  exit 1
}
