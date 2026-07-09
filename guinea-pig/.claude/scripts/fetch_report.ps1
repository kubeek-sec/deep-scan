#!/usr/bin/env pwsh
<#
.SYNOPSIS
Fetch a finished scan's report from the Deep Scan API by job id (mirror of
fetch_report.py / fetch_report.sh - same CLI). The MCP scan tools print
"Job #N"; pass N here.

.EXAMPLE
  pwsh -File fetch_report.ps1 42                       # JSON to stdout
  pwsh -File fetch_report.ps1 42 -Format md            # markdown
  pwsh -File fetch_report.ps1 42 -BaseUrl http://127.0.0.1:8800

.NOTES
The API base defaults to http://127.0.0.1:8800 (override with -BaseUrl or the
DEEPSCAN_API_URL env var). PowerShell 5.1+.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0, Mandatory = $true)][string]$JobId,
  [ValidateSet("json", "md", "html", "sarif", "junit")][string]$Format = "json",
  [string]$BaseUrl
)
$ErrorActionPreference = "Stop"

function Coalesce($a, $b) { if ($a) { $a } else { $b } }

if (-not $BaseUrl) { $BaseUrl = Coalesce $env:DEEPSCAN_API_URL "http://127.0.0.1:8800" }
$BaseUrl = $BaseUrl.TrimEnd('/')
$url = "$BaseUrl/api/scans/$JobId/report?format=$Format"

try {
  (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
}
catch {
  Write-Error "could not fetch ${url}: $_"
  exit 1
}
