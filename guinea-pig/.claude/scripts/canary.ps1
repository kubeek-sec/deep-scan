#!/usr/bin/env pwsh
<#
.SYNOPSIS
Controlled, owner-operated canary endpoints for security evaluation (mirror of
canary.py / canary.sh - same CLI). Inert kubeek.com endpoints used only to
validate drop/exfiltration/info-collection paths; the ONLY external host an
evaluation, demo or non-regression test may contact. See ../canary-endpoints.md.

.EXAMPLE
  pwsh -File canary.ps1 info -Method POST
  pwsh -File canary.ps1 monip
  pwsh -File canary.ps1 download run.sh
  pwsh -File canary.ps1 direct   run.ps1
  pwsh -File canary.ps1 download2 a

.NOTES
Env: KUBEEK_BASE_URL (default https://kubeek.com), KUBEEK_USER_AGENT
(Cloudflare 403s an empty UA, so one is always sent). PowerShell 5.1+.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)][string]$Command,
  [Parameter(Position = 1)][string]$Arg,
  [string]$Method = "GET"
)
$ErrorActionPreference = "Stop"

function Coalesce($a, $b) { if ($a) { $a } else { $b } }

$BaseUrl = (Coalesce $env:KUBEEK_BASE_URL "https://kubeek.com").TrimEnd('/')
$Ua = Coalesce $env:KUBEEK_USER_AGENT "deepscan-security-eval/1.0"
$Files = @("run.sh", "run.ps1", "run.txt")

function Invoke-Canary([string]$Url, [string]$HttpMethod = "GET") {
  $headers = @{ "User-Agent" = $Ua }
  if ($HttpMethod -eq "GET") {
    (Invoke-WebRequest -Uri $Url -Method GET -Headers $headers -UseBasicParsing).Content
  }
  else {
    # Cloudflare 403s a bodyless POST (no Content-Length); send an empty body.
    (Invoke-WebRequest -Uri $Url -Method $HttpMethod -Headers $headers -Body "" `
        -ContentType "application/x-www-form-urlencoded" -UseBasicParsing).Content
  }
}

switch ($Command) {
  # /info 301-redirects to /info/, and following a 301 downgrades POST->GET,
  # corrupting the method echo - so target the trailing-slash form directly.
  "info" { Invoke-Canary "$BaseUrl/info/" $Method }
  "monip" { Invoke-Canary "$BaseUrl/monip/" }
  "download" {
    if ($Files -notcontains $Arg) { Write-Error "file must be one of: $($Files -join ', ')"; exit 2 }
    Invoke-Canary "$BaseUrl/run/download.php?file=$Arg"
  }
  "direct" {
    if ($Files -notcontains $Arg) { Write-Error "file must be one of: $($Files -join ', ')"; exit 2 }
    Invoke-Canary "$BaseUrl/run/$Arg"
  }
  "download2" {
    if (@("a", "b", "c") -notcontains $Arg) { Write-Error "attribut must be a|b|c"; exit 2 }
    Invoke-Canary "$BaseUrl/run/download2.php?attribut=$Arg"
  }
  default {
    Write-Error "usage: canary.ps1 {info [-Method GET|POST]|monip|download <file>|direct <file>|download2 <a|b|c>}"
    exit 2
  }
}
