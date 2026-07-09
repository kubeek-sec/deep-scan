#!/usr/bin/env pwsh
<#
.SYNOPSIS
Zip the project and upload it to the Deep Scan MCP server's /upload endpoint
(mirror of upload_to_mcp.py / upload_to_mcp.sh - same CLI). Prints the returned
upload_id to stdout; pass it to a scan tool, e.g. static_scan(upload_id=<id>).

.EXAMPLE
  pwsh -File upload_to_mcp.ps1
  pwsh -File upload_to_mcp.ps1 src/python -BaseUrl http://127.0.0.1:8000

.NOTES
The MCP base URL comes from .mcp.json (the deepscan server's url, with a
trailing /mcp stripped) unless -BaseUrl is given. Pure PowerShell 5.1+/.NET - no
external tools, no Python.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)][string]$Target = ".",
  [string]$McpConfig = ".mcp.json",
  [string]$Server = "deepscan",
  [string]$BaseUrl
)
$ErrorActionPreference = "Stop"

$Skip = @(".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
  ".tox", ".nox", "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache",
  ".idea", "target")
# Exact project-relative files to leave OUT of the zip: the guinea-pig's own
# test-harness scaffolding (canary endpoints, /security-* commands, helper
# scripts) - tooling, not code under test. EXACT posix paths, NOT the whole
# .claude, so real skills/commands a target keeps under .claude are still scanned.
$SkipFiles = @(
  ".claude/canary-endpoints.md",
  ".claude/settings.local.json",
  ".claude/commands/security.md",
  ".claude/commands/security-eval.md",
  ".claude/commands/security-patch.md",
  ".claude/scripts/README.md",
  ".claude/scripts/canary.py",
  ".claude/scripts/canary.sh",
  ".claude/scripts/canary.ps1",
  ".claude/scripts/fetch_report.py",
  ".claude/scripts/fetch_report.sh",
  ".claude/scripts/fetch_report.ps1",
  ".claude/scripts/upload_to_mcp.py",
  ".claude/scripts/upload_to_mcp.sh",
  ".claude/scripts/upload_to_mcp.ps1")
$MaxBytes = 200 * 1024 * 1024

$targetItem = Get-Item -LiteralPath $Target -ErrorAction SilentlyContinue
if (-not $targetItem -or -not $targetItem.PSIsContainer) { Write-Error "not a directory: $Target"; exit 2 }
$root = $targetItem.FullName

# Resolve the MCP base URL.
if (-not $BaseUrl) {
  if (-not (Test-Path -LiteralPath $McpConfig)) { Write-Error "$McpConfig not found (pass -BaseUrl)"; exit 2 }
  $cfg = Get-Content -LiteralPath $McpConfig -Raw | ConvertFrom-Json
  $entry = $cfg.mcpServers.$Server
  if (-not $entry) { $entry = ($cfg.mcpServers.PSObject.Properties | Select-Object -First 1).Value }
  if (-not $entry -or -not $entry.url) { Write-Error "no MCP server url in $McpConfig (stdio transport? pass -BaseUrl)"; exit 2 }
  $BaseUrl = $entry.url
}
$BaseUrl = $BaseUrl.TrimEnd('/')
if ($BaseUrl.EndsWith("/mcp")) { $BaseUrl = $BaseUrl.Substring(0, $BaseUrl.Length - 4) }
$uploadUrl = "$BaseUrl/upload"

# Build the zip in memory, excluding VCS/dependency/build dirs and symlinks,
# with relative posix entry names (matches the .py / .sh behaviour).
Add-Type -AssemblyName System.IO.Compression | Out-Null
$ms = [System.IO.MemoryStream]::new()
$zip = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Create, $true)
[Console]::Error.WriteLine("zipping $root …")
foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File -Force) {
  if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
  $rel = $file.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
  $skipHit = $false
  foreach ($p in $rel.Split('/')) { if ($Skip -contains $p) { $skipHit = $true; break } }
  if ($skipHit) { continue }
  if ($SkipFiles -contains $rel) { continue }
  $entry = $zip.CreateEntry($rel, [System.IO.Compression.CompressionLevel]::Optimal)
  $es = $entry.Open()
  $fs = [System.IO.File]::OpenRead($file.FullName)
  try { $fs.CopyTo($es) } finally { $fs.Dispose(); $es.Dispose() }
}
$zip.Dispose()
$bytes = $ms.ToArray()
$ms.Dispose()

if ($bytes.Length -gt $MaxBytes) {
  Write-Error "zip is $([math]::Round($bytes.Length / 1MB)) MiB > 200 MiB limit - remove build/vendor dirs"
  exit 1
}
[Console]::Error.WriteLine("uploading $([math]::Round($bytes.Length / 1MB, 1)) MiB to $uploadUrl …")

$name = [System.Uri]::EscapeDataString((Split-Path -Leaf $root) + ".zip")
try {
  $resp = Invoke-WebRequest -Uri "$uploadUrl?filename=$name" -Method Post -ContentType "application/zip" -Body $bytes -UseBasicParsing
}
catch {
  Write-Error "upload failed ($uploadUrl): $_"
  exit 1
}

$uid = ($resp.Content | ConvertFrom-Json).upload_id
if (-not $uid) { Write-Error "no upload_id in response: $($resp.Content)"; exit 1 }

Write-Output $uid   # stdout: just the id, easy to capture
[Console]::Error.WriteLine("ok - pass upload_id=$uid to static_scan / scan_family")
