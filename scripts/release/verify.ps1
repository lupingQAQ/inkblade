#requires -Version 5.1
<#
.SYNOPSIS
  Pre-release self-audit: byte-compile, public-tree hygiene, vendor checksums,
  plugin SDK contract and the release hygiene gate.
.DESCRIPTION
  Every step must pass. Use -Full to additionally run the whole unittest suite
  (slow: several minutes).
.EXAMPLE
  pwsh scripts/release/verify.ps1
  pwsh scripts/release/verify.ps1 -Full
#>
param(
  [switch]$Full
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$steps = @(
  @{ Name = "compile";     Args = @("scripts/release/compile-check.py") },
  @{ Name = "public-tree"; Args = @("scripts/check-public-tree.py", "--root", ".") },
  @{ Name = "vendor";      Args = @("-m", "unittest", "tests.test_vendor_checksums", "-v") },
  @{ Name = "sdk";         Args = @("-m", "unittest", "tests.test_sdk", "-v") },
  @{ Name = "hygiene";     Args = @("scripts/release/verify.py") }
)
if ($Full) {
  $steps += @{ Name = "tests"; Args = @("-m", "unittest", "discover", "-s", "tests", "-t", ".") }
}

Push-Location $repo
$failed = @()
try {
  foreach ($step in $steps) {
    Write-Host ""
    Write-Host "=== $($step.Name) ===" -ForegroundColor Cyan
    & $python @($step.Args)
    if ($LASTEXITCODE -ne 0) {
      $failed += $step.Name
      Write-Host "FAILED: $($step.Name)" -ForegroundColor Red
    }
    else {
      Write-Host "ok: $($step.Name)" -ForegroundColor Green
    }
  }
}
finally {
  Pop-Location
}

if ($failed.Count -gt 0) {
  Write-Host ""
  Write-Host "verify: FAILED -> $($failed -join ', ')" -ForegroundColor Red
  exit 1
}
Write-Host ""
Write-Host "verify: all checks passed" -ForegroundColor Green
exit 0
