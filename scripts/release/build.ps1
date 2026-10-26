#requires -Version 5.1
<#
.SYNOPSIS
  Build wheel + sdist for InkBlade.
.EXAMPLE
  pwsh scripts/release/build.ps1 -Out dist -Clean
#>
param(
  [string]$Out = "dist",
  [switch]$Clean
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = if ($env:PYTHON) { $env:PYTHON } else { "python" }

Write-Host "build: repo=$repo out=$Out"
Push-Location $repo
try {
  $cliArgs = @("scripts/release/build.py", "--out", $Out)
  if ($Clean) { $cliArgs += "--clean" }
  & $python @cliArgs
  if ($LASTEXITCODE -ne 0) { throw "build failed (exit $LASTEXITCODE)" }

  & $python "scripts/release/sbom.py" --dist $Out --out (Join-Path $Out "sbom.cdx.json")
  if ($LASTEXITCODE -ne 0) { throw "sbom failed (exit $LASTEXITCODE)" }

  $sums = Join-Path $Out "SHA256SUMS"
  if (Test-Path $sums) { Remove-Item $sums -Force }
  Get-ChildItem (Join-Path $Out "*") -File |
    Where-Object { $_.Name -ne "SHA256SUMS" } |
    Sort-Object Name |
    ForEach-Object {
      $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
      "$hash  $($_.Name)" | Add-Content -Path $sums -Encoding ascii
    }
  Write-Host "build: wrote $sums"
  Get-ChildItem (Join-Path $Out "*") -File | ForEach-Object { Write-Host "  $($_.Name)" }
}
finally {
  Pop-Location
}
