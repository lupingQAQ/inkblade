#requires -Version 5.1
<#
.SYNOPSIS
  Sign release artifacts with cosign keyless (Sigstore Fulcio + Rekor).
.DESCRIPTION
  Requires the cosign binary and an ambient OIDC identity. When cosign is not
  installed the step is skipped with exit code 0 so it never blocks CI.
.EXAMPLE
  pwsh scripts/release/sign.ps1 -Dist dist
  pwsh scripts/release/sign.ps1 -Dist dist -Verify
#>
param(
  [string]$Dist = "dist",
  [string]$Identity = "",
  [switch]$Verify
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = if ($env:PYTHON) { $env:PYTHON } else { "python" }

Push-Location $repo
try {
  $cliArgs = @("scripts/release/sign.py", "--dist", $Dist)
  if ($Verify) { $cliArgs += "--verify" }
  if ($Identity) { $cliArgs += @("--identity", $Identity) }
  & $python @cliArgs
  exit $LASTEXITCODE
}
finally {
  Pop-Location
}
