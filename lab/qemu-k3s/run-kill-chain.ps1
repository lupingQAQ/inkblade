<#
.SYNOPSIS
    Run the Trident cluster-takeover objective against the QEMU/TCG k3s lab.

.DESCRIPTION
    Applies the intentionally vulnerable operator fixture, runs all seven
    objective stages against the real k3s API, writes PROOF/report artifacts,
    then tears the fixture down. If the VM is unavailable, use -Fake to run the
    explicit fake-kubectl fixture (PROOF marks real_cluster=false).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File lab/qemu-k3s/run-kill-chain.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File lab/qemu-k3s/run-kill-chain.ps1 -Fake
#>
[CmdletBinding()]
param(
    [string]$Kubectl = (Join-Path $PSScriptRoot 'kubectl.exe'),
    [string]$Kubeconfig = (Join-Path $PSScriptRoot 'out\k3s.yaml'),
    [string]$ProofMarker = '',
    [string]$Out = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')) 'reports\samples\kill-chain'),
    [switch]$Fake
)

$ErrorActionPreference = 'Stop'
$Python = 'D:\llm-audit-2026-10\env\reproenv-d\Scripts\python.exe'
if (-not (Test-Path $Python)) { $Python = 'python' }
$Backend = if ($Fake) { 'fake' } else { 'kubectl' }
$Args = @(
    (Join-Path $PSScriptRoot 'kill_chain_lab.py'),
    '--kubectl', $Kubectl,
    '--kubeconfig', $Kubeconfig,
    '--backend', $Backend,
    '--out', $Out
)
if ($ProofMarker) { $Args += @('--proof-marker', $ProofMarker) }

& $Python @Args
exit $LASTEXITCODE
