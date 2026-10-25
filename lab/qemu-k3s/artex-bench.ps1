<#
.SYNOPSIS
    Run the ARTEX benchmark inside the QEMU TCG Alpine + k3s VM and collect evidence.

.DESCRIPTION
    End-to-end, reproducible driver for docs/ARTEX-BENCH-RESULT.md:

      1. boot the lab VM with the higher spec used for the bench (-MemoryMB 6144 -Smp 6)
      2. start the host-side mock LLM (OpenAI-compatible, deterministic answers)
      3. make sure the shared mock target is reachable from the guest at 10.0.2.2:30080
         (the k3s NodePort used by the earlier Trident real-cluster run), else fall back
         to lab/mock_targets.py on 10.0.2.2:18080
      4. copy lab/qemu-k3s/artex-bench-{setup,run}.sh into the guest and run them
      5. pull the raw measurement file back and turn it into
         reports/samples/artex-bench/artex-bench.{json,md}

    ARTEX is executed unmodified (AGPL-3.0: black-box timing only).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\artex-bench.ps1
    powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\artex-bench.ps1 -SkipPull -SkipStart
#>
[CmdletBinding()]
param(
    [string]$Python = 'D:\llm-audit-2026-10\env\reproenv-d\Scripts\python.exe',
    [int]$MemoryMB = 6144,
    [int]$Smp = 6,
    [int]$SshPort = 2222,
    [int]$ApiPort = 6445,
    [int]$ConsolePort = 4555,
    [int]$ArtexPort = 18787,
    [int]$MockLlmPort = 18081,
    [int]$MockTargetPort = 30080,
    [string]$Target = 'http://10.0.2.2:30080',
    [string]$ArtexImage = 'ruoji6/artex:v0.3.23',
    [switch]$SkipStart,
    [switch]$SkipPull,
    [switch]$Restart
)

$ErrorActionPreference = 'Stop'
# The lab helpers print Chinese route lists; without this they die on cp1252
# console encoding when started via Start-Process.
$env:PYTHONIOENCODING = 'utf-8'
$Root = $PSScriptRoot
$Lab = Split-Path $Root -Parent
$Repo = Split-Path $Lab -Parent
$Out = Join-Path $Root 'out'
$Key = Join-Path $Root 'http\id_ed25519'
$Known = Join-Path $Out 'known_hosts'
$RawLocal = Join-Path $Out 'artex-bench-raw.txt'
$MockLog = Join-Path $Out 'mock-llm.jsonl'
$Samples = Join-Path $Repo 'reports\samples\artex-bench'
New-Item -ItemType Directory -Force -Path $Out, $Samples | Out-Null

function Get-SshArgs([string]$RemoteCommand) {
    return @('-i', $Key, '-p', "$SshPort", '-o', 'StrictHostKeyChecking=no',
             '-o', "UserKnownHostsFile=$Known", '-o', 'BatchMode=yes',
             '-o', 'ConnectTimeout=10', 'root@127.0.0.1', $RemoteCommand)
}
# Native commands (ssh/scp) write progress to stderr, which PowerShell turns into
# ErrorRecords when $ErrorActionPreference='Stop'; keep them non-terminating here.
function Invoke-Guest([string]$Command) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { return (& ssh @(Get-SshArgs $Command) 2>&1) }
    finally { $ErrorActionPreference = $prev }
}
function Wait-Ssh([int]$TimeoutSec = 300) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        Invoke-Guest 'true' | Out-Null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep 3
    }
    throw "ssh to guest did not come up within ${TimeoutSec}s"
}
function Wait-Tcp([int]$Port, [int]$TimeoutSec = 30) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep 1
    }
    return $false
}

# --- 1. VM --------------------------------------------------------------------
function Start-VmWithRetry {
    param([int]$Attempts = 3)
    for ($i = 1; $i -le $Attempts; $i++) {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'start-vm.ps1') -Mode run `
            -MemoryMB $MemoryMB -Smp $Smp -ConsolePort $ConsolePort -SshPort $SshPort `
            -ApiPort $ApiPort -ArtexPort $ArtexPort
        $deadline = (Get-Date).AddSeconds(150)
        while ((Get-Date) -lt $deadline) {
            Invoke-Guest 'true' | Out-Null
            if ($LASTEXITCODE -eq 0) { return }
            $serialLog = Join-Path $Out 'serial-run.log'
            if ((Test-Path $serialLog) -and ((Get-Content $serialLog -Raw -ErrorAction SilentlyContinue) -match 'Kernel panic')) {
                Write-Warning "guest panicked at boot (TCG IO-APIC timer race), attempt $i/$Attempts"
                break
            }
            Start-Sleep 3
        }
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'start-vm.ps1') -Stop
        Start-Sleep 3
    }
    throw "VM did not reach ssh after $Attempts attempts"
}

$vm = Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue
if ($Restart -and $vm) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'start-vm.ps1') -Stop
    Start-Sleep 3
    $vm = $null
}
if (-not $vm -and -not $SkipStart) {
    Write-Host "[artex-bench] starting VM -MemoryMB $MemoryMB -Smp $Smp" -ForegroundColor Cyan
    Start-VmWithRetry
}
Wait-Ssh -TimeoutSec 300
$guestFacts = (Invoke-Guest 'echo "cpus=$(nproc) mem_mb=$(awk ''/MemTotal/{print int($2/1024)}'' /proc/meminfo) kernel=$(uname -r)"; rc-service k3s status 2>&1 | head -1') -join ' '
Write-Host "[artex-bench] guest: $guestFacts"

# --- 2. host mock LLM ---------------------------------------------------------
if (-not (Wait-Tcp -Port $MockLlmPort -TimeoutSec 3)) {
    Write-Host "[artex-bench] starting mock LLM on 127.0.0.1:$MockLlmPort" -ForegroundColor Cyan
    Start-Process -FilePath $Python -ArgumentList @(
        (Join-Path $Root 'artex-mock-llm.py'), '--port', "$MockLlmPort", '--log', $MockLog,
        '--max-tool-calls', '1') -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $Out 'mock-llm.out') -RedirectStandardError (Join-Path $Out 'mock-llm.err')
    if (-not (Wait-Tcp -Port $MockLlmPort -TimeoutSec 20)) { throw "mock LLM did not start on $MockLlmPort" }
}

# --- 3. shared mock target check (from the guest, through 10.0.2.2) -----------
$probe = (Invoke-Guest "curl -s -o /dev/null -w '%{http_code}' -m 8 http://10.0.2.2:$MockTargetPort/__routes__") -join ''
if ($probe -notmatch '^(200|401|403)$') {
    Write-Host "[artex-bench] NodePort target not reachable ($probe); starting lab/mock_targets.py on 18080" -ForegroundColor Yellow
    Start-Process -FilePath $Python -ArgumentList @((Join-Path $Lab 'mock_targets.py'), '--port', '18080', '--mode', 'vulnerable') `
        -WindowStyle Hidden -RedirectStandardOutput (Join-Path $Out 'mock-target.out') -RedirectStandardError (Join-Path $Out 'mock-target.err')
    if (-not (Wait-Tcp -Port 18080 -TimeoutSec 20)) { throw 'mock target did not start on 18080' }
    $Target = 'http://10.0.2.2:18080'
}
Write-Host "[artex-bench] target from guest: $Target"

# --- 4. guest scripts ---------------------------------------------------------
& scp -i $Key -P $SshPort -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$Known" `
    (Join-Path $Root 'artex-bench-setup.sh') (Join-Path $Root 'artex-bench-run.sh') 'root@127.0.0.1:/root/' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'scp of guest scripts failed' }

if (-not $SkipPull) {
    Write-Host "[artex-bench] pulling images in the guest (docker daemon proxy 10.0.2.2:7897)" -ForegroundColor Cyan
    Invoke-Guest "ARTEX_IMAGE=$ArtexImage sh /root/artex-bench-setup.sh pull 2>&1 | tail -20"
}

$t0 = Get-Date
Invoke-Guest ("ARTEX_IMAGE=$ArtexImage MOCK_TARGET=$Target sh /root/artex-bench-run.sh 2>&1 | tail -40")
if ($LASTEXITCODE -ne 0) { throw 'guest bench run failed (see output above)' }
$benchSeconds = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
Write-Host "[artex-bench] guest bench wall clock: ${benchSeconds}s"

# container logs are evidence for the task/LLM path
Invoke-Guest 'docker logs artex --tail 200 > /root/artex-container.log 2>&1; docker logs artex-pg --tail 40 > /root/artex-pg.log 2>&1; echo saved'
& scp -i $Key -P $SshPort -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$Known" `
    'root@127.0.0.1:/root/artex-bench-raw.txt' $RawLocal | Out-Null
& scp -i $Key -P $SshPort -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$Known" `
    'root@127.0.0.1:/root/artex-container.log' (Join-Path $Out 'artex-container.log') | Out-Null

# --- 5. artefacts -------------------------------------------------------------
$qemuVersion = (& (Join-Path $Root 'qemu\qemu-system-x86_64.exe') --version) -join ' '
$meta = @(
    "qemu=$qemuVersion",
    "vm=tcg pc -smp $Smp -m ${MemoryMB}MB",
    "guest_facts=$guestFacts",
    "mock_target=$Target",
    "bench_wall_clock_s=$benchSeconds"
)
$limitations = @(
    'QEMU TCG software emulation: absolute numbers are not comparable to bare-metal; only the ARTEX-vs-Trident ratio on the same host is meaningful.',
    'The LLM is a deterministic OpenAI-compatible mock on the host; it exercises the real HTTP/agent loop but not model quality or token cost.',
    'Idle RSS is sampled 60-90 s after start via docker stats (2 s cadence), not an instantaneous peak.',
    'k3s (single-node control plane) is running in the same guest during the whole bench and consumes CPU/RAM.',
    'Image pull time is excluded from cold start (images are pre-pulled); it is reported separately.'
)
$metaArgs = @()
foreach ($m in $meta) { $metaArgs += @('--meta', $m) }
$limArgs = @()
foreach ($l in $limitations) { $limArgs += @('--limitation', $l) }

& $Python (Join-Path $Root 'artex-bench-collect.py') --raw $RawLocal --mock-log $MockLog `
    --out $Samples --trident (Join-Path $Lab 'bench\out\bench-smoke.json') @metaArgs @limArgs
if ($LASTEXITCODE -ne 0) { throw 'collector failed' }
Write-Host "[artex-bench] wrote $Samples\artex-bench.json / .md" -ForegroundColor Green
