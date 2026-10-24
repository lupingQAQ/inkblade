<#
.SYNOPSIS
    End-to-end real-cluster verification: Alpine + k3s under QEMU TCG, no KVM,
    no Hyper-V, no WSL.

.DESCRIPTION
    Phases (each can be skipped when already done):

      1. provision : boot the Alpine virt kernel/initramfs (netboot media), run
                     setup-alpine.sh over the serial console, install to a qcow2
      2. k3s       : boot the disk, ssh in, run install-k3s.sh, wait for Ready
      3. kubeconfig: copy /etc/rancher/k3s/k3s.yaml to out\k3s.yaml and rewrite
                     the server URL to https://127.0.0.1:6445 (QEMU hostfwd)
      4. verify    : kubectl evidence, live snapshot, Trident recon modules,
                     mock_targets Pod behind a NodePort, Trident HTTP module from
                     Windows, hostNetwork vs NetworkPolicy proof

    Evidence lands in reports\samples\real-cluster\ and is summarized in
    docs\REAL-CLUSTER-VERIFICATION.md.

    Prerequisites (downloaded by this script's docs, kept out of git):
      lab\qemu-k3s\qemu\qemu-system-x86_64.exe   (qemu.weilnetz.de w64 package)
      lab\qemu-k3s\vmlinuz-virt, initramfs-virt  (Alpine netboot kernel)
      lab\qemu-k3s\kubectl.exe                   (dl.k8s.io)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\run-real-cluster-check.ps1
    # resume after a manual k3s install:
    powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\run-real-cluster-check.ps1 -SkipInstall -SkipK3s
#>
[CmdletBinding()]
param(
    [string]$Python = 'D:\llm-audit-2026-10\env\reproenv-d\Scripts\python.exe',
    [int]$SshPort = 2222,
    [int]$ApiPort = 6445,
    [int]$ConsolePort = 4555,
    [int]$HttpPort = 8000,
    [int]$ReadyTimeoutMin = 40,
    [switch]$SkipInstall,
    [switch]$SkipK3s,
    [switch]$StopVmAtEnd
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Lab = Split-Path $Root -Parent            # lab\
$Repo = Split-Path $Lab -Parent            # repo root
$Out = Join-Path $Root 'out'
$Key = Join-Path $Root 'http\id_ed25519'
$Known = Join-Path $Out 'known_hosts'
$Kubeconfig = Join-Path $Out 'k3s.yaml'
$Timings = [ordered]@{}
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Step([string]$Name, [scriptblock]$Body) {
    $t0 = Get-Date
    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
    & $Body
    $Timings[$Name] = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    Write-Host "[$Name] $($Timings[$Name])s" -ForegroundColor DarkGray
}

function Assert-File([string]$Path, [string]$Hint) {
    if (-not (Test-Path $Path)) { throw "missing $Path`n$Hint" }
}

function Get-SshArgs([string]$RemoteCommand) {
    return @('-i', $Key, '-p', "$SshPort", '-o', 'StrictHostKeyChecking=no',
             '-o', "UserKnownHostsFile=$Known", '-o', 'BatchMode=yes',
             '-o', 'ConnectTimeout=10', 'root@127.0.0.1', $RemoteCommand)
}

function Wait-Ssh([int]$TimeoutSec = 300) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        & ssh @(Get-SshArgs 'true') 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep 3
    }
    throw "ssh to guest did not come up within ${TimeoutSec}s"
}

function Wait-GuestLog([string]$Pattern, [int]$TimeoutSec) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $tail = (& ssh @(Get-SshArgs 'tail -n 40 /root/install-k3s.log' 2>$null) | Out-String)
        if ($tail -match $Pattern) { return $tail }
        Start-Sleep 10
    }
    throw "timed out waiting for /$Pattern/ in /root/install-k3s.log`n$tail"
}

Assert-File (Join-Path $Root 'qemu\qemu-system-x86_64.exe') 'download the QEMU w64 package (see docs/REAL-CLUSTER-VERIFICATION.md)'
Assert-File (Join-Path $Root 'kubectl.exe') 'download kubectl.exe from dl.k8s.io'
Assert-File $Python 'point -Python at a Python interpreter with the repo installed'
Assert-File $Key 'ssh-keygen -t ed25519 -N "" -f lab/qemu-k3s/http/id_ed25519; copy .pub to authorized_keys'
if (-not (Test-Path (Join-Path $Root 'http\authorized_keys'))) {
    Copy-Item (Join-Path $Root 'http\id_ed25519.pub') (Join-Path $Root 'http\authorized_keys')
}
# the guest fetches these over QEMU user-net gateway 10.0.2.2:8000
Copy-Item (Join-Path $Root 'setup-alpine.sh') (Join-Path $Root 'http\setup-alpine.sh') -Force
Copy-Item (Join-Path $Root 'install-k3s.sh') (Join-Path $Root 'http\install-k3s.sh') -Force

if (-not $SkipInstall) {
    Step 'install-alpine' {
        if (-not (Test-Path (Join-Path $Root 'disk\k3s.qcow2'))) {
            & (Join-Path $Root 'qemu\qemu-img.exe') create -f qcow2 (Join-Path $Root 'disk\k3s.qcow2') 8G
        }
        # host HTTP server for answers/keys/scripts (10.0.2.2:8000 in the guest)
        $existing = Get-NetTCPConnection -LocalPort $HttpPort -State Listen -ErrorAction SilentlyContinue
        if (-not $existing) {
            Start-Process -FilePath $Python -ArgumentList '-m', 'http.server', "$HttpPort",
                '--bind', '127.0.0.1', '--directory', (Join-Path $Root 'http') -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $Out 'http.log') -RedirectStandardError (Join-Path $Out 'http.err')
            Start-Sleep 2
        }
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'start-vm.ps1') -Mode install `
            -Kernel (Join-Path $Root 'vmlinuz-virt') -Initrd (Join-Path $Root 'initramfs-virt') -ConsolePort $ConsolePort
        Start-Sleep 8
        & $Python (Join-Path $Root 'provision_alpine.py') --direct-kernel --console-port $ConsolePort --timeout 2400
        # setup-alpine.sh powers the VM off; wait for qemu to exit
        $deadline = (Get-Date).AddMinutes(10)
        while ((Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep 5 }
    }
}

Step 'boot-and-ssh' {
    if (-not (Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue)) {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'start-vm.ps1') -Mode run `
            -ConsolePort $ConsolePort -SshPort $SshPort -ApiPort $ApiPort -NodePortPort 30080
    }
    Wait-Ssh -TimeoutSec 300
}

if (-not $SkipK3s) {
    Step 'install-k3s' {
        & scp -i $Key -P $SshPort -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$Known" `
            (Join-Path $Root 'install-k3s.sh') 'root@127.0.0.1:/root/install-k3s.sh'
        & ssh @(Get-SshArgs 'chmod +x /root/install-k3s.sh; nohup sh /root/install-k3s.sh > /root/install-k3s.log 2>&1 &') | Out-Null
        Wait-GuestLog -Pattern 'K3S-READY|node never became Ready' -TimeoutSec ($ReadyTimeoutMin * 60) | Out-Null
    }
}

Step 'kubeconfig' {
    & scp -i $Key -P $SshPort -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$Known" `
        'root@127.0.0.1:/etc/rancher/k3s/k3s.yaml' $Kubeconfig
    (Get-Content $Kubeconfig -Raw) -replace 'https://127\.0\.0\.1:6443', "https://127.0.0.1:$ApiPort" |
        Set-Content $Kubeconfig -NoNewline
    & (Join-Path $Root 'kubectl.exe') --kubeconfig $Kubeconfig get nodes -o wide
    if ($LASTEXITCODE -ne 0) { throw 'kubectl get nodes failed' }
}

Step 'verify' {
    & $Python (Join-Path $Root 'verify_real_cluster.py') --kubectl (Join-Path $Root 'kubectl.exe') `
        --kubeconfig $Kubeconfig --out (Join-Path $Repo 'reports\samples\real-cluster')
    if ($LASTEXITCODE -ne 0) { throw "verify_real_cluster.py exited $LASTEXITCODE" }
}

$Timings['finished_at'] = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$Timings | ConvertTo-Json | Set-Content (Join-Path $Out 'timings.json')
$Timings | Format-Table -AutoSize | Out-String | Write-Host

if ($StopVmAtEnd) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'start-vm.ps1') -Stop
}
