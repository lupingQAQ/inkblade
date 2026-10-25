<#
.SYNOPSIS
    Start/stop the QEMU TCG Alpine + k3s lab VM (no Hyper-V, no WSL, no admin).

.DESCRIPTION
    Pure userspace emulation (`-accel tcg`). Two boot modes:

      install : boot the Alpine virt ISO (CD first) to provision /dev/vda
      run     : boot the installed qcow2 disk (default)

    Port forwards (QEMU user-mode networking):

      127.0.0.1:2222  -> guest :22    (ssh/scp)
      127.0.0.1:6445  -> guest :6443  (k3s API server)
      127.0.0.1:30080 -> guest :30080 (NodePort used by the mock target)
      127.0.0.1:18787 -> guest :8787  (ARTEX UI/API, bench)
      127.0.0.1:18788 -> guest :8788  (ARTEX traffic proxy, bench)

    The guest serial console is exposed as a TCP chardev on 127.0.0.1:4555 and
    mirrored to lab/qemu-k3s/out/serial-<mode>.log for evidence. Use
    vm_console.py to drive it.

.EXAMPLE
    powershell -File lab/qemu-k3s/start-vm.ps1 -Mode install
    powershell -File lab/qemu-k3s/start-vm.ps1 -Mode run
    powershell -File lab/qemu-k3s/start-vm.ps1 -Mode run -MemoryMB 6144 -Smp 6
    powershell -File lab/qemu-k3s/start-vm.ps1 -Stop
#>
[CmdletBinding()]
param(
    [ValidateSet('install', 'run')]
    [string]$Mode = 'run',
    [string]$Disk = '',
    [string]$Iso = '',
    [int]$ConsolePort = 4555,
    [int]$SshPort = 2222,
    [int]$ApiPort = 6445,
    [int]$NodePortPort = 30080,
    # ARTEX UI/API (guest :8787) and its traffic proxy (:8788) for host access.
    [int]$ArtexPort = 18787,
    [int]$ArtexProxyPort = 18788,
    # -MemoryMB / -Smp are the documented names (ARTEX bench uses -MemoryMB 6144 -Smp 6);
    # the old -Memory / -Cpus names stay as aliases so existing callers keep working.
    [Alias('Memory')]
    [int]$MemoryMB = 2048,
    [Alias('Cpus')]
    [int]$Smp = 4,
    [string]$Kernel = '',
    [string]$Initrd = '',
    [string]$Append = 'console=ttyS0,115200',
    # TCG accelerator options. `-accel tcg,thread=single` is the fallback when
    # multi-threaded TCG panics the guest at IO-APIC setup with -Smp > 4.
    # Machine type. QEMU 11.x defaults x86_64 to q35, which under TCG aborts the
    # guest halfway through openrc with 6 vCPUs (and panics at IO-APIC setup with
    # 6 vCPUs / 6 GB). i440fx (`pc`) boots -Smp 6 reliably; see
    # docs/ARTEX-BENCH-RESULT.md §"SMP 6 under TCG".
    [string]$Machine = 'pc',
    [string]$Accel = 'tcg',
    [switch]$Stop,
    [switch]$Foreground
)

$ErrorActionPreference = 'Stop'
if (-not $Disk) { $Disk = Join-Path $PSScriptRoot 'disk\k3s.qcow2' }
if (-not $Iso) { $Iso = Join-Path $PSScriptRoot 'alpine-virt-3.24.3-x86_64.iso' }
$Qemu = Join-Path $PSScriptRoot 'qemu\qemu-system-x86_64.exe'
$OutDir = Join-Path $PSScriptRoot 'out'
$PidFile = Join-Path $OutDir 'qemu.pid'
New-Item -ItemType Directory -Force -Path $OutDir, (Split-Path $Disk) | Out-Null

function Get-LabQemuProcess {
    if (Test-Path $PidFile) {
        $procId = [int](Get-Content $PidFile -Raw).Trim()
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -like 'qemu*') { return $p }
    }
    Get-Process -Name 'qemu-system-x86_64' -ErrorAction SilentlyContinue | Select-Object -First 1
}

if ($Stop) {
    $p = Get-LabQemuProcess
    if ($p) {
        Write-Host "[qemu-k3s] stopping pid $($p.Id)"
        Stop-Process -Id $p.Id -Force
    } else {
        Write-Host "[qemu-k3s] no lab VM running"
    }
    Remove-Item $PidFile -ErrorAction SilentlyContinue
    return
}

if (-not (Test-Path $Qemu)) { throw "qemu not found: $Qemu (run the setup steps in docs/REAL-CLUSTER-VERIFICATION.md)" }
if (-not (Test-Path $Disk)) { throw "disk not found: $Disk (qemu-img create -f qcow2 $Disk 8G)" }
if ($Mode -eq 'install' -and -not (Test-Path $Iso)) { throw "iso not found: $Iso" }

$running = Get-LabQemuProcess
if ($running) { throw "lab VM already running (pid $($running.Id)); use -Stop first" }

$serialLog = Join-Path $OutDir "serial-$Mode.log"
$qemuLog = Join-Path $OutDir "qemu-$Mode.log"
$args = @(
    '-accel', $Accel,
    '-machine', $Machine,
    '-m', "$MemoryMB",
    '-smp', "$Smp",
    '-cpu', 'max',
    '-display', 'none',
    '-chardev', "socket,id=ser0,host=127.0.0.1,port=$ConsolePort,server=on,wait=off,logfile=$serialLog",
    '-serial', 'chardev:ser0',
    '-netdev', "user,id=n0,hostfwd=tcp::$SshPort-:22,hostfwd=tcp::$ApiPort-:6443,hostfwd=tcp::$NodePortPort-:30080,hostfwd=tcp::$ArtexPort-:8787,hostfwd=tcp::${ArtexProxyPort}-:8788",
    '-device', 'virtio-net-pci,netdev=n0',
    '-device', 'virtio-rng-pci',
    '-drive', "file=$Disk,if=virtio,format=qcow2,cache=writeback",
    '-rtc', 'base=utc',
    '-pidfile', $PidFile
)
if ($Mode -eq 'install') {
    $args += @('-drive', "file=$Iso,media=cdrom,readonly=on", '-boot', 'order=d')
    if ($Kernel -and $Initrd) {
        # Bypass isolinux: boot the Alpine virt kernel directly so the serial
        # console works from the first byte (isolinux serial input is flaky
        # under QEMU TCG on Windows). The ISO stays attached as the apk/modloop
        # medium; `alpine_dev=cdrom` tells the initramfs to use it.
        $args += @('-kernel', $Kernel, '-initrd', $Initrd, '-append', ('"' + $Append + '"'))
        Write-Host "[qemu-k3s] direct kernel boot: $Kernel"
    }
} else {
    $args += @('-boot', 'order=c')
}

Write-Host "[qemu-k3s] mode=$Mode memory=${MemoryMB}MB smp=$Smp console=:$ConsolePort ssh=:$SshPort api=:$ApiPort nodeport=:$NodePortPort artex=:$ArtexPort"
Write-Host "[qemu-k3s] serial log: $serialLog"

if ($Foreground) {
    & $Qemu @args
    return
}

Start-Process -FilePath $Qemu -ArgumentList $args -RedirectStandardOutput $qemuLog -RedirectStandardError "$qemuLog.err" -WindowStyle Hidden | Out-Null
Start-Sleep -Seconds 2
$p = Get-LabQemuProcess
if (-not $p) { throw "qemu failed to start; see $qemuLog.err" }
Write-Host "[qemu-k3s] started pid $($p.Id)"

