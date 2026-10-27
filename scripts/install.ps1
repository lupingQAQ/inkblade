#Requires -Version 5.1
<#
.SYNOPSIS
  InkBlade one-command install for Windows: install this checkout (or the PyPI
  package), then run "inkblade up".

.DESCRIPTION
  Everything stays local: no remote scripts, no CDN, no telemetry.
  uv is preferred when it is installed; otherwise python -m pip is used.
  The file is ASCII-only on purpose so Windows PowerShell 5.1 can parse it
  without an encoding BOM.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -NoStart

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 --port 9000 --no-browser
#>
[CmdletBinding()]
param(
    [string]$Python = $env:INKBLADE_PYTHON,
    [string]$Local = $env:INKBLADE_SRC,
    [switch]$NoStart,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$UpArgs = @()
)

$ErrorActionPreference = "Stop"

function Show-Usage {
    Write-Host @"
InkBlade installer (Windows)

Usage: powershell -ExecutionPolicy Bypass -File scripts\install.ps1 [options] [-- up-options]

Options:
  -Python <path>   interpreter to use (default: python3.12/3.11/3.10/python/py -3)
  -Local <path>    install from a local checkout or wheel directory
  -NoStart         install only; do not run "inkblade up"
  -Help            show this help

Environment:
  INKBLADE_PYTHON  same as -Python
  INKBLADE_SRC     same as -Local

Examples:
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 --port 9000 --no-browser
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -NoStart
"@
}

function Resolve-PythonExe {
    param([string]$Explicit)

    $candidates = if ($Explicit) { @($Explicit) } else {
        @("python3.12", "python3.11", "python3.10", "python", "py")
    }
    foreach ($cand in $candidates) {
        $exe = $null
        $pyArgs = @()
        if ([System.IO.Path]::IsPathRooted($cand)) {
            if (-not (Test-Path -LiteralPath $cand)) { continue }
            $exe = $cand
        } else {
            $cmd = Get-Command $cand -ErrorAction SilentlyContinue
            if (-not $cmd) { continue }
            $exe = $cmd.Source
            if ($cand -eq "py") { $pyArgs = @("-3") }
        }
        try {
            $resolved = & $exe @pyArgs -c "import sys; print(sys.executable)" 2>$null
        } catch {
            continue
        }
        if ($LASTEXITCODE -eq 0 -and $resolved) {
            return ($resolved | Select-Object -First 1).Trim()
        }
    }
    return $null
}

if ($Help) {
    Show-Usage
    exit 0
}

$py = Resolve-PythonExe -Explicit $Python
if (-not $py) {
    Write-Host "install.ps1: no Python 3.10+ found." -ForegroundColor Red
    Write-Host "  Install Python 3.10+ and retry, or pass the interpreter explicitly:" -ForegroundColor Red
    Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Python <python 3.10+>\python.exe" -ForegroundColor Red
    exit 1
}

& $py -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "install.ps1: $py is older than Python 3.10." -ForegroundColor Red
    Write-Host "  Pick another interpreter with -Python <path to python 3.10+>." -ForegroundColor Red
    exit 1
}

$repo = Split-Path -Parent $PSScriptRoot
if (-not $Local -and (Test-Path -LiteralPath (Join-Path $repo "pyproject.toml"))) {
    $Local = $repo
}

if ($Local) {
    if (-not (Test-Path -LiteralPath $Local)) {
        Write-Host "install.ps1: -Local path does not exist: $Local" -ForegroundColor Red
        exit 2
    }
    $wheels = @()
    $distDir = Join-Path $Local "dist"
    if (Test-Path -LiteralPath $distDir) {
        $wheels = @(Get-ChildItem -LiteralPath $distDir -Filter *.whl -ErrorAction SilentlyContinue)
    }
    if ($wheels.Count -gt 0) {
        $target = @("--find-links", $distDir, "inkblade")
    } elseif (Test-Path -LiteralPath (Join-Path $Local "pyproject.toml")) {
        $target = @("-e", $Local)
    } else {
        $target = @($Local)
    }
} else {
    $target = @("inkblade")
}

$source = if ($Local) { $Local } else { "PyPI (inkblade)" }
Write-Host "==> interpreter: $py"
Write-Host "==> source: $source"

$installed = $false
$uv = Get-Command uv -ErrorAction SilentlyContinue
if ($uv) {
    Write-Host "==> using uv: $($uv.Source)"
    $uvArgs = @("pip", "install", "--python", $py)
    $inVenv = $false
    if ($env:VIRTUAL_ENV) {
        $normalizedVenv = [System.IO.Path]::GetFullPath($env:VIRTUAL_ENV)
        $normalizedPy = [System.IO.Path]::GetFullPath($py)
        if ($normalizedPy.StartsWith($normalizedVenv, [System.StringComparison]::OrdinalIgnoreCase)) {
            $inVenv = $true
        }
    }
    if (-not $inVenv) { $uvArgs += "--system" }
    $uvArgs += $target
    & $uv.Source @uvArgs
    if ($LASTEXITCODE -eq 0) {
        $installed = $true
    } else {
        Write-Host "install.ps1: uv install failed, falling back to pip." -ForegroundColor Yellow
    }
}

if (-not $installed) {
    Write-Host "==> using pip: $py -m pip"
    & $py -m pip install --upgrade --disable-pip-version-check @target
    if ($LASTEXITCODE -ne 0) {
        Write-Host "install.ps1: pip install failed (exit code $LASTEXITCODE)." -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

if ($NoStart) {
    Write-Host ""
    Write-Host "Installed. Next steps:"
    Write-Host "  1. inkblade up"
    Write-Host "  2. open http://127.0.0.1:8765/ and sign in with the admin password printed once"
    Write-Host "  3. inkblade down to stop; inkblade status for state"
    exit 0
}

Write-Host "==> starting: inkblade up"
& $py -m inkblade up @UpArgs
exit $LASTEXITCODE
