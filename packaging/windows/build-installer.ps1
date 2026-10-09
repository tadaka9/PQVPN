# PQVPN Windows portable package builder
# Produces a portable zip with binaries, config examples, launchers,
# and the Qt runtime deployed next to the GUI executable.
#
# Security boundary: this package never ships the tunnel driver.
# Kernel drivers must come from a qualified release pipeline with a
# valid signature (see packaging/gates and publish-qualified-release.yml).

param(
    [string]$BuildDir = "build",
    [string]$OutputDir = "artifacts",
    [string]$Version = "0.0.0"
)

$ErrorActionPreference = 'Stop'

Write-Host "Building PQVPN Windows portable package..." -ForegroundColor Cyan

if (-not (Test-Path (Join-Path $BuildDir "pqvpn_node.exe"))) {
    throw "pqvpn_node.exe not found in $BuildDir"
}

$package_name = "PQVPN-windows-x64-$Version-portable"
$package_path = Join-Path $OutputDir $package_name
$zip_path = Join-Path $OutputDir "$package_name.zip"

if (Test-Path $package_path) {
    Remove-Item -Recurse -Force $package_path
}
New-Item -ItemType Directory -Path $package_path -Force | Out-Null

Write-Host "Copying binaries..." -ForegroundColor Yellow
Copy-Item (Join-Path $BuildDir "pqvpn_node.exe") $package_path
Copy-Item (Join-Path $BuildDir "pqvpn_tui.exe") $package_path
$has_gui = Test-Path (Join-Path $BuildDir "pqvpn_monitor.exe")
if ($has_gui) {
    Copy-Item (Join-Path $BuildDir "pqvpn_monitor.exe") $package_path
}

Write-Host "Copying configuration..." -ForegroundColor Yellow
Copy-Item "config.json" $package_path
Copy-Item "config.udp2raw.json" $package_path
Copy-Item "LICENSE", "README.md" $package_path

if ($has_gui) {
    Write-Host "Deploying Qt runtime with windeployqt..." -ForegroundColor Yellow
    $qt_dir = $env:QT_ROOT_DIR
    if (-not $qt_dir) {
        $candidate = Get-ChildItem "$env:RUNNER_TEMP\Qt" -Recurse -Filter "windeployqt.exe" -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
        if ($candidate) { $qt_dir = Split-Path (Split-Path $candidate) }
    }
    if ($qt_dir -and (Test-Path (Join-Path $qt_dir "bin\windeployqt.exe"))) {
        $gui = Join-Path $package_path "pqvpn_monitor.exe"
        & (Join-Path $qt_dir "bin\windeployqt.exe") --release --no-translations --no-opengl-sw $gui
        if ($LASTEXITCODE -ne 0) { throw 'windeployqt failed' }
    } else {
        Write-Host "Warning: windeployqt not found; the GUI may not start without Qt DLLs." -ForegroundColor Red
    }
}

Write-Host "Creating launcher scripts..." -ForegroundColor Yellow
$launchers = @{
    "run-node.bat" = "pqvpn_node.exe"
    "run-tui.bat"  = "pqvpn_tui.exe"
    "run-gui.bat"  = "pqvpn_monitor.exe"
}
foreach ($entry in $launchers.GetEnumerator()) {
    if (-not (Test-Path (Join-Path $package_path $entry.Value))) { continue }
    @"
@echo off
setlocal
set PQVPN_DIR=%~dp0
"%PQVPN_DIR%$($entry.Value)" %*
exit /b %ERRORLEVEL%
"@ | Set-Content -Path (Join-Path $package_path $entry.Key)
}

Write-Host "Creating README..." -ForegroundColor Yellow
$readme = @"
# PQVPN for Windows (portable)

## Quick Start

- Node daemon:      run-node.bat
- Terminal console: run-tui.bat
- Privacy Console:  run-gui.bat

## Configuration

Edit config.json next to the executables before starting the node.
A hardened mainnet example is provided as config.udp2raw.json.

## Tunnel driver

This portable package does not include the Windows tunnel driver.
The driver is installed by the qualified installer produced by the
release pipeline, which requires a signed kernel binary.
"@
Set-Content -Path (Join-Path $package_path "README.txt") -Value $readme

Write-Host "Creating zip archive..." -ForegroundColor Yellow
Compress-Archive -Path (Join-Path $package_path '*') -DestinationPath $zip_path -Force
Remove-Item -Recurse -Force $package_path

Write-Host ""
Write-Host "Package created: $zip_path" -ForegroundColor Green
Write-Host "Package size: $([math]::Round((Get-Item $zip_path).Length / 1MB, 2)) MB" -ForegroundColor Green
