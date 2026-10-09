# PQVPN Windows Installer Builder
# Builds a portable zip package with all required dependencies

param(
    [string]$BuildDir = "build",
    [string]$OutputDir = "../artifacts",
    [string]$Version = "0.0.5-alpha"
)

Write-Host "Building PQVPN Windows installer package..." -ForegroundColor Cyan

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Package name
$package_name = "pqvpn-windows-x64-$Version"
$package_path = Join-Path $OutputDir $package_name
$zip_path = Join-Path $OutputDir "$package_name.zip"

# Clean previous package
if (Test-Path $package_path) {
    Remove-Item -Recurse -Force $package_path
}
New-Item -ItemType Directory -Path $package_path -Force | Out-Null

Write-Host "Copying binaries..." -ForegroundColor Yellow
Copy-Item (Join-Path $BuildDir "pqvpn_node.exe") $package_path
Copy-Item (Join-Path $BuildDir "pqvpn_tui.exe") $package_path
if (Test-Path (Join-Path $BuildDir "pqvpn_monitor.exe")) {
    Copy-Item (Join-Path $BuildDir "pqvpn_monitor.exe") $package_path
}

Write-Host "Copying configuration..." -ForegroundColor Yellow
Copy-Item "config.json" $package_path
Copy-Item "config.udp2raw.json" $package_path

Write-Host "Copying driver..." -ForegroundColor Yellow
if (Test-Path "driver/build/x64/Release/pqvpn_tunnel.inf") {
    New-Item -ItemType Directory -Path "$package_path/driver" -Force | Out-Null
    Copy-Item "driver/build/x64/Release/pqvpn_tunnel.sys" $package_path/driver
    Copy-Item "driver/build/x64/Release/pqvpn_tunnel.inf" $package_path/driver
}

Write-Host "Copying Qt dependencies (for GUI)..." -ForegroundColor Yellow
if (Test-Path "$package_path/pqvpn_monitor.exe") {
    # Find Qt installation
    $qt_dir = $env:QTDIR
    if (-not $qt_dir) {
        Write-Host "Warning: QTDIR not set, skipping Qt dependencies" -ForegroundColor Red
    } else {
        New-Item -ItemType Directory -Path "$package_path/qt" -Force | Out-Null
        Copy-Item "$qt_dir/bin/Qt6Core.dll" $package_path/qt -ErrorAction SilentlyContinue
        Copy-Item "$qt_dir/bin/Qt6Gui.dll" $package_path/qt -ErrorAction SilentlyContinue
        Copy-Item "$qt_dir/bin/Qt6Widgets.dll" $package_path/qt -ErrorAction SilentlyContinue
        Copy-Item "$qt_dir/bin/platforms/qwindows.dll" "$package_path/qt/platforms/" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Creating launcher scripts..." -ForegroundColor Yellow
$launcher_content = @"
@echo off
setlocal
set PQVPN_DIR=%~dp0
if exist "%PQVPN_DIR%qt\platforms" (
    set PATH=%PQVPN_DIR%qt;%PQVPN_DIR%qt\platforms;%PATH%
)
"%PQVPN_DIR%\pqvpn_node.exe" --config "%PQVPN_DIR%\config.json" %*
"@
Set-Content -Path "$package_path/run-node.bat" -Value $launcher_content

$tui_launcher = @"
@echo off
setlocal
set PQVPN_DIR=%~dp0
if exist "%PQVPN_DIR%qt\platforms" (
    set PATH=%PQVPN_DIR%qt;%PQVPN_DIR%qt\platforms;%PATH%
)
"%PQVPN_DIR%\pqvpn_tui.exe" --config "%PQVPN_DIR%\config.json" %*
"@
Set-Content -Path "$package_path/run-tui.bat" -Value $tui_launcher

$gui_launcher = @"
@echo off
setlocal
set PQVPN_DIR=%~dp0
if exist "%PQVPN_DIR%qt\platforms" (
    set PATH=%PQVPN_DIR%qt;%PQVPN_DIR%qt\platforms;%PATH%
)
"%PQVPN_DIR%\pqvpn_monitor.exe" %*
"@
Set-Content -Path "$package_path/run-gui.bat" -Value $gui_launcher

Write-Host "Creating README..." -ForegroundColor Yellow
$readme = @"
# PQVPN for Windows

## Quick Start

### Node (CLI)
```bash
run-node.bat
```

### Terminal UI
```bash
run-tui.bat
```

### Graphical Console (requires Qt)
```bash
run-gui.bat
```

## Install Tunnel Driver

Run as Administrator:
```powershell
pnputil /add-driver driver\pqvpn_tunnel.inf /install
```

## Configuration

Edit config.json before starting the node.
"@
Set-Content -Path "$package_path/README.txt" -Value $readme

# Create zip archive
Write-Host "Creating zip archive..." -ForegroundColor Yellow
Compress-Archive -Path "$package_path/*" -DestinationPath $zip_path -Force

Write-Host ""
Write-Host "Package created: $zip_path" -ForegroundColor Green
Write-Host "Package size: $([math]::Round((Get-Item $zip_path).Length / 1MB, 2)) MB" -ForegroundColor Green