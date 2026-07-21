<#
.SYNOPSIS
    Setup-PQVPNAdapter.ps1 - Installa e configura l'interfaccia TAP per PQVPN su Windows.
#>

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "Questo script deve essere eseguito come AMMINISTRATORE."
    exit 1
}

Write-Host "--- PQVPN Windows Adapter Setup ---" -ForegroundColor Cyan

# 1. Verifica driver TAP esistente
Write-Host "[1/4] Verificando presenza driver TAP..." -NoNewline
$tapAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*TAP-Windows*" }

if ($null -eq $tapAdapter) {
    Write-Host " [MANCANTE]" -ForegroundColor Red
    Write-Host "[*] Scaricamento e installazione TAP-Windows..." -ForegroundColor Yellow

    $url = "https://build.openvpn.net/downloads/releases/tap-windows-9.24.7-bundle-oss.exe"
    $dest = "$env:TEMP\tap_installer.exe"

    Invoke-WebRequest -Uri $url -OutFile $dest
    Start-Process -FilePath $dest -ArgumentList "/S" -Wait

    # Ricarica lista adapter
    $tapAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*TAP-Windows*" }
    if ($null -eq $tapAdapter) {
        Write-Error "Installazione fallita. Assicurati che il driver sia compatibile."
        exit 1
    }
    Write-Host " [OK]" -ForegroundColor Green
} else {
    Write_Host " [PRESENTE]" -ForegroundColor Green
}

# 2. Configurazione IP
Write-Host "[2/4] Configurando indirizzo IP (10.8.0.2)..." -NoNewline
$interfaceName = $tapAdapter.Name
try {
    # Reset e configurazione IP statico per il tunnel PQVPN
    New-NetIPAddress -InterfaceAlias $interfaceName -IPAddress "10.8.0.2" -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
    Write-Host " [OK]" -ForegroundColor Green
} catch {
    Write-Host " [GIÀ CONFIGURATO O ERRORE]" -ForegroundColor Yellow
}

# 3. Configurazione Routing
Write-Host "[3/4] Configurando rotte di rete..." -NoNewline
try {
    # Aggiungiamo una rotta per la rete interna del tunnel PQVPN
    New-NetRoute -InterfaceAlias $interfaceName -DestinationPrefix "10.8.0.0/24" -ErrorAction SilentlyContinue | Out-Null
    Write-Host " [OK]" -ForegroundColor Green
} catch {
    Write-Host " [ERRORE]" -ForegroundColor Red
}

# 4. Verifica Finale
Write-Host "[4/4] Verifica stato interfaccia..." -NoNewline
$status = Get-NetAdapter -Name $interfaceName | Select-Object -ExpandProperty Status
if ($status -eq "Up") {
    Write-Host " [PRONTO]" -ForegroundColor Green
    Write-Host "`nConfigurazione completata con successo!" -ForegroundColor Cyan
    Write-Host "L'interfaccia '$interfaceName' è pronta per ricevere pacchetti PQVPN."
} else {
    Write-Host " [ERRORE: $status]" -                ForegroundColor Red
    exit 1
}
