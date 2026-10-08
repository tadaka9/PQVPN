<# Installs and configures the repository-owned PQVPN layer-3 adapter. #>
[CmdletBinding()]
param(
    [string]$DriverDirectory = (Join-Path $PSScriptRoot '..\..\driver\build\x64\Release'),
    [string]$Address = '10.8.0.2',
    [int]$PrefixLength = 24
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Setup-PQVPNAdapter.ps1 must run as Administrator.'
}

$inf = Join-Path $DriverDirectory 'pqvpn_tunnel.inf'
$sys = Join-Path $DriverDirectory 'pqvpn_tunnel.sys'
if (-not (Test-Path $inf) -or -not (Test-Path $sys)) {
    throw "PQVPN driver package is incomplete in $DriverDirectory"
}

Write-Host 'Installing the PQVPN-owned tunnel driver...' -ForegroundColor Cyan
& pnputil.exe /add-driver $inf /install
if ($LASTEXITCODE -ne 0) { throw "pnputil failed with exit code $LASTEXITCODE" }

$adapter = Get-NetAdapter -IncludeHidden | Where-Object InterfaceDescription -Like 'PQVPN Tunnel*' |
    Select-Object -First 1
if (-not $adapter) { throw 'The PQVPN Tunnel adapter did not appear after driver installation.' }

Rename-NetAdapter -Name $adapter.Name -NewName 'PQVPN Tunnel' -ErrorAction SilentlyContinue
$adapter = Get-NetAdapter -Name 'PQVPN Tunnel'
$existing = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object IPAddress -EQ $Address
if (-not $existing) {
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $Address -PrefixLength $PrefixLength | Out-Null
}
Enable-NetAdapter -InterfaceIndex $adapter.ifIndex -Confirm:$false
Write-Host "PQVPN Tunnel is ready on $Address/$PrefixLength." -ForegroundColor Green
