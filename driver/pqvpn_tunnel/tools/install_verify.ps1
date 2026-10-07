#requires -Version 3
<#
.SYNOPSIS
    ELEVATED one-shot: trust the PQVPN test certificate as a local root, install the
    driver package, and verify the adapter + an elevated open of \\.\PQVPN_TUN0.

.DESCRIPTION
    Run this in an ELEVATED PowerShell with -ExecutionPolicy Bypass. It:
      1) imports the self-signed cert into Cert:\LocalMachine\Root if not already there
         (this is what pnputil needs to accept the package signature),
      2) reports test-signing state,
      3) runs pnputil /add-driver .../install and shows its output,
      4) lists network adapters and checks for "PQVPN Tunnel",
      5) attempts an elevated open of \\.\PQVPN_TUN0 (expect OPEN OK).

    After this, run verify_load.ps1 a second time WITHOUT elevation to confirm the
    default-deny path returns ACCESS_DENIED.
#>
$ErrorActionPreference = 'Stop'

$dist = "C:\Users\dvx3\Workspace\PQVPN\driver\dist\x64"
$cer  = Join-Path $dist "pqvpn_test_sign.cer"
$inf  = Join-Path $dist "pqvpn_tunnel.inf"

# --- must be elevated --------------------------------------------------------
$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run this ELEVATED (as Administrator)." }

Write-Host "== 1) trust the test certificate as a local root ==" -ForegroundColor Cyan
$trusted = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -eq 'CN=PQVPN Test Sign' }
if ($trusted) {
    Write-Host "   already trusted: $($trusted.Thumbprint)"
} else {
    if (-not (Test-Path $cer)) { throw "cert not found: $cer  (run testsign.ps1 first)" }
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host "   imported into LocalMachine\Root"
}

Write-Host "`n== 2) test-signing state ==" -ForegroundColor Cyan
$ts = (& bcdedit /enum 2>$null | Select-String 'testsigning') -join ''
Write-Host ("   {0}" -f $ts.Trim())
if ($ts -notmatch 'Yes') { Write-Host "   NOTE: testsigning is off. Needed to LOAD the driver later: bcdedit /set testsigning on  (then reboot)." }

Write-Host "`n== 3) install driver package ==" -ForegroundColor Cyan
& pnputil /add-driver $inf /install
$pn = $LASTEXITCODE
Write-Host "   pnputil exit=$pn"

Write-Host "`n== 4) network adapters ==" -ForegroundColor Cyan
(netsh interface show interface) | Out-String | Write-Host
$ad = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*PQVPN*' -or $_.Name -like '*PQVPN*' }
if ($ad) { Write-Host "   ADAPTER FOUND: $($ad.Name)" -ForegroundColor Green } else { Write-Host "   adapter NOT found yet" -ForegroundColor Yellow }

Write-Host "`n== 5) service state (diagnostic) ==" -ForegroundColor Cyan
& sc.exe query pqvpn_tunnel 2>&1 | Out-String | Write-Host

Write-Host "`n== 6) elevated open test of \\.\PQVPN_TUN0 ==" -ForegroundColor Cyan
$src = @"
using System; using System.Runtime.InteropServices;
public static class DevOpen {
  [StructLayout(LayoutKind.Sequential)] struct SA { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr CreateFileW(string name, uint dwDesiredAccess, int dwShareMode, ref SA sa, int dwCreationDisposition, int dwFlagsAndAttributes, IntPtr hTemplate);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr hObject);
  public static string TryOpen() {
    var sa = new SA(); sa.nLength = Marshal.SizeOf<SA>();
    const uint GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000;
    IntPtr h = CreateFileW(@"\\.\PQVPN_TUN0", GENERIC_READ|GENERIC_WRITE, 3, ref sa, 3, 0, IntPtr.Zero);
    if (h.ToInt64() == -1) return "OPEN FAILED: Win32 error " + Marshal.GetLastWin32Error();
    CloseHandle(h); return "OPEN OK";
  }
}
"@
$null = Add-Type -TypeDefinition $src
Write-Host ("   " + [DevOpen]::TryOpen())
