#requires -Version 3
<#
.SYNOPSIS
    Verifies the PQVPN tunnel driver Phase-1 exit criteria after it is loaded.

.DESCRIPTION
    Checks, in order:
      - whether test signing is enabled (bcdedit),
      - whether a "PQVPN Tunnel" network adapter is present,
      - whether \\.\PQVPN_TUN0 can be opened (accurate CreateFile semantics).

    Run this script TWICE to cover both halves of the access-control criterion:
      1) ELEVATED     -> expect "OPEN OK"                 (allowed path works)
      2) NOT elevated -> expect ACCESS_DENIED, error 5    (default-deny works)

    A Win32 error of 2 (FILE_NOT_FOUND) means the driver/service is not loaded yet.
#>
$ErrorActionPreference = 'Stop'

# --- elevation ---------------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
$elevated = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Elevated : $elevated"

# --- test signing ------------------------------------------------------------
try {
    $ts = (& bcdedit /enum 2>$null | Select-String 'testsigning') -join ''
    Write-Host "TestSign: '$($ts.Trim())'"
} catch { Write-Host "TestSign: (could not read; run elevated)" }

# --- adapter present? --------------------------------------------------------
$ad = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*PQVPN*' -or $_.Name -like '*PQVPN*' }
if ($ad) {
    Write-Host "Adapter  : FOUND"
    $ad | ForEach-Object { Write-Host ("   {0}  [{1}]  status={2}" -f $_.Name, $_.InterfaceDescription, $_.Status) }
} else {
    Write-Host "Adapter  : NOT FOUND (driver not installed/loaded yet?)"
}

# --- open the device file (accurate CreateFile semantics via P/Invoke) -------
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
    IntPtr h = CreateFileW(@"\\.\PQVPN_TUN0", GENERIC_READ|GENERIC_WRITE, 3 /*SHARE_READ|WRITE*/, ref sa, 3 /*OPEN_EXISTING*/, 0, IntPtr.Zero);
    if (h.ToInt64() == -1) return "OPEN FAILED: Win32 error " + Marshal.GetLastWin32Error();
    CloseHandle(h); return "OPEN OK";
  }
}
"@
$null = Add-Type -TypeDefinition $src
$result = [DevOpen]::TryOpen()
Write-Host "Device   : $result"

# --- verdict -----------------------------------------------------------------
Write-Host ""
if ($result -eq 'OPEN OK') {
    Write-Host "RESULT: allowed-path OK (elevated open succeeded)."
} elseif ($result -like '*error 5*') {
    Write-Host "RESULT: default-deny OK (non-elevated open was ACCESS_DENIED)."
} elseif ($result -like '*error 2*') {
    Write-Host "RESULT: driver not loaded yet (FILE_NOT_FOUND). Install + start first."
} else {
    Write-Host "RESULT: unexpected -- inspect the Win32 error above."
}
