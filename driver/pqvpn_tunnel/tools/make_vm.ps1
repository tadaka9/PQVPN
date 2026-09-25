#requires -Version 3
<#
.SYNOPSIS
    Cleanly (re)creates the PQVPN-Test VirtualBox guest in ONE consistent folder.

.DESCRIPTION
    Idempotent: removes any existing PQVPN-Test registration + artifacts first, then builds
    fresh so there is exactly one registered VM with .vbox and .vdi co-located under the
    VirtualBox default base folder (no split-folder / duplicate-UUID surprises). Applies all
    test config: 8 GB RAM, 2 CPU, BIOS firmware (no Secure Boot), disk + Windows ISO + Guest
    Additions ISO attached, boot order dvd-first, and the pqvpn_pkg shared folder.

.NOTES
    Run as your normal user. The signed driver package in driver/dist is NOT touched.
#>
$ErrorActionPreference = 'Stop'

$vbm   = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$name  = "PQVPN-Test"
$iso   = "C:\Users\dvx3\Downloads\Win11_25H2_Italian_x64_v2.iso"
$gaIso = "C:\Program Files\Oracle\VirtualBox\VBoxGuestAdditions.iso"
$pkg   = "C:\Users\dvx3\Workspace\PQVPN\driver\dist\x64"

if (-not (Test-Path $vbm)) { throw "VBoxManage not found: $vbm" }
if (-not (Test-Path $iso)) { throw "Windows ISO not found: $iso" }

function Run-Vx([string[]]$a) { & $vbm @a; return $LASTEXITCODE }

# --- clean any existing registration + artifacts -----------------------------
if ((Run-Vx @("showvminfo", $name)) -eq 0) {
    Write-Host "[clean] unregistering existing VM"
    Run-Vx @("unregister", $name, "--delete") | Out-Null
}
foreach ($d in @("$env:USERPROFILE\VirtualBox VMs\$name", "$env:USERPROFILE\Virtual Machines\$name")) {
    if (Test-Path $d) { Write-Host "[clean] removing $d"; Remove-Item $d -Recurse -Force }
}

# --- create VM (default base folder) + resources -----------------------------
Write-Host "[createvm] ostype=Windows11 arch=x86"
if ((Run-Vx @("createvm","--name",$name,"--ostype","Windows11","--platform-architecture","x86","--register")) -ne 0) { throw "createvm failed" }
Run-Vx @("modifyvm", $name, "--memory", "8192") | Out-Null
Run-Vx @("modifyvm", $name, "--cpus",   "2")    | Out-Null
Run-Vx @("modifyvm", $name, "--vram",   "32")   | Out-Null

# --- disk co-located with the .vbox ------------------------------------------
$base = "$env:USERPROFILE\VirtualBox VMs\$name"
$vdi  = Join-Path $base ($name + ".vdi")
Write-Host "[createhd] 64 GB -> $vdi"
if ((Run-Vx @("createhd","--filename",$vdi,"--size","65536")) -ne 0) { throw "createhd failed" }

# --- storage: SATA controller; attach disk + Windows ISO + Guest Additions ISO
Run-Vx @("storagectl", $name, "--name", "SATA", "--add", "sata") 2>&1 | Out-Null   # ok if it already exists
Write-Host ("[attach hdd]    exit=" + (Run-Vx @("storageattach",$name,"--storagectl","SATA","--port","0","--device","0","--type","hdd","--medium",$vdi)))
Write-Host ("[attach winiso] exit=" + (Run-Vx @("storageattach",$name,"--storagectl","SATA","--port","1","--device","0","--type","dvddrive","--medium",$iso)))
if (Test-Path $gaIso) { Write-Host ("[attach gaiso]  exit=" + (Run-Vx @("storageattach",$name,"--storagectl","SATA","--port","2","--device","0","--type","dvddrive","--medium",$gaIso))) }

# --- boot order + shared folder ----------------------------------------------
Write-Host ("[bootorder]    exit=" + (Run-Vx @("modifyvm", $name, "--boot1", "dvd", "--boot2", "disk")))
Write-Host ("[sharedfolder] exit=" + (Run-Vx @("sharedfolder","add",$name,"--name","pqvpn_pkg","--hostpath",$pkg,"--automount")))

# --- verify ------------------------------------------------------------------
Write-Host "`n=== registered vms ==="
& $vbm list vms
Write-Host "`n=== key state ==="
& $vbm showvminfo $name | Select-String -Pattern 'Name:|Firmware|Memory size|Number of CPUs'
Write-Host "=== media + shared folder ==="
& $vbm showvminfo $name --details | Select-String -Pattern '\.iso|\.vdi|pqvpn_pkg|auto-mount'
