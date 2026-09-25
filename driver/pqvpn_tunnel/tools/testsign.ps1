#requires -Version 3
<#
.SYNOPSIS
    Builds and test-signs the PQVPN tunnel driver (x64) into a consistent,
    installable package under driver/dist/x64/. Dev-only; never a release path.

.DESCRIPTION
    Correct signing order matters: an Authenticode signature changes the .sys
    bytes, so the catalog must be generated AFTER the .sys is signed and then
    itself signed. This script does exactly that:
      1) rebuild (fresh unsigned .sys + stamped .inf)
      2) stage .sys + .inf into driver/dist/x64/
      3) sign the .sys            (signtool /fd SHA256, self-signed test cert)
      4) regenerate the catalog   (inf2cat over the signed .sys)
      5) sign the catalog         (signtool /fd SHA256)
      6) verify both signatures and export the public cert for the admin trust step

    Signing does not require elevation. Trusting the cert + enabling test signing do.
#>
$ErrorActionPreference = 'Stop'

# --- tool locations ----------------------------------------------------------
$sdkRoot  = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0"
$signtool = Join-Path $sdkRoot "x64\signtool.exe"
$inf2cat  = Join-Path $sdkRoot "x86\Inf2Cat.exe"   # inf2cat ships as x86 in this SDK
$msbuild  = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"

# --- paths -------------------------------------------------------------------
$projDir   = Split-Path $PSScriptRoot -Parent                       # .../driver/pqvpn_tunnel
$vcxproj   = Join-Path $projDir "pqvpn_tunnel.vcxproj"
$buildOut  = Join-Path (Split-Path $projDir -Parent) "build\x64\Release"   # .../driver/build/x64/Release
$stampedInf = Join-Path $buildOut "pqvpn_tunnel.inf"
$unsignedSys = Join-Path $buildOut "pqvpn_tunnel.sys"
$dist      = Join-Path (Split-Path $projDir -Parent) "dist\x64"     # .../driver/dist/x64

foreach ($t in @($signtool, $inf2cat, $msbuild)) { if (-not (Test-Path $t)) { throw "missing tool: $t" } }

# --- 1) rebuild fresh unsigned artifacts -------------------------------------
Write-Host "`n[1/6] rebuilding driver (Release x64)..."
& $msbuild $vcxproj -p:Configuration=Release -p:Platform=x64 -t:Rebuild -v:minimal -nologo | Out-Null
if ($LASTEXITCODE -ne 0) { throw "MSBuild failed (exit $LASTEXITCODE)" }
foreach ($f in @($stampedInf, $unsignedSys)) { if (-not (Test-Path $f)) { throw "build did not produce: $f" } }

# --- 2) stage into a clean installable package dir ---------------------------
Write-Host "[2/6] staging package -> $dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item $unsignedSys (Join-Path $dist "pqvpn_tunnel.sys") -Force
Copy-Item $stampedInf  (Join-Path $dist "pqvpn_tunnel.inf") -Force

$sys = Join-Path $dist "pqvpn_tunnel.sys"
$inf = Join-Path $dist "pqvpn_tunnel.inf"
$cat = Join-Path $dist "pqvpn_tunnel.cat"

# --- certificate -------------------------------------------------------------
$subject = 'CN=PQVPN Test Sign'
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type Custom -Subject $subject `
        -KeyUsage DigitalSignature -FriendlyName 'PQVPN Test Sign' `
        -CertStoreLocation Cert:\CurrentUser\My `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')   # Code Signing EKU
    Write-Host "[+] created self-signed code-signing certificate"
} else {
    Write-Host "[=] reusing certificate: $($cert.Thumbprint)"
}

# --- 3) sign the .sys ---------------------------------------------------------
Write-Host "`n[3/6] signing pqvpn_tunnel.sys (SHA256)..."
& $signtool sign /fd SHA256 /sha1 $cert.Thumbprint $sys | Out-Null
if ($LASTEXITCODE -ne 0) { throw "failed to sign .sys" }

# --- 4) regenerate the catalog over the SIGNED .sys --------------------------
Write-Host "[4/6] regenerating catalog (inf2cat /driver:$dist /os:10_X64)..."
& $inf2cat "/driver:$dist" "/os:10_X64" | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $cat)) { throw "inf2cat failed to produce the catalog" }

# --- 5) sign the catalog ------------------------------------------------------
Write-Host "[5/6] signing pqvpn_tunnel.cat (SHA256)..."
& $signtool sign /fd SHA256 /sha1 $cert.Thumbprint $cat | Out-Null
if ($LASTEXITCODE -ne 0) { throw "failed to sign .cat" }

# --- 6) verify + export cert --------------------------------------------------
Write-Host "`n[6/6] verifying signatures..."
& $signtool verify /v $sys | Select-Object -Last 3
$sysOk = ($LASTEXITCODE -eq 0)
& $signtool verify /v $cat | Select-Object -Last 3
$catOk = ($LASTEXITCODE -eq 0)

# Note: with a self-signed cert not yet in a trusted root, signtool verify reports
# a trust error even though the signature is valid. Confirm the signer instead:
$sSys = (Get-AuthenticodeSignature $sys).SignerCertificate.Subject
$sCat = (Get-AuthenticodeSignature $cat).SignerCertificate.Subject

$cerOut = Join-Path $dist "pqvpn_test_sign.cer"
Export-Certificate -Cert $cert -FilePath $cerOut | Out-Null

Write-Host "`n=============================================================="
Write-Host "  package    : $dist"
Write-Host "  sys signer : $sSys   (signtool verify trusted=$sysOk)"
Write-Host "  cat signer : $sCat   (signtool verify trusted=$catOk)"
Write-Host "  thumbprint : $($cert.Thumbprint)"
Write-Host "  exported   : $cerOut"
Write-Host ""
Write-Host "  NEXT -- run in an ELEVATED PowerShell, then reboot:"
Write-Host "    Import-Certificate -FilePath `"$cerOut`" -CertStoreLocation Cert:\LocalMachine\Root"
Write-Host "    bcdedit /set testsigning on"
Write-Host "    shutdown /r /t 0"
Write-Host ""
Write-Host "  AFTER REBOOT (elevated) -- install + load + verify:"
Write-Host "    pnputil /add-driver `"$inf`" /install"
Write-Host "    netsh interface show interface        # expect 'PQVPN Tunnel'"
Write-Host "=============================================================="
