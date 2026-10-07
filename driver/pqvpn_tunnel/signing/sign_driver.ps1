# PQVPN Tunnel Driver — Automated Code Signing Script
# Usage: .\sign_driver.ps1 [-DriverPath <path>] [-CertPfx <path>] [-CertPassword <password>]
#                           [-TimestampServer <url>] [-Verify]

param(
    [string]$DriverPath = "..\pqvpn_tunnel.sys",
    [string]$CertPfx,
    [SecureString]$CertPassword,
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [switch]$Verify
)

Write-Host "=== PQVPN Tunnel Driver Code Signing ===" -ForegroundColor Cyan
Write-Host ""

# Determine signing method
if ($CertPfx) {
    Write-Host "Signing with PFX file: $CertPfx" -ForegroundColor Yellow
    
    # Import certificate temporarily for signing
    if (-not $CertPassword) {
        $CertPassword = Read-Host "Enter PFX password" -AsSecureString
    }
    
    $certPath = Join-Path $env:TEMP "pqvpn_sign_cert.pfx"
    Copy-Item $CertPfx $certPath
    
    try {
        # Sign the driver
        Write-Host "Signing driver..." -ForegroundColor Yellow
        $signResult = signtool sign /f $certPath `
            /p (ConvertFrom-SecureString $CertPassword -AsPlainText) `
            /fd SHA256 /tr $TimestampServer /td SHA256 `
            /n "PQVPN Project" $DriverPath
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: signtool failed with exit code $LASTEXITCODE" -ForegroundColor Red
            exit 1
        }
        
        Write-Host "Driver signed successfully." -ForegroundColor Green
    } finally {
        # Clean up temporary certificate file
        Remove-Item $certPath -Force
    }
} else {
    # Sign using certificate from Windows certificate store
    Write-Host "Signing with certificate from Windows store..." -ForegroundColor Yellow
    
    try {
        $signResult = signtool sign /fd SHA256 /tr $TimestampServer `
            /td SHA256 /n "PQVPN Project" $DriverPath
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: signtool failed with exit code $LASTEXITCODE" -ForegroundColor Red
            exit 1
        }
        
        Write-Host "Driver signed successfully." -ForegroundColor Green
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
        exit 1
    }
}

# Verify signature if requested
if ($Verify) {
    Write-Host ""
    Write-Host "Verifying driver signature..." -ForegroundColor Yellow
    
    $verifyResult = signtool verify /pa $DriverPath
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Signature verification failed." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Signature verified successfully." -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Code Signing Complete ===" -ForegroundColor Cyan