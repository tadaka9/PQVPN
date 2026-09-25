# PQVPN Tunnel Driver — Signature Verification Script
# Usage: .\verify_signature.ps1 [-DriverPath <path>] [-Detailed]

param(
    [string]$DriverPath = "..\pqvpn_tunnel.sys",
    [switch]$Detailed
)

Write-Host "=== PQVPN Tunnel Driver Signature Verification ===" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $DriverPath)) {
    Write-Host "ERROR: Driver file not found: $DriverPath" -ForegroundColor Red
    exit 1
}

Write-Host "Verifying signature of: $DriverPath" -ForegroundColor Yellow

# Basic verification
$verifyResult = signtool verify /pa $DriverPath

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "RESULT: Signature verification FAILED" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "RESULT: Signature verification PASSED" -ForegroundColor Green

# Detailed information if requested
if ($Detailed) {
    Write-Host ""
    Write-Host "=== Detailed Signature Information ===" -ForegroundColor Cyan
    
    # Get signature details
    $details = signtool verify /pa /d $DriverPath
    Write-Host $details
    
    # Check certificate chain
    Write-Host ""
    Write-Host "Certificate Chain:" -ForegroundColor Yellow
    $chainResult = signtool verify /pa /c $DriverPath
    Write-Host $chainResult
}

Write-Host ""
Write-Host "=== Verification Complete ===" -ForegroundColor Cyan