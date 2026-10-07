# PQVPN Tunnel Driver HLK Test Runner
# Usage: .\run_hlk_tests.ps1 [-ConfigFile <path>] [-Architecture x64|arm64]

param(
    [string]$ConfigFile = ".\pqvpn_tunnel.hlkx",
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64"
)

Write-Host "=== PQVPN Tunnel Driver HLK Tests ===" -ForegroundColor Cyan
Write-Host "Configuration: $ConfigFile"
Write-Host "Architecture:  $Architecture"
Write-Host ""

# Check if HLK is installed
$hlkPath = Get-Command hlk.exe -ErrorAction SilentlyContinue
if (-not $hlkPath) {
    Write-Host "ERROR: HLK not found. Install Windows Hardware Lab Kit." -ForegroundColor Red
    exit 1
}

Write-Host "HLK found at: $($hlkPath.Source)" -ForegroundColor Green

# Run HLK tests
Write-Host ""
Write-Host "Running HLK tests..." -ForegroundColor Yellow
$exitCode = 0
& hlk.exe /config:$ConfigFile /architecture:$Architecture /output:hlk_results.xml 2>&1 | Tee-Object -Variable testOutput
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0) {
    Write-Host ""
    Write-Host "HLK tests FAILED (exit code: $exitCode)" -ForegroundColor Red
} else {
    Write-Host ""
    Write-Host "HLK tests PASSED" -ForegroundColor Green
}

# Parse and display results
if (Test-Path hlk_results.xml) {
    Write-Host ""
    Write-Host "=== Test Results Summary ===" -ForegroundColor Cyan
    
    [xml]$results = Get-Content hlk_results.xml
    
    $totalTests = 0
    $passedTests = 0
    $failedTests = 0
    
    foreach ($test in $results.TestResults.Test) {
        $totalTests++
        if ($test.Result -eq "Pass") {
            $passedTests++
            Write-Host "[PASS] $($test.Name)" -ForegroundColor Green
        } else {
            $failedTests++
            Write-Host "[FAIL] $($test.Name): $($test.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Total: $totalTests | Passed: $passedTests | Failed: $failedTests"
}

exit $exitCode