# PQVPN Tunnel Driver — HLK/DDI Compliance Testing

This directory contains the Hardware Lab Kit (HLK) test configuration and runner scripts for validating the PQVPN Tunnel NDIS miniport driver against Windows DDI compliance requirements.

## Prerequisites

1. **Windows Hardware Lab Kit (HLK)** installed
   - Download from [Microsoft HLK](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/)
   - Requires Windows 10/11 Pro or Enterprise, or Windows Server 2019+

2. **WDK (Windows Driver Kit)** matching the target OS version
   - Install via Visual Studio Installer or standalone WDK installer

3. **Test signing enabled** on the test machine:
   ```powershell
   bcdedit /set testsigning on
   reboot
   ```

## Running HLK Tests

### Manual Execution

```powershell
# From driver/pqvpn_tunnel/hlk_tests/
.\run_hlk_tests.ps1 -ConfigFile .\pqvpn_tunnel.hlkx -Architecture x64
```

### CI Integration

The HLK tests are integrated into the functional release gates workflow (`.github/workflows/functional-release-gates.yml`). They run automatically on every push to `main` and `future` branches.

## Test Suites

| Suite | Description | Priority |
|-------|-------------|----------|
| NDIS_Miniport | Basic driver installation, removal, entry/exit, NDIS registration | High |
| DDI_Compliance | WDM interface compliance, NDIS API usage, memory management | High/Medium |
| Functional | Adapter creation, file object access, security descriptor validation | High/Medium |
| Stress | IRP fuzzing, concurrent access testing | Low (Phase 4) |

## Test Results

Results are saved to `hlk_results.xml` in the test output directory. The runner script parses and displays a summary of pass/fail status for each test case.

## DDI Compliance Requirements

The PQVPN Tunnel driver must comply with:
- WDM Driver Interface specifications
- NDIS 6.x Miniport API requirements
- Windows kernel memory management rules
- Power management guidelines (for future phases)

## Troubleshooting

### HLK not found
Ensure the Hardware Lab Kit is installed and `hlk.exe` is in your PATH.

### Test signing errors
Verify test signing is enabled: `bcdedit /enum | findstr testsigning`

### Driver installation failures
Check the Windows Event Viewer for driver-specific error messages. Ensure the INF file references the correct architecture.