# PQVPN Tunnel Driver — Code Signing

This directory contains documentation and scripts for code-signing the PQVPN Tunnel NDIS driver.

## Files

| File | Description |
|------|-------------|
| `EV_CODE_SIGNING.md` | Complete guide to obtaining and using EV code-signing certificates |
| `sign_driver.ps1` | PowerShell script for automated driver signing |
| `verify_signature.ps1` | Script to verify driver signature validity |

## Quick Start

### Manual Signing (Development)
```powershell
# Sign with certificate from Windows store
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /n "PQVPN Project" pqvpn_tunnel.sys

# Verify signature
signtool verify /pa pqvpn_tunnel.sys
```

### Automated Signing (CI/CD)
```powershell
.\signing\sign_driver.ps1 -DriverPath ..\pqvpn_tunnel.sys -Verify
```

## CI Integration

The signing process is integrated into the GitHub Actions workflow. See `.github/workflows/build.yml` for the `driver-signing` job configuration.

Required GitHub Secrets:
- `EV_CERT_PFX`: Base64-encoded PFX file
- `EV_CERT_PASSWORD`: PFX file password
- `TIMESTAMP_SERVER`: Timestamp server URL (optional)

## Certificate Management

For production use, store your EV certificate in a USB token or hardware security module (HSM). For CI/CD environments, use a PFX file with strong password protection stored in GitHub Secrets.

## References

- [Microsoft Driver Signing Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/signing)
- [signtool Command-Line Options](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)