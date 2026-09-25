# PQVPN Tunnel Driver — EV Code-Signing Guide

This document describes the process for obtaining and using an Extended Validation (EV) code-signing certificate to sign the PQVPN Tunnel NDIS driver for production deployment on Windows.

## Why EV Code-Signing?

Windows 10+ requires drivers to be signed with a trusted certificate. There are two main paths:

1. **WHQL Certification**: Submit driver to Microsoft's Hardware Lab Kit (HLK) testing and certification process. This is time-consuming and expensive.
2. **EV Code-Signing + Attestation**: Use an EV code-signing certificate combined with Microsoft's attestation pipeline. This is faster and more cost-effective for modern Windows deployments.

PQVPN uses the second approach: EV code-signing with optional Microsoft attestation through Partner Center.

## Obtaining an EV Code-Signing Certificate

### Requirements
- Business entity registered in a supported country
- D-U-N-S Number (Data Universal Numbering System)
- Valid business address and phone number
- Domain ownership verification

### Recommended CAs
1. **DigiCert** — Industry standard, widely trusted
2. **Sectigo** — Cost-effective alternative
3. **GlobalSign** — Good international support

### Process (using DigiCert as example)
1. Visit [DigiCert Code Signing](https://www.digicert.com/code-signing/)
2. Select "EV Code Signing Certificate"
3. Complete the application form with business details
4. Submit D-U-N-S Number for verification
5. Wait for validation (typically 3-7 business days)
6. Receive certificate via email or download from customer portal

### Cost
- EV code-signing certificates typically cost $300-$800/year depending on CA and features

## Installing the Certificate

### Option 1: USB Token (Recommended for Production)
Most CAs provide a USB token (e.g., SafeNet, Aladdin eToken) containing the private key. This provides hardware-level security.

```powershell
# Insert USB token and verify certificate is visible
certutil -scinfo
```

### Option 2: PFX File (For Development/CI)
If you have a .pfx file with password protection:

```powershell
# Import certificate into Windows certificate store
Import-PfxCertificate -FilePath "pqvpn-ev-cert.pfx" `
    -Password (ConvertTo-SecureString "your-password" -AsPlainText -Force) `
    -CertStoreLocation Cert:\LocalMachine\My
```

## Signing the Driver

### Manual Signing (Development)

```powershell
# Sign the driver binary
signtool sign /fd SHA256 /tr http://timestamp.digicert.com `
    /td SHA256 /n "PQVPN Project" pqvpn_tunnel.sys

# Verify signature
signtool verify /pa pqvpn_tunnel.sys
```

### Automated Signing (CI/CD)

See [sign_driver.ps1](./sign_driver.ps1) for the automated signing script used in CI.

## Microsoft Attestation Pipeline (Optional)

For additional trust and to bypass some driver signature enforcement requirements, you can submit your signed driver through Microsoft's attestation pipeline via Partner Center.

### Prerequisites
- Microsoft Partner Center account
- EV code-signed driver binary
- Driver INF file

### Process
1. Log in to [Partner Center](https://partner.microsoft.com/)
2. Navigate to "Dashboard" > "Windows Hardware"
3. Select "Submit a driver for attestation"
4. Upload your signed driver package (.sys + .inf)
5. Complete the required metadata and testing information
6. Submit for review (typically 1-3 business days)

### Benefits of Attestation
- Driver can be installed without WHQL certification
- Bypasses some Driver Signature Enforcement (DSE) requirements
- Provides additional trust signal to users

## CI/CD Integration

The signing process is integrated into the GitHub Actions workflow via the `driver-signing` job. This job:

1. Retrieves the EV certificate from GitHub Secrets
2. Signs the driver binary using signtool
3. Verifies the signature
4. Uploads the signed driver as a build artifact

### Required GitHub Secrets
- `EV_CERT_PFX`: Base64-encoded PFX file containing the EV certificate
- `EV_CERT_PASSWORD`: Password for the PFX file
- `TIMESTAMP_SERVER`: URL of the timestamp server (default: http://timestamp.digicert.com)

## Testing Signed Driver Installation

### Without Test Signing Mode
```powershell
# Install signed driver
pnputil /add-driver pqvpn_tunnel.inf /install

# Verify installation
pnputil /enum-drivers | findstr PQVPN
```

### With Test Signing Mode (Development Only)
```powershell
# Enable test signing mode
bcdedit /set testsigning on
reboot

# Install unsigned or test-signed driver
pnputil /add-driver pqvpn_tunnel.inf /install
```

## Troubleshooting

### "Driver is not digitally signed" error
- Verify the certificate chain is complete and trusted
- Check that the timestamp server URL is correct and accessible
- Ensure the certificate has not expired

### "Signature verification failed" error
- Re-sign the driver with a fresh timestamp
- Verify the PFX file password is correct
- Check that signtool version supports SHA256 signing

### USB Token Not Detected
- Install the appropriate token drivers from the CA's website
- Try a different USB port
- Restart the computer with the token inserted