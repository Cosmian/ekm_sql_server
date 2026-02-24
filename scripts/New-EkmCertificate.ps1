#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates a self-signed Authenticode certificate for the Cosmian EKM DLL
    and registers it in the machine trust store.

.DESCRIPTION
    Run this script ONCE on the target machine before signing the DLL for
    the first time.

    What it does:
      1. Creates a self-signed code-signing certificate in LocalMachine\My.
      2. Adds the certificate to LocalMachine\Root so that SQL Server
         trusts the signature when loading the EKM provider DLL.
      3. Exports the public certificate to scripts\CosmianEKM.cer so it
         can be copied and trusted on other machines if needed.

.NOTES
    Requires an elevated (Run as Administrator) PowerShell session.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Configuration — adjust if needed
# ---------------------------------------------------------------------------
$CertSubject   = "CN=Cosmian EKM Dev"
$ValidityYears = 2
$ExportPath    = Join-Path $PSScriptRoot "CosmianEKM.cer"

# ---------------------------------------------------------------------------
# Check that the cert does not already exist
# ---------------------------------------------------------------------------
$existing = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq $CertSubject } |
    Select-Object -First 1

if ($existing) {
    Write-Host "[INFO] Certificate '$CertSubject' already exists (thumbprint: $($existing.Thumbprint))."
    Write-Host "       Delete it first if you want to recreate it:"
    Write-Host "       Remove-Item Cert:\LocalMachine\My\$($existing.Thumbprint)"
    exit 0
}

# ---------------------------------------------------------------------------
# 1. Create the self-signed certificate
# ---------------------------------------------------------------------------
Write-Host "[1/3] Creating self-signed code-signing certificate..."
$cert = New-SelfSignedCertificate `
    -Subject           $CertSubject `
    -Type              CodeSigning `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter          (Get-Date).AddYears($ValidityYears) `
    -KeyUsage          DigitalSignature `
    -KeyAlgorithm      RSA `
    -KeyLength         2048

Write-Host "    Subject   : $($cert.Subject)"
Write-Host "    Thumbprint: $($cert.Thumbprint)"
Write-Host "    Expires   : $($cert.NotAfter)"

# ---------------------------------------------------------------------------
# 2. Add to Trusted Root so SQL Server accepts the signature
# ---------------------------------------------------------------------------
Write-Host "[2/3] Adding certificate to LocalMachine\Root (trusted root CAs)..."
$rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    "Root", "LocalMachine")
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close()
Write-Host "    Done."

# ---------------------------------------------------------------------------
# 3. Export the public certificate (.cer) for reference / distribution
# ---------------------------------------------------------------------------
Write-Host "[3/3] Exporting public certificate to '$ExportPath'..."
$bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes($ExportPath, $bytes)
Write-Host "    Done."

Write-Host ""
Write-Host "[OK] Certificate created and trusted."
Write-Host "     Run Sign-EkmDll.ps1 to sign the DLL."
