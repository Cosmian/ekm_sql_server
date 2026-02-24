#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Signs the Cosmian EKM DLL with the self-signed certificate created by
    New-EkmCertificate.ps1.

.DESCRIPTION
    Run this script after every cargo build --release.

    What it does:
      1. Locates the certificate in LocalMachine\My by subject name.
      2. Signs target\release\cosmian_ekm_sql_server.dll with
         Set-AuthenticodeSignature.
      3. Verifies the resulting signature status.

.NOTES
    Requires an elevated (Run as Administrator) PowerShell session.
    Run from the repository root directory.
#>

param(
    # Path to the DLL to sign. Defaults to the release build output.
    [string]$DllPath = "target\release\cosmian_ekm_sql_server.dll"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$CertSubject = "CN=Cosmian EKM Dev"

# ---------------------------------------------------------------------------
# Resolve the DLL path relative to the repository root
# ---------------------------------------------------------------------------
$repoRoot = Split-Path $PSScriptRoot -Parent
$fullDllPath = Join-Path $repoRoot $DllPath

if (-not (Test-Path $fullDllPath)) {
    Write-Error "DLL not found: $fullDllPath`nRun 'cargo build --release' first."
}

# ---------------------------------------------------------------------------
# Locate the certificate
# ---------------------------------------------------------------------------
Write-Host "[1/3] Looking up certificate '$CertSubject' in LocalMachine\My..."
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq $CertSubject } |
    Select-Object -First 1

if (-not $cert) {
    Write-Error "Certificate '$CertSubject' not found.`nRun New-EkmCertificate.ps1 first."
}

Write-Host "    Found: thumbprint $($cert.Thumbprint), expires $($cert.NotAfter)"

# ---------------------------------------------------------------------------
# Sign the DLL
# ---------------------------------------------------------------------------
Write-Host "[2/3] Signing '$fullDllPath'..."
$result = Set-AuthenticodeSignature `
    -FilePath    $fullDllPath `
    -Certificate $cert

if ($result.Status -ne 'Valid') {
    Write-Error "Signing failed: status = $($result.Status)"
}

Write-Host "    Signed OK."

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
Write-Host "[3/3] Verifying signature..."
$sig = Get-AuthenticodeSignature $fullDllPath
Write-Host "    Status     : $($sig.Status)"
Write-Host "    Signer     : $($sig.SignerCertificate.Subject)"
Write-Host "    Thumbprint : $($sig.SignerCertificate.Thumbprint)"

if ($sig.Status -ne 'Valid') {
    Write-Error "Signature verification failed: $($sig.Status)"
}

Write-Host ""
Write-Host "[OK] DLL is signed and ready to deploy."
Write-Host "     Run Deploy-EkmDll.ps1 to copy it to SQL Server."
