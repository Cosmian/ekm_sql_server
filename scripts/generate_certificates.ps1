#Requires -Version 5.1
<#
.SYNOPSIS
    Generate a self-signed CA and a client certificate for Cosmian EKM testing.

.DESCRIPTION
    Uses OpenSSL to create:
      1. A CA private key + self-signed CA certificate (ca.key.pem, ca.cert.pem)
      2. A client private key + CSR + signed client cert  (admin.key.pem, admin.cert.pem)

    The client certificate has CN=admin and a SAN of DNS:admin so both
    SqlCryptCreateKey identity-validation paths are covered.

    Output is written to the repository's certificates\ directory.

.PARAMETER OpenSslExe
    Path to the openssl.exe binary.  When omitted the script searches PATH.

.PARAMETER OutDir
    Output directory (default: <repo>\certificates).

.PARAMETER Username
    Username for the client certificate CN (default: admin).
#>
[CmdletBinding()]
param(
    [string]$OpenSslExe,
    [string]$OutDir,
    [string]$Username = "admin"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------- locate openssl ----------
if (-not $OpenSslExe) {
    $cmd = Get-Command openssl -ErrorAction SilentlyContinue
    if ($cmd) { $OpenSslExe = $cmd.Definition }
}
if (-not $OpenSslExe) {
    # Fall back to the common winget / scoop / chocolatey locations
    $candidates = @(
        "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe",
        "$env:ProgramFiles\OpenSSL\bin\openssl.exe",
        "$env:LOCALAPPDATA\Programs\OpenSSL\bin\openssl.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $OpenSslExe = $c; break }
    }
}
if (-not $OpenSslExe -or -not (Test-Path $OpenSslExe)) {
    Write-Error "openssl.exe not found.  Install OpenSSL or pass -OpenSslExe <path>."
    exit 1
}
Write-Host "Using OpenSSL: $OpenSslExe"

# ---------- output directory ----------
if (-not $OutDir) {
    $OutDir = Join-Path $PSScriptRoot "..\certificates"
}
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}
$OutDir = (Resolve-Path $OutDir).Path
Write-Host "Output directory: $OutDir"

# ---------- temporary OpenSSL config for SAN ----------
$sanConf = Join-Path $OutDir "_san.cnf"
@"
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no

[req_dn]
CN = $Username

[v3_req]
subjectAltName = DNS:$Username
"@ | Set-Content -Path $sanConf -Encoding ASCII

# ---------- 1. CA key + cert ----------
$caKey  = Join-Path $OutDir "ca.key.pem"
$caCert = Join-Path $OutDir "ca.cert.pem"

if (-not (Test-Path $caCert)) {
    Write-Host "Generating CA private key..."
    & $OpenSslExe genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out $caKey 2>&1 | Write-Host
    Write-Host "Generating self-signed CA certificate (10 years)..."
    & $OpenSslExe req -new -x509 -key $caKey -days 3650 `
        -subj "/CN=Cosmian EKM Test CA/O=Cosmian/C=FR" `
        -out $caCert 2>&1 | Write-Host
    Write-Host "  -> $caCert"
} else {
    Write-Host "CA certificate already exists, skipping."
}

# ---------- 2. Client key + cert ----------
$clientKey  = Join-Path $OutDir "$Username.key.pem"
$clientCsr  = Join-Path $OutDir "$Username.csr.pem"
$clientCert = Join-Path $OutDir "$Username.cert.pem"

if (-not (Test-Path $clientCert)) {
    Write-Host "Generating client private key for '$Username'..."
    & $OpenSslExe genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $clientKey 2>&1 | Write-Host

    Write-Host "Generating CSR..."
    & $OpenSslExe req -new -key $clientKey -config $sanConf -out $clientCsr 2>&1 | Write-Host

    Write-Host "Signing client certificate with CA (1 year)..."
    & $OpenSslExe x509 -req -in $clientCsr -CA $caCert -CAkey $caKey `
        -CAcreateserial -days 365 `
        -extfile $sanConf -extensions v3_req `
        -out $clientCert 2>&1 | Write-Host
    Write-Host "  -> $clientCert"

    # Clean up CSR and serial
    Remove-Item $clientCsr -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $OutDir "ca.cert.srl") -ErrorAction SilentlyContinue
} else {
    Write-Host "Client certificate for '$Username' already exists, skipping."
}

# Clean up temp config
Remove-Item $sanConf -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done.  Files in ${OutDir}:"
Get-ChildItem $OutDir -Filter "*.pem" | ForEach-Object { Write-Host "  $($_.Name)" }
