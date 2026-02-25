# Sign the DLL, deploy it, restart SQL Server, and test registration.
# Must be run from an ELEVATED (Administrator) PowerShell prompt.
#
# Usage:
#   cd test_provider_c
#   .\sign_and_deploy.ps1

param(
    [string]$DllName     = "test_provider.dll",
    [string]$DeployDir   = "C:\Program Files\Cosmian\EKM",
    [string]$DeployName  = "cosmian_ekm_sql_server.dll",
    [string]$ProviderSql = "CosmianEKM"
)

$ErrorActionPreference = "Stop"

# --- Locate code-signing certificate --------------------------------------
$cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Select-Object -First 1
if (-not $cert) {
    Write-Error "No code-signing certificate found in Cert:\LocalMachine\My"
    exit 1
}
Write-Host "Signing with: $($cert.Subject)  ($($cert.Thumbprint))"

# --- Sign ------------------------------------------------------------------
Set-AuthenticodeSignature -FilePath $DllName -Certificate $cert
$sig = Get-AuthenticodeSignature $DllName
if ($sig.Status -ne "Valid") {
    Write-Error "Signature status: $($sig.Status) — $($sig.StatusMessage)"
    exit 1
}
Write-Host "Signature: $($sig.Status)"

# --- Deploy ----------------------------------------------------------------
if (-not (Test-Path $DeployDir)) {
    New-Item -ItemType Directory -Path $DeployDir -Force | Out-Null
}

Write-Host "Stopping MSSQLSERVER..."
Stop-Service MSSQLSERVER -Force

Copy-Item $DllName (Join-Path $DeployDir $DeployName) -Force
Write-Host "Copied to $DeployDir\$DeployName"

Write-Host "Starting MSSQLSERVER..."
Start-Service MSSQLSERVER

# --- Test ------------------------------------------------------------------
Write-Host "`n--- Testing CREATE CRYPTOGRAPHIC PROVIDER ---"
sqlcmd -S localhost -E -Q "IF EXISTS (SELECT 1 FROM sys.cryptographic_providers WHERE name='$ProviderSql') DROP CRYPTOGRAPHIC PROVIDER $ProviderSql;"
sqlcmd -S localhost -E -Q "CREATE CRYPTOGRAPHIC PROVIDER $ProviderSql FROM FILE = '$DeployDir\$DeployName';"
