#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys a newly built and signed Cosmian EKM DLL to SQL Server.

.DESCRIPTION
    Run this script after every cargo build --release + Sign-EkmDll.ps1.

    What it does:
      1. Verifies the DLL signature is valid before deploying.
      2. Stops the SQL Server service.
      3. Copies the signed DLL to C:\Program Files\Cosmian\EKM\.
      4. Restarts the SQL Server service.
      5. Waits for the service to be running again and prints status.

.PARAMETER DllPath
    Path to the signed DLL to deploy.
    Defaults to target\release\cosmian_ekm_sql_server.dll (relative to repo root).

.PARAMETER SqlServiceName
    Windows service name of the SQL Server instance.
    Default: "MSSQLSERVER" (default instance).
    For a named instance use "MSSQL$<InstanceName>".

.PARAMETER SkipServiceRestart
    If set, the SQL Server service is NOT stopped/restarted.
    Useful if you want to restart manually or SQL Server is not yet registered.

.PARAMETER SkipRegistration
    If set, the script will NOT attempt to re-register the provider in SQL Server.

.NOTES
    Requires an elevated (Run as Administrator) PowerShell session.
    Run from the repository root directory.
#>

param(
    [string]$DllPath          = "target\release\cosmian_ekm_sql_server.dll",
    [string]$SqlServiceName   = "MSSQLSERVER",
    [switch]$SkipServiceRestart,
    [switch]$SkipRegistration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installDir  = "C:\Program Files\Cosmian\EKM"
$destDll     = "$installDir\cosmian_ekm_sql_server.dll"
$repoRoot    = Split-Path $PSScriptRoot -Parent
$fullDllPath = Join-Path $repoRoot $DllPath

# ---------------------------------------------------------------------------
# 1. Pre-flight: check the source DLL exists and has a valid signature
# ---------------------------------------------------------------------------
Write-Host "[1/6] Checking source DLL..."
if (-not (Test-Path $fullDllPath)) {
    Write-Error "DLL not found: $fullDllPath`nRun 'cargo build --release' then Sign-EkmDll.ps1 first."
}

$sig = Get-AuthenticodeSignature $fullDllPath
if ($sig.Status -ne 'Valid') {
    Write-Error "DLL signature is not valid (status: $($sig.Status)).`nRun Sign-EkmDll.ps1 first."
}
Write-Host "    Signature : $($sig.Status)"
Write-Host "    Signer    : $($sig.SignerCertificate.Subject)"

# ---------------------------------------------------------------------------
# 2. Check that the install directory exists
# ---------------------------------------------------------------------------
Write-Host "[2/6] Checking install directory..."
if (-not (Test-Path $installDir)) {
    Write-Error "Install directory '$installDir' does not exist.`nRun Initialize-EkmEnvironment.ps1 first."
}
Write-Host "    OK: $installDir"

# ---------------------------------------------------------------------------
# 3. Stop SQL Server
# ---------------------------------------------------------------------------
if ($SkipServiceRestart) {
    Write-Host "[3/6] Skipping SQL Server stop (SkipServiceRestart set)."
}
else {
    Write-Host "[3/6] Stopping SQL Server service '$SqlServiceName'..."
    $svc = Get-Service -Name $SqlServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Error "Service '$SqlServiceName' not found. Check the service name or use -SkipServiceRestart."
    }
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $SqlServiceName -Force
        # Wait up to 60 seconds for the service to stop
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
    }
    Write-Host "    Service stopped."
}

# ---------------------------------------------------------------------------
# 4. Copy the DLL
# ---------------------------------------------------------------------------
Write-Host "[4/6] Copying DLL to '$destDll'..."
Copy-Item -Path $fullDllPath -Destination $destDll -Force
Write-Host "    Done."

# ---------------------------------------------------------------------------
# 5. Start SQL Server
# ---------------------------------------------------------------------------
if ($SkipServiceRestart) {
    Write-Host "[5/6] Skipping SQL Server start (SkipServiceRestart set)."
}
else {
    Write-Host "[5/6] Starting SQL Server service '$SqlServiceName'..."
    Start-Service -Name $SqlServiceName
    $svc = Get-Service -Name $SqlServiceName
    $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
    Write-Host "    Status: $((Get-Service $SqlServiceName).Status)"
}

Write-Host ""
Write-Host "[OK] Deployment complete."
Write-Host "     DLL installed at: $destDll"
if (-not $SkipServiceRestart) {
    Write-Host "     SQL Server is running."
}

# ---------------------------------------------------------------------------
# 6. Rec-register the provider in SQL Server
# ---------------------------------------------------------------------------
if ($SkipRegistration) {
    Write-Host "[6/6] Skipping SQL Server provider (re)registration (SkipRegistration set)."
}
else {
    Write-Host "[6/6] Re-registering the cryptographic provider in SQL Server..."
    sqlcmd -S localhost -E -Q "IF EXISTS (SELECT 1 FROM sys.cryptographic_providers WHERE name='CosmianEKM') DROP CRYPTOGRAPHIC PROVIDER CosmianEKM;"
    sqlcmd -S localhost -E -Q "CREATE CRYPTOGRAPHIC PROVIDER CosmianEKM FROM FILE = '$destDll';"
    Write-Host "    Done."
}