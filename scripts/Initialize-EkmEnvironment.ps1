#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-time setup of directories and permissions for the Cosmian EKM provider.

.DESCRIPTION
    Run this script ONCE on the target machine before the first deployment.

    What it does:
      1. Creates C:\Program Files\Cosmian\EKM\  (DLL location)
      2. Creates C:\ProgramData\Cosmian\EKM\    (config.toml location)
      3. Creates C:\ProgramData\Cosmian\EKM\logs\ (rolling log files)
      4. Grants the SQL Server service account Modify rights on
         C:\ProgramData\Cosmian\EKM\ (so it can write logs and read config).
      5. Creates a template config.toml if one does not already exist.

.PARAMETER SqlServiceAccount
    The Windows service account that runs SQL Server.
    Default: "NT SERVICE\MSSQLSERVER" (default instance).
    For a named instance use "NT SERVICE\MSSQL$<InstanceName>".

.NOTES
    Requires an elevated (Run as Administrator) PowerShell session.
#>

param(
    [string]$SqlServiceAccount = "NT SERVICE\MSSQLSERVER"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installDir = "C:\Program Files\Cosmian\EKM"
$dataDir    = "C:\ProgramData\Cosmian\EKM"
$logsDir    = "$dataDir\logs"
$configFile = "$dataDir\config.toml"

# ---------------------------------------------------------------------------
# 1. Create directories
# ---------------------------------------------------------------------------
Write-Host "[1/4] Creating directories..."
foreach ($dir in $installDir, $dataDir, $logsDir) {
    if (Test-Path $dir) {
        Write-Host "    Already exists: $dir"
    }
    else {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Write-Host "    Created: $dir"
    }
}

# ---------------------------------------------------------------------------
# 2. Grant the SQL Server service account Modify on the data directory
# ---------------------------------------------------------------------------
Write-Host "[2/4] Granting '$SqlServiceAccount' Modify rights on '$dataDir'..."
$acl  = Get-Acl $dataDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $SqlServiceAccount,
    "Modify",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow")
$acl.SetAccessRule($rule)
Set-Acl $dataDir $acl
Write-Host "    Done."

# ---------------------------------------------------------------------------
# 3. Grant the SQL Server service account ReadAndExecute on the install dir
#    (needed so the process can load the DLL)
# ---------------------------------------------------------------------------
Write-Host "[3/4] Granting '$SqlServiceAccount' ReadAndExecute rights on '$installDir'..."
$acl  = Get-Acl $installDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $SqlServiceAccount,
    "ReadAndExecute",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow")
$acl.SetAccessRule($rule)
Set-Acl $installDir $acl
Write-Host "    Done."

# ---------------------------------------------------------------------------
# 4. Create a template config.toml if it does not already exist
# ---------------------------------------------------------------------------
Write-Host "[4/4] Config file '$configFile'..."
if (Test-Path $configFile) {
    Write-Host "    Already exists - not overwritten."
}
else {
    $lines = @(
        '# Cosmian EKM provider configuration',
        '# Edit this file before starting SQL Server.',
        '',
        '# URL of the Cosmian KMS REST API',
        'kms_url = "https://kms.example.com:9998"',
        '',
        '# Path to the PEM-encoded client certificate for mutual TLS authentication',
        "client_cert = 'C:\ProgramData\Cosmian\EKM\client.pem'",
        '',
        '# Path to the matching private key',
        "client_key = 'C:\ProgramData\Cosmian\EKM\client.key'",
        '',
        '# Optional: custom CA bundle to trust (PEM)',
        "# ca_cert = 'C:\ProgramData\Cosmian\EKM\ca.pem'"
    )
    $lines | Set-Content $configFile -Encoding UTF8
    Write-Host "    Template created. Edit '$configFile' before starting SQL Server."
}

Write-Host ""
Write-Host "[OK] Environment initialised."
Write-Host "     Next steps:"
Write-Host "       1. Edit $configFile"
Write-Host "       2. Run Deploy-EkmDll.ps1 to copy the signed DLL"
