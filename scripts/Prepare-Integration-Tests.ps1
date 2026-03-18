#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds, signs, deploys the EKM DLL, copies the test config, and restarts SQL Server.
    Run this script as Administrator before running integration tests.

.DESCRIPTION
    Delegates each step to the dedicated scripts:
      1. cargo build --release
      2. Sign-EkmDll.ps1      (code signing)
      3. Deploy-EkmDll.ps1    (stop SQL Server, copy DLL, start SQL Server, register provider)
      4. Copy config.test.toml to %ProgramData%\Cosmian\EKM\config.toml

.NOTES
    Run from the repository root or the scripts\ directory.
    Prerequisites: New-EkmCertificate.ps1 and Initialize-EkmEnvironment.ps1
    must have been run at least once on this machine.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot   = Split-Path $PSScriptRoot -Parent
$scriptsDir = $PSScriptRoot

# 1. Build
Write-Host "[1/4] Building release DLL..."
Push-Location $repoRoot
cargo build --release
if ($LASTEXITCODE -ne 0) { Write-Error "cargo build --release failed" }
Pop-Location

# 2. Sign (delegate to Sign-EkmDll.ps1)
Write-Host "[2/4] Signing DLL..."
& "$scriptsDir\Sign-EkmDll.ps1"

# 3. Deploy (delegate to Deploy-EkmDll.ps1)
Write-Host "[3/4] Deploying DLL..."
& "$scriptsDir\Deploy-EkmDll.ps1"

# 4. Copy test config
Write-Host "[4/4] Copying test config..."
$configSrc  = Join-Path $repoRoot "config.test.toml"
$configDest = "C:\ProgramData\Cosmian\EKM\config.toml"
$configDir  = Split-Path $configDest -Parent
if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
Copy-Item $configSrc $configDest -Force
Write-Host "    Config installed at: $configDest"

Write-Host ""
Write-Host "[OK] Ready. Run integration tests with:"
Write-Host "    cargo test --test integration -- --test-threads=1"
