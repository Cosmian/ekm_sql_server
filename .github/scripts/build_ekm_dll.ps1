$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Helper: run a native command, stream its output, and throw on non-zero exit.
# Works in both PS 5.1 and PS 7.
# ---------------------------------------------------------------------------
function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(ValueFromRemainingArguments)][string[]] $Arguments
    )
    $ErrorActionPreference = "Continue"
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "'$Exe $($Arguments -join ' ')' failed with exit code $LASTEXITCODE"
    }
}

function Build-EkmDll {
    # -------------------------------------------------------------------------
    # Validate required environment variables
    # -------------------------------------------------------------------------
    if (-not $env:OPENSSL_DIR) {
        throw "OPENSSL_DIR is not set. Install OpenSSL via vcpkg --triplet x64-windows-static first."
    }
    if (-not (Test-Path $env:OPENSSL_DIR)) {
        throw "OPENSSL_DIR does not exist: $env:OPENSSL_DIR"
    }
    if (-not $env:LIBCLANG_PATH) {
        throw "LIBCLANG_PATH is not set. Required by build.rs (bindgen 0.71)."
    }

    Write-Host "OPENSSL_DIR    = $env:OPENSSL_DIR"
    Write-Host "OPENSSL_STATIC = $env:OPENSSL_STATIC"
    Write-Host "LIBCLANG_PATH  = $env:LIBCLANG_PATH"

    # -------------------------------------------------------------------------
    # Ensure the MSVC Windows target is present
    # -------------------------------------------------------------------------
    try {
        Invoke-NativeCommand rustup target add x86_64-pc-windows-msvc
    }
    catch {
        Write-Host "Note: $_ (target is likely already installed)"
    }

    # -------------------------------------------------------------------------
    # Build the cdylib (DLL only; --lib skips the generate-certs binary)
    # -------------------------------------------------------------------------
    Invoke-NativeCommand cargo build --release --lib

    $dll = "target\release\cosmian_ekm_sql_server.dll"
    if (-not (Test-Path $dll)) {
        throw "Expected DLL not found after build: $dll"
    }

    $item = Get-Item $dll
    Write-Host ""
    Write-Host "DLL built successfully:"
    Write-Host "  Name    : $($item.Name)"
    Write-Host "  Size    : $([math]::Round($item.Length / 1KB, 1)) KB"
    Write-Host "  Modified: $($item.LastWriteTime)"
}
