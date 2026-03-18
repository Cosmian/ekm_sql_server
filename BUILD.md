# Build Guide

This document explains how to build the Cosmian EKM SQL Server provider DLL
and get it code-signed and ready for deployment.

## Prerequisites

| Tool | Purpose |
|------|---------|
| [Rust toolchain](https://rustup.rs) (stable, `x86_64-pc-windows-msvc`) | Compiles the DLL |
| [vcpkg](https://vcpkg.io) + OpenSSL (`x64-windows-static`) | OpenSSL headers/libs used by the certificate-generation utility |
| PowerShell 5.1 (elevated) | Runs the helper scripts |
| Visual Studio Build Tools 2019 or later | MSVC linker required by the Windows CDylib target |

> The OpenSSL path is configured in `.cargo/config.toml` via `OPENSSL_DIR`.
> Update it if your vcpkg installation is in a different location.

---

## 1. One-time machine setup

Run these two scripts **once** on any machine where the DLL will be compiled
and/or deployed.  Skip a script if you have already run it.

```powershell
# Create directory structure and set ACLs for the SQL Server service account
scripts\Initialize-EkmEnvironment.ps1

# Create the self-signed Authenticode certificate used to sign the DLL
scripts\New-EkmCertificate.ps1
```

`New-EkmCertificate.ps1` creates a certificate with subject `CN=Cosmian EKM Dev`,
stores it in `Cert:\LocalMachine\My`, and copies it to `Cert:\LocalMachine\Root`
so SQL Server trusts the signature.  It also exports the certificate to
`scripts\CosmianEKM.cer`.

---

## 2. Build

```powershell
cargo build --release
```

The output is `target\release\cosmian_ekm_sql_server.dll`.

The `generate-certs` utility (used during development to create mTLS
certificates) is compiled as a separate binary:

```powershell
cargo build --release --bin generate-certs
```

---

## 3. Sign the DLL

SQL Server requires that any DLL loaded as a cryptographic provider carries a
valid Authenticode signature.

```powershell
# Must be run as Administrator
scripts\Sign-EkmDll.ps1
```

The script:
1. Locates the `CN=Cosmian EKM Dev` certificate in `Cert:\LocalMachine\My`.
2. Signs `target\release\cosmian_ekm_sql_server.dll` with SHA-256.
3. Verifies the resulting signature status is `Valid`.

To sign a different build (e.g. debug):

```powershell
scripts\Sign-EkmDll.ps1 -DllPath "target\debug\cosmian_ekm_sql_server.dll"
```

---

## 4. Verify the signature

```powershell
Get-AuthenticodeSignature "target\release\cosmian_ekm_sql_server.dll"
```

The `Status` field must read `Valid`.

---

## Script reference

| Script | When to run |
|--------|-------------|
| `Initialize-EkmEnvironment.ps1` | Once per machine — creates directories and ACLs |
| `New-EkmCertificate.ps1` | Once per machine — creates the code-signing certificate |
| `Sign-EkmDll.ps1` | After every `cargo build --release` |
| `Deploy-EkmDll.ps1` | After signing — copies the DLL and registers the provider |
| `Prepare-Integration-Tests.ps1` | All-in-one: build + sign + deploy + copy test config |
| `generate_certificates.ps1` | Generates mTLS certificates for the KMS (development only) |

---

## Troubleshooting

**`error: linking with link.exe failed`** — Make sure Visual Studio Build Tools
are installed and the `x86_64-pc-windows-msvc` target is active:
```powershell
rustup target add x86_64-pc-windows-msvc
rustup default stable-x86_64-pc-windows-msvc
```

**`error[E0433]: failed to resolve: use of unresolved item openssl`** — The
`OPENSSL_DIR` environment variable in `.cargo\config.toml` points to a path
that does not exist.  Install the OpenSSL static libraries via vcpkg or update
the path.

**`Certificate 'CN=Cosmian EKM Dev' not found`** — Run
`scripts\New-EkmCertificate.ps1` first (as Administrator).

**`DLL signature is not valid`** — The certificate may have expired (default
validity is 2 years).  Run `scripts\New-EkmCertificate.ps1` again after
removing the old certificate:
```powershell
$t = (Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq "CN=Cosmian EKM Dev").Thumbprint
Remove-Item "Cert:\LocalMachine\My\$t"
Remove-Item "Cert:\LocalMachine\Root\$t"
scripts\New-EkmCertificate.ps1
```
