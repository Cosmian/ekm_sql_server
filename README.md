# cosmian_ekm_sql_server

A Windows DLL implementing the [SQL Server Extensible Key Management (EKM)](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/extensible-key-management-ekm) provider interface, backed by the [Cosmian KMS](https://github.com/Cosmian/kms).

The library exposes the `SqlCrypt*` C ABI required by SQL Server and is built as a `cdylib` (a Windows `.dll`).

---

## Prerequisites

| Tool | Notes |
|---|---|
| [Rust toolchain](https://rustup.rs) ≥ 1.85 (edition 2024) | `rustup update stable` |
| MSVC target `x86_64-pc-windows-msvc` | `rustup target add x86_64-pc-windows-msvc` |
| [LLVM / Clang](https://releases.llvm.org/download.html) | Required by `bindgen` at build time. Add `<llvm>/bin` to `PATH` and set `LIBCLANG_PATH=<llvm>/lib`. |

> **Note:** `bindgen` calls Clang to parse `sqlcrypt.h` during every `cargo build`. If Clang is not on `PATH`, the build will fail with `Unable to find libclang`.

---

## Building

### Debug build

```powershell
cargo build
```

Output: `target\debug\cosmian_ekm_sql_server.dll`

### Release build

```powershell
cargo build --release
```

Output: `target\release\cosmian_ekm_sql_server.dll`

The DLL exports the full `SqlCrypt*` symbol set expected by SQL Server. No additional link flags are required; the `#[no_mangle] pub extern "C"` declarations are sufficient.

---

## Installation

1. Copy the release DLL to a permanent location, for example  
   `C:\Program Files\Cosmian\EKM\cosmian_ekm_sql_server.dll`

2. Register the provider with SQL Server (run as `sysadmin`):

```sql
-- Enable EKM support
sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure 'EKM provider enabled', 1;
RECONFIGURE;

-- Register the DLL
CREATE CRYPTOGRAPHIC PROVIDER CosmianEKM
    FROM FILE = 'C:\Program Files\Cosmian\EKM\cosmian_ekm_sql_server.dll';
```

---

## Configuration file

The provider reads its settings from a TOML file at:

```
%PROGRAMDATA%\Cosmian\EKM\config.toml
```

On a default Windows installation this is:

```
C:\ProgramData\Cosmian\EKM\config.toml
```

`%PROGRAMDATA%` is used (rather than `%APPDATA%`) because SQL Server runs as a
Windows service account (e.g. `NT SERVICE\MSSQLSERVER`) that has no user
profile. `C:\ProgramData` is readable and writable by all service accounts and
persists across sessions.

### Example `config.toml`

```toml
# URL of the Cosmian KMS REST API
kms_url = "https://kms.example.com:9998"

# Path to the PEM-encoded client certificate used for mutual TLS authentication
client_cert = 'C:\ProgramData\Cosmian\EKM\client.pem'

# Path to the PEM-encoded private key for the client certificate
client_key  = 'C:\ProgramData\Cosmian\EKM\client.key'

# Optional: path to a custom CA certificate bundle (PEM) to trust
# ca_cert = 'C:\ProgramData\Cosmian\EKM\ca.pem'
```

Create the directory and drop the file there before starting SQL Server:

```powershell
New-Item -ItemType Directory -Force -Path 'C:\ProgramData\Cosmian\EKM'
# then copy your config.toml into that directory
```

---

## Log files

Rolling daily log files are written to:

```
%PROGRAMDATA%\Cosmian\EKM\logs\cosmian_ekm.log.<yyyy-MM-dd>
```

On a default Windows installation:

```
C:\ProgramData\Cosmian\EKM\logs\
    cosmian_ekm.log.2026-02-24
    cosmian_ekm.log.2026-02-25
    ...
```

The directory is created automatically on the first call to
`SqlCryptInitializeProvider` (i.e. when SQL Server loads the provider). If
directory creation fails (e.g. due to permissions), the provider will still
load but no log file will be written.

Logging is initialised only once per process lifetime. The background I/O
thread is shut down and all pending records are flushed when SQL Server calls
`SqlCryptFreeProvider` (i.e. when the provider is unloaded).

### Granting write access to the SQL Server service account

```powershell
$serviceAccount = 'NT SERVICE\MSSQLSERVER'   # adjust for named instances
$logDir = 'C:\ProgramData\Cosmian\EKM\logs'
New-Item -ItemType Directory -Force -Path $logDir
$acl = Get-Acl $logDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $serviceAccount, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.SetAccessRule($rule)
Set-Acl $logDir $acl
```

---

## Project structure

```
build.rs          # Calls bindgen to generate Rust types from sqlcrypt.h
Cargo.toml
src/
  lib.rs          # SqlCrypt* entry points
  sqlcrypt.h      # Microsoft SQL Server EKM C interface header
  wrapper.h       # Thin bindgen wrapper that includes sqlcrypt.h
```

---

## License

See [LICENSE](LICENSE).
