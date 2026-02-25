# Minimal EKM Provider — SQL Server 2025 Reproduction Case

## Problem

`CREATE CRYPTOGRAPHIC PROVIDER` fails with:

```
Msg 33029, Level 16, State 2, Server DESKTOP-7KE1EPJ, Line 1
Cannot initialize cryptographic provider. Provider error code: 0.
(Success - Consult EKM Provider for details)
```

The error code is **0 (Success)**, meaning every `SqlCrypt*` function called by
SQL Server returned `scp_err_Success`, yet SQL Server still rejects the provider.

## Environment

| Component | Value |
|---|---|
| **SQL Server** | Microsoft SQL Server 2025 (RTM-GDR) (KB5073177) — **17.0.1050.2** (X64) |
| **Edition** | Enterprise Developer Edition (64-bit) |
| **OS** | Windows 10 Pro 10.0 Build 26100 (x64) |
| **Compiler** | MSVC 19.44.35209 for x64 (Visual Studio 2022) |
| **EKM enabled** | `sp_configure 'EKM provider enabled'` → `run_value = 1` |

## What this DLL does

This is a **pure C** minimal EKM provider that implements all 17 `SqlCrypt*`
entry points required by the SQL Crypto API v1 (`sqlcrypt.h`,
`x_scp_SqlCpVerMajor = 1`, `x_scp_SqlCpVerMinor = 1`).

The `SqlCryptGetProviderInfo` function populates the `SqlCpProviderInfo` struct
with values identical to the sample USB provider from the official
"SQL Server 2008 EKM Development Guide" (`EKMDevGuide.docx`):

| Field | Value | Notes |
|---|---|---|
| `name.cb` | 38 | `wcslen(L"Test C EKM Provider") * 2` |
| `name.ws` | pointer to `L"Test C EKM Provider"` | |
| `guid` | `{C05A1A00-1001-4001-8001-000000000001}` | Stable GUID |
| `version` | `{1, 0, 0, 0}` | Matches PE VERSIONINFO `FILEVERSION 1,0,0,0` |
| `scpVersion` | `{1, 1, 0, 0}` | SQL Crypto API v1.1 |
| `authType` | `scp_auth_Basic` (1) | |
| `symmKeySupport` | `scp_kf_Supported` (1) | |
| `asymmKeySupport` | `scp_kf_Supported` (1) | |
| `cbKeyThumbLen` | 16 | `sizeof(GUID)` |
| `fAcceptsKeyName` | `TRUE` (1) | |

All other functions return `scp_err_NotFound` (algorithm/key enumeration) or
`scp_err_NotSupported` (operations).

## Files

| File | Description |
|---|---|
| `test_provider.c` | Complete EKM provider source — single file, no dependencies beyond `<windows.h>` |
| `version.rc` | PE VERSIONINFO resource (`FILEVERSION 1,0,0,0`) |
| `sign_and_deploy.ps1` | PowerShell script to sign, deploy, restart SQL Server, and test |
| `README.md` | This file |

## Build

Requires Visual Studio 2022 (or Build Tools) with the C++ desktop workload.

Open a **x64 Native Tools Command Prompt for VS 2022** or run `vcvars64.bat`
first:

```bat
rc /fo version.res version.rc
cl /LD /Fe:test_provider.dll test_provider.c version.res /link /DEF:NUL
```

This produces `test_provider.dll` (~12 KB).

## Sign and Deploy

### Prerequisites

1. A code-signing certificate in `Cert:\LocalMachine\My` whose root CA is in
   `Cert:\LocalMachine\Root` (Trusted Root Certification Authorities).

   To create a self-signed development certificate:

   ```powershell
   $cert = New-SelfSignedCertificate `
       -Subject "CN=EKM Test Dev" `
       -Type CodeSigningCert `
       -CertStoreLocation Cert:\LocalMachine\My `
       -NotAfter (Get-Date).AddYears(2)
   # Trust it
   Export-Certificate -Cert $cert -FilePath "$env:TEMP\ekm_test.cer" | Out-Null
   Import-Certificate -FilePath "$env:TEMP\ekm_test.cer" `
       -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
   ```

2. EKM must be enabled:

   ```sql
   sp_configure 'show advanced', 1;
   RECONFIGURE;
   sp_configure 'EKM provider enabled', 1;
   RECONFIGURE;
   ```

### Deploy

From an **elevated** PowerShell prompt:

```powershell
cd test_provider_c
.\sign_and_deploy.ps1
```

Or manually:

```powershell
# Sign
$cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath "test_provider.dll" -Certificate $cert

# Deploy
Stop-Service MSSQLSERVER -Force
Copy-Item "test_provider.dll" "C:\Program Files\Cosmian\EKM\cosmian_ekm_sql_server.dll" -Force
Start-Service MSSQLSERVER

# Test
sqlcmd -S localhost -E -Q "CREATE CRYPTOGRAPHIC PROVIDER CosmianEKM FROM FILE = 'C:\Program Files\Cosmian\EKM\cosmian_ekm_sql_server.dll';"
```

## What we verified

- All **17 exports** are present and undecorated (`dumpbin /exports`).
- The Authenticode signature is **Valid** (`Get-AuthenticodeSignature`, `signtool verify /pa /v`).
- The signing certificate's root is in `Cert:\LocalMachine\Root`.
- The certificate chain builds successfully (no `X509ChainStatus` errors).
- `sp_configure 'EKM provider enabled'` → `run_value = 1`.
- SQL Server edition is **Enterprise Developer** (supports EKM).
- SQL Server error log confirms: *"Cryptographic provider library '...' loaded into memory."*
- Extended Events trace (`sec_ekm_provider_called`) shows exactly 3 calls,
  all returning 0:
  1. `SqlCryptInitializeProvider` → 0
  2. `SqlCryptGetProviderInfo` → 0
  3. `SqlCryptFreeProvider` → 0
- A hex dump of the raw `SqlCpProviderInfo` struct bytes (64 bytes, compiled
  with MSVC x64) confirms correct layout and field values.
- Tested with both `scp_auth_Basic` and `scp_auth_Other` — same failure.
- Tested both with and without PE VERSIONINFO resource — same failure.
- Tested with a separate Rust implementation producing byte-identical struct
  content — same failure.

## Expected result

```
Command(s) completed successfully.
```

## Actual result

```
Msg 33029, Level 16, State 2, Server DESKTOP-7KE1EPJ, Line 1
Cannot initialize cryptographic provider. Provider error code: 0.
(Success - Consult EKM Provider for details)
```

## Questions for Microsoft

1. Error 33029 with error code 0 ("Success") implies an internal validation
   failure after `SqlCryptGetProviderInfo` returns `scp_err_Success`. What
   exactly does SQL Server 2025 validate beyond the return code?

2. Has the SQL Crypto API v1 (`sqlcrypt.h`) changed in SQL Server 2025
   (version 17.x)? The only publicly available documentation is the
   "SQL Server 2008 EKM Development Guide" with `x_scp_SqlCpVerMajor = 1`,
   `x_scp_SqlCpVerMinor = 1`.

3. Is there a newer version of the `sqlcrypt.h` header or an updated
   development guide for SQL Server 2025?

4. Are there any additional requirements (PE resources, manifest, specific
   Authenticode certificate properties, etc.) not documented in the
   EKM Development Guide that SQL Server 2025 enforces?

## Useful SQLCMD Diagnostics

The following `sqlcmd` commands can be run from any terminal to gather
diagnostic information directly from SQL Server.

### SQL Server version and edition

```bat
sqlcmd -S localhost -E -Q "SELECT @@VERSION;"
```

Or for structured output:

```bat
sqlcmd -S localhost -E -Q "SELECT SERVERPROPERTY('ProductVersion') AS Version, SERVERPROPERTY('Edition') AS Edition, SERVERPROPERTY('ProductLevel') AS Level;"
```

### EKM configuration

```bat
sqlcmd -S localhost -E -Q "sp_configure 'EKM provider enabled';"
```

### Registered cryptographic providers

```bat
sqlcmd -S localhost -E -Q "SELECT provider_id, name, guid, version, dll_path, is_enabled FROM sys.cryptographic_providers;"
```

### SQL Server error log (most recent)

```bat
sqlcmd -S localhost -E -Q "EXEC xp_readerrorlog 0, 1;"
```

Filter to EKM / cryptographic entries:

```bat
sqlcmd -S localhost -E -Q "EXEC xp_readerrorlog 0, 1, N'EKM';"
sqlcmd -S localhost -E -Q "EXEC xp_readerrorlog 0, 1, N'cryptographic';"
sqlcmd -S localhost -E -Q "EXEC xp_readerrorlog 0, 1, N'Attempting to load library';"
```

Filter by time range (useful right after a repro):

```bat
sqlcmd -S localhost -E -Q "EXEC xp_readerrorlog 0, 1, NULL, NULL, '2026-02-25 08:00', '2026-02-25 09:00';"
```

### Extended Events trace for EKM calls

Create and start a trace session (run once):

```sql
CREATE EVENT SESSION ekm_trace ON SERVER
ADD EVENT sqlserver.sec_ekm_provider_called
ADD TARGET package0.event_file(
    SET filename = N'C:\ProgramData\Cosmian\EKM\logs\ekm_trace.xel',
        max_file_size = 10
)
WITH (MAX_MEMORY = 4096 KB, STARTUP_STATE = OFF);

ALTER EVENT SESSION ekm_trace ON SERVER STATE = START;
```

After reproducing the error, stop and read the trace:

```sql
ALTER EVENT SESSION ekm_trace ON SERVER STATE = STOP;

SELECT
    CAST(event_data AS xml).value('(event/data[@name="cred_prov_api"]/value)[1]', 'varchar(100)')  AS api_call,
    CAST(event_data AS xml).value('(event/data[@name="cred_prov_result"]/value)[1]', 'int')        AS result,
    CAST(event_data AS xml).value('(event/@timestamp)[1]', 'datetime2')                            AS ts
FROM sys.fn_xe_file_target_read_file(
    'C:\ProgramData\Cosmian\EKM\logs\ekm_trace*.xel', NULL, NULL, NULL
)
ORDER BY ts;
```

> **Note:** The XE query requires `SET QUOTED_IDENTIFIER ON` (use `sqlcmd -I`
> or save to a `.sql` file and run with `sqlcmd -S localhost -E -i query.sql`).

### Clean up a failed provider registration

```bat
sqlcmd -S localhost -E -Q "IF EXISTS (SELECT 1 FROM sys.cryptographic_providers WHERE name='CosmianEKM') DROP CRYPTOGRAPHIC PROVIDER CosmianEKM;"
```
