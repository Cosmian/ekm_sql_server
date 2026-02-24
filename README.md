# cosmian_ekm_sql_server

A Windows DLL implementing the [SQL Server Extensible Key Management (EKM)](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/extensible-key-management-ekm?view=sql-server-ver17) provider interface, backed by the [Cosmian KMS](https://github.com/Cosmian/kms).

The library exposes the `SqlCrypt*` C ABI required by SQL Server and is built as a `cdylib` (a Windows `.dll`).

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building the DLL](#building-the-dll)
3. [Signing the DLL](#signing-the-dll) <- **required by SQL Server**
4. [Deploying files and setting permissions](#deploying-files-and-setting-permissions)
5. [Configuration file (`config.toml`)](#configuration-file-configtoml)
6. [Log files](#log-files)
7. [Connecting to SQL Server with `sqlcmd`](#connecting-to-sql-server-with-sqlcmd)
8. [Installing the EKM provider in SQL Server](#installing-the-ekm-provider-in-sql-server)
9. [Starting / restarting SQL Server](#starting--restarting-sql-server)
10. [Creating a test database and testing encryption](#creating-a-test-database-and-testing-encryption)
11. [Uninstalling the provider](#uninstalling-the-provider)
12. [Troubleshooting](#troubleshooting)

---

## 1. Prerequisites

| Tool | Notes |
|---|---|
| [Rust toolchain](https://rustup.rs) ≥ 1.85 (edition 2024) | `rustup update stable` |
| MSVC target `x86_64-pc-windows-msvc` | `rustup target add x86_64-pc-windows-msvc` |
| [LLVM / Clang](https://releases.llvm.org/download.html) | Required by `bindgen` at build time. Add `<llvm>\bin` to `PATH` and set `LIBCLANG_PATH=<llvm>\lib`. |
| Windows SDK (signtool) | Included with Visual Studio or the standalone Windows SDK. |
| A code-signing certificate | Self-signed is fine for dev; must be trusted by the machine. |
| SQL Server Developer / Enterprise edition | EKM is **not** available in Express or Web editions. |
| `sqlcmd` or SQL Server Management Studio | To execute T-SQL commands. |

---

## 2. Building the DLL

All commands are run in an elevated PowerShell prompt from the repository root.

### Debug build (development only)

```powershell
cargo build
# Output: target\debug\cosmian_ekm_sql_server.dll
```

### Release build (recommended for installation)

```powershell
cargo build --release
# Output: target\release\cosmian_ekm_sql_server.dll
```

---

## 3. Signing the DLL

> **This step is mandatory.**  
> SQL Server calls `CREATE CRYPTOGRAPHIC PROVIDER` only if the DLL is digitally
> signed with a certificate whose chain is trusted by the Windows machine.  
> An unsigned DLL will cause error 33085 or a signature verification failure.

Two scripts handle this. Both must be run in an **elevated** PowerShell session.

> **PowerShell execution policy**  
> On a fresh Windows installation scripts are disabled by default. If you see:  
> `cannot be loaded because running scripts is disabled on this system`  
> run this **once** in your elevated PowerShell session:
>
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
> ```
>
> `RemoteSigned` allows locally created scripts to run freely while still
> requiring a signature on scripts downloaded from the internet.  
> To check the current policy: `Get-ExecutionPolicy -List`

### Step 3a - Create and trust the certificate (`scripts\New-EkmCertificate.ps1`)

Run **once** on the target machine.

```powershell
# From the repository root, in an elevated PowerShell:
.\scripts\New-EkmCertificate.ps1
```

What it does:

- Creates a self-signed RSA-2048 code-signing certificate `CN=Cosmian EKM Dev` in `LocalMachine\My`.
- Adds it to `LocalMachine\Root` so SQL Server trusts the chain.
- Exports the public certificate to `scripts\CosmianEKM.cer` for reference.

If the certificate already exists the script is a no-op - safe to re-run.

### Step 3b - Sign the DLL (`scripts\Sign-EkmDll.ps1`)

Run **after every `cargo build --release`**.

```powershell
# From the repository root, in an elevated PowerShell:
.\scripts\Sign-EkmDll.ps1
```

What it does:

- Finds the certificate created in Step 3a.
- Calls `Set-AuthenticodeSignature` on `target\release\cosmian_ekm_sql_server.dll`.
- Verifies the resulting signature status and exits with an error if it is not `Valid`.

**Custom DLL path** (e.g. debug build):

```powershell
.\scripts\Sign-EkmDll.ps1 -DllPath target\debug\cosmian_ekm_sql_server.dll
```

### Option B - Certificate issued by a CA already trusted by the machine

If you have an existing trusted code-signing certificate, skip Step 3a and sign directly:

```powershell
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -like "*Cosmian*" } |
    Select-Object -First 1

Set-AuthenticodeSignature `
    -FilePath        "target\release\cosmian_ekm_sql_server.dll" `
    -Certificate     $cert `
    -TimestampServer "http://timestamp.digicert.com"
```

---

## 4. Deploying files and setting permissions

Two scripts handle deployment.

### Step 4a - Initial setup (`scripts\Initialize-EkmEnvironment.ps1`)

Run **once** on the target machine, before the first deployment.

```powershell
# From the repository root, in an elevated PowerShell:
.\scripts\Initialize-EkmEnvironment.ps1
```

What it does:

- Creates `C:\Program Files\Cosmian\EKM\` (DLL install location).
- Creates `C:\ProgramData\Cosmian\EKM\` and `...\logs\`.
- Grants the SQL Server service account `Modify` on `C:\ProgramData\Cosmian\EKM\` and `ReadAndExecute` on the install directory.
- Writes a template `config.toml` if none exists (see [Section 5](#configuration-file-configtoml)).

**Named SQL Server instance:**

```powershell
.\scripts\Initialize-EkmEnvironment.ps1 -SqlServiceAccount "NT SERVICE\MSSQL`$MyInstance"
```

### Step 4b - Redeploy a new DLL version (`scripts\Deploy-EkmDll.ps1`)

Run **after every build + sign cycle** to push a new version to SQL Server.

```powershell
# From the repository root, in an elevated PowerShell:
.\scripts\Deploy-EkmDll.ps1
```

What it does:

1. Validates the DLL's Authenticode signature (refuses to deploy unsigned/invalid DLLs).
2. Stops the SQL Server service.
3. Overwrites `C:\Program Files\Cosmian\EKM\cosmian_ekm_sql_server.dll`.
4. Restarts SQL Server and waits until it is running.

> **Do I need to re-register the provider after updating the DLL?**  
> **No.** `CREATE CRYPTOGRAPHIC PROVIDER` is a one-time operation that records the
> DLL path in the SQL Server catalog. Replacing the file at that path with a new
> version is all that is needed - SQL Server will load the updated DLL on the
> next startup with no SQL changes required.
>
> **Do I need to stop and restart SQL Server every time?**  
> **Yes.** SQL Server loads the EKM DLL directly into its process and holds an
> exclusive file lock on it. You cannot overwrite a locked file, and the new code
> only takes effect once the process reloads the DLL from disk. The
> `Deploy-EkmDll.ps1` script handles the stop/copy/start sequence automatically.

**Named instance or custom DLL path:**

```powershell
.\scripts\Deploy-EkmDll.ps1 -SqlServiceName "MSSQL`$MyInstance"
.\scripts\Deploy-EkmDll.ps1 -DllPath target\debug\cosmian_ekm_sql_server.dll
```

If SQL Server is not yet installed or you want to restart it yourself:

```powershell
.\scripts\Deploy-EkmDll.ps1 -SkipServiceRestart
```

### Full release workflow (summary)

```powershell
# 1. Build
cargo build --release

# 2. Sign
.\scripts\Sign-EkmDll.ps1

# 3. Deploy (stops SQL Server, copies DLL, restarts SQL Server)
.\scripts\Deploy-EkmDll.ps1
```

---

## 5. Configuration file (`config.toml`)

The provider reads its settings from:

```
C:\ProgramData\Cosmian\EKM\config.toml
```

Create this file **before** starting SQL Server.

### Example `config.toml`

```toml
# URL of the Cosmian KMS REST API
kms_url = "https://kms.example.com:9998"

# Path to the PEM-encoded client certificate for mutual TLS authentication
client_cert = 'C:\ProgramData\Cosmian\EKM\client.pem'

# Path to the matching private key
client_key = 'C:\ProgramData\Cosmian\EKM\client.key'

# Optional: custom CA bundle to trust (PEM)
# ca_cert = 'C:\ProgramData\Cosmian\EKM\ca.pem'
```

```powershell
# Create a minimal config (edit values before use)
@"
kms_url     = "https://kms.example.com:9998"
client_cert = 'C:\ProgramData\Cosmian\EKM\client.pem'
client_key  = 'C:\ProgramData\Cosmian\EKM\client.key'
"@ | Set-Content "C:\ProgramData\Cosmian\EKM\config.toml" -Encoding UTF8
```

> **Why `C:\ProgramData`?**  
> SQL Server runs under a Windows service account (`NT SERVICE\MSSQLSERVER`) that
> has no user profile. `%APPDATA%` and `%LOCALAPPDATA%` are unavailable to it.
> `C:\ProgramData` is the standard Windows location for machine-wide service data
> and is accessible to all service accounts.

---

## 6. Log files

Rolling daily log files are written automatically to:

```
C:\ProgramData\Cosmian\EKM\logs\cosmian_ekm.log.<yyyy-MM-dd>
```

The directory is created on the first call to `SqlCryptInitializeProvider`
(when SQL Server loads the provider). All pending records are flushed and the
background I/O thread is stopped when `SqlCryptFreeProvider` is called (when SQL
Server unloads the provider).

To tail the current day's log:

```powershell
$today = Get-Date -Format "yyyy-MM-dd"
Get-Content "C:\ProgramData\Cosmian\EKM\logs\cosmian_ekm.log.$today" -Wait
```

---

## 7. Connecting to SQL Server with `sqlcmd`

The T-SQL commands in the following sections must be run as a member of the
`sysadmin` fixed server role. You do **not** need an elevated PowerShell shell
for `sqlcmd` itself - elevation is only needed for the PowerShell deployment
scripts that touch the file system and Windows services.

### Default instance, Windows authentication (recommended)

```powershell
sqlcmd -S localhost -E
```

`-E` uses your current Windows login (Trusted Connection). If your Windows
account is a sysadmin this is all you need.

### Named instance

```powershell
sqlcmd -S localhost\MyInstance -E
```

### SQL Server authentication (if Windows auth is not available)

```powershell
sqlcmd -S localhost -U sa -P "<YourPassword>"
```

### Running a T-SQL file directly from the shell

```powershell
sqlcmd -S localhost -E -i setup.sql
```

### At the `sqlcmd` prompt

- Type T-SQL statements and press **Enter** to add lines.
- Type `GO` and press **Enter** to execute the accumulated batch.
- Type `EXIT` to quit.

> **`sqlcmd` not found?**  
> It is installed with SQL Server by default. If it is missing from your `PATH`,
> add the SQL Server tools directory:
>
> ```powershell
> # Adjust the version year as needed
> $env:PATH += ";C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn"
> ```
>
> Or install the standalone [sqlcmd utility](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility).

---

## 8. Installing the EKM provider in SQL Server

Connect to SQL Server as a member of the `sysadmin` fixed server role (e.g. using
`sqlcmd` or SSMS) and execute the following T-SQL statements **in order**.

### Step 8.1 - Enable EKM support (server option)

EKM is disabled by default. Enable it once per SQL Server instance:

```sql
EXECUTE sp_configure 'show advanced options', 1;
GO
RECONFIGURE;
GO

EXECUTE sp_configure 'EKM provider enabled', 1;
GO
RECONFIGURE;
GO
```

### Step 8.2 - Register the Cosmian EKM DLL as a cryptographic provider

```sql
CREATE CRYPTOGRAPHIC PROVIDER CosmianEKM
    FROM FILE = 'C:\Program Files\Cosmian\EKM\cosmian_ekm_sql_server.dll';
GO
```

> **If this statement returns `Msg 33029`:** The provider is *not* registered —
> a failed `CREATE CRYPTOGRAPHIC PROVIDER` leaves no entry in the catalog.
> Fix the underlying issue (consult Section 12 and the log file in
> `C:\ProgramData\Cosmian\EKM\logs\`), then:
>
> 1. Rebuild: `cargo build --release`
> 2. Redeploy following **Step 4b** (sign + deploy scripts)
> 3. Re-run the `CREATE CRYPTOGRAPHIC PROVIDER` statement above
>
> If a previous attempt *did* partially register the provider (check with
> `SELECT name FROM sys.cryptographic_providers`), drop it first:
>
> ```sql
> DROP CRYPTOGRAPHIC PROVIDER CosmianEKM;
> GO
> ```

Verify registration:

```sql
SELECT name, dll_path, is_enabled
FROM   sys.cryptographic_providers;
```

### Step 8.3 - Create a credential for the provider

The credential carries authentication information (identity / secret) that SQL
Server passes to the EKM provider when opening a session. Adjust the values to
match the KMS authentication scheme you configure in `config.toml`.

```sql
-- Credential used by the sysadmin who will create keys
CREATE CREDENTIAL Cosmian_Admin_Cred
    WITH IDENTITY = 'CosmianKMSUser',
         SECRET   = '<kms-password-or-token>'
    FOR CRYPTOGRAPHIC PROVIDER CosmianEKM;
GO

-- Map the credential to your login (replace DOMAIN\YourLogin as appropriate)
ALTER LOGIN [DOMAIN\YourLogin]
    ADD CREDENTIAL Cosmian_Admin_Cred;
GO
```

### Step 8.4 - Create an asymmetric key inside the EKM provider

```sql
USE master;
GO

CREATE ASYMMETRIC KEY Cosmian_MasterKey
    FROM PROVIDER CosmianEKM
    WITH ALGORITHM         = RSA_2048,
         PROVIDER_KEY_NAME = 'cosmian-sql-master-key';
GO
```

### Step 8.5 - Create a SQL Server login backed by the asymmetric key

This is the login the Database Engine uses internally (e.g. for TDE auto-open at
startup). Users cannot sign in with it directly.

```sql
CREATE LOGIN EKM_DBEngine_Login
    FROM ASYMMETRIC KEY Cosmian_MasterKey;
GO

-- Create a second credential for the Database Engine login
CREATE CREDENTIAL Cosmian_DBEngine_Cred
    WITH IDENTITY = 'CosmianKMSUser',
         SECRET   = '<kms-password-or-token>'
    FOR CRYPTOGRAPHIC PROVIDER CosmianEKM;
GO

ALTER LOGIN EKM_DBEngine_Login
    ADD CREDENTIAL Cosmian_DBEngine_Cred;
GO
```

---

## 9. Starting / restarting SQL Server

After changing EKM provider configuration or registering a new provider, restart
the SQL Server service so it reloads the DLL.

### Using PowerShell (elevated)

```powershell
# Default instance
Restart-Service -Name MSSQLSERVER -Force

# Named instance (replace MyInstance)
# Restart-Service -Name "MSSQL`$MyInstance" -Force
```

### Using SQL Server Configuration Manager (GUI)

1. Open **SQL Server Configuration Manager** (`SQLServerManager17.msc`).
2. Select **SQL Server Services** in the left pane.
3. Right-click **SQL Server (MSSQLSERVER)** → **Restart**.

### Check service status

```powershell
Get-Service MSSQLSERVER | Select-Object Status, DisplayName
```

---

## 10. Creating a test database and testing encryption

The following T-SQL creates a database, protects its encryption key with the
Cosmian EKM asymmetric key (TDE), and then creates a table with a column-level
symmetric key also protected by the same EKM key.

Run everything in `sqlcmd` or SSMS as `sysadmin`.

### Step 10.1 - Create the test database

```sql
CREATE DATABASE CosmianEKMTest;
GO
```

### Step 10.2 - Create the database master key

```sql
USE CosmianEKMTest;
GO

CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'AStr0ng!DBMasterKeyPwd';
GO
```

### Step 10.3 - Enable Transparent Data Encryption (TDE) with the EKM key

```sql
USE CosmianEKMTest;
GO

-- Create the database encryption key, protected by the EKM asymmetric key
CREATE DATABASE ENCRYPTION KEY
    WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER ASYMMETRIC KEY Cosmian_MasterKey;
GO

-- Turn on TDE - the entire database file is now encrypted at rest
ALTER DATABASE CosmianEKMTest SET ENCRYPTION ON;
GO
```

Verify TDE status:

```sql
SELECT db.name, dek.encryption_state, dek.encryptor_type, dek.percent_complete
FROM   sys.dm_database_encryption_keys dek
JOIN   sys.databases                   db  ON dek.database_id = db.database_id
WHERE  db.name = 'CosmianEKMTest';
-- encryption_state 3 = encrypted
```

### Step 10.4 - Create a symmetric key for column-level encryption

Column-level encryption (CLE) gives you field-granular control, independent of TDE.

```sql
USE CosmianEKMTest;
GO

CREATE SYMMETRIC KEY Cosmian_ColKey
    WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER ASYMMETRIC KEY Cosmian_MasterKey;
GO
```

### Step 10.5 - Create a test table and insert encrypted data

```sql
USE CosmianEKMTest;
GO

CREATE TABLE dbo.SensitiveData
(
    Id            INT            IDENTITY PRIMARY KEY,
    PlainLabel    NVARCHAR(100)  NOT NULL,           -- stored in plain text
    SecretValue   VARBINARY(256) NOT NULL            -- stored encrypted
);
GO

-- Open the symmetric key before encrypting
OPEN SYMMETRIC KEY Cosmian_ColKey
    DECRYPTION BY SERVER ASYMMETRIC KEY Cosmian_MasterKey;

INSERT INTO dbo.SensitiveData (PlainLabel, SecretValue)
VALUES
    ('Record A', ENCRYPTBYKEY(KEY_GUID('Cosmian_ColKey'), N'Top secret value A')),
    ('Record B', ENCRYPTBYKEY(KEY_GUID('Cosmian_ColKey'), N'Top secret value B'));

CLOSE SYMMETRIC KEY Cosmian_ColKey;
GO
```

### Step 10.6 - Read back the decrypted data

```sql
USE CosmianEKMTest;
GO

OPEN SYMMETRIC KEY Cosmian_ColKey
    DECRYPTION BY SERVER ASYMMETRIC KEY Cosmian_MasterKey;

SELECT
    Id,
    PlainLabel,
    CONVERT(NVARCHAR(200),
        DECRYPTBYKEY(SecretValue)) AS DecryptedValue
FROM dbo.SensitiveData;

CLOSE SYMMETRIC KEY Cosmian_ColKey;
GO
```

Expected output:

| Id | PlainLabel | DecryptedValue     |
|----|------------|--------------------|
| 1  | Record A   | Top secret value A |
| 2  | Record B   | Top secret value B |

---

## 11. Uninstalling the provider

```sql
-- 1. Remove TDE from databases that use this provider
ALTER DATABASE CosmianEKMTest SET ENCRYPTION OFF;
GO

-- 2. Drop the database encryption key
USE CosmianEKMTest;
DROP DATABASE ENCRYPTION KEY;
GO

-- 3. Drop the asymmetric key and logins/credentials in master
USE master;
GO
DROP LOGIN  EKM_DBEngine_Login;
DROP LOGIN  [DOMAIN\YourLogin];   -- only removes the credential mapping
ALTER LOGIN [DOMAIN\YourLogin] DROP CREDENTIAL Cosmian_Admin_Cred;
DROP CREDENTIAL Cosmian_DBEngine_Cred;
DROP CREDENTIAL Cosmian_Admin_Cred;
DROP ASYMMETRIC KEY Cosmian_MasterKey;
DROP CRYPTOGRAPHIC PROVIDER CosmianEKM;
GO
```

Then stop SQL Server, remove the DLL, and clean up:

```powershell
Stop-Service MSSQLSERVER -Force
Remove-Item "C:\Program Files\Cosmian\EKM\cosmian_ekm_sql_server.dll"
# Optionally remove data directory:
# Remove-Item "C:\ProgramData\Cosmian\EKM" -Recurse
Start-Service MSSQLSERVER
```

---

## 12. Troubleshooting

### Msg 33029 - Cannot initialize cryptographic provider. Provider error code: 3 (Not Supported)

```
Msg 33029, Level 16, State 2
Cannot initialize cryptographic provider. Provider error code: 3.
(Not Supported - Consult EKM Provider for details)
```

**Cause:** Error code 3 maps to `scp_err_NotSupported` in the SQL Crypto ABI.
During `CREATE CRYPTOGRAPHIC PROVIDER`, SQL Server calls the following functions
in order:

1. `SqlCryptInitializeProvider`
2. `SqlCryptGetProviderInfo` ← most likely failure point
3. `SqlCryptGetNextAlgorithmId`
4. `SqlCryptFreeProvider`

If any of these returns a non-zero error code, SQL Server reports 33029 with
that code as the "Provider error code".

**Fix:** Ensure `SqlCryptGetProviderInfo` fills in the `SqlCpProviderInfo`
struct (provider name, GUID, version, API version, auth type, key support flags)
and returns `scp_err_Success`. Also ensure `SqlCryptGetNextAlgorithmId` returns
`scp_err_NotFound` (not `scp_err_NotSupported`) to signal an empty algorithm
list - NotFound is the correct sentinel for "end of enumeration".

### Msg 33029 - Cannot initialize cryptographic provider. Provider error code: 0 (Success)

```
Msg 33029, Level 16, State 2
Cannot initialize cryptographic provider. Provider error code: 0.
(Success - Consult EKM Provider for details)
```

**Cause:** All provider functions returned `scp_err_Success` (0), but SQL Server
internally rejected the contents of the `SqlCpProviderInfo` struct returned by
`SqlCryptGetProviderInfo`.  The "(Success)" annotation means the *last error
code the provider returned* was 0 - it does **not** mean the provider
registration succeeded.

Common struct problems SQL Server validates silently (derived from the official
Microsoft sample provider):

| Field | Required value | Notes |
|---|---|---|
| `name.ws` | Pointer to UTF-16 data | Per spec, `ws` does **not** need to be null-terminated; `cb` is the sole length authority |
| `name.cb` | Byte count of the string | Must be > 0 and ≤ 2048 |
| `scpVersion` | `{major=1, minor=1, build=0, revision=0}` | Must match `x_scp_SqlCpVerMajor/Minor` in `sqlcrypt.h` exactly |
| `version` | Any `{major, minor, build, revision}` but **fixed forever** | SQL Server stores this on first registration and rejects the DLL if it changes on reload |
| `cbKeyThumbLen` | `sizeof(GUID)` = **16** | SQL Server validates this equals the GUID size; values like 32 cause silent rejection |
| `symmKeySupport` | At least `scp_kf_Supported (0x01)` | SQL Server rejects a provider with zero key support entirely |
| `asymmKeySupport` | At least `scp_kf_Supported (0x01)` | Same |
| Struct padding | All padding bytes must be zero | Zero-initialise the whole struct before filling fields |

**Fix (already applied in this codebase):**

1. `SqlCryptGetProviderInfo` calls `std::ptr::write_bytes(p_provider_info, 0, 1)`
   to zero-initialise the full 64-byte `SqlCpProviderInfo` **before** filling in
   individual fields.
2. `PROVIDER_NAME_UTF16` ends with a `0x0000` null terminator, and `name.cb` is
   set to the byte count *excluding* that null.
3. `cbKeyThumbLen` is set to `size_of::<GUID>()` = 16 (not 32).
4. `symmKeySupport` is set to `scp_kf_Supported`; `asymmKeySupport` likewise.
5. `version` is fixed at `{1, 0, 0, 0}` — do **not** change this value after the
   provider has been registered, or SQL Server will refuse to load the DLL.

If you are building from an older checkout that predates these fixes, rebuild and
redeploy:

```powershell
cargo build --release
.\scripts\Sign-EkmDll.ps1
.\scripts\Deploy-EkmDll.ps1
```

### Msg 33029 - Provider error code: 1 (Failure) or signature-related

```
Msg 33029 ... Provider error code: 1.
```

or

```
Msg 33095, Level 16 ... The cryptographic provider is not registered.
```

**Cause:** The DLL is not digitally signed, or the signing certificate is not in
`LocalMachine\Root` (Trusted Root CAs) on this machine.

**Fix:** Run `scripts\New-EkmCertificate.ps1` (once) then `scripts\Sign-EkmDll.ps1`
after every build. Verify with:

```powershell
Get-AuthenticodeSignature "C:\Program Files\Cosmian\EKM\cosmian_ekm_sql_server.dll"
# Status must be: Valid
```

### Execution policy error when running scripts

```
cannot be loaded because running scripts is disabled on this system
```

**Fix:** In an elevated PowerShell, run once:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

### No log file appears

The log directory `C:\ProgramData\Cosmian\EKM\logs\` is created automatically
on first load. If it is missing, the SQL Server service account likely lacks
write access. Re-run `scripts\Initialize-EkmEnvironment.ps1` (elevated) to
correct the ACLs.

### How to check which provider functions were called

Tail the log file while reproducing the error (SQL Server must have been
restarted after deploying the DLL):

```powershell
$today = Get-Date -Format "yyyy-MM-dd"
Get-Content "C:\ProgramData\Cosmian\EKM\logs\cosmian_ekm.log.$today" -Wait
```

Every `SqlCrypt*` entry point logs an INFO line on entry, so the last logged
function before the error is where execution stopped.

---

## Project structure

```
build.rs          # Calls bindgen to generate Rust types from sqlcrypt.h
Cargo.toml
src/
  lib.rs          # SqlCrypt* entry points
  sqlcrypt.h      # Microsoft SQL Server EKM C interface header
  wrapper.h       # Thin bindgen wrapper that includes sqlcrypt.h
scripts/
  New-EkmCertificate.ps1       # (once)     Create & trust the self-signed cert
  Sign-EkmDll.ps1              # (each build) Sign the release DLL
  Initialize-EkmEnvironment.ps1 # (once)    Create dirs & set permissions
  Deploy-EkmDll.ps1            # (each deploy) Stop SQL Server, copy DLL, restart
```

---

## License

See [LICENSE](LICENSE).
