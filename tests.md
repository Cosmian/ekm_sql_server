# Integration Tests

All tests live in [tests/integration.rs](tests/integration.rs) and exercise the
deployed DLL through `sqlcmd` against a live SQL Server and Cosmian KMS.

Run with:
```powershell
cargo test --test integration -- --test-threads=1
```

> Tests must run sequentially (`--test-threads=1`): they share global SQL Server
> state (provider registration, credentials, keys).

## Test Cases

| Test | Functional description |
|------|------------------------|
| `t00_prerequisites` | Verifies the Cosmian KMS is reachable on localhost:9998 and SQL Server responds to a basic query. |
| `t01_ekm_enabled` | Enables the EKM feature (`sp_configure 'EKM provider enabled'`) and confirms `CosmianEKM` is visible in `sys.cryptographic_providers`. |
| `t02_provider_properties` | Reads `sys.dm_cryptographic_provider_properties` and checks the provider returns a friendly name and authentication type. |
| `t03_provider_algorithms` | Calls `sys.dm_cryptographic_provider_algorithms` and asserts that all six advertised algorithm tags are present: `RSA_2048`, `RSA_3072`, `RSA_4096`, `AES_128`, `AES_192`, and `AES_256`. |
| `t04_credential_setup` | Creates a `CRYPTOGRAPHIC PROVIDER` credential mapped to the `admin` KMS identity, maps it to the current Windows login, and verifies the mapping. |
| `t05_create_asymmetric_key` | Creates a 2048-bit RSA asymmetric key (`Cosmian_TestKey_RSA`) via the EKM provider and confirms it appears in `sys.asymmetric_keys`. |
| `t06_create_symmetric_key` | Creates a 256-bit AES symmetric key (`Cosmian_TestKey_AES`) via the EKM provider and confirms it appears in `sys.symmetric_keys`. |
| `t07_symmetric_encrypt_decrypt` | Column-level encryption end-to-end: creates an AES-256 key protected by `Cosmian_TestKey_RSA`, inserts a row encrypted with `ENCRYPTBYKEY`, then decrypts with `DECRYPTBYKEY` and asserts the plaintext is recovered. Exercises KMS-side RSA encrypt (key wrapping) and RSA decrypt (key unwrapping). |
| `t08_tde_encryption` | Transparent Data Encryption end-to-end: creates a database, attaches a `DATABASE ENCRYPTION KEY` using `Cosmian_TestKey_RSA`, enables TDE, and verifies `sys.dm_database_encryption_keys` reports encryption state 2 (in progress) or 3 (encrypted). |
| `t09_provider_sessions` | Queries `sys.dm_cryptographic_provider_sessions` to confirm the DMV returns results without error (sessions may be empty). |
| `t10_drop_symmetric_key` | Creates then drops a symmetric key via the EKM provider, verifying removal from `sys.symmetric_keys` and destruction on the KMS. |
| `t11_create_rsa4096_key` | Creates a 4096-bit RSA asymmetric key and asserts SQL Server stores it with `key_length = 4096`, validating the provider returns the correct public-key modulus size. |
| `t12_provider_keys_dmv` | Calls `sys.dm_cryptographic_provider_keys` (`SqlCryptGetNextKeyId`) and confirms it completes without error (empty result set is expected). |
| `t13_drop_asymmetric_key` | Creates then drops a 2048-bit RSA asymmetric key via the EKM provider, verifying removal from `sys.asymmetric_keys` and destruction on the KMS. Covers the `SqlCryptDropKey` asymmetric path. |
| `t99_cleanup` | Drops all objects created by the test suite (databases, keys, logins, credentials) to leave SQL Server in a clean state. |