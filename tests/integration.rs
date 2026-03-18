// Integration tests for the Cosmian EKM SQL Server provider.
//
// These tests require:
// 1. A Cosmian KMS server running at https://localhost:9998 with mTLS
// 2. SQL Server running locally (default instance)
// 3. The EKM provider DLL built, signed, and deployed
// 4. The config.toml placed at %PROGRAMDATA%\Cosmian\EKM\config.toml
//
// Run with:
//   cargo test --test integration -- --test-threads=1
//
// The tests MUST run sequentially (--test-threads=1) because they share
// global SQL Server state (provider registration, credentials, keys).

use std::process::Command;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The hostname\login used for Windows Authentication credential mapping.
const WIN_LOGIN: &str = "DESKTOP-7KE1EPJ\\bgrieder";

/// The identity string stored in the SQL Server credential.
/// Must match a `[[kms.certificates]] username` entry in config.toml.
const EKM_IDENTITY: &str = "admin";

/// The name of the credential created by the tests.
const CRED_NAME: &str = "Cosmian_IntTest_Cred";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run a T-SQL statement via sqlcmd and return (stdout, stderr, success).
fn sqlcmd(sql: &str) -> (String, String, bool) {
    let output = Command::new("sqlcmd")
        .args(["-S", "localhost", "-E", "-Q", sql])
        .output()
        .expect("failed to execute sqlcmd");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

/// Run a T-SQL statement and assert it succeeds (no SQL error messages).
fn sqlcmd_ok(sql: &str) -> String {
    let (stdout, stderr, ok) = sqlcmd(sql);
    assert!(
        ok,
        "sqlcmd failed.\nSQL: {sql}\nstdout: {stdout}\nstderr: {stderr}"
    );
    // sqlcmd returns exit 0 even for some SQL errors — check for "Msg NNNN".
    let has_error = stdout
        .lines()
        .any(|l| l.starts_with("Msg ") && !l.contains("Changed database context"));
    assert!(
        !has_error,
        "SQL error in output.\nSQL: {sql}\nstdout: {stdout}\nstderr: {stderr}"
    );
    stdout
}

/// Run a T-SQL statement, accepting failure (used for cleanup).
fn sqlcmd_ignore(sql: &str) {
    let _ = sqlcmd(sql);
}

/// Check that the KMS is reachable at localhost:9998.
fn assert_kms_reachable() {
    use std::net::TcpStream;
    use std::time::Duration;
    let result =
        TcpStream::connect_timeout(&"127.0.0.1:9998".parse().unwrap(), Duration::from_secs(5));
    assert!(
        result.is_ok(),
        "Cannot connect to KMS at localhost:9998. Is the KMS server running?"
    );
}

/// Check that SQL Server is running.
fn assert_sql_server_running() {
    let (stdout, _stderr, ok) = sqlcmd("SELECT 1 AS alive");
    assert!(
        ok && stdout.contains("1"),
        "Cannot connect to SQL Server. Is the service running?"
    );
}

/// Get the EKM provider's `provider_id`, or panic.
fn provider_id() -> i32 {
    let out = sqlcmd_ok(
        "SET NOCOUNT ON; \
         SELECT provider_id FROM sys.cryptographic_providers WHERE name = 'CosmianEKM';",
    );
    // Parse the first integer from the output.
    out.split_whitespace()
        .find_map(|w| w.trim().parse::<i32>().ok())
        .expect("CosmianEKM provider not found in sys.cryptographic_providers")
}

// ---------------------------------------------------------------------------
// Test: Prerequisites check
// ---------------------------------------------------------------------------

#[test]
fn t00_prerequisites() {
    assert_kms_reachable();
    assert_sql_server_running();
}

// ---------------------------------------------------------------------------
// Test: EKM provider is enabled and registered
// ---------------------------------------------------------------------------

#[test]
fn t01_ekm_enabled() {
    sqlcmd_ok("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
    sqlcmd_ok("EXEC sp_configure 'EKM provider enabled', 1; RECONFIGURE;");

    let out = sqlcmd_ok(
        "SELECT name, is_enabled FROM sys.cryptographic_providers WHERE name = 'CosmianEKM';",
    );
    assert!(
        out.contains("CosmianEKM"),
        "CosmianEKM provider not registered. Deploy the DLL first.\nOutput: {out}"
    );
}

// ---------------------------------------------------------------------------
// Test: Provider properties visible through DMV
// ---------------------------------------------------------------------------

#[test]
fn t02_provider_properties() {
    let pid = provider_id();
    let out = sqlcmd_ok(&format!(
        "SELECT friendly_name, authentication_type \
         FROM sys.dm_cryptographic_provider_properties \
         WHERE provider_id = {pid};"
    ));
    assert!(
        out.contains("Cosmian") || out.contains("Basic"),
        "Provider properties not found.\nOutput: {out}"
    );
}

// ---------------------------------------------------------------------------
// Test: Provider algorithms are enumerated
// ---------------------------------------------------------------------------

#[test]
fn t03_provider_algorithms() {
    let pid = provider_id();
    let out = sqlcmd_ok(&format!(
        "SELECT algorithm_id, algorithm_tag, key_type, key_length \
         FROM sys.dm_cryptographic_provider_algorithms({pid});"
    ));
    // The provider declares 6 algorithms: all three RSA sizes and all three AES sizes.
    for tag in ["RSA_2048", "RSA_3072", "RSA_4096", "AES_128", "AES_192", "AES_256"] {
        assert!(
            out.contains(tag),
            "Algorithm tag {tag} not found in provider algorithm list.\nOutput: {out}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: Credential creation and mapping
// ---------------------------------------------------------------------------

#[test]
fn t04_credential_setup() {
    // Drop any credential already mapped to this login (regardless of name).
    sqlcmd_ignore(&format!(
        "DECLARE @cred NVARCHAR(256); \
         SELECT @cred = c.name FROM sys.server_principal_credentials spc \
         JOIN sys.credentials c ON c.credential_id = spc.credential_id \
         JOIN sys.server_principals p ON p.principal_id = spc.principal_id \
         WHERE p.name = '{WIN_LOGIN}' AND c.target_type = 'CRYPTOGRAPHIC PROVIDER'; \
         IF @cred IS NOT NULL BEGIN \
           EXEC('ALTER LOGIN [{WIN_LOGIN}] DROP CREDENTIAL ' + @cred); \
           EXEC('DROP CREDENTIAL ' + @cred); \
         END"
    ));
    // Also drop our specific test credential if it exists
    sqlcmd_ignore(&format!(
        "ALTER LOGIN [{WIN_LOGIN}] DROP CREDENTIAL {CRED_NAME};"
    ));
    sqlcmd_ignore(&format!("DROP CREDENTIAL {CRED_NAME};"));

    // Create credential with identity matching config.toml [[kms.certificates]] username
    sqlcmd_ok(&format!(
        "CREATE CREDENTIAL {CRED_NAME} \
         WITH IDENTITY = '{EKM_IDENTITY}', SECRET = 'unused' \
         FOR CRYPTOGRAPHIC PROVIDER CosmianEKM;"
    ));

    // Map to current Windows login
    sqlcmd_ok(&format!(
        "ALTER LOGIN [{WIN_LOGIN}] ADD CREDENTIAL {CRED_NAME};"
    ));

    // Verify
    let out = sqlcmd_ok(&format!(
        "SELECT name, credential_identity FROM sys.credentials WHERE name = '{CRED_NAME}';"
    ));
    assert!(
        out.contains(EKM_IDENTITY),
        "Credential identity mismatch.\nOutput: {out}"
    );
}

// ---------------------------------------------------------------------------
// Test: Create an asymmetric key (RSA 2048) on the EKM provider
// ---------------------------------------------------------------------------

#[test]
fn t05_create_asymmetric_key() {
    sqlcmd_ignore("USE master; DROP ASYMMETRIC KEY Cosmian_TestKey_RSA;");

    sqlcmd_ok(
        "USE master; \
         CREATE ASYMMETRIC KEY Cosmian_TestKey_RSA \
         FROM PROVIDER CosmianEKM \
         WITH ALGORITHM = RSA_2048, \
              PROVIDER_KEY_NAME = 'test-rsa-key-001', \
              CREATION_DISPOSITION = CREATE_NEW;",
    );

    let out = sqlcmd_ok(
        "SELECT name, algorithm_desc, key_length \
         FROM sys.asymmetric_keys \
         WHERE name = 'Cosmian_TestKey_RSA';",
    );
    assert!(
        out.contains("Cosmian_TestKey_RSA"),
        "Asymmetric key not found.\nOutput: {out}"
    );
}

// ---------------------------------------------------------------------------
// Test: Create a symmetric key (AES 256) on the EKM provider
// ---------------------------------------------------------------------------

#[test]
fn t06_create_symmetric_key() {
    sqlcmd_ignore("USE master; DROP SYMMETRIC KEY Cosmian_TestKey_AES;");

    sqlcmd_ok(
        "USE master; \
         CREATE SYMMETRIC KEY Cosmian_TestKey_AES \
         FROM PROVIDER CosmianEKM \
         WITH ALGORITHM = AES_256, \
              PROVIDER_KEY_NAME = 'test-aes-key-001', \
              CREATION_DISPOSITION = CREATE_NEW;",
    );

    let out = sqlcmd_ok(
        "SELECT name, algorithm_desc, key_length \
         FROM sys.symmetric_keys \
         WHERE name = 'Cosmian_TestKey_AES';",
    );
    assert!(
        out.contains("Cosmian_TestKey_AES"),
        "Symmetric key not found.\nOutput: {out}"
    );
}

// ---------------------------------------------------------------------------
// Test: Encrypt and decrypt with symmetric key (column-level encryption)
// ---------------------------------------------------------------------------

#[test]
fn t07_symmetric_encrypt_decrypt() {
    sqlcmd_ignore("USE master; DROP DATABASE CosmianEKMTestDB;");

    sqlcmd_ok("CREATE DATABASE CosmianEKMTestDB;");

    // Create a symmetric key protected by our EKM asymmetric key.
    // The asymmetric key lives in master (EKM-backed), so we reference it
    // with ENCRYPTION BY ASYMMETRIC KEY from the master database context.
    sqlcmd_ok(
        "USE master; \
         CREATE SYMMETRIC KEY Cosmian_ColTestKey \
         WITH ALGORITHM = AES_256 \
         ENCRYPTION BY ASYMMETRIC KEY Cosmian_TestKey_RSA;",
    );

    // Create test table
    sqlcmd_ok(
        "USE master; \
         CREATE TABLE dbo.EncTest ( \
             Id INT IDENTITY PRIMARY KEY, \
             Label NVARCHAR(50), \
             Secret VARBINARY(512) \
         );",
    );

    // Encrypt data
    sqlcmd_ok(
        "USE master; \
         OPEN SYMMETRIC KEY Cosmian_ColTestKey \
             DECRYPTION BY ASYMMETRIC KEY Cosmian_TestKey_RSA; \
         INSERT INTO dbo.EncTest (Label, Secret) \
         VALUES ('hello', ENCRYPTBYKEY(KEY_GUID('Cosmian_ColTestKey'), N'Secret Value 42')); \
         CLOSE SYMMETRIC KEY Cosmian_ColTestKey;",
    );

    // Decrypt and verify
    let out = sqlcmd_ok(
        "USE master; \
         OPEN SYMMETRIC KEY Cosmian_ColTestKey \
             DECRYPTION BY ASYMMETRIC KEY Cosmian_TestKey_RSA; \
         SELECT Label, CONVERT(NVARCHAR(200), DECRYPTBYKEY(Secret)) AS Decrypted \
         FROM dbo.EncTest; \
         CLOSE SYMMETRIC KEY Cosmian_ColTestKey;",
    );
    assert!(
        out.contains("Secret Value 42"),
        "Decrypted value not found.\nOutput: {out}"
    );
}

// ---------------------------------------------------------------------------
// Test: TDE (Transparent Data Encryption) with EKM
// ---------------------------------------------------------------------------

#[test]
fn t08_tde_encryption() {
    sqlcmd_ignore("ALTER DATABASE CosmianEKMTestTDE SET ENCRYPTION OFF;");
    // Give SQL Server a moment to handle TDE shutdown
    std::thread::sleep(std::time::Duration::from_secs(2));
    sqlcmd_ignore("USE CosmianEKMTestTDE; DROP DATABASE ENCRYPTION KEY;");
    sqlcmd_ignore("USE master; DROP DATABASE CosmianEKMTestTDE;");
    sqlcmd_ignore("DROP LOGIN Cosmian_TDE_Login;");

    sqlcmd_ok("CREATE DATABASE CosmianEKMTestTDE;");

    // TDE requires a login mapped from the asymmetric key with the EKM
    // credential so SQL Server can automatically access the key via the
    // provider without an interactive session.
    sqlcmd_ignore("DROP CREDENTIAL Cosmian_TDE_Cred;");
    sqlcmd_ok("CREATE LOGIN Cosmian_TDE_Login FROM ASYMMETRIC KEY Cosmian_TestKey_RSA;");
    sqlcmd_ok(&format!(
        "CREATE CREDENTIAL Cosmian_TDE_Cred \
         WITH IDENTITY = '{EKM_IDENTITY}', SECRET = 'unused' \
         FOR CRYPTOGRAPHIC PROVIDER CosmianEKM;"
    ));
    sqlcmd_ok("ALTER LOGIN Cosmian_TDE_Login ADD CREDENTIAL Cosmian_TDE_Cred;");

    sqlcmd_ok(
        "USE CosmianEKMTestTDE; \
         CREATE DATABASE ENCRYPTION KEY \
         WITH ALGORITHM = AES_256 \
         ENCRYPTION BY SERVER ASYMMETRIC KEY Cosmian_TestKey_RSA;",
    );

    sqlcmd_ok("ALTER DATABASE CosmianEKMTestTDE SET ENCRYPTION ON;");

    // Verify TDE state (2 = encryption in progress, 3 = encrypted)
    let out = sqlcmd_ok(
        "SELECT db.name, dek.encryption_state \
         FROM sys.dm_database_encryption_keys dek \
         JOIN sys.databases db ON dek.database_id = db.database_id \
         WHERE db.name = 'CosmianEKMTestTDE';",
    );
    assert!(
        out.contains("2") || out.contains("3"),
        "TDE not active.\nOutput: {out}"
    );
}

// ---------------------------------------------------------------------------
// Test: Provider sessions visible through DMV
// ---------------------------------------------------------------------------

#[test]
fn t09_provider_sessions() {
    let pid = provider_id();
    // The DMV is a table-valued function; pass the provider_id.
    let out = sqlcmd_ok(&format!(
        "SELECT provider_id, session_handle, [identity] \
         FROM sys.dm_cryptographic_provider_sessions({pid});"
    ));
    // Sessions may or may not be present — the query just must not crash.
    let _ = out;
}

// ---------------------------------------------------------------------------
// Test: Drop symmetric key
// ---------------------------------------------------------------------------

#[test]
fn t10_drop_symmetric_key() {
    sqlcmd_ignore("USE master; DROP SYMMETRIC KEY Cosmian_DropTest;");

    sqlcmd_ok(
        "USE master; \
         CREATE SYMMETRIC KEY Cosmian_DropTest \
         FROM PROVIDER CosmianEKM \
         WITH ALGORITHM = AES_128, \
              PROVIDER_KEY_NAME = 'test-drop-aes-001', \
              CREATION_DISPOSITION = CREATE_NEW;",
    );

    sqlcmd_ok("USE master; DROP SYMMETRIC KEY Cosmian_DropTest;");

    let out = sqlcmd_ok("SELECT name FROM sys.symmetric_keys WHERE name = 'Cosmian_DropTest';");
    assert!(
        !out.contains("Cosmian_DropTest"),
        "Key should have been dropped.\nOutput: {out}"
    );
}

// ---------------------------------------------------------------------------
// Test: Multiple algorithm support (RSA 4096)
// ---------------------------------------------------------------------------

#[test]
fn t11_create_rsa4096_key() {
    sqlcmd_ignore("USE master; DROP ASYMMETRIC KEY Cosmian_TestKey_RSA4096;");

    sqlcmd_ok(
        "USE master; \
         CREATE ASYMMETRIC KEY Cosmian_TestKey_RSA4096 \
         FROM PROVIDER CosmianEKM \
         WITH ALGORITHM = RSA_4096, \
              PROVIDER_KEY_NAME = 'test-rsa4096-key-001', \
              CREATION_DISPOSITION = CREATE_NEW;",
    );

    let out = sqlcmd_ok(
        "SELECT name, key_length \
         FROM sys.asymmetric_keys \
         WHERE name = 'Cosmian_TestKey_RSA4096';",
    );
    assert!(
        out.contains("Cosmian_TestKey_RSA4096") && out.contains("4096"),
        "RSA 4096 key not found.\nOutput: {out}"
    );
}

// ---------------------------------------------------------------------------
// Test: Drop asymmetric key
// ---------------------------------------------------------------------------

#[test]
fn t13_drop_asymmetric_key() {
    sqlcmd_ignore("USE master; DROP ASYMMETRIC KEY Cosmian_DropTest_RSA;");

    sqlcmd_ok(
        "USE master; \
         CREATE ASYMMETRIC KEY Cosmian_DropTest_RSA \
         FROM PROVIDER CosmianEKM \
         WITH ALGORITHM = RSA_2048, \
              PROVIDER_KEY_NAME = 'test-drop-rsa-001', \
              CREATION_DISPOSITION = CREATE_NEW;",
    );

    // Verify the key exists
    let out = sqlcmd_ok(
        "SELECT name FROM sys.asymmetric_keys WHERE name = 'Cosmian_DropTest_RSA';",
    );
    assert!(
        out.contains("Cosmian_DropTest_RSA"),
        "Asymmetric key should exist after creation.\nOutput: {out}"
    );

    sqlcmd_ok("USE master; DROP ASYMMETRIC KEY Cosmian_DropTest_RSA;");

    let out = sqlcmd_ok(
        "SELECT name FROM sys.asymmetric_keys WHERE name = 'Cosmian_DropTest_RSA';",
    );
    assert!(
        !out.contains("Cosmian_DropTest_RSA"),
        "Asymmetric key should have been dropped.\nOutput: {out}"
    );
}

// ---------------------------------------------------------------------------
// Test: Provider keys DMV (GetNextKeyId)
// ---------------------------------------------------------------------------

#[test]
fn t12_provider_keys_dmv() {
    let pid = provider_id();
    // dm_cryptographic_provider_keys is a table-valued function.
    // Our provider returns NotFound for GetNextKeyId (no key enumeration),
    // so the result set will be empty — the query just must not error.
    let out = sqlcmd_ok(&format!(
        "SELECT key_name, algorithm_id \
         FROM sys.dm_cryptographic_provider_keys({pid});"
    ));
    let _ = out;
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

#[test]
fn t99_cleanup() {
    // TDE cleanup (must disable before dropping)
    sqlcmd_ignore("ALTER DATABASE CosmianEKMTestTDE SET ENCRYPTION OFF;");
    std::thread::sleep(std::time::Duration::from_secs(3));
    sqlcmd_ignore("USE CosmianEKMTestTDE; DROP DATABASE ENCRYPTION KEY;");
    sqlcmd_ignore("USE master; DROP DATABASE CosmianEKMTestTDE;");
    sqlcmd_ignore("ALTER LOGIN Cosmian_TDE_Login DROP CREDENTIAL Cosmian_TDE_Cred;");
    sqlcmd_ignore("DROP CREDENTIAL Cosmian_TDE_Cred;");
    sqlcmd_ignore("DROP LOGIN Cosmian_TDE_Login;");

    // Column-encryption cleanup
    sqlcmd_ignore("USE master; DROP SYMMETRIC KEY Cosmian_ColTestKey;");
    sqlcmd_ignore("USE master; DROP TABLE dbo.EncTest;");
    sqlcmd_ignore("USE master; DROP DATABASE CosmianEKMTestDB;");

    // Provider keys
    sqlcmd_ignore("USE master; DROP ASYMMETRIC KEY Cosmian_TestKey_RSA4096;");
    sqlcmd_ignore("USE master; DROP SYMMETRIC KEY Cosmian_TestKey_AES;");
    sqlcmd_ignore("USE master; DROP ASYMMETRIC KEY Cosmian_TestKey_RSA;");
    sqlcmd_ignore("USE master; DROP ASYMMETRIC KEY Cosmian_DropTest_RSA;");

    // Credential
    sqlcmd_ignore(&format!(
        "ALTER LOGIN [{WIN_LOGIN}] DROP CREDENTIAL {CRED_NAME};"
    ));
    sqlcmd_ignore(&format!("DROP CREDENTIAL {CRED_NAME};"));
}
