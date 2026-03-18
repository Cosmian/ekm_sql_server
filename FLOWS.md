# Cryptographic Flows

Sequence diagrams for the interactions between SQL Server, the Cosmian EKM DLL,
and the Cosmian KMS.  Actors:

- **SQL Server** — the database engine (calls the EKM C API)
- **EKM DLL** — `cosmian_ekm_sql_server.dll` loaded in-process by SQL Server
- **KMS** — Cosmian KMS server (KMIP over HTTPS/mTLS)

---

## Provider initialisation

Called once when SQL Server loads the DLL.

```mermaid
sequenceDiagram
    participant S as SQL Server
    participant D as EKM DLL

    S->>D: SqlCryptInitializeProvider()
    D->>D: init_logging() — start rolling file appender
    Note over D: SESSION_STORE and KEY_STORE are OnceLock —
    Note over D: they initialise lazily on first use.
    D-->>S: scp_err_Success
```

---

## Session open / close

Called for each SQL Server connection that uses EKM keys.

```mermaid
sequenceDiagram
    participant S as SQL Server
    participant D as EKM DLL

    S->>D: SqlCryptOpenSession(credential)
    D->>D: Copy username + password from SqlCpCredential
    D->>D: Allocate monotonic session_id
    D->>D: Insert (session_id, credential) into SESSION_STORE
    D-->>S: session_id (as opaque pointer)

    Note over S,D: ... key operations run here ...

    S->>D: SqlCryptCloseSession(session_id)
    D->>D: Remove session_id from SESSION_STORE
    D-->>S: scp_err_Success
```

---

## Key creation

`CREATE ASYMMETRIC KEY … FROM PROVIDER` or `CREATE SYMMETRIC KEY … FROM PROVIDER`.

```mermaid
sequenceDiagram
    participant S as SQL Server
    participant D as EKM DLL
    participant K as KMS

    S->>D: SqlCryptCreateKey(session, PROVIDER_KEY_NAME, algorithm)
    D->>D: Lookup session → username
    D->>D: Lookup mTLS cert entry for username
    D->>D: Validate cert CN/SAN matches username
    D->>D: get_kms_client() — return cached Arc<KmsClient>

    alt Symmetric (AES)
        D->>K: KMIP Create (AES, bit_len, tag=PROVIDER_KEY_NAME)
        K-->>D: unique_identifier (UUID)
    else Asymmetric (RSA)
        D->>K: KMIP CreateKeyPair (RSA, bit_len, tag=PROVIDER_KEY_NAME)
        K-->>D: private_key_uuid, public_key_uuid
    end

    D->>D: uuid_str_to_bytes(private_or_symmetric_uuid) → 16-byte thumbprint
    D->>D: KEY_STORE.insert(thumbprint_hex → {key_name, is_symmetric, bit_len})
    D-->>S: thumbprint (16 bytes)
```

---

## Key info retrieval

`sys.asymmetric_keys`, `sys.symmetric_keys`, or SQL Server internal look-ups
call `SqlCryptGetKeyInfoByThumb`.

```mermaid
sequenceDiagram
    participant S as SQL Server
    participant D as EKM DLL
    participant K as KMS

    S->>D: SqlCryptGetKeyInfoByThumb(session, thumbprint)
    D->>D: Lookup session → username
    D->>D: thumbprint_to_uuid(thumbprint) → uuid
    D->>D: KEY_STORE.get(thumbprint_hex) → key_name (override from keystore)
    D->>D: get_kms_client() — return cached Arc<KmsClient>
    D->>K: KMIP GetAttributes(uuid)
    K-->>D: algorithm, key_length, object_type, tags
    D->>D: Merge KMS algorithm/bit_len with keystore key_name
    D-->>S: KeyInfo { key_name, algorithm, bit_len, is_symmetric }
```

---

## RSA encrypt (key wrapping)

SQL Server calls `SqlCryptEncrypt` when opening a symmetric key protected by an
EKM asymmetric key (e.g. `OPEN SYMMETRIC KEY … DECRYPTION BY ASYMMETRIC KEY`
or column-level / TDE key wrapping).

```mermaid
sequenceDiagram
    participant S as SQL Server
    participant D as EKM DLL
    participant K as KMS

    S->>D: SqlCryptEncrypt(session, thumbprint, plaintext)
    D->>D: Lookup session → username
    D->>D: thumbprint_to_uuid(thumbprint) → private_key_uuid
    D->>D: pk_uuid = private_key_uuid + "_pk"
    D->>D: get_kms_client() — return cached Arc<KmsClient>
    D->>K: KMIP Encrypt(pk_uuid, RSA-OAEP-SHA256, plaintext)
    Note right of K: KMS encrypts with the public key server-side
    K-->>D: ciphertext
    D-->>S: ciphertext
```

---

## RSA decrypt (key unwrapping)

Called when SQL Server needs to recover the plaintext of a wrapped key.

```mermaid
sequenceDiagram
    participant S as SQL Server
    participant D as EKM DLL
    participant K as KMS

    S->>D: SqlCryptDecrypt(session, thumbprint, ciphertext)
    D->>D: Lookup session → username
    D->>D: thumbprint_to_uuid(thumbprint) → private_key_uuid
    D->>D: get_kms_client() — return cached Arc<KmsClient>
    D->>K: KMIP Decrypt(private_key_uuid, RSA-OAEP-SHA256, ciphertext)
    Note right of K: KMS decrypts with the private key server-side
    K-->>D: plaintext
    D-->>S: plaintext
```

---

## AES encrypt / decrypt

Used for AES symmetric keys (`CREATE SYMMETRIC KEY … FROM PROVIDER`, algorithm `AES_*`).

```mermaid
sequenceDiagram
    participant S as SQL Server
    participant D as EKM DLL
    participant K as KMS

    S->>D: SqlCryptEncrypt(session, thumbprint, plaintext, iv?)
    D->>D: thumbprint_to_uuid → aes_uuid
    D->>D: get_kms_client()
    D->>K: KMIP Encrypt(aes_uuid, AES-CBC, plaintext, iv?)
    Note right of K: KMS generates IV when not provided
    K-->>D: ciphertext + iv
    D->>D: output = iv ∥ ciphertext  (IV prepended as first 16 bytes)
    D-->>S: one blob: iv ∥ ciphertext

    S->>D: SqlCryptDecrypt(session, thumbprint, blob)
    D->>D: thumbprint_to_uuid → aes_uuid
    D->>D: iv = blob[0..16],  ciphertext = blob[16..]
    D->>D: get_kms_client()
    D->>K: KMIP Decrypt(aes_uuid, AES-CBC, ciphertext, iv)
    K-->>D: plaintext
    D-->>S: plaintext
```

---

## Public key export

Called by `SqlCryptExportKey` — SQL Server needs the public key bytes to store in
its metadata (e.g. certificate, `sys.asymmetric_keys`).

```mermaid
sequenceDiagram
    participant S as SQL Server
    participant D as EKM DLL
    participant K as KMS

    S->>D: SqlCryptExportKey(session, thumbprint)
    D->>D: thumbprint_to_uuid → private_key_uuid
    D->>D: pk_uuid = private_key_uuid + "_pk"
    D->>D: get_kms_client()
    D->>K: KMIP Get(pk_uuid, format=PKCS#1)
    K-->>D: DER-encoded RSA public key (PKCS#1)
    D-->>S: public key blob
```

---

## Key deletion

`DROP ASYMMETRIC KEY` or `DROP SYMMETRIC KEY`.

```mermaid
sequenceDiagram
    participant S as SQL Server
    participant D as EKM DLL
    participant K as KMS

    S->>D: SqlCryptDropKey(session, thumbprint)
    D->>D: thumbprint_to_uuid → uuid
    D->>D: get_kms_client()
    D->>K: KMIP Revoke(uuid, cascade=true)
    Note right of K: Marks the key (and its public counterpart) as revoked
    K-->>D: OK (or already revoked — ignored)
    D->>K: KMIP Destroy(uuid, cascade=true)
    K-->>D: OK
    D->>D: KEY_STORE.remove(thumbprint_hex)
    D-->>S: scp_err_Success
```

---

## KMS client caching

The EKM DLL maintains one `KmsClient` per KMS identity (username) for the
lifetime of the DLL load.  Building a new HTTP/mTLS client is relatively
expensive; caching avoids reopening TLS connections on every SQL Server request.

```mermaid
sequenceDiagram
    participant D as EKM DLL
    participant C as KMS_CLIENT_CACHE (RwLock<HashMap>)
    participant K as KMS

    D->>C: read-lock — lookup by username
    alt Cache hit
        C-->>D: Arc<KmsClient>
    else Cache miss
        C-->>D: None
        D->>D: build_kms_client() — create new HTTP+mTLS client
        D->>C: write-lock — insert(username, Arc<KmsClient>)
        C-->>D: Arc<KmsClient>
    end
    D->>K: KMIP request (using Arc<KmsClient>)
```
